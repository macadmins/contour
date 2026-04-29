//! DDM CLI handlers
//!
//! Commands for working with Declarative Device Management declarations.
//! Uses embedded DDM schemas (42 declaration types) by default.

use crate::config::ProfileConfig;
use crate::ddm::{
    Declaration, DeclarationPayload, is_ddm_file, parse_declaration_file, write_declaration,
};
use crate::output::OutputMode;
use crate::schema::SchemaRegistry;
use anyhow::Result;
use colored::Colorize;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Load schema registry (embedded or from external path)
fn load_registry(schema_path: Option<&str>) -> Result<SchemaRegistry> {
    match schema_path {
        Some(p) => SchemaRegistry::from_auto_detect(Path::new(p)),
        None => SchemaRegistry::embedded(),
    }
}

/// Collect DDM JSON files from paths
fn collect_ddm_files(paths: &[String], recursive: bool, max_depth: Option<usize>) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for path_str in paths {
        let path = Path::new(path_str);

        if path.is_file() {
            if path.extension().is_some_and(|e| e == "json") {
                files.push(path.to_path_buf());
            }
        } else if path.is_dir() {
            if recursive {
                let mut walker = WalkDir::new(path).follow_links(true);
                if let Some(depth) = max_depth {
                    walker = walker.max_depth(depth);
                }
                for entry in walker.into_iter().filter_map(std::result::Result::ok) {
                    let p = entry.path();
                    if p.is_file() && p.extension().is_some_and(|e| e == "json") && is_ddm_file(p) {
                        files.push(p.to_path_buf());
                    }
                }
            } else if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.filter_map(std::result::Result::ok) {
                    let p = entry.path();
                    if p.is_file() && p.extension().is_some_and(|e| e == "json") && is_ddm_file(&p)
                    {
                        files.push(p);
                    }
                }
            }
        }
    }

    files
}

/// Parse a single DDM declaration and format output
fn parse_single_ddm(path: &Path, output_mode: OutputMode) -> Result<Option<serde_json::Value>> {
    let decl = parse_declaration_file(path)?;

    if output_mode == OutputMode::Json {
        let info = serde_json::json!({
            "file": path.to_string_lossy(),
            "type": decl.declaration_type,
            "identifier": decl.identifier,
            "category": decl.category().map(|c| c.as_str()),
            "server_token": decl.server_token,
            "payload_keys": decl.payload.keys().collect::<Vec<_>>(),
            "payload": decl.payload.0
        });
        return Ok(Some(info));
    }

    println!("\n{}", path.to_string_lossy().cyan().bold());
    println!("{} {}", "Type:".bold(), decl.declaration_type.cyan());
    println!("{} {}", "Identifier:".bold(), decl.identifier);

    if let Some(category) = decl.category() {
        println!("{} {}", "Category:".bold(), category.to_string().green());
    }

    if let Some(token) = &decl.server_token {
        println!("{} {}", "Server Token:".bold(), token.dimmed());
    }

    println!("\n{}", "Payload:".bold());
    for (key, value) in decl.payload.iter() {
        let value_str = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Null => "null".to_string(),
            _ => serde_json::to_string(value).unwrap_or_default(),
        };
        println!("  {} = {}", key.yellow(), value_str);
    }

    Ok(None)
}

/// Parse and display DDM declaration(s)
pub fn handle_ddm_parse(
    paths: &[String],
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let files = collect_ddm_files(paths, recursive, max_depth);

    if files.is_empty() {
        if output_mode == OutputMode::Json {
            println!("[]");
        } else {
            println!("{}", "No DDM JSON files found.".yellow());
        }
        return Ok(());
    }

    if output_mode == OutputMode::Json {
        let results: Vec<serde_json::Value> = if parallel && files.len() > 1 {
            files
                .par_iter()
                .filter_map(|f| parse_single_ddm(f, output_mode).ok().flatten())
                .collect()
        } else {
            files
                .iter()
                .filter_map(|f| parse_single_ddm(f, output_mode).ok().flatten())
                .collect()
        };
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!("{} {} DDM file(s)\n", "Parsing".bold(), files.len());

        if parallel && files.len() > 1 {
            // Collect results first, then print
            let results: Vec<_> = files
                .par_iter()
                .map(|f| (f.clone(), parse_single_ddm(f, output_mode)))
                .collect();

            for (path, result) in results {
                if let Err(e) = result {
                    eprintln!("{} {}: {}", "✗".red(), path.display(), e);
                }
            }
        } else {
            for file in &files {
                if let Err(e) = parse_single_ddm(file, output_mode) {
                    eprintln!("{} {}: {}", "✗".red(), file.display(), e);
                }
            }
        }
    }

    Ok(())
}

/// Validation result for a single DDM file
struct DdmValidationResult {
    file: PathBuf,
    declaration_type: String,
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

/// Resolve the ancestor path for a nested field by walking `parent_key` links.
///
/// Returns the chain from root to immediate parent, e.g. for `AddSquareRoot`
/// (parent=`BasicMode`, whose parent=`Calculator`) returns `["Calculator", "BasicMode"]`.
fn resolve_ancestor_path(
    field_name: &str,
    manifest: &crate::schema::types::PayloadManifest,
) -> Vec<String> {
    let mut path = Vec::new();
    let mut current = field_name.to_string();

    for _ in 0..32 {
        let parent = manifest
            .fields
            .get(&current)
            .and_then(|f| f.parent_key.as_ref());
        match parent {
            Some(p) => {
                path.push(p.clone());
                current = p.clone();
            }
            None => break,
        }
    }

    path.reverse();
    path
}

/// Walk into a payload along the given key path.
///
/// The root is a `HashMap` (DeclarationPayload), but nested levels are
/// `serde_json::Map` inside `Value::Object`. Returns the innermost object
/// if every key in the path resolves, or `None` if any key is absent or
/// not an object.
fn walk_payload_path<'a>(
    root: &'a std::collections::HashMap<String, serde_json::Value>,
    path: &[String],
) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
    let (first, rest) = path.split_first()?;
    let serde_json::Value::Object(obj) = root.get(first)? else {
        return None;
    };
    let mut current = obj;
    for key in rest {
        match current.get(key) {
            Some(serde_json::Value::Object(nested)) => current = nested,
            _ => return None,
        }
    }
    Some(current)
}

/// Validate a single DDM declaration
fn validate_single_ddm(path: &Path, registry: &SchemaRegistry) -> Result<DdmValidationResult> {
    let decl = parse_declaration_file(path)?;

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Check if schema exists for this declaration type
    if let Some(manifest) = registry.get(&decl.declaration_type) {
        // Check required fields
        for field in manifest.required_fields() {
            if field.depth == 0 {
                if decl.payload.get(&field.name).is_none() {
                    errors.push(format!("Missing required field: {}", field.name));
                }
            } else if field.parent_key.is_some() {
                let ancestors = resolve_ancestor_path(&field.name, manifest);
                if let Some(parent_obj) = walk_payload_path(&decl.payload.0, &ancestors) {
                    if !parent_obj.contains_key(&field.name) {
                        let full_path = ancestors.join(".");
                        errors.push(format!(
                            "Missing required field: {full_path}.{}",
                            field.name
                        ));
                    }
                }
            }
        }

        // Check for unknown fields
        for key in decl.payload.keys() {
            if !manifest.fields.contains_key(key) {
                warnings.push(format!("Unknown field: {key}"));
            }
        }
    } else {
        warnings.push(format!(
            "Unknown declaration type: {}",
            decl.declaration_type
        ));
    }

    // Basic structural validation
    if decl.identifier.is_empty() {
        errors.push("Identifier is empty".to_string());
    }

    if decl.declaration_type.is_empty() {
        errors.push("Type is empty".to_string());
    }

    Ok(DdmValidationResult {
        file: path.to_path_buf(),
        declaration_type: decl.declaration_type,
        valid: errors.is_empty(),
        errors,
        warnings,
    })
}

/// Validate DDM declaration(s) against embedded schema
pub fn handle_ddm_validate(
    paths: &[String],
    schema_path: Option<&str>,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let files = collect_ddm_files(paths, recursive, max_depth);

    if files.is_empty() {
        if output_mode == OutputMode::Json {
            println!("[]");
        } else {
            println!("{}", "No DDM JSON files found.".yellow());
        }
        return Ok(());
    }

    // Load schema registry once
    let registry = load_registry(schema_path)?;

    let results: Vec<DdmValidationResult> = if parallel && files.len() > 1 {
        files
            .par_iter()
            .filter_map(|f| validate_single_ddm(f, &registry).ok())
            .collect()
    } else {
        files
            .iter()
            .filter_map(|f| validate_single_ddm(f, &registry).ok())
            .collect()
    };

    let valid_count = results.iter().filter(|r| r.valid).count();
    let invalid_count = results.len() - valid_count;

    if output_mode == OutputMode::Json {
        let json_results: Vec<_> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "valid": r.valid,
                    "file": r.file.to_string_lossy(),
                    "type": r.declaration_type,
                    "errors": r.errors,
                    "warnings": r.warnings
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_results)?);
        return Ok(());
    }

    // Human output
    for result in &results {
        let filename = result
            .file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        if result.valid {
            println!("{} {} is valid", "✓".green(), filename.cyan());
        } else {
            println!("{} {} has validation errors", "✗".red(), filename.cyan());
        }

        for error in &result.errors {
            println!("  {} {}", "Error:".red(), error);
        }

        for warning in &result.warnings {
            println!("  {} {}", "Warning:".yellow(), warning);
        }
    }

    // Summary for multiple files
    if results.len() > 1 {
        println!();
        println!(
            "{}: {} valid, {} invalid out of {} files",
            "Summary".bold(),
            valid_count.to_string().green(),
            if invalid_count > 0 {
                invalid_count.to_string().red().to_string()
            } else {
                invalid_count.to_string()
            },
            results.len()
        );
    }

    if invalid_count > 0 {
        anyhow::bail!("Validation failed for {invalid_count} file(s)");
    }

    Ok(())
}

/// List available DDM declaration types from embedded schema
pub fn handle_ddm_list(
    category: Option<&str>,
    schema_path: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = load_registry(schema_path)?;

    // Get DDM declarations (categories starting with ddm-)
    let ddm_categories = [
        "ddm-configuration",
        "ddm-activation",
        "ddm-asset",
        "ddm-management",
    ];

    let manifests: Vec<_> = if let Some(cat) = category {
        let full_cat = if cat.starts_with("ddm-") {
            cat.to_string()
        } else {
            format!("ddm-{cat}")
        };
        registry.by_category(&full_cat)
    } else {
        registry
            .all()
            .filter(|m| m.category.starts_with("ddm-"))
            .collect()
    };

    if output_mode == OutputMode::Json {
        let list: Vec<_> = manifests
            .iter()
            .map(|m| {
                serde_json::json!({
                    "type": m.payload_type,
                    "title": m.title,
                    "category": m.category.strip_prefix("ddm-").unwrap_or(&m.category),
                    "platforms": m.platforms.to_vec()
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(());
    }

    println!(
        "{} ({} declaration types)\n",
        "DDM Declaration Types".bold(),
        manifests.len()
    );

    // Group by category
    for ddm_cat in ddm_categories {
        if let Some(cat) = category {
            // Skip if filtering by specific category
            let filter_cat = if cat.starts_with("ddm-") {
                cat.to_string()
            } else {
                format!("ddm-{cat}")
            };
            if ddm_cat != filter_cat {
                continue;
            }
        }

        let cat_manifests: Vec<_> = manifests.iter().filter(|m| m.category == ddm_cat).collect();
        if cat_manifests.is_empty() {
            continue;
        }

        let cat_name = ddm_cat.strip_prefix("ddm-").unwrap_or(ddm_cat);
        println!(
            "{} ({}):",
            format!("[{cat_name}]").magenta().bold(),
            cat_manifests.len()
        );

        for m in cat_manifests {
            let platforms = m.platforms.to_vec().join(", ");
            println!(
                "  {} - {} [{}]",
                m.payload_type.cyan(),
                m.title,
                platforms.dimmed()
            );
        }
        println!();
    }

    println!(
        "{}",
        "Use 'contour profile ddm info <type>' for detailed schema information.".dimmed()
    );
    println!(
        "{}",
        "Use 'contour profile ddm create <type> -i <identifier>' to create a declaration.".dimmed()
    );

    Ok(())
}

/// Show DDM declaration schema info
pub fn handle_ddm_info(
    name: &str,
    schema_path: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = load_registry(schema_path)?;

    let manifest = registry.get_by_name(name).ok_or_else(|| {
        anyhow::anyhow!(
            "DDM declaration type '{name}' not found.\nUse 'contour profile ddm list' to see available types."
        )
    })?;

    // Verify it's a DDM declaration
    if !manifest.category.starts_with("ddm-") {
        anyhow::bail!(
            "'{name}' is a profile payload type, not a DDM declaration.\nUse 'contour profile schema info {name}' for profile schemas."
        );
    }

    if output_mode == OutputMode::Json {
        let fields: Vec<_> = manifest
            .field_order
            .iter()
            .filter_map(|name| manifest.fields.get(name))
            .map(|f| {
                serde_json::json!({
                    "name": f.name,
                    "type": f.field_type.as_str(),
                    "required": f.flags.required,
                    "default": f.default,
                    "allowed_values": f.allowed_values,
                })
            })
            .collect();

        let info = serde_json::json!({
            "type": manifest.payload_type,
            "title": manifest.title,
            "description": manifest.description,
            "category": manifest.category.strip_prefix("ddm-").unwrap_or(&manifest.category),
            "platforms": manifest.platforms.to_vec(),
            "fields": fields,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }

    // Human output
    println!("{}\n", manifest.title.bold());
    println!("{}: {}", "Declaration Type".cyan(), manifest.payload_type);
    println!(
        "{}: {}",
        "Category".cyan(),
        manifest
            .category
            .strip_prefix("ddm-")
            .unwrap_or(&manifest.category)
            .magenta()
    );
    println!(
        "{}: {}",
        "Platforms".cyan(),
        manifest.platforms.to_vec().join(", ")
    );
    println!("\n{}", "Description:".cyan());
    println!("  {}", manifest.description);

    // Show fields
    let fields: Vec<_> = manifest.top_level_fields();

    if !fields.is_empty() {
        println!("\n{} ({}):", "Payload Keys".cyan().bold(), fields.len());

        for field in fields {
            let mut markers = Vec::new();
            if field.flags.required {
                markers.push("required".red().to_string());
            }

            let marker_str = if markers.is_empty() {
                String::new()
            } else {
                format!(" [{}]", markers.join(", "))
            };

            println!(
                "  {} ({}){}",
                field.name.yellow(),
                field.field_type.as_str().dimmed(),
                marker_str
            );

            // Show default if present
            if let Some(ref default) = field.default {
                println!("    Default: {}", default.dimmed());
            }

            // Show allowed values if present
            if !field.allowed_values.is_empty() {
                println!("    Allowed: {}", field.allowed_values.join(", ").dimmed());
            }
        }
    }

    // Show required fields summary
    let required = manifest.required_fields();
    if !required.is_empty() {
        println!(
            "\n{}: {}",
            "Required fields".red(),
            required
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    Ok(())
}

/// Generate a default JSON value for a field, recursively populating Dictionary children.
///
/// Required children are always emitted so that optional parents remain valid when
/// included (matches the validator's rule: "if parent is present, required children
/// must be present"). When `full` is true, optional children are included as well.
fn generate_field_value(
    field_name: &str,
    field: &crate::schema::FieldDefinition,
    manifest: &crate::schema::PayloadManifest,
    full: bool,
) -> serde_json::Value {
    use crate::schema::FieldType;

    // Honor explicit defaults for scalar types.
    if let Some(default) = &field.default {
        return match field.field_type {
            FieldType::Boolean => serde_json::Value::Bool(default.parse().unwrap_or(false)),
            FieldType::Integer => {
                serde_json::Value::Number(default.parse::<i64>().unwrap_or(0).into())
            }
            FieldType::Real => default
                .parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
                .map_or(serde_json::Value::Null, serde_json::Value::Number),
            _ => serde_json::Value::String(default.clone()),
        };
    }

    match field.field_type {
        FieldType::Boolean => serde_json::Value::Bool(false),
        FieldType::Integer => serde_json::Value::Number(0.into()),
        FieldType::Real => serde_json::Number::from_f64(0.0)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        FieldType::Array => serde_json::Value::Array(vec![]),
        FieldType::Dictionary => {
            // Walk field_order (not fields map) to preserve declaration order.
            let mut obj = serde_json::Map::new();
            for child_name in &manifest.field_order {
                let Some(child) = manifest.fields.get(child_name) else {
                    continue;
                };
                if child.parent_key.as_deref() != Some(field_name) {
                    continue;
                }
                if !child.flags.required && !full {
                    continue;
                }
                obj.insert(
                    child_name.clone(),
                    generate_field_value(child_name, child, manifest, full),
                );
            }
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::String(String::new()),
    }
}

/// Generate a DDM declaration JSON from schema
pub fn handle_ddm_generate(
    name: &str,
    output: Option<&str>,
    full: bool,
    schema_path: Option<&str>,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = load_registry(schema_path)?;

    let manifest = registry.get_by_name(name).ok_or_else(|| {
        anyhow::anyhow!(
            "DDM declaration type '{name}' not found.\nUse 'contour profile ddm list' to see available types."
        )
    })?;

    // Verify it's a DDM declaration
    if !manifest.category.starts_with("ddm-") {
        anyhow::bail!(
            "'{name}' is a profile payload type, not a DDM declaration.\nUse 'contour profile template generate {name}' for profile templates."
        );
    }

    // Build the declaration
    let mut payload = DeclarationPayload::new();

    // Top-level fields only — nested children are emitted by the Dictionary arm of
    // `generate_field_value`, driven by each field's `parent_key`. Emitting nested
    // fields at the top level would flatten the structure and (for required children
    // of optional parents) create invalid docs that fail `ddm validate`.
    for field_name in &manifest.field_order {
        if let Some(field) = manifest.fields.get(field_name) {
            if field.parent_key.is_some() {
                continue;
            }
            if !field.flags.required && !full {
                continue;
            }
            let value = generate_field_value(field_name, field, manifest, full);
            payload.insert(field_name.clone(), value);
        }
    }

    // Build identifier
    let short_name = manifest
        .payload_type
        .split('.')
        .next_back()
        .unwrap_or("declaration");
    let identifier = if let Some(cfg) = config {
        format!("{}.{}", cfg.organization.domain, short_name)
    } else {
        format!("com.example.{short_name}")
    };

    let decl = Declaration {
        declaration_type: manifest.payload_type.clone(),
        identifier,
        server_token: None,
        payload,
    };

    let json = write_declaration(&decl)?;

    // Determine output path
    let slug = manifest
        .title
        .to_lowercase()
        .replace([' ', ':'], "-")
        .replace("--", "-");
    let output_path = output.map_or_else(
        || format!("{slug}-declaration.json"),
        std::string::ToString::to_string,
    );

    // Create output directory if needed
    if let Some(parent) = Path::new(&output_path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&output_path, &json)?;

    // Double-validate the generated file using the SAME validator that
    // `profile ddm validate` uses. This catches nested-required-field bugs
    // that the shallow post-generate check would miss, and turns round-trip
    // failures into a hard error at generate time rather than leaving the
    // user holding an invalid file.
    let result = validate_single_ddm(std::path::Path::new(&output_path), &registry)?;
    if !result.valid {
        if output_mode == OutputMode::Human {
            eprintln!(
                "\n{} Generated declaration failed schema validation:",
                "✗".red().bold()
            );
            for err in &result.errors {
                eprintln!("  {} {err}", "·".red());
            }
            eprintln!(
                "\n{}",
                "This is a generator bug — please report with the `--full` flag and type name."
                    .dimmed()
            );
        }
        anyhow::bail!(
            "generated DDM declaration failed validation: {}",
            result.errors.join("; ")
        );
    }
    for warn in &result.warnings {
        if output_mode == OutputMode::Human {
            eprintln!("  {} {warn}", "⚠".yellow());
        }
    }

    if output_mode == OutputMode::Json {
        let result = serde_json::json!({
            "success": true,
            "type": manifest.payload_type,
            "title": manifest.title,
            "output": output_path,
            "fields": if full { "all" } else { "required" }
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "{} Generated DDM declaration: {}",
            "✓".green(),
            output_path.cyan()
        );
        println!("  {} {}", "Type:".bold(), manifest.payload_type);
        println!("  {} {}", "Title:".bold(), manifest.title);
        println!(
            "  {} {}",
            "Fields:".bold(),
            if full { "all" } else { "required only" }
        );
        println!(
            "\n{}",
            "Edit the JSON file to set your values, then deploy via your MDM.".dimmed()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate the payload for a DDM type via the same code path as
    /// `handle_ddm_generate`, without touching the filesystem.
    fn build_payload(type_name: &str, full: bool) -> DeclarationPayload {
        let registry = SchemaRegistry::embedded().expect("embedded registry loads");
        let manifest = registry
            .get_by_name(type_name)
            .unwrap_or_else(|| panic!("manifest not found: {type_name}"));

        let mut payload = DeclarationPayload::new();
        for field_name in &manifest.field_order {
            if let Some(field) = manifest.fields.get(field_name) {
                if field.parent_key.is_some() {
                    continue;
                }
                if !field.flags.required && !full {
                    continue;
                }
                payload.insert(
                    field_name.clone(),
                    generate_field_value(field_name, field, manifest, full),
                );
            }
        }
        payload
    }

    /// Run the same required-field validation as `validate_single_ddm` for a
    /// payload generated in-process. Returns the list of `errors`.
    fn validate_payload(type_name: &str, payload: &DeclarationPayload) -> Vec<String> {
        let registry = SchemaRegistry::embedded().expect("embedded registry loads");
        let manifest = registry
            .get_by_name(type_name)
            .unwrap_or_else(|| panic!("manifest not found: {type_name}"));
        let mut errors = Vec::new();
        for field in manifest.required_fields() {
            if field.depth == 0 {
                if payload.get(&field.name).is_none() {
                    errors.push(format!("Missing required field: {}", field.name));
                }
            } else if field.parent_key.is_some() {
                let ancestors = resolve_ancestor_path(&field.name, manifest);
                if let Some(parent_obj) = walk_payload_path(&payload.0, &ancestors)
                    && !parent_obj.contains_key(&field.name)
                {
                    let full_path = ancestors.join(".");
                    errors.push(format!(
                        "Missing required field: {full_path}.{}",
                        field.name
                    ));
                }
            }
        }
        errors
    }

    /// Regression test for https://github.com/macadmins/contour/pull/5 follow-up:
    /// `ddm generate --full` must produce a doc that passes `ddm validate`.
    /// Prior to this test, `CustomRegex` was emitted as `{}` and its required
    /// nested `Regex` child was emitted at the top level, yielding a doc that
    /// the (correctly nesting-aware) validator rejected.
    #[test]
    fn passcode_settings_full_round_trip_is_valid() {
        let payload = build_payload("com.apple.configuration.passcode.settings", true);

        // Nested children must NOT leak to the top level.
        assert!(
            payload.get("Regex").is_none(),
            "nested `Regex` must not be emitted at top level; payload keys: {:?}",
            payload.keys().collect::<Vec<_>>()
        );

        // If the optional parent is present, the required child must be present too.
        if let Some(serde_json::Value::Object(cr)) = payload.get("CustomRegex") {
            assert!(
                cr.contains_key("Regex"),
                "CustomRegex is present but required child `Regex` is missing"
            );
        }

        let errors = validate_payload("com.apple.configuration.passcode.settings", &payload);
        assert!(
            errors.is_empty(),
            "generated --full doc failed validation: {errors:?}"
        );
    }

    /// Required-only (no --full) must also validate. This is the default path
    /// and the one used in CI pipelines.
    #[test]
    fn passcode_settings_required_only_round_trip_is_valid() {
        let payload = build_payload("com.apple.configuration.passcode.settings", false);
        let errors = validate_payload("com.apple.configuration.passcode.settings", &payload);
        assert!(
            errors.is_empty(),
            "generated required-only doc failed validation: {errors:?}"
        );
    }

    /// Exhaustive round-trip: every DDM type in the embedded registry must
    /// produce a valid doc in both `--full` and required-only modes. Protects
    /// the entire DDM surface from nested-required-field regressions.
    #[test]
    fn every_ddm_type_round_trips_cleanly() {
        let registry = SchemaRegistry::embedded().expect("embedded registry loads");
        let mut ddm_types: Vec<String> = Vec::new();
        for cat in [
            "ddm-configuration",
            "ddm-activation",
            "ddm-asset",
            "ddm-management",
        ] {
            for m in registry.by_category(cat) {
                ddm_types.push(m.payload_type.clone());
            }
        }

        assert!(!ddm_types.is_empty(), "no DDM types found in registry");

        let mut failures: Vec<String> = Vec::new();
        for type_name in &ddm_types {
            for full in [false, true] {
                let payload = build_payload(type_name, full);
                let errors = validate_payload(type_name, &payload);
                if !errors.is_empty() {
                    failures.push(format!("{type_name} (full={full}): {}", errors.join(", ")));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} DDM types produced invalid docs:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }
}
