//! DDM CLI handlers
//!
//! Commands for working with Declarative Device Management declarations.
//! Uses embedded DDM schemas (42 declaration types) by default.

use crate::config::ProfileConfig;
use crate::ddm::compose::{Bundle, ComposeOptions, ComposedBundle, compose};
use crate::ddm::verify::{VerifyError, VerifyReport, VerifyWarning, build_report};
use crate::ddm::{
    Declaration, DeclarationPayload, is_ddm_file, parse_declaration_file, write_declaration,
};
use crate::output::OutputMode;
use crate::schema::SchemaRegistry;
use anyhow::{Context, Result};
use colored::Colorize;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// List Apple-provided examples for a declaration type.
pub fn handle_ddm_examples(name: &str, beta: bool, output_mode: OutputMode) -> Result<()> {
    let registry = load_registry_opts(None, beta)?;
    let manifest = registry
        .get_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("type '{name}' not found"))?;
    let examples = crate::example::lookup::for_type(&manifest.payload_type, beta)?;
    if output_mode == OutputMode::Json {
        let rows: Vec<_> = examples
            .iter()
            .map(|e| {
                serde_json::json!({
                    "index": e.index,
                    "tab": e.tab,
                    "description": e.description,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else if examples.is_empty() {
        println!("No examples for {}", manifest.payload_type);
    } else {
        for e in &examples {
            println!(
                "  [{}] {}",
                e.index,
                e.tab.as_deref().unwrap_or("(example)")
            );
            if let Some(d) = &e.description {
                println!("      {d}");
            }
        }
    }
    Ok(())
}

/// Load schema registry (embedded or from external path)
fn load_registry(schema_path: Option<&str>) -> Result<SchemaRegistry> {
    load_registry_opts(schema_path, false)
}

/// Tell a person at a terminal, once per run, that `--beta` changes nothing.
///
/// While no OS seed is open the beta channel is retired and serves the
/// released schema byte for byte ([`mdm_schema::beta_is_retired`]). Nothing
/// said so, and help text and SOPs kept pointing people at `--beta` for keys
/// that had long since shipped.
///
/// Silent unless stderr is a terminal: Wedge and CI run `--json` and read
/// stderr for the error envelope, which an advisory line would corrupt. And it
/// goes quiet by itself the day the accessors are re-pointed at a new seed.
pub(crate) fn note_if_beta_is_retired() {
    use std::io::IsTerminal;
    static ONCE: std::sync::Once = std::sync::Once::new();
    if !mdm_schema::beta_is_retired() || !std::io::stderr().is_terminal() {
        return;
    }
    ONCE.call_once(|| {
        eprintln!(
            "{} --beta changes nothing right now: no OS seed is open, so the beta \
             channel serves the released schema. It will matter again when Apple \
             opens the next seed.",
            "Note:".yellow().bold()
        );
    });
}

/// Load the schema registry, optionally from the beta seed dataset.
///
/// An explicit `schema_path` always wins (external dir); `beta` only selects
/// the embedded **seed** schema (pre-release OS keys) when no path is given.
pub(crate) fn load_registry_opts(schema_path: Option<&str>, beta: bool) -> Result<SchemaRegistry> {
    match schema_path {
        Some(p) => SchemaRegistry::from_auto_detect(Path::new(p)),
        None if beta => {
            note_if_beta_is_retired();
            SchemaRegistry::embedded_beta()
        }
        None => SchemaRegistry::embedded(),
    }
}

/// Resolve the organization domain for DDM generation/compose.
///
/// Resolution order:
///   1. Explicit `--org <ORG>` flag (highest priority)
///   2. `profile.toml` (`config.organization.domain`)
///   3. `CONTOUR_ORG` env var (ideal for CI / GitHub Actions)
///   4. `.contour/config.toml` walked up from cwd
///
/// Returns `None` only when no source provides a value; the caller emits
/// the typed error envelope.
pub(crate) fn resolve_ddm_org_domain(
    cli_flag: Option<&str>,
    config: Option<&ProfileConfig>,
) -> Option<String> {
    if let Some(s) = cli_flag {
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    if let Some(cfg) = config {
        return Some(cfg.organization.domain.clone());
    }
    if let Ok(env_org) = std::env::var("CONTOUR_ORG") {
        if !env_org.is_empty() {
            return Some(env_org);
        }
    }
    contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.domain)
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

/// Every concrete object matching `path`, expanding `ANY` segments.
///
/// Apple models a free-form dictionary as a field literally named `ANY`:
/// `Privacy.PermissionDefaults.ANY.Camera` means "every key under
/// PermissionDefaults has a Camera". [`walk_payload_path`] resolves a path
/// literally, so it looks for a key named `ANY`, finds nothing, and every
/// check below it silently passes. That is how a
/// `com.apple.configuration.app.settings` declaration could omit
/// `OrganizationJustification` — which this schema marks required — and
/// still validate.
///
/// Returns `(label, object)` pairs where `label` is the concrete path, so an
/// error names the app it came from rather than the word `ANY`.
fn walk_payload_paths<'a>(
    root: &'a std::collections::HashMap<String, serde_json::Value>,
    path: &[String],
) -> Vec<(String, &'a serde_json::Map<String, serde_json::Value>)> {
    // `parent_key` in a manifest is a full dotted path
    // ("Privacy.PermissionDefaults.ANY"), so a caller's segment may itself
    // contain dots. Flatten before walking, or the first lookup searches for
    // a key literally named "Privacy.PermissionDefaults.ANY".
    // As segments, so an escaped `\.` inside a key name stays inside it.
    let flat: Vec<String> = path
        .iter()
        .flat_map(|seg| crate::schema::FieldPath::parse(seg).segments().to_vec())
        .collect();
    let Some((first, rest)) = flat.split_first() else {
        return Vec::new();
    };
    let Some(serde_json::Value::Object(obj)) = root.get(first) else {
        return Vec::new();
    };

    let mut current: Vec<(String, &serde_json::Map<String, serde_json::Value>)> =
        vec![(first.clone(), obj)];

    for key in rest {
        let mut next = Vec::new();
        for (label, obj) in current {
            if key == "ANY" {
                // Every key at this level is an instance of the ANY node.
                for (concrete, value) in obj {
                    if let serde_json::Value::Object(nested) = value {
                        next.push((format!("{label}.{concrete}"), nested));
                    }
                }
            } else if let Some(serde_json::Value::Object(nested)) = obj.get(key) {
                next.push((format!("{label}.{key}"), nested));
            }
        }
        current = next;
        if current.is_empty() {
            break;
        }
    }
    current
}

/// Findings inside array elements, which [`walk_payload_paths`] cannot reach.
///
/// The walker follows objects only, so everything inside an array was
/// invisible to validation: the element's shape, unknown keys, enum values.
///
/// Apple describes an array's element as its single child field — the
/// element descriptor. `AllowedBinaries` → `BinaryIdentifier` (a dictionary),
/// `AllowedApps` → `AppIdentifier` (a string). That child names the element's
/// *type*; it is never a key. Nesting under it — `[{"BinaryIdentifier": {…}}]`
/// or `[{"AppIdentifier": "…"}]` — is the natural misreading of the schema,
/// and it produces a declaration that validates, deploys, and matches nothing.
///
/// This is also why the descriptor can't simply be walked through: the
/// required-field check would then look for a *key* named `BinaryIdentifier`
/// in every correct element and fail it.
fn array_element_findings(
    payload: &std::collections::HashMap<String, serde_json::Value>,
    manifest: &crate::schema::PayloadManifest,
) -> (Vec<String>, Vec<String>) {
    use crate::schema::{FieldDefinition, FieldType};

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let path_of = |f: &FieldDefinition| match &f.parent_key {
        Some(parent) => format!("{parent}.{}", f.name),
        None => f.name.clone(),
    };
    // Children of `path`, in schema order.
    let children_of = |path: &str| -> Vec<&FieldDefinition> {
        manifest
            .field_order
            .iter()
            .filter_map(|name| manifest.fields.get(name))
            .filter(|f| f.parent_key.as_deref() == Some(path))
            .collect()
    };

    for array in manifest
        .fields
        .values()
        .filter(|f| f.field_type == FieldType::Array)
    {
        let array_path = path_of(array);
        // Exactly one child is Apple's shape. None means the schema lost the
        // row — the loader's leaf-name dedup, or an unexpanded YAML alias —
        // and without it there is nothing to judge the element by.
        let [element] = children_of(&array_path)[..] else {
            continue;
        };
        let element_path = format!("{array_path}.{}", element.name);
        let fields = children_of(&element_path);

        // Every place the array occurs in the payload.
        let arrays: Vec<(String, &Vec<serde_json::Value>)> = match &array.parent_key {
            None => payload
                .get(&array.name)
                .and_then(serde_json::Value::as_array)
                .map(|items| vec![(array.name.clone(), items)])
                .unwrap_or_default(),
            Some(parent) => walk_payload_paths(payload, std::slice::from_ref(parent))
                .into_iter()
                .filter_map(|(label, obj)| {
                    obj.get(&array.name)
                        .and_then(serde_json::Value::as_array)
                        .map(|items| (format!("{label}.{}", array.name), items))
                })
                .collect(),
        };

        for (label, items) in arrays {
            for (i, item) in items.iter().enumerate() {
                let at = format!("{label}[{i}]");
                match (&element.field_type, item) {
                    (FieldType::Dictionary, serde_json::Value::Object(obj)) => {
                        if obj.contains_key(&element.name) {
                            let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
                            let first = names.first().copied().unwrap_or("…");
                            errors.push(format!(
                                "{at} nests its fields under \"{name}\". {name} is Apple's name \
                                 for the array element, not a key: put {} directly in the \
                                 element — {{\"{first}\": …}}, not {{\"{name}\": {{…}}}}. As \
                                 written it matches nothing.",
                                names.join(", "),
                                name = element.name,
                            ));
                            continue;
                        }
                        for (key, value) in obj {
                            match fields.iter().find(|f| &f.name == key) {
                                Some(field) if !field.allowed_values.is_empty() => {
                                    if let Some(text) = value.as_str()
                                        && !field.allowed_values.iter().any(|v| v == text)
                                    {
                                        errors.push(format!(
                                            "Invalid value for {at}.{key}: \"{text}\" (allowed: {})",
                                            field.allowed_values.join(", ")
                                        ));
                                    }
                                }
                                Some(_) => {}
                                // A leaf name the type uses elsewhere may have been lost
                                // here to the loader's leaf-name dedup, so it is not
                                // reported. A name the type uses nowhere is.
                                None if manifest.fields.contains_key(key) => {}
                                None => warnings.push(format!(
                                    "Unknown field: {at}.{key} (known: {})",
                                    fields
                                        .iter()
                                        .map(|f| f.name.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                )),
                            }
                        }
                    }
                    (FieldType::Dictionary, _) => errors.push(format!(
                        "{at} must be a dictionary ({}), not a bare value",
                        element.name
                    )),
                    (scalar, serde_json::Value::Object(obj)) => {
                        let kind = format!("{scalar:?}").to_lowercase();
                        let wrapped = if obj.contains_key(&element.name) {
                            format!(
                                " {} is Apple's name for the element, not a key.",
                                element.name
                            )
                        } else {
                            String::new()
                        };
                        errors.push(format!(
                            "{at} is an object, but each element of {label} is a bare {kind}.{wrapped} \
                             Write [\"value\"], not [{{\"{}\": \"value\"}}] — as written it matches nothing.",
                            element.name
                        ));
                    }
                    _ => {}
                }
            }
        }
    }

    (errors, warnings)
}

/// Resolve a declaration's `Identifier`.
///
/// An explicit `--identifier` is used verbatim and needs no `--org` — the org
/// domain exists only to *derive* an identifier (`<domain>.<short name>`).
/// Callers that name declarations themselves (a GUI, a pipeline stage) would
/// otherwise have to rewrite contour's output.
///
/// # Errors
/// When no identifier is given and no org domain can be resolved.
pub(crate) fn resolve_declaration_identifier(
    identifier: Option<&str>,
    org: Option<&str>,
    config: Option<&ProfileConfig>,
    short_name: &str,
) -> Result<String> {
    if let Some(id) = identifier.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(id.to_string());
    }
    // Refuse silent "com.example" defaulting — DDM declarations are deployable
    // and an example-domain identifier collides across orgs.
    let domain = resolve_ddm_org_domain(org, config).ok_or_else(|| {
        anyhow::anyhow!(
            "organization domain is required for DDM generation\n\
             Set it via:\n  \
             • --identifier com.yourcompany.something (name it directly)\n  \
             • organization.domain in profile.toml\n  \
             • CONTOUR_ORG=com.yourcompany (env var, ideal for CI)\n  \
             • organization.domain in .contour/config.toml"
        )
    })?;
    Ok(format!("{domain}.{short_name}"))
}

/// Cross-key constraints Apple documents in prose but does not encode
/// machine-readably in its schema — so neither the type checks nor the
/// rangelist check can see them.
///
/// These are hand-encoded per declaration type from Apple's own key
/// descriptions. Violations install cleanly and then misbehave on device,
/// which is exactly the failure class contour exists to catch. A type with
/// no rules here returns no errors.
fn cross_key_errors(decl: &Declaration) -> Vec<String> {
    let mut errors = Vec::new();

    if decl.declaration_type == "com.apple.configuration.softwareupdate.settings" {
        let Some(beta) = decl.payload.get("Beta").and_then(|v| v.as_object()) else {
            return errors;
        };
        // Absent ProgramEnrollment is implicitly `Allowed` (Apple says so
        // for unsupervised devices), so only an explicit value constrains.
        let enrollment = beta.get("ProgramEnrollment").and_then(|v| v.as_str());
        let has_offer = beta.contains_key("OfferPrograms");
        let has_require = beta.contains_key("RequireProgram");

        if has_offer && has_require {
            errors.push(
                "Beta.OfferPrograms and Beta.RequireProgram are mutually exclusive — \
                 Apple: \"The OfferPrograms key must not be present if this key is present\""
                    .to_string(),
            );
        }
        if has_offer && enrollment == Some("AlwaysOff") {
            errors.push(
                "Beta.OfferPrograms requires Beta.ProgramEnrollment to be \
                 Allowed or AlwaysOn (found AlwaysOff)"
                    .to_string(),
            );
        }
        if has_require && enrollment != Some("AlwaysOn") {
            let found = enrollment.unwrap_or("absent (implicitly Allowed)");
            errors.push(format!(
                "Beta.RequireProgram requires Beta.ProgramEnrollment to be \
                 AlwaysOn (found {found})"
            ));
        }
    }

    errors
}

/// Schema-validation errors + warnings for an in-memory declaration. Reused by
/// the `validate` command and as the fail-closed gate before `generate`/`compose`
/// write a declaration.
pub fn declaration_errors(
    decl: &Declaration,
    registry: &SchemaRegistry,
) -> (Vec<String>, Vec<String>) {
    declaration_errors_scoped(decl, registry, None)
}

/// Report payload keys the schema does not define at their path.
///
/// Fields are keyed by full path (`Apps.Mail.AllowSummary`), so a key is
/// known only where the schema puts it. Skipped, because another check owns
/// them or there is nothing to compare against: a dictionary with an `ANY`
/// child (free-form keys, checked against the ANY node's children), a
/// dictionary the schema declares no children for, and arrays (checked
/// element by element in `array_element_findings`).
fn unknown_fields<'a>(
    obj: impl IntoIterator<Item = (&'a String, &'a serde_json::Value)>,
    prefix: Option<&str>,
    manifest: &crate::schema::PayloadManifest,
    warnings: &mut Vec<String>,
) {
    use crate::schema::FieldType;
    let any = prefix.map_or_else(|| "ANY".to_string(), |p| format!("{p}.ANY"));
    if manifest.fields.contains_key(&any) {
        return;
    }
    let siblings: Vec<&str> = manifest
        .field_order
        .iter()
        .filter_map(|path| manifest.fields.get(path))
        .filter(|f| f.parent_key.as_deref() == prefix)
        .map(|f| f.name.as_str())
        .collect();
    if prefix.is_some() && siblings.is_empty() {
        return;
    }
    for (key, value) in obj {
        let path = prefix.map_or_else(|| key.clone(), |p| format!("{p}.{key}"));
        match manifest.fields.get(&path) {
            None if prefix.is_none() => warnings.push(format!("Unknown field: {key}")),
            None => warnings.push(format!(
                "Unknown field: {path} (known under {}: {})",
                prefix.unwrap_or_default(),
                siblings.join(", ")
            )),
            Some(f) if f.field_type == FieldType::Dictionary => {
                if let serde_json::Value::Object(child) = value {
                    unknown_fields(child, Some(&path), manifest, warnings);
                }
            }
            Some(_) => {}
        }
    }
}

/// Keys in `decl` that Apple does not offer on `platform`, and the type
/// itself when it is not available there.
///
/// Apple marks a key unavailable per platform (`introduced: n/a`); the
/// loader keeps that as the key's `platforms` list, empty when the key
/// inherits the payload's. A declaration carries no platform of its own, so
/// this runs only when the caller names one — `--platform`, or a bundle's
/// `platforms`. A key the device's OS does not have is ignored there.
pub fn platform_findings(
    decl: &Declaration,
    registry: &SchemaRegistry,
    platform: crate::schema::Platform,
) -> Vec<String> {
    use crate::schema::Platform;
    let Some(manifest) = registry.get(&decl.declaration_type) else {
        return Vec::new();
    };
    let p = &manifest.platforms;
    let type_has = match platform {
        Platform::MacOS => p.macos,
        Platform::Ios => p.ios,
        Platform::TvOS => p.tvos,
        Platform::WatchOS => p.watchos,
        Platform::VisionOS => p.visionos,
        Platform::Windows => p.windows,
    };
    if !type_has {
        return vec![format!(
            "{} is not available on {} (Apple lists: {})",
            decl.declaration_type,
            platform.as_str(),
            p.to_vec().join(", ")
        )];
    }
    fn walk(
        obj: &serde_json::Map<String, serde_json::Value>,
        prefix: Option<&str>,
        manifest: &crate::schema::PayloadManifest,
        platform: crate::schema::Platform,
        out: &mut Vec<String>,
    ) {
        for (key, value) in obj {
            let path = prefix.map_or_else(|| key.clone(), |pre| format!("{pre}.{key}"));
            let Some(field) = manifest.fields.get(&path) else {
                continue; // unknown keys are the unknown-field check's to report
            };
            if !field.platforms.is_empty() && !field.platforms.contains(&platform) {
                out.push(format!(
                    "{path} is not available on {} (Apple offers it on: {})",
                    platform.as_str(),
                    field
                        .platforms
                        .iter()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if let serde_json::Value::Object(child) = value {
                walk(child, Some(&path), manifest, platform, out);
            }
        }
    }
    let root: serde_json::Map<String, serde_json::Value> = decl
        .payload
        .0
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut out = Vec::new();
    walk(&root, None, manifest, platform, &mut out);
    out.sort();
    out
}

/// Parse `--platform` / bundle `platforms` names, refusing an unknown one.
pub fn parse_platforms(names: &[String]) -> Result<Vec<crate::schema::Platform>> {
    names
        .iter()
        .map(|n| {
            crate::schema::Platform::from_cli_str(n).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown platform '{n}' (expected macOS, iOS, tvOS, watchOS or visionOS)"
                )
            })
        })
        .collect()
}

/// As [`declaration_errors`], with the delivery scope the MDM will use.
///
/// A DDM declaration does not state its own scope — the channel is the MDM's
/// choice at delivery time — so scope-dependent checks run only when the
/// caller supplies it. With `None`, only the scope-INDEPENDENT check runs:
/// a declaration whose keys demand opposite scopes is broken under any
/// channel, and saying so requires no assumption.
pub fn declaration_errors_scoped(
    decl: &Declaration,
    registry: &SchemaRegistry,
    scope: Option<crate::ddm::scope::Scope>,
) -> (Vec<String>, Vec<String>) {
    let mut errors = cross_key_errors(decl);
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
                for (label, parent_obj) in walk_payload_paths(&decl.payload.0, &ancestors) {
                    if !parent_obj.contains_key(&field.name) {
                        errors.push(format!("Missing required field: {label}.{}", field.name));
                    }
                }
            }
        }

        // Check for unknown fields, at the top level and inside every
        // dictionary the schema declares children for. The top level alone
        // let `Mail` written at the payload root — Apple nests it under
        // `Apps` — pass as a known field, since `Mail` exists by name.
        unknown_fields(&decl.payload.0, None, manifest, &mut warnings);

        // ...and inside every free-form (`ANY`) dictionary. Without this a
        // typo'd or foreign key — a PPPC service name in an app.settings
        // privacy block, say — is accepted in silence, because the check
        // above only sees the payload's top level.
        for any_field in manifest.fields.values().filter(|f| f.name == "ANY") {
            // The ANY node's own full path, e.g. Privacy.PermissionDefaults.ANY.
            let any_path = match &any_field.parent_key {
                Some(parent) => format!("{parent}.ANY"),
                None => "ANY".to_string(),
            };
            let legal: std::collections::BTreeSet<&str> = manifest
                .fields
                .values()
                .filter(|f| f.parent_key.as_deref() == Some(any_path.as_str()))
                .map(|f| f.name.as_str())
                .collect();
            if legal.is_empty() {
                continue;
            }
            for (label, obj) in walk_payload_paths(&decl.payload.0, std::slice::from_ref(&any_path))
            {
                for key in obj.keys() {
                    if !legal.contains(key.as_str()) {
                        warnings.push(format!(
                            "Unknown field: {label}.{key} (known: {})",
                            legal.iter().copied().collect::<Vec<_>>().join(", ")
                        ));
                    }
                }
            }
        }

        // ...and inside array elements, which the path walker cannot reach.
        let (element_errors, element_warnings) = array_element_findings(&decl.payload.0, manifest);
        errors.extend(element_errors);
        warnings.extend(element_warnings);

        // Check enum membership for fields that declare a rangelist.
        // Only fields with allowed_values are checked — no data, no opinion.
        for field_name in &manifest.field_order {
            let Some(field) = manifest.fields.get(field_name) else {
                continue;
            };
            if field.allowed_values.is_empty() {
                continue;
            }
            let sites: Vec<(String, &serde_json::Value)> = if field.parent_key.is_none() {
                decl.payload
                    .get(&field.name)
                    .map(|v| vec![(field.name.clone(), v)])
                    .unwrap_or_default()
            } else {
                let ancestors = resolve_ancestor_path(&field.name, manifest);
                walk_payload_paths(&decl.payload.0, &ancestors)
                    .into_iter()
                    .filter_map(|(label, obj)| {
                        obj.get(&field.name)
                            .map(|v| (format!("{label}.{}", field.name), v))
                    })
                    .collect()
            };
            for (label, value) in sites {
                // A rangelist on an Array field constrains its elements.
                let candidates: Vec<&serde_json::Value> = match value {
                    serde_json::Value::Array(items) => items.iter().collect(),
                    other => vec![other],
                };
                for candidate in candidates {
                    let text = match candidate {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        // Rangelists only ever constrain strings and numbers.
                        _ => continue,
                    };
                    if !field.allowed_values.contains(&text) {
                        errors.push(format!(
                            "Invalid value for {label}: \"{text}\" (allowed: {})",
                            field.allowed_values.join(", ")
                        ));
                    }
                }
            }
        }
    } else {
        // An unknown declaration type is a hard error, not a warning: the active
        // schema can't validate it at all. Mirrors `library validate`'s
        // `ddm-unknown-type` (error) and compose's fail-closed rejection. When
        // validating against the stable channel, the likely cause is a
        // pre-release OS seed type — hint at `--beta`.
        errors.push(format!(
            "Unknown declaration type: {} (not in the active schema; if this is a \
             pre-release OS seed type, re-run with --beta)",
            decl.declaration_type
        ));
    }

    // Delivery scope. Two failures, reported differently.
    if let Some(manifest_cap) = registry.get(&decl.declaration_type) {
        // Which keys the declaration actually sets, by schema name. Nested
        // keys count: app.settings' scope split is Privacy (user) against
        // Allowed.DeniedBinaries (system), and the latter is a subkey. A
        // field is "present" when the declaration sets it anywhere its path
        // resolves — walk_payload_paths already expands ANY nodes.
        let present: std::collections::BTreeSet<String> = manifest_cap
            .fields
            .values()
            .filter(|f| {
                if f.parent_key.is_none() {
                    decl.payload.get(&f.name).is_some()
                } else {
                    let ancestors = resolve_ancestor_path(&f.name, manifest_cap);
                    walk_payload_paths(&decl.payload.0, &ancestors)
                        .into_iter()
                        .any(|(_, obj)| obj.contains_key(&f.name))
                }
            })
            .map(|f| f.name.clone())
            .collect();

        // Scope-independent, so it needs no --scope and cannot false-positive
        // on a guessed channel. This is the check that earns the feature.
        for pair in crate::ddm::scope::unsatisfiable_pairs(
            manifest_cap,
            crate::schema::Platform::MacOS,
            &present,
        ) {
            errors.push(pair.to_string());
        }

        // Scope, in order: what the declaration itself carries, then what
        // the caller supplied — a Fleet-targeted declaration states it, so
        // the check needs no flag there.
        //
        // `PayloadScope` is Fleet-specific: it is not in Apple's DDM spec
        // (the key lives in mdm/profiles/TopLevel.yaml and appears nowhere
        // under declarative/). Fleet reads it to choose the channel; every
        // other MDM ignores it. Say so, so nobody reads its presence as a
        // guarantee — and validate the value, since a typo reverts to
        // Fleet's "System" default silently.
        if let Some(raw) = decl.payload_scope.as_deref() {
            match crate::ddm::scope::Scope::parse(raw) {
                Some(crate::ddm::scope::Scope::User) => warnings.push(format!(
                    "PayloadScope \"{raw}\" is a Fleet-specific key, not part of \
                     Apple's DDM spec — Fleet delivers this on the user channel, \
                     other MDMs ignore the key and use their own default"
                )),
                Some(crate::ddm::scope::Scope::System) => warnings.push(format!(
                    "PayloadScope \"{raw}\" is a Fleet-specific key, not part of \
                     Apple's DDM spec. System is Fleet's default, so this states \
                     the existing behaviour"
                )),
                None => errors.push(format!(
                    "PayloadScope \"{raw}\" is not a valid value: Fleet accepts \
                     \"System\" or \"User\" (User is macOS only). An unrecognised \
                     value falls back to System, so the declaration would be \
                     delivered on the device channel"
                )),
            }
        }

        let delivered = decl
            .payload_scope
            .as_deref()
            .and_then(crate::ddm::scope::Scope::parse)
            .or(scope);

        if let Some(delivered_in) = delivered {
            for conflict in crate::ddm::scope::key_conflicts(
                manifest_cap,
                crate::schema::Platform::MacOS,
                &present,
                delivered_in,
            ) {
                errors.push(conflict.to_string());
            }
            if let Some(allowed) = crate::ddm::scope::payload_out_of_scope(
                manifest_cap,
                crate::schema::Platform::MacOS,
                delivered_in,
            ) {
                warnings.push(format!(
                    "{} is {}-scope only on macOS; delivered in {delivered_in} scope the \
                     whole declaration is accepted and ignored",
                    decl.declaration_type,
                    allowed
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("/"),
                ));
            }
        }
    }

    // app.settings privacy keys are "<bundle id> {<designated requirement>}".
    // Apple types the key as a free-form string, so a bare bundle identifier
    // is schema-valid and matches no app: the declaration deploys, reports
    // Verified and manages nothing. A warning rather than an error — the key
    // format is documented behaviour rather than something Apple's schema
    // states, so this flags it without failing a deployment outright.
    if decl.declaration_type == "com.apple.configuration.app.settings" {
        let defaults = decl
            .payload
            .get("Privacy")
            .and_then(|p| p.get("PermissionDefaults"))
            .and_then(serde_json::Value::as_object);
        for key in defaults.into_iter().flat_map(serde_json::Map::keys) {
            let trimmed = key.trim();
            let braced = trimmed.contains('{') && trimmed.ends_with('}');

            // Parentheses are the near-miss worth naming on its own: the
            // requirement IS there, so "carries no designated requirement"
            // would send the operator looking for the wrong thing.
            if !braced && trimmed.contains('(') && trimmed.ends_with(')') {
                warnings.push(format!(
                    "Privacy.PermissionDefaults key \"{key}\" wraps its designated \
                     requirement in parentheses. It must be curly braces — \
                     \"<bundle id> {{<requirement>}}\" — or the entry matches no app."
                ));
                continue;
            }

            if !braced {
                warnings.push(format!(
                    "Privacy.PermissionDefaults key \"{key}\" carries no designated \
                     requirement. The key must be \"<bundle id> {{<requirement>}}\"; \
                     without it the entry matches no app. `contour profile ddm \
                     app-privacy scan` reads the requirement from the installed app."
                ));
                continue;
            }

            // Only the identifier, not the requirement: the requirement's own
            // body legitimately quotes things (`identifier "us.zoom.xos"`).
            let identifier = trimmed.split('{').next().unwrap_or_default().trim();
            if identifier.starts_with('"') || identifier.ends_with('"') {
                warnings.push(format!(
                    "Privacy.PermissionDefaults key \"{key}\" wraps its app identifier \
                     in double quotes. The identifier is bare — \
                     \"<bundle id> {{<requirement>}}\" — and quoting it makes the \
                     declaration invalid."
                ));
            }
        }
    }

    // app.settings binary entries: Apple's per-list identifier rules. These
    // live in the schema's notes rather than its structure, so no generic
    // check can see them — an entry of only PathPrefix is schema-shaped and
    // rejected on the device. Santa's validator already encodes them.
    if decl.declaration_type == "com.apple.configuration.app.settings" {
        use santa::app_settings::{BinaryIdentifier, BinaryPolicy, validate_binary};
        for (key, policy) in [
            ("AllowedBinaries", BinaryPolicy::Allow),
            ("DeniedBinaries", BinaryPolicy::Deny),
        ] {
            let items = decl
                .payload
                .get("Allowed")
                .and_then(|a| a.get(key))
                .and_then(serde_json::Value::as_array);
            for (i, item) in items.into_iter().flatten().enumerate() {
                // A wrapped element is already reported, and would only
                // re-surface here as a missing identifier.
                if item.get("BinaryIdentifier").is_some() {
                    continue;
                }
                let Ok(entry) = serde_json::from_value::<BinaryIdentifier>(item.clone()) else {
                    continue; // a bad SigningState is reported as an enum value
                };
                if let Err(reason) = validate_binary(&entry, policy) {
                    errors.push(format!("Allowed.{key}[{i}]: {reason}"));
                }
            }
        }
    }

    // Basic structural validation
    if decl.identifier.is_empty() {
        errors.push("Identifier is empty".to_string());
    }
    if decl.declaration_type.is_empty() {
        errors.push("Type is empty".to_string());
    }

    (errors, warnings)
}

/// Validate a single DDM declaration file.
fn validate_single_ddm(
    path: &Path,
    registry: &SchemaRegistry,
    platforms: &[crate::schema::Platform],
) -> Result<DdmValidationResult> {
    let decl = parse_declaration_file(path)?;
    let (errors, mut warnings) = declaration_errors(&decl, registry);
    for p in platforms {
        warnings.extend(platform_findings(&decl, registry, *p));
    }
    Ok(DdmValidationResult {
        file: path.to_path_buf(),
        declaration_type: decl.declaration_type.clone(),
        valid: errors.is_empty(),
        errors,
        warnings,
    })
}

/// Validate DDM declaration(s) against embedded schema
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_ddm_validate(
    paths: &[String],
    schema_path: Option<&str>,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    beta: bool,
    platforms: &[String],
    output_mode: OutputMode,
) -> Result<()> {
    let platforms = parse_platforms(platforms)?;
    let files = collect_ddm_files(paths, recursive, max_depth);

    if files.is_empty() {
        if output_mode == OutputMode::Json {
            println!("[]");
        } else {
            println!("{}", "No DDM JSON files found.".yellow());
        }
        return Ok(());
    }

    // Load schema registry once (beta seed schema when requested).
    let registry = load_registry_opts(schema_path, beta)?;

    let results: Vec<DdmValidationResult> = if parallel && files.len() > 1 {
        files
            .par_iter()
            .filter_map(|f| validate_single_ddm(f, &registry, &platforms).ok())
            .collect()
    } else {
        files
            .iter()
            .filter_map(|f| validate_single_ddm(f, &registry, &platforms).ok())
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

/// Substring search across DDM declaration types. Mirrors `profile search`
/// but scoped to `ddm-*` categories so callers don't have to filter
/// `ddm list | grep` themselves.
pub fn handle_ddm_search(
    query: &str,
    schema_path: Option<&str>,
    beta: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = load_registry_opts(schema_path, beta)?;
    let mut results: Vec<_> = registry
        .search(query)
        .into_iter()
        .filter(|m| m.category.starts_with("ddm-"))
        .collect();
    results.sort_by(|a, b| a.payload_type.cmp(&b.payload_type));

    if output_mode == OutputMode::Json {
        let list: Vec<_> = results
            .iter()
            .map(|m| {
                serde_json::json!({
                    "type": m.payload_type,
                    "title": m.title,
                    "category": m.category.strip_prefix("ddm-").unwrap_or(&m.category),
                    "kind": m.kind.map(|k| k.as_str()),
                    "platforms": m.platforms.to_vec(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(());
    }

    if results.is_empty() {
        println!("No DDM declaration types match '{query}'.");
        return Ok(());
    }

    println!(
        "{} DDM declaration type(s) match '{}':\n",
        results.len().to_string().bold(),
        query.bold()
    );
    for m in &results {
        let cat = m.category.strip_prefix("ddm-").unwrap_or(&m.category);
        let platforms = m.platforms.to_vec().join(", ");
        println!(
            "  • {} — {} [{}] ({})",
            m.payload_type.cyan().bold(),
            m.title,
            cat.magenta(),
            platforms
        );
    }
    Ok(())
}

/// List available DDM declaration types from embedded schema
pub fn handle_ddm_list(
    category: Option<&str>,
    schema_path: Option<&str>,
    beta: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = load_registry_opts(schema_path, beta)?;

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
                    "kind": m.kind.map(|k| k.as_str()),
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
    beta: bool,
    full: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = load_registry_opts(schema_path, beta)?;

    let manifest = registry.get_by_name(name).ok_or_else(|| {
        let channel = if beta {
            crate::schema::Channel::Beta
        } else {
            crate::schema::Channel::Stable
        };
        if let Some(hint) = crate::schema::suggest_other_channel(name, channel, true) {
            return anyhow::anyhow!("DDM declaration type '{name}' not found.\n{hint}");
        }
        anyhow::anyhow!(
            "DDM declaration type '{name}' not found.\nUse 'contour profile ddm list' to see available types."
        )
    })?;

    // Verify it's a DDM declaration
    if !manifest.category.starts_with("ddm-") {
        anyhow::bail!(
            "'{name}' is a profile payload type, not a DDM declaration.\nUse 'contour profile info {name}' for profile schemas."
        );
    }

    if output_mode == OutputMode::Json {
        // A projection of the schema, not a curated subset: titles,
        // descriptions, bounds, validator hints, asset types and merge
        // semantics all reach the surface. A field absent from the schema
        // emits null — never a default, because "unspecified" and "none"
        // differ.
        let fields: Vec<_> = manifest
            .fields_in_order()
            .map(|f| {
                let mut entry = serde_json::json!({
                    "name": f.name,
                    // Identity. Not the leaf name: a payload may carry the
                    // same name under two parents.
                    "path": f.path,
                    "type": f.field_type.as_str(),
                    "plist_tag": crate::cli::info::plist_tag_for(&f.field_type),
                    "title": (!f.title.is_empty()).then(|| f.title.clone()),
                    "description": (!f.description.is_empty())
                        .then(|| f.description.clone()),
                    "required": f.flags.required,
                    "supervised": f.flags.supervised,
                    "sensitive": f.flags.sensitive,
                    "default": f.default,
                    "allowed_values": f.allowed_values,
                    "range": match (f.range_min, f.range_max) {
                        (None, None) => serde_json::Value::Null,
                        (min, max) => serde_json::json!({ "min": min, "max": max }),
                    },
                    "subtype": f.subtype,
                    "format": f.format,
                    "asset_types": (!f.asset_types.is_empty())
                        .then(|| f.asset_types.clone()),
                    "combinetype": f.combinetype,
                    // Per platform, never unioned: Apple states these per
                    // platform and the platforms disagree.
                    "allowed_scopes": (!f.allowed_scopes.is_empty()).then(|| {
                        f.allowed_scopes
                            .iter()
                            .map(|(p, v)| (p.as_str().to_string(), v.clone()))
                            .collect::<std::collections::BTreeMap<_, _>>()
                    }),
                    "introduced_by_platform": (!f.introduced_by_platform.is_empty())
                        .then(|| {
                            f.introduced_by_platform
                                .iter()
                                .map(|(p, v)| (p.as_str().to_string(), v.clone()))
                                .collect::<std::collections::BTreeMap<_, _>>()
                        }),
                    "deprecated_in": f.deprecated_in,
                    // Hierarchy: depth and immediate parent, so consumers can
                    // reconstruct the nested dictionary structure.
                    "depth": f.depth,
                    "parent": f.parent_key,
                });
                entry
                    .as_object_mut()
                    .expect("json! object")
                    .extend(crate::cli::info::dynamic_keys_json(manifest, f));
                entry
            })
            .collect();

        let mut info = serde_json::json!({
            "type": manifest.payload_type,
            "title": manifest.title,
            "description": manifest.description,
            "category": manifest.category.strip_prefix("ddm-").unwrap_or(&manifest.category),
            "kind": manifest.kind.map(|k| k.as_str()),
            "authorable": manifest.is_authorable(),
            // Declarations have no .mobileconfig envelope; present as null so
            // the key is always there.
            "nesting": crate::schema::form::default_nesting(crate::schema::form::kind_of(manifest)),
            "platforms": manifest.platforms.to_vec(),
            // Per platform, never unioned. `profile info` has emitted this
            // since 0.4.1; this surface lagged behind it. A consumer that
            // unions these gets `["system","user"]` for safari.settings — a
            // value true on no platform.
            "os_support": crate::cli::info::os_support_json_map(manifest, None),
            "fields": fields,
            "beta_only": crate::ddm::notes::is_beta_only(&manifest.payload_type),
            "deployment_notes": crate::ddm::notes::notes_for(&manifest.payload_type),
        });
        info.as_object_mut()
            .expect("json! object")
            .extend(crate::cli::info::root_dynamic_keys_json(manifest));
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
    crate::cli::info::print_os_support(manifest, None);
    println!("\n{}", "Description:".cyan());
    println!("  {}", manifest.description);

    // Show fields. Top-level keys always; nested keys when `--full` is set
    // (otherwise each dictionary is annotated with its nested-key count).
    let top = manifest.top_level_fields();
    if !top.is_empty() {
        let total = manifest.fields.len();
        let header = if full || total == top.len() {
            format!("Payload Keys ({total})")
        } else {
            format!("Payload Keys ({} top-level, {total} total)", top.len())
        };
        println!("\n{}:", header.cyan().bold());
        for field in &top {
            print_ddm_field(manifest, field, 1, full);
        }
        if !full && total > top.len() {
            println!(
                "\n  {}",
                "Pass --full to expand nested dictionary keys.".dimmed()
            );
        }
    }

    // Required-fields summary — use dotted paths so nested requireds
    // (e.g. Allowed.AllowedApps.AppIdentifier) are unambiguous.
    let mut required: Vec<String> = manifest
        .required_fields()
        .iter()
        // The field's own path. This looked the field up by its leaf name,
        // which matches nothing nested in a path-keyed map, so it printed
        // `Identifier` six times for six different fields.
        .map(|f| f.path.clone())
        .collect();
    required.sort();
    if !required.is_empty() {
        println!("\n{}: {}", "Required fields".red(), required.join(", "));
    }

    print_deployment_notes(&manifest.payload_type);
    Ok(())
}

/// Print the pre-release flag + deployment caveats for a declaration type, so
/// the operator knows what else is needed to actually deploy it.
fn print_deployment_notes(declaration_type: &str) {
    let beta_only = crate::ddm::notes::is_beta_only(declaration_type);
    let notes = crate::ddm::notes::notes_for(declaration_type);
    if !beta_only && notes.is_empty() {
        return;
    }
    println!("\n{}", "Deployment notes:".yellow().bold());
    if beta_only {
        println!(
            "  • {}",
            "Pre-release — this type is in the OS 27 beta seed only; keys may still change."
                .dimmed()
        );
    }
    for n in notes {
        println!("  • {n}");
    }
}

/// Render one schema field and (recursively, when `recurse`) its nested
/// children as an indented tree. A dictionary with children shows its
/// nested-key count even when not recursing.
fn print_ddm_field(
    manifest: &crate::schema::PayloadManifest,
    field: &crate::schema::FieldDefinition,
    indent: usize,
    recurse: bool,
) {
    let pad = "  ".repeat(indent);
    let children = manifest.children_of(&field.path);
    let type_label = if children.is_empty() {
        field.field_type.as_str().to_string()
    } else {
        let n = children.len();
        let noun = if n == 1 { "key" } else { "keys" };
        format!("{}, {n} {noun}", field.field_type.as_str())
    };
    let req = if field.flags.required {
        " [required]".red().to_string()
    } else {
        String::new()
    };
    println!(
        "{pad}{} ({}){}",
        field.name.yellow(),
        type_label.dimmed(),
        req
    );
    if let Some(ref default) = field.default {
        println!("{pad}  Default: {}", default.dimmed());
    }
    if !field.allowed_values.is_empty() {
        println!(
            "{pad}  Allowed: {}",
            field.allowed_values.join(", ").dimmed()
        );
    }
    if recurse {
        for child in children {
            print_ddm_field(manifest, child, indent + 1, true);
        }
    }
}

/// `ddm map` — surface the legacy MDM → DDM migration mapping: the DDM
/// equivalent for a profile payload type, plus per-key detail (keys that
/// carry over directly, keys that are renamed/restructured, and keys with
/// no DDM equivalent). With no `name`, prints the whole table + coverage.
pub fn handle_ddm_map(name: Option<&str>, output_mode: OutputMode) -> Result<()> {
    use crate::migrate::mapping::{MigrationRegistry, MigrationStatus};
    let registry = MigrationRegistry::new();

    // Whole-table mode.
    let Some(query) = name else {
        let mut all: Vec<_> = registry.all().collect();
        all.sort_by_key(|m| m.mdm_type);
        if output_mode == OutputMode::Json {
            let stats = registry.stats();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "mappings": all,
                    "stats": {
                        "total": stats.total,
                        "available": stats.available,
                        "partial": stats.partial,
                        "legacy": stats.legacy,
                        "none": stats.none,
                    },
                }))?
            );
            return Ok(());
        }
        println!("{}\n", "Legacy MDM → DDM migration map".bold());
        for m in &all {
            println!(
                "  {:<11} {}  {}  {}",
                format!("[{}]", m.status.as_str()).dimmed(),
                m.mdm_type.yellow(),
                "→".dimmed(),
                m.ddm_type.cyan()
            );
        }
        let s = registry.stats();
        println!(
            "\n{} types: {} available, {} partial, {} legacy, {} none",
            s.total, s.available, s.partial, s.legacy, s.none
        );
        println!(
            "{}",
            "\nRun `contour profile ddm map <mdm-type>` for per-key detail.".dimmed()
        );
        return Ok(());
    };

    // Single-type mode — exact key, else a unique fuzzy match.
    let mapping = registry.get(query).or_else(|| {
        let hits = registry.search(query);
        if hits.len() == 1 { Some(hits[0]) } else { None }
    });
    let Some(m) = mapping else {
        let hits = registry.search(query);
        if hits.is_empty() {
            anyhow::bail!(
                "No migration mapping for '{query}'.\nRun `contour profile ddm map` to list all mapped types."
            );
        }
        let names: Vec<&str> = hits.iter().map(|h| h.mdm_type).collect();
        anyhow::bail!("'{query}' is ambiguous. Did you mean: {}", names.join(", "));
    };

    let moved = moved_keys(m.mdm_type);

    if output_mode == OutputMode::Json {
        let mut v = serde_json::to_value(m)?;
        v["moved_to"] = serde_json::json!(
            moved
                .iter()
                .map(|(decl, keys)| (
                    decl.clone(),
                    keys.iter()
                        .map(|(k, to)| serde_json::json!({"key": k, "ddm_key": to}))
                        .collect::<Vec<_>>()
                ))
                .collect::<std::collections::BTreeMap<_, _>>()
        );
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }

    println!(
        "{}  {}  {}   {}",
        m.mdm_type.yellow().bold(),
        "→".dimmed(),
        m.ddm_type.cyan().bold(),
        format!("[{}]", m.status.as_str()).dimmed()
    );
    println!("{}\n", m.notes);
    if m.status == MigrationStatus::None {
        println!(
            "{}",
            "No DDM migration path — keep the legacy profile.".dimmed()
        );
        return Ok(());
    }

    if !m.direct_keys.is_empty() {
        println!(
            "{} ({}) {}",
            "Direct keys".green().bold(),
            m.direct_keys.len(),
            "— same key name in DDM:".dimmed()
        );
        println!("  {}", m.direct_keys.join(", "));
    }
    if !m.transformed_keys.is_empty() {
        println!(
            "\n{} ({}) {}",
            "Transformed keys".yellow().bold(),
            m.transformed_keys.len(),
            "— renamed / restructured:".dimmed()
        );
        for (old, new) in m.transformed_keys {
            println!("  {} {} {}", old.yellow(), "→".dimmed(), new.cyan());
        }
    }
    if !m.unsupported_keys.is_empty() {
        println!(
            "\n{} ({}) {}",
            "Unsupported keys".red().bold(),
            m.unsupported_keys.len(),
            "— no DDM equivalent:".dimmed()
        );
        println!("  {}", m.unsupported_keys.join(", "));
    }
    if !moved.is_empty() {
        let n: usize = moved.values().map(Vec::len).sum();
        println!(
            "\n{} ({n}) {}",
            "Moved to other declarations".green().bold(),
            "— Apple's notes on each key name the replacement:".dimmed()
        );
        for (decl, keys) in &moved {
            println!("  {}", decl.cyan());
            for (k, to) in keys {
                match to {
                    Some(t) => println!("    {} {} {}", k.yellow(), "→".dimmed(), t),
                    None => println!("    {}", k.yellow()),
                }
            }
        }
    }
    Ok(())
}

/// Keys of a profile payload that Apple deprecated in favour of a named
/// declaration, grouped by that declaration, each with its matching key
/// there when one is found.
///
/// The source is Apple's own note on the key — "Deprecated: use the
/// declarative management `…` configuration." — so a new move in the data
/// shows up here without a hand-kept list going stale.
fn moved_keys(mdm_type: &str) -> std::collections::BTreeMap<String, Vec<(String, Option<String>)>> {
    let mut out: std::collections::BTreeMap<String, Vec<(String, Option<String>)>> =
        std::collections::BTreeMap::new();
    let Ok(registry) = SchemaRegistry::embedded() else {
        return out;
    };
    let Some(manifest) = registry.get(mdm_type) else {
        return out;
    };
    const MARK: &str = "Deprecated: use the declarative management `";
    for path in &manifest.field_order {
        let Some(field) = manifest.fields.get(path) else {
            continue;
        };
        let Some(rest) = field.description.split(MARK).nth(1) else {
            continue;
        };
        let Some(decl) = rest
            .split('`')
            .next()
            .filter(|d| d.starts_with("com.apple."))
        else {
            continue;
        };
        let to = registry
            .get(decl)
            .and_then(|target| matching_key(&field.name, target));
        out.entry(decl.to_string())
            .or_default()
            .push((field.name.clone(), to));
    }
    out
}

/// The key in `target` a restriction key corresponds to, by name alone:
/// `allowGenmoji` → `AllowGenmoji`, `allowMailSummary` →
/// `Apps.Mail.AllowSummary`. Exact after normalising, never fuzzy — a key
/// that matches nothing is reported without a partner rather than paired
/// with a guess.
fn matching_key(restriction: &str, target: &contour_form::PayloadManifest) -> Option<String> {
    let norm = |s: &str| s.to_ascii_lowercase();
    let bare = |s: &str| {
        let l = norm(s);
        l.strip_prefix("allow").map(str::to_string).unwrap_or(l)
    };
    let want_full = norm(restriction);
    let want_bare = bare(restriction);
    let mut hits = target.field_order.iter().filter(|path| {
        let segments: Vec<&str> = path.split('.').filter(|s| *s != "Apps").collect();
        let Some((leaf, parents)) = segments.split_last() else {
            return false;
        };
        let full: String = parents.iter().map(|p| norm(p)).collect::<String>() + &norm(leaf);
        let stripped: String = parents.iter().map(|p| norm(p)).collect::<String>() + &bare(leaf);
        full == want_full || stripped == want_bare
    });
    let first = hits.next()?.clone();
    // Two candidates is no answer.
    hits.next().is_none().then_some(first)
}

/// `ddm coverage` — how much of the legacy MDM surface has a declarative
/// (DDM) equivalent today, and what still requires legacy configuration
/// profiles. Combines the migration registry (assessed types, by status)
/// with the embedded schema counts (DDM declaration vs. profile payload
/// types). Honors `--channel` so the schema counts reflect the seed.
pub fn handle_ddm_coverage(channel: crate::schema::Channel, output_mode: OutputMode) -> Result<()> {
    use crate::migrate::mapping::{MigrationRegistry, MigrationStatus};
    let migration = MigrationRegistry::new();
    let stats = migration.stats();
    if channel.is_beta() {
        note_if_beta_is_retired();
    }
    let registry = SchemaRegistry::embedded_channel(channel)?;
    let schema = registry.stats();

    // The gap: types with no native DDM equivalent — `legacy` (wrap in
    // com.apple.configuration.legacy) and `none` (no path at all).
    let mut gap: Vec<_> = migration.by_status(MigrationStatus::Legacy);
    gap.extend(migration.by_status(MigrationStatus::None));
    gap.sort_by_key(|m| m.mdm_type);

    // Apple profile payload types with no migration assessment at all.
    let assessed: std::collections::HashSet<&str> = migration.all().map(|m| m.mdm_type).collect();
    let unassessed = registry
        .all()
        .filter(|m| m.category == "apple")
        .filter(|m| !assessed.contains(m.payload_type.as_str()))
        .count();

    if output_mode == OutputMode::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "channel": channel.to_string(),
                "assessed_total": stats.total,
                "available": stats.available,
                "partial": stats.partial,
                "legacy": stats.legacy,
                "none": stats.none,
                "native_ddm_coverage_pct": stats.ddm_coverage(),
                "requires_legacy": gap.iter().map(|m| serde_json::json!({
                    "mdm_type": m.mdm_type,
                    "status": m.status.as_str(),
                    "ddm_type": m.ddm_type,
                })).collect::<Vec<_>>(),
                "schema": {
                    "ddm_declaration_types": schema.ddm_count,
                    "apple_profile_types": schema.apple_count,
                    "apple_unassessed": unassessed,
                },
            }))?
        );
        return Ok(());
    }

    println!(
        "{}  {}",
        "DDM Migration Coverage".bold(),
        format!("(channel: {channel})").dimmed()
    );
    println!("\nLegacy MDM types assessed: {}", stats.total);
    println!(
        "  {:<10} {:>3}  {}",
        "available",
        stats.available,
        "— direct DDM equivalent".dimmed()
    );
    println!(
        "  {:<10} {:>3}  {}",
        "partial",
        stats.partial,
        "— some keys migrate; rest stay legacy".dimmed()
    );
    println!(
        "  {:<10} {:>3}  {}",
        "legacy",
        stats.legacy,
        "— no native DDM; wrap in com.apple.configuration.legacy".dimmed()
    );
    println!(
        "  {:<10} {:>3}  {}",
        "none",
        stats.none,
        "— no DDM path at all".dimmed()
    );
    println!(
        "\nNative DDM coverage: {:.0}% ({} of {} assessed types fully or partially declarative)",
        stats.ddm_coverage(),
        stats.available + stats.partial,
        stats.total
    );

    if !gap.is_empty() {
        println!(
            "\n{} ({}):",
            "Still require legacy profiles".yellow().bold(),
            gap.len()
        );
        for m in &gap {
            println!(
                "  {} {} {}",
                m.mdm_type.yellow(),
                "→".dimmed(),
                m.ddm_type.dimmed()
            );
        }
    }

    println!(
        "\n{}",
        format!(
            "Schema ({channel}): {} DDM declaration types · {} apple profile payload types ({unassessed} not yet assessed for DDM migration).",
            schema.ddm_count, schema.apple_count
        )
        .dimmed()
    );
    Ok(())
}

/// `parent` value for keys that sit directly in a declaration's Payload and
/// so have no parent field to name.
const TOP_LEVEL: &str = "";

/// Sibling keys that cannot coexist, per Apple's prose cross-key rules (see
/// `cross_key_errors`), so contour never produces a document its own
/// validator rejects.
///
/// `parent` is the immediate parent's leaf name, or [`TOP_LEVEL`].
///
/// The slice is in PREFERENCE order: `--full` emits the first member the
/// manifest actually carries and skips the rest. Preference rather than
/// encounter order, because `field_order` would otherwise decide — and for
/// app.managed it reaches AppComposedIdentifier first, the one member that
/// is unavailable on iOS.
fn exclusive_siblings(payload_type: &str, parent: &str) -> &'static [&'static str] {
    match (payload_type, parent) {
        ("com.apple.configuration.softwareupdate.settings", "Beta") => {
            &["OfferPrograms", "RequireProgram"]
        }
        // app.managed.yaml repeats this under all four keys: "Only one of
        // `AppStoreID`, `BundleID`, `ManifestURL`, or `AppComposedIdentifier`
        // needs to be present."
        //
        // BundleID leads because it is the only member valid on both macOS
        // and iOS — ManifestURL is `introduced: n/a` on macOS, and
        // AppComposedIdentifier is `n/a` on iOS. AppStoreID follows: it is
        // the App Store and VPP case, and what Apple's own example1.json uses.
        ("com.apple.configuration.app.managed", TOP_LEVEL) => &[
            "BundleID",
            "AppStoreID",
            "ManifestURL",
            "AppComposedIdentifier",
        ],
        _ => &[],
    }
}

/// Which alternatives the scaffold dropped, and what it kept instead.
struct ExclusiveChoice {
    chosen: String,
    omitted: Vec<String>,
}

/// The member of an exclusive `group` that `--full` should emit: the first
/// listed that this manifest actually carries, so a platform-filtered schema
/// still illustrates one of them rather than none.
fn preferred_exclusive(
    group: &[&'static str],
    parent_path: &str,
    manifest: &crate::schema::PayloadManifest,
) -> Option<&'static str> {
    // `group` holds bare leaf names, because that is how Apple's prose names
    // them. Fields are addressed by path, so compose one: the `Beta` group's
    // members live at `Beta.OfferPrograms`, not `OfferPrograms`.
    group.iter().copied().find(|k| {
        let path = crate::schema::FieldDefinition::compose_path(
            (!parent_path.is_empty()).then_some(parent_path),
            k,
        );
        manifest.field_by_path(&path).is_some()
    })
}

/// A per-type sentence naming when to reach for one of the omitted keys.
fn exclusive_hint(payload_type: &str) -> Option<&'static str> {
    match payload_type {
        "com.apple.configuration.app.managed" => Some(
            "Use AppStoreID instead for an App Store or VPP app, or ManifestURL \
             for a self-hosted iOS app (macOS: n/a).",
        ),
        _ => None,
    }
}

/// Scaffold the declaration's top-level Payload.
///
/// Top-level fields only — nested children are emitted by the Dictionary arm
/// of `generate_field_value`, driven by each field's `parent_key`. Emitting
/// nested fields at the top level would flatten the structure and (for
/// required children of optional parents) create invalid docs that fail
/// `ddm validate`.
fn build_top_level_payload(
    manifest: &crate::schema::PayloadManifest,
    full: bool,
) -> (DeclarationPayload, Option<ExclusiveChoice>) {
    let exclusive = exclusive_siblings(&manifest.payload_type, TOP_LEVEL);
    let preferred = preferred_exclusive(exclusive, TOP_LEVEL, manifest);
    let mut payload = DeclarationPayload::new();
    let mut omitted = Vec::new();

    for field_name in &manifest.field_order {
        let Some(field) = manifest.fields.get(field_name) else {
            continue;
        };
        if field.parent_key.is_some() {
            continue;
        }
        if !field.flags.required && !full {
            continue;
        }
        // A root-level marker means the declaration itself is keyed by the
        // operator; there is nothing to emit for it.
        if field.is_placeholder() {
            continue;
        }
        // Mutually exclusive: emit the preferred member, record the rest.
        if exclusive.contains(&field_name.as_str()) && preferred != Some(field_name.as_str()) {
            omitted.push(field_name.clone());
            continue;
        }
        payload.insert(
            field_name.clone(),
            generate_field_value(field_name, field, manifest, full),
        );
    }

    let choice = match (preferred, omitted.is_empty()) {
        (Some(chosen), false) => Some(ExclusiveChoice {
            chosen: chosen.to_string(),
            omitted,
        }),
        _ => None,
    };
    (payload, choice)
}

/// Generate a default JSON value for a field, recursively populating Dictionary children.
///
/// Required children are always emitted so that optional parents remain valid when
/// included (matches the validator's rule: "if parent is present, required children
/// must be present"). When `full` is true, optional children are included as well.
fn generate_field_value(
    field_path: &str,
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

    // Defaultless enum fields scaffold as their first allowed value — the
    // fail-closed gate rejects anything outside the rangelist, `""` included.
    if !field.allowed_values.is_empty()
        && matches!(field.field_type, FieldType::String | FieldType::Integer)
    {
        let first = &field.allowed_values[0];
        return match field.field_type {
            FieldType::Integer => first
                .parse::<i64>()
                .map_or_else(|_| serde_json::Value::String(first.clone()), |n| n.into()),
            _ => serde_json::Value::String(first.clone()),
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
            // `parent_key` is a FULL dotted path ("Calculator.BasicMode"), not
            // an immediate name, so children are matched against the path this
            // field was reached by. Comparing against the bare field name
            // matched only depth-1 children, and everything deeper was dropped
            // — including required ones, which is how `--full` emitted a parent
            // object without the children its schema demands.
            let parsed = crate::schema::FieldPath::parse(field_path);
            let leaf = parsed.leaf().unwrap_or(field_path);
            let exclusive = exclusive_siblings(&manifest.payload_type, leaf);
            let preferred = preferred_exclusive(exclusive, field_path, manifest);
            let mut obj = serde_json::Map::new();
            for child_name in &manifest.field_order {
                let Some(child) = manifest.fields.get(child_name) else {
                    continue;
                };
                if child.parent_key.as_deref() != Some(field_path) {
                    continue;
                }
                // `ANY` / `{{key}}` / `{{value}}` describe the operator's
                // keys; they are not keys. The dictionary is left for the
                // operator to fill — `ddm info` reports its value_shape.
                if child.is_placeholder() {
                    continue;
                }
                if !child.flags.required && !full {
                    continue;
                }
                // `child_name` walks field_order, which holds PATHS. The
                // exclusive groups are bare leaf names and the emitted JSON
                // key must be the leaf too — a document keyed
                // `Beta.OfferPrograms` is not the document Apple's schema
                // describes.
                if exclusive.contains(&child.name.as_str())
                    && preferred != Some(child.name.as_str())
                {
                    continue;
                }
                obj.insert(
                    child.name.clone(),
                    generate_field_value(&child.path, child, manifest, full),
                );
            }
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::String(String::new()),
    }
}

/// Generate a DDM declaration JSON from schema
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_ddm_generate(
    name: &str,
    output: Option<&str>,
    full: bool,
    org: Option<&str>,
    identifier: Option<&str>,
    schema_path: Option<&str>,
    payload_file: Option<&str>,
    beta: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = load_registry_opts(schema_path, beta)?;

    let manifest = registry.get_by_name(name).ok_or_else(|| {
        let channel = if beta {
            crate::schema::Channel::Beta
        } else {
            crate::schema::Channel::Stable
        };
        if let Some(hint) = crate::schema::suggest_other_channel(name, channel, true) {
            return anyhow::anyhow!("DDM declaration type '{name}' not found.\n{hint}");
        }
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
    let (mut payload, exclusive_choice) = build_top_level_payload(manifest, full);

    // Merge an explicit payload file (JSON or TOML) over the schema skeleton —
    // e.g. {"hello":"world"} fills a `com.apple.management.properties` Payload.
    if let Some(pf) = payload_file {
        let text =
            std::fs::read_to_string(pf).with_context(|| format!("reading payload file '{pf}'"))?;
        let is_toml = Path::new(pf)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
        let map: serde_json::Map<String, serde_json::Value> = if is_toml {
            let v: toml::Value =
                toml::from_str(&text).with_context(|| format!("parsing TOML payload '{pf}'"))?;
            serde_json::to_value(v)?
                .as_object()
                .cloned()
                .unwrap_or_default()
        } else {
            serde_json::from_str(&text).with_context(|| format!("parsing JSON payload '{pf}'"))?
        };
        for (k, v) in map {
            payload.insert(k, v);
        }
    }

    // Build identifier.
    // --identifier is used verbatim; otherwise domain: --org → profile.toml →
    // CONTOUR_ORG → .contour/config.toml → error.
    // Refuse silent "com.example" defaulting — DDM declarations are deployable
    // and an example-domain identifier collides across orgs.
    let short_name = manifest
        .payload_type
        .split('.')
        .next_back()
        .unwrap_or("declaration");
    let identifier = resolve_declaration_identifier(identifier, org, config, short_name)?;

    let decl = Declaration {
        payload_scope: None,
        declaration_type: manifest.payload_type.clone(),
        identifier,
        server_token: None,
        authentication: None,
        payload,
    };

    // Fail-closed: never write a schema-invalid declaration.
    let (errors, _) = declaration_errors(&decl, &registry);
    if !errors.is_empty() {
        let msg = format!(
            "generated '{name}' is schema-invalid:\n  - {}",
            errors.join("\n  - ")
        );
        if output_mode == OutputMode::Json {
            contour_core::output::print_error_json(&msg, Some("SCHEMA_VIOLATION"));
        }
        anyhow::bail!(msg);
    }

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

    // Re-validate the written file through the same path `profile ddm
    // validate` uses. The in-memory check above already ran the schema
    // rules; this guards the serialize/parse round-trip, so a file that
    // would fail `validate` is a hard error here rather than left on disk.
    let result = validate_single_ddm(std::path::Path::new(&output_path), &registry, &[])?;
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
        print_deployment_notes(&manifest.payload_type);
        // "required only" means required TOP-LEVEL fields. A type whose
        // top-level keys are all optional — app.settings is one — therefore
        // scaffolds as `{}`, which reads as "contour knows nothing about
        // this type" rather than "ask for all fields". Say which it is.
        if !full && decl.payload.is_empty() {
            println!(
                "\n{} every top-level field of this type is optional, so \
                 \"required only\" produced an empty payload. Re-run with --full \
                 to scaffold the whole structure.",
                "Note:".yellow().bold()
            );
        }

        // The scaffold picked one of a mutually exclusive group. Name what it
        // left out, so the omission reads as Apple's constraint rather than a
        // hole in contour's schema.
        if let Some(choice) = &exclusive_choice {
            let hint = exclusive_hint(&manifest.payload_type)
                .map(|h| format!(" {h}"))
                .unwrap_or_default();
            println!(
                "\n{} Apple allows only one of these per declaration, so the \
                 scaffold set {} and omitted {}.{hint}",
                "Note:".yellow().bold(),
                choice.chosen,
                choice.omitted.join(", ")
            );
        }
        println!(
            "\n{}",
            "Edit the JSON file to set your values, then deploy via your MDM.".dimmed()
        );
    }

    Ok(())
}

/// Print available DDM presets (embedded + external from `--preset-path`
/// and `~/.contour/presets/`). JSON for agents, table for humans.
fn list_presets_action(preset_path: Option<&str>, output_mode: OutputMode) -> Result<()> {
    let entries = crate::ddm::presets::list(preset_path);
    if output_mode == OutputMode::Json {
        let json: Vec<serde_json::Value> = entries
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "description": p.description,
                    "source": p.source,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }
    if entries.is_empty() {
        println!("No presets available.");
        return Ok(());
    }
    println!("DDM presets:\n");
    for p in &entries {
        println!("  {}", p.name);
        println!("    {}", p.description);
        println!("    source: {}", p.source);
    }
    println!("\nUse: contour profile ddm compose --preset <NAME> --org <ORG> -o ./out/");
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "ddm compose threads many CLI flags including --preset / --preset-path / --list-presets"
)]
/// Compose a DDM bundle into asset / configuration / activation declarations
/// in one shot. Mirror of `handle_ddm_generate` but driven by a TOML bundle
/// describing the full intent rather than a single declaration type.
///
/// The org domain is resolved with the same fallback chain
/// `handle_ddm_generate` uses (`--org` → `profile.toml` → `CONTOUR_ORG` →
/// `.contour/config.toml`) and threaded into [`compose`]. Failures emit the
/// standard `{success:false, error, error_code}` envelope on stderr when
/// `--json` is set.
pub fn handle_ddm_compose(
    bundle_path: Option<&str>,
    output_dir: Option<&str>,
    schema_path: Option<&str>,
    allow_orphans: bool,
    org_flag: Option<&str>,
    preset: Option<&str>,
    preset_path: Option<&str>,
    list_presets: bool,
    platforms: &[String],
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    // --list-presets short-circuits — no schema/registry/output needed.
    if list_presets {
        return list_presets_action(preset_path, output_mode);
    }

    let registry = load_registry(schema_path)?;

    // 1. Read + parse the bundle TOML — either from disk (positional
    //    argument) or from an embedded preset (--preset <name>).
    let (bundle_text, source_label): (String, String) = if let Some(name) = preset {
        let body = crate::ddm::presets::load(name, preset_path).ok_or_else(|| {
            let valid: Vec<String> = crate::ddm::presets::list(preset_path)
                .into_iter()
                .map(|p| p.name)
                .collect();
            let msg = format!(
                "Unknown --preset '{name}'. Valid: {}\nRun `contour profile ddm compose --list-presets` for descriptions.",
                valid.join(", ")
            );
            if output_mode == OutputMode::Json {
                contour_core::output::print_error_json(&msg, Some("UNKNOWN"));
            }
            anyhow::anyhow!(msg)
        })?;
        (body, format!("preset:{name}"))
    } else {
        let path =
            bundle_path.expect("clap enforces bundle when neither preset nor list-presets is set");
        match std::fs::read_to_string(path) {
            Ok(s) => (s, path.to_string()),
            Err(e) => {
                let msg = format!("Failed to read {path}: {e}");
                if output_mode == OutputMode::Json {
                    contour_core::output::print_error_json(&msg, Some("IO_ERROR"));
                }
                anyhow::bail!(msg);
            }
        }
    };
    let mut bundle: Bundle = match toml::from_str(&bundle_text) {
        Ok(b) => b,
        Err(e) => {
            let msg = format!("Failed to parse bundle TOML from {source_label}: {e}");
            if output_mode == OutputMode::Json {
                contour_core::output::print_error_json(&msg, Some("INVALID_FORMAT"));
            }
            anyhow::bail!(msg);
        }
    };

    // Resolve an [asset].zip into a hashed Reference, relative to the bundle
    // file's directory (presets have no path → resolve against cwd).
    if let Some(asset) = bundle.asset.as_mut() {
        let base_dir = bundle_path
            .and_then(|p| Path::new(p).parent().map(Path::to_path_buf))
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        if let Err(e) = crate::ddm::compose::materialize_asset(asset, &base_dir) {
            let msg = format!("failed to hash asset zip: {e}");
            if output_mode == OutputMode::Json {
                contour_core::output::print_error_json(&msg, Some("IO_ERROR"));
            }
            anyhow::bail!(msg);
        }
    }

    // 2. Resolve org domain (shared resolution: profile.toml → CONTOUR_ORG → .contour/config.toml).
    let Some(domain) = resolve_ddm_org_domain(org_flag, config) else {
        let msg = "organization domain is required for DDM compose\n\
                   Set it via:\n  \
                   • organization.domain in profile.toml\n  \
                   • CONTOUR_ORG=com.yourcompany (env var, ideal for CI)\n  \
                   • organization.domain in .contour/config.toml"
            .to_string();
        if output_mode == OutputMode::Json {
            contour_core::output::print_error_json(&msg, Some("INVALID_ORG"));
        }
        anyhow::bail!(msg);
    };

    // 3. Compose.
    let opts = ComposeOptions { allow_orphans };
    let composed = match compose(&bundle, &domain, &registry, &opts) {
        Ok(c) => c,
        Err(e) => {
            if output_mode == OutputMode::Json {
                contour_core::output::print_error_json(&e.to_string(), Some(e.error_code()));
            }
            anyhow::bail!(e.to_string());
        }
    };

    // 4. Ensure output directory exists, then write declarations in BUILD ORDER.
    let output_dir = output_dir.expect("clap enforces --output when not in --list-presets mode");
    let out = Path::new(output_dir);
    if !out.exists() {
        std::fs::create_dir_all(out)?;
    } else if !out.is_dir() {
        anyhow::bail!("--output {output_dir} is not a directory");
    }

    // Fail-closed: validate every emitted declaration against the embedded
    // schema before writing any of them.
    let mut compose_warnings: Vec<String> = Vec::new();
    // --platform wins over the bundle's own `platforms`.
    let targets = parse_platforms(if platforms.is_empty() {
        &bundle.platforms
    } else {
        platforms
    })?;
    {
        let mut decls: Vec<(&str, &Declaration)> = vec![("configuration", &composed.configuration)];
        if let Some(a) = &composed.asset {
            decls.push(("asset", a));
        }
        if let Some(a) = &composed.activation {
            decls.push(("activation", a));
        }
        if let Some(s) = &composed.subscriptions {
            decls.push(("status-subscriptions", s));
        }
        let mut all_errors = Vec::new();
        for (kind, d) in &decls {
            let (errors, warnings) = declaration_errors(d, &registry);
            for e in errors {
                all_errors.push(format!("{kind}: {e}"));
            }
            // An unknown field is a warning to `validate`, which reads files
            // someone may have reasons for. Compose writes them: a key Apple
            // does not define at that path is ignored on the device, so the
            // setting the author meant does not apply. Refused, not warned.
            // A key the target OS does not have is ignored there, like an
            // unknown one: refused, not warned.
            for p in &targets {
                for f in platform_findings(d, &registry, *p) {
                    all_errors.push(format!("{kind}: {f}"));
                }
            }
            for w in warnings {
                if w.starts_with("Unknown field") {
                    all_errors.push(format!("{kind}: {w}"));
                } else {
                    compose_warnings.push(format!("{kind}: {w}"));
                }
            }
        }
        if !all_errors.is_empty() {
            let msg = format!(
                "composed declarations are schema-invalid:\n  - {}",
                all_errors.join("\n  - ")
            );
            if output_mode == OutputMode::Json {
                contour_core::output::print_error_json(&msg, Some("SCHEMA_VIOLATION"));
            }
            anyhow::bail!(msg);
        }
    }

    let mut written: Vec<(String, PathBuf, Declaration)> = Vec::new();

    // Deploy order: status-subscriptions first (so the device has the
    // subscription set up before any predicate evaluates), then asset,
    // then configuration, then activation.
    if let Some(subs) = &composed.subscriptions {
        let path = out.join("status-subscriptions.json");
        std::fs::write(&path, write_declaration(subs)?)?;
        written.push(("status-subscriptions".to_string(), path, subs.clone()));
    }
    if let Some(asset) = &composed.asset {
        let path = out.join("asset.json");
        std::fs::write(&path, write_declaration(asset)?)?;
        written.push(("asset".to_string(), path, asset.clone()));
    }
    let config_path = out.join("configuration.json");
    std::fs::write(&config_path, write_declaration(&composed.configuration)?)?;
    written.push((
        "configuration".to_string(),
        config_path,
        composed.configuration.clone(),
    ));
    if let Some(activation) = &composed.activation {
        let path = out.join("activation.json");
        std::fs::write(&path, write_declaration(activation)?)?;
        written.push(("activation".to_string(), path, activation.clone()));
    }

    // 5. Emit human or JSON report.
    match output_mode {
        OutputMode::Json => emit_compose_json(&bundle, &composed, &written, &compose_warnings),
        OutputMode::Human => emit_compose_human(&bundle, &composed, &written, &compose_warnings),
    }

    Ok(())
}

fn emit_compose_json(
    bundle: &Bundle,
    composed: &ComposedBundle,
    written: &[(String, PathBuf, Declaration)],
    warnings: &[String],
) {
    let files: Vec<_> = written
        .iter()
        .map(|(kind, path, decl)| {
            let mut entry = serde_json::json!({
                "kind": kind,
                "identifier": decl.identifier,
                "type": decl.declaration_type,
                "path": path.display().to_string(),
            });
            if kind == "configuration"
                && let Some(field) = &composed.asset_ref_field_used
                && let Some(asset) = &composed.asset
            {
                entry["asset_ref_field"] = serde_json::Value::String(field.clone());
                entry["asset_ref"] = serde_json::Value::String(asset.identifier.clone());
            }
            if kind == "activation"
                && let Some(refs) = decl.payload.get("StandardConfigurations")
            {
                entry["configuration_refs"] = refs.clone();
            }
            entry
        })
        .collect();

    let report = serde_json::json!({
        "success":     true,
        "intent_name": bundle.intent_name,
        "files":       files,
        "warnings":    warnings,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| report.to_string())
    );
}

fn emit_compose_human(
    bundle: &Bundle,
    composed: &ComposedBundle,
    written: &[(String, PathBuf, Declaration)],
    warnings: &[String],
) {
    println!(
        "{} {}",
        "✓".green().bold(),
        format!("Composed bundle '{}'", bundle.intent_name).bold()
    );
    if let Some(field) = &composed.asset_ref_field_used
        && let Some(asset) = &composed.asset
    {
        println!(
            "  asset reference: {} = \"{}\"",
            field.cyan(),
            asset.identifier.dimmed()
        );
    }
    println!();
    println!("Files (deploy in this order):");
    for (kind, path, decl) in written {
        println!(
            "  {} {} → {}",
            format!("[{kind}]").green(),
            decl.identifier.bold(),
            path.display()
        );
    }
    for w in warnings {
        println!("  {} {w}", "Warning:".yellow());
    }
}

/// Verify cross-references across a directory of DDM declarations.
///
/// Pure-Rust check delegated to [`crate::ddm::verify::build_report`].
/// This handler walks the directory, parses each `*.json` file with the
/// existing `parse_declaration_file`, and emits a typed report.
pub fn handle_ddm_verify(
    directory: &str,
    recursive: bool,
    strict: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let dir = Path::new(directory);
    if !dir.exists() || !dir.is_dir() {
        let msg = format!("--directory must be an existing directory: {directory}");
        if output_mode == OutputMode::Json {
            contour_core::output::print_error_json(&msg, Some("IO_ERROR"));
        }
        anyhow::bail!(msg);
    }

    // Walk and parse.
    let mut files: Vec<PathBuf> = Vec::new();
    if recursive {
        for entry in WalkDir::new(dir).follow_links(true).into_iter().flatten() {
            let p = entry.path();
            if p.is_file() && p.extension().is_some_and(|e| e == "json") && is_ddm_file(p) {
                files.push(p.to_path_buf());
            }
        }
    } else if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(std::result::Result::ok) {
            let p = entry.path();
            if p.is_file() && p.extension().is_some_and(|e| e == "json") && is_ddm_file(&p) {
                files.push(p);
            }
        }
    }

    // Verifying nothing is not a pass: a bundle composed into per-intent
    // subdirectories and checked without -r would otherwise report success
    // over zero declarations.
    if files.is_empty() {
        let nested = if recursive {
            0
        } else {
            WalkDir::new(dir)
                .min_depth(2)
                .follow_links(true)
                .into_iter()
                .flatten()
                .filter(|e| {
                    let p = e.path();
                    p.is_file() && p.extension().is_some_and(|x| x == "json") && is_ddm_file(p)
                })
                .count()
        };
        let msg = if nested > 0 {
            format!(
                "no DDM declarations directly in {directory}; {nested} found in \
                 subdirectories — pass -r/--recursive to verify them"
            )
        } else {
            format!("no DDM declarations in {directory} — nothing was verified")
        };
        if output_mode == OutputMode::Json {
            // IO_ERROR, not a new code: the DDM error-code enum is a
            // contract agents switch on, and "no input found" is its case.
            contour_core::output::print_error_json(&msg, Some("IO_ERROR"));
        }
        anyhow::bail!(msg);
    }

    let mut declarations: Vec<(PathBuf, Declaration)> = Vec::new();
    let mut parse_errors: Vec<(PathBuf, String)> = Vec::new();
    for file in files {
        match parse_declaration_file(&file) {
            Ok(decl) => declarations.push((file, decl)),
            Err(e) => parse_errors.push((file, e.to_string())),
        }
    }

    let report = build_report(&declarations);

    let clean = if strict {
        report.is_clean_strict()
    } else {
        report.is_clean()
    };
    let exit_ok = clean && parse_errors.is_empty();

    match output_mode {
        OutputMode::Json => emit_verify_json(directory, &report, &parse_errors),
        OutputMode::Human => emit_verify_human(directory, &report, &parse_errors, strict),
    }

    if !exit_ok {
        anyhow::bail!(
            "{} verify error(s), {} warning(s), {} parse failure(s)",
            report.errors.len(),
            report.warnings.len(),
            parse_errors.len()
        );
    }

    Ok(())
}

fn emit_verify_json(directory: &str, report: &VerifyReport, parse_errors: &[(PathBuf, String)]) {
    let json = serde_json::json!({
        "success":          report.is_clean() && parse_errors.is_empty(),
        "directory":        directory,
        "asset_count":      report.assets.len(),
        "config_count":     report.configurations.len(),
        "activation_count": report.activations.len(),
        "subscription_count": report.subscriptions.len(),
        "errors":   report.errors.iter().map(verify_error_to_json).collect::<Vec<_>>(),
        "warnings": report.warnings.iter().map(verify_warning_to_json).collect::<Vec<_>>(),
        "parse_errors": parse_errors
            .iter()
            .map(|(p, e)| serde_json::json!({ "file": p.display().to_string(), "error": e }))
            .collect::<Vec<_>>(),
        "graph": {
            "assets": report.assets.iter().map(|a| serde_json::json!({
                "identifier": a.identifier, "type": a.r#type, "file": a.file.display().to_string()
            })).collect::<Vec<_>>(),
            "configurations": report.configurations.iter().map(|c| serde_json::json!({
                "identifier": c.identifier, "type": c.r#type, "file": c.file.display().to_string(),
                "asset_refs": c.asset_refs,
            })).collect::<Vec<_>>(),
            "activations": report.activations.iter().map(|a| serde_json::json!({
                "identifier": a.identifier, "type": a.r#type, "file": a.file.display().to_string(),
                "configuration_refs": a.configuration_refs,
                "predicate": a.predicate,
                "predicate_status_keys": a.predicate_status_keys,
            })).collect::<Vec<_>>(),
            "subscriptions": report.subscriptions.iter().map(|s| serde_json::json!({
                "identifier": s.identifier, "type": s.r#type, "file": s.file.display().to_string(),
                "status_items": s.status_items,
            })).collect::<Vec<_>>(),
        }
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_else(|_| json.to_string())
    );
}

fn verify_error_to_json(err: &VerifyError) -> serde_json::Value {
    match err {
        VerifyError::DanglingAssetReference {
            configuration_id,
            field,
            target,
            file,
        } => serde_json::json!({
            "kind": "DanglingAssetReference",
            "configuration_id": configuration_id,
            "field": field,
            "target": target,
            "file": file.display().to_string(),
        }),
        VerifyError::DanglingConfigurationReference {
            activation_id,
            target,
            file,
        } => serde_json::json!({
            "kind": "DanglingConfigurationReference",
            "activation_id": activation_id,
            "target": target,
            "file": file.display().to_string(),
        }),
        VerifyError::UnsubscribedStatusKey {
            activation_id,
            key,
            file,
        } => serde_json::json!({
            "kind": "UnsubscribedStatusKey",
            "activation_id": activation_id,
            "key": key,
            "file": file.display().to_string(),
        }),
        VerifyError::ServerTokenAuthored { identifier, file } => serde_json::json!({
            "kind": "ServerTokenAuthored",
            "identifier": identifier,
            "file": file.display().to_string(),
        }),
    }
}

fn verify_warning_to_json(warn: &VerifyWarning) -> serde_json::Value {
    match warn {
        VerifyWarning::OrphanAsset { identifier, file } => serde_json::json!({
            "kind": "OrphanAsset",
            "identifier": identifier,
            "file": file.display().to_string(),
        }),
        VerifyWarning::OrphanConfiguration { identifier, file } => serde_json::json!({
            "kind": "OrphanConfiguration",
            "identifier": identifier,
            "file": file.display().to_string(),
        }),
        VerifyWarning::UnusedSubscriptionKey { key, file } => serde_json::json!({
            "kind": "UnusedSubscriptionKey",
            "key": key,
            "file": file.display().to_string(),
        }),
    }
}

fn emit_verify_human(
    directory: &str,
    report: &VerifyReport,
    parse_errors: &[(PathBuf, String)],
    strict: bool,
) {
    let clean = if strict {
        report.is_clean_strict() && parse_errors.is_empty()
    } else {
        report.is_clean() && parse_errors.is_empty()
    };
    if clean {
        println!(
            "{} {} ({} asset(s), {} configuration(s), {} activation(s), {} subscription(s))",
            "✓".green().bold(),
            format!("Verified {directory}").bold(),
            report.assets.len(),
            report.configurations.len(),
            report.activations.len(),
            report.subscriptions.len(),
        );
        return;
    }
    println!(
        "{} {}",
        "✗".red().bold(),
        format!("Verify failed for {directory}").bold()
    );
    for err in &report.errors {
        println!("  {} {}", "·".red(), describe_error(err));
    }
    for (file, msg) in parse_errors {
        println!("  {} parse error in {}: {}", "·".red(), file.display(), msg);
    }
    if !report.warnings.is_empty() {
        let label = if strict {
            "·".red().to_string()
        } else {
            "·".yellow().to_string()
        };
        for warn in &report.warnings {
            println!("  {label} {}", describe_warning(warn));
        }
    }
}

fn describe_error(err: &VerifyError) -> String {
    match err {
        VerifyError::DanglingAssetReference {
            configuration_id,
            field,
            target,
            ..
        } => format!(
            "configuration '{configuration_id}' references missing asset '{target}' \
             via {field}"
        ),
        VerifyError::DanglingConfigurationReference {
            activation_id,
            target,
            ..
        } => format!("activation '{activation_id}' references missing configuration '{target}'"),
        VerifyError::UnsubscribedStatusKey {
            activation_id, key, ..
        } => format!(
            "activation '{activation_id}' predicate references unsubscribed status key \
             '{key}' (would deploy as Error.UnableToEvaluatePredicate)"
        ),
        VerifyError::ServerTokenAuthored { identifier, .. } => format!(
            "declaration '{identifier}' has ServerToken authored — that field is \
             server-managed; remove it"
        ),
    }
}

fn describe_warning(warn: &VerifyWarning) -> String {
    match warn {
        VerifyWarning::OrphanAsset { identifier, .. } => {
            format!("orphan asset '{identifier}' (no configuration references it)")
        }
        VerifyWarning::OrphanConfiguration { identifier, .. } => format!(
            "orphan configuration '{identifier}' (no activation references it; \
             this is valid Apple-side but worth confirming)"
        ),
        VerifyWarning::UnusedSubscriptionKey { key, .. } => format!(
            "unused subscription key '{key}' (subscribed but no predicate \
             references it)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intelligence(payload: serde_json::Value) -> Vec<String> {
        let registry = SchemaRegistry::embedded().expect("embedded registry loads");
        let decl: Declaration = serde_json::from_value(serde_json::json!({
            "Type": "com.apple.configuration.intelligence.settings",
            "Identifier": "com.acme.config.ai",
            "Payload": payload,
        }))
        .unwrap();
        declaration_errors(&decl, &registry).1
    }

    /// Apple's per-key deprecation notes drive the map: the intelligence
    /// restrictions show up, nested targets are found, and a key with no
    /// exact partner is listed without a guessed one.
    #[test]
    fn ddm_map_lists_keys_moved_to_other_declarations() {
        let moved = moved_keys("com.apple.applicationaccess");
        let ai = moved
            .get("com.apple.configuration.intelligence.settings")
            .expect("the intelligence declaration must be listed");
        assert!(
            ai.iter().any(|(k, to)| k == "allowMailSummary"
                && to.as_deref() == Some("Apps.Mail.AllowSummary")),
            "{ai:?}"
        );
        let siri = &moved["com.apple.configuration.siri.settings"];
        assert!(
            siri.iter()
                .any(|(k, to)| k == "allowAssistant" && to.is_none()),
            "{siri:?}"
        );
    }

    fn intelligence_decl(payload: serde_json::Value) -> Declaration {
        serde_json::from_value(serde_json::json!({
            "Type": "com.apple.configuration.intelligence.settings",
            "Identifier": "com.acme.config.ai",
            "Payload": payload,
        }))
        .unwrap()
    }

    /// Apple's per-platform `n/a` reaches the check, at the top level and
    /// nested: Image Wand is not a macOS key, Notes transcription is not a
    /// visionOS one.
    #[test]
    fn a_key_apple_does_not_offer_on_the_platform_is_reported() {
        use crate::schema::Platform;
        let registry = SchemaRegistry::embedded().unwrap();
        let d = intelligence_decl(serde_json::json!({
            "AllowImageWand": false,
            "AllowGenmoji": false,
            "Apps": {"Notes": {"AllowTranscription": false}}
        }));
        let mac = platform_findings(&d, &registry, Platform::MacOS);
        assert_eq!(mac.len(), 1, "{mac:?}");
        assert!(
            mac[0].starts_with("AllowImageWand is not available on macOS"),
            "{mac:?}"
        );
        let vision = platform_findings(&d, &registry, Platform::VisionOS);
        assert!(
            vision
                .iter()
                .any(|f| f.starts_with("Apps.Notes.AllowTranscription")),
            "{vision:?}"
        );
        assert!(platform_findings(&d, &registry, Platform::Ios).is_empty());
    }

    /// A key known by name elsewhere is unknown at the wrong path: `Mail`
    /// belongs under `Apps`.
    #[test]
    fn a_nested_key_at_the_payload_root_is_unknown() {
        let w = intelligence(serde_json::json!({"Mail": {"AllowSummary": false}}));
        assert!(w.iter().any(|w| w == "Unknown field: Mail"), "{w:?}");
    }

    /// Unknown keys are found inside nested dictionaries, not only at the
    /// top level, and the message names what is valid there.
    #[test]
    fn an_unknown_key_in_a_nested_dictionary_is_reported() {
        let w = intelligence(serde_json::json!({"Apps": {"Mial": {"AllowSummary": false}}}));
        assert!(
            w.iter()
                .any(|w| w.starts_with("Unknown field: Apps.Mial") && w.contains("Mail")),
            "{w:?}"
        );
        let clean = intelligence(serde_json::json!({"Apps": {"Mail": {"AllowSummary": false}}}));
        assert!(
            !clean.iter().any(|w| w.starts_with("Unknown field")),
            "{clean:?}"
        );
    }

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
                if field.parent_key.is_some() || field.is_placeholder() {
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
                for (label, parent_obj) in walk_payload_paths(&payload.0, &ancestors) {
                    if !parent_obj.contains_key(&field.name) {
                        errors.push(format!("Missing required field: {label}.{}", field.name));
                    }
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
                let mut errors = validate_payload(type_name, &payload);
                // Scaffolds must also satisfy Apple's cross-key rules —
                // contour must never emit a document its own validator rejects.
                let manifest = registry.get_by_name(type_name).unwrap();
                let decl = Declaration {
                    payload_scope: None,
                    declaration_type: manifest.payload_type.clone(),
                    identifier: "com.acme.test".to_string(),
                    server_token: None,
                    authentication: None,
                    payload: payload.clone(),
                };
                errors.extend(cross_key_errors(&decl));
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

    #[test]
    fn reproduces_macadmins_sshd_bundle_structure() {
        use crate::ddm::compose::{BundleActivation, BundleAsset, BundleConfiguration};
        use serde_json::{Map, Value, json};
        let registry = SchemaRegistry::embedded().expect("embedded registry loads");

        let mut reference = Map::new();
        reference.insert("ContentType".into(), json!("application/zip"));
        reference.insert(
            "DataURL".into(),
            json!("https://files.macadmins.io/sshd-0.0.1.zip"),
        );
        reference.insert(
            "Hash-SHA-256".into(),
            json!("708904b8ceb7fb26a7e10bc391e643d269ed13d91b6af3f2262f138ddf4f449c"),
        );
        let mut asset_payload = Map::new();
        asset_payload.insert("Reference".into(), Value::Object(reference));
        let mut cfg_payload = Map::new();
        cfg_payload.insert("ServiceType".into(), json!("com.apple.sshd"));

        let bundle = Bundle {
            intent_name: "sshd".into(),
            platforms: Vec::new(),
            asset: Some(BundleAsset {
                type_name: "com.apple.asset.data".into(),
                payload: asset_payload,
                ..Default::default()
            }),
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.services.configuration-files".into(),
                identifier: None,
                asset_ref_field: None,
                payload: cfg_payload,
            },
            activation: Some(BundleActivation::default()),
            subscriptions: None,
        };
        let c = compose(
            &bundle,
            "io.macadmins",
            &registry,
            &ComposeOptions::default(),
        )
        .unwrap();

        // Asset: computed identifier + Authentication {Type: None} (the gap closed).
        let asset = c.asset.expect("asset emitted");
        assert_eq!(asset.identifier, "io.macadmins.asset.sshd");
        assert_eq!(
            asset
                .authentication
                .unwrap()
                .get("Type")
                .and_then(Value::as_str),
            Some("None")
        );
        // Configuration: auto-wired DataAssetReference + the ServiceType.
        assert_eq!(
            c.configuration
                .payload
                .get("DataAssetReference")
                .and_then(Value::as_str),
            Some("io.macadmins.asset.sshd")
        );
        assert_eq!(
            c.configuration
                .payload
                .get("ServiceType")
                .and_then(Value::as_str),
            Some("com.apple.sshd")
        );
        // Activation: StandardConfigurations references the configuration.
        let act = c.activation.expect("activation emitted");
        let cfgs = act
            .payload
            .get("StandardConfigurations")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(cfgs[0].as_str(), Some("io.macadmins.config.sshd"));
    }

    #[test]
    fn zip_materialization_feeds_compose() {
        use crate::ddm::compose::{
            BundleActivation, BundleAsset, BundleConfiguration, materialize_asset,
        };
        use serde_json::{Value, json};
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("z.zip"), b"hello").unwrap();
        let mut asset = BundleAsset {
            type_name: "com.apple.asset.data".into(),
            zip: Some("z.zip".into()),
            url: Some("https://cdn.example.com/z.zip".into()),
            ..Default::default()
        };
        materialize_asset(&mut asset, tmp.path()).unwrap();

        let registry = SchemaRegistry::embedded().expect("embedded registry loads");
        let mut cfg = serde_json::Map::new();
        cfg.insert("ServiceType".into(), json!("com.apple.sshd"));
        let bundle = Bundle {
            intent_name: "z".into(),
            platforms: Vec::new(),
            asset: Some(asset),
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.services.configuration-files".into(),
                identifier: None,
                asset_ref_field: None,
                payload: cfg,
            },
            activation: Some(BundleActivation::default()),
            subscriptions: None,
        };
        let c = compose(
            &bundle,
            "io.macadmins",
            &registry,
            &ComposeOptions::default(),
        )
        .unwrap();
        let reference = c
            .asset
            .unwrap()
            .payload
            .get("Reference")
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            reference.get("Hash-SHA-256").and_then(Value::as_str),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
        assert_eq!(
            reference.get("DataURL").and_then(Value::as_str),
            Some("https://cdn.example.com/z.zip")
        );
    }
}

#[cfg(test)]
mod identifier_tests {
    use super::resolve_declaration_identifier;

    /// An explicit `--identifier` is used verbatim, and makes `--org`
    /// unnecessary — the org was only ever needed to derive one. Wedge (and
    /// any GUI/pipeline that names declarations itself) previously had to
    /// regex-patch contour's output to achieve this.
    #[test]
    fn explicit_identifier_wins_and_needs_no_org() {
        let got =
            resolve_declaration_identifier(Some("com.acme.beta.pilot"), None, None, "settings")
                .unwrap();
        assert_eq!(got, "com.acme.beta.pilot");
    }

    #[test]
    fn falls_back_to_org_derived_identifier() {
        let got = resolve_declaration_identifier(None, Some("com.acme"), None, "settings").unwrap();
        assert_eq!(got, "com.acme.settings");
    }

    #[test]
    fn without_identifier_or_org_it_errors() {
        // No org anywhere (env/config are not set in the test process).
        let err = resolve_declaration_identifier(None, None, None, "settings");
        assert!(err.is_err(), "expected an error when neither is available");
    }

    #[test]
    fn blank_identifier_is_ignored_in_favour_of_org() {
        let got =
            resolve_declaration_identifier(Some("  "), Some("com.acme"), None, "settings").unwrap();
        assert_eq!(got, "com.acme.settings");
    }
}

#[cfg(test)]
mod cross_key_tests {
    use super::{Declaration, DeclarationPayload, cross_key_errors};

    const SWU: &str = "com.apple.configuration.softwareupdate.settings";

    fn decl_with_beta(beta: serde_json::Value) -> Declaration {
        let mut payload = DeclarationPayload::new();
        payload.insert("Beta".to_string(), beta);
        Declaration {
            payload_scope: None,
            declaration_type: SWU.to_string(),
            identifier: "com.acme.settings".to_string(),
            server_token: None,
            authentication: None,
            payload,
        }
    }

    fn programs() -> serde_json::Value {
        // Flat: `Program` is the element's name, not a key.
        serde_json::json!([{ "Description": "Pilot", "Token": "T" }])
    }

    fn program() -> serde_json::Value {
        serde_json::json!({ "Description": "Pilot", "Token": "T" })
    }

    /// Apple: OfferPrograms "must only be present if ProgramEnrollment is
    /// set to Allowed or AlwaysOn".
    #[test]
    fn offer_programs_with_always_off_is_an_error() {
        let d = decl_with_beta(serde_json::json!({
            "ProgramEnrollment": "AlwaysOff",
            "OfferPrograms": programs(),
        }));
        let errors = cross_key_errors(&d);
        assert!(
            errors.iter().any(|e| e.contains("OfferPrograms")),
            "expected an OfferPrograms/AlwaysOff error, got: {errors:?}"
        );
    }

    /// Apple: RequireProgram "must only be present if ProgramEnrollment is
    /// set to AlwaysOn".
    #[test]
    fn require_program_without_always_on_is_an_error() {
        let d = decl_with_beta(serde_json::json!({
            "ProgramEnrollment": "Allowed",
            "RequireProgram": program(),
        }));
        let errors = cross_key_errors(&d);
        assert!(
            errors.iter().any(|e| e.contains("RequireProgram")),
            "expected a RequireProgram/AlwaysOn error, got: {errors:?}"
        );
    }

    /// Apple: "The OfferPrograms key must not be present if this
    /// [RequireProgram] key is present."
    #[test]
    fn offer_and_require_together_is_an_error() {
        let d = decl_with_beta(serde_json::json!({
            "ProgramEnrollment": "AlwaysOn",
            "OfferPrograms": programs(),
            "RequireProgram": program(),
        }));
        let errors = cross_key_errors(&d);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("OfferPrograms") && e.contains("RequireProgram")),
            "expected a mutual-exclusion error, got: {errors:?}"
        );
    }

    #[test]
    fn legal_beta_combinations_pass() {
        // offer
        let offer = decl_with_beta(serde_json::json!({
            "ProgramEnrollment": "Allowed", "OfferPrograms": programs(),
        }));
        // always-on with a menu
        let always_on = decl_with_beta(serde_json::json!({
            "ProgramEnrollment": "AlwaysOn", "OfferPrograms": programs(),
        }));
        // require
        let require = decl_with_beta(serde_json::json!({
            "ProgramEnrollment": "AlwaysOn", "RequireProgram": program(),
        }));
        // block
        let block = decl_with_beta(serde_json::json!({ "ProgramEnrollment": "AlwaysOff" }));
        for (name, d) in [
            ("offer", offer),
            ("always_on", always_on),
            ("require", require),
            ("block", block),
        ] {
            assert!(
                cross_key_errors(&d).is_empty(),
                "{name} must be legal, got: {:?}",
                cross_key_errors(&d)
            );
        }
    }

    /// Apple explicitly allows OfferPrograms with no ProgramEnrollment on
    /// unsupervised devices, where it is implicitly `Allowed`.
    #[test]
    fn offer_programs_without_program_enrollment_is_legal() {
        let d = decl_with_beta(serde_json::json!({ "OfferPrograms": programs() }));
        assert!(cross_key_errors(&d).is_empty());
    }

    /// Declaration types with no encoded cross-key rules are unaffected.
    #[test]
    fn unknown_declaration_type_has_no_cross_key_rules() {
        let mut payload = DeclarationPayload::new();
        payload.insert("Anything".to_string(), serde_json::json!(true));
        let d = Declaration {
            payload_scope: None,
            declaration_type: "com.apple.configuration.passcode.settings".to_string(),
            identifier: "com.acme.p".to_string(),
            server_token: None,
            authentication: None,
            payload,
        };
        assert!(cross_key_errors(&d).is_empty());
    }
}

#[cfg(test)]
mod array_element_tests {
    use super::{Declaration, DeclarationPayload, declaration_errors};

    /// Validate an app.settings declaration whose `Allowed` block is `allowed`.
    fn check(allowed: serde_json::Value) -> (Vec<String>, Vec<String>) {
        let registry = crate::schema::SchemaRegistry::embedded().unwrap();
        let mut payload = DeclarationPayload::new();
        payload.insert("Allowed".to_string(), allowed);
        let decl = Declaration {
            payload_scope: None,
            declaration_type: "com.apple.configuration.app.settings".to_string(),
            identifier: "com.acme.t".to_string(),
            server_token: None,
            authentication: None,
            payload,
        };
        declaration_errors(&decl, &registry)
    }

    fn mentions(list: &[String], needle: &str) -> bool {
        list.iter().any(|m| m.contains(needle))
    }

    #[test]
    fn a_binary_wrapped_in_its_element_name_is_an_error() {
        let (errors, _) = check(serde_json::json!({
            "AllowedBinaries": [{"BinaryIdentifier": {"TeamID": "BJ4HAAB9B3"}}]
        }));
        assert!(
            mentions(&errors, "nests its fields under \"BinaryIdentifier\""),
            "{errors:?}"
        );
    }

    #[test]
    fn a_flat_binary_entry_is_clean() {
        // Apple's own shape, from the alr-* examples.
        let (errors, warnings) = check(serde_json::json!({
            "AllowedBinaries": [{"TeamID": "*APPLE*", "SigningID": "com.apple.Safari.WebApp"}],
            "DeniedBinaries": [{"CDHash": "03552d8140254d0c190af06f1e470dbc5ded53ba"}]
        }));
        assert!(errors.is_empty(), "{errors:?}");
        assert!(!mentions(&warnings, "[0]"), "{warnings:?}");
    }

    #[test]
    fn an_app_list_of_objects_is_an_error() {
        // AppIdentifier is a <string> element: the list is bare bundle IDs.
        let (errors, _) = check(serde_json::json!({
            "AllowedApps": [{"AppIdentifier": "us.zoom.xos"}]
        }));
        assert!(
            mentions(
                &errors,
                "each element of Allowed.AllowedApps is a bare string"
            ),
            "{errors:?}"
        );
    }

    #[test]
    fn an_app_list_of_bare_bundle_ids_is_clean() {
        let (errors, _) = check(serde_json::json!({
            "AllowedApps": ["us.zoom.xos"],
            "DeniedApps": ["com.apple.webapp"]
        }));
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn a_key_the_type_uses_nowhere_is_reported() {
        let (_, warnings) = check(serde_json::json!({
            "AllowedBinaries": [{"TeamID": "BJ4HAAB9B3", "TotallyMadeUp": "x"}]
        }));
        assert!(
            mentions(&warnings, "Allowed.AllowedBinaries[0].TotallyMadeUp"),
            "{warnings:?}"
        );
    }

    #[test]
    fn an_element_enum_value_is_checked() {
        let (errors, _) = check(serde_json::json!({
            "AllowedBinaries": [{"TeamID": "BJ4HAAB9B3", "SigningState": "Bogus"}]
        }));
        assert!(
            mentions(
                &errors,
                "Allowed.AllowedBinaries[0].SigningState: \"Bogus\""
            ),
            "{errors:?}"
        );
    }

    #[test]
    fn a_deny_entry_needs_a_real_identifier() {
        // PathPrefix narrows a match but identifies nothing on its own.
        let (errors, _) = check(serde_json::json!({
            "DeniedBinaries": [{"PathPrefix": "/Users/Shared/"}]
        }));
        assert!(
            mentions(
                &errors,
                "DeniedBinaries requires CDHash, TeamID, or SigningID"
            ),
            "{errors:?}"
        );
    }

    #[test]
    fn a_santa_prefixed_signing_id_is_refused() {
        let (errors, _) = check(serde_json::json!({
            "DeniedBinaries": [{"SigningID": "BJ4HAAB9B3:us.zoom.xos"}]
        }));
        assert!(mentions(&errors, "no 'TeamID:' prefix"), "{errors:?}");
    }
}

#[cfg(test)]
mod privacy_key_tests {
    use super::{Declaration, DeclarationPayload, declaration_errors};

    const APP_SETTINGS: &str = "com.apple.configuration.app.settings";

    /// A real key, as an admin would write it: bare identifier, requirement
    /// in curly braces, quotes only inside the requirement's own body.
    const ZOOM: &str = "us.zoom.xos {identifier \"us.zoom.xos\" and anchor apple generic \
                        and certificate leaf[subject.OU] = BJ4HAAB9B3}";

    fn warnings_for(key: &str) -> Vec<String> {
        let registry = crate::schema::SchemaRegistry::embedded().unwrap();
        let mut defaults = serde_json::Map::new();
        defaults.insert(key.to_string(), serde_json::json!({ "Camera": "Allow" }));
        let mut payload = DeclarationPayload::new();
        payload.insert(
            "Privacy".to_string(),
            serde_json::json!({ "PermissionDefaults": defaults }),
        );
        let decl = Declaration {
            payload_scope: None,
            declaration_type: APP_SETTINGS.to_string(),
            identifier: "com.acme.privacy".to_string(),
            server_token: None,
            authentication: None,
            payload,
        };
        declaration_errors(&decl, &registry).1
    }

    #[test]
    fn parenthesised_requirement_is_named_as_such() {
        let w = warnings_for("us.zoom.xos (identifier \"us.zoom.xos\")");
        assert!(
            w.iter().any(|m| m.contains("parentheses")),
            "a parenthesised requirement should be named, not reported as missing: {w:?}"
        );
        assert!(
            !w.iter().any(|m| m.contains("carries no designated")),
            "the requirement is present, just bracketed wrong: {w:?}"
        );
    }

    #[test]
    fn quoted_identifier_is_flagged() {
        let w = warnings_for("\"us.zoom.xos\" {anchor apple generic}");
        assert!(
            w.iter().any(|m| m.contains("double quotes")),
            "a quoted app identifier should be flagged: {w:?}"
        );
    }

    #[test]
    fn a_well_formed_key_is_quiet() {
        let w = warnings_for(ZOOM);
        for noise in ["parentheses", "double quotes", "carries no designated"] {
            assert!(
                !w.iter().any(|m| m.contains(noise)),
                "well-formed key raised {noise}: {w:?}"
            );
        }
    }
}

#[cfg(test)]
mod enum_validation_tests {
    use super::{Declaration, DeclarationPayload, declaration_errors};
    use crate::schema::types::{FieldFlags, Platforms};
    use crate::schema::{FieldDefinition, FieldType, PayloadManifest, SchemaRegistry};
    use std::collections::HashMap;

    /// Registry with one DDM type shaped like the real
    /// `softwareupdate.settings`: a top-level enum string plus a nested one
    /// under a Dictionary parent, both with a rangelist.
    fn test_registry() -> SchemaRegistry {
        let field = |name: &str,
                     field_type: FieldType,
                     allowed: &[&str],
                     depth: u8,
                     parent: Option<&str>| {
            FieldDefinition {
                allowed_scopes: std::collections::HashMap::new(),
                name: name.to_string(),
                range_min: None,
                range_max: None,
                subtype: None,
                format: None,
                asset_types: Vec::new(),
                path: name.to_string(),
                field_type,
                flags: FieldFlags::default(),
                title: name.to_string(),
                description: String::new(),
                default: None,
                allowed_values: allowed.iter().map(ToString::to_string).collect(),
                depth,
                parent_key: parent.map(ToString::to_string),
                platforms: Vec::new(),
                min_version: None,
                deprecated_in: None,
                introduced_by_platform: HashMap::new(),
                deprecated_by_platform: HashMap::new(),
                removed_by_platform: Default::default(),
                combinetype: None,
            }
        };

        let defs = [
            field("Cadence", FieldType::String, &["High", "Low"], 0, None),
            field("AutomaticActions", FieldType::Dictionary, &[], 0, None),
            field(
                "Download",
                FieldType::String,
                &["Allowed", "AlwaysOn", "AlwaysOff"],
                1,
                Some("AutomaticActions"),
            ),
        ];

        let mut fields = HashMap::new();
        let mut field_order = Vec::new();
        for d in defs {
            field_order.push(d.name.clone());
            fields.insert(d.name.clone(), d);
        }

        SchemaRegistry::from_manifests_for_test(vec![PayloadManifest {
            manifest_source: None,
            fields_recording_availability: Default::default(),
            payload_type: "com.test.configuration.enumcheck".to_string(),
            kind: None,
            title: "Enum Check".to_string(),
            description: String::new(),
            platforms: Platforms::default(),
            min_versions: HashMap::new(),
            os_support: HashMap::new(),
            apply_mode: None,
            category: "ddm-configuration".to_string(),
            fields,
            field_order,
            segments: vec![],
        }])
    }

    fn declaration(payload: DeclarationPayload) -> Declaration {
        Declaration {
            payload_scope: None,
            declaration_type: "com.test.configuration.enumcheck".to_string(),
            identifier: "com.test.enumcheck".to_string(),
            server_token: None,
            authentication: None,
            payload,
        }
    }

    #[test]
    fn enum_value_outside_rangelist_is_an_error() {
        let registry = test_registry();
        let mut payload = DeclarationPayload::new();
        payload.insert("Cadence".to_string(), serde_json::json!("Bogus"));

        let (errors, _) = declaration_errors(&declaration(payload), &registry);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Cadence") && e.contains("High")),
            "expected an enum-membership error naming the field and allowed \
             values, got: {errors:?}"
        );
    }

    #[test]
    fn enum_value_inside_rangelist_passes() {
        let registry = test_registry();
        let mut payload = DeclarationPayload::new();
        payload.insert("Cadence".to_string(), serde_json::json!("High"));

        let (errors, _) = declaration_errors(&declaration(payload), &registry);
        assert!(errors.is_empty(), "valid enum value flagged: {errors:?}");
    }

    /// The shipped-bug shape: a JSON-quoted enum (`"\"Allowed\""`) nested under
    /// a Dictionary parent must be rejected, not written to disk.
    #[test]
    fn nested_quoted_enum_value_is_an_error() {
        let registry = test_registry();
        let mut payload = DeclarationPayload::new();
        payload.insert(
            "AutomaticActions".to_string(),
            serde_json::json!({"Download": "\"Allowed\""}),
        );

        let (errors, _) = declaration_errors(&declaration(payload), &registry);
        assert!(
            errors.iter().any(|e| e.contains("Download")),
            "expected an enum-membership error for nested Download, got: {errors:?}"
        );
    }

    #[test]
    fn absent_enum_field_is_not_an_error() {
        let registry = test_registry();
        let (errors, _) = declaration_errors(&declaration(DeclarationPayload::new()), &registry);
        assert!(
            errors.is_empty(),
            "absent optional field flagged: {errors:?}"
        );
    }
}

#[cfg(test)]
mod scaffold_value_tests {
    use super::generate_field_value;

    /// `--full` scaffolds every optional key — but mutually exclusive
    /// siblings must not both appear, or contour emits a document its own
    /// validator rejects. (softwareupdate.settings carries the canonical
    /// pair: Beta.OfferPrograms vs Beta.RequireProgram.)
    #[test]
    fn full_scaffold_omits_mutually_exclusive_siblings() {
        let registry = crate::schema::SchemaRegistry::embedded().unwrap();
        let manifest = registry
            .get("com.apple.configuration.softwareupdate.settings")
            .unwrap();
        let field = manifest.fields.get("Beta").unwrap();
        let beta = generate_field_value("Beta", field, manifest, true);

        let has_offer = beta.get("OfferPrograms").is_some();
        let has_require = beta.get("RequireProgram").is_some();
        assert!(
            !(has_offer && has_require),
            "scaffold emitted both mutually exclusive keys: {beta}"
        );
        assert!(
            has_offer || has_require,
            "scaffold should still illustrate one of them"
        );
    }

    /// app.managed's four delivery keys are mutually exclusive at the TOP
    /// level, where there is no parent dictionary to key the rule on.
    /// BundleID wins: the only member valid on both macOS and iOS.
    #[test]
    fn full_scaffold_picks_bundle_id_for_app_managed() {
        let registry = crate::schema::SchemaRegistry::embedded().unwrap();
        let manifest = registry
            .get("com.apple.configuration.app.managed")
            .expect("app.managed is in the embedded schema");

        let (payload, choice) = super::build_top_level_payload(manifest, true);
        let choice = choice.expect("app.managed declares an exclusive group");

        assert_eq!(choice.chosen, "BundleID");
        assert!(
            payload.get("BundleID").is_some(),
            "scaffold dropped the member it claims to have chosen"
        );
        for other in ["AppStoreID", "ManifestURL", "AppComposedIdentifier"] {
            assert!(
                payload.get(other).is_none(),
                "scaffold emitted {other} alongside BundleID; Apple allows only one"
            );
            assert!(
                choice.omitted.iter().any(|o| o == other),
                "{other} was dropped but not reported to the operator"
            );
        }
    }

    /// A defaultless enum field must scaffold as a member of its rangelist,
    /// not as `""` — generate's fail-closed gate rejects non-members.
    #[test]
    fn defaultless_enum_field_scaffolds_first_allowed_value() {
        use crate::schema::types::FieldFlags;
        use std::collections::HashMap;

        let field = crate::schema::FieldDefinition {
            allowed_scopes: std::collections::HashMap::new(),
            name: "Cadence".to_string(),
            range_min: None,
            range_max: None,
            subtype: None,
            format: None,
            asset_types: Vec::new(),
            path: "Cadence".to_string(),
            field_type: crate::schema::FieldType::String,
            flags: FieldFlags::default(),
            title: "Cadence".to_string(),
            description: String::new(),
            default: None,
            allowed_values: vec!["All".to_string(), "Oldest".to_string()],
            depth: 0,
            parent_key: None,
            platforms: Vec::new(),
            min_version: None,
            deprecated_in: None,
            introduced_by_platform: HashMap::new(),
            deprecated_by_platform: HashMap::new(),
            removed_by_platform: Default::default(),
            combinetype: None,
        };
        let manifest = crate::schema::PayloadManifest {
            manifest_source: None,
            fields_recording_availability: Default::default(),
            payload_type: "com.test.configuration.scaffold".to_string(),
            kind: None,
            title: "Scaffold".to_string(),
            description: String::new(),
            platforms: crate::schema::types::Platforms::default(),
            min_versions: HashMap::new(),
            os_support: HashMap::new(),
            apply_mode: None,
            category: "ddm-configuration".to_string(),
            fields: HashMap::from([("Cadence".to_string(), field.clone())]),
            field_order: vec!["Cadence".to_string()],
            segments: vec![],
        };

        let value = generate_field_value("Cadence", &field, &manifest, true);
        assert_eq!(value, serde_json::json!("All"));
    }

    /// `--full` scaffolds must emit deployable enum values. The parquet stores
    /// string defaults JSON-encoded; if the decode is lost anywhere between
    /// mdm-schema and here, `Download` scaffolds as `"\"Allowed\""` — a value
    /// Apple's DDM engine rejects on device.
    #[test]
    fn full_scaffold_string_defaults_carry_no_embedded_quotes() {
        let registry = crate::schema::SchemaRegistry::embedded().unwrap();
        let manifest = registry
            .get("com.apple.configuration.softwareupdate.settings")
            .unwrap();

        let field = manifest.fields.get("AutomaticActions").unwrap();
        let value = generate_field_value("AutomaticActions", field, manifest, true);

        let download = value
            .get("Download")
            .and_then(serde_json::Value::as_str)
            .expect("AutomaticActions.Download should scaffold as a string");
        assert_eq!(
            download, "Allowed",
            "scaffolded enum default must not carry embedded JSON quotes"
        );
    }
}

#[cfg(test)]
mod placeholder_key_tests {
    use super::*;

    fn placeholder_keys(v: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(o) => {
                for (k, child) in o {
                    if crate::schema::FieldDefinition::is_placeholder_name(k) {
                        out.push(format!("{path}.{k}"));
                    }
                    placeholder_keys(child, &format!("{path}.{k}"), out);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    placeholder_keys(item, &format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }

    /// Apple writes `ANY` under a dictionary whose keys the operator names.
    /// `--full` must leave that dictionary empty, never emit `"ANY": {…}`.
    #[test]
    fn no_full_declaration_emits_a_placeholder_key() {
        let registry = SchemaRegistry::embedded().expect("embedded registry loads");
        let mut offenders = Vec::new();
        let mut dynamic = 0usize;
        for m in registry.all().filter(|m| m.category.starts_with("ddm-")) {
            if m.fields
                .values()
                .any(|f| m.dynamic_value_shape(f).is_some())
            {
                dynamic += 1;
            }
            for f in m.top_level_fields() {
                let v = generate_field_value(&f.path, f, m, true);
                placeholder_keys(
                    &v,
                    &format!("{}.{}", m.payload_type, f.name),
                    &mut offenders,
                );
            }
        }
        assert!(
            offenders.is_empty(),
            "placeholder keys emitted:\n{}",
            offenders.join("\n")
        );
        assert!(
            dynamic >= 3,
            "expected several dynamic-key declarations, saw {dynamic}"
        );
    }

    /// The R7 acceptance case: `Privacy.PermissionDefaults` is keyed by app
    /// and its value shape is the per-app permission dictionary.
    #[test]
    fn app_settings_permission_defaults_reports_its_value_shape() {
        let registry = SchemaRegistry::embedded().expect("embedded registry loads");
        let m = registry
            .get("com.apple.configuration.app.settings")
            .expect("app.settings is in the schema");
        let defaults = m
            .field_by_path("Privacy.PermissionDefaults")
            .expect("Privacy.PermissionDefaults exists");
        let shape = m
            .dynamic_value_shape(defaults)
            .expect("PermissionDefaults is keyed by the operator");
        assert!(shape.is_placeholder(), "the shape *is* the ANY child");
        let names = m.child_names(shape);
        for want in ["Camera", "Microphone", "OrganizationJustification"] {
            assert!(names.contains(&want), "value shape lacks {want}: {names:?}");
        }
        // And an ordinary dictionary reports nothing.
        let privacy = m.field_by_path("Privacy").unwrap();
        assert!(m.dynamic_value_shape(privacy).is_none());
    }
}
