//! Profile generation from schema and recipes.
//!
//! Generates mobileconfig profiles from embedded Apple payload schemas,
//! with optional recipe support for multi-profile bundles.

use crate::config::ProfileConfig;
use crate::output::OutputMode;
use crate::recipe;
use crate::schema::{FieldDefinition, FieldType, SchemaRegistry};
use anyhow::{Context, Result};
use base64::Engine;
use colored::Colorize;
use contour_profiles::ProfileBuilder;
use inquire::{Confirm, MultiSelect, Select, Text};
use plist::{Dictionary, Value};
use std::collections::HashMap;
use std::path::Path;

/// Load schema registry — embedded base, optionally merged with external schemas.
pub fn load_registry(schema_path: Option<&str>) -> Result<SchemaRegistry> {
    let mut registry = SchemaRegistry::embedded()?;
    if let Some(p) = schema_path {
        let external = SchemaRegistry::from_auto_detect(Path::new(p))?;
        registry.merge(external);
    }
    Ok(registry)
}

/// Convert a TOML value to a plist value.
fn toml_to_plist(val: &toml::Value) -> Value {
    match val {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::Integer((*i).into()),
        toml::Value::Float(f) => Value::Real(*f),
        toml::Value::Boolean(b) => Value::Boolean(*b),
        toml::Value::Array(arr) => Value::Array(arr.iter().map(toml_to_plist).collect()),
        toml::Value::Table(tbl) => {
            let mut dict = Dictionary::new();
            for (k, v) in tbl {
                dict.insert(k.clone(), toml_to_plist(v));
            }
            Value::Dictionary(dict)
        }
        toml::Value::Datetime(dt) => Value::String(dt.to_string()),
    }
}

/// Apply a dot-notation key into a nested dictionary structure.
///
/// For example, `"PlatformSSO.AuthenticationMethod"` with value `"UserSecureEnclaveKey"`
/// creates `{"PlatformSSO": {"AuthenticationMethod": "UserSecureEnclaveKey"}}`.
fn apply_nested_field(dict: &mut Dictionary, dotted_key: &str, value: Value) {
    let parts: Vec<&str> = dotted_key.splitn(2, '.').collect();
    if parts.len() == 1 {
        dict.insert(dotted_key.to_string(), value);
    } else {
        let parent = parts[0];
        let rest = parts[1];

        // Get or create the parent dictionary
        if !dict.contains_key(parent) {
            dict.insert(parent.to_string(), Value::Dictionary(Dictionary::new()));
        }

        if let Some(Value::Dictionary(inner)) = dict.get_mut(parent) {
            apply_nested_field(inner, rest, value);
        }
    }
}

/// Result of resolving a value reference.
#[derive(Debug)]
struct ResolvedValue {
    /// The resolved string (base64-encoded if binary).
    value: String,
    /// Whether the resolved value is binary data (base64-encoded).
    is_binary: bool,
}

/// Resolve a value that may be a secret reference (`op://`, `env:`, `file:`).
fn resolve_value(raw: &str) -> Result<ResolvedValue> {
    if raw.starts_with("op://") {
        resolve_op(raw)
    } else if let Some(env_name) = raw.strip_prefix("env:") {
        let val = std::env::var(env_name)
            .with_context(|| format!("Environment variable '{env_name}' not set"))?;
        Ok(ResolvedValue {
            value: val,
            is_binary: false,
        })
    } else if let Some(path) = raw.strip_prefix("file:") {
        let bytes = std::fs::read(path).with_context(|| format!("Failed to read file: {path}"))?;
        Ok(ResolvedValue {
            value: base64_encode(&bytes),
            is_binary: true,
        })
    } else {
        Ok(ResolvedValue {
            value: raw.to_string(),
            is_binary: false,
        })
    }
}

/// Resolve an `op://` reference via the 1Password CLI.
fn resolve_op(reference: &str) -> Result<ResolvedValue> {
    let output = match std::process::Command::new("op")
        .args(["read", reference, "--no-newline"])
        .output()
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "1Password CLI ('op') not found.\n\
                 Install it from https://developer.1password.com/docs/cli/get-started/"
            );
        }
        Err(e) => {
            anyhow::bail!("Failed to run 'op' CLI: {e}");
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let hint = op_error_hint(&stderr);
        anyhow::bail!("1Password read failed for '{reference}': {stderr}{hint}");
    }
    let bytes = &output.stdout;
    // Heuristic: if bytes aren't valid UTF-8, treat as binary
    match String::from_utf8(bytes.clone()) {
        Ok(s) => Ok(ResolvedValue {
            value: s,
            is_binary: false,
        }),
        Err(_) => Ok(ResolvedValue {
            value: base64_encode(bytes),
            is_binary: true,
        }),
    }
}

/// Map common `op` CLI error patterns to actionable hints.
fn op_error_hint(stderr: &str) -> &'static str {
    let lower = stderr.to_lowercase();
    if lower.contains("not signed in") || lower.contains("sign in") {
        "\nHint: Run 'op signin' to authenticate with 1Password."
    } else if lower.contains("not found")
        || lower.contains("isn't an item")
        || lower.contains("could not find")
    {
        "\nHint: Check the vault/item/field path in your op:// reference."
    } else if lower.contains("biometric") || lower.contains("touch id") {
        "\nHint: Approve the biometric prompt to allow 1Password access."
    } else if lower.contains("unauthorized") || lower.contains("session expired") {
        "\nHint: Your 1Password session has expired. Run 'op signin' to re-authenticate."
    } else {
        ""
    }
}

/// Base64-encode raw bytes.
fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Parse `KEY=VALUE` strings into a map, resolving `op://`, `env:`, and `file:` prefixes.
fn parse_vars(vars: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for v in vars {
        let (key, value) = v
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Invalid --set format: '{v}' (expected KEY=VALUE)"))?;
        let resolved = resolve_value(value)?;
        map.insert(key.to_string(), resolved.value);
    }
    Ok(map)
}

/// Resolve secret references (`op://`, `env:`, `file:`) in TOML string values.
/// For binary results, returns a plist `Data` value instead of a string.
fn resolve_toml_value(val: &toml::Value) -> Result<toml::Value> {
    match val {
        toml::Value::String(s) if is_secret_reference(s) => {
            let resolved = resolve_value(s)?;
            if resolved.is_binary {
                // Binary data stays as a string here — will be handled as base64
                // in toml_to_plist_resolved() which converts it to Value::Data
                Ok(toml::Value::String(format!("base64:{}", resolved.value)))
            } else {
                Ok(toml::Value::String(resolved.value))
            }
        }
        toml::Value::Array(arr) => {
            let resolved: Result<Vec<_>> = arr.iter().map(resolve_toml_value).collect();
            Ok(toml::Value::Array(resolved?))
        }
        toml::Value::Table(tbl) => {
            let mut resolved = toml::map::Map::new();
            for (k, v) in tbl {
                resolved.insert(k.clone(), resolve_toml_value(v)?);
            }
            Ok(toml::Value::Table(resolved))
        }
        other => Ok(other.clone()),
    }
}

/// Check if a string value is a secret reference that needs resolution.
fn is_secret_reference(s: &str) -> bool {
    s.starts_with("op://") || s.starts_with("env:") || s.starts_with("file:")
}

/// Convert a TOML value to plist, handling `base64:` prefix as binary Data.
fn toml_to_plist_resolved(val: &toml::Value) -> Value {
    match val {
        toml::Value::String(s) if s.starts_with("base64:") => {
            let b64 = &s["base64:".len()..];
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap_or_default();
            Value::Data(bytes)
        }
        _ => toml_to_plist(val),
    }
}

/// Resolve all secret references in a recipe's profile specs.
fn resolve_recipe_secrets(profiles: &mut [recipe::ProfileSpec]) -> Result<()> {
    for spec in profiles.iter_mut() {
        let mut resolved_fields = HashMap::new();
        for (k, v) in &spec.fields {
            resolved_fields.insert(k.clone(), resolve_toml_value(v)?);
        }
        spec.fields = resolved_fields;

        let mut resolved_extra = HashMap::new();
        for (k, v) in &spec.extra_fields {
            resolved_extra.insert(k.clone(), resolve_toml_value(v)?);
        }
        spec.extra_fields = resolved_extra;
    }
    Ok(())
}

/// Replace `{{KEY}}` placeholders in content with values from the vars map.
/// Returns the substituted content.
fn substitute_placeholders(content: &[u8], vars: &HashMap<String, String>) -> Vec<u8> {
    if vars.is_empty() {
        return content.to_vec();
    }
    let mut s = String::from_utf8_lossy(content).into_owned();
    for (key, value) in vars {
        let placeholder = format!("{{{{{key}}}}}");
        s = s.replace(&placeholder, value);
    }
    s.into_bytes()
}

/// Scan a string for `{{...}}` placeholder patterns and return them.
fn find_placeholders(content: &str) -> Vec<String> {
    let mut placeholders = Vec::new();
    let mut pos = 0;
    let bytes = content.as_bytes();
    while pos + 3 < bytes.len() {
        if bytes[pos] == b'{' && bytes[pos + 1] == b'{' {
            if let Some(end) = content[pos + 2..].find("}}") {
                let placeholder = &content[pos..pos + 2 + end + 2];
                if !placeholders.contains(&placeholder.to_string()) {
                    placeholders.push(placeholder.to_string());
                }
                pos += 2 + end + 2;
                continue;
            }
        }
        pos += 1;
    }
    placeholders
}

/// Generate a single profile from schema.
pub fn handle_generate(
    payload_type: &str,
    output: Option<&str>,
    org: Option<&str>,
    full: bool,
    schema_path: Option<&str>,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
    format: &str,
) -> Result<()> {
    let registry = load_registry(schema_path)?;

    let manifest = registry.get_by_name(payload_type).ok_or_else(|| {
        anyhow::anyhow!(
            "Payload type '{payload_type}' not found in schema.\n\
             Use 'contour profile docs list' to see available types."
        )
    })?;

    // Skip DDM declarations
    if manifest.category.starts_with("ddm-") {
        anyhow::bail!(
            "'{payload_type}' is a DDM declaration, not a profile payload.\n\
             Use 'contour profile ddm generate {payload_type}' instead."
        );
    }

    // Build payload content from schema fields
    let payload_content = build_payload_from_schema(manifest, &HashMap::new(), full);

    let is_plist = format == "plist";

    let (output_bytes, default_ext) = if is_plist {
        // Raw plist — just the payload dictionary, no mobileconfig envelope
        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, &Value::Dictionary(payload_content))?;
        (buf, "plist")
    } else {
        // Full mobileconfig envelope.
        // Resolve org domain: CLI --org → profile.toml → .contour/config.toml → error.
        // We refuse to default to "com.example" because the resulting PayloadIdentifier
        // is not deployable and silently produces invalid output (caught only at validation).
        let domain = org
            .map(ToString::to_string)
            .or_else(|| config.map(|c| c.organization.domain.clone()))
            .or_else(|| {
                contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.domain)
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--org is required (e.g., --org com.yourorg)\n\
                     Alternatively, set organization.domain in profile.toml or .contour/config.toml"
                )
            })?;

        let short = manifest
            .payload_type
            .split('.')
            .next_back()
            .unwrap_or("profile");
        let identifier = format!("{domain}.{short}");

        let bytes = ProfileBuilder::new(&domain, &identifier)
            .display_name(&manifest.title)
            .description(&manifest.description)
            .build(&manifest.payload_type, payload_content)?;
        (bytes, "mobileconfig")
    };

    // Output path
    let slug = manifest
        .title
        .to_lowercase()
        .replace([' ', ':'], "-")
        .replace("--", "-");
    let output_path = output.map_or_else(
        || format!("{slug}.{default_ext}"),
        std::string::ToString::to_string,
    );

    // Create parent dirs
    if let Some(parent) = Path::new(&output_path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&output_path, &output_bytes)?;

    // Auto-validate generated output (mobileconfig only, not raw plist)
    if !is_plist {
        let _ =
            super::post_generate::validate_generated_profile(Path::new(&output_path), output_mode);
    }

    if output_mode == OutputMode::Json {
        let result = serde_json::json!({
            "success": true,
            "payload_type": manifest.payload_type,
            "title": manifest.title,
            "output": output_path,
            "format": format,
            "fields": if full { "all" } else { "required" }
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let format_label = if is_plist {
            "plist (raw payload)"
        } else {
            "mobileconfig"
        };
        println!(
            "{} Generated {}: {}",
            "✓".green(),
            format_label,
            output_path.cyan()
        );
        println!("  {} {}", "Type:".bold(), manifest.payload_type);
        println!("  {} {}", "Title:".bold(), manifest.title);
        println!(
            "  {} {}",
            "Fields:".bold(),
            if full { "all" } else { "required only" }
        );
        if is_plist {
            println!(
                "\n{}",
                "Raw plist for WS1 Custom Settings — paste into Custom XML payload.".dimmed()
            );
        } else {
            println!(
                "\n{}",
                "Edit the profile to set your values, then deploy via your MDM.".dimmed()
            );
        }
    }

    Ok(())
}

/// Generate profiles from a recipe.
pub fn handle_generate_recipe(
    recipe_name: &str,
    recipe_path: Option<&str>,
    output_dir: Option<&str>,
    org: Option<&str>,
    schema_path: Option<&str>,
    config: Option<&ProfileConfig>,
    vars: &[String],
    output_mode: OutputMode,
    format: &str,
) -> Result<()> {
    let var_map = parse_vars(vars)?;
    let mut r = recipe::loader::load_recipe(recipe_name, recipe_path)?;
    let registry = load_registry(schema_path)?;

    // Resolve op://, env:, file: references in recipe field values
    resolve_recipe_secrets(&mut r.profiles)?;

    // Resolve org domain: CLI --org → profile.toml → .contour/config.toml → error.
    // We refuse to default to "com.example" because the resulting PayloadIdentifier
    // is not deployable and silently produces invalid output.
    let domain = org
        .map(ToString::to_string)
        .or_else(|| config.map(|c| c.organization.domain.clone()))
        .or_else(|| {
            contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.domain)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--org is required (e.g., --org com.yourorg)\n\
                 Alternatively, set organization.domain in profile.toml or .contour/config.toml"
            )
        })?;

    // Output directory
    let out_dir = output_dir.unwrap_or(&r.recipe.name);
    if !Path::new(out_dir).exists() {
        std::fs::create_dir_all(out_dir)?;
    }

    let mut generated = Vec::new();
    let mut all_placeholders = Vec::new();

    for spec in &r.profiles {
        let manifest = registry.get_by_name(&spec.payload_type);

        // Build payload content (using resolved values for secret references)
        let payload_content = if let Some(m) = manifest {
            let mut content = build_payload_from_schema(m, &spec.fields, true);
            // Apply extra fields with dot-notation nesting
            for (key, val) in &spec.extra_fields {
                apply_nested_field(&mut content, key, toml_to_plist_resolved(val));
            }
            content
        } else {
            // No schema — vendor-specific payload, build from recipe fields only
            if output_mode == OutputMode::Human {
                println!(
                    "  {} No schema for '{}', using recipe fields only",
                    "!".yellow(),
                    spec.payload_type
                );
            }
            let mut content = Dictionary::new();
            for (key, val) in &spec.fields {
                apply_nested_field(&mut content, key, toml_to_plist_resolved(val));
            }
            for (key, val) in &spec.extra_fields {
                apply_nested_field(&mut content, key, toml_to_plist_resolved(val));
            }
            content
        };

        let is_plist = format == "plist";

        let profile_bytes = if is_plist {
            let mut buf = Vec::new();
            plist::to_writer_xml(&mut buf, &Value::Dictionary(payload_content))?;
            buf
        } else {
            let short = spec
                .payload_type
                .split('.')
                .next_back()
                .unwrap_or("profile");
            let identifier = format!("{domain}.{short}");

            ProfileBuilder::new(&domain, &identifier)
                .display_name(&spec.display_name)
                .description(&spec.description)
                .removal_disallowed(spec.removal_disallowed)
                .build(&spec.payload_type, payload_content)?
        };

        // Swap extension for plist format
        let filename = if is_plist {
            spec.filename.replace(".mobileconfig", ".plist")
        } else {
            spec.filename.clone()
        };
        let output_path = Path::new(out_dir).join(&filename).display().to_string();

        // Apply --set variable substitution before writing
        let final_bytes = substitute_placeholders(&profile_bytes, &var_map);
        std::fs::write(&output_path, &final_bytes)?;

        // Auto-validate generated output
        if !is_plist {
            let _ = super::post_generate::validate_generated_profile(
                Path::new(&output_path),
                output_mode,
            );
        }

        // Check for remaining placeholders
        let xml = String::from_utf8_lossy(&final_bytes);
        let placeholders = find_placeholders(&xml);
        for p in &placeholders {
            if !all_placeholders.contains(p) {
                all_placeholders.push(p.clone());
            }
        }

        generated.push((output_path, spec.display_name.clone()));
    }

    if output_mode == OutputMode::Json {
        let result = serde_json::json!({
            "success": true,
            "recipe": r.recipe.name,
            "vendor": r.recipe.vendor,
            "output_dir": out_dir,
            "profiles": generated.iter().map(|(path, name)| {
                serde_json::json!({"path": path, "display_name": name})
            }).collect::<Vec<_>>(),
            "placeholders": all_placeholders,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "{} Generated {} profiles from recipe '{}':",
            "✓".green(),
            generated.len(),
            r.recipe.name.cyan()
        );
        if let Some(vendor) = &r.recipe.vendor {
            println!("  {} {}", "Vendor:".bold(), vendor);
        }
        println!("  {} {}", "Output:".bold(), out_dir);
        println!();
        for (path, name) in &generated {
            println!("  {} {}", "→".green(), path);
            println!("    {}", name.dimmed());
        }

        if !all_placeholders.is_empty() {
            println!(
                "\n{} Replace these placeholders before deploying:",
                "!".yellow()
            );
            for p in &all_placeholders {
                println!("  {} {}", "•".yellow(), p);
            }
        }
    }

    Ok(())
}

/// List available recipes.
pub fn handle_list_recipes(recipe_path: Option<&str>, output_mode: OutputMode) -> Result<()> {
    let recipes = recipe::loader::list_recipes(recipe_path);

    if output_mode == OutputMode::Json {
        let result = serde_json::json!({
            "recipes": recipes.iter().map(|r| {
                serde_json::json!({
                    "name": r.name,
                    "description": r.description,
                    "vendor": r.vendor,
                    "profile_count": r.profile_count,
                    "source": r.source,
                    "placeholders": r.placeholders,
                    "secrets": r.secrets,
                })
            }).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        if recipes.is_empty() {
            println!("{} No recipes found.", "!".yellow());
            return Ok(());
        }
        println!("{} Available recipes:\n", "✓".green());
        for r in &recipes {
            let vendor = r
                .vendor
                .as_deref()
                .map(|v| format!(" ({})", v))
                .unwrap_or_default();
            println!(
                "  {} {}{} — {} [{} profiles]",
                "•".cyan(),
                r.name.bold(),
                vendor.dimmed(),
                r.description,
                r.profile_count,
            );
            // Show non-secret vars
            let non_secret_vars: Vec<_> = r
                .placeholders
                .iter()
                .filter(|p| !r.secrets.contains(p))
                .collect();
            if !non_secret_vars.is_empty() {
                let set_args: Vec<String> = non_secret_vars
                    .iter()
                    .map(|p| format!("--set {p}=..."))
                    .collect();
                println!("    {} {}", "vars:".dimmed(), set_args.join(" ").dimmed());
            }
            // Show secrets separately with op:// hints
            if !r.secrets.is_empty() {
                let secret_args: Vec<String> = r
                    .secrets
                    .iter()
                    .map(|s| format!("--set {s}=op://vault/item/field"))
                    .collect();
                println!(
                    "    {} {}",
                    "secrets:".dimmed(),
                    secret_args.join(" ").dimmed()
                );
            }
            if r.source != "embedded" {
                println!("    {}", r.source.dimmed());
            }
        }
        println!(
            "\n{}",
            "Use 'contour profile generate --recipe <name>' to generate.".dimmed()
        );
    }

    Ok(())
}

/// Create a recipe TOML file from payload types by reading their schemas.
pub fn handle_create_recipe(
    recipe_name: &str,
    payload_types: &[String],
    output: Option<&str>,
    schema_path: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    if payload_types.is_empty() {
        anyhow::bail!(
            "Specify payload types after --create-recipe <name>.\n\
             Example: contour profile generate --create-recipe m365 \\\n  \
             --schema-path ~/ProfileManifests \\\n  \
             com.microsoft.Edge com.microsoft.Outlook"
        );
    }

    let registry = load_registry(schema_path)?;

    let mut toml_out = String::new();
    toml_out.push_str(&format!(
        "[recipe]\nname = \"{recipe_name}\"\ndescription = \"\"\n# vendor = \"\"\n# variables = []\n\n"
    ));

    let mut count = 0;
    for pt in payload_types {
        let manifest = registry.get_by_name(pt);

        let (payload_type, title, description) = if let Some(m) = manifest {
            (
                m.payload_type.clone(),
                m.title.clone(),
                m.description.clone(),
            )
        } else {
            (pt.clone(), pt.clone(), String::new())
        };

        // Build filename from payload type (use full type to avoid collisions)
        let filename = format!("{}.mobileconfig", payload_type.to_lowercase());

        toml_out.push_str("[[profile]]\n");
        toml_out.push_str(&format!("filename = \"{filename}\"\n"));
        toml_out.push_str(&format!("payload_type = \"{payload_type}\"\n"));
        toml_out.push_str(&format!("display_name = \"{title}\"\n"));
        if !description.is_empty() {
            // Truncate long descriptions for the recipe
            let desc = if description.len() > 100 {
                format!("{}...", &description[..97])
            } else {
                description
            };
            toml_out.push_str(&format!("description = \"{desc}\"\n"));
        }

        // Add required fields from schema (skip Payload* metadata — ProfileBuilder handles those)
        if let Some(m) = manifest {
            let skip_prefixes = [
                "PayloadDisplayName",
                "PayloadIdentifier",
                "PayloadType",
                "PayloadUUID",
                "PayloadVersion",
                "PayloadDescription",
                "PayloadOrganization",
                "PayloadEnabled",
                "PayloadScope",
                "PFC_",
            ];
            let should_skip = |name: &str| skip_prefixes.iter().any(|p| name.starts_with(p));

            let required: Vec<_> = m
                .field_order
                .iter()
                .filter_map(|name| m.fields.get(name))
                .filter(|f| f.flags.required && f.depth == 0 && !should_skip(&f.name))
                .collect();

            if !required.is_empty() {
                toml_out.push_str("\n[profile.fields]\n");
                for f in &required {
                    let val = if let Some(default) = &f.default {
                        match f.field_type {
                            FieldType::Boolean => default.clone(),
                            FieldType::Integer => default.clone(),
                            _ => format!("\"{}\"", default.replace('"', "\\\"")),
                        }
                    } else {
                        match f.field_type {
                            FieldType::Boolean => "false".to_string(),
                            FieldType::Integer => "0".to_string(),
                            FieldType::Array => "[]".to_string(),
                            _ => "\"\"".to_string(),
                        }
                    };
                    toml_out.push_str(&format!("{} = {val}\n", f.name));
                }
            }

            // Add a commented sample of top-level optional fields
            let optional: Vec<_> = m
                .field_order
                .iter()
                .filter_map(|name| m.fields.get(name))
                .filter(|f| !f.flags.required && f.depth == 0 && !should_skip(&f.name))
                .take(10)
                .collect();

            if !optional.is_empty() {
                let total_optional = m
                    .field_order
                    .iter()
                    .filter_map(|name| m.fields.get(name))
                    .filter(|f| !f.flags.required && f.depth == 0 && !should_skip(&f.name))
                    .count();
                toml_out.push_str(&format!(
                    "\n# Optional fields ({total_optional} available, showing first {}):\n",
                    optional.len()
                ));
                for f in &optional {
                    let val = match f.field_type {
                        FieldType::Boolean => "false",
                        FieldType::Integer => "0",
                        FieldType::Array => "[]",
                        _ => "\"\"",
                    };
                    toml_out.push_str(&format!("# {} = {val}\n", f.name));
                }
            }
        }

        toml_out.push('\n');
        count += 1;
    }

    // Output
    let output_path = output
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("{recipe_name}.toml"));

    std::fs::write(&output_path, &toml_out)?;

    if output_mode == OutputMode::Json {
        let result = serde_json::json!({
            "success": true,
            "recipe": recipe_name,
            "output": output_path,
            "profiles": count,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "{} Created recipe '{}' with {} profiles: {}",
            "✓".green(),
            recipe_name.cyan(),
            count,
            output_path.cyan()
        );
        println!(
            "\n{}",
            "Edit the TOML to set field values, then generate with:".dimmed()
        );
        println!(
            "  contour profile generate --recipe-path {} --recipe {recipe_name}",
            output_path
        );
    }

    Ok(())
}

/// Interactive profile generation — pick segments, set field values, write recipe TOML.
pub fn handle_generate_interactive(
    payload_type: &str,
    output: Option<&str>,
    schema_path: Option<&str>,
) -> Result<()> {
    let registry = load_registry(schema_path)?;

    let manifest = registry.get_by_name(payload_type).ok_or_else(|| {
        anyhow::anyhow!(
            "Payload type '{payload_type}' not found in schema.\n\
             Use 'contour profile docs list' to see available types."
        )
    })?;

    if manifest.category.starts_with("ddm-") {
        anyhow::bail!(
            "'{payload_type}' is a DDM declaration, not a profile payload.\n\
             Use 'contour profile ddm generate {payload_type}' instead."
        );
    }

    println!(
        "\n{} {} — {} ({} fields)",
        "▶".cyan(),
        manifest.payload_type.bold(),
        manifest.title,
        manifest.fields.len()
    );
    if !manifest.description.is_empty() {
        println!("  {}", manifest.description.dimmed());
    }
    println!();

    // Determine which fields to configure
    let selected_fields = if !manifest.segments.is_empty() {
        select_fields_by_segment(manifest)?
    } else {
        select_fields_all(manifest)?
    };

    if selected_fields.is_empty() {
        println!("{} No fields selected, nothing to generate.", "!".yellow());
        return Ok(());
    }

    // Prompt for values
    let mut field_values: Vec<(String, String)> = Vec::new();
    println!(
        "\n{} Set values for {} fields (Enter to skip/use default):\n",
        "▶".cyan(),
        selected_fields.len()
    );

    for field in &selected_fields {
        if let Some(val) = prompt_field_value(field) {
            field_values.push((field.name.clone(), val));
        }
    }

    // Generate recipe TOML
    let recipe_toml = build_interactive_recipe(manifest, &field_values);

    let output_path = output
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("{}.toml", manifest.payload_type.to_lowercase()));

    std::fs::write(&output_path, &recipe_toml)?;

    println!("\n{} Recipe written: {}", "✓".green(), output_path.cyan());
    println!("\n{}", "Edit the recipe, then generate with:".dimmed());
    println!(
        "  contour profile generate --recipe-path {} --recipe {}",
        output_path,
        manifest.payload_type.to_lowercase().replace('.', "-")
    );

    Ok(())
}

/// Prompt user to select segments, then return the union of fields from selected segments.
fn select_fields_by_segment(
    manifest: &crate::schema::PayloadManifest,
) -> Result<Vec<&FieldDefinition>> {
    let segment_labels: Vec<String> = manifest
        .segments
        .iter()
        .map(|s| {
            let count = s.field_names.len();
            format!("{} ({count} fields)", s.name)
        })
        .collect();

    println!(
        "{} {} has {} segments:",
        "▶".cyan(),
        manifest.title.bold(),
        manifest.segments.len()
    );

    let selected = MultiSelect::new("Select segments to configure:", segment_labels)
        .with_help_message("Space to toggle, Enter to confirm")
        .prompt()?;

    if selected.is_empty() {
        return Ok(vec![]);
    }

    // Collect field names from selected segments
    let mut selected_field_names: Vec<&str> = Vec::new();
    for label in &selected {
        // Extract segment name (everything before " (")
        let seg_name = label.split(" (").next().unwrap_or(label);
        if let Some(segment) = manifest.segments.iter().find(|s| s.name == seg_name) {
            for fname in &segment.field_names {
                if !selected_field_names.contains(&fname.as_str()) {
                    selected_field_names.push(fname);
                }
            }
        }
    }

    // Resolve to FieldDefinitions (top-level only)
    let fields: Vec<&FieldDefinition> = selected_field_names
        .iter()
        .filter_map(|name| manifest.fields.get(*name))
        .filter(|f| f.depth == 0)
        .collect();

    Ok(fields)
}

/// Fallback: let user pick from all top-level fields via MultiSelect.
fn select_fields_all(manifest: &crate::schema::PayloadManifest) -> Result<Vec<&FieldDefinition>> {
    let top_level = manifest.top_level_fields();

    if top_level.is_empty() {
        return Ok(vec![]);
    }

    let labels: Vec<String> = top_level
        .iter()
        .map(|f| {
            let type_str = f.field_type.as_str();
            let req = if f.flags.required { " [required]" } else { "" };
            let title = if f.title.is_empty() || f.title == f.name {
                String::new()
            } else {
                format!(" — {}", f.title)
            };
            format!("{} ({}){}{}", f.name, type_str, title, req)
        })
        .collect();

    let selected = MultiSelect::new("Select fields to configure:", labels)
        .with_help_message("Space to toggle, Enter to confirm")
        .prompt()?;

    // Map back to field definitions
    let fields: Vec<&FieldDefinition> = selected
        .iter()
        .filter_map(|label| {
            let name = label.split(' ').next()?;
            manifest.fields.get(name)
        })
        .collect();

    Ok(fields)
}

/// Prompt for a single field value based on its type. Returns None if skipped.
fn prompt_field_value(field: &FieldDefinition) -> Option<String> {
    let default_hint = field
        .default
        .as_deref()
        .map(|d| format!(" [default: {d}]"))
        .unwrap_or_default();
    let label = format!("{}{}", field.name, default_hint);

    match field.field_type {
        FieldType::Boolean => {
            let default = field
                .default
                .as_deref()
                .and_then(|d| d.parse().ok())
                .unwrap_or(false);
            match Confirm::new(&label).with_default(default).prompt() {
                Ok(val) => Some(val.to_string()),
                Err(_) => None,
            }
        }
        FieldType::String if !field.allowed_values.is_empty() => {
            let options = field.allowed_values.clone();
            match Select::new(&label, options).prompt() {
                Ok(val) => Some(format!("\"{}\"", val.replace('"', "\\\""))),
                Err(_) => None,
            }
        }
        FieldType::Integer if !field.allowed_values.is_empty() => {
            let options = field.allowed_values.clone();
            Select::new(&label, options).prompt().ok()
        }
        FieldType::String => {
            let default = field.default.clone().unwrap_or_default();
            match Text::new(&label).with_default(&default).prompt() {
                Ok(val) if val.is_empty() => None,
                Ok(val) => Some(format!("\"{}\"", val.replace('"', "\\\""))),
                Err(_) => None,
            }
        }
        FieldType::Integer | FieldType::Real => {
            let default = field.default.clone().unwrap_or_else(|| "0".to_string());
            match Text::new(&label).with_default(&default).prompt() {
                Ok(val) if val.is_empty() => None,
                Ok(val) => Some(val),
                Err(_) => None,
            }
        }
        FieldType::Array | FieldType::Dictionary | FieldType::Data | FieldType::Date => {
            println!(
                "  {} {} ({}) — edit manually in TOML",
                "⊘".dimmed(),
                field.name.dimmed(),
                field.field_type.as_str()
            );
            None
        }
    }
}

/// Build a recipe TOML string from the manifest and user-provided field values.
fn build_interactive_recipe(
    manifest: &crate::schema::PayloadManifest,
    field_values: &[(String, String)],
) -> String {
    let recipe_name = manifest.payload_type.to_lowercase().replace('.', "-");
    let filename = format!("{}.mobileconfig", manifest.payload_type.to_lowercase());

    let mut toml = String::new();
    toml.push_str(&format!(
        "[recipe]\nname = \"{recipe_name}\"\ndescription = \"Generated interactively from {} schema\"\n\n",
        manifest.title
    ));
    toml.push_str("[[profile]]\n");
    toml.push_str(&format!("filename = \"{filename}\"\n"));
    toml.push_str(&format!("payload_type = \"{}\"\n", manifest.payload_type));
    toml.push_str(&format!("display_name = \"{}\"\n", manifest.title));
    if !manifest.description.is_empty() {
        let desc = if manifest.description.len() > 100 {
            format!("{}...", &manifest.description[..97])
        } else {
            manifest.description.clone()
        };
        toml.push_str(&format!("description = \"{desc}\"\n"));
    }

    if !field_values.is_empty() {
        toml.push_str("\n[profile.fields]\n");
        for (key, val) in field_values {
            toml.push_str(&format!("{key} = {val}\n"));
        }
    }

    toml.push('\n');
    toml
}

/// Build a plist Dictionary from a schema manifest, applying any field overrides.
fn build_payload_from_schema(
    manifest: &crate::schema::PayloadManifest,
    overrides: &HashMap<String, toml::Value>,
    full: bool,
) -> Dictionary {
    let mut dict = Dictionary::new();

    // Build index: for each field, find its children (next fields with depth = parent.depth + 1)
    let children_of = |parent_idx: usize, parent_depth: u8| -> Vec<usize> {
        let mut children = Vec::new();
        for i in (parent_idx + 1)..manifest.field_order.len() {
            let Some(f) = manifest.fields.get(&manifest.field_order[i]) else {
                continue;
            };
            if f.depth <= parent_depth {
                break; // Back to same or higher level — done
            }
            if f.depth == parent_depth + 1 {
                children.push(i);
            }
        }
        children
    };

    // Recursive builder for a field and its children
    fn build_field_value(
        manifest: &crate::schema::PayloadManifest,
        idx: usize,
        overrides: &HashMap<String, toml::Value>,
        full: bool,
        children_of: &dyn Fn(usize, u8) -> Vec<usize>,
    ) -> Value {
        let field_name = &manifest.field_order[idx];
        let field = &manifest.fields[field_name];

        // For Dictionary fields, build children inside
        if field.field_type == FieldType::Dictionary {
            let child_indices = children_of(idx, field.depth);
            if !child_indices.is_empty() {
                let mut inner = Dictionary::new();
                for ci in child_indices {
                    let child_name = &manifest.field_order[ci];
                    let child_field = &manifest.fields[child_name];

                    // Check override
                    if let Some(ov) = overrides.get(child_name) {
                        inner.insert(child_name.clone(), toml_to_plist_resolved(ov));
                        continue;
                    }

                    if !child_field.flags.required && !full {
                        continue;
                    }

                    let child_val = build_field_value(manifest, ci, overrides, full, children_of);
                    inner.insert(child_name.clone(), child_val);
                }
                return Value::Dictionary(inner);
            }
        }

        // Leaf value — always respect the field type, use default where it makes sense
        match field.field_type {
            FieldType::Boolean => {
                let v = field
                    .default
                    .as_deref()
                    .and_then(|d| d.parse().ok())
                    .unwrap_or(false);
                Value::Boolean(v)
            }
            FieldType::Integer => {
                let v = field
                    .default
                    .as_deref()
                    .and_then(|d| d.parse::<i64>().ok())
                    .unwrap_or(0);
                Value::Integer(v.into())
            }
            FieldType::Real => {
                let v = field
                    .default
                    .as_deref()
                    .and_then(|d| d.parse().ok())
                    .unwrap_or(0.0);
                Value::Real(v)
            }
            FieldType::Array => Value::Array(vec![]),
            FieldType::Dictionary => Value::Dictionary(Dictionary::new()),
            FieldType::Data => Value::Data(vec![]),
            _ => Value::String(field.default.clone().unwrap_or_default()),
        }
    }

    // Only process top-level fields (depth 0)
    for (idx, field_name) in manifest.field_order.iter().enumerate() {
        let Some(field) = manifest.fields.get(field_name) else {
            continue;
        };

        if field.depth > 0 {
            continue;
        }

        // Check override
        if let Some(override_val) = overrides.get(field_name) {
            apply_nested_field(&mut dict, field_name, toml_to_plist_resolved(override_val));
            continue;
        }

        // Skip optional unless --full
        if !field.flags.required && !full {
            continue;
        }

        let value = build_field_value(manifest, idx, overrides, full, &children_of);
        dict.insert(field_name.clone(), value);
    }

    // Apply any overrides for fields not in schema (e.g., dot-notation keys)
    for (key, val) in overrides {
        if !manifest.fields.contains_key(key) {
            apply_nested_field(&mut dict, key, toml_to_plist_resolved(val));
        }
    }

    dict
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toml_to_plist_string() {
        let val = toml::Value::String("hello".into());
        assert_eq!(toml_to_plist(&val), Value::String("hello".into()));
    }

    #[test]
    fn test_toml_to_plist_integer() {
        let val = toml::Value::Integer(42);
        assert_eq!(toml_to_plist(&val), Value::Integer(42.into()));
    }

    #[test]
    fn test_toml_to_plist_bool() {
        let val = toml::Value::Boolean(true);
        assert_eq!(toml_to_plist(&val), Value::Boolean(true));
    }

    #[test]
    fn test_toml_to_plist_array() {
        let val = toml::Value::Array(vec![
            toml::Value::String("a".into()),
            toml::Value::String("b".into()),
        ]);
        match toml_to_plist(&val) {
            Value::Array(arr) => assert_eq!(arr.len(), 2),
            _ => panic!("Expected Array"),
        }
    }

    #[test]
    fn test_apply_nested_field_simple() {
        let mut dict = Dictionary::new();
        apply_nested_field(&mut dict, "Key", Value::String("val".into()));
        assert_eq!(dict.get("Key"), Some(&Value::String("val".into())));
    }

    #[test]
    fn test_apply_nested_field_dotted() {
        let mut dict = Dictionary::new();
        apply_nested_field(
            &mut dict,
            "PlatformSSO.AuthenticationMethod",
            Value::String("UserSecureEnclaveKey".into()),
        );
        let psso = dict.get("PlatformSSO").unwrap();
        if let Value::Dictionary(inner) = psso {
            assert_eq!(
                inner.get("AuthenticationMethod"),
                Some(&Value::String("UserSecureEnclaveKey".into()))
            );
        } else {
            panic!("Expected Dictionary");
        }
    }

    #[test]
    fn test_apply_nested_field_deep() {
        let mut dict = Dictionary::new();
        apply_nested_field(
            &mut dict,
            "PayloadContent.URL",
            Value::String("https://example.com".into()),
        );
        apply_nested_field(
            &mut dict,
            "PayloadContent.Name",
            Value::String("Test CA".into()),
        );
        let pc = dict.get("PayloadContent").unwrap();
        if let Value::Dictionary(inner) = pc {
            assert_eq!(inner.len(), 2);
        } else {
            panic!("Expected Dictionary");
        }
    }

    #[test]
    fn test_find_placeholders() {
        let content = "https://{{OKTA_DOMAIN}}/api?token={{SCEP_CHALLENGE}}&other={{OKTA_DOMAIN}}";
        let placeholders = find_placeholders(content);
        assert_eq!(placeholders.len(), 2);
        assert!(placeholders.contains(&"{{OKTA_DOMAIN}}".to_string()));
        assert!(placeholders.contains(&"{{SCEP_CHALLENGE}}".to_string()));
    }

    #[test]
    fn test_find_placeholders_none() {
        let placeholders = find_placeholders("no placeholders here");
        assert!(placeholders.is_empty());
    }

    #[test]
    fn test_resolve_value_literal() {
        let result = resolve_value("acme.okta.com").unwrap();
        assert_eq!(result.value, "acme.okta.com");
        assert!(!result.is_binary);
    }

    #[test]
    fn test_resolve_value_env() {
        // HOME is always set on macOS/Linux
        let result = resolve_value("env:HOME").unwrap();
        assert!(!result.value.is_empty());
        assert!(!result.is_binary);
    }

    #[test]
    fn test_resolve_value_env_missing() {
        let result = resolve_value("env:CONTOUR_TEST_MISSING_VAR_12345");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not set"));
    }

    #[test]
    fn test_resolve_value_file() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("test.cer");
        std::fs::write(&cert_path, b"\x30\x82\x01\x00").unwrap();
        let reference = format!("file:{}", cert_path.display());
        let result = resolve_value(&reference).unwrap();
        assert!(result.is_binary);
        // Verify it's valid base64
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&result.value)
            .unwrap();
        assert_eq!(decoded, b"\x30\x82\x01\x00");
    }

    #[test]
    fn test_resolve_value_file_missing() {
        let result = resolve_value("file:/nonexistent/path/cert.cer");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_secret_reference() {
        assert!(is_secret_reference("op://vault/item/field"));
        assert!(is_secret_reference("env:MY_SECRET"));
        assert!(is_secret_reference("file:./cert.p12"));
        assert!(!is_secret_reference("literal-value"));
        assert!(!is_secret_reference("https://example.com"));
    }

    #[test]
    fn test_toml_to_plist_resolved_base64() {
        let val = toml::Value::String("base64:AQID".into());
        match toml_to_plist_resolved(&val) {
            Value::Data(bytes) => assert_eq!(bytes, vec![1, 2, 3]),
            other => panic!("Expected Data, got {other:?}"),
        }
    }

    #[test]
    fn test_toml_to_plist_resolved_normal_string() {
        let val = toml::Value::String("hello".into());
        assert_eq!(toml_to_plist_resolved(&val), Value::String("hello".into()));
    }

    #[test]
    fn test_resolve_toml_value_literal() {
        let val = toml::Value::String("literal".into());
        let resolved = resolve_toml_value(&val).unwrap();
        assert_eq!(resolved, toml::Value::String("literal".into()));
    }

    #[test]
    fn test_resolve_toml_value_env() {
        let val = toml::Value::String("env:HOME".into());
        let resolved = resolve_toml_value(&val).unwrap();
        if let toml::Value::String(s) = resolved {
            assert!(!s.is_empty());
            assert!(!s.starts_with("env:"));
        } else {
            panic!("Expected String");
        }
    }

    #[test]
    fn test_resolve_toml_value_nested() {
        // Test that resolution works inside arrays and tables
        let val = toml::Value::Array(vec![
            toml::Value::String("literal".into()),
            toml::Value::Integer(42),
        ]);
        let resolved = resolve_toml_value(&val).unwrap();
        assert_eq!(resolved, val);
    }

    #[test]
    fn test_parse_vars_with_env() {
        let vars = vec!["KEY=env:HOME".to_string()];
        let map = parse_vars(&vars).unwrap();
        assert!(map.get("KEY").unwrap().starts_with('/'));
    }

    #[test]
    fn test_parse_vars_literal() {
        let vars = vec!["DOMAIN=acme.okta.com".to_string()];
        let map = parse_vars(&vars).unwrap();
        assert_eq!(map.get("DOMAIN").unwrap(), "acme.okta.com");
    }

    #[test]
    fn test_handle_generate_requires_org() {
        // Reject silent `com.example` defaulting — generated profiles without --org
        // produce non-deployable PayloadIdentifiers and waste downstream review cycles.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.mobileconfig");

        let result = handle_generate(
            "com.apple.mobiledevice.passwordpolicy",
            Some(out.to_str().unwrap()),
            None, // no --org
            true,
            None,
            None, // no profile.toml
            OutputMode::Json,
            "mobileconfig",
        );

        assert!(result.is_err(), "expected error when --org is missing");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("--org is required"),
            "error should mention --org requirement, got: {err}"
        );
    }
}
