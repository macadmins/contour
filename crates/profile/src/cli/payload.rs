//! Payload inspection and extraction commands.
//!
//! Community edition includes read-only operations:
//! - list: List payloads in a profile
//! - read: Read a specific value from a payload
//! - extract: Extract specific payload types into a new profile

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::HashMap;
use std::path::Path;

use crate::output::OutputMode;
use crate::profile::parser::parse_profile_auto_unsign;
use crate::profile::{ConfigurationProfile, PayloadContent};
use crate::schema::SchemaRegistry;

/// Resolve payload type - supports short names like "wifi" -> "com.apple.wifi.managed"
fn resolve_payload_type(type_str: &str) -> String {
    // If it looks like a full payload type, use as-is
    if type_str.contains('.') {
        return type_str.to_string();
    }

    // Try to resolve via schema registry
    if let Ok(registry) = SchemaRegistry::embedded()
        && let Some(manifest) = registry.get_by_name(type_str)
    {
        return manifest.payload_type.clone();
    }

    // Fall back to original
    type_str.to_string()
}

/// Handle `payload list` command
pub fn handle_payload_list(file: &str, output_mode: OutputMode) -> Result<()> {
    let profile = parse_profile_auto_unsign(file)?;

    if output_mode == OutputMode::Json {
        let payloads: Vec<_> = profile
            .payload_content
            .iter()
            .enumerate()
            .map(|(i, p)| {
                serde_json::json!({
                    "index": i,
                    "type": p.payload_type,
                    "identifier": p.payload_identifier,
                    "display_name": p.payload_display_name(),
                    "uuid": p.payload_uuid,
                })
            })
            .collect();

        let output = serde_json::json!({
            "profile": {
                "identifier": profile.payload_identifier,
                "display_name": profile.payload_display_name,
                "payload_count": profile.payload_content.len(),
            },
            "payloads": payloads,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    // Human output
    println!(
        "{}: {} ({})\n",
        "Profile".cyan(),
        profile.payload_display_name,
        profile.payload_identifier
    );

    println!(
        "{} ({}):",
        "Payloads".cyan().bold(),
        profile.payload_content.len()
    );

    for (i, payload) in profile.payload_content.iter().enumerate() {
        let display_name_opt = payload.payload_display_name();
        let display_name = display_name_opt.as_deref().unwrap_or("(unnamed)");

        println!(
            "  {}. {} {}",
            i,
            payload.payload_type.green(),
            format!("- {display_name}").dimmed()
        );

        // Show key count
        let key_count = payload.content.len();
        println!(
            "     {} keys, UUID: {}",
            key_count,
            &payload.payload_uuid[..8]
        );
    }

    Ok(())
}

/// Handle `payload read` command
pub fn handle_payload_read(
    file: &str,
    type_str: &str,
    key: &str,
    index: Option<usize>,
    output_mode: OutputMode,
) -> Result<()> {
    let profile = parse_profile_auto_unsign(file)?;
    let payload_type = resolve_payload_type(type_str);

    // Find matching payloads
    let matches: Vec<_> = profile
        .payload_content
        .iter()
        .enumerate()
        .filter(|(_, p)| p.payload_type == payload_type)
        .collect();

    if matches.is_empty() {
        anyhow::bail!("No payload found with type: {payload_type}");
    }

    // Select the right payload
    let (idx, payload) = if let Some(i) = index {
        matches.get(i).ok_or_else(|| {
            anyhow::anyhow!("Payload index {} out of range (found {})", i, matches.len())
        })?
    } else if matches.len() > 1 {
        anyhow::bail!(
            "Multiple payloads of type '{}' found. Use --index to specify which one (0-{})",
            payload_type,
            matches.len() - 1
        );
    } else {
        &matches[0]
    };

    // Get the value
    let value = payload
        .content
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("Key '{key}' not found in payload"))?;

    if output_mode == OutputMode::Json {
        let output = serde_json::json!({
            "payload_type": payload_type,
            "payload_index": idx,
            "key": key,
            "value": plist_value_to_json(value),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", format_plist_value(value));
    }

    Ok(())
}

/// Handle `payload extract` command
pub fn handle_payload_extract(
    file: &str,
    types: &[String],
    output: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let profile = parse_profile_auto_unsign(file)?;

    // Resolve all types
    let resolved_types: Vec<String> = types.iter().map(|t| resolve_payload_type(t)).collect();

    // Extract values from profile before consuming payload_content
    let orig_identifier = profile.payload_identifier.clone();
    let orig_display_name = profile.payload_display_name.clone();
    let orig_organization = profile.payload_organization();

    // Filter payloads
    let extracted: Vec<PayloadContent> = profile
        .payload_content
        .into_iter()
        .filter(|p| resolved_types.contains(&p.payload_type))
        .collect();

    if extracted.is_empty() {
        anyhow::bail!(
            "No payloads found matching types: {}",
            resolved_types.join(", ")
        );
    }

    // Build additional fields
    let mut additional_fields = HashMap::new();
    additional_fields.insert(
        "PayloadDescription".to_string(),
        plist::Value::String(format!(
            "Extracted from {} - types: {}",
            orig_identifier,
            resolved_types.join(", ")
        )),
    );
    if let Some(org) = orig_organization {
        additional_fields.insert("PayloadOrganization".to_string(), plist::Value::String(org));
    }

    // Create new profile with extracted payloads
    let new_profile = ConfigurationProfile {
        payload_type: "Configuration".to_string(),
        payload_version: 1,
        payload_identifier: format!("{orig_identifier}.extracted"),
        payload_uuid: uuid::Uuid::new_v4().to_string().to_uppercase(),
        payload_display_name: format!("{orig_display_name} (extracted)"),
        payload_content: extracted.clone(),
        additional_fields,
    };

    // Determine output path
    let output_path = output
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| {
            let path = Path::new(file);
            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
            let ext = path.extension().unwrap_or_default().to_string_lossy();
            format!("{stem}_extract.{ext}")
        });

    // Write profile
    let plist_data = plist::to_value(&new_profile)?;
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &plist_data)?;
    std::fs::write(&output_path, &buf)
        .with_context(|| format!("Failed to write to {output_path}"))?;

    if output_mode == OutputMode::Json {
        let result = serde_json::json!({
            "success": true,
            "extracted_count": extracted.len(),
            "types": resolved_types,
            "output": output_path,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "{} Extracted {} payload(s) to {}",
            "✓".green(),
            extracted.len(),
            output_path
        );
        for p in &extracted {
            println!("  - {}", p.payload_type.green());
        }
    }

    Ok(())
}

/// Format a plist value for human display
fn format_plist_value(value: &plist::Value) -> String {
    match value {
        plist::Value::String(s) => s.clone(),
        plist::Value::Integer(i) => i.to_string(),
        plist::Value::Real(f) => f.to_string(),
        plist::Value::Boolean(b) => b.to_string(),
        plist::Value::Data(d) => format!("<{} bytes>", d.len()),
        plist::Value::Date(d) => format!("{d:?}"),
        plist::Value::Array(a) => format!("[{} items]", a.len()),
        plist::Value::Dictionary(d) => format!("{{{} keys}}", d.len()),
        _ => "(unknown)".to_string(),
    }
}

/// Convert plist value to JSON
fn plist_value_to_json(value: &plist::Value) -> serde_json::Value {
    match value {
        plist::Value::String(s) => serde_json::Value::String(s.clone()),
        plist::Value::Integer(i) => {
            serde_json::Value::Number(serde_json::Number::from(i.as_signed().unwrap_or(0)))
        }
        plist::Value::Real(f) => serde_json::json!(*f),
        plist::Value::Boolean(b) => serde_json::Value::Bool(*b),
        plist::Value::Data(d) => serde_json::Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            d,
        )),
        plist::Value::Date(d) => serde_json::Value::String(format!("{d:?}")),
        plist::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(plist_value_to_json).collect())
        }
        plist::Value::Dictionary(d) => {
            let obj: serde_json::Map<String, serde_json::Value> = d
                .iter()
                .map(|(k, v)| (k.clone(), plist_value_to_json(v)))
                .collect();
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::Null,
    }
}
