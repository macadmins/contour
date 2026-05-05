//! Handler for the `profile search` command.
//!
//! Two modes:
//! - Substring search (default): matches payload_type, title, description,
//!   and field names — returns matching payloads.
//! - `--field <name>` (exact field lookup): returns the matching field's
//!   full detail (type, plist tag, default, allowed values) alongside its
//!   payload_type, so an agent can answer "what type does Apple expect for
//!   `<key>`?" in one CLI call.

use anyhow::Result;
use colored::Colorize;

use crate::cli::info::plist_tag_for;
use crate::output::OutputMode;
use crate::schema::PayloadManifest;

/// Handle the `search` command.
pub fn handle_search(
    query: Option<&str>,
    field: Option<&str>,
    schema_path: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = crate::cli::generate::load_registry(schema_path)?;

    if let Some(name) = field {
        return handle_field_lookup(&registry, name, output_mode);
    }

    let q = query.expect("clap enforces a query when --field is unset");
    let mut results: Vec<&PayloadManifest> = registry.search(q);

    // Sort by payload_type for deterministic output
    results.sort_by(|a, b| a.payload_type.cmp(&b.payload_type));

    if output_mode == OutputMode::Json {
        output_json(&results)?;
    } else {
        output_human(q, &results);
    }

    Ok(())
}

/// Exact field-name lookup across every payload in the registry.
///
/// Walks `registry.all()` and emits one entry per (payload_type, field)
/// pair where `field.name == name`. Case-insensitive match — `WiFi` and
/// `wifi` both find `WiFi`.
fn handle_field_lookup(
    registry: &crate::schema::SchemaRegistry,
    name: &str,
    output_mode: OutputMode,
) -> Result<()> {
    let target = name.to_lowercase();
    let mut matches: Vec<(&PayloadManifest, &crate::schema::FieldDefinition)> = registry
        .all()
        .flat_map(|m| {
            m.fields
                .values()
                .filter(|f| f.name.to_lowercase() == target)
                .map(move |f| (m, f))
        })
        .collect();

    // Deterministic order: by payload_type, then field name (which is the
    // same across matches but kept for symmetry with future-proofing).
    matches.sort_by(|(a_m, a_f), (b_m, b_f)| {
        a_m.payload_type
            .cmp(&b_m.payload_type)
            .then(a_f.name.cmp(&b_f.name))
    });

    if output_mode == OutputMode::Json {
        let entries: Vec<serde_json::Value> = matches
            .iter()
            .map(|(m, f)| {
                serde_json::json!({
                    "payload_type": m.payload_type,
                    "title": m.title,
                    "category": m.category,
                    "field": {
                        "name": f.name,
                        "type": f.field_type.as_str(),
                        "plist_tag": plist_tag_for(&f.field_type),
                        "required": f.flags.required,
                        "supervised": f.flags.supervised,
                        "sensitive": f.flags.sensitive,
                        "default": f.default,
                        "allowed_values": f.allowed_values,
                        "min_version": f.min_version,
                        "depth": f.depth,
                        "parent_key": f.parent_key,
                        "title": f.title,
                        "description": f.description,
                    },
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    // Human output
    if matches.is_empty() {
        println!(
            "{} No field named '{}' in any payload",
            "!".yellow(),
            name.bold()
        );
        return Ok(());
    }

    println!(
        "{} {} match(es) for field '{}':\n",
        "=".green(),
        matches.len(),
        name.bold()
    );
    for (m, f) in &matches {
        let mut markers = Vec::new();
        if f.flags.required {
            markers.push("required".red().to_string());
        }
        if f.flags.supervised {
            markers.push("supervised".yellow().to_string());
        }
        if f.flags.sensitive {
            markers.push("sensitive".red().to_string());
        }
        let marker_str = if markers.is_empty() {
            String::new()
        } else {
            format!(" [{}]", markers.join(", "))
        };
        println!(
            "  {} : <{}>{}  in {}",
            f.name.green(),
            plist_tag_for(&f.field_type).cyan(),
            marker_str,
            m.payload_type.dimmed()
        );
        if !f.allowed_values.is_empty() {
            println!("    values: {}", f.allowed_values.join(", ").dimmed());
        }
        if let Some(d) = &f.default {
            println!("    default: {}", d.dimmed());
        }
    }
    Ok(())
}

fn output_json(results: &[&PayloadManifest]) -> Result<()> {
    let entries: Vec<serde_json::Value> = results
        .iter()
        .map(|m| {
            let kind = if m.category.starts_with("ddm-") {
                "DdmDeclaration"
            } else {
                "MdmProfile"
            };
            serde_json::json!({
                "payload_type": m.payload_type,
                "title": m.title,
                "description": m.description,
                "category": m.category,
                "platforms": m.platforms.to_vec(),
                "field_count": m.fields.len(),
                "kind": kind,
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&entries)?);
    Ok(())
}

fn output_human(query: &str, results: &[&PayloadManifest]) {
    if results.is_empty() {
        println!("{} No schemas matched '{}'", "!".yellow(), query.bold());
        return;
    }

    println!(
        "{} {} schema(s) matching '{}':\n",
        "=".green(),
        results.len(),
        query.bold()
    );

    // Header
    println!(
        "  {:<50} {:<25} {:<12} {:>6}  {}",
        "Payload Type".bold(),
        "Title".bold(),
        "Category".bold(),
        "Fields".bold(),
        "Platforms".bold(),
    );
    println!("  {}", "-".repeat(110));

    for m in results {
        let platforms = m.platforms.to_vec().join(", ");
        println!(
            "  {:<50} {:<25} {:<12} {:>6}  {}",
            m.payload_type,
            m.title,
            m.category,
            m.fields.len(),
            platforms,
        );
    }
}
