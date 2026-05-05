//! Handler for the `profile search` command.
//!
//! Three modes:
//! - Substring search (default): matches payload_type, title, description,
//!   and field names — returns matching payloads.
//! - `--field <name>` (exact field lookup): returns the matching field's
//!   full detail (type, plist tag, default, allowed values) alongside its
//!   payload_type, so an agent can answer "what type does Apple expect for
//!   `<key>`?" in one CLI call.
//! - `--include-fields` (polymorphic): substring-matches at both the
//!   payload AND field level. Returns categorized JSON
//!   `{payload_matches: [...], field_matches: [...]}` with a `matched_in`
//!   tag on each hit so the agent sees WHERE the substring landed
//!   (name / title / description / payload_type).

use anyhow::Result;
use colored::Colorize;

use crate::cli::info::plist_tag_for;
use crate::output::OutputMode;
use crate::schema::{FieldDefinition, PayloadManifest, SchemaRegistry};

/// Handle the `search` command.
pub fn handle_search(
    query: Option<&str>,
    field: Option<&str>,
    include_fields: bool,
    schema_path: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = crate::cli::generate::load_registry(schema_path)?;

    if let Some(name) = field {
        return handle_field_lookup(&registry, name, output_mode);
    }

    let q = query.expect("clap enforces a query when --field is unset");

    if include_fields {
        return handle_polymorphic_search(&registry, q, output_mode);
    }

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

/// Polymorphic substring search across payload-level AND field-level
/// metadata. Returns categorized results so an agent can read
/// "X payloads matched, Y fields matched" without flattening; the
/// `matched_in` tag on each hit names the axis where the substring
/// landed (payload_type / title / description / name) — useful when
/// a description match is noisier than a name match.
fn handle_polymorphic_search(
    registry: &SchemaRegistry,
    query: &str,
    output_mode: OutputMode,
) -> Result<()> {
    let q = query.to_lowercase();
    let mut payload_hits: Vec<(&PayloadManifest, Vec<&'static str>)> = Vec::new();
    let mut field_hits: Vec<(&PayloadManifest, &FieldDefinition, Vec<&'static str>)> = Vec::new();

    for m in registry.all() {
        // Payload-level axes
        let mut p_in = Vec::new();
        if m.payload_type.to_lowercase().contains(&q) {
            p_in.push("payload_type");
        }
        if m.title.to_lowercase().contains(&q) {
            p_in.push("title");
        }
        if m.description.to_lowercase().contains(&q) {
            p_in.push("description");
        }
        if !p_in.is_empty() {
            payload_hits.push((m, p_in));
        }

        // Field-level axes — sorted by field_order to keep output
        // deterministic and readable per payload.
        for name in &m.field_order {
            let Some(f) = m.fields.get(name) else {
                continue;
            };
            let mut f_in = Vec::new();
            if f.name.to_lowercase().contains(&q) {
                f_in.push("name");
            }
            if f.title.to_lowercase().contains(&q) {
                f_in.push("title");
            }
            if f.description.to_lowercase().contains(&q) {
                f_in.push("description");
            }
            if !f_in.is_empty() {
                field_hits.push((m, f, f_in));
            }
        }
    }

    payload_hits.sort_by(|a, b| a.0.payload_type.cmp(&b.0.payload_type));
    field_hits.sort_by(|a, b| {
        a.0.payload_type
            .cmp(&b.0.payload_type)
            .then(a.1.name.cmp(&b.1.name))
    });

    if output_mode == OutputMode::Json {
        let json = serde_json::json!({
            "query": query,
            "payload_matches": payload_hits.iter().map(|(m, in_)| {
                serde_json::json!({
                    "payload_type": m.payload_type,
                    "title": m.title,
                    "description": m.description,
                    "category": m.category,
                    "platforms": m.platforms.to_vec(),
                    "field_count": m.fields.len(),
                    "matched_in": in_,
                })
            }).collect::<Vec<_>>(),
            "field_matches": field_hits.iter().map(|(m, f, in_)| {
                serde_json::json!({
                    "payload_type": m.payload_type,
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
                    "matched_in": in_,
                })
            }).collect::<Vec<_>>(),
            "summary": {
                "payloads_matched": payload_hits.len(),
                "fields_matched": field_hits.len(),
            }
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    // Human output — two clearly separated sections.
    if payload_hits.is_empty() && field_hits.is_empty() {
        println!(
            "{} No payloads or fields matched '{}'",
            "!".yellow(),
            query.bold()
        );
        return Ok(());
    }

    println!(
        "{} '{}' — {} payload(s) + {} field(s):\n",
        "=".green(),
        query.bold(),
        payload_hits.len(),
        field_hits.len()
    );

    if !payload_hits.is_empty() {
        println!("{}", "Payload matches:".cyan().bold());
        for (m, where_) in &payload_hits {
            println!(
                "  {:<48} {:<24} [{}]",
                m.payload_type.green(),
                m.title,
                where_.join(", ").dimmed()
            );
        }
        println!();
    }

    if !field_hits.is_empty() {
        println!("{}", "Field matches:".cyan().bold());
        for (m, f, where_) in &field_hits {
            let mut markers = Vec::new();
            if f.flags.required {
                markers.push("required".red().to_string());
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
                "  {} : <{}>{}  in {} [{}]",
                f.name.green(),
                plist_tag_for(&f.field_type).cyan(),
                marker_str,
                m.payload_type.dimmed(),
                where_.join(", ").dimmed()
            );
        }
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
