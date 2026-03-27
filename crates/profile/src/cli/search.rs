//! Handler for the `profile search` command.
//!
//! Searches embedded Apple schema payload types, titles, descriptions,
//! and key names using the schema registry's full-text search.

use anyhow::Result;
use colored::Colorize;

use crate::output::OutputMode;
use crate::schema::PayloadManifest;

/// Handle the `search` command.
pub fn handle_search(
    query: &str,
    schema_path: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = crate::cli::generate::load_registry(schema_path)?;
    let mut results: Vec<&PayloadManifest> = registry.search(query);

    // Sort by payload_type for deterministic output
    results.sort_by(|a, b| a.payload_type.cmp(&b.payload_type));

    if output_mode == OutputMode::Json {
        output_json(&results)?;
    } else {
        output_human(query, &results);
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
