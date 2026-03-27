//! Documentation generator CLI handler
//!
//! Generate markdown documentation from embedded payload schemas.

use crate::cli::generate::load_registry;
use crate::docs;
use crate::output::OutputMode;
use anyhow::Result;
use colored::Colorize;
use std::path::Path;

pub fn handle_docs_generate(
    output: &str,
    payload: Option<&str>,
    category: Option<&str>,
    schema_path: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = load_registry(schema_path)?;
    let output_path = Path::new(output);

    let count = docs::generate_docs(&registry, output_path, payload, category)?;

    if output_mode == OutputMode::Json {
        let json = serde_json::json!({
            "output_directory": output,
            "files_generated": count,
            "payload_filter": payload,
            "category_filter": category,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else if count == 0 {
        println!("{} No matching payloads found", "!".yellow());
    } else {
        println!("{} Generated {} documentation file(s)", "✓".green(), count);
        println!("  Output: {}", output_path.display());

        if let Some(p) = payload {
            println!("  Filter: {p}");
        }
        if let Some(c) = category {
            println!("  Category: {c}");
        }

        if count > 1 {
            println!("  Index: {}/README.md", output_path.display());
        }
    }

    Ok(())
}

pub fn handle_docs_list(
    category: Option<&str>,
    schema_path: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = load_registry(schema_path)?;

    let manifests: Vec<_> = if let Some(cat) = category {
        registry.by_category(cat)
    } else {
        registry.all().collect()
    };

    if output_mode == OutputMode::Json {
        let json: Vec<serde_json::Value> = manifests
            .iter()
            .map(|m| {
                serde_json::json!({
                    "payload_type": m.payload_type,
                    "title": m.title,
                    "category": m.category,
                    "fields_count": m.fields.len(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!("{} payloads available for documentation\n", manifests.len());

        let categories = ["apple", "apps", "prefs"];
        for cat in categories {
            if let Some(filter_cat) = category
                && cat != filter_cat
            {
                continue;
            }

            let cat_manifests: Vec<_> = manifests.iter().filter(|m| m.category == cat).collect();

            if cat_manifests.is_empty() {
                continue;
            }

            println!("{} ({}):", capitalize(cat).cyan(), cat_manifests.len());
            for m in cat_manifests.iter().take(10) {
                println!("  {} - {}", m.payload_type.green(), m.title);
            }
            if cat_manifests.len() > 10 {
                println!("  ... and {} more", cat_manifests.len() - 10);
            }
            println!();
        }
    }

    Ok(())
}

pub fn handle_docs_from_profile(
    file: &str,
    output: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    use crate::profile::parser;

    let registry = load_registry(None)?;
    let profile = parser::parse_profile_auto_unsign(file)?;

    let markdown = docs::generate_profile_doc(&profile, &registry)?;

    if let Some(output_path) = output {
        std::fs::write(output_path, &markdown)?;

        if output_mode == OutputMode::Json {
            let json = serde_json::json!({
                "file": file,
                "output": output_path,
                "profile_name": profile.payload_display_name,
                "payloads": profile.payload_content.len(),
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        } else {
            println!("{} Generated profile documentation", "✓".green());
            println!("  Input: {file}");
            println!("  Output: {output_path}");
            println!("  Profile: {}", profile.payload_display_name);
            println!("  Payloads: {}", profile.payload_content.len());
        }
    } else {
        // Output to stdout
        println!("{markdown}");
    }

    Ok(())
}

pub fn handle_docs_ddm(
    output: &str,
    declaration: Option<&str>,
    category: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = load_registry(None)?;
    let output_path = Path::new(output);

    let count = docs::generate_ddm_docs(&registry, output_path, declaration, category)?;

    if output_mode == OutputMode::Json {
        let json = serde_json::json!({
            "output_directory": output,
            "files_generated": count,
            "declaration_filter": declaration,
            "category_filter": category,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else if count == 0 {
        println!("{} No matching DDM declarations found", "!".yellow());
    } else {
        println!(
            "{} Generated {} DDM documentation file(s)",
            "✓".green(),
            count
        );
        println!("  Output: {}", output_path.display());

        if let Some(d) = declaration {
            println!("  Filter: {d}");
        }
        if let Some(c) = category {
            println!("  Category: {c}");
        }

        if count > 1 {
            println!("  Index: {}/README.md", output_path.display());
        }
    }

    Ok(())
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().chain(chars).collect(),
    }
}
