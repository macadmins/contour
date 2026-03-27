//! CLI handlers for FAA (File Access Authorization) subcommands.

use crate::faa;
use crate::output::{
    OutputMode, print_error, print_info, print_json, print_success, print_warning,
};
use anyhow::{Context, Result};
use std::path::Path;

/// Generate an FAA plist from a YAML or TOML policy file.
pub fn handle_faa_generate(input: &Path, output: Option<&Path>, mode: OutputMode) -> Result<()> {
    let policy_file = faa::load_policy_file(input)?;

    // Validate before generating.
    let errors = faa::validate(&policy_file);
    if !errors.is_empty() {
        for err in &errors {
            print_error(&err.to_string());
        }
        anyhow::bail!(
            "FAA policy validation failed with {} error(s)",
            errors.len()
        );
    }

    let plist_bytes = faa::generate_plist(&policy_file)?;

    let output_path = output.map_or_else(
        || {
            let stem = input
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("faa-policy");
            std::path::PathBuf::from(format!("{stem}.plist"))
        },
        Path::to_path_buf,
    );

    std::fs::write(&output_path, &plist_bytes)
        .with_context(|| format!("Failed to write plist to {}", output_path.display()))?;

    let policy_count = policy_file.faa_policies.len();

    match mode {
        OutputMode::Json => {
            print_json(&serde_json::json!({
                "success": true,
                "output": output_path.display().to_string(),
                "policies": policy_count,
                "bytes": plist_bytes.len(),
            }))?;
        }
        OutputMode::Human => {
            print_success(&format!(
                "Generated FAA plist with {policy_count} policy/policies -> {}",
                output_path.display()
            ));
        }
    }

    Ok(())
}

/// Validate an FAA policy file (YAML or TOML).
pub fn handle_faa_validate(input: &Path, mode: OutputMode) -> Result<()> {
    let policy_file = faa::load_policy_file(input)?;
    let errors = faa::validate(&policy_file);

    if errors.is_empty() {
        let policy_count = policy_file.faa_policies.len();
        match mode {
            OutputMode::Json => {
                let empty: Vec<String> = Vec::new();
                print_json(&serde_json::json!({
                    "success": true,
                    "policies": policy_count,
                    "errors": empty,
                }))?;
            }
            OutputMode::Human => {
                print_success(&format!("FAA policy is valid ({policy_count} policies)"));
            }
        }
        Ok(())
    } else {
        match mode {
            OutputMode::Json => {
                let error_list: Vec<serde_json::Value> = errors
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "policy": e.policy,
                            "message": e.message,
                        })
                    })
                    .collect();
                print_json(&serde_json::json!({
                    "success": false,
                    "errors": error_list,
                }))?;
            }
            OutputMode::Human => {
                for err in &errors {
                    print_error(&err.to_string());
                }
                print_warning(&format!("Validation failed with {} error(s)", errors.len()));
            }
        }
        anyhow::bail!(
            "FAA policy validation failed with {} error(s)",
            errors.len()
        );
    }
}

/// Output the FAA schema (rule types, options, process fields, placeholders).
pub fn handle_faa_schema(mode: OutputMode) -> Result<()> {
    let schema = faa::schema::faa_schema();

    match mode {
        OutputMode::Json => {
            print_json(&schema)?;
        }
        OutputMode::Human => {
            // Rule types.
            print_info("FAA Rule Types:");
            if let Some(rule_types) = schema["rule_types"].as_array() {
                for rt in rule_types {
                    let name = rt["name"].as_str().unwrap_or("?");
                    let desc = rt["description"].as_str().unwrap_or("");
                    println!("  {name:<40} {desc}");
                }
            }
            println!();

            // Options.
            print_info("Options:");
            if let Some(options) = schema["options"].as_array() {
                for opt in options {
                    let name = opt["name"].as_str().unwrap_or("?");
                    let typ = opt["type"].as_str().unwrap_or("?");
                    let desc = opt["description"].as_str().unwrap_or("");
                    println!("  {name:<24} ({typ:<6})  {desc}");
                }
            }
            println!();

            // Process identity fields.
            print_info("Process Identity Fields:");
            if let Some(fields) = schema["process_identity_fields"].as_array() {
                for f in fields {
                    let name = f["name"].as_str().unwrap_or("?");
                    let typ = f["type"].as_str().unwrap_or("?");
                    let desc = f["description"].as_str().unwrap_or("");
                    println!("  {name:<24} ({typ:<6})  {desc}");
                }
            }
            println!();

            // Runtime placeholders.
            print_info("Runtime Placeholders (for event_detail_url):");
            if let Some(placeholders) = schema["runtime_placeholders"].as_array() {
                for p in placeholders {
                    let name = p["name"].as_str().unwrap_or("?");
                    let desc = p["description"].as_str().unwrap_or("");
                    println!("  {name:<24} {desc}");
                }
            }
        }
    }

    Ok(())
}
