//! CLI handlers for ODV (Organizational Defined Values) commands.

use crate::managers::OdvOverrides;
use crate::output::OutputMode;
use anyhow::{Context, Result};
use colored::Colorize;
use std::path::PathBuf;

/// Initialize ODV override file for a baseline
pub fn odv_init(
    mscp_repo: PathBuf,
    baseline: String,
    output: PathBuf,
    output_mode: OutputMode,
) -> Result<()> {
    // Ensure output directory exists
    if !output.exists() {
        std::fs::create_dir_all(&output)
            .with_context(|| format!("Failed to create output directory: {}", output.display()))?;
    }

    // Create override file
    let file_path = OdvOverrides::create_override_file(&mscp_repo, &baseline, &output)?;

    // Load to get count
    let manager = OdvOverrides::load(&baseline, Some(file_path.clone()))?;
    let count = manager.get_overrides().len();

    match output_mode {
        OutputMode::Human => {
            if count == 0 {
                println!(
                    "\n{} No ODVs found for baseline '{}'",
                    "Note:".yellow(),
                    baseline
                );
                println!("This baseline may not have any rules with customizable values.");
            } else {
                println!(
                    "\n{} Created ODV override file with {} value{}",
                    "✓".green().bold(),
                    count.to_string().cyan(),
                    if count == 1 { "" } else { "s" }
                );
                println!("  {} {}", "File:".bold(), file_path.display());
                println!();
                println!("{}", "Next steps:".bold());
                println!("  1. Edit {} to customize values", file_path.display());
                println!("  2. Set custom_value for any ODV you want to override");
                println!(
                    "  3. Run: contour mscp generate --baseline {} --odv {}",
                    baseline,
                    file_path.display()
                );
            }
        }
        OutputMode::Json => {
            let json = serde_json::json!({
                "success": true,
                "baseline": baseline,
                "file": file_path.display().to_string(),
                "odv_count": count,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }

    Ok(())
}

/// List ODVs for a baseline (shows defaults and any overrides)
pub fn odv_list(
    mscp_repo: PathBuf,
    baseline: String,
    overrides_path: Option<PathBuf>,
    output_mode: OutputMode,
) -> Result<()> {
    // Discover ODVs from mSCP repo
    let discovered_odvs = OdvOverrides::discover_odvs(&mscp_repo, &baseline)?;

    // Load override file if it exists
    let override_manager = OdvOverrides::try_load(&baseline, overrides_path.clone());

    match output_mode {
        OutputMode::Human => {
            if discovered_odvs.is_empty() {
                println!(
                    "\n{} No ODVs found for baseline '{}'",
                    "Note:".yellow(),
                    baseline
                );
                return Ok(());
            }

            println!(
                "\n{} for baseline '{}'",
                "ODVs (Organizational Defined Values)".cyan().bold(),
                baseline
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════".dimmed()
            );

            if let Some(ref manager) = override_manager {
                let custom_count = manager
                    .get_overrides()
                    .iter()
                    .filter(|o| o.custom_value.is_some())
                    .count();
                if custom_count > 0 {
                    println!(
                        "\n{} {} custom override{}",
                        "Loaded:".bold(),
                        custom_count.to_string().green(),
                        if custom_count == 1 { "" } else { "s" }
                    );
                }
            }

            println!();

            for odv in &discovered_odvs {
                // Get baseline-specific default
                let default = odv
                    .baseline_values
                    .get(&baseline)
                    .unwrap_or(&odv.recommended);

                // Check for custom override
                let custom_value = override_manager
                    .as_ref()
                    .and_then(|m| m.get_overrides().iter().find(|o| o.rule_id == odv.rule_id))
                    .and_then(|o| o.custom_value.as_ref());

                let effective_value = custom_value.unwrap_or(default);

                // Format output
                print!("  {} ", odv.rule_id.cyan());
                if let Some(custom) = custom_value {
                    // Show custom override
                    println!(
                        "{} {} {}",
                        format_yaml_value(default).dimmed().strikethrough(),
                        "→".green(),
                        format_yaml_value(custom).green().bold()
                    );
                } else {
                    println!("{}", format_yaml_value(effective_value));
                }

                if !odv.hint.is_empty() {
                    println!("    {} {}", "Hint:".dimmed(), odv.hint.dimmed());
                }
            }

            println!(
                "\n{}",
                "──────────────────────────────────────────────────────────".dimmed()
            );
            println!(
                "{}: {} ODV{}",
                "Total".bold(),
                discovered_odvs.len(),
                if discovered_odvs.len() == 1 { "" } else { "s" }
            );

            if override_manager.is_none() {
                println!();
                println!(
                    "{} No override file loaded. Create one with:",
                    "Tip:".yellow()
                );
                println!(
                    "  contour mscp odv init --mscp-repo {} --baseline {}",
                    mscp_repo.display(),
                    baseline
                );
            }
        }
        OutputMode::Json => {
            let odvs_json: Vec<serde_json::Value> = discovered_odvs
                .iter()
                .map(|odv| {
                    let default = odv
                        .baseline_values
                        .get(&baseline)
                        .unwrap_or(&odv.recommended);

                    let custom_value = override_manager
                        .as_ref()
                        .and_then(|m| m.get_overrides().iter().find(|o| o.rule_id == odv.rule_id))
                        .and_then(|o| o.custom_value.as_ref());

                    serde_json::json!({
                        "rule_id": odv.rule_id,
                        "hint": odv.hint,
                        "default_value": yaml_to_json(default),
                        "custom_value": custom_value.map(yaml_to_json),
                        "effective_value": yaml_to_json(custom_value.unwrap_or(default)),
                        "baseline_values": odv.baseline_values.iter()
                            .map(|(k, v)| (k.clone(), yaml_to_json(v)))
                            .collect::<std::collections::HashMap<_, _>>(),
                    })
                })
                .collect();

            let json = serde_json::json!({
                "baseline": baseline,
                "odv_count": discovered_odvs.len(),
                "override_file": overrides_path.map(|p| p.display().to_string()),
                "odvs": odvs_json,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }

    Ok(())
}

/// Edit ODV values interactively (opens in $EDITOR or prints instructions)
pub fn odv_edit(overrides_path: PathBuf, output_mode: OutputMode) -> Result<()> {
    if !overrides_path.exists() {
        match output_mode {
            OutputMode::Human => {
                eprintln!(
                    "{} ODV file not found: {}",
                    "Error:".red().bold(),
                    overrides_path.display()
                );
                eprintln!();
                eprintln!("Create one first with:");
                eprintln!("  contour mscp odv init --mscp-repo <PATH> --baseline <NAME>");
            }
            OutputMode::Json => {
                let json = serde_json::json!({
                    "success": false,
                    "error": format!("ODV file not found: {}", overrides_path.display()),
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
        }
        return Ok(());
    }

    // Try to open in editor
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vim".to_string());

    match output_mode {
        OutputMode::Human => {
            println!(
                "Opening {} in {}...",
                overrides_path.display(),
                editor.cyan()
            );

            let status = std::process::Command::new(&editor)
                .arg(&overrides_path)
                .status();

            match status {
                Ok(exit_status) if exit_status.success() => {
                    println!("{} File saved", "✓".green());
                }
                Ok(_) => {
                    eprintln!("{} Editor exited with error", "Warning:".yellow());
                }
                Err(e) => {
                    eprintln!(
                        "{} Failed to open editor '{}': {}",
                        "Error:".red(),
                        editor,
                        e
                    );
                    eprintln!();
                    eprintln!("You can manually edit the file at:");
                    eprintln!("  {}", overrides_path.display());
                }
            }
        }
        OutputMode::Json => {
            // In JSON mode, just report the file path (no interactive editing)
            let json = serde_json::json!({
                "success": true,
                "file": overrides_path.display().to_string(),
                "message": "Edit this file to customize ODV values",
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }

    Ok(())
}

/// Format a YAML value for display
fn format_yaml_value(value: &yaml_serde::Value) -> String {
    match value {
        yaml_serde::Value::Null => "null".to_string(),
        yaml_serde::Value::Bool(b) => b.to_string(),
        yaml_serde::Value::Number(n) => n.to_string(),
        yaml_serde::Value::String(s) => format!("\"{s}\""),
        yaml_serde::Value::Sequence(seq) => {
            let items: Vec<String> = seq.iter().map(format_yaml_value).collect();
            format!("[{}]", items.join(", "))
        }
        yaml_serde::Value::Mapping(map) => {
            let items: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", format_yaml_value(k), format_yaml_value(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
        yaml_serde::Value::Tagged(t) => format_yaml_value(&t.value),
    }
}

/// Convert YAML value to JSON value
fn yaml_to_json(value: &yaml_serde::Value) -> serde_json::Value {
    match value {
        yaml_serde::Value::Null => serde_json::Value::Null,
        yaml_serde::Value::Bool(b) => serde_json::Value::Bool(*b),
        yaml_serde::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f)
                    .map_or(serde_json::Value::Null, serde_json::Value::Number)
            } else {
                serde_json::Value::Null
            }
        }
        yaml_serde::Value::String(s) => serde_json::Value::String(s.clone()),
        yaml_serde::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.iter().map(yaml_to_json).collect())
        }
        yaml_serde::Value::Mapping(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter_map(|(k, v)| k.as_str().map(|s| (s.to_string(), yaml_to_json(v))))
                .collect();
            serde_json::Value::Object(obj)
        }
        yaml_serde::Value::Tagged(t) => yaml_to_json(&t.value),
    }
}
