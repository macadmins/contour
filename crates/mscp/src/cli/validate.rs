use crate::output::{OutputMode, ValidationResult};
use crate::validators::SchemaValidator;
use anyhow::Result;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

/// Validate command - check output structure and schemas
pub fn validate_output(
    output_path: PathBuf,
    schemas_path: Option<PathBuf>,
    strict: bool,
    output_mode: OutputMode,
) -> Result<()> {
    tracing::info!(
        "Validating Fleet GitOps output at: {}",
        output_path.display()
    );

    let mut result = ValidationResult::new(output_path.to_string_lossy().to_string(), strict);

    // Step 1: Check directory structure
    if output_mode == OutputMode::Human {
        println!("{}", "Checking directory structure...".cyan());
    }
    let lib_mscp = output_path.join("lib").join("mscp");
    let teams_dir = output_path.join("fleets");

    if !lib_mscp.exists() {
        result.add_error("Missing lib/mscp directory");
    } else if output_mode == OutputMode::Human {
        println!("  {} lib/mscp directory exists", "✓".green());
    }

    if !teams_dir.exists() {
        result.add_error("Missing fleets directory");
    } else if output_mode == OutputMode::Human {
        println!("  {} fleets directory exists", "✓".green());
    }

    // Step 2: Validate team YAML files
    if output_mode == OutputMode::Human {
        println!("\n{}", "Validating team YAML files...".cyan());
    }
    let validator = SchemaValidator::new(schemas_path.as_ref());

    for entry in WalkDir::new(&teams_dir)
        .max_depth(1)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("yml")
            || path.extension().and_then(|s| s.to_str()) == Some("yaml")
        {
            result.team_files_checked += 1;

            match validator.validate_team_yaml(path) {
                Ok(validation_result) => {
                    if validation_result.valid {
                        result.team_files_valid += 1;
                        if output_mode == OutputMode::Human {
                            println!(
                                "  {} {} - {}",
                                "✓".green(),
                                path.file_name().unwrap_or_default().to_string_lossy(),
                                "valid".green()
                            );
                        }
                    } else {
                        result.team_files_invalid += 1;
                        if output_mode == OutputMode::Human {
                            println!(
                                "  {} {} - {}",
                                "✗".red(),
                                path.file_name().unwrap_or_default().to_string_lossy(),
                                "invalid".red()
                            );
                        }
                        for error in &validation_result.errors {
                            if output_mode == OutputMode::Human {
                                println!("    {} {}", "-".dimmed(), error.red());
                            }
                            result.add_error(format!("{}: {}", path.display(), error));
                        }
                    }
                }
                Err(e) => {
                    result.team_files_invalid += 1;
                    if output_mode == OutputMode::Human {
                        println!(
                            "  {} {} - {}: {}",
                            "✗".red(),
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            "error".red(),
                            e
                        );
                    }
                    result.add_error(format!("{}: {}", path.display(), e));
                }
            }

            // Validate file paths exist
            match validator.validate_file_paths(path, &output_path) {
                Ok(path_result) => {
                    if !path_result.valid {
                        if output_mode == OutputMode::Human {
                            println!("    {}", "⚠ Missing referenced files:".yellow());
                        }
                        for missing in &path_result.missing_paths {
                            if output_mode == OutputMode::Human {
                                println!("      {} {}", "-".dimmed(), missing.yellow());
                            }
                            let msg = format!("Missing file: {missing}");
                            if strict {
                                result.add_error(msg);
                            } else {
                                result.add_warning(msg);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to validate paths: {}", e);
                }
            }
        }
    }

    // Step 3: Check for conflicts if multiple baselines exist
    if output_mode == OutputMode::Human {
        println!("\n{}", "Checking for baseline conflicts...".cyan());
    }
    let baselines = find_baselines(&output_path)?;
    result.baselines_found = baselines.len();

    if baselines.len() > 1 {
        // This is a simplified check - in production you'd load actual baseline data
        if output_mode == OutputMode::Human {
            println!(
                "  {} {} baselines, conflict detection skipped (requires processed data)",
                "Found".dimmed(),
                baselines.len()
            );
        }
    } else if output_mode == OutputMode::Human {
        println!("  {} Single baseline, no conflicts possible", "✓".green());
    }

    // Output results
    match output_mode {
        OutputMode::Json => {
            crate::output::json::output_validation_result(&result)?;
        }
        OutputMode::Human => {
            // Summary
            println!("\n{}", "=".repeat(50));
            if result.success {
                println!("{}", "✓ Validation PASSED".green().bold());
                println!("  All checks completed successfully");
            } else {
                println!("{}", "✗ Validation FAILED".red().bold());
                println!("  {} error(s) found:", result.errors.len());
                for error in &result.errors {
                    println!("    {} {}", "-".dimmed(), error.red());
                }
                if !strict {
                    println!(
                        "\n  {}",
                        "(Non-strict mode: some errors are warnings)".dimmed()
                    );
                }
            }
        }
    }

    if !result.success && strict {
        anyhow::bail!("Validation failed");
    }

    Ok(())
}

/// Find baselines in the output directory
fn find_baselines(output_path: &PathBuf) -> Result<Vec<String>> {
    let mut baselines = Vec::new();
    let lib_mscp = output_path.join("lib").join("mscp");

    if lib_mscp.exists() {
        for entry in fs::read_dir(&lib_mscp)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && let Some(name) = entry.file_name().to_str()
                && name != "versions"
            {
                baselines.push(name.to_string());
            }
        }
    }

    Ok(baselines)
}
