//! CLI handler for the `form link` command.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;

use crate::cli::glob_utils::collect_profile_files_multi_with_depth;
use crate::config::ProfileConfig;
use crate::link::types::LinkResult;
use crate::link::{
    LinkConfig, extract_references, format_validation_errors, link_profiles, merge_profiles_v2,
    summarize_extraction, validate_references,
};
use crate::output::OutputMode;
use crate::profile::{ConfigurationProfile, parser};

/// Handle the `form link` command.
#[expect(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "CLI handler requires many parameters"
)]
pub fn handle_link(
    paths: &[String],
    output: Option<&str>,
    org_domain: Option<&str>,
    predictable: bool,
    merge: bool,
    no_validate: bool,
    recursive: bool,
    max_depth: Option<usize>,
    dry_run: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    // Collect all profile files
    let files = collect_profile_files_multi_with_depth(paths, recursive, max_depth)?;

    if files.is_empty() {
        if output_mode == OutputMode::Human {
            println!("{}", "No .mobileconfig files found".yellow());
        } else {
            let result = serde_json::json!({
                "success": false,
                "error": "No .mobileconfig files found"
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human {
        println!(
            "{}",
            format!(
                "Analyzing {} profile(s) for cross-references...",
                files.len()
            )
            .cyan()
        );
    }

    // Load all profiles
    let profiles: Vec<(PathBuf, ConfigurationProfile)> = files
        .iter()
        .map(|f| {
            let profile = parser::parse_profile_auto_unsign(&f.to_string_lossy())
                .with_context(|| format!("Failed to parse: {}", f.display()))?;
            Ok((f.clone(), profile))
        })
        .collect::<Result<Vec<_>>>()?;

    // Determine effective config: profile.toml → CLI --org → .contour/config.toml
    let effective_domain = config
        .map(|c| c.organization.domain.clone())
        .or_else(|| org_domain.map(String::from))
        .or_else(|| {
            contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.domain)
        });

    let effective_predictable = config.map_or(predictable, |c| c.uuid.predictable);

    let link_config = LinkConfig {
        org_domain: effective_domain,
        predictable: effective_predictable,
        merge,
        validate: !no_validate,
    };

    // Extract and analyze references
    let (references, referenceables) = extract_references(&profiles);
    let summary = summarize_extraction(&references, &referenceables);

    if output_mode == OutputMode::Human {
        println!();
        println!("{}", "Cross-Reference Analysis:".cyan().bold());
        println!("  References found:      {}", summary.total_references);
        println!(
            "  Unique UUIDs:          {}",
            summary.unique_referenced_uuids
        );
        println!(
            "  Certificate payloads:  {}",
            summary.referenceable_payloads
        );

        if !summary.orphan_references.is_empty() {
            println!(
                "  {} {}",
                "Orphan references:".yellow(),
                summary.orphan_references.len()
            );
            for orphan in &summary.orphan_references {
                println!("    - {}", orphan.dimmed());
            }
        }
        println!();
    }

    // Validate if requested
    if link_config.validate {
        let validation = validate_references(&references, &referenceables);
        if !validation.valid {
            if output_mode == OutputMode::Human {
                println!("{}", "Validation Errors:".red().bold());
                println!("{}", format_validation_errors(&validation));
            } else {
                let result = serde_json::json!({
                    "success": false,
                    "errors": validation.errors.iter().map(|e| {
                        serde_json::json!({
                            "field": e.field_name,
                            "referenced_uuid": e.referenced_uuid,
                            "source_payload": e.source_payload_uuid,
                        })
                    }).collect::<Vec<_>>()
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            anyhow::bail!("Cross-reference validation failed");
        }

        if output_mode == OutputMode::Human && !validation.warnings.is_empty() {
            println!("{}", "Warnings:".yellow().bold());
            for warning in &validation.warnings {
                println!("  - {warning}");
            }
            println!();
        }
    }

    // Handle dry-run
    if dry_run {
        print_dry_run(&profiles, output, merge, &link_config, output_mode)?;
        return Ok(());
    }

    // Perform linking
    if merge {
        handle_merge(&profiles, output, &link_config, output_mode)?;
    } else {
        handle_link_separate(&profiles, output, &link_config, output_mode)?;
    }

    Ok(())
}

/// Handle linking with separate output files.
fn handle_link_separate(
    profiles: &[(PathBuf, ConfigurationProfile)],
    output_dir: Option<&str>,
    config: &LinkConfig,
    output_mode: OutputMode,
) -> Result<()> {
    let result = link_profiles(profiles.to_vec(), config)?;

    // Determine output directory
    let out_dir = if let Some(dir) = output_dir {
        let path = Path::new(dir);
        fs::create_dir_all(path)?;
        Some(path.to_path_buf())
    } else {
        None
    };

    // Write each profile
    for (original_path, profile) in &result.profiles {
        let output_path = if let Some(ref dir) = out_dir {
            let filename = original_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("path has no filename: {}", original_path.display()))?;
            dir.join(filename)
        } else {
            // Write next to original with -linked suffix
            let stem = original_path
                .file_stem()
                .ok_or_else(|| anyhow::anyhow!("path has no file stem: {}", original_path.display()))?
                .to_string_lossy();
            let new_name = format!("{stem}-linked.mobileconfig");
            original_path
                .parent()
                .unwrap_or(Path::new("."))
                .join(new_name)
        };

        parser::write_profile(profile, &output_path)?;

        if output_mode == OutputMode::Human {
            println!(
                "{} {} -> {}",
                "✓".green(),
                original_path.display(),
                output_path.display()
            );
        }
    }

    print_link_summary(&result, output_mode)?;
    Ok(())
}

/// Handle merging profiles into a single file.
fn handle_merge(
    profiles: &[(PathBuf, ConfigurationProfile)],
    output: Option<&str>,
    config: &LinkConfig,
    output_mode: OutputMode,
) -> Result<()> {
    let (merged, uuid_mapping) = merge_profiles_v2(profiles.to_vec(), config)?;

    // Determine output path
    let output_path = if let Some(out) = output {
        PathBuf::from(out)
    } else {
        PathBuf::from("merged.mobileconfig")
    };

    // Create parent directory if needed
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }

    parser::write_profile(&merged, &output_path)?;

    if output_mode == OutputMode::Human {
        println!(
            "{}",
            format!(
                "Merged {} profiles into: {}",
                profiles.len(),
                output_path.display()
            )
            .green()
        );
        println!("  Total payloads: {}", merged.payload_content.len());
        println!("  UUIDs updated:  {}", uuid_mapping.mapping.len());
    } else {
        let result = serde_json::json!({
            "success": true,
            "output": output_path.to_string_lossy(),
            "profiles_merged": profiles.len(),
            "total_payloads": merged.payload_content.len(),
            "uuids_updated": uuid_mapping.mapping.len(),
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Print dry-run preview.
fn print_dry_run(
    profiles: &[(PathBuf, ConfigurationProfile)],
    output: Option<&str>,
    merge: bool,
    config: &LinkConfig,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        println!("{}", "\nDry run mode - no files will be written\n".yellow());

        if merge {
            let output_path = output.unwrap_or("merged.mobileconfig");
            println!(
                "Would merge {} profiles into: {}",
                profiles.len(),
                output_path
            );
            println!("\nProfiles to merge:");
            for (path, profile) in profiles {
                println!(
                    "  - {} ({} payloads)",
                    path.display(),
                    profile.payload_content.len()
                );
            }
        } else {
            println!("Would link {} profiles:", profiles.len());
            for (path, _) in profiles {
                let stem = path.file_stem().map(|s| s.to_string_lossy()).unwrap_or_else(|| path.to_string_lossy());
                let output_path = if let Some(dir) = output {
                    format!("{dir}/{stem}.mobileconfig")
                } else {
                    format!("{stem}-linked.mobileconfig")
                };
                println!("  {} -> {}", path.display(), output_path);
            }
        }

        println!("\nConfiguration:");
        println!(
            "  Predictable UUIDs: {}",
            if config.predictable { "yes" } else { "no" }
        );
        if let Some(ref domain) = config.org_domain {
            println!("  Organization domain: {domain}");
        }
    } else {
        let items: Vec<_> = profiles
            .iter()
            .map(|(path, profile)| {
                serde_json::json!({
                    "input": path.to_string_lossy(),
                    "payloads": profile.payload_content.len(),
                })
            })
            .collect();

        let result = serde_json::json!({
            "dry_run": true,
            "merge": merge,
            "would_process": items,
            "output": output.unwrap_or(if merge { "merged.mobileconfig" } else { "<input>-linked.mobileconfig" }),
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Print summary of link operation.
fn print_link_summary(result: &LinkResult, output_mode: OutputMode) -> Result<()> {
    if output_mode == OutputMode::Human {
        println!();
        println!("{}", "Link Summary:".cyan().bold());
        println!("  Profiles linked:   {}", result.profiles.len());
        println!("  References updated: {}", result.reference_count);
        println!(
            "  UUIDs regenerated:  {}",
            result.uuid_mapping.mapping.len()
        );
        println!("\n{}", "All cross-references are now synchronized.".green());
    } else {
        let json_result = serde_json::json!({
            "success": true,
            "profiles_linked": result.profiles.len(),
            "references_updated": result.reference_count,
            "uuids_regenerated": result.uuid_mapping.mapping.len(),
        });
        println!("{}", serde_json::to_string_pretty(&json_result)?);
    }

    Ok(())
}
