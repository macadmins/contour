use crate::output::{BaselineDiff, DiffResult, OutputMode};
use crate::versioning::{DiffEngine, Manifest};
use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

/// Diff command - compare versions
pub fn diff_versions(
    output_path: PathBuf,
    baseline_name: Option<String>,
    format: DiffFormat,
    output_mode: OutputMode,
) -> Result<()> {
    tracing::info!("Comparing versions in: {}", output_path.display());

    let mut result = DiffResult::new(output_path.to_string_lossy().to_string());

    // Load manifest
    let manifest_path = output_path
        .join("lib")
        .join("mscp")
        .join("versions")
        .join("manifest.json");

    if !manifest_path.exists() {
        let error_msg = format!(
            "Manifest not found at: {}. Have you processed any baselines yet?",
            manifest_path.display()
        );
        result.add_error(&error_msg);

        match output_mode {
            OutputMode::Json => {
                crate::output::json::output_diff_result(&result)?;
            }
            OutputMode::Human => {
                eprintln!("{} {}", "Error:".red().bold(), error_msg);
            }
        }
        anyhow::bail!(error_msg);
    }

    let manifest_content = fs::read_to_string(&manifest_path).context("Failed to read manifest")?;
    let manifest: Manifest =
        serde_json::from_str(&manifest_content).context("Failed to parse manifest")?;

    if manifest.baselines.is_empty() {
        if output_mode == OutputMode::Human {
            println!("{}", "No baselines found in manifest.".yellow());
        }

        match output_mode {
            OutputMode::Json => {
                crate::output::json::output_diff_result(&result)?;
            }
            OutputMode::Human => {}
        }
        return Ok(());
    }

    // Filter by baseline name if provided
    let baselines_to_diff: Vec<_> = if let Some(ref name) = baseline_name {
        manifest
            .baselines
            .iter()
            .filter(|b| b.name == *name)
            .collect()
    } else {
        manifest.baselines.iter().collect()
    };

    if baselines_to_diff.is_empty()
        && let Some(name) = baseline_name
    {
        let error_msg = format!("Baseline '{name}' not found in manifest");
        result.add_error(&error_msg);

        match output_mode {
            OutputMode::Json => {
                crate::output::json::output_diff_result(&result)?;
            }
            OutputMode::Human => {
                eprintln!("{} {}", "Error:".red().bold(), error_msg);
            }
        }
        anyhow::bail!(error_msg);
    }

    // For each baseline, compare with its previous version
    let diffs = Vec::new();

    for baseline in baselines_to_diff {
        // Find previous version
        let prev_version = manifest
            .previous_versions
            .iter()
            .filter(|pv| pv.baseline_name == baseline.name)
            .max_by_key(|pv| &pv.date);

        if let Some(prev) = prev_version {
            // Load previous baseline entry (would need to be stored separately in production)
            tracing::info!(
                "Found previous version of '{}': {}",
                baseline.name,
                prev.version_id
            );
            // For now, we'll just show current info
            if output_mode == OutputMode::Human {
                println!("\n{} {}", "Baseline:".cyan().bold(), baseline.name);
                println!("  {} {}", "Current version:".dimmed(), baseline.version_id);
                println!("  {} {}", "Previous version:".dimmed(), prev.version_id);
                println!("  {} {}", "Profiles:".dimmed(), baseline.profile_count);
                println!("  {} {}", "Scripts:".dimmed(), baseline.script_count);
                println!(
                    "  {} {}",
                    "mSCP Git:".dimmed(),
                    &baseline.mscp_git_hash[..7]
                );
            }

            result.add_baseline_diff(BaselineDiff {
                baseline_name: baseline.name.clone(),
                current_version: baseline.version_id.clone(),
                previous_version: Some(prev.version_id.clone()),
                profile_count: baseline.profile_count,
                script_count: baseline.script_count,
                mscp_git_hash: baseline.mscp_git_hash.clone(),
            });
        } else {
            if output_mode == OutputMode::Human {
                println!(
                    "\n{} {} {}",
                    "Baseline:".cyan().bold(),
                    baseline.name,
                    "(no previous version)".dimmed()
                );
                println!("  {} {}", "Version:".dimmed(), baseline.version_id);
                println!("  {} {}", "Profiles:".dimmed(), baseline.profile_count);
            }

            result.add_baseline_diff(BaselineDiff {
                baseline_name: baseline.name.clone(),
                current_version: baseline.version_id.clone(),
                previous_version: None,
                profile_count: baseline.profile_count,
                script_count: baseline.script_count,
                mscp_git_hash: baseline.mscp_git_hash.clone(),
            });
        }
    }

    // Generate diff report
    if !diffs.is_empty() {
        let report = DiffEngine::generate_markdown_report(&diffs);

        match format {
            DiffFormat::Markdown => {
                let diff_path = output_path
                    .join("lib")
                    .join("mscp")
                    .join("versions")
                    .join("diffs");
                fs::create_dir_all(&diff_path)?;

                let report_path = diff_path.join(format!(
                    "diff-{}.md",
                    chrono::Utc::now().format("%Y%m%d-%H%M%S")
                ));
                fs::write(&report_path, report)?;
                if output_mode == OutputMode::Human {
                    println!(
                        "\n{} {}",
                        "✓ Diff report written to:".green(),
                        report_path.display().to_string().dimmed()
                    );
                }
            }
            DiffFormat::Console => {
                if output_mode == OutputMode::Human {
                    println!("\n{report}");
                }
            }
        }
    }

    // Output results
    match output_mode {
        OutputMode::Json => {
            crate::output::json::output_diff_result(&result)?;
        }
        OutputMode::Human => {
            // Already printed above
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub enum DiffFormat {
    Markdown,
    Console,
}
