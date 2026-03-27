use crate::managers::{BaselineIndex, VerificationReport};
use anyhow::Result;
use colored::Colorize;
use std::path::PathBuf;

pub fn clean_baseline(baseline: String, output: PathBuf, force: bool) -> Result<()> {
    let manager = BaselineIndex::new(output.clone());

    println!("{} '{}'...", "Cleaning baseline".cyan(), baseline);

    match manager.clean_baseline(&baseline, force) {
        Ok(report) => {
            println!(
                "\n{} '{}'",
                "✓ Successfully removed baseline".green(),
                report.baseline_name
            );
            println!(
                "\n{} {} file(s):",
                "Removed".cyan(),
                report.removed_files.len()
            );
            for file in report.removed_files {
                println!("  {} {}", "-".dimmed(), file.display().to_string().dimmed());
            }

            if !report.warnings.is_empty() {
                println!("\n{}", "⚠ Warnings:".yellow().bold());
                for warning in report.warnings {
                    println!("  {} {}", "-".dimmed(), warning.yellow());
                }
            }

            // Run verification to check for orphaned references
            println!("\n{}", "Verifying repository integrity...".cyan());
            let verify_report = manager.verify_references()?;

            if verify_report.valid {
                println!("{}", "✓ No orphaned references found".green());
            } else {
                println!(
                    "\n{}",
                    "⚠ Found orphaned references after cleanup:".yellow().bold()
                );

                if !verify_report.orphaned_label_references.is_empty() {
                    println!("\n{}", "Orphaned label references:".yellow());
                    for orphan in &verify_report.orphaned_label_references {
                        println!(
                            "  {} {} in {}",
                            "-".dimmed(),
                            orphan.reference,
                            orphan.file.display().to_string().dimmed()
                        );
                    }
                }

                if !verify_report.orphaned_baseline_references.is_empty() {
                    println!("\n{}", "Orphaned baseline references:".yellow());
                    for orphan in &verify_report.orphaned_baseline_references {
                        println!(
                            "  {} Baseline '{}' in {}",
                            "-".dimmed(),
                            orphan.reference,
                            orphan.file.display().to_string().dimmed()
                        );
                    }
                }

                println!(
                    "\n💡 Run '{}' to automatically fix these issues",
                    format!("contour mscp verify --output {} --fix", output.display()).cyan()
                );
            }

            Ok(())
        }
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            if !force {
                eprintln!(
                    "\n{} Use --force to remove baseline even if referenced by team files",
                    "Hint:".yellow()
                );
            }
            Err(e)
        }
    }
}

pub fn migrate_team_file(
    from: String,
    to: String,
    team: PathBuf,
    output: PathBuf,
    create_backup: bool,
) -> Result<()> {
    let manager = BaselineIndex::new(output.clone());

    println!(
        "{} '{}' → '{}'...",
        "Migrating team file from".cyan(),
        from,
        to
    );
    println!("{} {}", "Team file:".dimmed(), team.display());

    // Resolve team file path relative to output if needed
    let team_path = if team.is_absolute() {
        team
    } else {
        output.join("fleets").join(&team)
    };

    match manager.migrate_team_file(&team_path, &from, &to, create_backup) {
        Ok(report) => {
            println!("\n{}", "✓ Successfully migrated team file".green());
            println!(
                "  {} {} path reference(s) updated",
                "-".dimmed(),
                report.path_replacements
            );
            println!(
                "  {} {} label reference(s) updated",
                "-".dimmed(),
                report.label_replacements
            );

            if create_backup {
                let backup_path = team_path.with_extension("yml.bak");
                println!(
                    "  {} Backup created: {}",
                    "-".dimmed(),
                    backup_path.display().to_string().dimmed()
                );
            }

            Ok(())
        }
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            Err(e)
        }
    }
}

pub fn verify_references(output: PathBuf, fix: bool) -> Result<()> {
    let manager = BaselineIndex::new(output.clone());

    println!("{}\n", "Verifying GitOps repository integrity...".cyan());

    let report = manager.verify_references()?;

    if report.valid {
        println!(
            "{}",
            "✓ No orphaned references found. Repository is clean.".green()
        );
        return Ok(());
    }

    println!("{}\n", "⚠ Found orphaned references:".yellow().bold());

    if !report.orphaned_label_references.is_empty() {
        println!("{}", "Orphaned label references in default.yml:".yellow());
        for orphan in &report.orphaned_label_references {
            println!("  {} {}", "-".dimmed(), orphan.reference);
            println!("    {} {}", "Reason:".dimmed(), orphan.reason);
            println!(
                "    {} {}",
                "File:".dimmed(),
                orphan.file.display().to_string().dimmed()
            );
        }
        println!();
    }

    if !report.orphaned_baseline_references.is_empty() {
        println!("{}", "Orphaned baseline references in team files:".yellow());
        for orphan in &report.orphaned_baseline_references {
            println!("  {} Baseline: {}", "-".dimmed(), orphan.reference);
            println!("    {} {}", "Reason:".dimmed(), orphan.reason);
            println!(
                "    {} {}",
                "File:".dimmed(),
                orphan.file.display().to_string().dimmed()
            );
        }
        println!();
    }

    if fix {
        println!("{}\n", "Fixing orphaned references...".cyan());
        fix_orphaned_references(&report)?;
        println!("{}", "✓ Orphaned references have been removed".green());
    } else {
        println!(
            "{}",
            "Run with --fix to automatically remove these orphaned references".dimmed()
        );
    }

    Ok(())
}

fn fix_orphaned_references(report: &VerificationReport) -> Result<()> {
    use std::collections::HashMap;

    // Group orphans by file
    let mut files_to_fix: HashMap<PathBuf, Vec<String>> = HashMap::new();

    for orphan in &report.orphaned_label_references {
        files_to_fix
            .entry(orphan.file.clone())
            .or_default()
            .push(orphan.reference.clone());
    }

    for orphan in &report.orphaned_baseline_references {
        let baseline_pattern = format!("lib/mscp/{}/", orphan.reference);
        files_to_fix
            .entry(orphan.file.clone())
            .or_default()
            .push(baseline_pattern);
    }

    // Fix each file
    for (file_path, patterns) in files_to_fix {
        let content = std::fs::read_to_string(&file_path)?;

        // Parse as YAML
        let mut yaml: yaml_serde::Value = yaml_serde::from_str(&content)?;

        // Remove orphaned label references from default.yml
        if file_path.file_name().and_then(|n| n.to_str()) == Some("default.yml")
            && let Some(labels) = yaml.get_mut("labels").and_then(|l| l.as_sequence_mut())
        {
            labels.retain(|label_entry| {
                if let Some(path) = label_entry.get("path").and_then(|p| p.as_str()) {
                    !patterns.iter().any(|pattern| path.contains(pattern))
                } else {
                    true
                }
            });
        }

        // Remove orphaned baseline references from team files
        if let Some(controls) = yaml.get_mut("controls") {
            // Remove from custom_settings
            if let Some(macos_settings) = controls.get_mut("macos_settings")
                && let Some(custom_settings) = macos_settings.get_mut("custom_settings")
                && let Some(settings_array) = custom_settings.as_sequence_mut()
            {
                settings_array.retain(|item| {
                    if let Some(path) = item.get("path").and_then(|p| p.as_str()) {
                        !patterns.iter().any(|pattern| path.contains(pattern))
                    } else {
                        true
                    }
                });
            }

            // Remove from scripts
            if let Some(scripts) = controls.get_mut("scripts")
                && let Some(scripts_array) = scripts.as_sequence_mut()
            {
                scripts_array.retain(|item| {
                    if let Some(path) = item.get("path").and_then(|p| p.as_str()) {
                        !patterns.iter().any(|pattern| path.contains(pattern))
                    } else {
                        true
                    }
                });
            }
        }

        // Write back
        let updated_content = yaml_serde::to_string(&yaml)?;
        std::fs::write(&file_path, updated_content)?;
        println!(
            "  {} {}",
            "Fixed:".green(),
            file_path.display().to_string().dimmed()
        );
    }

    Ok(())
}
