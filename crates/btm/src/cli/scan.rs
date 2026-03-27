//! BTM scan command — scan for launch items and merge into btm.toml.

use crate::cli::{BtmScanMode, OutputMode, print_info, print_kv, print_success, print_warning};
use crate::config::{BtmAppEntry, BtmConfig, BtmSettings};
use crate::scan;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Run the BTM scan command.
///
/// Scans for launch items (filesystem or app-bundle mode), optionally
/// presents an interactive picker, then merges results into a btm.toml.
pub fn run(
    mode: &BtmScanMode,
    paths: &[PathBuf],
    output: &Path,
    org: &str,
    interactive: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        print_info("Scanning for background task management items...");
        print_kv("Organization", org);
        print_kv(
            "Mode",
            match mode {
                BtmScanMode::LaunchItems => "launch-items (system LaunchDaemons/LaunchAgents)",
                BtmScanMode::Apps => "apps (embedded in .app bundles)",
            },
        );
    }

    let results = match mode {
        BtmScanMode::LaunchItems => scan::scan_launch_items(paths)?,
        BtmScanMode::Apps => {
            let scan_paths = if paths.is_empty() {
                vec![PathBuf::from("/Applications")]
            } else {
                paths.to_vec()
            };
            scan::scan_app_bundles(&scan_paths)?
        }
    };

    if results.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No launch items found");
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human {
        print_kv("Launch items found", &results.len().to_string());
    }

    // Interactive selection or use all results
    let selected = if interactive {
        scan::interactive_btm_selection(&results)?
    } else {
        results
    };

    if selected.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No items selected");
        }
        return Ok(());
    }

    // Load existing config or create new
    let mut config = if output.exists() {
        if output_mode == OutputMode::Human {
            print_info(&format!(
                "Loading existing config from {}...",
                output.display()
            ));
        }
        BtmConfig::load(output)?
    } else {
        BtmConfig {
            settings: BtmSettings {
                org: org.to_string(),
                display_name: None,
            },
            apps: Vec::new(),
        }
    };

    // Merge scan results into config
    let mut rules_added = 0usize;
    let mut apps_created = 0usize;

    for scan_result in &selected {
        // Try to find a matching app by team_id or label-based bundle_id
        let existing_app = config.apps.iter_mut().find(|app| {
            // Match by team_id
            if let (Some(app_tid), Some(scan_tid)) = (&app.team_id, &scan_result.team_id)
                && app_tid == scan_tid
            {
                return true;
            }
            // Match by bundle_id appearing in scan's bundle_ids
            scan_result.bundle_ids.contains(&app.bundle_id)
        });

        if let Some(app) = existing_app {
            // Merge rules into existing app, avoiding duplicates
            for rule in &scan_result.suggested_rules {
                let already_has = app.rules.iter().any(|existing| {
                    existing.rule_type == rule.rule_type && existing.rule_value == rule.rule_value
                });
                if !already_has {
                    app.rules.push(rule.clone());
                    rules_added += 1;
                }
            }
        } else {
            // Create new app entry from scan result
            let name = scan_result
                .label
                .rsplit('.')
                .next()
                .unwrap_or(&scan_result.label)
                .to_string();

            let bundle_id = scan_result
                .bundle_ids
                .first()
                .cloned()
                .unwrap_or_else(|| scan_result.label.clone());

            // Try to get code requirement from executable
            let code_requirement = scan_result
                .executable
                .as_ref()
                .filter(|exe| exe.exists())
                .and_then(|exe| contour_core::get_code_requirement(exe).ok());

            let new_app = BtmAppEntry {
                name,
                bundle_id,
                team_id: scan_result.team_id.clone(),
                code_requirement,
                rules: scan_result.suggested_rules.clone(),
            };

            rules_added += new_app.rules.len();
            config.apps.push(new_app);
            apps_created += 1;
        }
    }

    // Save config
    config.save(output)?;

    if output_mode == OutputMode::Human {
        println!();
        print_success(&format!(
            "Added {} BTM rule(s) across {} item(s) ({} new app entries)",
            rules_added,
            selected.len(),
            apps_created,
        ));
        print_kv("Output", &output.display().to_string());
        println!();
        print_info("Next steps:");
        println!("  1. Review: cat {}", output.display());
        println!(
            "  2. Generate: contour btm generate {} --output ./profiles/",
            output.display()
        );
    }

    Ok(())
}

/// Convert a scan result into a `BtmAppEntry` by extracting a name,
/// choosing a bundle_id, looking up code requirements, and copying rules.
fn scan_result_to_app_entry(scan_result: &scan::BtmScanResult) -> BtmAppEntry {
    let name = scan_result
        .label
        .rsplit('.')
        .next()
        .unwrap_or(&scan_result.label)
        .to_string();

    let bundle_id = scan_result
        .bundle_ids
        .first()
        .cloned()
        .unwrap_or_else(|| scan_result.label.clone());

    let code_requirement = scan_result
        .executable
        .as_ref()
        .filter(|exe| exe.exists())
        .and_then(|exe| contour_core::get_code_requirement(exe).ok());

    BtmAppEntry {
        name,
        bundle_id,
        team_id: scan_result.team_id.clone(),
        code_requirement,
        rules: scan_result.suggested_rules.clone(),
    }
}

/// Run the one-shot mode (no subcommand).
///
/// Combines scan + generate in a single step, skipping the intermediate
/// btm.toml file. Launch items are scanned, optionally filtered
/// interactively, and service management profiles (or DDM declarations)
/// are generated directly.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
pub fn run_oneshot(
    mode: &BtmScanMode,
    paths: &[PathBuf],
    output: Option<&Path>,
    org: &str,
    interactive: bool,
    ddm: bool,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    use crate::generate::{
        generate_btm_declaration, generate_combined_service_management_profile, sanitize_filename,
    };
    use anyhow::Context;

    if output_mode == OutputMode::Human {
        print_info("Scanning for BTM items for profile generation...");
        print_kv("Organization", org);
        print_kv(
            "Mode",
            match mode {
                BtmScanMode::LaunchItems => "launch-items (system LaunchDaemons/LaunchAgents)",
                BtmScanMode::Apps => "apps (embedded in .app bundles)",
            },
        );
    }

    let results = match mode {
        BtmScanMode::LaunchItems => scan::scan_launch_items(paths)?,
        BtmScanMode::Apps => {
            let scan_paths = if paths.is_empty() {
                vec![PathBuf::from("/Applications")]
            } else {
                paths.to_vec()
            };
            scan::scan_app_bundles(&scan_paths)?
        }
    };

    if results.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No launch items found");
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human {
        print_kv("Launch items found", &results.len().to_string());
    }

    let selected = if interactive {
        scan::interactive_btm_selection(&results)?
    } else {
        results
    };

    if selected.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No items selected");
        }
        return Ok(());
    }

    // Build in-memory app entries from scan results
    let apps: Vec<BtmAppEntry> = selected.iter().map(scan_result_to_app_entry).collect();

    if dry_run {
        use colored::Colorize;

        if output_mode == OutputMode::Json {
            let total_rules: usize = apps.iter().map(|a| a.rules.len().max(1)).sum();
            let json = serde_json::json!({
                "mode": "combined",
                "format": if ddm { "ddm" } else { "mobileconfig" },
                "filename": "service-management.mobileconfig",
                "total_rules": total_rules,
                "apps": apps.iter().map(|a| {
                    serde_json::json!({
                        "name": a.name,
                        "bundle_id": a.bundle_id,
                        "rules": a.rules.len(),
                    })
                }).collect::<Vec<_>>(),
            });
            if let Ok(json_str) = serde_json::to_string_pretty(&json) {
                println!("{json_str}");
            }
        } else {
            let total_rules: usize = apps.iter().map(|a| a.rules.len().max(1)).sum();
            println!();
            println!("{}", "Dry Run - BTM Profile Preview".bold());
            println!("{}", "=".repeat(50));
            println!();

            if ddm {
                println!("{}", "DDM Background Task Declarations:".bold().cyan());
                for app in &apps {
                    let btm_info = if app.rules.is_empty() {
                        String::new()
                    } else {
                        format!(" ({} rules)", app.rules.len())
                    };
                    println!(
                        "  {} {}{} → {}-btm.json",
                        "•".green(),
                        app.name,
                        btm_info.cyan(),
                        sanitize_filename(&app.name)
                    );
                }
                println!();
                println!("{}", "-".repeat(50));
                println!("Total declarations to generate: {}", apps.len());
            } else {
                println!("{}", "Combined Service Management Profile:".bold().cyan());
                println!(
                    "  {} service-management.mobileconfig ({} rules from {} apps)",
                    "•".green(),
                    total_rules,
                    apps.len()
                );
                println!();
                println!("{}", "Included apps:".dimmed());
                for app in &apps {
                    let rules = if app.rules.is_empty() {
                        1
                    } else {
                        app.rules.len()
                    };
                    println!(
                        "    {} ({} rule{})",
                        app.name,
                        rules,
                        if rules == 1 { "" } else { "s" }
                    );
                }
            }
        }
        return Ok(());
    }

    // Generate profiles
    let output_dir = output.map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;

    if ddm {
        // DDM: still per-app (each declaration is per-task-type)
        let mut profiles_written = Vec::new();
        for app in &apps {
            let filename = format!("{}-btm.json", sanitize_filename(&app.name));
            let output_path = output_dir.join(&filename);

            match generate_btm_declaration(app, org) {
                Ok(content) => {
                    std::fs::write(&output_path, &content).with_context(|| {
                        format!(
                            "Failed to write DDM declaration to {}",
                            output_path.display()
                        )
                    })?;
                    profiles_written.push((format!("{} BTM Declaration", app.name), output_path));
                }
                Err(e) => {
                    if output_mode == OutputMode::Human {
                        print_warning(&format!("Skipping DDM declaration for {}: {}", app.name, e));
                    }
                }
            }
        }
        if output_mode == OutputMode::Human {
            println!();
            print_success(&format!(
                "Generated {} declaration(s)",
                profiles_written.len()
            ));
            println!();
            print_info("Declarations created:");
            for (name, path) in &profiles_written {
                print_kv(&format!("  {name}"), &path.display().to_string());
            }
        }
    } else {
        // Mobileconfig: combined (single profile with all rules)
        let filename = "service-management.mobileconfig";
        let output_path = output_dir.join(filename);

        let content = generate_combined_service_management_profile(&apps, org, None)?;
        std::fs::write(&output_path, &content)
            .with_context(|| format!("Failed to write profile to {}", output_path.display()))?;

        if output_mode == OutputMode::Human {
            let total_rules: usize = apps.iter().map(|a| a.rules.len().max(1)).sum();
            println!();
            print_success(&format!(
                "Generated combined service management profile ({} rules from {} apps)",
                total_rules,
                apps.len()
            ));
            println!();
            print_info("Profile created:");
            print_kv("  Service Management", &output_path.display().to_string());
        }
    }

    Ok(())
}
