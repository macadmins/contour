//! Notifications scan command — scan for installed apps and merge into notifications.toml.

use crate::cli::{OutputMode, print_info, print_kv, print_success, print_warning};
use crate::config::{NotificationAppEntry, NotificationConfig, NotificationSettings};
use crate::scan;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Run the notifications scan command.
///
/// Scans for .app bundles, optionally presents an interactive picker,
/// then merges results into a notifications.toml.
pub fn run(
    paths: &[PathBuf],
    output: &Path,
    org: &str,
    interactive: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        print_info("Scanning for applications...");
        print_kv("Organization", org);
    }

    let results = scan::scan_apps(paths)?;

    if results.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No applications found");
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human {
        print_kv("Applications found", &results.len().to_string());
    }

    // Interactive selection or use all results
    let selected = if interactive {
        scan::interactive_selection(&results)?
    } else {
        results
    };

    if selected.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No apps selected");
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
        NotificationConfig::load(output)?
    } else {
        NotificationConfig {
            settings: NotificationSettings {
                org: org.to_string(),
                display_name: None,
            },
            apps: Vec::new(),
        }
    };

    // Merge scan results into config
    let mut apps_added = 0usize;

    for scan_result in &selected {
        // Skip if already present by bundle_id
        let already_exists = config
            .apps
            .iter()
            .any(|app| app.bundle_id == scan_result.bundle_id);

        if !already_exists {
            config.apps.push(NotificationAppEntry::new(
                scan_result.name.clone(),
                scan_result.bundle_id.clone(),
            ));
            apps_added += 1;
        }
    }

    // Save config
    config.save(output)?;

    if output_mode == OutputMode::Human {
        println!();
        print_success(&format!(
            "Added {} app(s) to notification config ({} total)",
            apps_added,
            config.apps.len(),
        ));
        print_kv("Output", &output.display().to_string());
        println!();
        print_info("Next steps:");
        println!(
            "  1. Configure settings: contour notifications configure {}",
            output.display()
        );
        println!(
            "  2. Generate profiles: contour notifications generate {} --output ./profiles/",
            output.display()
        );
    }

    Ok(())
}

/// Run the one-shot mode (no subcommand).
///
/// Combines scan + generate in a single step, skipping the intermediate
/// notifications.toml file. Apps are scanned, optionally filtered interactively,
/// and notification profiles are generated directly.
pub fn run_oneshot(
    paths: &[PathBuf],
    output: Option<&Path>,
    org: &str,
    interactive: bool,
    combined: bool,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    use crate::generate::{
        generate_combined_notification_profile, generate_notification_profile, sanitize_filename,
    };
    use anyhow::Context;

    if output_mode == OutputMode::Human {
        print_info("Scanning applications for notification profile generation...");
        print_kv("Organization", org);
        print_kv(
            "Paths",
            &paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    let results = scan::scan_apps(paths)?;

    if results.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No applications found");
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human {
        print_kv("Applications found", &results.len().to_string());
    }

    // Interactive selection or use all results
    let selected = if interactive {
        scan::interactive_selection(&results)?
    } else {
        results
    };

    if selected.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No apps selected");
        }
        return Ok(());
    }

    // Build in-memory app entries with sensible defaults
    let apps: Vec<NotificationAppEntry> = selected
        .iter()
        .map(|r| NotificationAppEntry::new(r.name.clone(), r.bundle_id.clone()))
        .collect();

    if dry_run {
        use colored::Colorize;

        if output_mode == OutputMode::Json {
            let json = serde_json::json!({
                "mode": if combined { "combined" } else { "per-app" },
                "profiles": if combined {
                    vec![serde_json::json!({
                        "filename": "notifications.mobileconfig",
                        "apps": apps.len(),
                    })]
                } else {
                    apps.iter().map(|a| {
                        serde_json::json!({
                            "name": a.name,
                            "bundle_id": a.bundle_id,
                            "filename": format!("{}-notifications.mobileconfig", sanitize_filename(&a.name)),
                        })
                    }).collect::<Vec<_>>()
                },
            });
            if let Ok(json_str) = serde_json::to_string_pretty(&json) {
                println!("{json_str}");
            }
        } else {
            println!();
            println!("{}", "Dry Run - Notification Profile Preview".bold());
            println!("{}", "=".repeat(50));
            println!();

            if combined {
                println!(
                    "{} Combined profile with {} app(s) → notifications.mobileconfig",
                    "•".green(),
                    apps.len()
                );
                for app in &apps {
                    println!("    {} ({})", app.name, app.bundle_id.dimmed());
                }
            } else {
                println!("{}", "Notification Settings Profiles:".bold().cyan());
                for app in &apps {
                    println!(
                        "  {} {} [{}] → {}-notifications.mobileconfig",
                        "•".green(),
                        app.name,
                        app.bundle_id.dimmed(),
                        sanitize_filename(&app.name)
                    );
                }
            }

            println!();
            println!("{}", "-".repeat(50));
            println!(
                "Total profiles to generate: {}",
                if combined { 1 } else { apps.len() }
            );
        }
        return Ok(());
    }

    // Generate profiles
    let output_dir = output.map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;

    if combined {
        let content = generate_combined_notification_profile(&apps, org, None)?;
        let output_path = output_dir.join("notifications.mobileconfig");
        std::fs::write(&output_path, &content)
            .with_context(|| format!("Failed to write profile to {}", output_path.display()))?;

        if output_mode == OutputMode::Human {
            println!();
            print_success("Generated combined notification profile");
            print_kv("Output", &output_path.display().to_string());
            print_kv("Apps included", &apps.len().to_string());
        }
    } else {
        let mut profiles_written = Vec::new();

        for app in &apps {
            let filename = format!(
                "{}-notifications.mobileconfig",
                sanitize_filename(&app.name)
            );
            let output_path = output_dir.join(&filename);

            match generate_notification_profile(app, org) {
                Ok(content) => {
                    std::fs::write(&output_path, &content).with_context(|| {
                        format!("Failed to write profile to {}", output_path.display())
                    })?;
                    profiles_written.push((format!("{} Notifications", app.name), output_path));
                }
                Err(e) => {
                    if output_mode == OutputMode::Human {
                        print_warning(&format!(
                            "Skipping notification profile for {}: {}",
                            app.name, e
                        ));
                    }
                }
            }
        }

        if output_mode == OutputMode::Human {
            println!();
            print_success(&format!(
                "Generated {} notification profile(s)",
                profiles_written.len()
            ));
            println!();
            print_info("Profiles created:");
            for (name, path) in &profiles_written {
                print_kv(&format!("  {name}"), &path.display().to_string());
            }
        }
    }

    Ok(())
}
