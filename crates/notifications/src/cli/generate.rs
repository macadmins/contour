//! Notifications generate command — generate notification mobileconfig profiles.
//!
//! Default: individual profiles per app.
//! With --combined: merges all notification entries into a single profile.
//! With --fragment: generates a Fleet fragment directory.

use crate::cli::{OutputMode, print_info, print_kv, print_success, print_warning};
use crate::config::NotificationConfig;
use crate::generate::{
    generate_combined_notification_profile, generate_notification_profile, resolve_output_dir,
    sanitize_filename,
};
use anyhow::{Context, Result};
use colored::Colorize;
use contour_core::FleetLayout;
use contour_core::fragment::{
    DefaultYmlEntries, FleetEntries, FragmentManifest, FragmentMeta, LibFiles, ProfileEntry,
    ScriptEntries,
};
use std::path::{Path, PathBuf};

/// Run the notifications generate command.
///
/// Generates notification settings profiles (mobileconfig) — either per-app
/// or combined into a single profile.
/// With `--fragment`, generates a Fleet fragment directory.
pub fn run(
    input: &Path,
    output: Option<&Path>,
    combined: bool,
    dry_run: bool,
    fragment: bool,
    output_mode: OutputMode,
) -> Result<()> {
    // Delegate to Fleet fragment generation if requested
    if fragment {
        return run_fragment(input, output, dry_run, output_mode);
    }

    if output_mode == OutputMode::Human {
        print_info(&format!(
            "Loading notification settings from {}...",
            input.display()
        ));
    }

    let config = NotificationConfig::load(input)?;

    if config.apps.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No apps with notification settings found");
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human {
        print_kv("Organization", &config.settings.org);
        print_kv("Apps", &config.apps.len().to_string());
        print_kv("Mode", if combined { "combined" } else { "per-app" });
    }

    if dry_run {
        print_dry_run(&config, combined, output_mode);
        return Ok(());
    }

    let output_dir = resolve_output_dir(output, input)?;

    if combined {
        let display_name = config.settings.display_name.as_deref();
        let content = generate_combined_notification_profile(
            &config.apps,
            &config.settings.org,
            display_name,
        )?;
        let output_path = output_dir.join("notifications.mobileconfig");
        std::fs::write(&output_path, &content).with_context(|| {
            format!(
                "Failed to write combined profile to {}",
                output_path.display()
            )
        })?;

        if output_mode == OutputMode::Human {
            println!();
            print_success("Generated combined notification profile");
            print_kv("Output", &output_path.display().to_string());
            print_kv("Apps included", &config.apps.len().to_string());
        }
    } else {
        let mut profiles_written = Vec::new();

        for app in &config.apps {
            let filename = format!(
                "{}-notifications.mobileconfig",
                sanitize_filename(&app.name)
            );
            let output_path = output_dir.join(&filename);

            match generate_notification_profile(app, &config.settings.org) {
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

            println!();
            print_info("Next steps:");
            println!("  1. Validate: plutil -lint <profile>.mobileconfig");
            println!("  2. Deploy via MDM to manage notification settings");
        }
    }

    Ok(())
}

/// Print dry-run preview for notifications generate.
fn print_dry_run(config: &NotificationConfig, combined: bool, output_mode: OutputMode) {
    if output_mode == OutputMode::Json {
        let json = serde_json::json!({
            "mode": if combined { "combined" } else { "per-app" },
            "profiles": if combined {
                vec![serde_json::json!({
                    "filename": "notifications.mobileconfig",
                    "apps": config.apps.len(),
                })]
            } else {
                config.apps.iter().map(|a| {
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
        return;
    }

    println!();
    println!("{}", "Dry Run - Notification Profile Preview".bold());
    println!("{}", "=".repeat(50));
    println!();

    if combined {
        println!(
            "{} Combined profile with {} app(s) → notifications.mobileconfig",
            "•".green(),
            config.apps.len()
        );
        for app in &config.apps {
            println!("    {} ({})", app.name, app.bundle_id.dimmed());
        }
    } else {
        println!("{}", "Notification Settings Profiles:".bold().cyan());
        for app in &config.apps {
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
        if combined { 1 } else { config.apps.len() }
    );
}

/// Generate a Fleet fragment directory.
///
/// Produces:
/// - `platforms/macos/configuration-profiles/` with mobileconfig files
/// - `fleets/reference-team.yml` with profile entries
/// - `fragment.toml` manifest for merge
fn run_fragment(
    input: &Path,
    output: Option<&Path>,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        print_info(&format!(
            "Loading notification settings from {}...",
            input.display()
        ));
    }

    let config = NotificationConfig::load(input)?;

    if config.apps.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No apps with notification settings found for fragment");
        }
        return Ok(());
    }

    let layout = FleetLayout::default();

    // Determine output directory
    let output_dir = output.map_or_else(
        || PathBuf::from("notifications-fragment"),
        Path::to_path_buf,
    );

    if output_mode == OutputMode::Human {
        print_kv("Organization", &config.settings.org);
        print_kv("Apps", &config.apps.len().to_string());
        print_kv("Mode", "fragment");
        print_kv("Output directory", &output_dir.display().to_string());
    }

    if dry_run {
        if output_mode == OutputMode::Human {
            print_info("Dry run - no files will be written");
            println!();
            println!("{}", "Fragment Preview".bold());
            println!("{}", "=".repeat(50));
            println!(
                "  Notification profiles: {}",
                config.apps.len().to_string().bold()
            );
        }
        return Ok(());
    }

    // Create directory structure
    let profiles_dir = output_dir.join(layout.macos_profiles_subdir);
    let fleets_dir = output_dir.join(layout.fleets_dir);
    std::fs::create_dir_all(&profiles_dir)?;
    std::fs::create_dir_all(&fleets_dir)?;

    let mut profile_entries: Vec<ProfileEntry> = Vec::new();
    let mut lib_files: Vec<String> = Vec::new();
    let mut profiles_written = 0;

    // Generate notification profiles (per-app)
    for app in &config.apps {
        let filename = format!(
            "{}-notifications.mobileconfig",
            sanitize_filename(&app.name)
        );
        let output_path = profiles_dir.join(&filename);

        match generate_notification_profile(app, &config.settings.org) {
            Ok(content) => {
                std::fs::write(&output_path, &content).with_context(|| {
                    format!("Failed to write profile to {}", output_path.display())
                })?;

                let relative_path = format!("{}/{filename}", layout.macos_profiles_subdir);
                let team_relative_path = format!("../{}/{filename}", layout.macos_profiles_subdir);

                lib_files.push(relative_path);
                profile_entries.push(ProfileEntry {
                    path: team_relative_path,
                    labels_include_any: None,
                    labels_include_all: None,
                    labels_exclude_any: None,
                });
                profiles_written += 1;
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

    // Generate fleets/reference-team.yml
    {
        let mut content = String::from(
            "# Fleet GitOps - Team Configuration: Notifications\n\
             #\n\
             # Notification settings profiles for MDM deployment.\n\
             #\n\
             # Generated by Contour CLI (notifications fragment mode)\n\
             \n\
             name: notifications-reference\n\
             controls:\n\
             \x20 macos_settings:\n\
             \x20   custom_settings:\n",
        );

        for entry in &profile_entries {
            use std::fmt::Write;
            let _ = writeln!(content, "      - path: {}", entry.path);
        }

        std::fs::write(fleets_dir.join("reference-team.yml"), &content)?
    };

    // Generate fragment.toml
    {
        let manifest = FragmentManifest {
            fragment: FragmentMeta {
                name: "notification-profiles".to_string(),
                version: "1.0.0".to_string(),
                description: format!(
                    "Notification settings profiles for {} applications",
                    config.apps.len()
                ),
                generator: "contour-notifications".to_string(),
            },
            default_yml: DefaultYmlEntries {
                label_paths: Vec::new(),
                report_paths: Vec::new(),
                policy_paths: Vec::new(),
            },
            fleet_entries: FleetEntries {
                profiles: profile_entries.clone(),
                reports: Vec::new(),
                policies: Vec::new(),
                software: Vec::new(),
            },
            lib_files: LibFiles {
                copy: lib_files.clone(),
            },
            scripts: ScriptEntries::default(),
        };

        manifest.save(&output_dir.join("fragment.toml"))?
    };

    if output_mode == OutputMode::Human {
        println!();
        print_success(&format!(
            "Generated fragment with {} profiles in {}",
            profiles_written,
            output_dir.display()
        ));
        print_kv("Fragment manifest", "fragment.toml");
        print_kv("Profiles", &profiles_written.to_string());

        println!();
        print_info("Next steps:");
        println!(
            "  1. Review the generated fragment in {}",
            output_dir.display()
        );
        println!("  2. Merge into your Fleet GitOps repository");
    }

    Ok(())
}
