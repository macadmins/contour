//! BTM generate command — generate service management profiles or DDM declarations.

use crate::cli::{OutputMode, print_info, print_kv, print_success, print_warning};
use crate::config::{BtmAppEntry, BtmConfig};
use crate::generate::{
    generate_btm_declaration, generate_combined_service_management_profile,
    generate_service_management_profile, resolve_output_dir, sanitize_filename,
};
use anyhow::{Context, Result};
use colored::Colorize;
use contour_core::FleetLayout;
use contour_core::fragment::{
    DefaultYmlEntries, FleetEntries, FragmentManifest, FragmentMeta, LibFiles, ProfileEntry,
    ScriptEntries,
};
use std::path::{Path, PathBuf};

/// Run the BTM generate command.
///
/// By default generates a single combined service management profile with all
/// rules. Use `per_app` to generate one profile per app instead.
pub fn run(
    input: &Path,
    output: Option<&Path>,
    dry_run: bool,
    fragment: bool,
    ddm: bool,
    per_app: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if fragment {
        return run_generate_fragment(input, output, dry_run, ddm, output_mode);
    }

    if output_mode == OutputMode::Human {
        print_info(&format!("Loading BTM policy from {}...", input.display()));
    }

    let config = BtmConfig::load(input)?;
    let apps_with_btm: Vec<_> = config.apps.iter().collect();

    if apps_with_btm.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No apps with BTM rules found");
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human {
        print_kv("Organization", &config.settings.org);
        print_kv("Apps with BTM", &apps_with_btm.len().to_string());
        print_kv(
            "Format",
            if ddm {
                "DDM declaration (JSON)"
            } else {
                "mobileconfig"
            },
        );
        print_kv("Mode", if per_app { "per-app" } else { "combined" });
    }

    if dry_run {
        print_btm_dry_run(&apps_with_btm, ddm, per_app, output_mode);
        return Ok(());
    }

    let output_dir = resolve_output_dir(output, input)?;
    let mut profiles_written = Vec::new();

    if per_app {
        // Per-app mode: one profile per app
        for app in &apps_with_btm {
            if ddm {
                let filename = format!("{}-btm.json", sanitize_filename(&app.name));
                let output_path = output_dir.join(&filename);

                match generate_btm_declaration(app, &config.settings.org) {
                    Ok(content) => {
                        std::fs::write(&output_path, &content).with_context(|| {
                            format!(
                                "Failed to write DDM declaration to {}",
                                output_path.display()
                            )
                        })?;
                        profiles_written
                            .push((format!("{} BTM Declaration", app.name), output_path));
                    }
                    Err(e) => {
                        if output_mode == OutputMode::Human {
                            print_warning(&format!(
                                "Skipping DDM declaration for {}: {}",
                                app.name, e
                            ));
                        }
                    }
                }
            } else {
                let filename = format!(
                    "{}-service-management.mobileconfig",
                    sanitize_filename(&app.name)
                );
                let output_path = output_dir.join(&filename);

                match generate_service_management_profile(app, &config.settings.org) {
                    Ok(content) => {
                        std::fs::write(&output_path, &content).with_context(|| {
                            format!("Failed to write profile to {}", output_path.display())
                        })?;
                        profiles_written
                            .push((format!("{} Service Management", app.name), output_path));
                    }
                    Err(e) => {
                        if output_mode == OutputMode::Human {
                            print_warning(&format!(
                                "Skipping service management for {}: {}",
                                app.name, e
                            ));
                        }
                    }
                }
            }
        }
    } else {
        // Combined mode (default): single profile with all rules
        let display_name = config.settings.display_name.as_deref();
        let filename = "service-management.mobileconfig";
        let output_path = output_dir.join(filename);

        let content = generate_combined_service_management_profile(
            &config.apps,
            &config.settings.org,
            display_name,
        )?;
        std::fs::write(&output_path, &content)
            .with_context(|| format!("Failed to write profile to {}", output_path.display()))?;
        let total_rules: usize = config.apps.iter().map(|a| a.rules.len().max(1)).sum();
        profiles_written.push((
            format!(
                "Service Management ({total_rules} rules from {} apps)",
                config.apps.len()
            ),
            output_path,
        ));
    }

    if output_mode == OutputMode::Human {
        println!();
        print_success(&format!("Generated {} profile(s)", profiles_written.len()));
        println!();
        print_info("Profiles created:");
        for (name, path) in &profiles_written {
            print_kv(&format!("  {name}"), &path.display().to_string());
        }

        println!();
        print_info("Next steps:");
        if ddm {
            println!("  1. Review declarations in {}", output_dir.display());
            println!("  2. Upload to MDM for DDM deployment (macOS 15+)");
        } else {
            println!("  1. Validate: plutil -lint <profile>.mobileconfig");
            println!("  2. Deploy via MDM to manage login items");
        }
    }

    Ok(())
}

/// Print dry-run preview for BTM generate.
fn print_btm_dry_run(apps: &[&BtmAppEntry], ddm: bool, per_app: bool, output_mode: OutputMode) {
    if output_mode == OutputMode::Json {
        let json = if per_app {
            serde_json::json!({
                "mode": "per-app",
                "format": if ddm { "ddm" } else { "mobileconfig" },
                "profiles": apps.iter().map(|a| {
                    serde_json::json!({
                        "name": a.name,
                        "bundle_id": a.bundle_id,
                        "team_id": a.team_id,
                        "rules": a.rules.len(),
                        "filename": if ddm {
                            format!("{}-btm.json", sanitize_filename(&a.name))
                        } else {
                            format!("{}-service-management.mobileconfig", sanitize_filename(&a.name))
                        },
                    })
                }).collect::<Vec<_>>(),
            })
        } else {
            let total_rules: usize = apps.iter().map(|a| a.rules.len().max(1)).sum();
            serde_json::json!({
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
            })
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&json) {
            println!("{json_str}");
        }
        return;
    }

    println!();
    println!("{}", "Dry Run - BTM Profile Preview".bold());
    println!("{}", "=".repeat(50));
    println!();

    if per_app {
        if ddm {
            println!(
                "{}",
                "DDM Background Task Declarations (per-app):".bold().cyan()
            );
        } else {
            println!("{}", "Service Management Profiles (per-app):".bold().cyan());
        }

        for app in apps {
            let team_id = app.team_id.as_deref().unwrap_or("(from code_requirement)");
            let btm_info = if app.rules.is_empty() {
                String::new()
            } else {
                format!(" ({} BTM rules)", app.rules.len())
            };
            if ddm {
                println!(
                    "  {} {} [Team: {}]{} → {}-btm.json",
                    "•".green(),
                    app.name,
                    team_id.dimmed(),
                    btm_info.cyan(),
                    sanitize_filename(&app.name)
                );
            } else {
                println!(
                    "  {} {} [Team: {}]{} → {}-service-management.mobileconfig",
                    "•".green(),
                    app.name,
                    team_id.dimmed(),
                    btm_info.cyan(),
                    sanitize_filename(&app.name)
                );
            }
        }

        println!();
        println!("{}", "-".repeat(50));
        println!("Total profiles to generate: {}", apps.len());
    } else {
        let total_rules: usize = apps.iter().map(|a| a.rules.len().max(1)).sum();
        println!("{}", "Combined Service Management Profile:".bold().cyan());
        println!(
            "  {} service-management.mobileconfig ({} rules from {} apps)",
            "•".green(),
            total_rules,
            apps.len()
        );
        println!();
        println!("{}", "Included apps:".dimmed());
        for app in apps {
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

/// Generate a Fleet fragment directory for BTM profiles.
///
/// Uses [`FleetLayout`] to resolve all directory paths.
fn run_generate_fragment(
    input: &Path,
    output: Option<&Path>,
    dry_run: bool,
    ddm: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        print_info(&format!("Loading BTM policy from {}...", input.display()));
    }

    let config = BtmConfig::load(input)?;
    let apps_with_btm: Vec<_> = config.apps.iter().collect();

    if apps_with_btm.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No apps with BTM rules for fragment");
        }
        return Ok(());
    }

    let output_dir = output.map_or_else(
        || PathBuf::from("btm-fragment"),
        std::path::Path::to_path_buf,
    );

    if output_mode == OutputMode::Human {
        print_kv("Organization", &config.settings.org);
        print_kv("Apps with BTM", &apps_with_btm.len().to_string());
        print_kv("Mode", "fragment");
        print_kv(
            "Format",
            if ddm {
                "DDM declaration (JSON)"
            } else {
                "mobileconfig"
            },
        );
        print_kv("Output directory", &output_dir.display().to_string());
    }

    if dry_run {
        if output_mode == OutputMode::Human {
            print_info("Dry run - no files will be written");
            println!();
            println!("{}", "Fragment Preview".bold());
            println!("{}", "=".repeat(50));
            println!("  BTM profiles: {}", apps_with_btm.len().to_string().bold());
        }
        return Ok(());
    }

    let layout = FleetLayout::default();

    let profiles_dir = output_dir.join(layout.macos_profiles_subdir);
    let teams_dir = output_dir.join(layout.fleets_dir);
    std::fs::create_dir_all(&profiles_dir)?;
    std::fs::create_dir_all(&teams_dir)?;

    let mut profile_entries: Vec<ProfileEntry> = Vec::new();
    let mut lib_files: Vec<String> = Vec::new();
    let mut profiles_written = 0;

    for app in &apps_with_btm {
        if ddm {
            let filename = format!("{}-btm.json", sanitize_filename(&app.name));
            let output_path = profiles_dir.join(&filename);

            match generate_btm_declaration(app, &config.settings.org) {
                Ok(content) => {
                    std::fs::write(&output_path, &content).with_context(|| {
                        format!(
                            "Failed to write DDM declaration to {}",
                            output_path.display()
                        )
                    })?;

                    let relative_path = format!("{}/{filename}", layout.macos_profiles_subdir);
                    let team_relative_path =
                        format!("../{}/{filename}", layout.macos_profiles_subdir);

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
                        print_warning(&format!("Skipping DDM declaration for {}: {}", app.name, e));
                    }
                }
            }
        } else {
            let filename = format!(
                "{}-service-management.mobileconfig",
                sanitize_filename(&app.name)
            );
            let output_path = profiles_dir.join(&filename);

            match generate_service_management_profile(app, &config.settings.org) {
                Ok(content) => {
                    std::fs::write(&output_path, &content).with_context(|| {
                        format!("Failed to write profile to {}", output_path.display())
                    })?;

                    let relative_path = format!("{}/{filename}", layout.macos_profiles_subdir);
                    let team_relative_path =
                        format!("../{}/{filename}", layout.macos_profiles_subdir);

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
                            "Skipping service management for {}: {}",
                            app.name, e
                        ));
                    }
                }
            }
        }
    }

    // Generate fleets/reference-team.yml
    {
        let mut content = String::from(
            "# Fleet GitOps - Team Configuration: BTM/Service Management\n\
             #\n\
             # Background task management profiles for MDM deployment.\n\
             #\n\
             # Generated by Contour CLI (btm fragment mode)\n\
             \n\
             name: btm-reference\n\
             controls:\n\
             \x20 macos_settings:\n\
             \x20   custom_settings:\n",
        );

        for entry in &profile_entries {
            use std::fmt::Write;
            let _ = writeln!(content, "      - path: {}", entry.path);
        }

        std::fs::write(teams_dir.join("reference-team.yml"), &content)?
    };

    // Generate fragment.toml
    {
        let manifest = FragmentManifest {
            fragment: FragmentMeta {
                name: "btm-profiles".to_string(),
                version: "1.0.0".to_string(),
                description: format!(
                    "BTM/service management profiles for {} applications",
                    apps_with_btm.len()
                ),
                generator: "contour-btm".to_string(),
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
            "Generated BTM fragment with {} profiles in {}",
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
