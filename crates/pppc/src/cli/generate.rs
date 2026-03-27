//! PPPC generate command — GitOps workflow step 2.
//!
//! Reads a pppc.toml file and generates TCC/PPPC mobileconfig profiles.
//!
//! Default: individual profiles per app.
//! With --combined: merges all TCC entries into a single profile.
//! With --fragment: generates a Fleet fragment directory.

use crate::cli::{OutputMode, print_info, print_kv, print_success, print_warning};
use crate::pppc::{PppcConfig, PppcPolicy, PppcService, generate_pppc_profile, sanitize_id};
use anyhow::{Context, Result};
use colored::Colorize;
use contour_core::fragment::{
    DefaultYmlEntries, FleetEntries, FragmentManifest, FragmentMeta, LibFiles, ProfileEntry,
    ScriptEntries,
};
use contour_core::{FleetLayout, resolve_output_dir, sanitize_filename};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Run the generate subcommand.
///
/// Reads a pppc.toml file and generates TCC/PPPC mobileconfig profiles.
/// Default is per-app profiles; `--combined` merges TCC into one.
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
        print_info(&format!("Loading PPPC policy from {}...", input.display()));
    }

    let config = PppcConfig::load(input)?;

    if output_mode == OutputMode::Human {
        print_kv("Organization", &config.config.org);
        print_kv("Apps in policy", &config.apps.len().to_string());
        if combined {
            print_kv("Mode", "combined (single TCC profile)");
        } else {
            print_kv("Mode", "per-app (individual profiles)");
        }
    }

    let policies = config.to_policies();

    if policies.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No TCC profiles to generate");
            println!();
            print_info(&format!(
                "Hint: Edit {} and configure apps:",
                input.display()
            ));
            println!("  [[apps]]");
            println!("  name = \"App Name\"");
            println!("  bundle_id = \"com.example.app\"");
            println!(r#"  code_requirement = 'identifier "com.example.app"...'"#);
            println!("  services = [\"fda\", \"camera\"]");
        }
        return Ok(());
    }

    // Check for duplicate bundle_ids
    let duplicates = find_duplicate_bundle_ids(&config);

    if output_mode == OutputMode::Human {
        let total_entries: usize = policies.iter().map(|p| p.services.len()).sum();
        print_kv("Apps with TCC services", &policies.len().to_string());
        print_kv("Total TCC entries", &total_entries.to_string());

        // Warn about duplicates
        if !duplicates.is_empty() {
            println!();
            print_warning(&format!(
                "{} duplicate bundle ID(s) detected (will produce colliding profiles):",
                duplicates.len()
            ));
            for (bundle_id, count) in &duplicates {
                println!("    {} {} ({}x)", "·".dimmed(), bundle_id, count);
            }
        }
    }

    if dry_run {
        print_dry_run(&policies, combined, output_mode);
        return Ok(());
    }

    let output_dir = resolve_output_dir(output, input)?;
    let mut profiles_written = Vec::new();

    // TCC/PPPC profiles
    if combined {
        generate_combined_tcc(
            &policies,
            &config,
            input,
            output,
            &output_dir,
            &mut profiles_written,
        )?;
    } else {
        generate_per_app_tcc(&policies, &config, &output_dir, &mut profiles_written)?;
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
        println!("  1. Validate: plutil -lint <profile>.mobileconfig");
        println!("  2. Deploy via MDM to grant permissions automatically");
    }

    Ok(())
}

/// Generate one TCC profile per app (default mode).
fn generate_per_app_tcc(
    policies: &[PppcPolicy],
    config: &PppcConfig,
    output_dir: &Path,
    profiles_written: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    for policy in policies {
        let filename = format!("{}-pppc.mobileconfig", sanitize_filename(&policy.app.name));
        let output_path = output_dir.join(&filename);

        let display_name = Some(format!("{} PPPC", policy.app.name));
        let suffix = sanitize_id(&policy.app.bundle_id);
        let content = generate_pppc_profile(
            std::slice::from_ref(policy),
            &config.config.org,
            display_name.as_deref(),
            Some(&suffix),
        )?;

        std::fs::write(&output_path, &content)
            .with_context(|| format!("Failed to write profile to {}", output_path.display()))?;

        profiles_written.push((format!("{} PPPC", policy.app.name), output_path));
    }
    Ok(())
}

/// Generate a single combined TCC profile (--combined mode).
fn generate_combined_tcc(
    policies: &[PppcPolicy],
    config: &PppcConfig,
    input: &Path,
    output: Option<&Path>,
    output_dir: &Path,
    profiles_written: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let tcc_output = output
        .filter(|p| p.extension().is_some_and(|e| e == "mobileconfig"))
        .map_or_else(
            || {
                let stem = input.file_stem().unwrap_or_default();
                output_dir.join(format!("{}-pppc.mobileconfig", stem.to_string_lossy()))
            },
            std::path::Path::to_path_buf,
        );

    let display_name = config.config.display_name.as_deref();
    let content = generate_pppc_profile(policies, &config.config.org, display_name, None)?;

    std::fs::write(&tcc_output, &content)
        .with_context(|| format!("Failed to write profile to {}", tcc_output.display()))?;

    profiles_written.push(("PPPC/TCC (combined)".to_string(), tcc_output));
    Ok(())
}

/// Print dry-run preview.
fn print_dry_run(policies: &[PppcPolicy], combined: bool, output_mode: OutputMode) {
    if output_mode == OutputMode::Json {
        let service_breakdown: Vec<_> = count_services(policies)
            .iter()
            .map(|(s, c)| serde_json::json!({"service": s.key(), "display_name": s.display_name(), "count": c}))
            .collect();

        let json = serde_json::json!({
            "mode": if combined { "combined" } else { "per-app" },
            "service_breakdown": service_breakdown,
            "tcc_policies": policies.iter().map(|p| {
                serde_json::json!({
                    "name": p.app.name,
                    "bundle_id": p.app.bundle_id,
                    "services": p.services.iter().map(super::super::pppc::PppcService::key).collect::<Vec<_>>(),
                })
            }).collect::<Vec<_>>(),
        });

        if let Ok(json_str) = serde_json::to_string_pretty(&json) {
            println!("{json_str}");
        }
        return;
    }

    println!();
    println!("{}", "Dry Run - Profile Preview".bold());
    println!("{}", "=".repeat(50));

    if !policies.is_empty() {
        println!();
        if combined {
            println!("{}", "TCC/PPPC (combined into 1 profile):".bold().cyan());
        } else {
            println!(
                "{}",
                format!("TCC/PPPC ({} individual profiles):", policies.len())
                    .bold()
                    .cyan()
            );
        }
        for policy in policies {
            println!(
                "  {} {} ({})",
                "•".green(),
                policy.app.name,
                policy.app.bundle_id.dimmed()
            );
            for service in &policy.services {
                println!("    - {}", service.display_name());
            }
            if !combined {
                println!(
                    "    → {}-pppc.mobileconfig",
                    sanitize_filename(&policy.app.name)
                );
            }
        }
    }

    // Service breakdown
    if !policies.is_empty() {
        println!();
        println!("{}", "TCC Service Breakdown:".bold().cyan());
        let service_counts = count_services(policies);
        let max_count = service_counts
            .iter()
            .map(|(_, c)| *c)
            .max()
            .unwrap_or(1)
            .max(1);
        let max_bar_width: usize = 30;
        for (service, count) in &service_counts {
            #[expect(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "intentional lossy casts for display bar width calculation"
            )]
            let bar_len = if *count == 0 {
                0
            } else {
                ((*count as f64 / max_count as f64) * max_bar_width as f64).ceil() as usize
            };
            let bar = "█".repeat(bar_len);
            println!(
                "  {:>22}  {:>4}  {}",
                service.display_name(),
                count.to_string().bold(),
                bar.green()
            );
        }
    }

    println!();
    println!("{}", "-".repeat(50));
    let tcc_count = if combined {
        usize::from(!policies.is_empty())
    } else {
        policies.len()
    };
    println!("Total profiles to generate: {tcc_count}");
}

/// Count how many apps use each TCC service, sorted by frequency descending.
fn count_services(policies: &[PppcPolicy]) -> Vec<(PppcService, usize)> {
    let mut counts: BTreeMap<&str, (PppcService, usize)> = BTreeMap::new();
    for policy in policies {
        for service in &policy.services {
            counts.entry(service.key()).or_insert((*service, 0)).1 += 1;
        }
    }
    let mut sorted: Vec<_> = counts.into_values().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted
}

/// Find duplicate bundle_ids in the config.
pub fn find_duplicate_bundle_ids(config: &PppcConfig) -> Vec<(String, usize)> {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for app in &config.apps {
        *seen.entry(&app.bundle_id).or_default() += 1;
    }
    seen.into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(id, count)| (id.to_string(), count))
        .collect()
}

/// Generate a Fleet fragment directory.
///
/// Produces:
/// - `<layout.macos_profiles_subdir>/` with mobileconfig files
/// - `<layout.fleets_dir>/reference-team.yml` with profile entries
/// - `fragment.toml` manifest for merge
fn run_fragment(
    input: &Path,
    output: Option<&Path>,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        print_info(&format!("Loading PPPC policy from {}...", input.display()));
    }

    let config = PppcConfig::load(input)?;
    let policies = config.to_policies();

    if policies.is_empty() {
        if output_mode == OutputMode::Human {
            print_warning("No TCC profiles to generate for fragment");
        }
        return Ok(());
    }

    // Determine output directory
    let output_dir = output.map_or_else(
        || PathBuf::from("pppc-fragment"),
        std::path::Path::to_path_buf,
    );

    if output_mode == OutputMode::Human {
        print_kv("Organization", &config.config.org);
        print_kv("Apps in policy", &config.apps.len().to_string());
        print_kv("Mode", "fragment");
        print_kv("Output directory", &output_dir.display().to_string());
    }

    if dry_run {
        if output_mode == OutputMode::Human {
            print_info("Dry run - no files will be written");
            println!();
            println!("{}", "Fragment Preview".bold());
            println!("{}", "=".repeat(50));
            println!("  TCC/PPPC profiles: {}", policies.len().to_string().bold());
        }
        return Ok(());
    }

    let layout = FleetLayout::default();

    // Create directory structure
    let profiles_dir = output_dir.join(layout.macos_profiles_subdir);
    let fleets_dir = output_dir.join(layout.fleets_dir);
    std::fs::create_dir_all(&profiles_dir)?;
    std::fs::create_dir_all(&fleets_dir)?;

    let mut profile_entries: Vec<ProfileEntry> = Vec::new();
    let mut lib_files: Vec<String> = Vec::new();
    let mut profiles_written = 0;

    // Generate TCC/PPPC profiles (per-app)
    for policy in &policies {
        let filename = format!("{}-pppc.mobileconfig", sanitize_filename(&policy.app.name));
        let output_path = profiles_dir.join(&filename);

        let display_name = Some(format!("{} PPPC", policy.app.name));
        let suffix = sanitize_id(&policy.app.bundle_id);
        let content = generate_pppc_profile(
            std::slice::from_ref(policy),
            &config.config.org,
            display_name.as_deref(),
            Some(&suffix),
        )?;

        std::fs::write(&output_path, &content)
            .with_context(|| format!("Failed to write profile to {}", output_path.display()))?;

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

    // Generate fleets/reference-team.yml
    {
        let mut content = String::from(
            "# Fleet GitOps - Team Configuration: PPPC/TCC\n\
             #\n\
             # Privacy permission profiles for MDM deployment.\n\
             #\n\
             # Generated by Contour CLI (pppc fragment mode)\n\
             \n\
             name: pppc-reference\n\
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
                name: "pppc-profiles".to_string(),
                version: "1.0.0".to_string(),
                description: format!("PPPC/TCC profiles for {} applications", config.apps.len()),
                generator: "contour-pppc".to_string(),
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
