//! Support generate command — generate Support App mobileconfig profiles.
//!
//! Default: per-brand profiles and plist files.
//! With --fragment: generates a Fleet fragment directory.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use contour_core::fragment::{
    DefaultYmlEntries, FleetEntries, FragmentManifest, FragmentMeta, LibFiles, ProfileEntry,
    ScriptEntries,
};
use contour_core::{FleetLayout, OutputMode, print_info, print_kv, print_success};
use serde::Serialize;

use crate::config::SupportConfig;
use crate::generator;

#[derive(Serialize)]
struct DryRunOutput {
    brands: Vec<DryRunBrand>,
    total_files: usize,
}

#[derive(Serialize)]
struct DryRunBrand {
    name: String,
    files: Vec<String>,
}

/// Run the `support generate` command: read config and produce profile files.
pub fn run(
    config_path: &Path,
    output_dir: Option<&Path>,
    dry_run: bool,
    brand_filter: Option<&str>,
    fragment: bool,
    output_mode: OutputMode,
) -> Result<()> {
    // Delegate to Fleet fragment generation if requested
    if fragment {
        return run_fragment(config_path, output_dir, dry_run, brand_filter, output_mode);
    }

    let config = SupportConfig::load(config_path)?;

    // Default output directory is the same directory as the config file
    let out_dir = output_dir.map(Path::to_path_buf).unwrap_or_else(|| {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });

    let results = generator::generate_all(&config, brand_filter)?;

    if dry_run {
        if output_mode == OutputMode::Json {
            let brands: Vec<DryRunBrand> = results
                .iter()
                .map(|r| DryRunBrand {
                    name: r.name.clone(),
                    files: vec![
                        r.discover_filename.clone(),
                        r.default_filename.clone(),
                        r.raw_plist_filename.clone(),
                    ],
                })
                .collect();
            contour_core::print_json(&DryRunOutput {
                total_files: brands.len() * 3,
                brands,
            })?;
        } else {
            print_info("Dry run — files that would be generated:");
            println!();
            for result in &results {
                print_kv(&result.name, &result.discover_filename);
                print_kv("", &result.default_filename);
                print_kv("", &result.raw_plist_filename);
            }
            println!();
            print_info(&format!(
                "{} brands, {} files total",
                results.len(),
                results.len() * 3
            ));
        }
        return Ok(());
    }

    // Create output directory if needed
    std::fs::create_dir_all(&out_dir)?;

    let mut file_count = 0;
    for result in &results {
        let discover_path = out_dir.join(&result.discover_filename);
        let default_path = out_dir.join(&result.default_filename);
        let plist_path = out_dir.join(&result.raw_plist_filename);

        std::fs::write(&discover_path, &result.discover_profile)?;
        std::fs::write(&default_path, &result.default_profile)?;
        std::fs::write(&plist_path, &result.raw_plist)?;

        if output_mode == OutputMode::Human {
            print_success(&format!("{} (3 files)", result.name));
        }

        file_count += 3;
    }

    if output_mode == OutputMode::Human {
        println!();
        print_success(&format!(
            "Generated {} files for {} brands in {}",
            file_count,
            results.len(),
            out_dir.display(),
        ));
    }

    Ok(())
}

/// Generate a Fleet fragment directory for Support App profiles.
///
/// Produces:
/// - `platforms/macos/configuration-profiles/` with mobileconfig and plist files
/// - `fleets/reference-team.yml` with profile entries
/// - `fragment.toml` manifest for merge
fn run_fragment(
    config_path: &Path,
    output: Option<&Path>,
    dry_run: bool,
    brand_filter: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        print_info(&format!(
            "Loading support config from {}...",
            config_path.display()
        ));
    }

    let config = SupportConfig::load(config_path)?;
    let results = generator::generate_all(&config, brand_filter)?;

    if results.is_empty() {
        if output_mode == OutputMode::Human {
            print_info("No brands to generate for fragment");
        }
        return Ok(());
    }

    let layout = FleetLayout::default();

    // Determine output directory
    let output_dir = output.map_or_else(|| PathBuf::from("support-fragment"), Path::to_path_buf);

    if output_mode == OutputMode::Human {
        print_kv("Brands", &results.len().to_string());
        print_kv("Mode", "fragment");
        print_kv("Output directory", &output_dir.display().to_string());
    }

    if dry_run {
        if output_mode == OutputMode::Human {
            print_info("Dry run - no files will be written");
            println!();
            println!("{}", "Fragment Preview".bold());
            println!("{}", "=".repeat(50));
            println!("  Brands: {}", results.len().to_string().bold());
            println!("  Files per brand: {}", "3".bold());
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
    let mut files_written = 0;

    for result in &results {
        // Write discover mobileconfig
        let discover_path = profiles_dir.join(&result.discover_filename);
        std::fs::write(&discover_path, &result.discover_profile)
            .with_context(|| format!("Failed to write profile to {}", discover_path.display()))?;

        // Write default mobileconfig
        let default_path = profiles_dir.join(&result.default_filename);
        std::fs::write(&default_path, &result.default_profile)
            .with_context(|| format!("Failed to write profile to {}", default_path.display()))?;

        // Write raw plist
        let plist_path = profiles_dir.join(&result.raw_plist_filename);
        std::fs::write(&plist_path, &result.raw_plist)
            .with_context(|| format!("Failed to write plist to {}", plist_path.display()))?;

        // Track files for fragment manifest
        for filename in [
            &result.discover_filename,
            &result.default_filename,
            &result.raw_plist_filename,
        ] {
            let relative_path = format!("{}/{filename}", layout.macos_profiles_subdir);
            let team_relative_path = format!("../{}/{filename}", layout.macos_profiles_subdir);

            lib_files.push(relative_path);

            // Only add mobileconfig files as profile entries (not raw plists)
            if filename.ends_with(".mobileconfig") {
                profile_entries.push(ProfileEntry {
                    path: team_relative_path,
                    labels_include_any: None,
                    labels_include_all: None,
                    labels_exclude_any: None,
                });
            }
        }

        files_written += 3;
    }

    // Generate fleets/reference-team.yml
    {
        let mut content = String::from(
            "# Fleet GitOps - Team Configuration: Support App\n\
             #\n\
             # Root3 Support App profiles for MDM deployment.\n\
             #\n\
             # Generated by Contour CLI (support fragment mode)\n\
             \n\
             name: support-reference\n\
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
                name: "support-profiles".to_string(),
                version: "1.0.0".to_string(),
                description: format!("Root3 Support App profiles for {} brands", results.len()),
                generator: "contour-support".to_string(),
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
            "Generated fragment with {} files for {} brands in {}",
            files_written,
            results.len(),
            output_dir.display()
        ));
        print_kv("Fragment manifest", "fragment.toml");
        print_kv("Profiles", &profile_entries.len().to_string());
        print_kv("Total files", &files_written.to_string());

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
