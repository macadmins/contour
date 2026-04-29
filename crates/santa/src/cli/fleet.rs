use crate::fleet::{FleetOutputConfig, generate_fleet_output};
use crate::models::RingConfig;
use crate::output::{CommandResult, OutputMode, print_info, print_json, print_kv, print_success};
use crate::parser::parse_files;
use anyhow::Result;
use contour_core::fleet_layout::FleetLayout;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
struct FleetOutput {
    profiles_written: usize,
    manifest_path: String,
    profile_paths: Vec<String>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
pub fn run(
    inputs: &[impl AsRef<Path>],
    output_dir: Option<&Path>,
    org: &str,
    prefix: &str,
    team_name: &str,
    num_rings: u8,
    dry_run: bool,
    mode: OutputMode,
    fragment: bool,
) -> Result<()> {
    if fragment {
        return run_fragment(
            inputs, output_dir, org, prefix, team_name, num_rings, dry_run, mode,
        );
    }

    let rules = parse_files(inputs)?;

    let ring_config = match num_rings {
        5 => RingConfig::standard_five_rings(),
        7 => RingConfig::standard_seven_rings(),
        n => {
            let mut config = RingConfig::new();
            for i in 0..n {
                config.add_ring(
                    crate::models::Ring::new(format!("ring{i}"), i)
                        .with_description(format!("Ring {}", i + 1))
                        .with_fleet_labels(vec![format!("ring:{i}")]),
                );
            }
            config
        }
    };

    let output_dir = output_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("fleet-gitops"));

    let layout = FleetLayout::default();
    let config = FleetOutputConfig {
        org: org.to_string(),
        prefix: prefix.to_string(),
        team_name: team_name.to_string(),
        ring_config,
        profiles_base_path: format!("{}/profiles", layout.platforms_dir),
        deterministic_uuids: true,
    };

    if mode == OutputMode::Human {
        print_info(&format!(
            "Generating Fleet GitOps output for {} rules",
            rules.len()
        ));
        print_kv("Organization", org);
        print_kv("Team", team_name);
        print_kv("Rings", &num_rings.to_string());
    }

    if dry_run {
        if mode == OutputMode::Human {
            print_info("Dry run - no files will be written");
            print_kv("Output directory", &output_dir.display().to_string());
        } else {
            print_json(&CommandResult::success(serde_json::json!({
                "dry_run": true,
                "output_dir": output_dir.display().to_string(),
                "rules_count": rules.len()
            })))?;
        }
        return Ok(());
    }

    // Create output directory
    std::fs::create_dir_all(&output_dir)?;

    let result = generate_fleet_output(&rules, &config, &output_dir)?;

    if mode == OutputMode::Human {
        print_success(&format!(
            "Generated {} profiles in {}",
            result.profiles_written,
            output_dir.display()
        ));
        print_kv("Manifest", &result.manifest_path);
        for path in &result.profile_paths {
            print_kv("  Profile", path);
        }
    } else {
        print_json(&CommandResult::success(FleetOutput {
            profiles_written: result.profiles_written,
            manifest_path: result.manifest_path,
            profile_paths: result.profile_paths,
        }))?;
    }

    Ok(())
}

/// Generate a Fleet fragment directory.
///
/// Produces:
/// - `lib/macos/configuration-profiles/` with mobileconfig files
/// - `lib/all/labels/` with ring label YAML files
/// - `default.yml` with labels section only
/// - `fleets/reference-team.yml` with profile entries using `../lib/` paths
/// - `fragment.toml` manifest for merge
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
fn run_fragment(
    inputs: &[impl AsRef<Path>],
    output_dir: Option<&Path>,
    org: &str,
    prefix: &str,
    team_name: &str,
    num_rings: u8,
    dry_run: bool,
    mode: OutputMode,
) -> Result<()> {
    use crate::fleet::ring_to_fleet_labels;
    use crate::generator::{GeneratorOptions, generate};
    use crate::models::{ProfileCategory, ProfileNaming, Ring, RuleCategory};

    let rules = parse_files(inputs)?;

    let ring_config = match num_rings {
        5 => RingConfig::standard_five_rings(),
        7 => RingConfig::standard_seven_rings(),
        n => {
            let mut config = RingConfig::new();
            for i in 0..n {
                config.add_ring(
                    Ring::new(format!("ring{i}"), i)
                        .with_description(format!("Ring {}", i + 1))
                        .with_fleet_labels(vec![format!("ring:{i}")]),
                );
            }
            config
        }
    };

    let output_dir = output_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("fleet-fragment"));

    if mode == OutputMode::Human {
        print_info(&format!(
            "Generating Fleet fragment output for {} rules",
            rules.len()
        ));
        print_kv("Organization", org);
        print_kv("Team", team_name);
        print_kv("Rings", &num_rings.to_string());
        print_kv("Mode", "fragment");
    }

    if dry_run {
        if mode == OutputMode::Human {
            print_info("Dry run - no files will be written");
            print_kv("Output directory", &output_dir.display().to_string());
        } else {
            print_json(&CommandResult::success(serde_json::json!({
                "dry_run": true,
                "fragment": true,
                "output_dir": output_dir.display().to_string(),
                "rules_count": rules.len()
            })))?;
        }
        return Ok(());
    }

    let layout = FleetLayout::default();

    // Create directory structure
    let profiles_dir = output_dir.join(layout.macos_profiles_subdir);
    let labels_dir = output_dir.join(layout.labels_dir);
    let teams_dir = output_dir.join(layout.fleets_dir);
    std::fs::create_dir_all(&profiles_dir)?;
    std::fs::create_dir_all(&labels_dir)?;
    std::fs::create_dir_all(&teams_dir)?;

    let naming = ProfileNaming::new(prefix);
    let mut profile_paths = Vec::new();
    let mut profile_entries = Vec::new();
    let mut label_paths = Vec::new();
    let mut lib_files = Vec::new();

    // Generate profiles per ring per category
    for ring in ring_config.rings_by_priority() {
        let ring_rules = rules.by_ring(&ring.name);
        if ring_rules.is_empty() {
            continue;
        }

        for profile_cat in ProfileCategory::all() {
            let rule_cat = match profile_cat {
                ProfileCategory::Software => RuleCategory::Software,
                ProfileCategory::Cel => RuleCategory::Cel,
                ProfileCategory::Faa => RuleCategory::Faa,
            };

            let category_rules = ring_rules.by_category(rule_cat);
            if category_rules.is_empty() {
                continue;
            }

            let profile_name = naming.generate(ring.priority, *profile_cat);
            let identifier = naming.generate_identifier(org, ring.priority, *profile_cat);
            let filename = format!("{profile_name}.mobileconfig");
            let filepath = profiles_dir.join(&filename);

            let options = GeneratorOptions::new(org)
                .with_identifier(&identifier)
                .with_display_name(&format!(
                    "{} - Ring {}",
                    profile_cat.display_name(),
                    ring.priority + 1
                ))
                .with_deterministic_uuids(true);

            let content = generate(&category_rules, &options)?;
            std::fs::write(&filepath, content)?;

            let relative_path = format!("{}/{filename}", layout.macos_profiles_subdir);
            let team_relative_path = format!("../{}/{filename}", layout.macos_profiles_subdir);

            profile_paths.push(relative_path.clone());
            lib_files.push(relative_path);

            // Build profile entry with ring labels
            let ring_labels = ring_to_fleet_labels(ring);
            profile_entries.push(contour_core::fragment::ProfileEntry {
                path: team_relative_path,
                labels_include_any: if ring_labels.is_empty() {
                    None
                } else {
                    Some(ring_labels)
                },
                labels_include_all: None,
                labels_exclude_any: None,
            });
        }
    }

    // Generate ring label files
    for ring in ring_config.rings_by_priority() {
        let ring_labels = ring_to_fleet_labels(ring);
        for label in &ring_labels {
            let label_filename = format!("{prefix}-{}.labels.yml", label.replace(':', "-"));
            let label_path = labels_dir.join(&label_filename);

            let label_content = format!(
                "# Ring label: {label}\n\
                 #\n\
                 # Generated by Contour Santa (fragment mode)\n\
                 \n\
                 - name: {label}\n\
                 "
            );
            std::fs::write(&label_path, label_content)?;

            let relative = format!("./{}/{label_filename}", layout.labels_dir);
            label_paths.push(relative.clone());
            lib_files.push(format!("{}/{label_filename}", layout.labels_dir));
        }
    }

    // Generate fragment-style default.yml (labels only)
    {
        let mut content = String::from(
            "# Fleet GitOps - Fragment Configuration (labels only)\n\
             #\n\
             # This fragment provides label definitions to be merged into a target repo.\n\
             #\n\
             # Generated by Contour Santa - https://github.com/macadmins/contour\n\
             \n",
        );

        content.push_str("labels:\n");
        for lp in &label_paths {
            content.push_str(&format!("  - path: {lp}\n"));
        }

        content.push_str("\nreports:\n\npolicies:\n");

        std::fs::write(output_dir.join("default.yml"), &content)?
    };

    // Generate fleets/reference-team.yml
    {
        let team_slug = team_name.to_lowercase().replace(' ', "-");
        let mut content = format!(
            "# Fleet GitOps - Team Configuration: {team_name}\n\
             #\n\
             # Santa rule profiles organized by ring.\n\
             #\n\
             # Generated by Contour Santa (fragment mode)\n\
             \n\
             name: {team_slug}\n\
             controls:\n\
             \x20 macos_settings:\n\
             \x20   custom_settings:\n"
        );

        for entry in &profile_entries {
            content.push_str(&format!("      - path: {}\n", entry.path));
            if let Some(ref labels) = entry.labels_include_any {
                content.push_str("        labels_include_any:\n");
                for label in labels {
                    content.push_str(&format!("          - {label}\n"));
                }
            }
        }

        std::fs::write(teams_dir.join("reference-team.yml"), &content)?
    };

    // Generate fragment.toml
    {
        let manifest = contour_core::fragment::FragmentManifest {
            fragment: contour_core::fragment::FragmentMeta {
                name: format!("{prefix}-santa-rules"),
                version: "1.0.0".to_string(),
                description: format!("Santa rules for {team_name}"),
                generator: "contour-santa".to_string(),
            },
            default_yml: contour_core::fragment::DefaultYmlEntries {
                label_paths: label_paths.clone(),
                report_paths: Vec::new(),
                policy_paths: Vec::new(),
            },
            fleet_entries: contour_core::fragment::FleetEntries {
                profiles: profile_entries.clone(),
                reports: Vec::new(),
                policies: Vec::new(),
                software: Vec::new(),
            },
            lib_files: contour_core::fragment::LibFiles {
                copy: lib_files.clone(),
            },
            scripts: contour_core::fragment::ScriptEntries::default(),
        };

        manifest.save(&output_dir.join("fragment.toml"))?
    };

    if mode == OutputMode::Human {
        print_success(&format!(
            "Generated fragment with {} profiles in {}",
            profile_paths.len(),
            output_dir.display()
        ));
        print_kv("Fragment manifest", "fragment.toml");
        print_kv("Labels", &label_paths.len().to_string());
        print_kv("Profiles", &profile_paths.len().to_string());
    } else {
        print_json(&CommandResult::success(serde_json::json!({
            "fragment": true,
            "profiles_written": profile_paths.len(),
            "labels_written": label_paths.len(),
            "output_dir": output_dir.display().to_string(),
        })))?;
    }

    Ok(())
}
