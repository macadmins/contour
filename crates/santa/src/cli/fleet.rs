use crate::cli::rings_output::{EditionInfo, RingsOutput, collect_unknown_ring_warnings};
use crate::fleet::{FleetOutputConfig, generate_fleet_output};
use crate::models::{ProfileNaming, resolve_ring_config};
use crate::output::{
    CommandResult, OutputMode, print_info, print_json, print_kv, print_success, print_warning,
};
use crate::parser::parse_files;
use anyhow::Result;
use contour_core::fleet_layout::FleetLayout;
use std::path::{Path, PathBuf};

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
    num_rings: Option<u8>,
    rings_config_path: Option<&Path>,
    max_rules: Option<usize>,
    strict: bool,
    dry_run: bool,
    mode: OutputMode,
    fragment: bool,
) -> Result<()> {
    if fragment {
        return run_fragment(
            inputs,
            output_dir,
            org,
            prefix,
            team_name,
            num_rings,
            rings_config_path,
            max_rules,
            strict,
            dry_run,
            mode,
        );
    }

    let rules = parse_files(inputs)?;
    let ring_config = resolve_ring_config(num_rings, rings_config_path)?;

    let warnings = collect_unknown_ring_warnings(&rules, &ring_config);
    if strict && !warnings.is_empty() {
        for w in &warnings {
            print_warning(w);
        }
        anyhow::bail!(
            "{} rule(s) reference unknown ring names; refusing to continue under --strict",
            warnings.len()
        );
    }
    if mode == OutputMode::Human {
        for w in &warnings {
            print_warning(w);
        }
    }

    let output_dir = output_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("fleet-gitops"));

    let layout = FleetLayout::default();
    let config = FleetOutputConfig {
        org: org.to_string(),
        prefix: prefix.to_string(),
        fleet_name: team_name.to_string(),
        ring_config: ring_config.clone(),
        profiles_base_path: format!("{}/profiles", layout.platforms_dir),
        deterministic_uuids: true,
        max_rules,
    };

    if mode == OutputMode::Human {
        print_info(&format!(
            "Generating Fleet GitOps editions for {} rules",
            rules.len()
        ));
        print_kv("Organization", org);
        print_kv("Team", team_name);
        print_kv("Rings", &ring_config.rings.len().to_string());
    }

    if dry_run {
        if mode == OutputMode::Human {
            print_info("Dry run - no files will be written");
            print_kv("Output directory", &output_dir.display().to_string());
        } else {
            let payload = RingsOutput {
                rings_count: ring_config.rings.len(),
                editions: Vec::new(),
                manifest_path: None,
                fragment: false,
                dry_run: true,
            };
            print_json(&CommandResult::success(payload).with_warnings(warnings))?;
        }
        return Ok(());
    }

    std::fs::create_dir_all(&output_dir)?;

    let result = generate_fleet_output(&rules, &config, &output_dir)?;

    let editions = result
        .editions
        .iter()
        .map(|e| EditionInfo {
            ring: e.ring.clone(),
            category: e.category.clone(),
            filename: e.filename.clone(),
            rules_count: e.rules_count,
            part: e.part,
            fleet_labels: e.fleet_labels.clone(),
        })
        .collect::<Vec<_>>();

    if mode == OutputMode::Human {
        print_success(&format!(
            "Generated {} editions in {}",
            editions.len(),
            output_dir.display()
        ));
        print_kv("Manifest", &result.manifest_path);
        for edition in &editions {
            print_kv("  Edition", &edition.filename);
        }
    } else {
        let payload = RingsOutput {
            rings_count: ring_config.rings.len(),
            editions,
            manifest_path: Some(PathBuf::from(&result.manifest_path)),
            fragment: false,
            dry_run: false,
        };
        print_json(&CommandResult::success(payload).with_warnings(warnings))?;
    }

    Ok(())
}

/// Generate a Fleet fragment directory.
///
/// Produces:
/// - `lib/macos/configuration-profiles/` with mobileconfig files
/// - `lib/all/labels/` with ring label YAML files
/// - `default.yml` with labels section only
/// - `fleets/reference-fleet.yml` with profile entries using `../lib/` paths
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
    num_rings: Option<u8>,
    rings_config_path: Option<&Path>,
    max_rules: Option<usize>,
    strict: bool,
    dry_run: bool,
    mode: OutputMode,
) -> Result<()> {
    use crate::fleet::ring_to_fleet_labels;
    use crate::generator::{GeneratorOptions, generate};
    use crate::models::{ProfileCategory, RuleCategory};

    let rules = parse_files(inputs)?;
    let ring_config = resolve_ring_config(num_rings, rings_config_path)?;

    let warnings = collect_unknown_ring_warnings(&rules, &ring_config);
    if strict && !warnings.is_empty() {
        for w in &warnings {
            print_warning(w);
        }
        anyhow::bail!(
            "{} rule(s) reference unknown ring names; refusing to continue under --strict",
            warnings.len()
        );
    }
    if mode == OutputMode::Human {
        for w in &warnings {
            print_warning(w);
        }
    }

    let output_dir = output_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("fleet-fragment"));

    if mode == OutputMode::Human {
        print_info(&format!(
            "Generating Fleet fragment editions for {} rules",
            rules.len()
        ));
        print_kv("Organization", org);
        print_kv("Team", team_name);
        print_kv("Rings", &ring_config.rings.len().to_string());
        print_kv("Mode", "fragment");
    }

    if dry_run {
        if mode == OutputMode::Human {
            print_info("Dry run - no files will be written");
            print_kv("Output directory", &output_dir.display().to_string());
        } else {
            let payload = RingsOutput {
                rings_count: ring_config.rings.len(),
                editions: Vec::new(),
                manifest_path: None,
                fragment: true,
                dry_run: true,
            };
            print_json(&CommandResult::success(payload).with_warnings(warnings))?;
        }
        return Ok(());
    }

    let layout = FleetLayout::default();

    let profiles_dir = output_dir.join(layout.macos_profiles_subdir);
    let labels_dir = output_dir.join(layout.labels_dir);
    let fleets_dir = output_dir.join(layout.fleets_dir);
    std::fs::create_dir_all(&profiles_dir)?;
    std::fs::create_dir_all(&labels_dir)?;
    std::fs::create_dir_all(&fleets_dir)?;

    let naming = ProfileNaming::new(prefix);
    let mut editions = Vec::new();
    let mut profile_entries = Vec::new();
    let mut label_paths = Vec::new();
    let mut lib_files = Vec::new();

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

            let chunks = category_rules.split_into_chunks(max_rules);
            let needs_split = chunks.len() > 1;

            for (idx, chunk_rules) in chunks.iter().enumerate() {
                let part = idx + 1;
                let (profile_name, identifier, filename, display_name) = if needs_split {
                    let name = naming.generate_split(ring.priority, *profile_cat, part);
                    let id =
                        naming.generate_identifier_split(org, ring.priority, *profile_cat, part);
                    let fname = format!("{name}.mobileconfig");
                    let display = format!(
                        "{} - Ring {} (Part {})",
                        profile_cat.display_name(),
                        ring.priority + 1,
                        part
                    );
                    (name, id, fname, display)
                } else {
                    let name = naming.generate(ring.priority, *profile_cat);
                    let id = naming.generate_identifier(org, ring.priority, *profile_cat);
                    let fname = format!("{name}.mobileconfig");
                    let display = format!(
                        "{} - Ring {}",
                        profile_cat.display_name(),
                        ring.priority + 1
                    );
                    (name, id, fname, display)
                };

                let filepath = profiles_dir.join(&filename);

                let options = GeneratorOptions::new(org)
                    .with_identifier(&identifier)
                    .with_display_name(&display_name)
                    .with_deterministic_uuids(true);

                let content = generate(chunk_rules, &options)?;
                std::fs::write(&filepath, content)?;

                let relative_path = format!("{}/{filename}", layout.macos_profiles_subdir);
                let team_relative_path = format!("../{}/{filename}", layout.macos_profiles_subdir);

                lib_files.push(relative_path);

                let ring_labels = ring_to_fleet_labels(ring);
                profile_entries.push(contour_core::fragment::ProfileEntry {
                    path: team_relative_path,
                    labels_include_any: if ring_labels.is_empty() {
                        None
                    } else {
                        Some(ring_labels.clone())
                    },
                    labels_include_all: None,
                    labels_exclude_any: None,
                });

                editions.push(EditionInfo {
                    ring: ring.name.clone(),
                    category: profile_cat.display_name().to_string(),
                    filename: filename.clone(),
                    rules_count: chunk_rules.len(),
                    part: if needs_split { Some(part) } else { None },
                    fleet_labels: ring_labels,
                });

                let _ = profile_name;
            }
        }
    }

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

    let mut default_yml = String::from(
        "# Fleet GitOps - Fragment Configuration (labels only)\n\
         #\n\
         # This fragment provides label definitions to be merged into a target repo.\n\
         #\n\
         # Generated by Contour Santa - https://github.com/macadmins/contour\n\
         \n",
    );
    default_yml.push_str("labels:\n");
    for lp in &label_paths {
        default_yml.push_str(&format!("  - path: {lp}\n"));
    }
    default_yml.push_str("\nreports:\n\npolicies:\n");
    std::fs::write(output_dir.join("default.yml"), &default_yml)?;

    let team_slug = team_name.to_lowercase().replace(' ', "-");
    let mut fleet_yml = format!(
        "# Fleet GitOps - Fleet Configuration: {team_name}\n\
         #\n\
         # Santa rule editions organized by ring.\n\
         #\n\
         # Generated by Contour Santa (fragment mode)\n\
         \n\
         name: {team_slug}\n\
         controls:\n\
         \x20 macos_settings:\n\
         \x20   custom_settings:\n"
    );
    for entry in &profile_entries {
        fleet_yml.push_str(&format!("      - path: {}\n", entry.path));
        if let Some(ref labels) = entry.labels_include_any {
            fleet_yml.push_str("        labels_include_any:\n");
            for label in labels {
                fleet_yml.push_str(&format!("          - {label}\n"));
            }
        }
    }
    std::fs::write(fleets_dir.join("reference-fleet.yml"), &fleet_yml)?;

    let fragment_toml_path = output_dir.join("fragment.toml");
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
    manifest.save(&fragment_toml_path)?;

    if mode == OutputMode::Human {
        print_success(&format!(
            "Generated fragment with {} editions in {}",
            editions.len(),
            output_dir.display()
        ));
        print_kv("Fragment manifest", "fragment.toml");
        print_kv("Labels", &label_paths.len().to_string());
        print_kv("Editions", &editions.len().to_string());
    } else {
        let payload = RingsOutput {
            rings_count: ring_config.rings.len(),
            editions,
            manifest_path: Some(fragment_toml_path),
            fragment: true,
            dry_run: false,
        };
        print_json(&CommandResult::success(payload).with_warnings(warnings))?;
    }

    Ok(())
}
