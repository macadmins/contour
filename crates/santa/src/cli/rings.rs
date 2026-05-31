use crate::cli::rings_output::{
    EditionInfo, RingsOutput, apply_baseline_merge, collect_unknown_ring_warnings,
};
use crate::generator::{GeneratorOptions, write_to_file};
use crate::models::{
    ProfileCategory, ProfileNaming, RingConfig, RuleCategory, resolve_ring_config,
};
use crate::output::{
    CommandResult, OutputMode, print_info, print_json, print_kv, print_success, print_warning,
};
use crate::parser::parse_files;
use anyhow::Result;
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
    num_rings: Option<u8>,
    rings_config_path: Option<&Path>,
    baseline_path: Option<&Path>,
    max_rules: Option<usize>,
    strict: bool,
    dry_run: bool,
    mode: OutputMode,
) -> Result<()> {
    let input_rules = parse_files(inputs)?;
    let (all_rules, baseline_warnings) = apply_baseline_merge(input_rules, baseline_path)?;
    let ring_config = resolve_ring_config(num_rings, rings_config_path)?;

    let ring_warnings = collect_unknown_ring_warnings(&all_rules, &ring_config);
    if strict && !ring_warnings.is_empty() {
        for w in &ring_warnings {
            print_warning(w);
        }
        anyhow::bail!(
            "{} rule(s) reference unknown ring names; refusing to continue under --strict",
            ring_warnings.len()
        );
    }
    let mut warnings = baseline_warnings;
    warnings.extend(ring_warnings);
    if mode == OutputMode::Human {
        for w in &warnings {
            print_warning(w);
        }
    }

    let naming = ProfileNaming::new(prefix);
    let output_dir = output_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("rings"));

    let mut editions = Vec::new();

    if mode == OutputMode::Human {
        print_info(&format!(
            "Generating {} ring editions with prefix '{}'",
            ring_config.rings.len(),
            prefix
        ));
        print_info(&format!(
            "Total rules: {} software, {} CEL, {} FAA",
            all_rules.software_rules().len(),
            all_rules.cel_rules().len(),
            all_rules.faa_rules().len()
        ));
    }

    emit_ring_editions(
        &all_rules,
        &ring_config,
        &naming,
        org,
        max_rules,
        dry_run,
        &output_dir,
        mode,
        &mut editions,
    )?;

    if mode == OutputMode::Human {
        if dry_run {
            print_info("Dry run - no files written");
        } else {
            print_success(&format!(
                "Generated {} editions in {}",
                editions.len(),
                output_dir.display()
            ));
        }
    } else {
        let payload = RingsOutput {
            rings_count: ring_config.rings.len(),
            editions,
            manifest_path: None,
            fragment: false,
            dry_run,
        };
        print_json(&CommandResult::success(payload).with_warnings(warnings))?;
    }

    Ok(())
}

/// Walk the resolved ring config and emit one mobileconfig per
/// (ring × category × split-part). Shared by both the rings and fleet paths.
#[expect(clippy::too_many_arguments, reason = "internal helper")]
pub(crate) fn emit_ring_editions(
    all_rules: &crate::models::RuleSet,
    ring_config: &RingConfig,
    naming: &ProfileNaming,
    org: &str,
    max_rules: Option<usize>,
    dry_run: bool,
    output_dir: &Path,
    mode: OutputMode,
    editions: &mut Vec<EditionInfo>,
) -> Result<()> {
    for ring in ring_config.rings_by_priority() {
        let ring_rules = all_rules.by_ring(&ring.name);

        if ring_rules.is_empty() {
            if mode == OutputMode::Human {
                print_kv(
                    &format!("Ring {} ({})", ring.priority + 1, ring.name),
                    "no rules",
                );
            }
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
                let (profile_name, identifier, filename) = if needs_split {
                    let name = naming.generate_split(ring.priority, *profile_cat, part);
                    let id =
                        naming.generate_identifier_split(org, ring.priority, *profile_cat, part);
                    let fname = format!("{name}.mobileconfig");
                    (name, id, fname)
                } else {
                    let name = naming.generate(ring.priority, *profile_cat);
                    let id = naming.generate_identifier(org, ring.priority, *profile_cat);
                    let fname = format!("{name}.mobileconfig");
                    (name, id, fname)
                };

                let filepath = output_dir.join(&filename);

                editions.push(EditionInfo {
                    ring: ring.name.clone(),
                    category: profile_cat.display_name().to_string(),
                    filename: filename.clone(),
                    rules_count: chunk_rules.len(),
                    part: if needs_split { Some(part) } else { None },
                    fleet_labels: ring.fleet_labels.clone(),
                });

                if !dry_run {
                    if !output_dir.exists() {
                        std::fs::create_dir_all(output_dir)?;
                    }

                    let display_name = if needs_split {
                        format!(
                            "{} - Ring {} (Part {})",
                            profile_cat.display_name(),
                            ring.priority + 1,
                            part
                        )
                    } else {
                        format!(
                            "{} - Ring {}",
                            profile_cat.display_name(),
                            ring.priority + 1
                        )
                    };

                    let options = GeneratorOptions::new(org)
                        .with_identifier(&identifier)
                        .with_display_name(&display_name)
                        .with_deterministic_uuids(true);

                    write_to_file(chunk_rules, &options, &filepath)?;
                }

                if mode == OutputMode::Human {
                    let label = if needs_split {
                        format!(
                            "  {} part {} ({})",
                            profile_name,
                            part,
                            profile_cat.display_name()
                        )
                    } else {
                        format!("  {} ({})", profile_name, profile_cat.display_name())
                    };
                    print_kv(&label, &format!("{} rules", chunk_rules.len()));
                }
            }
        }
    }
    Ok(())
}

/// Initialize a ring configuration template
pub fn init_rings(output: &Path, num_rings: u8, mode: OutputMode) -> Result<()> {
    let config = RingConfig::from_num_rings(num_rings);

    let yaml = yaml_serde::to_string(&config)?;
    std::fs::write(output, &yaml)?;

    if mode == OutputMode::Human {
        print_success(&format!("Created ring configuration: {}", output.display()));
    } else {
        print_json(&CommandResult::success(serde_json::json!({
            "path": output.display().to_string(),
            "rings": num_rings
        })))?;
    }

    Ok(())
}
