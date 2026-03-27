use crate::generator::{GeneratorOptions, write_to_file};
use crate::models::{ProfileCategory, ProfileNaming, RingConfig, RuleCategory, RuleSet};
use crate::output::{CommandResult, OutputMode, print_info, print_json, print_kv, print_success};
use crate::parser::parse_files;
use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
struct RingsOutput {
    rings_count: usize,
    profiles_generated: usize,
    profiles: Vec<ProfileInfo>,
}

#[derive(Debug, Serialize)]
struct ProfileInfo {
    ring: String,
    category: String,
    filename: String,
    rules_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    part: Option<usize>,
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
    num_rings: u8,
    max_rules: Option<usize>,
    dry_run: bool,
    mode: OutputMode,
) -> Result<()> {
    // Parse all input files
    let all_rules = parse_files(inputs)?;

    // Set up ring configuration
    let ring_config = match num_rings {
        5 => RingConfig::standard_five_rings(),
        7 => RingConfig::standard_seven_rings(),
        n => {
            let mut config = RingConfig::new();
            for i in 0..n {
                config.add_ring(
                    crate::models::Ring::new(format!("ring{i}"), i)
                        .with_description(format!("Ring {}", i + 1)),
                );
            }
            config
        }
    };

    let naming = ProfileNaming::new(prefix);
    let output_dir = output_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("rings"));

    let mut profiles_info = Vec::new();
    let mut profiles_generated = 0;

    if mode == OutputMode::Human {
        print_info(&format!(
            "Generating {} ring profiles with prefix '{}'",
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

    for ring in ring_config.rings_by_priority() {
        // Filter rules for this ring
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

        // Generate profiles for each category
        for profile_cat in ProfileCategory::all() {
            // Map ProfileCategory to RuleCategory for filtering
            let rule_cat = match profile_cat {
                ProfileCategory::Software => RuleCategory::Software,
                ProfileCategory::Cel => RuleCategory::Cel,
                ProfileCategory::Faa => RuleCategory::Faa,
            };

            // Get rules for this category in this ring
            let category_rules = ring_rules.by_category(rule_cat);

            // Skip if no rules for this category
            if category_rules.is_empty() {
                continue;
            }

            // Determine if we need to split this profile
            let chunks: Vec<RuleSet> = if let Some(max) = max_rules {
                if category_rules.len() > max {
                    // Split into chunks
                    category_rules
                        .rules()
                        .chunks(max)
                        .map(|chunk| RuleSet::from_rules(chunk.to_vec()))
                        .collect()
                } else {
                    vec![category_rules]
                }
            } else {
                vec![category_rules]
            };

            let needs_split = chunks.len() > 1;

            for (idx, chunk_rules) in chunks.iter().enumerate() {
                let part = idx + 1;
                let (profile_name, identifier, filename) = if needs_split {
                    let name = naming.generate_split(ring.priority, *profile_cat, part);
                    let id =
                        naming.generate_identifier_split(org, ring.priority, *profile_cat, part);
                    let fname = format!("{}.mobileconfig", name);
                    (name, id, fname)
                } else {
                    let name = naming.generate(ring.priority, *profile_cat);
                    let id = naming.generate_identifier(org, ring.priority, *profile_cat);
                    let fname = format!("{}.mobileconfig", name);
                    (name, id, fname)
                };

                let filepath = output_dir.join(&filename);

                profiles_info.push(ProfileInfo {
                    ring: ring.name.clone(),
                    category: profile_cat.display_name().to_string(),
                    filename: filename.clone(),
                    rules_count: chunk_rules.len(),
                    part: if needs_split { Some(part) } else { None },
                });

                if !dry_run {
                    if !output_dir.exists() {
                        std::fs::create_dir_all(&output_dir)?;
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

                profiles_generated += 1;

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

    if mode == OutputMode::Human {
        if dry_run {
            print_info("Dry run - no files written");
        } else {
            print_success(&format!(
                "Generated {} profiles in {}",
                profiles_generated,
                output_dir.display()
            ));
        }
    } else {
        print_json(&CommandResult::success(RingsOutput {
            rings_count: ring_config.rings.len(),
            profiles_generated,
            profiles: profiles_info,
        }))?;
    }

    Ok(())
}

/// Initialize a ring configuration template
pub fn init_rings(output: &Path, num_rings: u8, mode: OutputMode) -> Result<()> {
    let config = match num_rings {
        5 => RingConfig::standard_five_rings(),
        7 => RingConfig::standard_seven_rings(),
        n => {
            let mut config = RingConfig::new();
            for i in 0..n {
                config.add_ring(
                    crate::models::Ring::new(format!("ring{i}"), i)
                        .with_description(format!("Ring {} - TODO: add description", i + 1))
                        .with_fleet_labels(vec![format!("ring:{i}")]),
                );
            }
            config
        }
    };

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
