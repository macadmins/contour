//! mSCP CLI - Transform mSCP baselines into MDM-ready configurations.
//!
//! mscp is a command-line tool that processes macOS Security Compliance Project (mSCP)
//! baseline outputs and transforms them into configurations ready for deployment
//! via Fleet, Jamf Pro, or Munki.

// Microsoft Rust Guidelines: M-MIMALLOC-APPS - Use mimalloc as global allocator
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod api;
mod cli;
mod config;
mod deduplicator;
mod extractors;
mod filters;
mod generators;
mod managers;
mod models;
mod output;
mod transformers;
mod updaters;
mod validators;
mod versioning;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, ConstraintsAction, OdvAction, SchemaAction};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging (suppress in JSON mode for clean output)
    let log_level = if cli.json {
        tracing::Level::ERROR // Only show errors in JSON mode
    } else if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Execute command
    match cli.command {
        Commands::Info { config } => {
            let output_mode = if cli.json {
                output::OutputMode::Json
            } else {
                output::OutputMode::Human
            };
            cli::info_command(&config, output_mode)?;
        }

        Commands::Init {
            output,
            org,
            name,
            force,
            fleet,
            jamf,
            munki,
            sync,
            branch,
            baselines,
        } => {
            cli::init_project(
                &output, org, name, force, fleet, jamf, munki, sync, &branch, baselines, cli.json,
            )?;
        }

        Commands::Process {
            input,
            output,
            baseline,
            mscp_repo,
            jamf_mode,
            deterministic_uuids,
            no_creation_date,
            identical_payload_uuid,
            org,
            org_name,
            remove_consent_text,
            consent_text,
            description_format,
            no_labels,
            fleet_mode,
            jamf_exclude_conflicts,
            munki_compliance_flags,
            munki_compliance_path,
            munki_flag_prefix,
            munki_script_nopkg,
            munki_script_catalog,
            munki_script_category,
            munki_script_separate_postinstall,
            exclude,
            dry_run,
            script_mode,
            fragment,
        } => {
            // Resolve org from CLI flags, falling back to .contour/config.toml
            let org = resolve_org(org);
            let org_name = resolve_org_name(org_name);
            let deterministic_uuids = resolve_deterministic_uuids(deterministic_uuids);

            // Build ProfileOptions when any general profile option is set
            let profile_options = if org_name.is_some()
                || remove_consent_text
                || consent_text.is_some()
                || deterministic_uuids
            {
                Some(transformers::ProfileOptions {
                    org_name: org_name.clone(),
                    remove_consent_text,
                    consent_text: consent_text.clone(),
                    deterministic_uuids,
                })
            } else {
                None
            };

            // Only create JamfOptions when Jamf-specific flags are used.
            // --org/--org-name are shared with Fleet mode and should NOT
            // trigger Jamf mode on their own.
            // --deterministic-uuids is a general profile option (base layer).
            let has_jamf_flags = jamf_mode
                || no_creation_date
                || identical_payload_uuid
                || description_format.is_some();
            let jamf_options = if has_jamf_flags {
                Some(transformers::JamfOptions {
                    no_creation_date,
                    identical_payload_uuid,
                    baseline: Some(baseline.clone()),
                    domain: org,
                    org_name,
                    description_format,
                })
            } else {
                None
            };
            let munki_compliance_options = if munki_compliance_flags {
                Some(transformers::MunkiComplianceOptions {
                    target_path: std::path::PathBuf::from(munki_compliance_path),
                    flag_prefix: munki_flag_prefix,
                })
            } else {
                None
            };
            let munki_script_options = if munki_script_nopkg {
                Some(transformers::MunkiScriptOptions {
                    catalog: munki_script_catalog,
                    category: munki_script_category,
                    display_name_prefix: "mSCP".to_string(),
                    embed_fix_in_installcheck: !munki_script_separate_postinstall,
                })
            } else {
                None
            };
            // Determine output mode
            let output_mode = if cli.json {
                output::OutputMode::Json
            } else {
                output::OutputMode::Human
            };

            cli::process_baseline(
                input,
                output,
                baseline,
                mscp_repo,
                profile_options,
                jamf_options,
                munki_compliance_options,
                munki_script_options,
                no_labels,
                fleet_mode,
                jamf_exclude_conflicts,
                dry_run,
                output_mode,
                script_mode.into(),
                exclude,
                fragment,
                crate::config::OutputStructure::default(),
            )?;
        }

        Commands::Generate {
            config: config_path,
            mscp_repo,
            branch,
            baseline,
            output,
            use_uv,
            use_python3,
            use_container,
            container_image: _container_image, // TODO: Support custom container image
            jamf_mode,
            deterministic_uuids,
            no_creation_date,
            identical_payload_uuid,
            org,
            org_name,
            remove_consent_text,
            consent_text,
            description_format,
            generate_ddm,
            no_labels,
            teams,
            fleet_mode,
            jamf_exclude_conflicts,
            munki_compliance_flags,
            munki_compliance_path,
            munki_flag_prefix,
            munki_script_nopkg,
            munki_script_catalog,
            munki_script_category,
            munki_script_separate_postinstall,
            odv: _odv, // TODO: Pass ODV to generate_baseline for full substitution support
            exclude,
            dry_run,
            script_mode,
            fragment,
        } => {
            let python_method = if use_container {
                Some(cli::generate::PythonMethod::Container)
            } else if use_uv {
                Some(cli::generate::PythonMethod::Uv)
            } else if use_python3 {
                Some(cli::generate::PythonMethod::Python3)
            } else {
                None // Auto-detect
            };

            // Determine output mode
            let output_mode = if cli.json {
                output::OutputMode::Json
            } else {
                output::OutputMode::Human
            };

            // Config-driven generation: load mscp.toml, derive options for this baseline.
            if let Some(config_file) = config_path {
                let loaded_config = config::load_config(&config_file)?;

                // Find the requested baseline in the config (CLI --baseline selects which one)
                let baseline_config = loaded_config
                    .baselines
                    .iter()
                    .find(|b| b.name == baseline)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "baseline '{}' not found in {}; enabled baselines: {}",
                            baseline,
                            config_file.display(),
                            loaded_config
                                .baselines
                                .iter()
                                .map(|b| b.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })?;

                let opts = cli::config_generate::build_options_from_config(
                    &loaded_config,
                    baseline_config,
                );

                // Switch branch if specified in config for this baseline
                if let Some(ref target_branch) = baseline_config.branch {
                    cli::generate::switch_branch(&mscp_repo, target_branch)?;
                } else if let Some(ref target_branch) = branch {
                    cli::generate::switch_branch(&mscp_repo, target_branch)?;
                }

                cli::generate_baseline(
                    mscp_repo,
                    baseline,
                    output,
                    python_method,
                    opts.profile_options,
                    opts.jamf_options,
                    opts.munki_compliance_options,
                    opts.munki_script_options,
                    opts.no_labels,
                    opts.team_names,
                    opts.fleet_mode,
                    opts.jamf_exclude_conflicts,
                    opts.generate_ddm,
                    dry_run,
                    output_mode,
                    false, // batch_mode = false for single baseline
                    script_mode.into(),
                    exclude,
                    fragment,
                    opts.structure,
                )?;
                return Ok(());
            }

            // CLI-flag-driven generation (existing behavior when no --config)
            // Resolve org from CLI flags, falling back to .contour/config.toml
            let org = resolve_org(org);
            let org_name = resolve_org_name(org_name);
            let deterministic_uuids = resolve_deterministic_uuids(deterministic_uuids);

            // Build ProfileOptions when any general profile option is set
            let profile_options = if org_name.is_some()
                || remove_consent_text
                || consent_text.is_some()
                || deterministic_uuids
            {
                Some(transformers::ProfileOptions {
                    org_name: org_name.clone(),
                    remove_consent_text,
                    consent_text: consent_text.clone(),
                    deterministic_uuids,
                })
            } else {
                None
            };

            // Only create JamfOptions when Jamf-specific flags are used.
            // --org/--org-name are shared with Fleet mode and should NOT
            // trigger Jamf mode on their own.
            // --deterministic-uuids is a general profile option (base layer).
            let has_jamf_flags = jamf_mode
                || no_creation_date
                || identical_payload_uuid
                || description_format.is_some();
            let jamf_options = if has_jamf_flags {
                Some(transformers::JamfOptions {
                    no_creation_date,
                    identical_payload_uuid,
                    baseline: Some(baseline.clone()),
                    domain: org,
                    org_name,
                    description_format,
                })
            } else {
                None
            };
            let munki_compliance_options = if munki_compliance_flags {
                Some(transformers::MunkiComplianceOptions {
                    target_path: std::path::PathBuf::from(munki_compliance_path),
                    flag_prefix: munki_flag_prefix,
                })
            } else {
                None
            };
            let munki_script_options = if munki_script_nopkg {
                Some(transformers::MunkiScriptOptions {
                    catalog: munki_script_catalog,
                    category: munki_script_category,
                    display_name_prefix: "mSCP".to_string(),
                    embed_fix_in_installcheck: !munki_script_separate_postinstall,
                })
            } else {
                None
            };
            // Switch branch if specified
            if let Some(target_branch) = branch {
                cli::generate::switch_branch(&mscp_repo, &target_branch)?;
            }

            cli::generate_baseline(
                mscp_repo,
                baseline,
                output,
                python_method,
                profile_options,
                jamf_options,
                munki_compliance_options,
                munki_script_options,
                no_labels,
                teams,
                fleet_mode,
                jamf_exclude_conflicts,
                generate_ddm,
                dry_run,
                output_mode,
                false, // batch_mode = false for single baseline
                script_mode.into(),
                exclude,
                fragment,
                crate::config::OutputStructure::default(),
            )?;
        }

        Commands::GenerateAll {
            config: config_path,
            mscp_repo,
            baselines,
            output,
            use_uv,
            use_python3,
            use_container,
            generate_ddm,
            jamf_mode,
            deterministic_uuids,
            no_creation_date,
            identical_payload_uuid,
            jamf_exclude_conflicts,
            fleet_mode,
            munki_compliance_flags,
            munki_script_nopkg,
            dry_run,
            no_parallel,
            script_mode,
            fragment,
        } => {
            if let Some(config_file) = config_path {
                // Config-based generation
                let config = config::load_config(&config_file)?;
                cli::generate_from_config(config)?;
            } else {
                // CLI-based generation (existing behavior)
                let mscp_repo = mscp_repo.ok_or_else(|| {
                    anyhow::anyhow!("--mscp-repo required when not using --config")
                })?;
                let baselines = baselines.ok_or_else(|| {
                    anyhow::anyhow!("--baselines required when not using --config")
                })?;
                let output = output
                    .ok_or_else(|| anyhow::anyhow!("--output required when not using --config"))?;

                let python_method = if use_container {
                    Some(cli::generate::PythonMethod::Container)
                } else if use_uv {
                    Some(cli::generate::PythonMethod::Uv)
                } else if use_python3 {
                    Some(cli::generate::PythonMethod::Python3)
                } else {
                    None // Auto-detect
                };

                // GenerateAll CLI mode has no org/consent flags — use deterministic_uuids only
                let profile_options = if deterministic_uuids {
                    Some(transformers::ProfileOptions {
                        deterministic_uuids,
                        ..Default::default()
                    })
                } else {
                    None
                };

                // Build options structures
                // Baseline is set per-baseline in generate_all_baselines loop
                let jamf_options = if jamf_mode || no_creation_date || identical_payload_uuid {
                    Some(transformers::JamfOptions {
                        no_creation_date,
                        identical_payload_uuid,
                        baseline: None, // Set per-baseline in generate loop
                        domain: None,   // Use --config for domain settings
                        org_name: None,
                        description_format: None,
                    })
                } else {
                    None
                };

                let munki_compliance_options = if munki_compliance_flags {
                    Some(transformers::MunkiComplianceOptions {
                        target_path: std::path::PathBuf::from(
                            transformers::munki_compliance::DEFAULT_COMPLIANCE_PLIST_PATH,
                        ),
                        flag_prefix: transformers::munki_compliance::DEFAULT_FLAG_PREFIX
                            .to_string(),
                    })
                } else {
                    None
                };

                let munki_script_options = if munki_script_nopkg {
                    Some(transformers::MunkiScriptOptions {
                        catalog: transformers::munki_compliance::DEFAULT_MUNKI_CATALOG.to_string(),
                        category: transformers::munki_compliance::DEFAULT_MUNKI_CATEGORY
                            .to_string(),
                        display_name_prefix: "mSCP".to_string(),
                        embed_fix_in_installcheck: true,
                    })
                } else {
                    None
                };

                // Determine output mode
                let output_mode = if cli.json {
                    output::OutputMode::Json
                } else {
                    output::OutputMode::Human
                };

                let parallel = !no_parallel;
                cli::generate_all_baselines(
                    mscp_repo,
                    baselines,
                    output,
                    python_method,
                    profile_options,
                    jamf_options,
                    munki_compliance_options,
                    munki_script_options,
                    fleet_mode,
                    jamf_exclude_conflicts,
                    generate_ddm,
                    dry_run,
                    parallel,
                    output_mode,
                    script_mode.into(),
                    fragment,
                    crate::config::OutputStructure::default(),
                )?;
            }
        }

        Commands::Diff {
            output,
            baseline,
            format,
        } => {
            let output_mode = if cli.json {
                output::OutputMode::Json
            } else {
                output::OutputMode::Human
            };
            cli::diff_versions(output, baseline, format.into(), output_mode)?;
        }

        Commands::Validate {
            output,
            schemas,
            strict,
        } => {
            let output_mode = if cli.json {
                output::OutputMode::Json
            } else {
                output::OutputMode::Human
            };
            cli::validate_output(output, schemas, strict, output_mode)?;
        }

        Commands::Deduplicate {
            output,
            baselines,
            platform,
            jamf_mode,
            dry_run,
        } => {
            let output_mode = if cli.json {
                output::OutputMode::Json
            } else {
                output::OutputMode::Human
            };
            cli::deduplicate_profiles(
                output,
                baselines,
                platform,
                jamf_mode,
                dry_run,
                output_mode,
            )?;
        }

        Commands::List { output } => {
            cli::list_baselines(output)?;
        }

        Commands::ListBaselines { mscp_repo } => {
            cli::list_available_baselines(mscp_repo)?;
        }

        Commands::ExtractScripts {
            mscp_repo,
            baseline,
            output,
            flat,
            dry_run,
            constraints,
            odv,
        } => {
            let output_mode = if cli.json {
                output::OutputMode::Json
            } else {
                output::OutputMode::Human
            };
            cli::extract_scripts(
                mscp_repo,
                baseline,
                output,
                flat,
                dry_run,
                output_mode,
                constraints,
                odv,
            )?;
        }

        Commands::Clean {
            baseline,
            output,
            force,
        } => {
            cli::clean_baseline(baseline, output, force)?;
        }

        Commands::Migrate {
            from,
            to,
            team,
            output,
            no_backup,
        } => {
            cli::migrate_team_file(from, to, team, output, !no_backup)?;
        }

        Commands::Verify { output, fix } => {
            cli::verify_references(output, fix)?;
        }

        Commands::Constraints { action } => {
            let output_mode = if cli.json {
                output::OutputMode::Json
            } else {
                output::OutputMode::Human
            };

            match action {
                ConstraintsAction::Add {
                    r#type,
                    constraints,
                    mscp_repo,
                    baseline,
                } => {
                    cli::constraints_add(r#type, constraints, mscp_repo, baseline, output_mode)?;
                }
                ConstraintsAction::Remove {
                    r#type,
                    constraints,
                    ..
                } => {
                    cli::constraints_remove(r#type, constraints, output_mode)?;
                }
                ConstraintsAction::List {
                    r#type,
                    constraints,
                    ..
                } => {
                    cli::constraints_list(r#type, constraints, output_mode)?;
                }
                ConstraintsAction::AddScript {
                    r#type,
                    constraints,
                    mscp_repo,
                    baseline,
                } => {
                    cli::constraints_add_script(
                        r#type,
                        constraints,
                        mscp_repo,
                        baseline,
                        output_mode,
                    )?;
                }
                ConstraintsAction::RemoveScript {
                    r#type,
                    constraints,
                    ..
                } => {
                    cli::constraints_remove_script(r#type, constraints, output_mode)?;
                }
                ConstraintsAction::ListScripts {
                    r#type,
                    constraints,
                    ..
                } => {
                    cli::constraints_list_scripts(r#type, constraints, output_mode)?;
                }
                ConstraintsAction::AddCategories {
                    r#type,
                    constraints,
                    mscp_repo,
                    baseline,
                    exclude,
                } => {
                    cli::constraints_add_categories(
                        r#type,
                        constraints,
                        mscp_repo,
                        baseline,
                        exclude,
                        output_mode,
                    )?;
                }
            }
        }

        Commands::Odv { action } => {
            let output_mode = if cli.json {
                output::OutputMode::Json
            } else {
                output::OutputMode::Human
            };

            match action {
                OdvAction::Init {
                    mscp_repo,
                    baseline,
                    output,
                } => {
                    cli::odv_init(mscp_repo, baseline, output, output_mode)?;
                }
                OdvAction::List {
                    mscp_repo,
                    baseline,
                    overrides,
                } => {
                    cli::odv_list(mscp_repo, baseline, overrides, output_mode)?;
                }
                OdvAction::Edit { overrides } => {
                    cli::odv_edit(overrides, output_mode)?;
                }
            }
        }

        Commands::Schema { action } => {
            let output_mode = if cli.json {
                output::OutputMode::Json
            } else {
                output::OutputMode::Human
            };

            match action {
                SchemaAction::Baselines => {
                    cli::handle_schema_baselines(output_mode)?;
                }
                SchemaAction::Rules { baseline, platform } => {
                    cli::handle_schema_rules(&baseline, &platform, output_mode)?;
                }
                SchemaAction::Stats => {
                    cli::handle_schema_stats(output_mode)?;
                }
                SchemaAction::Compare {
                    mscp_repo,
                    baseline,
                    platform,
                } => {
                    cli::handle_schema_compare(&mscp_repo, &baseline, &platform, output_mode)?;
                }
                SchemaAction::Search { query, platform } => {
                    cli::handle_schema_search(&query, platform.as_deref(), output_mode)?;
                }
                SchemaAction::Rule { rule_id } => {
                    cli::handle_schema_rule(&rule_id, output_mode)?;
                }
            }
        }

        Commands::Container { action } => {
            use cli::ContainerAction;

            match action {
                ContainerAction::Init {
                    mscp_repo,
                    branch,
                    tag,
                    no_build,
                    docker,
                } => {
                    cli::generate::container_init(&mscp_repo, &branch, &tag, no_build, docker)?;
                }
                ContainerAction::Pull { image } => {
                    cli::generate::pull_mscp_container(image.as_deref())?;
                }
                ContainerAction::Status => {
                    cli::generate::container_status()?;
                }
                ContainerAction::Test { image } => {
                    cli::generate::test_container(image.as_deref())?;
                }
            }
        }
    }

    Ok(())
}

/// Resolve org domain from CLI flag, falling back to .contour/config.toml.
fn resolve_org(org: Option<String>) -> Option<String> {
    if org.is_some() {
        return org;
    }
    contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.domain)
}

/// Resolve org display name from CLI flag, falling back to .contour/config.toml.
fn resolve_org_name(org_name: Option<String>) -> Option<String> {
    if org_name.is_some() {
        return org_name;
    }
    contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.name)
}

/// Resolve deterministic_uuids from CLI flag, falling back to .contour/config.toml.
fn resolve_deterministic_uuids(cli_flag: bool) -> bool {
    if cli_flag {
        return true;
    }
    contour_core::config::ContourConfig::load_nearest()
        .and_then(|c| c.defaults.deterministic_uuids)
        .unwrap_or(false)
}
