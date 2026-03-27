use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use santa::cli::{CelAction, Cli, Commands, FaaAction, RingsCommands};
use santa::output::OutputMode;

/// Resolve org: if the user left the default "com.example", try .contour/config.toml.
fn resolve_org(org: String) -> String {
    if org != "com.example" {
        return org;
    }
    contour_core::config::ContourConfig::load_nearest()
        .map(|c| c.organization.domain)
        .unwrap_or(org)
}

fn resolve_org_opt(org: Option<String>) -> Option<String> {
    if org.is_some() {
        return org;
    }
    contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.domain)
}

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up logging based on flags
    let filter = if cli.json {
        "error"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .without_time()
        .init();

    let output_mode = if cli.json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    match cli.command {
        Commands::Generate {
            inputs,
            output,
            org,
            identifier,
            display_name,
            deterministic_uuids,
            format,
            dry_run,
            fragment,
        } => {
            let org = resolve_org(org);
            santa::cli::generate::run(
                &inputs,
                output.as_deref(),
                &org,
                identifier.as_deref(),
                display_name.as_deref(),
                deterministic_uuids,
                format,
                dry_run,
                fragment,
                output_mode,
            )
        }

        Commands::Validate {
            inputs,
            strict,
            warn_groups,
        } => santa::cli::validate::run_with_config(
            &inputs,
            santa::cli::validate::ValidateConfig {
                strict,
                warn_missing_groups: warn_groups,
                ..Default::default()
            },
            output_mode,
        ),

        Commands::Merge {
            inputs,
            output,
            strategy,
            dry_run,
        } => santa::cli::merge::run(&inputs, output.as_deref(), strategy, dry_run, output_mode),

        Commands::Diff { file1, file2 } => santa::cli::diff::run(&file1, &file2, output_mode),

        Commands::Config {
            output,
            mode,
            sync_url,
            machine_owner_plist,
            block_usb,
            dry_run,
        } => santa::cli::config::run(
            output.as_deref(),
            mode,
            sync_url.as_deref(),
            machine_owner_plist.as_deref(),
            block_usb,
            dry_run,
            output_mode,
        ),

        Commands::Fetch { command } => santa::cli::fetch::run(command, output_mode),

        Commands::Rings { command } => match command {
            RingsCommands::Generate {
                inputs,
                output_dir,
                org,
                prefix,
                num_rings,
                max_rules,
                dry_run,
            } => {
                let org = resolve_org(org);
                santa::cli::rings::run(
                    &inputs,
                    output_dir.as_deref(),
                    &org,
                    &prefix,
                    num_rings,
                    max_rules,
                    dry_run,
                    output_mode,
                )
            }
            RingsCommands::Init { output, num_rings } => {
                santa::cli::rings::init_rings(&output, num_rings, output_mode)
            }
        },

        Commands::Completions { shell } => {
            santa::cli::completions::run(shell);
            Ok(())
        }

        Commands::Init {
            output,
            org,
            name,
            force,
        } => {
            let org = org.map(resolve_org);
            santa::cli::init::run(&output, org.as_deref(), name.as_deref(), force, output_mode)
        }

        Commands::Prep {
            output_dir,
            org,
            dry_run,
        } => {
            let org = resolve_org(org);
            santa::cli::prep::run(&output_dir, &org, dry_run, output_mode)
        }

        Commands::Fleet {
            inputs,
            output_dir,
            org,
            prefix,
            team,
            num_rings,
            dry_run,
            fragment,
        } => {
            let org = resolve_org(org);
            santa::cli::fleet::run(
                &inputs,
                output_dir.as_deref(),
                &org,
                &prefix,
                &team,
                num_rings,
                dry_run,
                output_mode,
                fragment,
            )
        }

        Commands::Add {
            file,
            teamid,
            binary,
            certificate,
            signingid,
            cdhash,
            policy,
            description,
            group,
            regenerate,
            org,
            interactive,
        } => {
            // Determine rule type and identifier
            let (rule_type, identifier) = if let Some(id) = teamid {
                (santa::models::RuleType::TeamId, id)
            } else if let Some(id) = binary {
                (santa::models::RuleType::Binary, id)
            } else if let Some(id) = certificate {
                (santa::models::RuleType::Certificate, id)
            } else if let Some(id) = signingid {
                (santa::models::RuleType::SigningId, id)
            } else if let Some(id) = cdhash {
                (santa::models::RuleType::Cdhash, id)
            } else if interactive {
                (santa::models::RuleType::TeamId, String::new())
            } else {
                anyhow::bail!(
                    "Must specify one of: --teamid, --binary, --certificate, --signingid, --cdhash (or use --interactive)"
                );
            };

            let org = resolve_org_opt(org);
            santa::cli::add::run(
                &file,
                &identifier,
                rule_type,
                policy,
                description.as_deref(),
                group.as_deref(),
                regenerate.as_deref(),
                org.as_deref(),
                output_mode,
                interactive,
            )
        }

        Commands::Remove {
            file,
            identifier,
            rule_type,
            dry_run,
        } => santa::cli::remove::run(
            &file,
            &identifier,
            rule_type.as_deref(),
            dry_run,
            output_mode,
        ),

        Commands::Filter {
            inputs,
            output,
            rule_type,
            policy,
            group,
            ring,
            has_description,
            identifier_contains,
            description_contains,
        } => santa::cli::filter::run(
            &inputs,
            output.as_deref(),
            rule_type,
            policy,
            group.as_deref(),
            ring.as_deref(),
            has_description,
            identifier_contains.as_deref(),
            description_contains.as_deref(),
            output_mode,
        ),

        Commands::Stats { inputs } => santa::cli::stats::run(&inputs, output_mode),

        Commands::Discover {
            input,
            output,
            threshold,
            min_apps,
            interactive,
        } => santa::cli::discover::run(
            &input,
            output.as_deref(),
            threshold,
            min_apps,
            interactive,
            cli.json,
        ),

        Commands::Classify {
            input,
            bundles,
            output,
            orphan_policy,
            conflict_policy,
        } => santa::cli::classify::run(
            &input,
            &bundles,
            output.as_deref(),
            orphan_policy,
            conflict_policy,
            cli.json,
            cli.verbose,
        ),

        Commands::Pipeline {
            input,
            bundles,
            output_dir,
            org,
            dedup_level,
            rule_type,
            orphan_policy,
            conflict_policy,
            deterministic,
            layer_stage,
            stages,
            dry_run,
        } => {
            let org = resolve_org(org);
            santa::cli::pipeline_cmd::run(
                &input,
                &bundles,
                output_dir.as_deref(),
                &org,
                dedup_level,
                rule_type,
                orphan_policy,
                conflict_policy,
                deterministic,
                layer_stage,
                stages,
                dry_run,
                cli.json,
                cli.verbose,
            )
        }

        Commands::Scan {
            path,
            output,
            output_format,
            include_unsigned,
            org,
            rule_type,
            merge,
        } => {
            let org = resolve_org(org);
            if let Some(inputs) = merge {
                // For merge, use the output path directly or default to local-apps.csv
                let merge_output =
                    output.unwrap_or_else(|| std::path::PathBuf::from("local-apps.csv"));
                santa::cli::scan::merge_scans(&inputs, &merge_output)
            } else {
                santa::cli::scan::run(
                    &path,
                    output.as_deref(),
                    output_format,
                    include_unsigned,
                    &org,
                    rule_type,
                    cli.verbose,
                    cli.json,
                )
            }
        }

        Commands::Allow {
            input,
            output,
            rule_type,
            org,
            name,
            no_deterministic_uuids,
            dry_run,
        } => {
            let org = resolve_org(org);
            santa::cli::allow_cmd::run(
                &input,
                output.as_deref(),
                rule_type,
                &org,
                name.as_deref(),
                !no_deterministic_uuids,
                dry_run,
                cli.json,
            )
        }

        Commands::Select {
            input,
            output,
            rule_type,
            org,
        } => {
            let org = resolve_org(org);
            santa::cli::select::run(&input, output.as_deref(), &rule_type, &org, cli.json)
        }

        Commands::Snip {
            source,
            dest,
            identifier,
            rule_type,
            policy,
            group,
            dry_run,
        } => santa::cli::snip::run(
            &source,
            &dest,
            identifier.as_deref(),
            rule_type,
            policy,
            group.as_deref(),
            dry_run,
            output_mode,
        ),

        Commands::Cel { action } => match action {
            CelAction::Fields => santa::cli::cel_cmd::handle_cel_fields(output_mode),
            CelAction::Check { expression, v2 } => {
                santa::cli::cel_cmd::handle_cel_check(&expression, v2, output_mode)
            }
            CelAction::Eval { expression, fields } => {
                santa::cli::cel_cmd::handle_cel_evaluate(&expression, &fields, output_mode)
            }
            CelAction::Classify { bundles, input } => {
                santa::cli::cel_cmd::handle_cel_classify(&bundles, &input, output_mode)
            }
            CelAction::Compile {
                conditions,
                logic,
                result,
                else_result,
            } => santa::cli::cel_cmd::handle_cel_compile(
                &conditions,
                &logic,
                &result,
                &else_result,
                output_mode,
            ),
            CelAction::DryRun { input } => {
                santa::cli::cel_cmd::handle_cel_dry_run(&input, output_mode)
            }
        },

        Commands::Faa { action } => match action {
            FaaAction::Generate { input, output } => {
                santa::cli::faa_cmd::handle_faa_generate(&input, output.as_deref(), output_mode)
            }
            FaaAction::Validate { input } => {
                santa::cli::faa_cmd::handle_faa_validate(&input, output_mode)
            }
            FaaAction::Schema => santa::cli::faa_cmd::handle_faa_schema(output_mode),
        },
    }
}
