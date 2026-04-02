//! Dispatch logic for the unified Contour CLI.
//!
//! This module routes commands to the appropriate handler functions
//! in each tool's library.

use anyhow::Result;
use std::fmt::Write as _;
use std::io::Write;
use tracing_subscriber::EnvFilter;

use crate::{Cli, Commands, TrainerTool};
use contour_core::trainer::workflows::{
    MscpWorkflow, PppcWorkflow, ProfileWorkflow, SantaWorkflow,
};
use contour_core::trainer::{TrainerContext, TrainerWorkflow};

/// Run the appropriate command handler based on CLI arguments.
pub fn run(cli: Cli) -> Result<()> {
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

    // Handle trainer mode first (doesn't consume other command fields)
    if let Commands::Trainer { ref tool } = cli.command {
        return dispatch_trainer(tool, &cli);
    }

    match cli.command {
        Commands::Trainer { .. } => unreachable!(), // Already handled above
        Commands::Profile { action } => dispatch_profile(action, cli.verbose, cli.json),
        Commands::Pppc {
            action,
            path,
            output,
            org,
            service,
            interactive,
            dry_run,
        } => dispatch_pppc(
            action,
            path,
            output,
            org,
            service,
            interactive,
            dry_run,
            cli.json,
        ),
        Commands::Support {
            action,
            output,
            org,
            dry_run,
        } => dispatch_support(action, output, org, dry_run, cli.json),
        Commands::Santa { action } => dispatch_santa(action, cli.verbose, cli.json),
        Commands::Mscp { action } => dispatch_mscp(action, cli.verbose, cli.json),
        Commands::Btm {
            action,
            mode,
            path,
            output,
            org,
            interactive,
            ddm,
            dry_run,
        } => dispatch_btm(
            action,
            mode,
            path,
            output,
            org,
            interactive,
            ddm,
            dry_run,
            cli.json,
        ),
        Commands::Notifications {
            action,
            path,
            output,
            org,
            interactive,
            combined,
            dry_run,
        } => dispatch_notifications(
            action,
            path,
            output,
            org,
            interactive,
            combined,
            dry_run,
            cli.json,
        ),
        Commands::Osquery { action } => crate::osquery::handle(action, cli.json),
        Commands::HelpAgents {
            command,
            section,
            sop,
            full,
        } => {
            use clap::CommandFactory;
            let cmd = Cli::command();
            let mut out = std::io::stdout();

            if let Some(tool) = sop {
                // SOP for a specific tool
                contour_core::help_agents::generate_sop(&tool, &mut out)?;
            } else if let Some(path) = command {
                // Single command detail
                contour_core::help_agents::generate_command(&cmd, &path, &mut out)?;
            } else if full || section.is_some() {
                // Full dump or section-filtered dump
                let sections = section.as_deref();
                let has = |name: &str| match sections {
                    None => true,
                    Some(s) => s.iter().any(|v| v.eq_ignore_ascii_case(name)),
                };
                if has("cli") {
                    contour_core::help_agents::generate_full(&cmd, &mut out)?;
                }
                write_llm_domain_reference(&mut out, &has)?;
            } else {
                // Default: agent guide + command index
                contour_core::help_agents::generate_index(&cmd, &mut out)?;
            }
            Ok(())
        }
        Commands::HelpJson { command } => {
            use clap::CommandFactory;
            let cmd = Cli::command();
            let mut out = std::io::stdout();
            contour_core::help_agents::generate_json(&cmd, command.as_deref(), &mut out)?;
            Ok(())
        }
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            contour_core::generate_completions(&mut Cli::command(), "contour", shell);
            Ok(())
        }
        Commands::Init {
            path,
            name,
            domain,
            server_url,
            platforms,
            deterministic_uuids,
            yes,
        } => crate::init::run(
            &path,
            name,
            domain,
            server_url,
            platforms,
            deterministic_uuids,
            yes,
            cli.json,
        ),
    }
}

/// Dispatch trainer mode based on the selected tool.
fn dispatch_trainer(tool: &TrainerTool, cli: &Cli) -> Result<()> {
    let ctx = TrainerContext::default()
        .with_verbose(cli.verbose)
        .with_json(cli.json);

    match tool {
        TrainerTool::Santa => {
            let workflow = SantaWorkflow::default_workflow();
            workflow.run(&ctx)
        }
        TrainerTool::Pppc => {
            let workflow = PppcWorkflow::default_workflow();
            workflow.run(&ctx)
        }
        TrainerTool::Mscp => {
            let workflow = MscpWorkflow::default_workflow();
            workflow.run(&ctx)
        }
        TrainerTool::Profile => {
            let workflow = ProfileWorkflow::default_workflow();
            workflow.run(&ctx)
        }
    }
}

/// Dispatch profile commands.
fn dispatch_profile(action: profile::cli::Commands, _verbose: bool, json: bool) -> Result<()> {
    use colored::Colorize;
    use profile::cli::{
        CommandAction, Commands, DdmAction, DocsAction, EnrollmentAction, PayloadAction,
    };
    use profile::output::OutputMode;

    let output_mode = if json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    // Load config (only show message in human mode)
    let config = profile::config::ProfileConfig::load()?;
    if config.is_some() && output_mode == OutputMode::Human {
        println!("{}", "✓ Using config from profile.toml".green());
    }

    match action {
        Commands::Info => {
            profile::cli::info::handle_info(config.as_ref(), output_mode)?;
        }
        Commands::Init {
            output,
            org,
            name,
            force,
        } => {
            profile::cli::init::handle_init(
                output.as_deref(),
                org.as_deref(),
                name.as_deref(),
                force,
                output_mode,
            )?;
        }
        Commands::Import {
            source,
            output,
            org,
            name,
            no_validate,
            no_uuid,
            max_depth,
            dry_run,
            all,
        } => {
            let validate = !no_validate;
            let regen_uuid = !no_uuid;
            profile::cli::import::handle_import(
                &source,
                output.as_deref(),
                org.as_deref(),
                name.as_deref(),
                config.as_ref(),
                validate,
                regen_uuid,
                max_depth,
                dry_run,
                all,
                output_mode,
            )?;
        }
        Commands::Normalize {
            paths,
            output,
            org,
            name,
            no_validate,
            no_uuid,
            recursive,
            max_depth,
            no_parallel,
            dry_run,
            pasteboard,
            report,
        } => {
            let parallel = !no_parallel;
            let validate = !no_validate;
            let regen_uuid = !no_uuid;
            if pasteboard {
                profile::cli::normalize::handle_normalize_pasteboard(
                    output.as_deref(),
                    org.as_deref(),
                    name.as_deref(),
                    config.as_ref(),
                    validate,
                    regen_uuid,
                    output_mode,
                )?;
            } else {
                profile::cli::normalize::handle_normalize(
                    &paths,
                    output.as_deref(),
                    org.as_deref(),
                    name.as_deref(),
                    config.as_ref(),
                    validate,
                    regen_uuid,
                    recursive,
                    max_depth,
                    parallel,
                    dry_run,
                    report.as_deref(),
                    output_mode,
                )?;
            }
        }
        Commands::Duplicate {
            source,
            name,
            output,
            org,
            predictable,
            dry_run,
        } => {
            profile::cli::duplicate::handle_duplicate(
                &source,
                name.as_deref(),
                output.as_deref(),
                org.as_deref(),
                predictable,
                dry_run,
                output_mode,
            )?;
        }
        Commands::Validate {
            paths,
            no_schema,
            schema_path,
            lookup,
            strict,
            recursive,
            max_depth,
            no_parallel,
            report,
            no_placeholders,
        } => {
            let schema = !no_schema;
            let parallel = !no_parallel;
            let allow_placeholders = !no_placeholders;
            profile::cli::validate::handle_validate(
                &paths,
                schema,
                schema_path.as_deref(),
                lookup.as_deref(),
                strict,
                recursive,
                max_depth,
                parallel,
                output_mode,
                report.as_deref(),
                allow_placeholders,
            )?;
        }
        Commands::Scan {
            paths,
            simulate,
            org,
            recursive,
            max_depth,
            no_parallel,
        } => {
            let parallel = !no_parallel;
            profile::cli::scan::handle_scan(
                &paths,
                simulate,
                org.as_deref(),
                recursive,
                max_depth,
                parallel,
                config.as_ref(),
                output_mode,
            )?;
        }
        Commands::Search { query, schema_path } => {
            profile::cli::search::handle_search(&query, schema_path.as_deref(), output_mode)?;
        }
        Commands::Uuid {
            paths,
            output,
            org,
            predictable,
            recursive,
            max_depth,
            no_parallel,
            dry_run,
        } => {
            let parallel = !no_parallel;
            profile::cli::uuid::handle_uuid(
                &paths,
                output.as_deref(),
                org.as_deref(),
                predictable,
                config.as_ref(),
                recursive,
                max_depth,
                parallel,
                dry_run,
                output_mode,
            )?;
        }
        Commands::Diff {
            file1,
            file2,
            output,
        } => {
            profile::cli::diff::handle_diff(&file1, &file2, output.as_deref())?;
        }
        Commands::Unsign {
            paths,
            output,
            recursive,
            max_depth,
            no_parallel,
            dry_run,
        } => {
            let parallel = !no_parallel;
            profile::cli::unsign::handle_unsign(
                &paths,
                output.as_deref(),
                recursive,
                max_depth,
                parallel,
                dry_run,
                config.as_ref(),
                output_mode,
            )?;
        }
        Commands::Sign {
            paths,
            output,
            identity,
            keychain,
            recursive,
            max_depth,
            no_parallel,
            dry_run,
        } => {
            let parallel = !no_parallel;
            profile::cli::sign::handle_sign(
                &paths,
                output.as_deref(),
                identity.as_deref(),
                keychain.as_deref(),
                recursive,
                max_depth,
                parallel,
                dry_run,
                output_mode,
            )?;
        }
        Commands::Verify {
            paths,
            recursive,
            max_depth,
            no_parallel,
        } => {
            let parallel = !no_parallel;
            profile::cli::sign::handle_verify(&paths, recursive, max_depth, parallel, output_mode)?;
        }
        Commands::Identities => {
            profile::cli::sign::handle_list_identities(output_mode)?;
        }
        Commands::Link {
            paths,
            output,
            org,
            predictable,
            merge,
            no_validate,
            recursive,
            max_depth,
            dry_run,
        } => {
            profile::cli::link::handle_link(
                &paths,
                output.as_deref(),
                org.as_deref(),
                predictable,
                merge,
                no_validate,
                recursive,
                max_depth,
                dry_run,
                config.as_ref(),
                output_mode,
            )?;
        }
        Commands::Generate {
            payload_type,
            output,
            org,
            full,
            schema_path,
            recipe,
            recipe_path,
            list_recipes,
            vars,
            create_recipe,
            interactive,
            format,
        } => {
            if let Some(recipe_name) = create_recipe {
                profile::cli::generate::handle_create_recipe(
                    &recipe_name,
                    &payload_type,
                    output.as_deref(),
                    schema_path.as_deref(),
                    output_mode,
                )?;
            } else if list_recipes {
                profile::cli::generate::handle_list_recipes(recipe_path.as_deref(), output_mode)?;
            } else if let Some(recipe_name) = recipe {
                profile::cli::generate::handle_generate_recipe(
                    &recipe_name,
                    recipe_path.as_deref(),
                    output.as_deref(),
                    org.as_deref(),
                    schema_path.as_deref(),
                    config.as_ref(),
                    &vars,
                    output_mode,
                    &format,
                )?;
            } else if interactive {
                if let Some(pt) = payload_type.first() {
                    profile::cli::generate::handle_generate_interactive(
                        pt,
                        output.as_deref(),
                        schema_path.as_deref(),
                    )?;
                } else {
                    anyhow::bail!(
                        "Specify a payload type for interactive mode.\n\
                         Example: contour profile generate com.google.Chrome --interactive"
                    );
                }
            } else if let Some(pt) = payload_type.first() {
                profile::cli::generate::handle_generate(
                    pt,
                    output.as_deref(),
                    org.as_deref(),
                    full,
                    schema_path.as_deref(),
                    config.as_ref(),
                    output_mode,
                    &format,
                )?;
            } else {
                anyhow::bail!(
                    "Specify a payload type, --recipe, or --list-recipes.\n\
                     Examples:\n  \
                     contour profile generate com.apple.wifi.managed\n  \
                     contour profile generate --recipe okta\n  \
                     contour profile generate --list-recipes"
                );
            }
        }
        Commands::Docs { action } => match action {
            DocsAction::Generate {
                output,
                payload,
                category,
                schema_path,
            } => {
                profile::cli::docs::handle_docs_generate(
                    &output,
                    payload.as_deref(),
                    category.as_deref(),
                    schema_path.as_deref(),
                    output_mode,
                )?;
            }
            DocsAction::List {
                category,
                schema_path,
            } => {
                profile::cli::docs::handle_docs_list(
                    category.as_deref(),
                    schema_path.as_deref(),
                    output_mode,
                )?;
            }
            DocsAction::FromProfile { file, output } => {
                profile::cli::docs::handle_docs_from_profile(
                    &file,
                    output.as_deref(),
                    output_mode,
                )?;
            }
            DocsAction::Ddm {
                output,
                declaration,
                category,
            } => {
                profile::cli::docs::handle_docs_ddm(
                    &output,
                    declaration.as_deref(),
                    category.as_deref(),
                    output_mode,
                )?;
            }
        },
        Commands::Payload { action } => match action {
            PayloadAction::List { file } => {
                profile::cli::payload::handle_payload_list(&file, output_mode)?;
            }
            PayloadAction::Read {
                file,
                r#type,
                key,
                index,
            } => {
                profile::cli::payload::handle_payload_read(
                    &file,
                    &r#type,
                    &key,
                    index,
                    output_mode,
                )?;
            }
            PayloadAction::Extract {
                file,
                r#type,
                output,
            } => {
                profile::cli::payload::handle_payload_extract(
                    &file,
                    &r#type,
                    output.as_deref(),
                    output_mode,
                )?;
            }
        },
        Commands::Command { action } => match action {
            CommandAction::List => {
                profile::cli::command::handle_command_list(output_mode)?;
            }
            CommandAction::Generate {
                command_type,
                output,
                params,
                uuid,
                base64,
                interactive,
            } => {
                if interactive {
                    profile::cli::command::handle_command_generate_interactive(output_mode)?;
                } else {
                    let command_type = command_type.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "Command type is required unless --interactive is specified."
                        )
                    })?;
                    profile::cli::command::handle_command_generate(
                        command_type,
                        output.as_deref(),
                        &params,
                        uuid,
                        base64,
                        output_mode,
                    )?;
                }
            }
            CommandAction::Info { command_type } => {
                profile::cli::command::handle_command_info(&command_type, output_mode)?;
            }
        },
        Commands::Synthesize {
            paths,
            output,
            org,
            validate,
            dry_run,
            interactive,
        } => {
            profile::cli::synthesize::handle_synthesize(
                &paths,
                output.as_deref(),
                org.as_deref(),
                validate,
                dry_run,
                interactive,
                output_mode,
            )?;
        }
        Commands::Ddm { action } => match action {
            DdmAction::Parse {
                paths,
                recursive,
                max_depth,
                no_parallel,
            } => {
                let parallel = !no_parallel;
                profile::cli::ddm::handle_ddm_parse(
                    &paths,
                    recursive,
                    max_depth,
                    parallel,
                    output_mode,
                )?;
            }
            DdmAction::Validate {
                paths,
                schema_path,
                recursive,
                max_depth,
                no_parallel,
            } => {
                let parallel = !no_parallel;
                profile::cli::ddm::handle_ddm_validate(
                    &paths,
                    schema_path.as_deref(),
                    recursive,
                    max_depth,
                    parallel,
                    output_mode,
                )?;
            }
            DdmAction::List {
                category,
                schema_path,
            } => {
                profile::cli::ddm::handle_ddm_list(
                    category.as_deref(),
                    schema_path.as_deref(),
                    output_mode,
                )?;
            }
            DdmAction::Info { name, schema_path } => {
                profile::cli::ddm::handle_ddm_info(&name, schema_path.as_deref(), output_mode)?;
            }
            DdmAction::Generate {
                name,
                output,
                full,
                schema_path,
            } => {
                profile::cli::ddm::handle_ddm_generate(
                    &name,
                    output.as_deref(),
                    full,
                    schema_path.as_deref(),
                    config.as_ref(),
                    output_mode,
                )?;
            }
        },
        Commands::Enrollment { action } => match action {
            EnrollmentAction::List {
                platform,
                os_version,
            } => {
                profile::cli::enrollment::handle_enrollment_list(
                    &platform,
                    os_version.as_deref(),
                    output_mode,
                )?;
            }
            EnrollmentAction::Generate {
                platform,
                os_version,
                skip_all,
                skip,
                output,
                profile_name,
                interactive,
            } => {
                profile::cli::enrollment::handle_enrollment_generate(
                    &platform,
                    os_version.as_deref(),
                    skip_all,
                    &skip,
                    output.as_deref(),
                    &profile_name,
                    interactive,
                    output_mode,
                )?;
            }
        },
    }

    Ok(())
}

/// Dispatch pppc commands.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
fn dispatch_pppc(
    action: Option<pppc::cli::Commands>,
    path: Vec<std::path::PathBuf>,
    output: Option<std::path::PathBuf>,
    org: Option<String>,
    service: Option<Vec<pppc::pppc::PppcService>>,
    interactive: bool,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    use contour_core::OutputMode;
    use pppc::cli::Commands;

    let output_mode = if json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    match action {
        Some(Commands::Scan {
            path,
            from_csv,
            output,
            org,
            interactive,
        }) => {
            let org = contour_core::resolve_org(org)?;
            pppc::cli::scan::run(
                &path,
                from_csv.as_deref(),
                &output,
                &org,
                interactive,
                output_mode,
            )
        }

        Some(Commands::Configure {
            input,
            skip_configured,
        }) => pppc::cli::configure::run(&input, skip_configured),

        Some(Commands::Generate {
            input,
            output,
            combined,
            dry_run,
            fragment,
        }) => pppc::cli::generate::run(
            &input,
            output.as_deref(),
            combined,
            dry_run,
            fragment,
            output_mode,
        ),

        Some(Commands::Batch {
            input,
            add_services,
            remove_services,
            set_services,
            apps,
            dry_run,
        }) => pppc::cli::batch::run(
            &input,
            &add_services,
            &remove_services,
            &set_services,
            &apps,
            dry_run,
            output_mode,
        ),

        Some(Commands::Init {
            output,
            org,
            name,
            force,
        }) => pppc::cli::init::run(&output, org.as_deref(), name.as_deref(), force, output_mode),

        Some(Commands::Info) => pppc::cli::info::run(output_mode),

        Some(Commands::Validate { input, strict }) => {
            pppc::cli::validate::run(&input, strict, output_mode)
        }

        Some(Commands::Diff { file1, file2 }) => pppc::cli::diff::run(&file1, &file2, output_mode),

        Some(Commands::Completions { shell }) => {
            use clap::CommandFactory;
            contour_core::generate_completions(&mut pppc::cli::Cli::command(), "pppc", shell);
            Ok(())
        }

        None => {
            // One-shot mode (backwards compatibility)
            let org = contour_core::resolve_org(org)?;
            pppc::cli::scan::run_oneshot(
                &path,
                output.as_deref(),
                &org,
                interactive,
                service,
                dry_run,
                output_mode,
            )
        }
    }
}

/// Dispatch support commands.
fn dispatch_support(
    action: Option<support::cli::Commands>,
    output: Option<std::path::PathBuf>,
    org: Option<String>,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    use contour_core::OutputMode;

    let output_mode = if json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    match action {
        Some(support::cli::Commands::Init { path, output }) => {
            support::cli::init::run(&path, output.as_deref())
        }
        Some(support::cli::Commands::Generate {
            config,
            output,
            dry_run,
            brand,
            fragment,
        }) => support::cli::generate::run(
            &config,
            output.as_deref(),
            dry_run,
            brand.as_deref(),
            fragment,
            output_mode,
        ),

        None => support::cli::wizard::run_wizard(
            output.as_deref(),
            org.as_deref(),
            dry_run,
            output_mode,
        ),
    }
}

/// Dispatch BTM (Background Task Management) commands.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
fn dispatch_btm(
    action: Option<btm::cli::BtmCommands>,
    mode: btm::cli::BtmScanMode,
    path: Vec<std::path::PathBuf>,
    output: Option<std::path::PathBuf>,
    org: Option<String>,
    interactive: bool,
    ddm: bool,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    use btm::cli::BtmCommands;
    use contour_core::OutputMode;

    let output_mode = if json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    match action {
        Some(BtmCommands::Init {
            output,
            org,
            name,
            force,
        }) => btm::cli::init::run(&output, org.as_deref(), name.as_deref(), force, output_mode),
        Some(BtmCommands::Info) => btm::cli::info::run(output_mode),
        Some(BtmCommands::Scan {
            mode,
            path,
            output,
            org,
            interactive,
        }) => {
            let org = contour_core::resolve_org(org)?;
            btm::cli::scan::run(&mode, &path, &output, &org, interactive, output_mode)
        }
        Some(BtmCommands::Merge { source, target }) => {
            btm::cli::merge::run(&source, &target, output_mode)
        }
        Some(BtmCommands::Generate {
            input,
            output,
            dry_run,
            fragment,
            ddm,
            per_app,
        }) => btm::cli::generate::run(
            &input,
            output.as_deref(),
            dry_run,
            fragment,
            ddm,
            per_app,
            output_mode,
        ),
        Some(BtmCommands::Validate { input, strict }) => {
            btm::cli::validate::run(&input, strict, output_mode)
        }
        Some(BtmCommands::Diff { file1, file2 }) => {
            btm::cli::diff::run(&file1, &file2, output_mode)
        }
        Some(BtmCommands::Completions { shell }) => {
            use clap::CommandFactory;
            contour_core::generate_completions(&mut crate::Cli::command(), "contour", shell);
            Ok(())
        }
        None => {
            let org = contour_core::resolve_org(org)?;
            btm::cli::scan::run_oneshot(
                &mode,
                &path,
                output.as_deref(),
                &org,
                interactive,
                ddm,
                dry_run,
                output_mode,
            )
        }
    }
}

/// Dispatch notifications commands.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
fn dispatch_notifications(
    action: Option<notifications::cli::NotificationCommands>,
    path: Vec<std::path::PathBuf>,
    output: Option<std::path::PathBuf>,
    org: Option<String>,
    interactive: bool,
    combined: bool,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    use contour_core::OutputMode;
    use notifications::cli::NotificationCommands;

    let output_mode = if json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    match action {
        Some(NotificationCommands::Init {
            output,
            org,
            name,
            force,
        }) => notifications::cli::init::run(
            &output,
            org.as_deref(),
            name.as_deref(),
            force,
            output_mode,
        ),
        Some(NotificationCommands::Scan {
            path,
            output,
            org,
            interactive,
        }) => {
            let org = contour_core::resolve_org(org)?;
            notifications::cli::scan::run(&path, &output, &org, interactive, output_mode)
        }
        Some(NotificationCommands::Configure { input }) => {
            notifications::cli::configure::run(&input)
        }
        Some(NotificationCommands::Generate {
            input,
            output,
            combined,
            dry_run,
            fragment,
        }) => notifications::cli::generate::run(
            &input,
            output.as_deref(),
            combined,
            dry_run,
            fragment,
            output_mode,
        ),
        Some(NotificationCommands::Validate { input, strict }) => {
            notifications::cli::validate::run(&input, strict, output_mode)
        }
        Some(NotificationCommands::Diff { file1, file2 }) => {
            notifications::cli::diff::run(&file1, &file2, output_mode)
        }
        Some(NotificationCommands::Completions { shell }) => {
            use clap::CommandFactory;
            contour_core::generate_completions(&mut crate::Cli::command(), "contour", shell);
            Ok(())
        }
        None => {
            let org = contour_core::resolve_org(org)?;
            notifications::cli::scan::run_oneshot(
                &path,
                output.as_deref(),
                &org,
                interactive,
                combined,
                dry_run,
                output_mode,
            )
        }
    }
}

/// Resolve org for santa commands: if the user left the default "com.example", try ContourConfig.
fn resolve_santa_org(org: String) -> String {
    if org != "com.example" {
        return org;
    }
    contour_core::config::ContourConfig::load_nearest()
        .map(|c| c.organization.domain)
        .unwrap_or(org)
}

/// Same for optional org (santa add --org).
fn resolve_santa_org_opt(org: Option<String>) -> Option<String> {
    if org.is_some() {
        return org;
    }
    contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.domain)
}

/// Dispatch santa commands.
fn dispatch_santa(action: santa::cli::Commands, verbose: bool, json: bool) -> Result<()> {
    use santa::cli::{CelAction, Commands, FaaAction, RingsCommands};
    use santa::output::OutputMode;

    let output_mode = if json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    match action {
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
            let org = resolve_santa_org(org);
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
                let org = resolve_santa_org(org);
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
            let org = org.map(resolve_santa_org);
            santa::cli::init::run(&output, org.as_deref(), name.as_deref(), force, output_mode)
        }

        Commands::Prep {
            output_dir,
            org,
            dry_run,
        } => {
            let org = resolve_santa_org(org);
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
            let org = resolve_santa_org(org);
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

            let org = resolve_santa_org_opt(org);
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
            json,
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
            json,
            verbose,
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
            let org = resolve_santa_org(org);
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
                json,
                verbose,
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
            let org = resolve_santa_org(org);
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
                    verbose,
                    json,
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
            let org = resolve_santa_org(org);
            santa::cli::allow_cmd::run(
                &input,
                output.as_deref(),
                rule_type,
                &org,
                name.as_deref(),
                !no_deterministic_uuids,
                dry_run,
                json,
            )
        }

        Commands::Select {
            input,
            output,
            rule_type,
            org,
        } => {
            let org = resolve_santa_org(org);
            santa::cli::select::run(&input, output.as_deref(), &rule_type, &org, json)
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

/// Resolve org domain for mscp commands: CLI flag → ContourConfig.
fn resolve_mscp_org(org: Option<String>) -> Option<String> {
    if org.is_some() {
        return org;
    }
    contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.domain)
}

/// Resolve org display name for mscp commands: CLI flag → ContourConfig.
fn resolve_mscp_org_name(org_name: Option<String>) -> Option<String> {
    if org_name.is_some() {
        return org_name;
    }
    contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.name)
}

/// Resolve deterministic_uuids for mscp commands: CLI flag → ContourConfig.
fn resolve_mscp_deterministic_uuids(cli_flag: bool) -> bool {
    if cli_flag {
        return true;
    }
    contour_core::config::ContourConfig::load_nearest()
        .and_then(|c| c.defaults.deterministic_uuids)
        .unwrap_or(false)
}

/// Dispatch mscp commands.
fn dispatch_mscp(action: mscp::cli::Commands, _verbose: bool, json: bool) -> Result<()> {
    use mscp::cli::{Commands, ConstraintsAction, ContainerAction, OdvAction};
    use mscp::output::OutputMode;

    let output_mode = if json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    match action {
        Commands::Info { config } => {
            mscp::cli::info_command(&config, output_mode)?;
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
            mscp::cli::init_project(
                &output, org, name, force, fleet, jamf, munki, sync, &branch, baselines, json,
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
            let org = resolve_mscp_org(org);
            let org_name = resolve_mscp_org_name(org_name);
            let deterministic_uuids = resolve_mscp_deterministic_uuids(deterministic_uuids);

            // Build ProfileOptions when any general profile option is set
            let profile_options = if org_name.is_some()
                || remove_consent_text
                || consent_text.is_some()
                || deterministic_uuids
            {
                Some(mscp::transformers::ProfileOptions {
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
                Some(mscp::transformers::JamfOptions {
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
                Some(mscp::transformers::MunkiComplianceOptions {
                    target_path: std::path::PathBuf::from(munki_compliance_path),
                    flag_prefix: munki_flag_prefix,
                })
            } else {
                None
            };
            let munki_script_options = if munki_script_nopkg {
                Some(mscp::transformers::MunkiScriptOptions {
                    catalog: munki_script_catalog,
                    category: munki_script_category,
                    display_name_prefix: "mSCP".to_string(),
                    embed_fix_in_installcheck: !munki_script_separate_postinstall,
                })
            } else {
                None
            };

            mscp::cli::process_baseline(
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
                mscp::config::OutputStructure::default(),
            )?;
        }

        Commands::Generate {
            mscp_repo,
            branch,
            baseline,
            output,
            use_uv,
            use_python3,
            use_container,
            container_image: _container_image,
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
            odv: _odv,
            exclude,
            dry_run,
            script_mode,
            fragment,
        } => {
            // Resolve org from CLI flags, falling back to .contour/config.toml
            let org = resolve_mscp_org(org);
            let org_name = resolve_mscp_org_name(org_name);

            let python_method = if use_container {
                Some(mscp::cli::generate::PythonMethod::Container)
            } else if use_uv {
                Some(mscp::cli::generate::PythonMethod::Uv)
            } else if use_python3 {
                Some(mscp::cli::generate::PythonMethod::Python3)
            } else {
                None // Auto-detect
            };
            let deterministic_uuids = resolve_mscp_deterministic_uuids(deterministic_uuids);

            // Build ProfileOptions when any general profile option is set
            let profile_options = if org_name.is_some()
                || remove_consent_text
                || consent_text.is_some()
                || deterministic_uuids
            {
                Some(mscp::transformers::ProfileOptions {
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
                Some(mscp::transformers::JamfOptions {
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
                Some(mscp::transformers::MunkiComplianceOptions {
                    target_path: std::path::PathBuf::from(munki_compliance_path),
                    flag_prefix: munki_flag_prefix,
                })
            } else {
                None
            };
            let munki_script_options = if munki_script_nopkg {
                Some(mscp::transformers::MunkiScriptOptions {
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
                mscp::cli::generate::switch_branch(&mscp_repo, &target_branch)?;
            }

            mscp::cli::generate_baseline(
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
                mscp::config::OutputStructure::default(),
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
                let config = mscp::config::load_config(&config_file)?;
                mscp::cli::generate_from_config(config)?;
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
                    Some(mscp::cli::generate::PythonMethod::Container)
                } else if use_uv {
                    Some(mscp::cli::generate::PythonMethod::Uv)
                } else if use_python3 {
                    Some(mscp::cli::generate::PythonMethod::Python3)
                } else {
                    None // Auto-detect
                };

                // GenerateAll CLI mode has no org/consent flags — use deterministic_uuids only
                let profile_options = if deterministic_uuids {
                    Some(mscp::transformers::ProfileOptions {
                        deterministic_uuids,
                        ..Default::default()
                    })
                } else {
                    None
                };

                let jamf_options = if jamf_mode || no_creation_date || identical_payload_uuid {
                    Some(mscp::transformers::JamfOptions {
                        no_creation_date,
                        identical_payload_uuid,
                        baseline: None,
                        domain: None,
                        org_name: None,
                        description_format: None,
                    })
                } else {
                    None
                };

                let munki_compliance_options = if munki_compliance_flags {
                    Some(mscp::transformers::MunkiComplianceOptions {
                        target_path: std::path::PathBuf::from(
                            mscp::transformers::munki_compliance::DEFAULT_COMPLIANCE_PLIST_PATH,
                        ),
                        flag_prefix: mscp::transformers::munki_compliance::DEFAULT_FLAG_PREFIX
                            .to_string(),
                    })
                } else {
                    None
                };

                let munki_script_options = if munki_script_nopkg {
                    Some(mscp::transformers::MunkiScriptOptions {
                        catalog: mscp::transformers::munki_compliance::DEFAULT_MUNKI_CATALOG
                            .to_string(),
                        category: mscp::transformers::munki_compliance::DEFAULT_MUNKI_CATEGORY
                            .to_string(),
                        display_name_prefix: "mSCP".to_string(),
                        embed_fix_in_installcheck: true,
                    })
                } else {
                    None
                };

                let parallel = !no_parallel;
                mscp::cli::generate_all_baselines(
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
                    mscp::config::OutputStructure::default(),
                )?;
            }
        }

        Commands::Diff {
            output,
            baseline,
            format,
        } => {
            mscp::cli::diff_versions(output, baseline, format.into(), output_mode)?;
        }

        Commands::Validate {
            output,
            schemas,
            strict,
        } => {
            mscp::cli::validate_output(output, schemas, strict, output_mode)?;
        }

        Commands::Deduplicate {
            output,
            baselines,
            platform,
            jamf_mode,
            dry_run,
        } => {
            mscp::cli::deduplicate_profiles(
                output,
                baselines,
                platform,
                jamf_mode,
                dry_run,
                output_mode,
            )?;
        }

        Commands::List { output } => {
            mscp::cli::list_baselines(output)?;
        }

        Commands::ListBaselines { mscp_repo } => {
            mscp::cli::list_available_baselines(mscp_repo)?;
        }

        Commands::Schema { action } => match action {
            mscp::cli::SchemaAction::Baselines => {
                mscp::cli::handle_schema_baselines(output_mode)?;
            }
            mscp::cli::SchemaAction::Rules { baseline, platform } => {
                mscp::cli::handle_schema_rules(&baseline, &platform, output_mode)?;
            }
            mscp::cli::SchemaAction::Stats => {
                mscp::cli::handle_schema_stats(output_mode)?;
            }
            mscp::cli::SchemaAction::Compare {
                mscp_repo,
                baseline,
                platform,
            } => {
                mscp::cli::handle_schema_compare(&mscp_repo, &baseline, &platform, output_mode)?;
            }
            mscp::cli::SchemaAction::Search { query, platform } => {
                mscp::cli::handle_schema_search(&query, platform.as_deref(), output_mode)?;
            }
            mscp::cli::SchemaAction::Rule { rule_id } => {
                mscp::cli::handle_schema_rule(&rule_id, output_mode)?;
            }
        },

        Commands::ExtractScripts {
            mscp_repo,
            baseline,
            output,
            flat,
            dry_run,
            constraints,
            odv,
        } => {
            mscp::cli::extract_scripts(
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
            mscp::cli::clean_baseline(baseline, output, force)?;
        }

        Commands::Migrate {
            from,
            to,
            team,
            output,
            no_backup,
        } => {
            mscp::cli::migrate_team_file(from, to, team, output, !no_backup)?;
        }

        Commands::Verify { output, fix } => {
            mscp::cli::verify_references(output, fix)?;
        }

        Commands::Constraints { action } => match action {
            ConstraintsAction::Add {
                r#type,
                constraints,
                mscp_repo,
                baseline,
            } => {
                mscp::cli::constraints_add(r#type, constraints, mscp_repo, baseline, output_mode)?;
            }
            ConstraintsAction::Remove {
                r#type,
                constraints,
                ..
            } => {
                mscp::cli::constraints_remove(r#type, constraints, output_mode)?;
            }
            ConstraintsAction::List {
                r#type,
                constraints,
                ..
            } => {
                mscp::cli::constraints_list(r#type, constraints, output_mode)?;
            }
            ConstraintsAction::AddScript {
                r#type,
                constraints,
                mscp_repo,
                baseline,
            } => {
                mscp::cli::constraints_add_script(
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
                mscp::cli::constraints_remove_script(r#type, constraints, output_mode)?;
            }
            ConstraintsAction::ListScripts {
                r#type,
                constraints,
                ..
            } => {
                mscp::cli::constraints_list_scripts(r#type, constraints, output_mode)?;
            }
            ConstraintsAction::AddCategories {
                r#type,
                constraints,
                mscp_repo,
                baseline,
                exclude,
            } => {
                mscp::cli::constraints_add_categories(
                    r#type,
                    constraints,
                    mscp_repo,
                    baseline,
                    exclude,
                    output_mode,
                )?;
            }
        },

        Commands::Odv { action } => match action {
            OdvAction::Init {
                mscp_repo,
                baseline,
                output,
            } => {
                mscp::cli::odv_init(mscp_repo, baseline, output, output_mode)?;
            }
            OdvAction::List {
                mscp_repo,
                baseline,
                overrides,
            } => {
                mscp::cli::odv_list(mscp_repo, baseline, overrides, output_mode)?;
            }
            OdvAction::Edit { overrides } => {
                mscp::cli::odv_edit(overrides, output_mode)?;
            }
        },

        Commands::Container { action } => match action {
            ContainerAction::Init {
                mscp_repo,
                branch,
                tag,
                no_build,
                docker,
            } => {
                mscp::cli::generate::container_init(&mscp_repo, &branch, &tag, no_build, docker)?;
            }
            ContainerAction::Pull { image } => {
                mscp::cli::generate::pull_mscp_container(image.as_deref())?;
            }
            ContainerAction::Status => {
                mscp::cli::generate::container_status()?;
            }
            ContainerAction::Test { image } => {
                mscp::cli::generate::test_container(image.as_deref())?;
            }
        },
    }

    Ok(())
}

/// Write per-tool domain reference sections for LLM consumption.
///
/// Appended after the CLI reference so LLMs have the domain knowledge
/// needed to generate valid macOS MDM configurations.
fn write_llm_domain_reference(writer: &mut impl Write, has: &dyn Fn(&str) -> bool) -> Result<()> {
    let mut buf = String::with_capacity(64 * 1024);

    writeln!(buf, "\n---\n")?;
    writeln!(buf, "# Domain reference (for generating configurations)\n")?;

    // ── Profile: payload type catalog ──
    if has("profile") {
        writeln!(buf, "## profile — Payload type catalog\n")?;
        writeln!(
            buf,
            "Use `contour profile docs generate <type>` to generate markdown docs for any payload type."
        )?;
        writeln!(
            buf,
            "Use `contour profile validate <file>` to validate a .mobileconfig against these schemas.\n"
        )?;

        // Write schema catalog (flushing buf first since catalog writes directly)
        writer.write_all(buf.as_bytes())?;
        buf.clear();

        let registry = profile::schema::SchemaRegistry::embedded()?;
        registry.write_llm_catalog(writer)?;
    }

    // ── PPPC: services reference ──
    if has("pppc") {
        writeln!(buf, "## pppc — Privacy Preferences Policy Control\n")?;
        writeln!(
            buf,
            "Generates `com.apple.TCC.configuration-profile-policy` payloads.\n"
        )?;
        writeln!(buf, "| CLI name | TCC key | Display name | Auth | Notes |")?;
        writeln!(buf, "|----------|---------|--------------|------|-------|")?;
        for svc in pppc::pppc::PppcService::all() {
            let auth = if svc.is_deny_only() {
                "deny-only"
            } else if svc.supports_standard_user_set() {
                "user-settable"
            } else {
                "allow"
            };
            let notes = if svc.is_deny_only() {
                "Profile cannot grant; can only deny"
            } else if svc.supports_standard_user_set() {
                "Non-admin users can toggle"
            } else {
                ""
            };
            writeln!(
                buf,
                "| `{}` | `{}` | {} | {} | {} |",
                svc.key().to_lowercase(),
                svc.key(),
                svc.display_name(),
                auth,
                notes,
            )?;
        }
        writeln!(buf)?;
        writeln!(
            buf,
            "**Authorization values**: `Allow` (1), `Deny` (0), `AllowStandardUserToSetSystemService` (2)\n"
        )?;
    }

    // ── Santa: rule types & policies ──
    if has("santa") {
        writeln!(buf, "## santa — Endpoint security rules\n")?;
        writeln!(buf, "### Rule types\n")?;
        writeln!(buf, "| Type | Description |")?;
        writeln!(buf, "|------|-------------|")?;
        writeln!(buf, "| `BINARY` | Match by binary hash (SHA-256) |")?;
        writeln!(buf, "| `CERTIFICATE` | Match by signing certificate hash |")?;
        writeln!(buf, "| `TEAMID` | Match by Apple Team ID |")?;
        writeln!(
            buf,
            "| `SIGNINGID` | Match by signing identifier (e.g. `EQHXZ8M8AV:com.google.Chrome`) |"
        )?;
        writeln!(buf, "| `CDHASH` | Match by code directory hash |")?;
        writeln!(buf)?;
        writeln!(buf, "### Policies\n")?;
        writeln!(buf, "| Policy | Description |")?;
        writeln!(buf, "|--------|-------------|")?;
        writeln!(buf, "| `ALLOWLIST` | Allow execution |")?;
        writeln!(buf, "| `BLOCKLIST` | Block execution (shows message) |")?;
        writeln!(buf, "| `SILENT_BLOCKLIST` | Block execution (silent) |")?;
        writeln!(
            buf,
            "| `ALLOWLIST_COMPILER` | Allow + treat as compiler (outputs also allowed) |"
        )?;
        writeln!(buf, "| `REMOVE` | Remove existing rule |")?;
        writeln!(buf, "| `CEL` | Dynamic evaluation via CEL expression |")?;
        writeln!(buf)?;
        writeln!(buf, "### Client modes\n")?;
        writeln!(buf, "- **Monitor** (1): Log-only, no blocking")?;
        writeln!(buf, "- **Lockdown** (2): Block unsigned/unknown binaries\n")?;
    }

    // ── Notifications ──
    if has("notifications") {
        writeln!(buf, "## notifications — Notification settings profiles\n")?;
        writeln!(
            buf,
            "Generates `com.apple.notificationsettings` payloads with per-app notification settings.\n"
        )?;
        writeln!(buf, "### Per-app settings\n")?;
        writeln!(buf, "| Setting | Type | Default | Description |")?;
        writeln!(buf, "|---------|------|---------|-------------|")?;
        writeln!(
            buf,
            "| `alerts_enabled` | bool | true | Enable notifications |"
        )?;
        writeln!(
            buf,
            "| `alert_type` | int | 1 | 0=None, 1=Temporary Banner, 2=Persistent Banner |"
        )?;
        writeln!(
            buf,
            "| `badges_enabled` | bool | true | Show badge on app icon |"
        )?;
        writeln!(
            buf,
            "| `critical_alerts` | bool | true | Allow critical alerts |"
        )?;
        writeln!(buf, "| `lock_screen` | bool | true | Show on lock screen |")?;
        writeln!(
            buf,
            "| `notification_center` | bool | true | Show in notification center |"
        )?;
        writeln!(
            buf,
            "| `sounds_enabled` | bool | false | Play notification sound |"
        )?;
        writeln!(buf)?;
    }

    // ── BTM ──
    if has("btm") {
        writeln!(buf, "## btm — Background Task Management\n")?;
        writeln!(
            buf,
            "Generates `com.apple.servicemanagement` payloads for managed login/background items.\n"
        )?;
        writeln!(buf, "### Rule structure\n")?;
        writeln!(
            buf,
            "Each app entry has: `bundle_id`, optional `team_id`, optional `code_requirement`, and `rules[]`."
        )?;
        writeln!(
            buf,
            "Each rule has: `rule_type` (e.g. `TeamIdentifier`), `rule_value`, optional `comment`.\n"
        )?;
    }

    // ── mSCP ──
    if has("mscp") {
        writeln!(buf, "## mscp — macOS Security Compliance Project\n")?;
        writeln!(buf, "Builds and deploys mSCP security baselines.\n")?;

        if let Ok(registry) = mscp::registry::MscpRegistry::embedded() {
            // Platform coverage
            let versions = registry.platform_versions();
            writeln!(buf, "### Platform coverage\n")?;
            for (platform, os) in &versions {
                let edge_count = registry
                    .edges
                    .iter()
                    .filter(|e| {
                        e.platform.as_deref() == Some(platform)
                            && e.os_version.as_deref() == Some(os.as_str())
                    })
                    .count();
                writeln!(buf, "- {platform} {os} ({edge_count} rule-baseline edges)")?;
            }
            writeln!(buf)?;

            // Baselines with per-platform rule counts
            writeln!(
                buf,
                "### Baselines ({} available)\n",
                registry.baselines.len()
            )?;
            for b in &registry.baselines {
                let total = registry.unique_rule_count_for_baseline(&b.baseline);
                let mut per_platform = Vec::new();
                for (platform, os) in &versions {
                    let filter = mscp::registry::PlatformFilter {
                        platform,
                        os_version: Some(os),
                    };
                    let count = registry
                        .rule_ids_for_baseline(&b.baseline, Some(&filter))
                        .len();
                    if count > 0 {
                        per_platform.push(format!("{platform} {os}: {count}"));
                    }
                }
                // Show which platforms this baseline belongs to
                let platform_names: Vec<&str> = b
                    .platforms
                    .iter()
                    .map(|(p, _)| p.as_str())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let platform_tag = if platform_names.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", platform_names.join(", "))
                };
                if per_platform.is_empty() {
                    writeln!(
                        buf,
                        "- `{}` — {}{platform_tag} ({total} rules)",
                        b.baseline, b.title
                    )?;
                } else {
                    writeln!(
                        buf,
                        "- `{}` — {}{platform_tag} ({total} unique — {})",
                        b.baseline,
                        b.title,
                        per_platform.join(", ")
                    )?;
                }
            }
            writeln!(buf)?;

            // Sections
            writeln!(
                buf,
                "### Sections ({} categories)\n",
                registry.sections.len()
            )?;
            for s in &registry.sections {
                if s.description.is_empty() {
                    writeln!(buf, "- `{}`", s.name)?;
                } else {
                    writeln!(buf, "- `{}` — {}", s.name, s.description)?;
                }
            }
            writeln!(buf)?;

            // Stats
            writeln!(buf, "### Stats\n")?;
            writeln!(
                buf,
                "- {} unique rules across all platforms",
                registry.rules.len()
            )?;
            writeln!(
                buf,
                "- {} NIST 800-53 control mappings",
                registry.control_tiers.len()
            )?;
            let with_check = registry.rules.iter().filter(|r| r.has_check).count();
            let with_fix = registry.rules.iter().filter(|r| r.has_fix).count();
            let with_mc = registry.rules.iter().filter(|r| r.mobileconfig).count();
            writeln!(
                buf,
                "- {with_check} with check scripts, {with_fix} with fix scripts, {with_mc} with mobileconfig"
            )?;
        } else {
            writeln!(
                buf,
                "### Baselines (discovered at runtime from mSCP repo)\n"
            )?;
            writeln!(
                buf,
                "Common baselines: `cis_lvl1`, `cis_lvl2`, `800-53r5_high`, `800-53r5_moderate`, `800-53r5_low`, `800-171`, `cmmc_lvl2`, `stig`"
            )?;
        }
        writeln!(
            buf,
            "Each baseline produces: mobileconfig profiles, DDM declarations, compliance scripts\n"
        )?;
    }

    // ── DDM ──
    if has("ddm") {
        writeln!(buf, "## ddm — Declarative Device Management\n")?;
        writeln!(
            buf,
            "DDM declarations are JSON files with this structure:\n"
        )?;
        writeln!(buf, "```json")?;
        writeln!(buf, "{{")?;
        writeln!(
            buf,
            "  \"Type\": \"com.apple.configuration.passcode.settings\","
        )?;
        writeln!(buf, "  \"Identifier\": \"unique-declaration-id\",")?;
        writeln!(buf, "  \"Payload\": {{")?;
        writeln!(buf, "    \"RequirePasscode\": true,")?;
        writeln!(buf, "    \"MinimumLength\": 8")?;
        writeln!(buf, "  }}")?;
        writeln!(buf, "}}")?;
        writeln!(buf, "```\n")?;
        writeln!(
            buf,
            "Four DDM categories: configuration, asset, activation, management"
        )?;
        writeln!(
            buf,
            "Use `contour profile ddm list` to see all DDM declaration types."
        )?;
        writeln!(
            buf,
            "Use `contour profile ddm info <type>` to see fields for a specific type.\n"
        )?;
    }

    writer.write_all(buf.as_bytes())?;
    Ok(())
}
