//! Profile CLI - Apple configuration profile management toolkit (Community Edition).
//!
//! Profile provides commands for importing, validating, and normalizing
//! Apple configuration profiles (.mobileconfig) for MDM deployments.

mod cli;
mod config;
mod ddm;
mod diff;
mod docs;
mod link;
mod output;
mod profile;
mod recipe;
mod schema;
mod signing;
mod uuid;
mod validation;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use mimalloc::MiMalloc;
use output::OutputMode;

use cli::{Cli, CommandAction, Commands, DdmAction, DocsAction, PayloadAction};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<()> {
    // Parse CLI first to get global flags
    let cli = Cli::parse();

    // Determine output mode
    let output_mode = if cli.json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

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

    // Load config first (only show message in human mode)
    let config = config::ProfileConfig::load()?;

    if config.is_some() && output_mode == OutputMode::Human {
        println!("{}", "✓ Using config from profile.toml".to_string().green());
    }

    match cli.command {
        Commands::Info => {
            cli::info::handle_info(config.as_ref(), output_mode)?;
        }
        Commands::Init {
            output,
            org,
            name,
            force,
        } => {
            cli::init::handle_init(
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
            cli::import::handle_import(
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
            pasteboard,
            output,
            org,
            name,
            no_validate,
            no_uuid,
            recursive,
            max_depth,
            no_parallel,
            dry_run,
            report,
        } => {
            let parallel = !no_parallel;
            let validate = !no_validate;
            let regen_uuid = !no_uuid;
            if pasteboard {
                cli::normalize::handle_normalize_pasteboard(
                    output.as_deref(),
                    org.as_deref(),
                    name.as_deref(),
                    config.as_ref(),
                    validate,
                    regen_uuid,
                    output_mode,
                )?;
            } else {
                cli::normalize::handle_normalize(
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
            cli::duplicate::handle_duplicate(
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
            cli::validate::handle_validate(
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
            cli::scan::handle_scan(
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
            cli::search::handle_search(&query, schema_path.as_deref(), output_mode)?;
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
            cli::uuid::handle_uuid(
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
            cli::diff::handle_diff(&file1, &file2, output.as_deref())?;
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
            cli::unsign::handle_unsign(
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
            cli::sign::handle_sign(
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
            cli::sign::handle_verify(&paths, recursive, max_depth, parallel, output_mode)?;
        }
        Commands::Identities => {
            cli::sign::handle_list_identities(output_mode)?;
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
            cli::link::handle_link(
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
                cli::generate::handle_create_recipe(
                    &recipe_name,
                    &payload_type,
                    output.as_deref(),
                    schema_path.as_deref(),
                    output_mode,
                )?;
            } else if list_recipes {
                cli::generate::handle_list_recipes(recipe_path.as_deref(), output_mode)?;
            } else if let Some(recipe_name) = recipe {
                cli::generate::handle_generate_recipe(
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
                    cli::generate::handle_generate_interactive(
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
                cli::generate::handle_generate(
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
                cli::docs::handle_docs_generate(
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
                cli::docs::handle_docs_list(
                    category.as_deref(),
                    schema_path.as_deref(),
                    output_mode,
                )?;
            }
            DocsAction::FromProfile { file, output } => {
                cli::docs::handle_docs_from_profile(&file, output.as_deref(), output_mode)?;
            }
            DocsAction::Ddm {
                output,
                declaration,
                category,
            } => {
                cli::docs::handle_docs_ddm(
                    &output,
                    declaration.as_deref(),
                    category.as_deref(),
                    output_mode,
                )?;
            }
        },
        Commands::Payload { action } => match action {
            PayloadAction::List { file } => {
                cli::payload::handle_payload_list(&file, output_mode)?;
            }
            PayloadAction::Read {
                file,
                r#type,
                key,
                index,
            } => {
                cli::payload::handle_payload_read(&file, &r#type, &key, index, output_mode)?;
            }
            PayloadAction::Extract {
                file,
                r#type,
                output,
            } => {
                cli::payload::handle_payload_extract(
                    &file,
                    &r#type,
                    output.as_deref(),
                    output_mode,
                )?;
            }
        },
        Commands::Command { action } => match action {
            CommandAction::List => {
                cli::command::handle_command_list(output_mode)?;
            }
            CommandAction::Generate {
                command_type,
                output,
                params,
                uuid,
                interactive,
            } => {
                if interactive {
                    cli::command::handle_command_generate_interactive(output_mode)?;
                } else {
                    let command_type = command_type.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "Command type is required unless --interactive is specified."
                        )
                    })?;
                    cli::command::handle_command_generate(
                        command_type,
                        output.as_deref(),
                        &params,
                        uuid,
                        output_mode,
                    )?;
                }
            }
            CommandAction::Info { command_type } => {
                cli::command::handle_command_info(&command_type, output_mode)?;
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
            cli::synthesize::handle_synthesize(
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
                cli::ddm::handle_ddm_parse(&paths, recursive, max_depth, parallel, output_mode)?;
            }
            DdmAction::Validate {
                paths,
                schema_path,
                recursive,
                max_depth,
                no_parallel,
            } => {
                let parallel = !no_parallel;
                cli::ddm::handle_ddm_validate(
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
                cli::ddm::handle_ddm_list(
                    category.as_deref(),
                    schema_path.as_deref(),
                    output_mode,
                )?;
            }
            DdmAction::Info { name, schema_path } => {
                cli::ddm::handle_ddm_info(&name, schema_path.as_deref(), output_mode)?;
            }
            DdmAction::Generate {
                name,
                output,
                full,
                schema_path,
            } => {
                cli::ddm::handle_ddm_generate(
                    &name,
                    output.as_deref(),
                    full,
                    schema_path.as_deref(),
                    config.as_ref(),
                    output_mode,
                )?;
            }
        },
    }

    Ok(())
}
