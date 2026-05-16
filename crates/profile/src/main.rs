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
mod migrate;
mod output;
mod plan;
mod profile;
mod recipe;
mod rollback;
mod schema;
mod signing;
mod uuid;
mod validation;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use mimalloc::MiMalloc;
use output::OutputMode;

use cli::{
    Cli, CommandAction, Commands, DdmAction, DocsAction, EnrollmentAction, LibraryAction,
    PayloadAction,
};

/// Resolve a library-path argument: explicit CLI value wins,
/// otherwise fall back to `defaults.library_path` from
/// `.contour/config.toml`. Errors with a clear message naming the
/// flag/argument when neither source produced a path.
fn resolve_library_arg(cli_value: Option<&str>, flag_name: &str) -> Result<std::path::PathBuf> {
    if let Some(p) = contour_core::config::resolve_library_path(cli_value) {
        return Ok(p);
    }
    anyhow::bail!(
        "{flag_name} is required (no path passed and no `defaults.library_path` set in .contour/config.toml). Run `contour init --library-path <DIR>` or pass the path explicitly."
    )
}

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    // Parse CLI first so we know whether to render errors as JSON.
    let cli = Cli::parse();
    let json_mode = cli.json;

    if let Err(e) = run(cli) {
        if json_mode {
            // Phase B3: emit a parseable JSON error envelope on stderr so agents
            // and CI receive a structured failure shape, matching the BatchResult
            // error_code enum documented in the procedural SOP format spec.
            let msg = format!("{e:#}");
            let code = contour_core::classify_error(&msg);
            contour_core::print_error_json(&msg, Some(code));
        } else {
            eprintln!("Error: {e:#}");
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
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
        Commands::Info {
            payload_type,
            schema_path,
            full,
            os,
        } => {
            if let Some(t) = payload_type {
                cli::info::handle_payload_info(
                    &t,
                    schema_path.as_deref(),
                    full,
                    os.as_deref(),
                    output_mode,
                )?;
            } else {
                cli::info::handle_info(config.as_ref(), output_mode)?;
            }
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
            strict,
            jamf,
        } => {
            let validate = !no_validate;
            let regen_uuid = !no_uuid;
            if jamf {
                cli::jamf_import::handle_jamf_import(
                    &source,
                    output.as_deref(),
                    org.as_deref(),
                    name.as_deref(),
                    config.as_ref(),
                    validate,
                    regen_uuid,
                    dry_run,
                    all,
                    strict,
                    output_mode,
                )?;
            } else {
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
                    strict,
                    output_mode,
                )?;
            }
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
            lint_policy,
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
                &lint_policy,
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
            deprecations,
            md_report,
            fail_on_deprecations,
        } => {
            let parallel = !no_parallel;
            cli::scan::handle_scan(
                &paths,
                simulate,
                org.as_deref(),
                recursive,
                max_depth,
                parallel,
                deprecations,
                md_report.as_deref(),
                fail_on_deprecations,
                config.as_ref(),
                output_mode,
            )?;
        }
        Commands::Search {
            query,
            field,
            include_fields,
            schema_path,
        } => {
            cli::search::handle_search(
                query.as_deref(),
                field.as_deref(),
                include_fields,
                schema_path.as_deref(),
                output_mode,
            )?;
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
        Commands::Plan {
            baseline,
            proposed,
            recursive,
            org,
            predictable,
            format,
            accept_replace,
            accept_scope_change,
            fleet_size,
        } => {
            let opts = cli::plan::PlanOptions {
                recursive,
                predictable,
                org,
                org_name: None,
                format,
                accept_replace,
                accept_scope_change,
                fleet_size,
            };
            cli::plan::handle_plan(&baseline, &proposed, &opts)?;
        }
        Commands::Rollback {
            baseline,
            current,
            recursive,
            uuids_only,
            payload_types,
            refs_only,
            no_rewrite_refs,
            dry_run,
            output,
        } => {
            let opts = cli::rollback::RollbackCliOptions {
                recursive,
                uuids_only,
                payload_types,
                refs_only,
                no_rewrite_refs,
                dry_run,
                output_dir: output.map(std::path::PathBuf::from),
            };
            cli::rollback::handle_rollback(&baseline, &current, &opts)?;
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
            combined,
            no_combined,
            sanitize,
        } => {
            // Tristate: --combined wins true, --no-combined wins false,
            // neither leaves the value as None so the recipe TOML's
            // `[recipe.output] combined` controls.
            let combined_override: Option<bool> = if combined {
                Some(true)
            } else if no_combined {
                Some(false)
            } else {
                None
            };
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
            } else if !recipe.is_empty() {
                // Multi-recipe: each --recipe value runs through the
                // generator independently. Shared --org / --output /
                // --combined / --vars apply to each.
                for selector in &recipe {
                    cli::generate::handle_generate_recipe(
                        selector,
                        recipe_path.as_deref(),
                        output.as_deref(),
                        org.as_deref(),
                        full,
                        sanitize,
                        schema_path.as_deref(),
                        config.as_ref(),
                        &vars,
                        output_mode,
                        &format,
                        combined_override,
                    )?;
                }
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
                stdout,
                payload,
                category,
                schema_path,
            } => {
                cli::docs::handle_docs_generate(
                    output.as_deref(),
                    stdout,
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
                base64,
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
                        base64,
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
        Commands::Library { action } => match action {
            LibraryAction::New {
                path,
                no_presets,
                no_recipes,
                force,
            } => {
                cli::library::handle_library_new(
                    cli::library::LibraryNewOptions {
                        path: std::path::Path::new(&path),
                        include_presets: !no_presets,
                        include_recipes: !no_recipes,
                        force,
                    },
                    output_mode,
                )?;
            }
            LibraryAction::Import {
                inputs,
                into,
                name,
                combine,
                force,
            } => {
                let input_paths: Vec<std::path::PathBuf> =
                    inputs.iter().map(std::path::PathBuf::from).collect();
                let resolved_into = resolve_library_arg(into.as_deref(), "library import --into")?;
                cli::import_recipe::handle_library_import(
                    cli::import_recipe::LibraryImportOptions {
                        inputs: &input_paths,
                        into: &resolved_into,
                        name: name.as_deref(),
                        combine,
                        force,
                    },
                    output_mode,
                )?;
            }
            LibraryAction::Normalize { path, style } => {
                let mapped = match style {
                    cli::LibraryStyle::Flat => cli::library::LibraryStyle::Flat,
                    cli::LibraryStyle::Nested => cli::library::LibraryStyle::Nested,
                };
                let resolved = resolve_library_arg(path.as_deref(), "library normalize <PATH>")?;
                cli::library::handle_library_normalize(
                    cli::library::LibraryNormalizeOptions {
                        path: &resolved,
                        style: mapped,
                    },
                    output_mode,
                )?;
            }
            LibraryAction::Validate { path } => {
                let resolved = resolve_library_arg(path.as_deref(), "library validate <PATH>")?;
                cli::library_validate::handle_library_validate(
                    cli::library_validate::LibraryValidateOptions { path: &resolved },
                    output_mode,
                )?;
            }
            LibraryAction::Diff { a, b } => {
                cli::library_diff::handle_library_diff(
                    cli::library_diff::LibraryDiffOptions {
                        a: std::path::Path::new(&a),
                        b: std::path::Path::new(&b),
                    },
                    output_mode,
                )?;
            }
        },
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
            DdmAction::Compose {
                bundle,
                output,
                schema_path,
                allow_orphans,
                org,
                preset,
                preset_path,
                list_presets,
            } => {
                cli::ddm::handle_ddm_compose(
                    bundle.as_deref(),
                    output.as_deref(),
                    schema_path.as_deref(),
                    allow_orphans,
                    org.as_deref(),
                    preset.as_deref(),
                    preset_path.as_deref(),
                    list_presets,
                    config.as_ref(),
                    output_mode,
                )?;
            }
            DdmAction::Verify {
                directory,
                recursive,
                strict,
            } => {
                cli::ddm::handle_ddm_verify(&directory, recursive, strict, output_mode)?;
            }
        },
        Commands::Enrollment { action } => match action {
            EnrollmentAction::List {
                platform,
                os_version,
            } => {
                cli::enrollment::handle_enrollment_list(
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
                cli::enrollment::handle_enrollment_generate(
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
