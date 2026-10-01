//! Shared command dispatch for the profile toolkit.
//!
//! Both entry points call this: the standalone `profile` binary and
//! `contour profile …`. Keeping one match means a new subcommand is wired
//! once — previously each had its own copy, and they drifted the moment a
//! command was added to one and not the other (a missing import in the
//! standalone binary broke the build while the umbrella one compiled).

use anyhow::Result;

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

/// Dispatch one parsed `profile` subcommand.
///
/// `clap_root` yields the command tree that `find` searches. It is the one
/// place the two entry points genuinely differ, so the caller supplies it:
/// contour passes its real tree, the standalone binary a synthetic
/// `contour profile …` root. It is a closure so the tree is only built for
/// the commands that actually need it.
pub fn dispatch(
    action: crate::cli::Commands,
    json: bool,
    channel: crate::schema::Channel,
    clap_root: &dyn Fn() -> clap::Command,
) -> Result<()> {
    use crate::cli::{
        CommandAction, Commands, DdmAction, DocsAction, EnrollmentAction, LibraryAction,
        PayloadAction,
    };
    use crate::output::OutputMode;
    use colored::Colorize;

    let output_mode = if json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    // Load config (only show message in human mode)
    let config = crate::config::ProfileConfig::load()?;
    if config.is_some() && output_mode == OutputMode::Human {
        println!("{}", "✓ Using config from profile.toml".green());
    }

    match action {
        Commands::Info {
            payload_type,
            schema_path,
            full,
            os,
            beta,
            windows,
        } => {
            if let Some(t) = payload_type {
                crate::cli::info::handle_payload_info(
                    &t,
                    schema_path.as_deref(),
                    full,
                    os.as_deref(),
                    channel.or_beta(beta),
                    windows,
                    output_mode,
                )?;
            } else {
                crate::cli::info::handle_info(config.as_ref(), output_mode)?;
            }
        }
        Commands::Mcx(action) => match action {
            crate::cli::McxAction::List { paths, recursive } => {
                crate::cli::mcx::handle_list(&paths, recursive, output_mode)?;
            }
            crate::cli::McxAction::Rename {
                paths,
                from,
                to,
                from_prefix,
                to_prefix,
                interactive,
                recursive,
                write,
            } => {
                crate::cli::mcx::handle_rename(
                    &paths,
                    from.as_deref(),
                    to.as_deref(),
                    from_prefix.as_deref(),
                    to_prefix.as_deref(),
                    interactive,
                    recursive,
                    write,
                    output_mode,
                )?;
            }
        },
        Commands::Init {
            output,
            org,
            name,
            force,
        } => {
            crate::cli::init::handle_init(
                output.as_deref(),
                org.as_deref(),
                name.as_deref(),
                force,
                output_mode,
            )?;
        }
        Commands::Preset {
            manifest,
            output,
            source_note,
            domain,
        } => {
            crate::cli::jamf_preset::handle(
                std::path::Path::new(&manifest),
                output.as_deref().map(std::path::Path::new),
                source_note.as_deref(),
                domain.as_deref(),
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
                crate::cli::jamf_import::handle_jamf_import(
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
                crate::cli::import::handle_import(
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
            output,
            in_place,
            org,
            from_org,
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
                crate::cli::normalize::handle_normalize_pasteboard(
                    output.as_deref(),
                    org.as_deref(),
                    name.as_deref(),
                    config.as_ref(),
                    validate,
                    regen_uuid,
                    output_mode,
                )?;
            } else {
                crate::cli::normalize::handle_normalize(
                    &paths,
                    output.as_deref(),
                    org.as_deref(),
                    name.as_deref(),
                    from_org.as_deref(),
                    config.as_ref(),
                    validate,
                    regen_uuid,
                    recursive,
                    max_depth,
                    parallel,
                    dry_run,
                    in_place,
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
            crate::cli::duplicate::handle_duplicate(
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
            crate::cli::validate::handle_validate(
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
            crate::cli::scan::handle_scan(
                &paths,
                simulate,
                org.as_deref(),
                recursive,
                max_depth,
                parallel,
                deprecations,
                md_report.as_deref(),
                fail_on_deprecations,
                channel,
                config.as_ref(),
                output_mode,
            )?;
        }
        Commands::Reidentify {
            paths,
            org,
            scheme,
            from_prefix,
            to_prefix,
            regenerate_uuid,
            recursive,
            max_depth,
            no_parallel,
            write,
        } => {
            // Pattern mode names the new prefix outright, so no org is needed;
            // the uuid/name schemes derive identifiers from it and do.
            let org = if from_prefix.is_some() {
                org.unwrap_or_default()
            } else {
                contour_core::resolve_org(org)?
            };
            let scheme = crate::cli::reidentify::resolve_scheme(
                &scheme,
                from_prefix.as_deref(),
                to_prefix.as_deref(),
                regenerate_uuid,
            )?;
            crate::cli::reidentify::handle_reidentify(
                &paths,
                &org,
                &scheme,
                recursive,
                max_depth,
                !no_parallel,
                write,
                output_mode,
            )?;
        }
        Commands::Classify {
            paths,
            recursive,
            max_depth,
            no_parallel,
            map,
            write,
            sync_identity,
            org,
            identity_scheme,
            emit_map,
        } => {
            let scheme = crate::cli::reidentify::parse_scheme(&identity_scheme)?;
            let org = if sync_identity {
                Some(contour_core::resolve_org(org)?)
            } else {
                None
            };
            crate::cli::classify::handle_classify(
                &paths,
                recursive,
                max_depth,
                !no_parallel,
                map.as_deref(),
                write,
                sync_identity,
                scheme,
                org.as_deref(),
                emit_map.as_deref(),
                output_mode,
            )?;
        }
        Commands::Audit {
            paths,
            recursive,
            no_links,
            max_depth,
            no_parallel,
            certs_only,
            secrets_only,
            with_deprecations,
            fail_on_secrets,
            route_into,
            dry_run,
            md_report,
        } => {
            crate::cli::audit::handle_audit(
                &paths,
                recursive,
                max_depth,
                !no_parallel,
                certs_only,
                secrets_only,
                with_deprecations,
                no_links,
                fail_on_secrets,
                route_into.as_deref(),
                dry_run,
                md_report.as_deref(),
                output_mode,
            )?;
        }
        Commands::Collisions {
            paths,
            recursive,
            max_depth,
            flat,
            fail_on_conflict,
            fail_on_split,
            no_parallel,
            md_report,
        } => {
            crate::cli::collisions::handle_collisions(
                &paths,
                recursive,
                max_depth,
                flat,
                fail_on_conflict,
                fail_on_split,
                !no_parallel,
                md_report.as_deref(),
                output_mode,
            )?;
        }
        Commands::Report {
            paths,
            recursive,
            max_depth,
            flat,
            output,
            fail_on_secrets,
            fail_on_conflict,
        } => {
            crate::cli::report::handle_report(
                &paths,
                recursive,
                max_depth,
                flat,
                output.as_deref(),
                fail_on_secrets,
                fail_on_conflict,
                output_mode,
            )?;
        }
        Commands::Search {
            query,
            field,
            include_fields,
            schema_path,
            beta,
            windows,
            kind,
        } => {
            crate::cli::search::handle_search(
                query.as_deref(),
                field.as_deref(),
                include_fields,
                schema_path.as_deref(),
                channel.or_beta(beta),
                windows,
                kind.as_deref(),
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
            crate::cli::uuid::handle_uuid(
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
            md_report,
            structural,
            settings_only,
        } => {
            crate::cli::diff::handle_diff(
                &file1,
                &file2,
                output.as_deref(),
                md_report.as_deref(),
                crate::cli::diff::DiffMode {
                    structural,
                    settings_only,
                    json: matches!(output_mode, OutputMode::Json),
                },
            )?;
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
            crate::cli::unsign::handle_unsign(
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
            crate::cli::sign::handle_sign(
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
            crate::cli::sign::handle_verify(&paths, recursive, max_depth, parallel, output_mode)?;
        }
        Commands::Identities => {
            crate::cli::sign::handle_list_identities(output_mode)?;
        }
        Commands::Variables { mdm } => {
            crate::cli::variables::handle_variables(mdm.as_deref(), output_mode)?;
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
            crate::cli::link::handle_link(
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
            allow_placeholders,
            create_recipe,
            interactive,
            format,
            combined,
            no_combined,
            sanitize,
            beta,
            fragment,
        } => {
            let gen_channel = channel.or_beta(beta);
            // Tristate: --combined wins true, --no-combined wins false,
            // neither leaves the value as None so the recipe TOML
            // controls.
            let combined_override: Option<bool> = if combined {
                Some(true)
            } else if no_combined {
                Some(false)
            } else {
                None
            };
            if fragment {
                if create_recipe.is_some() || list_recipes || interactive {
                    anyhow::bail!(
                        "--fragment renders a payload type or --recipe; it does not combine \
                         with --create-recipe, --list-recipes or --interactive"
                    );
                }
                let source = if !recipe.is_empty() {
                    crate::cli::fragment::Source::Recipes(&recipe)
                } else if let Some(pt) = payload_type.first() {
                    crate::cli::fragment::Source::Payload(pt)
                } else {
                    anyhow::bail!("--fragment needs a payload type or --recipe");
                };
                crate::cli::fragment::handle_generate_fragment(
                    source,
                    output.as_deref(),
                    &crate::cli::fragment::Generate {
                        org: org.as_deref(),
                        full,
                        sanitize,
                        schema_path: schema_path.as_deref(),
                        recipe_path: recipe_path.as_deref(),
                        config: config.as_ref(),
                        vars: &vars,
                        format: &format,
                        combined: combined_override,
                        channel: gen_channel,
                        allow_placeholders,
                    },
                    output_mode,
                )?;
            } else if let Some(recipe_name) = create_recipe {
                crate::cli::generate::handle_create_recipe(
                    &recipe_name,
                    &payload_type,
                    output.as_deref(),
                    schema_path.as_deref(),
                    output_mode,
                )?;
            } else if list_recipes {
                crate::cli::generate::handle_list_recipes(recipe_path.as_deref(), output_mode)?;
            } else if !recipe.is_empty() {
                let mut renders = Vec::new();
                for selector in &recipe {
                    let render = crate::cli::generate::handle_generate_recipe(
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
                        true,
                    )?;
                    renders.push(render);
                }
                // A sanitized render leaves references unresolved on purpose.
                crate::cli::generate::judge_recipe_renders(
                    &renders,
                    &vars,
                    allow_placeholders || sanitize,
                )?;
            } else if interactive {
                if let Some(pt) = payload_type.first() {
                    crate::cli::generate::handle_generate_interactive(
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
                crate::cli::generate::handle_generate(
                    pt,
                    output.as_deref(),
                    org.as_deref(),
                    full,
                    schema_path.as_deref(),
                    config.as_ref(),
                    output_mode,
                    &format,
                    gen_channel,
                    true,
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
                crate::cli::docs::handle_docs_generate(
                    output.as_deref(),
                    stdout,
                    payload.as_deref(),
                    category.as_deref(),
                    schema_path.as_deref(),
                    channel,
                    output_mode,
                )?;
            }
            DocsAction::List {
                category,
                schema_path,
            } => {
                crate::cli::docs::handle_docs_list(
                    category.as_deref(),
                    schema_path.as_deref(),
                    channel,
                    output_mode,
                )?;
            }
            DocsAction::FromProfile { file, output } => {
                crate::cli::docs::handle_docs_from_profile(&file, output.as_deref(), output_mode)?;
            }
            DocsAction::Ddm {
                output,
                declaration,
                category,
            } => {
                crate::cli::docs::handle_docs_ddm(
                    &output,
                    declaration.as_deref(),
                    category.as_deref(),
                    output_mode,
                )?;
            }
        },
        Commands::Payload { action } => match action {
            PayloadAction::List { file } => {
                crate::cli::payload::handle_payload_list(&file, output_mode)?;
            }
            PayloadAction::Read {
                file,
                r#type,
                key,
                index,
            } => {
                crate::cli::payload::handle_payload_read(&file, &r#type, &key, index, output_mode)?;
            }
            PayloadAction::Extract {
                file,
                r#type,
                output,
                format,
            } => {
                crate::cli::payload::handle_payload_extract(
                    &file,
                    &r#type,
                    output.as_deref(),
                    &format,
                    output_mode,
                )?;
            }
        },
        Commands::Command { action } => match action {
            CommandAction::List => {
                crate::cli::command::handle_command_list(output_mode)?;
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
                    crate::cli::command::handle_command_generate_interactive(output_mode)?;
                } else {
                    let command_type = command_type.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "Command type is required unless --interactive is specified."
                        )
                    })?;
                    crate::cli::command::handle_command_generate(
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
                crate::cli::command::handle_command_info(&command_type, output_mode)?;
            }
            CommandAction::Decode { input, output } => {
                crate::cli::command::handle_command_decode(&input, output.as_deref(), output_mode)?;
            }
        },
        Commands::Synthesize {
            paths,
            output,
            org,
            validate,
            dry_run,
            interactive,
            keys_md,
        } => {
            crate::cli::synthesize::handle_synthesize(
                &paths,
                output.as_deref(),
                org.as_deref(),
                validate,
                dry_run,
                interactive,
                keys_md.as_deref(),
                output_mode,
            )?;
        }
        Commands::Find { term, deep } => {
            // Tree supplied by the caller (see `clap_root`), scoped to the
            // `profile` subtree so results render as `contour profile …`
            // with correct help-ai hints from either entry point.
            let cmd = clap_root();
            let mut out = std::io::stdout();
            contour_core::help_agents::generate_search(
                &cmd,
                &term,
                deep,
                json,
                Some("profile"),
                &mut out,
            )?;
        }
        Commands::Library { action } => match action {
            LibraryAction::New {
                path,
                no_presets,
                no_recipes,
                force,
            } => {
                crate::cli::library::handle_library_new(
                    crate::cli::library::LibraryNewOptions {
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
                crate::cli::import_recipe::handle_library_import(
                    crate::cli::import_recipe::LibraryImportOptions {
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
                    crate::cli::LibraryStyle::Flat => crate::cli::library::LibraryStyle::Flat,
                    crate::cli::LibraryStyle::Nested => crate::cli::library::LibraryStyle::Nested,
                };
                let resolved = resolve_library_arg(path.as_deref(), "library normalize <PATH>")?;
                crate::cli::library::handle_library_normalize(
                    crate::cli::library::LibraryNormalizeOptions {
                        path: &resolved,
                        style: mapped,
                    },
                    output_mode,
                )?;
            }
            LibraryAction::Validate { path } => {
                let resolved = resolve_library_arg(path.as_deref(), "library validate <PATH>")?;
                crate::cli::library_validate::handle_library_validate(
                    crate::cli::library_validate::LibraryValidateOptions { path: &resolved },
                    output_mode,
                )?;
            }
            LibraryAction::Diff { a, b } => {
                crate::cli::library_diff::handle_library_diff(
                    crate::cli::library_diff::LibraryDiffOptions {
                        a: std::path::Path::new(&a),
                        b: std::path::Path::new(&b),
                    },
                    output_mode,
                )?;
            }
        },
        Commands::Form(action) => match action {
            crate::cli::FormAction::Spec {
                name,
                os,
                os_version,
                annotate,
                schema_path,
                beta,
                output,
            } => {
                crate::cli::form::handle_spec(
                    name.as_deref(),
                    os.as_deref(),
                    os_version.as_deref(),
                    annotate,
                    schema_path.as_deref(),
                    channel.or_beta(beta),
                    output.as_deref(),
                    output_mode,
                )?;
            }
            crate::cli::FormAction::Parse {
                file,
                os,
                schema_path,
                beta,
            } => {
                crate::cli::form::handle_parse(
                    &file,
                    os.as_deref(),
                    schema_path.as_deref(),
                    channel.or_beta(beta),
                    output_mode,
                )?;
            }
            crate::cli::FormAction::Emit {
                name,
                values,
                org,
                intent,
                os,
                os_version,
                mcx,
                direct,
                output,
                write,
                schema_path,
                beta,
            } => {
                crate::cli::form::handle_emit(
                    &name,
                    &values,
                    org.as_deref(),
                    &intent,
                    os.as_deref(),
                    os_version.as_deref(),
                    mcx,
                    direct,
                    output.as_deref(),
                    write,
                    config.as_ref(),
                    schema_path.as_deref(),
                    channel.or_beta(beta),
                    output_mode,
                )?;
            }
        },
        Commands::Windows { 0: action } => match action {
            crate::cli::WindowsAction::Stig { action } => {
                let json = matches!(output_mode, OutputMode::Json);
                match action {
                    crate::cli::StigAction::List => crate::cli::windows_stig::handle_list(json)?,
                    crate::cli::StigAction::Search { term, profile } => {
                        crate::cli::windows_stig::handle_search(&term, profile.as_deref(), json)?
                    }
                    crate::cli::StigAction::Show { target } => {
                        crate::cli::windows_stig::handle_show(&target, json)?
                    }
                    crate::cli::StigAction::Export { profile, output } => {
                        crate::cli::windows_stig::handle_export(
                            &profile,
                            output.as_deref().map(std::path::Path::new),
                            json,
                        )?
                    }
                }
            }
            crate::cli::WindowsAction::Apps { action } => {
                let json = matches!(output_mode, OutputMode::Json);
                match action {
                    crate::cli::AppsAction::List => crate::cli::windows_apps::handle_list(json)?,
                    crate::cli::AppsAction::Search { term, app } => {
                        crate::cli::windows_apps::handle_search(&term, app.as_deref(), json)?
                    }
                    crate::cli::AppsAction::Show { app, policy } => {
                        crate::cli::windows_apps::handle_show(&app, &policy, json)?
                    }
                }
            }
            crate::cli::WindowsAction::Generate {
                input,
                output,
                envelope,
                write,
                admx_dir,
            } => {
                crate::cli::windows_generate::handle_generate(
                    &input,
                    output.as_deref(),
                    envelope,
                    write,
                    admx_dir.as_deref(),
                    matches!(output_mode, OutputMode::Json),
                )?;
            }
        },
        Commands::Ddm { action } => match action {
            DdmAction::Legacy(action) => match action {
                crate::cli::LegacyAction::Convert {
                    paths,
                    url_template,
                    sha,
                    predicate,
                    no_subscriptions,
                    org,
                    output,
                    recursive,
                    naming,
                    gitops,
                    write,
                } => {
                    crate::cli::ddm_legacy::handle_legacy_convert(
                        &paths,
                        &url_template,
                        sha.as_deref(),
                        predicate.as_deref(),
                        no_subscriptions,
                        org.as_deref(),
                        output.as_deref(),
                        recursive,
                        &naming,
                        gitops,
                        write,
                        config.as_ref(),
                        output_mode,
                    )?;
                }
                crate::cli::LegacyAction::Refresh {
                    declarations,
                    against,
                    sha,
                    write,
                } => {
                    crate::cli::ddm_legacy::handle_legacy_refresh(
                        &declarations,
                        &against,
                        &sha,
                        write,
                        output_mode,
                    )?;
                }
            },
            DdmAction::Status {
                query,
                platform,
                errors,
            } => {
                crate::cli::ddm_status::handle_status(
                    query.as_deref(),
                    platform.as_deref(),
                    errors,
                    output_mode,
                )?;
            }
            DdmAction::AppControl(action) => match action {
                crate::cli::AppControlAction::Scan {
                    paths,
                    interactive,
                    deny,
                    no_apple,
                    rule_type,
                    always_allow_managed,
                    output,
                } => crate::cli::ddm_app_control::handle_scan(
                    &paths,
                    interactive,
                    deny,
                    rule_type,
                    always_allow_managed,
                    no_apple,
                    output.as_deref(),
                    matches!(output_mode, OutputMode::Json),
                )?,
                crate::cli::AppControlAction::Generate {
                    input,
                    org,
                    output,
                    write,
                } => crate::cli::ddm_app_control::handle_generate(
                    &input,
                    org.as_deref(),
                    config.as_ref(),
                    output.as_deref(),
                    write,
                    matches!(output_mode, OutputMode::Json),
                )?,
            },
            DdmAction::AppPrivacy(action) => match action {
                crate::cli::AppPrivacyAction::Scan {
                    apps,
                    interactive,
                    skip_unreadable,
                    output,
                } => {
                    crate::cli::ddm_app_privacy::handle_scan(
                        &apps,
                        interactive,
                        skip_unreadable,
                        output.as_deref(),
                        matches!(output_mode, OutputMode::Json),
                    )?;
                }
                crate::cli::AppPrivacyAction::Generate {
                    input,
                    org,
                    output,
                    payload_scope,
                    write,
                } => {
                    crate::cli::ddm_app_privacy::handle_generate(
                        &input,
                        org.as_deref(),
                        config.as_ref(),
                        output.as_deref(),
                        payload_scope.as_deref(),
                        write,
                        matches!(output_mode, OutputMode::Json),
                    )?;
                }
                crate::cli::AppPrivacyAction::ImportPppc { input, output } => {
                    crate::cli::ddm_app_privacy::handle_import_pppc(
                        &input,
                        output.as_deref(),
                        matches!(output_mode, OutputMode::Json),
                    )?;
                }
            },
            DdmAction::ServiceConfig(action) => match action {
                crate::cli::ServiceConfigAction::Build {
                    source,
                    service,
                    base_url,
                    url_template,
                    intent,
                    predicate,
                    no_subscriptions,
                    org,
                    output,
                    write,
                } => {
                    crate::cli::ddm_service_config::handle_build(
                        &source,
                        &service,
                        base_url.as_deref(),
                        &url_template,
                        intent.as_deref(),
                        predicate.as_deref(),
                        no_subscriptions,
                        org.as_deref(),
                        output.as_deref(),
                        write,
                        config.as_ref(),
                        output_mode,
                    )?;
                }
                crate::cli::ServiceConfigAction::Rehost {
                    declarations,
                    base_url,
                    verify,
                    write,
                } => {
                    crate::cli::ddm_service_config::handle_rehost(
                        &declarations,
                        &base_url,
                        verify,
                        write,
                        output_mode,
                    )?;
                }
            },
            DdmAction::Reidentify {
                paths,
                from,
                to,
                from_prefix,
                to_prefix,
                recursive,
                write,
            } => {
                crate::cli::ddm_reidentify::handle_ddm_reidentify(
                    &paths,
                    from.as_deref(),
                    to.as_deref(),
                    from_prefix.as_deref(),
                    to_prefix.as_deref(),
                    recursive,
                    write,
                    output_mode,
                )?;
            }
            DdmAction::Beta {
                mode,
                tokens,
                select,
                split_by_os,
                interactive,
                output,
                org,
                identifier,
            } => {
                crate::cli::ddm_beta::handle_ddm_beta(
                    mode,
                    tokens.as_deref(),
                    &select,
                    split_by_os,
                    interactive,
                    org.as_deref(),
                    identifier.as_deref(),
                    output.as_deref(),
                    config.as_ref(),
                    output_mode,
                )?;
            }
            DdmAction::Parse {
                paths,
                recursive,
                max_depth,
                no_parallel,
            } => {
                let parallel = !no_parallel;
                crate::cli::ddm::handle_ddm_parse(
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
                beta,
                platforms,
            } => {
                let beta = beta || channel.is_beta();
                let parallel = !no_parallel;
                crate::cli::ddm::handle_ddm_validate(
                    &paths,
                    schema_path.as_deref(),
                    recursive,
                    max_depth,
                    parallel,
                    beta,
                    &platforms,
                    output_mode,
                )?;
            }
            DdmAction::Search {
                query,
                schema_path,
                beta,
            } => {
                let beta = beta || channel.is_beta();
                crate::cli::ddm::handle_ddm_search(
                    &query,
                    schema_path.as_deref(),
                    beta,
                    output_mode,
                )?;
            }
            DdmAction::List {
                category,
                schema_path,
                beta,
            } => {
                let beta = beta || channel.is_beta();
                crate::cli::ddm::handle_ddm_list(
                    category.as_deref(),
                    schema_path.as_deref(),
                    beta,
                    output_mode,
                )?;
            }
            DdmAction::Info {
                name,
                schema_path,
                beta,
                full,
            } => {
                let beta = beta || channel.is_beta();
                crate::cli::ddm::handle_ddm_info(
                    &name,
                    schema_path.as_deref(),
                    beta,
                    full,
                    output_mode,
                )?;
            }
            DdmAction::Map { name } => {
                crate::cli::ddm::handle_ddm_map(name.as_deref(), output_mode)?;
            }
            DdmAction::Coverage { beta } => {
                crate::cli::ddm::handle_ddm_coverage(channel.or_beta(beta), output_mode)?;
            }
            DdmAction::Generate {
                name,
                output,
                full,
                org,
                identifier,
                schema_path,
                payload,
                beta,
            } => {
                let beta = beta || channel.is_beta();
                crate::cli::ddm::handle_ddm_generate(
                    &name,
                    output.as_deref(),
                    full,
                    org.as_deref(),
                    identifier.as_deref(),
                    schema_path.as_deref(),
                    payload.as_deref(),
                    beta,
                    config.as_ref(),
                    output_mode,
                )?;
            }
            DdmAction::Transform {
                example_file,
                values,
                org,
                output,
                strict,
                scan,
                permissions,
                deny,
                type_name,
                example,
                beta,
            } => {
                let beta = beta || channel.is_beta();
                crate::cli::transform::handle_ddm_transform(
                    example_file.as_deref(),
                    values.as_deref(),
                    &scan,
                    permissions.as_deref(),
                    deny,
                    org.as_deref(),
                    output.as_deref(),
                    strict,
                    config.as_ref(),
                    output_mode,
                    type_name.as_deref(),
                    example,
                    beta,
                )?;
            }
            DdmAction::Examples { name, beta } => {
                crate::cli::ddm::handle_ddm_examples(
                    &name,
                    beta || channel.is_beta(),
                    output_mode,
                )?;
            }
            DdmAction::Compose {
                bundle,
                output,
                schema_path,
                allow_orphans,
                org,
                platforms,
                preset,
                preset_path,
                list_presets,
            } => {
                crate::cli::ddm::handle_ddm_compose(
                    bundle.as_deref(),
                    output.as_deref(),
                    schema_path.as_deref(),
                    allow_orphans,
                    org.as_deref(),
                    preset.as_deref(),
                    preset_path.as_deref(),
                    list_presets,
                    &platforms,
                    config.as_ref(),
                    output_mode,
                )?;
            }
            DdmAction::Verify {
                directory,
                recursive,
                strict,
            } => {
                crate::cli::ddm::handle_ddm_verify(&directory, recursive, strict, output_mode)?;
            }
        },
        Commands::Enrollment { action } => match action {
            EnrollmentAction::List {
                platform,
                os_version,
                beta,
                deprecated,
            } => {
                let beta = beta || channel.is_beta();
                crate::cli::enrollment::handle_enrollment_list(
                    &platform,
                    os_version.as_deref(),
                    beta,
                    deprecated,
                    output_mode,
                )?;
            }
            EnrollmentAction::Generate {
                platform,
                os_version,
                skip_all,
                skip,
                skip_list,
                output,
                profile_name,
                interactive,
                beta,
                preset,
                language,
                region,
                readme,
            } => {
                let beta = beta || channel.is_beta();
                crate::cli::enrollment::handle_enrollment_generate(
                    &platform,
                    os_version.as_deref(),
                    skip_all,
                    &skip,
                    skip_list.as_deref(),
                    output.as_deref(),
                    &profile_name,
                    interactive,
                    beta,
                    preset.as_deref(),
                    language.as_deref(),
                    region.as_deref(),
                    readme,
                    output_mode,
                )?;
            }
            EnrollmentAction::Presets => {
                crate::cli::enrollment::handle_enrollment_presets(output_mode)?;
            }
            EnrollmentAction::Migrate {
                input,
                to_version,
                platform,
                output,
                beta,
            } => {
                let beta = beta || channel.is_beta();
                crate::cli::enrollment::handle_enrollment_migrate(
                    &input,
                    &to_version,
                    &platform,
                    output.as_deref(),
                    beta,
                    output_mode,
                )?;
            }
        },
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
            md_report,
        } => {
            let opts = crate::cli::plan::PlanOptions {
                recursive,
                predictable,
                org,
                org_name: None,
                format,
                accept_replace,
                accept_scope_change,
                fleet_size,
                md_report,
            };
            crate::cli::plan::handle_plan(&baseline, &proposed, &opts)?;
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
            let opts = crate::cli::rollback::RollbackCliOptions {
                recursive,
                uuids_only,
                payload_types,
                refs_only,
                no_rewrite_refs,
                dry_run,
                output_dir: output.map(std::path::PathBuf::from),
            };
            crate::cli::rollback::handle_rollback(&baseline, &current, &opts)?;
        }
    }

    Ok(())
}
