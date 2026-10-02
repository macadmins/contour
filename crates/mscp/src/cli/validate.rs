use crate::output::{OutputMode, ValidationResult};
use crate::validators::{SchemaOrigin, SchemaValidator};
use anyhow::Result;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

/// What `[validation]` in mscp.toml resolves to for one `validate` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationOptions {
    pub schemas_path: Option<PathBuf>,
    pub strict: bool,
    pub validate_paths: bool,
}

/// Combine `mscp validate` flags with `[validation]` from an mscp.toml.
///
/// All three fields were parsed and never read: `validate` took no `--config`,
/// so the section was unreachable from the one command it describes, and the
/// generated template documented it anyway.
///
/// Flags win where given. `--strict` and `strict = true` each turn strict mode
/// on — a flag cannot turn off what the config asked for, because silently
/// relaxing a check someone wrote down is the failure this repo keeps finding.
/// A relative `schemas_path` resolves against the config file's directory,
/// not the shell's: a path in a config file means the same thing wherever the
/// command is run from.
pub fn resolve_validation_options(
    config_path: Option<&std::path::Path>,
    cli_schemas: Option<PathBuf>,
    cli_strict: bool,
) -> Result<ValidationOptions> {
    let Some(config_path) = config_path else {
        return Ok(ValidationOptions {
            schemas_path: cli_schemas,
            strict: cli_strict,
            validate_paths: true,
        });
    };
    let config = crate::config::load_config(config_path)?;
    let v = &config.validation;
    let from_config = v.schemas_path.as_ref().map(|p| {
        if p.is_absolute() {
            p.clone()
        } else {
            config_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(p)
        }
    });
    Ok(ValidationOptions {
        schemas_path: cli_schemas.or(from_config),
        strict: cli_strict || v.strict,
        validate_paths: v.validate_paths,
    })
}

/// Validate command - check output structure and schemas
pub fn validate_output(
    output_path: PathBuf,
    schemas_path: Option<PathBuf>,
    strict: bool,
    validate_paths: bool,
    output_mode: OutputMode,
) -> Result<()> {
    tracing::info!(
        "Validating Fleet GitOps output at: {}",
        output_path.display()
    );

    let mut result = ValidationResult::new(output_path.to_string_lossy().to_string(), strict);

    // Step 1: Check directory structure
    if output_mode == OutputMode::Human {
        println!("{}", "Checking directory structure...".cyan());
    }
    // Fleet v4.83+ layout: baseline components live at mscp/{baseline}/baseline.toml
    // (no longer under lib/mscp/). See sop-format-spec.md migration history.
    let mscp_dir = output_path.join("mscp");
    let fleets_dir = output_path.join("fleets");

    if !mscp_dir.exists() {
        result.add_error("Missing mscp/ directory (run `contour mscp generate` to populate)");
    } else if output_mode == OutputMode::Human {
        println!("  {} mscp/ directory exists", "✓".green());
    }

    if !fleets_dir.exists() {
        result.add_error("Missing fleets directory");
    } else if output_mode == OutputMode::Human {
        println!("  {} fleets directory exists", "✓".green());
    }

    // Step 2: Validate team YAML files
    if output_mode == OutputMode::Human {
        println!("\n{}", "Validating team YAML files...".cyan());
    }
    // Resolve the schema before any file is read. Asking for schema
    // validation and not getting it is a configuration error — the check the
    // operator requested never ran — so a --schemas dir without one fails
    // here, once, whatever `--strict` says. Non-strict mode softens findings;
    // it should not soften "there was nothing to find them with".
    //
    // With no dir, the pinned schema this build embeds is the default. A build that
    // embeds none is stated — a warning, visible under --json, or an error
    // under --strict, like every other softened finding here — never a
    // silent structural-only pass.
    let (validator, origin) = SchemaValidator::resolve(schemas_path.as_deref())?;
    result.schema = Some(origin.to_string());
    if origin == SchemaOrigin::Absent {
        let msg = "No Fleet GitOps schema: this build's mscp-schema dataset carries none, so only the structural checks ran. Pass --schemas <dir> \
                   holding Fleet's generated-schema.json, or rebuild against a newer dataset.";
        if strict {
            result.add_error(msg);
        } else {
            result.add_warning(msg);
        }
        if output_mode == OutputMode::Human {
            println!("  {} schema: {origin}", "⚠".yellow());
        }
    } else if output_mode == OutputMode::Human {
        println!("  {} schema: {origin}", "✓".green());
    }

    for entry in WalkDir::new(&fleets_dir)
        .max_depth(1)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("yml")
            || path.extension().and_then(|s| s.to_str()) == Some("yaml")
        {
            result.fleet_files_checked += 1;

            match validator.validate_fleet_yaml(path) {
                Ok(validation_result) => {
                    if validation_result.valid {
                        result.fleet_files_valid += 1;
                        if output_mode == OutputMode::Human {
                            println!(
                                "  {} {} - {}",
                                "✓".green(),
                                path.file_name().unwrap_or_default().to_string_lossy(),
                                "valid".green()
                            );
                        }
                    } else {
                        result.fleet_files_invalid += 1;
                        if output_mode == OutputMode::Human {
                            println!(
                                "  {} {} - {}",
                                "✗".red(),
                                path.file_name().unwrap_or_default().to_string_lossy(),
                                "invalid".red()
                            );
                        }
                        for error in &validation_result.errors {
                            if output_mode == OutputMode::Human {
                                println!("    {} {}", "-".dimmed(), error.red());
                            }
                            result.add_error(format!("{}: {}", path.display(), error));
                        }
                    }
                }
                Err(e) => {
                    result.fleet_files_invalid += 1;
                    if output_mode == OutputMode::Human {
                        println!(
                            "  {} {} - {}: {}",
                            "✗".red(),
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            "error".red(),
                            e
                        );
                    }
                    result.add_error(format!("{}: {}", path.display(), e));
                }
            }

            // Validate file paths exist — unless `[validation] validate_paths =
            // false`. That setting was documented and never consulted; the
            // check ran unconditionally.
            if !validate_paths {
                continue;
            }
            match validator.validate_file_paths(path, &output_path) {
                Ok(path_result) => {
                    if !path_result.valid {
                        if output_mode == OutputMode::Human {
                            println!("    {}", "⚠ Missing referenced files:".yellow());
                        }
                        for missing in &path_result.missing_paths {
                            if output_mode == OutputMode::Human {
                                println!("      {} {}", "-".dimmed(), missing.yellow());
                            }
                            let msg = format!("Missing file: {missing}");
                            if strict {
                                result.add_error(msg);
                            } else {
                                result.add_warning(msg);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to validate paths: {}", e);
                }
            }
        }
    }

    // Step 3: Check for conflicts if multiple baselines exist
    if output_mode == OutputMode::Human {
        println!("\n{}", "Checking for baseline conflicts...".cyan());
    }
    let baselines = find_baselines(&output_path)?;
    result.baselines_found = baselines.len();

    if baselines.len() > 1 {
        // This is a simplified check - in production you'd load actual baseline data
        if output_mode == OutputMode::Human {
            println!(
                "  {} {} baselines, conflict detection skipped (requires processed data)",
                "Found".dimmed(),
                baselines.len()
            );
        }
    } else if output_mode == OutputMode::Human {
        println!("  {} Single baseline, no conflicts possible", "✓".green());
    }

    // Output results
    match output_mode {
        OutputMode::Json => {
            crate::output::json::output_validation_result(&result)?;
        }
        OutputMode::Human => {
            // Summary
            println!("\n{}", "=".repeat(50));
            if result.success {
                println!("{}", "✓ Validation PASSED".green().bold());
                println!("  All checks completed successfully");
            } else {
                println!("{}", "✗ Validation FAILED".red().bold());
                println!("  {} error(s) found:", result.errors.len());
                for error in &result.errors {
                    println!("    {} {}", "-".dimmed(), error.red());
                }
                if !strict {
                    println!(
                        "\n  {}",
                        "(Non-strict mode: some errors are warnings)".dimmed()
                    );
                }
            }
        }
    }

    if !result.success && strict {
        anyhow::bail!("Validation failed");
    }

    Ok(())
}

/// Find baselines in the output directory.
///
/// Fleet v4.83+ layout: each baseline lives at `mscp/{name}/baseline.toml`.
/// We list immediate children of `mscp/`, skipping the `versions/` subdir
/// which holds the manifest file rather than a baseline.
fn find_baselines(output_path: &PathBuf) -> Result<Vec<String>> {
    let mut baselines = Vec::new();
    let mscp_dir = output_path.join("mscp");

    if mscp_dir.exists() {
        for entry in fs::read_dir(&mscp_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && let Some(name) = entry.file_name().to_str()
                && name != "versions"
            {
                baselines.push(name.to_string());
            }
        }
    }

    Ok(baselines)
}

#[cfg(test)]
mod validation_options_tests {
    use super::*;

    fn config_with(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mscp.toml");
        std::fs::write(
            &path,
            format!(
                "[settings]\nmscp_repo = \"./macos_security\"\noutput_dir = \"./out\"\n\n{body}"
            ),
        )
        .expect("write config");
        (dir, path)
    }

    /// No config: the flags are the whole story, and paths are checked.
    #[test]
    fn without_a_config_the_flags_decide() {
        let o = resolve_validation_options(None, Some("/s".into()), true).expect("ok");
        assert_eq!(o.schemas_path, Some(PathBuf::from("/s")));
        assert!(o.strict);
        assert!(o.validate_paths, "the path check is on by default");
    }

    /// `[validation]` was unreachable from the command it describes.
    #[test]
    fn the_config_section_reaches_validate() {
        let (_d, cfg) = config_with(
            "[validation]\nschemas_path = \"/abs/schemas\"\nstrict = true\nvalidate_paths = false\n",
        );
        let o = resolve_validation_options(Some(&cfg), None, false).expect("ok");
        assert_eq!(o.schemas_path, Some(PathBuf::from("/abs/schemas")));
        assert!(o.strict, "strict = true in the config must take effect");
        assert!(
            !o.validate_paths,
            "validate_paths = false must take effect — it was never consulted"
        );
    }

    /// A flag names a schema directory; the flag wins.
    #[test]
    fn the_schemas_flag_overrides_the_config() {
        let (_d, cfg) = config_with("[validation]\nschemas_path = \"/from/config\"\n");
        let o =
            resolve_validation_options(Some(&cfg), Some("/from/flag".into()), false).expect("ok");
        assert_eq!(o.schemas_path, Some(PathBuf::from("/from/flag")));
    }

    /// Neither side can relax what the other asked for.
    ///
    /// Silently loosening a check someone wrote down is the failure this repo
    /// keeps finding, so strict is an OR, not an override.
    #[test]
    fn strict_is_on_if_either_side_asks() {
        let (_d, on) = config_with("[validation]\nstrict = true\n");
        let (_e, off) = config_with("[validation]\nstrict = false\n");
        assert!(
            resolve_validation_options(Some(&on), None, false)
                .unwrap()
                .strict
        );
        assert!(
            resolve_validation_options(Some(&off), None, true)
                .unwrap()
                .strict
        );
        assert!(
            !resolve_validation_options(Some(&off), None, false)
                .unwrap()
                .strict
        );
    }

    /// A path in a config file means the same thing wherever you run from.
    #[test]
    fn a_relative_schemas_path_resolves_against_the_config_file() {
        let (dir, cfg) = config_with("[validation]\nschemas_path = \"schemas\"\n");
        let o = resolve_validation_options(Some(&cfg), None, false).expect("ok");
        assert_eq!(
            o.schemas_path,
            Some(dir.path().join("schemas")),
            "relative to the config's directory, not the shell's"
        );
    }

    /// Asking for a schema and not getting one fails, rather than passing.
    #[test]
    fn a_schemas_path_with_no_schema_in_it_is_an_error() {
        let empty = tempfile::tempdir().expect("tempdir");
        let err = crate::validators::SchemaValidator::resolve_schema_path(empty.path())
            .expect_err("an empty directory holds no schema");
        let msg = err.to_string();
        assert!(
            msg.contains("generated-schema.json"),
            "names Fleet's file: {msg}"
        );
        assert!(msg.contains("fleetdm/fleet"), "says where to get it: {msg}");
    }

    /// Fleet's own filename is found.
    #[test]
    fn fleets_schema_filename_is_recognised() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("generated-schema.json"), "{}").expect("write");
        let found = crate::validators::SchemaValidator::resolve_schema_path(dir.path())
            .expect("Fleet's filename must be accepted");
        assert!(found.ends_with("generated-schema.json"));
    }
}
