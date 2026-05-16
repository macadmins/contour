//! Validation CLI handlers
//!
//! Schema validation is enabled by default - validates payload fields against
//! 261 embedded Apple payload schemas.

use crate::cli::glob_utils::{
    collect_profile_files_multi_with_depth, print_batch_summary, process_parallel_with_warnings,
    process_sequential_with_warnings, should_batch_process_multi,
};
use crate::migrate::mapping::MigrationRegistry;
use crate::output::OutputMode;
use crate::profile::{
    lint::{self, LintOptions},
    parser, validator,
};
use crate::schema::SchemaRegistry;
use crate::schema::lookup::load_known_identifiers;
use crate::validation::{SchemaValidator, Severity, ValidationOptions};
use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::HashSet;
use std::path::Path;

/// Main entry point for validate command with batch support.
#[expect(
    clippy::too_many_arguments,
    reason = "validate handler threads many CLI flags"
)]
pub fn handle_validate(
    paths: &[String],
    schema: bool,
    schema_path: Option<&str>,
    lookup: Option<&str>,
    strict: bool,
    lint_policy: &[String],
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    output_mode: OutputMode,
    report: Option<&str>,
    allow_placeholders: bool,
) -> Result<()> {
    // Resolve --lint-policy + --strict into a LintOptions once.
    // Errors fast on unknown check names so a typo can't silently
    // skip a check the user thought they enabled.
    let lint_options = resolve_lint_options(strict, lint_policy)?;

    // Resolve lookup path: CLI flag > config.toml manifests_path
    let lookup_path = lookup.map(std::path::PathBuf::from).or_else(|| {
        contour_core::ContourConfig::load_nearest().and_then(|c| c.defaults.manifests_path)
    });

    // Load known identifiers if a lookup path was resolved
    let known_ids = if let Some(ref path) = lookup_path {
        let ids = load_known_identifiers(path)?;
        if output_mode == OutputMode::Human {
            println!(
                "{}",
                format!(
                    "✓ Loaded {} known identifiers from ProfileManifests",
                    ids.len()
                )
                .green()
            );
        }
        Some(ids)
    } else {
        None
    };

    if should_batch_process_multi(paths) {
        handle_validate_batch(
            paths,
            schema,
            schema_path,
            known_ids.as_ref(),
            strict,
            &lint_options,
            recursive,
            max_depth,
            parallel,
            output_mode,
            report,
            allow_placeholders,
        )
    } else {
        handle_validate_single(
            &paths[0],
            schema,
            schema_path,
            known_ids.as_ref(),
            strict,
            &lint_options,
            output_mode,
            allow_placeholders,
        )
    }
}

/// Resolve `--lint-policy <names...>` + `--strict` into a `LintOptions`.
///
/// Empty `lint_policy` (no flag passed) → `selected_checks: None`,
/// meaning the lint pass runs Tier-1 only.
///
/// `all` expands to every Tier-2 check; explicit names must match
/// `lint::TIER_2_CHECKS` exactly. Unknown names produce a fail-fast
/// error listing the valid ones — a typo can't silently skip the check
/// the user thought they enabled.
///
/// `apply_modes` is left empty here — call sites that have a
/// `SchemaRegistry` inject it via `with_apply_modes()` before passing
/// the options into `lint::lint_profile_with_options`.
fn resolve_lint_options(strict: bool, lint_policy: &[String]) -> Result<LintOptions> {
    if lint_policy.is_empty() {
        return Ok(LintOptions {
            strict,
            selected_checks: None,
            apply_modes: std::collections::HashMap::new(),
        });
    }
    let mut chosen: HashSet<String> = HashSet::new();
    for raw in lint_policy {
        let name = raw.trim();
        if name == "all" {
            chosen.extend(lint::TIER_2_CHECKS.iter().map(|s| (*s).to_string()));
            continue;
        }
        if !lint::TIER_2_CHECKS.contains(&name) {
            let valid = lint::TIER_2_CHECKS.join(", ");
            anyhow::bail!("Unknown --lint-policy check '{name}'. Valid: all, {valid}");
        }
        chosen.insert(name.to_string());
    }
    // Tier-1 always fires, even when --lint-policy is set.
    chosen.extend(lint::TIER_1_CHECKS.iter().map(|s| (*s).to_string()));
    Ok(LintOptions {
        strict,
        selected_checks: Some(chosen),
        apply_modes: std::collections::HashMap::new(),
    })
}

/// Build a `payload_type → apply_mode` map for the lint pass. Returns
/// an empty map when no registry is available — `single-instance-
/// payload-repeated` becomes a no-op in that case.
fn apply_modes_from_registry(
    registry: Option<&SchemaRegistry>,
) -> std::collections::HashMap<String, String> {
    let Some(reg) = registry else {
        return std::collections::HashMap::new();
    };
    reg.all()
        .filter_map(|m| {
            m.apply_mode
                .as_ref()
                .map(|mode| (m.payload_type.clone(), mode.clone()))
        })
        .collect()
}

#[expect(
    clippy::too_many_arguments,
    reason = "validate handler threads many CLI flags"
)]
fn handle_validate_batch(
    paths: &[String],
    schema: bool,
    schema_path: Option<&str>,
    known_ids: Option<&HashSet<String>>,
    strict: bool,
    lint_options: &LintOptions,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    output_mode: OutputMode,
    report: Option<&str>,
    allow_placeholders: bool,
) -> Result<()> {
    let files = collect_profile_files_multi_with_depth(paths, recursive, max_depth)?;

    if files.is_empty() {
        if output_mode == OutputMode::Human {
            println!("{}", "No .mobileconfig files found".yellow());
        } else {
            let result = serde_json::json!({
                "success": true,
                "total": 0,
                "message": "No .mobileconfig files found"
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    // Load schema registry once for all validations
    let registry = if schema {
        Some(if let Some(sp) = schema_path {
            SchemaRegistry::from_auto_detect(Path::new(sp))?
        } else {
            SchemaRegistry::embedded()?
        })
    } else {
        None
    };

    let options = if strict {
        ValidationOptions::strict()
    } else {
        ValidationOptions::default_checks()
    };

    // Detailed mode: JSON output or markdown report
    if output_mode == OutputMode::Json || report.is_some() {
        let detailed_results: Vec<DetailedValidationResult> = files
            .iter()
            .map(|f| {
                validate_single_file_detailed(
                    f,
                    schema,
                    registry.as_ref(),
                    &options,
                    known_ids,
                    allow_placeholders,
                    lint_options,
                )
            })
            .collect();

        let failed = detailed_results.iter().filter(|r| !r.valid).count();

        // Write markdown report if requested
        if let Some(report_path) = report {
            let md = generate_markdown_report(&detailed_results);
            std::fs::write(report_path, &md)?;
            if output_mode == OutputMode::Human {
                println!(
                    "{} Validation report written to {}",
                    "✓".green(),
                    report_path.cyan()
                );
            }
        }

        if output_mode == OutputMode::Json {
            let json = serde_json::json!({
                "operation": "validate",
                "success": failed == 0,
                "total": detailed_results.len(),
                "succeeded": detailed_results.len() - failed,
                "failed": failed,
                "results": detailed_results.iter().map(|r| {
                    let mut entry = serde_json::json!({
                        "file": r.file,
                        "valid": r.valid,
                        "errors": r.errors,
                        "warnings": r.warnings,
                        "profile": r.profile,
                        // Lint findings are emitted as a separate array
                        // keyed by stable check name. Existing consumers
                        // that key on errors/warnings keep working — lint
                        // messages are mirrored there with a `[<check>]`
                        // prefix for backwards compat.
                        "lint_findings": r.lint_findings,
                    });
                    if let Some(ref sv) = r.schema_validation {
                        entry["schema_validation"] = sv.clone();
                    }
                    entry
                }).collect::<Vec<_>>(),
            });

            println!("{}", serde_json::to_string_pretty(&json)?);
        }

        if failed > 0 {
            anyhow::bail!("{failed} file(s) failed validation");
        }

        if report.is_some() && output_mode != OutputMode::Json {
            return Ok(());
        }

        if output_mode == OutputMode::Json {
            return Ok(());
        }
    }

    // Human mode: use the standard batch pipeline
    println!(
        "{}",
        format!("Validating {} profile(s)...", files.len()).cyan()
    );

    let validate_file = |file_path: &Path| -> Result<Vec<String>> {
        let result = validate_single_file_internal(
            file_path,
            schema,
            registry.as_ref(),
            &options,
            known_ids,
        )?;
        Ok(result.warnings)
    };

    let result = if parallel {
        process_parallel_with_warnings(&files, validate_file, output_mode)
    } else {
        process_sequential_with_warnings(&files, validate_file, output_mode)
    };

    print_batch_summary(&result, "Validation");

    if result.failed > 0 {
        anyhow::bail!("{} file(s) failed validation", result.failed);
    }

    Ok(())
}

/// Result of validating a single file, including any warnings
struct SingleFileValidationResult {
    warnings: Vec<String>,
}

/// Detailed validation result for JSON output — matches single-file JSON structure
struct DetailedValidationResult {
    file: String,
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
    profile: serde_json::Value,
    schema_validation: Option<serde_json::Value>,
    /// Lint findings keyed by check name. Side-channel from
    /// `errors`/`warnings` so consumers that key on the legacy fields
    /// keep working unchanged. Each entry: `{check, severity, message,
    /// payload_index?}`.
    lint_findings: Vec<serde_json::Value>,
}

/// Detailed validation for JSON batch output — captures the same structure as single-file JSON
fn validate_single_file_detailed(
    file_path: &Path,
    schema: bool,
    registry: Option<&SchemaRegistry>,
    options: &ValidationOptions,
    known_ids: Option<&HashSet<String>>,
    allow_placeholders: bool,
    lint_options: &LintOptions,
) -> DetailedValidationResult {
    let file = file_path.to_str().unwrap_or_default().to_string();

    // Try normal parse first
    let (profile, placeholder_warnings) = match parser::parse_profile_auto_unsign(&file) {
        Ok(p) => (p, vec![]),
        Err(e) if allow_placeholders => {
            // Parse failed — try with placeholder substitution
            match std::fs::read(file_path) {
                Ok(raw) => {
                    let pr = parser::substitute_placeholders(&raw);
                    if pr.placeholders.is_empty() {
                        // No placeholders found, original error stands
                        return DetailedValidationResult {
                            file,
                            valid: false,
                            errors: vec![format!("Failed to parse: {e}")],
                            warnings: vec![],
                            profile: serde_json::json!(null),
                            schema_validation: None,
                            lint_findings: vec![],
                        };
                    }
                    match parser::parse_profile_from_bytes(&pr.substituted) {
                        Ok(p) => {
                            let warns: Vec<String> = pr
                                .placeholders
                                .iter()
                                .map(|ph| format!("MDM placeholder: {ph}"))
                                .collect();
                            (p, warns)
                        }
                        Err(e2) => {
                            return DetailedValidationResult {
                                file,
                                valid: false,
                                errors: vec![format!(
                                    "Failed to parse (even with placeholder substitution): {e2}"
                                )],
                                warnings: pr
                                    .placeholders
                                    .iter()
                                    .map(|ph| format!("MDM placeholder found: {ph}"))
                                    .collect(),
                                profile: serde_json::json!(null),
                                schema_validation: None,
                                lint_findings: vec![],
                            };
                        }
                    }
                }
                Err(_) => {
                    return DetailedValidationResult {
                        file,
                        valid: false,
                        errors: vec![format!("Failed to parse: {e}")],
                        warnings: vec![],
                        profile: serde_json::json!(null),
                        schema_validation: None,
                        lint_findings: vec![],
                    };
                }
            }
        }
        Err(e) => {
            return DetailedValidationResult {
                file,
                valid: false,
                errors: vec![format!("Failed to parse: {e}")],
                warnings: vec![],
                profile: serde_json::json!(null),
                schema_validation: None,
                lint_findings: vec![],
            };
        }
    };

    let validation = match validator::validate_profile(&profile) {
        Ok(v) => v,
        Err(e) => {
            return DetailedValidationResult {
                file,
                valid: false,
                errors: vec![format!("Validation error: {e}")],
                warnings: vec![],
                profile: serde_json::json!(null),
                schema_validation: None,
                lint_findings: vec![],
            };
        }
    };

    let profile_json = serde_json::json!({
        "display_name": profile.payload_display_name,
        "identifier": profile.payload_identifier,
        "uuid": profile.payload_uuid,
        "type": profile.payload_type,
        "version": profile.payload_version,
        "payload_count": profile.payload_content.len(),
        "organization": profile.payload_organization(),
        "payloads": profile.payload_content.iter().map(|p| {
            serde_json::json!({
                "type": p.payload_type,
                "display_name": p.payload_display_name(),
                "identifier": p.payload_identifier,
                "uuid": p.payload_uuid,
            })
        }).collect::<Vec<_>>(),
    });

    let schema_validation = if schema {
        if let Some(reg) = registry {
            let mut validator = SchemaValidator::with_options(reg, options.clone());
            if let Some(known) = known_ids {
                validator = validator.with_known_identifiers(known);
            }
            let sr = validator.validate(&profile);
            Some(serde_json::json!({
                "valid": sr.is_valid(),
                "payloads_validated": sr.payloads_validated,
                "payloads_unknown": sr.payloads_unknown,
                "errors": sr.errors().iter().map(|i| serde_json::json!({
                    "payload_type": i.payload_type,
                    "payload_index": i.payload_index,
                    "field": i.field,
                    "message": i.message,
                    "code": i.code,
                })).collect::<Vec<_>>(),
                "warnings": sr.warnings().iter().map(|i| serde_json::json!({
                    "payload_type": i.payload_type,
                    "payload_index": i.payload_index,
                    "field": i.field,
                    "message": i.message,
                    "code": i.code,
                })).collect::<Vec<_>>(),
            }))
        } else {
            None
        }
    } else {
        None
    };

    let schema_valid = schema_validation
        .as_ref()
        .and_then(|sv| sv.get("valid"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let mut warnings = validation.warnings;
    warnings.extend(placeholder_warnings);

    // Lint pass — re-parse the raw plist::Value so checks that need
    // the literal plist tag (e.g. <integer> vs <real>) can run.
    // Cheap on the small mobileconfig sizes we deal with; cleaner than
    // threading the value through every parse path.
    let mut lint_errors: Vec<String> = Vec::new();
    let mut lint_warnings: Vec<String> = Vec::new();
    let mut lint_findings: Vec<serde_json::Value> = Vec::new();
    if let Ok(raw_value) = plist::from_file::<_, plist::Value>(file_path) {
        let migration_registry = MigrationRegistry::new();
        // Inject apply_modes from the schema registry — clones are cheap
        // (~hundreds of small strings) and avoids passing two registries
        // through the lint API.
        let mut lint_options_with_modes = lint_options.clone();
        lint_options_with_modes.apply_modes = apply_modes_from_registry(registry);
        for finding in lint::lint_profile_with_options(
            &raw_value,
            &migration_registry,
            registry,
            &lint_options_with_modes,
        ) {
            let severity = match finding.severity {
                lint::LintSeverity::Error => "error",
                lint::LintSeverity::Warning => "warning",
            };
            let entry = serde_json::json!({
                "check": finding.check,
                "severity": severity,
                "message": finding.message,
                "payload_index": finding.payload_index,
            });
            lint_findings.push(entry);
            // Surface in the legacy errors/warnings vectors too so
            // existing JSON consumers see them without parsing the
            // new lint_findings field.
            let prefixed = format!("[{}] {}", finding.check, finding.message);
            match finding.severity {
                lint::LintSeverity::Error => lint_errors.push(prefixed),
                lint::LintSeverity::Warning => lint_warnings.push(prefixed),
            }
        }
    }
    let mut all_errors = validation.errors;
    all_errors.extend(lint_errors);
    warnings.extend(lint_warnings);

    DetailedValidationResult {
        file,
        valid: all_errors.is_empty() && schema_valid,
        errors: all_errors,
        warnings,
        profile: profile_json,
        schema_validation,
        lint_findings,
    }
}

/// Internal validation that returns Result with warnings for batch processing
fn validate_single_file_internal(
    file_path: &Path,
    schema: bool,
    registry: Option<&SchemaRegistry>,
    options: &ValidationOptions,
    known_ids: Option<&HashSet<String>>,
) -> Result<SingleFileValidationResult> {
    let file = file_path.to_str().unwrap_or_default();
    let profile = parser::parse_profile_auto_unsign(file)?;

    // Basic validation
    let validation = validator::validate_profile(&profile)?;

    // Collect warnings
    let mut warnings = Vec::new();

    // Add basic validation warnings
    for warning in &validation.warnings {
        warnings.push(warning.clone());
    }

    // Schema validation if requested
    let schema_valid = if schema {
        if let Some(reg) = registry {
            let mut validator = SchemaValidator::with_options(reg, options.clone());
            if let Some(known) = known_ids {
                validator = validator.with_known_identifiers(known);
            }
            let sr = validator.validate(&profile);

            // Collect schema warnings
            for issue in sr.warnings() {
                let location = match (issue.payload_index, &issue.field) {
                    (Some(idx), Some(field)) => format!("[{idx}].{field}"),
                    (Some(idx), None) => format!("[{idx}]"),
                    (None, Some(field)) => field.clone(),
                    (None, None) => String::new(),
                };
                let msg = if location.is_empty() {
                    format!("{}: {}", issue.payload_type, issue.message)
                } else {
                    format!("{} {}: {}", issue.payload_type, location, issue.message)
                };
                warnings.push(msg);
            }

            sr.is_valid()
        } else {
            true
        }
    } else {
        true
    };

    if !validation.valid || !schema_valid {
        // Collect error messages for the failure
        let mut errors = Vec::new();
        for error in &validation.errors {
            errors.push(error.clone());
        }
        if schema && let Some(reg) = registry {
            let mut validator = SchemaValidator::with_options(reg, options.clone());
            if let Some(known) = known_ids {
                validator = validator.with_known_identifiers(known);
            }
            let sr = validator.validate(&profile);
            for issue in sr.errors() {
                errors.push(issue.message.clone());
            }
        }
        let error_excerpt = if errors.is_empty() {
            "Validation failed".to_string()
        } else {
            errors
                .first()
                .cloned()
                .unwrap_or_else(|| "Validation failed".to_string())
        };
        anyhow::bail!("{error_excerpt}");
    }

    Ok(SingleFileValidationResult { warnings })
}

#[expect(
    clippy::too_many_arguments,
    reason = "validate handler threads many CLI flags"
)]
fn handle_validate_single(
    file: &str,
    schema: bool,
    schema_path: Option<&str>,
    known_ids: Option<&HashSet<String>>,
    strict: bool,
    lint_options: &LintOptions,
    output_mode: OutputMode,
    allow_placeholders: bool,
) -> Result<()> {
    let (profile, placeholder_warnings) = match parser::parse_profile_auto_unsign(file) {
        Ok(p) => (p, vec![]),
        Err(e) if allow_placeholders => {
            let raw = std::fs::read(file)
                .map_err(|io| anyhow::anyhow!("Failed to read file {file}: {io}"))?;
            let pr = parser::substitute_placeholders(&raw);
            if pr.placeholders.is_empty() {
                return Err(e);
            }
            let p = parser::parse_profile_from_bytes(&pr.substituted)
                .context("Failed to parse even with placeholder substitution")?;
            let warns: Vec<String> = pr
                .placeholders
                .iter()
                .map(|ph| format!("MDM placeholder: {ph}"))
                .collect();
            (p, warns)
        }
        Err(e) => return Err(e),
    };

    if output_mode == OutputMode::Human {
        println!("{}", "Validating configuration profile...".cyan());
        println!("{}", "✓ Profile parsed successfully".green());
    }

    // Basic validation
    let validation = validator::validate_profile(&profile)?;

    // Build the schema registry once — used for both schema validation
    // (when requested) and the lint pass's apply_modes lookup.
    let schema_registry = if let Some(path) = schema_path {
        Some(SchemaRegistry::from_auto_detect(Path::new(path))?)
    } else {
        Some(SchemaRegistry::embedded()?)
    };

    // Schema validation if requested
    let schema_result = if schema {
        let registry = schema_registry.as_ref().expect("registry was just built");

        let options = if strict {
            ValidationOptions::strict()
        } else {
            ValidationOptions::default_checks()
        };

        let mut validator = SchemaValidator::with_options(registry, options);
        if let Some(known) = known_ids {
            validator = validator.with_known_identifiers(known);
        }
        Some(validator.validate(&profile))
    } else {
        None
    };

    // Lint pass — re-parse the raw plist::Value so the lint walker can
    // see literal plist tags (e.g. <integer> vs <real>). Failures here
    // are non-fatal: a clean lint result is better than no lint at all.
    let mut lint_findings: Vec<serde_json::Value> = Vec::new();
    let mut lint_errors: Vec<String> = Vec::new();
    let mut lint_warnings: Vec<String> = Vec::new();
    if let Ok(raw_value) = plist::from_file::<_, plist::Value>(file) {
        let migration_registry = MigrationRegistry::new();
        let mut lint_options_with_modes = lint_options.clone();
        lint_options_with_modes.apply_modes = apply_modes_from_registry(schema_registry.as_ref());
        for finding in lint::lint_profile_with_options(
            &raw_value,
            &migration_registry,
            schema_registry.as_ref(),
            &lint_options_with_modes,
        ) {
            let severity = match finding.severity {
                lint::LintSeverity::Error => "error",
                lint::LintSeverity::Warning => "warning",
            };
            lint_findings.push(serde_json::json!({
                "check": finding.check,
                "severity": severity,
                "message": finding.message,
                "payload_index": finding.payload_index,
            }));
            let prefixed = format!("[{}] {}", finding.check, finding.message);
            match finding.severity {
                lint::LintSeverity::Error => lint_errors.push(prefixed),
                lint::LintSeverity::Warning => lint_warnings.push(prefixed),
            }
        }
    }

    let mut all_warnings = validation.warnings.clone();
    all_warnings.extend(placeholder_warnings);
    all_warnings.extend(lint_warnings);
    let mut all_errors = validation.errors.clone();
    all_errors.extend(lint_errors);
    let valid_after_lint = all_errors.is_empty();

    if output_mode == OutputMode::Json {
        let mut json_result = serde_json::json!({
            "file": file,
            "valid": valid_after_lint,
            "errors": all_errors,
            "warnings": all_warnings,
            "profile": {
                "display_name": profile.payload_display_name,
                "identifier": profile.payload_identifier,
                "uuid": profile.payload_uuid,
                "type": profile.payload_type,
                "version": profile.payload_version,
                "payload_count": profile.payload_content.len(),
                "organization": profile.payload_organization(),
            },
            "lint_findings": lint_findings,
        });

        if let Some(ref sr) = schema_result {
            json_result["schema_validation"] = serde_json::json!({
                "valid": sr.is_valid(),
                "payloads_validated": sr.payloads_validated,
                "payloads_unknown": sr.payloads_unknown,
                "errors": sr.errors().iter().map(|i| serde_json::json!({
                    "payload_type": i.payload_type,
                    "payload_index": i.payload_index,
                    "field": i.field,
                    "message": i.message,
                    "code": i.code,
                })).collect::<Vec<_>>(),
                "warnings": sr.warnings().iter().map(|i| serde_json::json!({
                    "payload_type": i.payload_type,
                    "payload_index": i.payload_index,
                    "field": i.field,
                    "message": i.message,
                    "code": i.code,
                })).collect::<Vec<_>>(),
            });
        }

        println!("{}", serde_json::to_string_pretty(&json_result)?);

        if !valid_after_lint || schema_result.as_ref().is_some_and(|s| !s.is_valid()) {
            anyhow::bail!("Validation failed");
        }
        return Ok(());
    }

    // Human output
    if valid_after_lint {
        println!("{}", "✓ Basic validation passed".green());
    } else {
        println!("{}", "✗ Basic validation failed".red());
        println!();
        println!("{}", "Errors:".red());
        for error in &all_errors {
            println!("  {} {}", "✗".red(), error);
        }
    }

    if !all_warnings.is_empty() {
        println!();
        println!("{}", "Warnings:".yellow());
        for warning in &all_warnings {
            println!("  {} {}", "!".yellow(), warning);
        }
    }

    // Schema validation results
    if let Some(sr) = &schema_result {
        println!();
        println!("{}", "Schema Validation:".cyan().bold());
        println!(
            "  Payloads validated: {}/{}",
            sr.payloads_validated,
            sr.payloads_validated + sr.payloads_unknown
        );

        if sr.is_valid() && sr.errors().is_empty() {
            println!("  {} All payloads conform to schema", "✓".green());
        }

        let errors = sr.errors();
        if !errors.is_empty() {
            println!();
            println!("  {}", "Schema Errors:".red());
            for issue in errors {
                let location = match (issue.payload_index, &issue.field) {
                    (Some(idx), Some(field)) => format!("[{idx}].{field}"),
                    (Some(idx), None) => format!("[{idx}]"),
                    (None, Some(field)) => field.clone(),
                    (None, None) => String::new(),
                };
                println!(
                    "    {} {} {}: {}",
                    "✗".red(),
                    issue.payload_type.green(),
                    location.dimmed(),
                    issue.message
                );
            }
        }

        let warnings = sr.warnings();
        if !warnings.is_empty() {
            println!();
            println!("  {}", "Schema Warnings:".yellow());
            for issue in warnings {
                let location = match (issue.payload_index, &issue.field) {
                    (Some(idx), Some(field)) => format!("[{idx}].{field}"),
                    (Some(idx), None) => format!("[{idx}]"),
                    (None, Some(field)) => field.clone(),
                    (None, None) => String::new(),
                };
                println!(
                    "    {} {} {}: {}",
                    "!".yellow(),
                    issue.payload_type.green(),
                    location.dimmed(),
                    issue.message
                );
            }
        }

        // Show info items only in verbose mode or if there are few
        let info = sr.info();
        if !info.is_empty() && info.len() <= 3 {
            println!();
            println!("  {}", "Notes:".dimmed());
            for issue in info {
                println!("    {} {}", "ℹ".blue(), issue.message.dimmed());
            }
        } else if !info.is_empty() {
            println!();
            println!(
                "    {} {} info items (sensitive fields, etc.)",
                "ℹ".blue(),
                info.len()
            );
        }
    }

    println!();
    println!("Profile Information:");
    println!("  Display Name: {}", profile.payload_display_name);
    println!("  Identifier: {}", profile.payload_identifier);
    println!("  UUID: {}", profile.payload_uuid);
    println!("  Type: {}", profile.payload_type);
    println!("  Version: {}", profile.payload_version);
    println!("  Content Items: {}", profile.payload_content.len());

    if let Some(org) = profile.payload_organization() {
        println!("  Organization: {org}");
    }

    // Show payload types
    if !profile.payload_content.is_empty() {
        println!();
        println!("Payloads:");
        for (idx, payload) in profile.payload_content.iter().enumerate() {
            let status = if schema {
                if let Some(ref sr) = schema_result {
                    let has_error = sr
                        .issues
                        .iter()
                        .any(|i| i.payload_index == Some(idx) && i.severity == Severity::Error);
                    if has_error {
                        "✗".red().to_string()
                    } else {
                        "✓".green().to_string()
                    }
                } else {
                    " ".to_string()
                }
            } else {
                " ".to_string()
            };

            let display_name = payload.payload_display_name();
            let name = display_name.as_deref().unwrap_or("(unnamed)");
            println!(
                "  {} {}. {} - {}",
                status,
                idx,
                payload.payload_type.green(),
                name.dimmed()
            );
        }
    }

    let schema_valid = schema_result
        .as_ref()
        .is_none_or(super::super::validation::schema_validator::SchemaValidationResult::is_valid);
    if !validation.valid || !schema_valid {
        anyhow::bail!("Profile validation failed");
    }

    Ok(())
}

/// Generate a markdown validation report from detailed results.
fn generate_markdown_report(results: &[DetailedValidationResult]) -> String {
    use std::fmt::Write;
    let mut md = String::with_capacity(8 * 1024);

    let failed = results.iter().filter(|r| !r.valid).count();
    let passed = results.len() - failed;
    let with_warnings = results
        .iter()
        .filter(|r| r.valid && !r.warnings.is_empty())
        .count();

    writeln!(md, "# Profile Validation Report").unwrap();
    writeln!(md).unwrap();
    writeln!(
        md,
        "| Metric | Count |\n|---|---|\n| Total | {} |\n| Passed | {} |\n| Failed | {} |\n| Warnings | {} |",
        results.len(),
        passed,
        failed,
        with_warnings
    )
    .unwrap();
    writeln!(md).unwrap();

    // Failures
    if failed > 0 {
        writeln!(md, "## Failures\n").unwrap();
        for r in results.iter().filter(|r| !r.valid) {
            writeln!(md, "### `{}`\n", r.file).unwrap();

            // Profile info if available
            if let Some(name) = r.profile.get("display_name").and_then(|v| v.as_str()) {
                if !name.is_empty() {
                    writeln!(md, "- **Display Name:** {name}").unwrap();
                }
            }
            if let Some(pt) = r.profile.get("type").and_then(|v| v.as_str()) {
                writeln!(md, "- **Type:** {pt}").unwrap();
            }

            if !r.errors.is_empty() {
                writeln!(md, "\n**Errors:**\n").unwrap();
                for e in &r.errors {
                    writeln!(md, "- {e}").unwrap();
                }
            }

            if let Some(ref sv) = r.schema_validation {
                if let Some(errs) = sv.get("errors").and_then(|v| v.as_array()) {
                    if !errs.is_empty() {
                        writeln!(md, "\n**Schema Errors:**\n").unwrap();
                        writeln!(md, "| Payload Type | Field | Message |").unwrap();
                        writeln!(md, "|---|---|---|").unwrap();
                        for e in errs {
                            let pt = e
                                .get("payload_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("-");
                            let field = e.get("field").and_then(|v| v.as_str()).unwrap_or("-");
                            let msg = e.get("message").and_then(|v| v.as_str()).unwrap_or("-");
                            writeln!(md, "| `{pt}` | `{field}` | {msg} |").unwrap();
                        }
                    }
                }
            }
            writeln!(md).unwrap();
        }
    }

    // Warnings
    if with_warnings > 0 {
        writeln!(md, "## Warnings\n").unwrap();
        for r in results.iter().filter(|r| r.valid && !r.warnings.is_empty()) {
            writeln!(md, "**`{}`**\n", r.file).unwrap();
            for w in &r.warnings {
                writeln!(md, "- {w}").unwrap();
            }
            writeln!(md).unwrap();
        }
    }

    // Passed
    if passed > 0 {
        writeln!(md, "## Passed ({passed})\n").unwrap();
        for r in results.iter().filter(|r| r.valid && r.warnings.is_empty()) {
            let name = r
                .profile
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            writeln!(md, "- `{}` {name}", r.file).unwrap();
        }
        writeln!(md).unwrap();
    }

    md
}
