//! Post-generation validation for profile generators.
//!
//! Every `.mobileconfig` generator calls `validate_generated_profile`
//! after writing output so invalid output is caught immediately rather
//! than after deployment. DDM generation does its own stricter check
//! inline (see `crate::cli::ddm::handle_ddm_generate`).

use crate::output::OutputMode;
use anyhow::Result;
use colored::Colorize;
use contour_core::config::ValidationConfig;
use std::path::Path;

/// Validate a generated mobileconfig file against the embedded schema.
///
/// `policy` controls whether errors or warnings cause the function to
/// return an `Err`. Reporting still happens in Human mode regardless,
/// so the operator sees the same diagnostic output before the failure.
///
/// `lenient` defers to the recipe over unreliable schema constraints, and is
/// set only on the recipe path — where the output faithfully reproduces mSCP
/// (and the Apple rules behind it). It downgrades two error classes to
/// warnings:
///
///   * **Missing required fields** (any payload). A recipe authoritatively
///     declares a *subset* of a payload's fields — a screensaver-lock rule
///     that never sets the required `moduleName`, an Exchange restriction
///     that doesn't provision the Mail account it rides on. mSCP itself never
///     enforces required fields.
///   * **Type mismatches on Apple payloads.** The embedded schema's base
///     layer is ProfileManifests/ProfileCreator (`profilecreator.parquet`),
///     whose data quality for `com.apple.*` payloads is unreliable wherever
///     Apple's authoritative `capabilities.parquet` doesn't override it — e.g.
///     legacy MCX payloads like `com.apple.MCX.FileVault2`, which types
///     `Enable` as String though Boolean is the standard MDM-deployed shape
///     mSCP emits. For Apple payloads we trust the rule over ProfileManifests.
///
/// Type mismatches on third-party payloads, and every other error, stay fatal.
pub fn validate_generated_profile(
    path: &Path,
    mode: OutputMode,
    policy: &ValidationConfig,
    lenient: bool,
) -> Result<()> {
    use crate::validation::schema_validator::{Severity, ValidationIssue};

    let registry = crate::schema::SchemaRegistry::embedded()?;
    let raw = std::fs::read(path)?;

    let profile = match crate::profile::parser::parse_profile_from_bytes(&raw) {
        Ok(p) => p,
        Err(_) => return Ok(()), // Can't parse = skip validation (plist format, etc.)
    };

    let validator = crate::validation::schema_validator::SchemaValidator::new(&registry);
    let result = validator.validate(&profile);

    // Apple payloads: `com.apple.*` or the dot-prefixed pseudo-domains
    // (`.GlobalPreferences`). Their ProfileManifests-sourced type constraints
    // are the ones we treat as advisory.
    let is_apple = |pt: &str| pt.starts_with("com.apple.") || pt.starts_with('.');

    // On the recipe path, demote ProfileManifests-driven errors to warnings
    // (see the doc comment); everywhere else they stay errors.
    let demoted = |i: &&ValidationIssue| {
        lenient
            && i.severity == Severity::Error
            && (i.code == "MISSING_REQUIRED"
                || i.code == "MISSING_NESTED_REQUIRED"
                || (i.code == "TYPE_MISMATCH" && is_apple(&i.payload_type)))
    };

    let errors: Vec<_> = result
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Error && !demoted(i))
        .collect();
    let warnings: Vec<_> = result
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Warning || demoted(i))
        .collect();

    if mode == OutputMode::Human {
        if errors.is_empty() && warnings.is_empty() {
            println!("  {} Schema validation passed", "✓".green());
        } else {
            if !errors.is_empty() {
                println!(
                    "  {} Schema validation: {} error(s)",
                    "✗".red(),
                    errors.len()
                );
                for e in &errors {
                    println!("    {} {}", "·".red(), e.message);
                }
            }
            if !warnings.is_empty() {
                println!(
                    "  {} Schema validation: {} warning(s)",
                    "⚠".yellow(),
                    warnings.len()
                );
                for w in &warnings {
                    println!("    {} {}", "·".yellow(), w.message);
                }
            }
        }
    }

    if policy.fail_on_errors && !errors.is_empty() {
        anyhow::bail!(
            "schema validation failed: {} error(s) in {}",
            errors.len(),
            path.display()
        );
    }
    if policy.fail_on_warnings && !warnings.is_empty() {
        anyhow::bail!(
            "schema validation failed: {} warning(s) in {} (validation.fail_on_warnings is enabled)",
            warnings.len(),
            path.display()
        );
    }

    Ok(())
}
