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

    let mut errors: Vec<String> = result
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Error && !demoted(i))
        .map(|i| i.message.clone())
        .collect();

    // Set-level identity collisions — per-payload schema checks can't see
    // them, and macOS keeps only one of two payloads sharing a PayloadUUID.
    // Always fatal, even on the lenient recipe path.
    if let Ok(raw_value) = plist::from_bytes::<plist::Value>(&raw) {
        errors.extend(
            crate::profile::lint::check_duplicate_payload_uuids(&raw_value)
                .into_iter()
                .map(|f| f.message),
        );
    }
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
                    println!("    {} {}", "·".red(), e);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Two payloads sharing a PayloadUUID/PayloadIdentifier install as ONE on
    /// macOS — the second silently wins. The generate-time gate must fail
    /// this even in lenient (recipe) mode; per-payload schema checks can't
    /// see set-level collisions.
    #[test]
    fn duplicate_payload_identity_fails_generation_gate() {
        let payload = |name: &str| {
            format!(
                r"<dict>
                <key>PayloadType</key><string>com.apple.security.root</string>
                <key>PayloadVersion</key><integer>1</integer>
                <key>PayloadIdentifier</key><string>com.acme.wifi.root.payload</string>
                <key>PayloadUUID</key><string>EA6C839A-F050-5AC2-893A-02501B33F5B4</string>
                <key>PayloadDisplayName</key><string>{name}</string>
            </dict>"
            )
        };
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>PayloadType</key><string>Configuration</string>
    <key>PayloadVersion</key><integer>1</integer>
    <key>PayloadIdentifier</key><string>com.acme.wifi</string>
    <key>PayloadUUID</key><string>57F10930-FEC3-5D9C-A937-B23C98FA9662</string>
    <key>PayloadDisplayName</key><string>Wifi</string>
    <key>PayloadContent</key><array>{}{}</array>
</dict></plist>"#,
            payload("Root CA"),
            payload("Intermediate CA"),
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dup.mobileconfig");
        std::fs::write(&path, xml).unwrap();

        let policy = ValidationConfig {
            fail_on_errors: true,
            fail_on_warnings: false,
            fail_on_deprecations: false,
        };
        let err = validate_generated_profile(&path, OutputMode::Human, &policy, true)
            .expect_err("duplicate payload identity must fail the gate");
        assert!(
            err.to_string().contains("error"),
            "unexpected error text: {err}"
        );
    }
}
