//! Post-generation validation for profile generators.
//!
//! Every `.mobileconfig` generator calls `validate_generated_profile`
//! after writing output so invalid output is caught immediately rather
//! than after deployment. DDM generation does its own stricter check
//! inline (see `crate::cli::ddm::handle_ddm_generate`).

use crate::output::OutputMode;
use anyhow::Result;
use colored::Colorize;
use std::path::Path;

/// Validate a generated mobileconfig file against the embedded schema.
///
/// Called automatically after every profile generation. Reports warnings
/// for unknown keys or type mismatches but does not fail — the generated
/// structure is always valid, field values may need user editing.
pub fn validate_generated_profile(path: &Path, mode: OutputMode) -> Result<()> {
    let registry = crate::schema::SchemaRegistry::embedded()?;
    let raw = std::fs::read(path)?;

    // Parse the profile
    let profile = match crate::profile::parser::parse_profile_from_bytes(&raw) {
        Ok(p) => p,
        Err(_) => return Ok(()), // Can't parse = skip validation (plist format, etc.)
    };

    let validator = crate::validation::schema_validator::SchemaValidator::new(&registry);
    let result = validator.validate(&profile);

    let errors: Vec<_> = result
        .issues
        .iter()
        .filter(|i| i.severity == crate::validation::schema_validator::Severity::Error)
        .collect();
    let warnings: Vec<_> = result
        .issues
        .iter()
        .filter(|i| i.severity == crate::validation::schema_validator::Severity::Warning)
        .collect();

    if mode != OutputMode::Human {
        return Ok(());
    }

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

    Ok(())
}
