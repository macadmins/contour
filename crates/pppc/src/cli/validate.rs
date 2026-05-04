//! Handler for the `pppc validate` command.
//!
//! Validates a pppc.toml policy file for structural correctness.

use crate::cli::generate::find_duplicate_bundle_ids;
use crate::cli::{OutputMode, print_error, print_json, print_success, print_warning};
use crate::pppc::PppcConfig;
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct ValidateResult {
    valid: bool,
    app_count: usize,
    error_count: usize,
    warning_count: usize,
    errors: Vec<String>,
    warnings: Vec<String>,
}

pub fn run(input: &Path, strict: bool, mode: OutputMode) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // 1. Parse the TOML
    let config = match PppcConfig::load(input) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("Failed to parse {}: {}", input.display(), e);
            if mode == OutputMode::Human {
                print_error(&msg);
            } else {
                print_json(&ValidateResult {
                    valid: false,
                    app_count: 0,
                    error_count: 1,
                    warning_count: 0,
                    errors: vec![msg],
                    warnings: vec![],
                })?;
            }
            anyhow::bail!("Validation failed");
        }
    };

    // 2. Org non-empty
    if config.config.org.is_empty() {
        errors.push("config.org is empty".to_string());
    }

    // 3. Each app has an identifier (bundle_id OR path) + code_requirement.
    //    Path-based entries (signed bare binaries like managedsoftwareupdate)
    //    have no bundle_id and are valid when path + identifier_type=path.
    for (i, app) in config.apps.iter().enumerate() {
        if app.identifier_value().is_empty() {
            errors.push(format!(
                "apps[{}] ({}) has neither bundle_id nor path; one is required",
                i, app.name
            ));
        }
        if app.identifier_type == "path" && app.path.is_none() {
            errors.push(format!(
                "apps[{}] ({}) has identifier_type=path but no `path` field",
                i, app.name
            ));
        }
        if app.code_requirement.is_empty() {
            warnings.push(format!(
                "apps[{}] ({}) has empty code_requirement",
                i, app.name
            ));
        }
        if app.name.is_empty() {
            warnings.push(format!(
                "apps[{}] has empty name (identifier: {})",
                i,
                app.identifier_value()
            ));
        }
    }

    // 4. Duplicate identifier detection (compares on the resolved value).
    let duplicates = find_duplicate_bundle_ids(&config);
    for (id, count) in &duplicates {
        warnings.push(format!("Duplicate identifier '{id}' appears {count} times"));
    }

    // 5. Strict mode: warnings become errors
    let is_valid = errors.is_empty() && (!strict || warnings.is_empty());

    if mode == OutputMode::Human {
        for err in &errors {
            print_error(err);
        }
        for warn in &warnings {
            print_warning(warn);
        }

        if is_valid {
            print_success(&format!(
                "Validated {} apps in {}",
                config.apps.len(),
                input.display()
            ));
        } else {
            print_error(&format!(
                "Validation failed: {} error(s), {} warning(s)",
                errors.len(),
                warnings.len()
            ));
        }
    } else {
        print_json(&ValidateResult {
            valid: is_valid,
            app_count: config.apps.len(),
            error_count: errors.len(),
            warning_count: warnings.len(),
            errors,
            warnings,
        })?;
    }

    if !is_valid {
        anyhow::bail!("Validation failed");
    }

    Ok(())
}
