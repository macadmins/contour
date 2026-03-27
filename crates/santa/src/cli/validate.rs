use crate::output::{
    CommandResult, OutputMode, print_error, print_json, print_success, print_warning,
};
use crate::parser::parse_files;
use crate::validator::{ValidationOptions, validate_ruleset_with_options};
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct ValidateOutput {
    valid: bool,
    rules_count: usize,
    errors_count: usize,
    warnings_count: usize,
}

/// Configuration for validate command
#[derive(Debug)]
pub struct ValidateConfig {
    pub strict: bool,
    pub warn_missing_groups: bool,
    pub group_warning_threshold: usize,
}

impl Default for ValidateConfig {
    fn default() -> Self {
        Self {
            strict: false,
            warn_missing_groups: false,
            group_warning_threshold: 50,
        }
    }
}

pub fn run(inputs: &[impl AsRef<Path>], strict: bool, mode: OutputMode) -> Result<()> {
    run_with_config(
        inputs,
        ValidateConfig {
            strict,
            ..Default::default()
        },
        mode,
    )
}

pub fn run_with_config(
    inputs: &[impl AsRef<Path>],
    config: ValidateConfig,
    mode: OutputMode,
) -> Result<()> {
    // Parse all input files
    let rules = parse_files(inputs)?;

    // Set up validation options
    let options = ValidationOptions {
        warn_missing_groups: config.warn_missing_groups,
        group_warning_threshold: config.group_warning_threshold,
    };

    // Validate
    let validation = validate_ruleset_with_options(&rules, &options);

    let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
    let warnings: Vec<String> = validation.warnings.iter().map(|e| e.to_string()).collect();

    let is_valid = validation.valid && (!config.strict || warnings.is_empty());

    if mode == OutputMode::Human {
        for err in &errors {
            print_error(err);
        }
        for warn in &warnings {
            print_warning(warn);
        }

        if is_valid {
            print_success(&format!("Validated {} rules", rules.len()));
        } else {
            print_error(&format!(
                "Validation failed: {} errors, {} warnings",
                errors.len(),
                warnings.len()
            ));
        }
    } else {
        let result = CommandResult::success(ValidateOutput {
            valid: is_valid,
            rules_count: rules.len(),
            errors_count: errors.len(),
            warnings_count: warnings.len(),
        })
        .with_warnings(warnings.clone());

        let result = if errors.is_empty() {
            result
        } else {
            CommandResult {
                success: false,
                errors,
                ..result
            }
        };

        print_json(&result)?;
    }

    if !is_valid {
        anyhow::bail!("Validation failed");
    }

    Ok(())
}
