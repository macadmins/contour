//! BTM validate command — validate BTM rules in a btm.toml.

use crate::cli::{OutputMode, print_error, print_json, print_success, print_warning};
use crate::config::BtmConfig;
use anyhow::Result;
use contour_profiles::BtmRuleType;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Serialize)]
struct BtmValidateResult {
    valid: bool,
    btm_app_count: usize,
    btm_rule_count: usize,
    error_count: usize,
    warning_count: usize,
    errors: Vec<String>,
    warnings: Vec<String>,
}

/// Run the BTM validate command.
///
/// Validates BTM rules: rule_type is valid, rule_value non-empty, no duplicate rules.
pub fn run(input: &Path, strict: bool, output_mode: OutputMode) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let config = match BtmConfig::load(input) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("Failed to parse {}: {}", input.display(), e);
            if output_mode == OutputMode::Human {
                print_error(&msg);
            } else {
                print_json(&BtmValidateResult {
                    valid: false,
                    btm_app_count: 0,
                    btm_rule_count: 0,
                    error_count: 1,
                    warning_count: 0,
                    errors: vec![msg],
                    warnings: vec![],
                })?;
            }
            anyhow::bail!("Validation failed");
        }
    };

    let mut total_rules = 0usize;

    for app in &config.apps {
        // App has no rules and no team_id — profile may be empty
        if app.rules.is_empty() && app.team_id.is_none() {
            warnings.push(format!(
                "{}: no rules or team_id — profile may be empty",
                app.name
            ));
        }

        // Check each rule
        for (j, rule) in app.rules.iter().enumerate() {
            total_rules += 1;
            if rule.rule_value.is_empty() {
                errors.push(format!("{} rules[{}]: empty rule_value", app.name, j));
            }
            if rule.rule_type.parse::<BtmRuleType>().is_err() {
                let valid = BtmRuleType::all()
                    .iter()
                    .map(contour_profiles::BtmRuleType::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                errors.push(format!(
                    "{} rules[{}]: invalid rule_type '{}' (expected one of: {})",
                    app.name, j, rule.rule_type, valid
                ));
            }
        }

        // Detect duplicate rules within an app
        let mut seen: BTreeMap<(&str, &str), usize> = BTreeMap::new();
        for rule in &app.rules {
            *seen
                .entry((rule.rule_type.as_str(), rule.rule_value.as_str()))
                .or_default() += 1;
        }
        for ((rtype, rval), count) in &seen {
            if *count > 1 {
                warnings.push(format!(
                    "{}: duplicate rule ({}, {}) appears {} times",
                    app.name, rtype, rval, count
                ));
            }
        }
    }

    let is_valid = errors.is_empty() && (!strict || warnings.is_empty());

    if output_mode == OutputMode::Human {
        for err in &errors {
            print_error(err);
        }
        for warn in &warnings {
            print_warning(warn);
        }

        if is_valid {
            print_success(&format!(
                "Validated {} BTM app(s), {} rule(s) in {}",
                config.apps.len(),
                total_rules,
                input.display()
            ));
        } else {
            print_error(&format!(
                "BTM validation failed: {} error(s), {} warning(s)",
                errors.len(),
                warnings.len()
            ));
        }
    } else {
        print_json(&BtmValidateResult {
            valid: is_valid,
            btm_app_count: config.apps.len(),
            btm_rule_count: total_rules,
            error_count: errors.len(),
            warning_count: warnings.len(),
            errors,
            warnings,
        })?;
    }

    if !is_valid {
        anyhow::bail!("BTM validation failed");
    }

    Ok(())
}
