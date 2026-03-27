//! Notifications validate command — validate notification settings in a notifications.toml.

use crate::cli::{OutputMode, print_error, print_json, print_success, print_warning};
use crate::config::NotificationConfig;
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

/// Run the notifications validate command.
///
/// Validates notification settings: bundle_id non-empty, alert_type in 0..=2, etc.
pub fn run(input: &Path, strict: bool, output_mode: OutputMode) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let config = match NotificationConfig::load(input) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("Failed to parse {}: {}", input.display(), e);
            if output_mode == OutputMode::Human {
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

    for app in &config.apps {
        // Empty bundle_id is always an error
        if app.bundle_id.is_empty() {
            errors.push(format!("{}: empty bundle_id", app.name));
        }

        // alert_type must be 0, 1, or 2
        if app.alert_type > 2 {
            errors.push(format!(
                "{}: invalid alert_type {} (expected 0, 1, or 2)",
                app.name, app.alert_type
            ));
        }

        // Warn if alerts disabled but other settings are enabled
        if !app.alerts_enabled
            && (app.badges_enabled
                || app.lock_screen
                || app.notification_center
                || app.sounds_enabled)
        {
            warnings.push(format!(
                "{}: alerts disabled but other notification settings still enabled",
                app.name
            ));
        }

        // Warn on empty name
        if app.name.is_empty() {
            warnings.push(format!("bundle_id {}: empty app name", app.bundle_id));
        }
    }

    // Warn on duplicate bundle_ids
    let mut seen_ids = std::collections::BTreeSet::new();
    for app in &config.apps {
        if !seen_ids.insert(&app.bundle_id) {
            warnings.push(format!("duplicate bundle_id: {}", app.bundle_id));
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
                "Validated {} notification app(s) in {}",
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
        anyhow::bail!("Notification validation failed");
    }

    Ok(())
}
