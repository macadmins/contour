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
/// Keys `[[apps]]` understands. Anything else is a typo or a key contour
/// does not implement, and either way the value is silently discarded.
///
/// This list is the reason the generator's three missing keys went
/// unnoticed: `preview_type` was documented in `--sop notifications`, a
/// reasonable operator set it, serde dropped it, and nothing said so.
const KNOWN_APP_KEYS: &[&str] = &[
    "name",
    "bundle_id",
    "alerts_enabled",
    "alert_type",
    "badges_enabled",
    "critical_alerts",
    "lock_screen",
    "notification_center",
    "sounds_enabled",
    "grouping_type",
    "preview_type",
    "show_in_car_play",
];

/// Report keys serde will discard.
///
/// Parsed from the raw TOML rather than the typed struct, because by the
/// time the struct exists the unknown keys are gone. `deny_unknown_fields`
/// would catch them at load time instead, but that turns a typo in one app
/// entry into a hard failure for the whole file — including for `generate`,
/// which should keep working on a file it can otherwise understand.
fn unknown_key_warnings(raw: &str) -> Vec<String> {
    // `toml::from_str`, not `str::parse` — the latter parses a bare VALUE and
    // rejects a document ("unexpected content, expected nothing"). The first
    // version of this function used parse and silently returned nothing,
    // which is precisely the failure it exists to catch.
    let Ok(doc) = toml::from_str::<toml::Value>(raw) else {
        return Vec::new();
    };
    let Some(apps) = doc.get("apps").and_then(|a| a.as_array()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for app in apps {
        let Some(table) = app.as_table() else {
            continue;
        };
        let label = table
            .get("bundle_id")
            .and_then(|v| v.as_str())
            .or_else(|| table.get("name").and_then(|v| v.as_str()))
            .unwrap_or("<unnamed>");
        for key in table.keys() {
            if !KNOWN_APP_KEYS.contains(&key.as_str()) {
                out.push(format!(
                    "{label}: unknown key '{key}' — it will be ignored, not written \
                     to the profile"
                ));
            }
        }
    }
    out
}

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

    // Keys serde discarded. Read from the raw text — the typed config has
    // already lost them.
    if let Ok(raw) = std::fs::read_to_string(input) {
        warnings.extend(unknown_key_warnings(&raw));
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

#[cfg(test)]
mod unknown_key_tests {
    use super::*;

    #[test]
    fn reports_keys_serde_would_discard() {
        // The reported case: a nonsense key passed validation in silence.
        // A typo'd real key is the one that actually bites — `preview_typo`
        // reads as configured and writes nothing.
        let sample = r#"
[settings]
org = "com.acme"

[[apps]]
name = "Teams"
bundle_id = "com.microsoft.teams2"
total_nonsense_key = 42
preview_typo = "never"
"#;
        let warnings = unknown_key_warnings(sample);
        assert_eq!(
            warnings.len(),
            2,
            "both unknown keys must be reported: {warnings:?}"
        );
        assert!(warnings.iter().any(|w| w.contains("total_nonsense_key")));
        assert!(warnings.iter().any(|w| w.contains("preview_typo")));
        // Named by bundle id, so a multi-app file points at the right entry.
        assert!(warnings.iter().all(|w| w.contains("com.microsoft.teams2")));
    }

    #[test]
    fn every_known_key_is_accepted() {
        // Guards the list against drifting from the struct: a field added to
        // NotificationAppEntry without being listed here would be reported
        // as unknown on a file that legitimately sets it.
        let sample = r#"
[settings]
org = "com.acme"

[[apps]]
name = "Teams"
bundle_id = "com.microsoft.teams2"
alerts_enabled = true
alert_type = 1
badges_enabled = true
critical_alerts = true
lock_screen = true
notification_center = true
sounds_enabled = false
grouping_type = "by_app"
preview_type = "when_unlocked"
show_in_car_play = false
"#;
        assert!(
            unknown_key_warnings(sample).is_empty(),
            "no legitimate key may be flagged: {:?}",
            unknown_key_warnings(sample)
        );
    }

    #[test]
    fn a_document_that_does_not_parse_is_not_a_crash() {
        assert!(unknown_key_warnings("this is not toml {{{").is_empty());
    }
}
