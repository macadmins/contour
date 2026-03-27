//! Notifications diff command — compare notification settings between two config files.

use crate::cli::{OutputMode, print_info, print_json, print_kv, print_success};
use crate::config::{NotificationAppEntry, NotificationConfig};
use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Run the notifications diff command.
///
/// Compares notification settings between two notifications.toml files.
pub fn run(file1: &Path, file2: &Path, output_mode: OutputMode) -> Result<()> {
    #[derive(Debug, Serialize)]
    struct Change {
        kind: String,
        bundle_id: String,
        details: Vec<String>,
    }

    let old = NotificationConfig::load(file1)?;
    let new = NotificationConfig::load(file2)?;

    // Index apps by bundle_id
    let old_apps: BTreeMap<&str, &NotificationAppEntry> =
        old.apps.iter().map(|a| (a.bundle_id.as_str(), a)).collect();
    let new_apps: BTreeMap<&str, &NotificationAppEntry> =
        new.apps.iter().map(|a| (a.bundle_id.as_str(), a)).collect();

    let mut changes: Vec<Change> = Vec::new();

    // Added apps
    for (bid, app) in &new_apps {
        if !old_apps.contains_key(bid) {
            changes.push(Change {
                kind: "added".to_string(),
                bundle_id: bid.to_string(),
                details: vec![format!("name: {}", app.name)],
            });
        }
    }

    // Removed apps
    for (bid, app) in &old_apps {
        if !new_apps.contains_key(bid) {
            changes.push(Change {
                kind: "removed".to_string(),
                bundle_id: bid.to_string(),
                details: vec![format!("name: {}", app.name)],
            });
        }
    }

    // Modified apps
    for (bid, old_app) in &old_apps {
        if let Some(new_app) = new_apps.get(bid) {
            let mut details = Vec::new();

            if old_app.alerts_enabled != new_app.alerts_enabled {
                details.push(format!(
                    "alerts_enabled: {} → {}",
                    old_app.alerts_enabled, new_app.alerts_enabled
                ));
            }
            if old_app.alert_type != new_app.alert_type {
                details.push(format!(
                    "alert_type: {} → {}",
                    old_app.alert_type, new_app.alert_type
                ));
            }
            if old_app.badges_enabled != new_app.badges_enabled {
                details.push(format!(
                    "badges_enabled: {} → {}",
                    old_app.badges_enabled, new_app.badges_enabled
                ));
            }
            if old_app.critical_alerts != new_app.critical_alerts {
                details.push(format!(
                    "critical_alerts: {} → {}",
                    old_app.critical_alerts, new_app.critical_alerts
                ));
            }
            if old_app.lock_screen != new_app.lock_screen {
                details.push(format!(
                    "lock_screen: {} → {}",
                    old_app.lock_screen, new_app.lock_screen
                ));
            }
            if old_app.notification_center != new_app.notification_center {
                details.push(format!(
                    "notification_center: {} → {}",
                    old_app.notification_center, new_app.notification_center
                ));
            }
            if old_app.sounds_enabled != new_app.sounds_enabled {
                details.push(format!(
                    "sounds_enabled: {} → {}",
                    old_app.sounds_enabled, new_app.sounds_enabled
                ));
            }

            if !details.is_empty() {
                changes.push(Change {
                    kind: "modified".to_string(),
                    bundle_id: bid.to_string(),
                    details,
                });
            }
        }
    }

    let added = changes.iter().filter(|c| c.kind == "added").count();
    let removed = changes.iter().filter(|c| c.kind == "removed").count();
    let modified = changes.iter().filter(|c| c.kind == "modified").count();

    if output_mode == OutputMode::Human {
        if changes.is_empty() {
            print_success("No notification differences found");
            return Ok(());
        }

        print_info(&format!(
            "Comparing notification settings: {} → {}",
            file1.display(),
            file2.display()
        ));
        println!();

        for change in &changes {
            let (symbol, label) = match change.kind.as_str() {
                "added" => ("+".green(), "added".green()),
                "removed" => ("-".red(), "removed".red()),
                _ => ("~".yellow(), "modified".yellow()),
            };

            println!("{} {} ({})", symbol, change.bundle_id, label);
            for detail in &change.details {
                println!("    {}", detail.dimmed());
            }
        }

        println!();
        print_kv("Added", &added.to_string());
        print_kv("Removed", &removed.to_string());
        print_kv("Modified", &modified.to_string());
    } else {
        print_json(&serde_json::json!({
            "added": added,
            "removed": removed,
            "modified": modified,
            "total_changes": changes.len(),
            "changes": changes,
        }))?;
    }

    Ok(())
}
