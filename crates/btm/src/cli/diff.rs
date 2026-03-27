//! BTM diff command — compare BTM rules between two config files.

use crate::cli::{OutputMode, print_info, print_json, print_kv, print_success};
use crate::config::{BtmAppEntry, BtmConfig};
use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Run the BTM diff command.
///
/// Compares BTM rules between two btm.toml files.
pub fn run(file1: &Path, file2: &Path, output_mode: OutputMode) -> Result<()> {
    #[derive(Debug, Serialize)]
    struct Change {
        kind: String,
        bundle_id: String,
        details: Vec<String>,
    }

    let old = BtmConfig::load(file1)?;
    let new = BtmConfig::load(file2)?;

    // Index apps by bundle_id
    let old_btm: BTreeMap<&str, &BtmAppEntry> =
        old.apps.iter().map(|a| (a.bundle_id.as_str(), a)).collect();
    let new_btm: BTreeMap<&str, &BtmAppEntry> =
        new.apps.iter().map(|a| (a.bundle_id.as_str(), a)).collect();

    let mut changes: Vec<Change> = Vec::new();

    // Added BTM apps
    for (bid, app) in &new_btm {
        if !old_btm.contains_key(bid) {
            changes.push(Change {
                kind: "added".to_string(),
                bundle_id: bid.to_string(),
                details: vec![
                    format!("name: {}", app.name),
                    format!("rules: {}", app.rules.len()),
                ],
            });
        }
    }

    // Removed BTM apps
    for (bid, app) in &old_btm {
        if !new_btm.contains_key(bid) {
            changes.push(Change {
                kind: "removed".to_string(),
                bundle_id: bid.to_string(),
                details: vec![
                    format!("name: {}", app.name),
                    format!("rules: {}", app.rules.len()),
                ],
            });
        }
    }

    // Modified BTM apps
    for (bid, old_app) in &old_btm {
        if let Some(new_app) = new_btm.get(bid) {
            let mut details = Vec::new();

            if old_app.rules.len() != new_app.rules.len()
                || old_app
                    .rules
                    .iter()
                    .zip(new_app.rules.iter())
                    .any(|(a, b)| a.rule_type != b.rule_type || a.rule_value != b.rule_value)
            {
                details.push(format!(
                    "rules: {} → {}",
                    old_app.rules.len(),
                    new_app.rules.len()
                ));
            }

            if old_app.team_id != new_app.team_id {
                details.push(format!(
                    "team_id: {:?} → {:?}",
                    old_app.team_id, new_app.team_id
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
            print_success("No BTM differences found");
            return Ok(());
        }

        print_info(&format!(
            "Comparing BTM rules: {} → {}",
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
