//! Handler for the `pppc diff` command.
//!
//! Compares two pppc.toml files and shows TCC service differences by bundle_id.

use crate::cli::{OutputMode, print_info, print_json, print_kv, print_success};
use crate::pppc::PppcConfig;
use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Serialize)]
struct DiffResult {
    added: usize,
    removed: usize,
    modified: usize,
    total_changes: usize,
    changes: Vec<DiffChange>,
}

#[derive(Debug, Serialize)]
struct DiffChange {
    change_type: String,
    bundle_id: String,
    details: Vec<String>,
}

pub fn run(file1: &Path, file2: &Path, mode: OutputMode) -> Result<()> {
    let old = PppcConfig::load(file1)?;
    let new = PppcConfig::load(file2)?;

    // Index apps by bundle_id
    let old_map: BTreeMap<&str, _> = old.apps.iter().map(|a| (a.bundle_id.as_str(), a)).collect();
    let new_map: BTreeMap<&str, _> = new.apps.iter().map(|a| (a.bundle_id.as_str(), a)).collect();

    let mut changes: Vec<DiffChange> = Vec::new();

    // Added apps
    for (bid, app) in &new_map {
        if !old_map.contains_key(bid) {
            let mut details = vec![format!("name: {}", app.name)];
            if !app.services.is_empty() {
                details.push(format!(
                    "services: {}",
                    app.services
                        .iter()
                        .map(|s| s.display_name().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            changes.push(DiffChange {
                change_type: "added".to_string(),
                bundle_id: bid.to_string(),
                details,
            });
        }
    }

    // Removed apps
    for (bid, app) in &old_map {
        if !new_map.contains_key(bid) {
            changes.push(DiffChange {
                change_type: "removed".to_string(),
                bundle_id: bid.to_string(),
                details: vec![format!("name: {}", app.name)],
            });
        }
    }

    // Modified apps
    for (bid, old_app) in &old_map {
        if let Some(new_app) = new_map.get(bid) {
            let mut details = Vec::new();

            // Services changed
            let old_svcs: Vec<_> = old_app
                .services
                .iter()
                .map(super::super::pppc::PppcService::key)
                .collect();
            let new_svcs: Vec<_> = new_app
                .services
                .iter()
                .map(super::super::pppc::PppcService::key)
                .collect();
            if old_svcs != new_svcs {
                let added: Vec<_> = new_app
                    .services
                    .iter()
                    .filter(|s| !old_app.services.contains(s))
                    .map(|s| format!("+{}", s.display_name()))
                    .collect();
                let removed: Vec<_> = old_app
                    .services
                    .iter()
                    .filter(|s| !new_app.services.contains(s))
                    .map(|s| format!("-{}", s.display_name()))
                    .collect();
                let all: Vec<_> = added.into_iter().chain(removed).collect();
                details.push(format!("services: {}", all.join(", ")));
            }

            if !details.is_empty() {
                changes.push(DiffChange {
                    change_type: "modified".to_string(),
                    bundle_id: bid.to_string(),
                    details,
                });
            }
        }
    }

    let added = changes.iter().filter(|c| c.change_type == "added").count();
    let removed = changes
        .iter()
        .filter(|c| c.change_type == "removed")
        .count();
    let modified = changes
        .iter()
        .filter(|c| c.change_type == "modified")
        .count();

    if mode == OutputMode::Human {
        if changes.is_empty() {
            print_success("No differences found");
            return Ok(());
        }

        print_info(&format!(
            "Comparing {} → {}",
            file1.display(),
            file2.display()
        ));
        println!();

        for change in &changes {
            let (symbol, label) = match change.change_type.as_str() {
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
        print_json(&DiffResult {
            added,
            removed,
            modified,
            total_changes: changes.len(),
            changes,
        })?;
    }

    Ok(())
}
