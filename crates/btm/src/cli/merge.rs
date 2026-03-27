//! BTM merge command — merge BTM rules from one config into another.

use crate::cli::{OutputMode, print_info, print_success, print_warning};
use crate::config::BtmConfig;
use anyhow::{Context, Result};
use std::path::Path;

/// Run the BTM merge command.
///
/// Loads rules from source and merges them into matching apps in target
/// (matched by bundle_id).
pub fn run(source: &Path, target: &Path, output_mode: OutputMode) -> Result<()> {
    if output_mode == OutputMode::Human {
        print_info(&format!(
            "Merging BTM rules from {} into {}...",
            source.display(),
            target.display()
        ));
    }

    let source_config =
        BtmConfig::load(source).with_context(|| format!("Failed to load {}", source.display()))?;
    let mut target_config =
        BtmConfig::load(target).with_context(|| format!("Failed to load {}", target.display()))?;

    let mut merged_count = 0usize;

    for source_app in &source_config.apps {
        if source_app.rules.is_empty() {
            continue;
        }

        // Find matching app in target by bundle_id
        if let Some(target_app) = target_config
            .apps
            .iter_mut()
            .find(|a| a.bundle_id == source_app.bundle_id)
        {
            for rule in &source_app.rules {
                let already_has = target_app.rules.iter().any(|existing| {
                    existing.rule_type == rule.rule_type && existing.rule_value == rule.rule_value
                });
                if !already_has {
                    target_app.rules.push(rule.clone());
                    merged_count += 1;
                }
            }
        } else if output_mode == OutputMode::Human {
            print_warning(&format!(
                "No matching app for {} in target — skipping",
                source_app.bundle_id
            ));
        }
    }

    target_config.save(target)?;

    if output_mode == OutputMode::Human {
        print_success(&format!(
            "Merged {} BTM rule(s) into {}",
            merged_count,
            target.display()
        ));
    }

    Ok(())
}
