use crate::models::RuleSet;
use crate::output::{CommandResult, OutputMode, print_json, print_success, print_warning};
use crate::parser::parse_file;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct RemoveOutput {
    removed: bool,
    identifier: String,
    remaining_rules: usize,
}

/// Normalize a rule type string for comparison by lowercasing and stripping
/// non-alphanumeric characters (e.g., "team-id" and "TEAMID" both become "teamid").
fn normalize_type(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// Remove a rule from a rules file by identifier
pub fn run(
    file: &Path,
    identifier: &str,
    rule_type: Option<&str>,
    dry_run: bool,
    mode: OutputMode,
) -> Result<()> {
    let rules = parse_file(file).with_context(|| format!("Failed to parse {}", file.display()))?;

    // Find and remove the rule
    let original_count = rules.len();
    let filtered: Vec<_> = rules
        .rules()
        .iter()
        .filter(|rule| {
            // Match by identifier
            if rule.identifier != identifier {
                return true; // Keep
            }

            // Optionally also match by rule type
            // Normalize both sides by stripping non-alphanumeric chars so that
            // clap's kebab-case "team-id" matches serde's "TEAMID"
            if let Some(rt) = rule_type
                && normalize_type(rule.rule_type.as_str()) != normalize_type(rt)
            {
                return true; // Keep - different type
            }

            false // Remove
        })
        .cloned()
        .collect();

    let new_rules = RuleSet::from_rules(filtered);
    let removed = original_count > new_rules.len();
    let removed_count = original_count - new_rules.len();

    if !removed {
        if mode == OutputMode::Human {
            print_warning(&format!("No rule found with identifier: {}", identifier));
        } else {
            print_json(&CommandResult::success(RemoveOutput {
                removed: false,
                identifier: identifier.to_string(),
                remaining_rules: new_rules.len(),
            }))?;
        }
        return Ok(());
    }

    if !dry_run {
        let yaml = yaml_serde::to_string(new_rules.rules())?;
        std::fs::write(file, &yaml)
            .with_context(|| format!("Failed to write {}", file.display()))?;
    }

    if mode == OutputMode::Human {
        if dry_run {
            print_success(&format!(
                "Would remove {} rule(s) with identifier: {} ({} remaining)",
                removed_count,
                identifier,
                new_rules.len()
            ));
        } else {
            print_success(&format!(
                "Removed {} rule(s) with identifier: {} ({} remaining)",
                removed_count,
                identifier,
                new_rules.len()
            ));
        }
    } else {
        print_json(&CommandResult::success(RemoveOutput {
            removed: true,
            identifier: identifier.to_string(),
            remaining_rules: new_rules.len(),
        }))?;
    }

    Ok(())
}
