use crate::models::{Policy, Rule, RuleSet, RuleType};
use crate::output::{CommandResult, OutputMode, print_info, print_json, print_kv, print_success};
use crate::parser::parse_file;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct SnipOutput {
    matched: usize,
    remaining: usize,
    source: String,
    dest: String,
    identifiers: Vec<String>,
}

/// Extract rules matching criteria from source into dest.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
pub fn run(
    source: &Path,
    dest: &Path,
    identifier: Option<&str>,
    rule_type: Option<RuleType>,
    policy: Option<Policy>,
    group: Option<&str>,
    dry_run: bool,
    mode: OutputMode,
) -> Result<()> {
    // At least one filter must be specified
    if identifier.is_none() && rule_type.is_none() && policy.is_none() && group.is_none() {
        anyhow::bail!(
            "Must specify at least one filter: --identifier, --rule-type, --policy, or --group"
        );
    }

    // Parse source
    let source_rules =
        parse_file(source).with_context(|| format!("Failed to parse {}", source.display()))?;
    let source_total = source_rules.len();

    // Partition rules into matched and remaining (all filters AND'd)
    let (matched, remaining): (Vec<Rule>, Vec<Rule>) = source_rules.into_iter().partition(|rule| {
        let id_match = identifier
            .map(|id| rule.identifier.contains(id))
            .unwrap_or(true);
        let type_match = rule_type.map(|rt| rule.rule_type == rt).unwrap_or(true);
        let policy_match = policy.map(|p| rule.policy == p).unwrap_or(true);
        let group_match = group
            .map(|g| rule.group.as_deref() == Some(g))
            .unwrap_or(true);
        id_match && type_match && policy_match && group_match
    });

    if matched.is_empty() {
        if mode == OutputMode::Human {
            print_info("No rules matched the given filters");
        } else {
            print_json(&CommandResult::success(SnipOutput {
                matched: 0,
                remaining: source_total,
                source: source.display().to_string(),
                dest: dest.display().to_string(),
                identifiers: vec![],
            }))?;
        }
        return Ok(());
    }

    let matched_ids: Vec<String> = matched.iter().map(|r| r.identifier.clone()).collect();

    // Build destination ruleset
    let mut dest_rules = if dest.exists() {
        parse_file(dest).with_context(|| format!("Failed to parse {}", dest.display()))?
    } else {
        RuleSet::new()
    };

    dest_rules.extend(matched.clone());
    dest_rules.deduplicate();
    dest_rules.sort();

    let remaining_set = RuleSet::from_rules(remaining);

    if mode == OutputMode::Human {
        print_kv("Matched rules", &matched.len().to_string());
        print_kv("Remaining in source", &remaining_set.len().to_string());
        print_kv("Destination total", &dest_rules.len().to_string());

        if dry_run {
            print_info("Dry run — no files written");
            println!();
            println!("Rules that would be snipped:");
            for rule in &matched {
                println!(
                    "  {} {}:{} ({})",
                    rule.rule_type.as_str(),
                    rule.identifier,
                    rule.policy.as_str(),
                    rule.description.as_deref().unwrap_or("-")
                );
            }
        }
    }

    if !dry_run {
        // Write remaining back to source
        let yaml = yaml_serde::to_string(remaining_set.rules())?;
        std::fs::write(source, &yaml)
            .with_context(|| format!("Failed to write {}", source.display()))?;

        // Write combined to dest
        let yaml = yaml_serde::to_string(dest_rules.rules())?;
        std::fs::write(dest, &yaml)
            .with_context(|| format!("Failed to write {}", dest.display()))?;

        if mode == OutputMode::Human {
            print_success(&format!(
                "Snipped {} rules from {} → {}",
                matched.len(),
                source.display(),
                dest.display()
            ));
        }
    }

    if mode != OutputMode::Human {
        print_json(&CommandResult::success(SnipOutput {
            matched: matched.len(),
            remaining: remaining_set.len(),
            source: source.display().to_string(),
            dest: dest.display().to_string(),
            identifiers: matched_ids,
        }))?;
    }

    Ok(())
}
