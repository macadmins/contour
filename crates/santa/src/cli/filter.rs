use crate::models::{Policy, RuleSet, RuleType};
use crate::output::{CommandResult, OutputMode, print_json, print_success};
use crate::parser::parse_files;
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct FilterOutput {
    matched: usize,
    total: usize,
    output_path: Option<String>,
}

/// Filter rules by various criteria
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
pub fn run(
    inputs: &[impl AsRef<Path>],
    output: Option<&Path>,
    rule_type: Option<RuleType>,
    policy: Option<Policy>,
    group: Option<&str>,
    ring: Option<&str>,
    has_description: Option<bool>,
    identifier_contains: Option<&str>,
    description_contains: Option<&str>,
    mode: OutputMode,
) -> Result<()> {
    let rules = parse_files(inputs)?;
    let total = rules.len();

    let filtered: Vec<_> = rules
        .rules()
        .iter()
        .filter(|rule| {
            // Filter by rule type
            if let Some(ref rt) = rule_type
                && rule.rule_type != *rt
            {
                return false;
            }

            // Filter by policy
            if let Some(ref p) = policy
                && rule.policy != *p
            {
                return false;
            }

            // Filter by group
            if let Some(g) = group {
                match &rule.group {
                    Some(rg) if rg == g => {}
                    None if g == "(none)" => {}
                    _ => return false,
                }
            }

            // Filter by ring
            if let Some(r) = ring {
                if r == "(global)" {
                    if !rule.rings.is_empty() {
                        return false;
                    }
                } else if !rule.rings.contains(&r.to_string()) {
                    return false;
                }
            }

            // Filter by has description
            if let Some(has_desc) = has_description {
                if has_desc && rule.description.is_none() {
                    return false;
                }
                if !has_desc && rule.description.is_some() {
                    return false;
                }
            }

            // Filter by identifier contains
            if let Some(pattern) = identifier_contains
                && !rule
                    .identifier
                    .to_lowercase()
                    .contains(&pattern.to_lowercase())
            {
                return false;
            }

            // Filter by description contains
            if let Some(pattern) = description_contains {
                match &rule.description {
                    Some(desc) if desc.to_lowercase().contains(&pattern.to_lowercase()) => {}
                    _ => return false,
                }
            }

            true
        })
        .cloned()
        .collect();

    let matched = filtered.len();
    let result_set = RuleSet::from_rules(filtered);

    // Write output if specified
    let output_path = if let Some(path) = output {
        let yaml = yaml_serde::to_string(result_set.rules())?;
        std::fs::write(path, &yaml)?;
        Some(path.display().to_string())
    } else {
        // Print to stdout if no output file
        if mode == OutputMode::Human {
            for rule in result_set.rules() {
                println!(
                    "{} {} - {}",
                    rule.rule_type.as_str(),
                    rule.identifier,
                    rule.description.as_deref().unwrap_or("(no description)")
                );
            }
        }
        None
    };

    if mode == OutputMode::Human {
        if let Some(ref path) = output_path {
            print_success(&format!(
                "Filtered {} of {} rules to {}",
                matched, total, path
            ));
        } else {
            println!();
            print_success(&format!("Found {} of {} rules", matched, total));
        }
    } else {
        print_json(&CommandResult::success(FilterOutput {
            matched,
            total,
            output_path,
        }))?;
    }

    Ok(())
}
