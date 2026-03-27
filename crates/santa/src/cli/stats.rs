use crate::models::RuleCategory;
use crate::output::{CommandResult, OutputMode, print_bar_chart, print_info, print_json};
use crate::parser::parse_files;
use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct StatsOutput {
    pub total_rules: usize,
    pub by_type: HashMap<String, usize>,
    pub by_policy: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub by_group: HashMap<String, usize>,
    pub by_ring: HashMap<String, usize>,
    pub with_description: usize,
    pub without_description: usize,
}

pub fn run(inputs: &[impl AsRef<Path>], mode: OutputMode) -> Result<()> {
    let rules = parse_files(inputs)?;

    let mut by_type: HashMap<String, usize> = HashMap::new();
    let mut by_policy: HashMap<String, usize> = HashMap::new();
    let mut by_category: HashMap<String, usize> = HashMap::new();
    let mut by_group: HashMap<String, usize> = HashMap::new();
    let mut by_ring: HashMap<String, usize> = HashMap::new();
    let mut with_description = 0;
    let mut without_description = 0;

    for rule in rules.rules() {
        // Count by type
        *by_type
            .entry(rule.rule_type.as_str().to_string())
            .or_default() += 1;

        // Count by policy
        *by_policy
            .entry(rule.policy.as_str().to_string())
            .or_default() += 1;

        // Count by category
        let cat = match rule.category() {
            RuleCategory::Software => "Software",
            RuleCategory::Cel => "CEL",
            RuleCategory::Faa => "FAA",
        };
        *by_category.entry(cat.to_string()).or_default() += 1;

        // Count by group
        let group = rule.group.clone().unwrap_or_else(|| "(none)".to_string());
        *by_group.entry(group).or_default() += 1;

        // Count by ring
        if rule.rings.is_empty() {
            *by_ring.entry("(global)".to_string()).or_default() += 1;
        } else {
            for ring in &rule.rings {
                *by_ring.entry(ring.clone()).or_default() += 1;
            }
        }

        // Count descriptions
        if rule.description.is_some() {
            with_description += 1;
        } else {
            without_description += 1;
        }
    }

    if mode == OutputMode::Human {
        print_info(&format!("Statistics for {} rules", rules.len()));

        println!();
        println!("{}", "By Rule Type:".bold());
        print_bar_chart(&to_bar_items(&by_type));

        println!();
        println!("{}", "By Policy:".bold());
        print_bar_chart(&to_bar_items(&by_policy));

        println!();
        println!("{}", "By Category:".bold());
        print_bar_chart(&to_bar_items(&by_category));

        println!();
        println!("{}", "By Group:".bold());
        print_bar_chart(&to_bar_items(&by_group));

        println!();
        println!("{}", "By Ring:".bold());
        print_bar_chart(&to_bar_items(&by_ring));

        println!();
        println!("{}", "Descriptions:".bold());
        print_bar_chart(&[
            ("With description", with_description),
            ("Without description", without_description),
        ]);
    } else {
        print_json(&CommandResult::success(StatsOutput {
            total_rules: rules.len(),
            by_type,
            by_policy,
            by_category,
            by_group,
            by_ring,
            with_description,
            without_description,
        }))?;
    }

    Ok(())
}

/// Convert a HashMap to sorted (label, count) pairs for bar chart display.
fn to_bar_items(map: &HashMap<String, usize>) -> Vec<(&str, usize)> {
    let mut items: Vec<_> = map.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1));
    items
}
