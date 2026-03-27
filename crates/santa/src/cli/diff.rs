use crate::diff::{ChangeType, diff};
use crate::output::{CommandResult, OutputMode, print_info, print_json, print_kv, print_success};
use crate::parser::parse_file;
use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct DiffOutput {
    added: usize,
    removed: usize,
    modified: usize,
    total_changes: usize,
    changes: Vec<ChangeInfo>,
}

#[derive(Debug, Serialize)]
struct ChangeInfo {
    change_type: String,
    key: String,
}

pub fn run(file1: &Path, file2: &Path, mode: OutputMode) -> Result<()> {
    let old = parse_file(file1)?;
    let new = parse_file(file2)?;

    let result = diff(&old, &new);

    if mode == OutputMode::Human {
        if result.is_empty() {
            print_success("No differences found");
            return Ok(());
        }

        print_info(&format!(
            "Comparing {} → {}",
            file1.display(),
            file2.display()
        ));

        for change in &result.changes {
            let symbol = match change.change_type {
                ChangeType::Added => "+".green(),
                ChangeType::Removed => "-".red(),
                ChangeType::Modified => "~".yellow(),
            };

            let label = match change.change_type {
                ChangeType::Added => "added".green(),
                ChangeType::Removed => "removed".red(),
                ChangeType::Modified => "modified".yellow(),
            };

            println!("{} {} ({})", symbol, change.key, label);

            // Show details for modified rules
            if change.change_type == ChangeType::Modified
                && let (Some(old_rule), Some(new_rule)) = (&change.old_rule, &change.new_rule)
                && old_rule.policy != new_rule.policy
            {
                println!(
                    "    policy: {} → {}",
                    format!("{}", old_rule.policy).red(),
                    format!("{}", new_rule.policy).green()
                );
            }
        }

        println!();
        print_kv("Added", &result.added.to_string());
        print_kv("Removed", &result.removed.to_string());
        print_kv("Modified", &result.modified.to_string());
    } else {
        let changes: Vec<ChangeInfo> = result
            .changes
            .iter()
            .map(|c| ChangeInfo {
                change_type: match c.change_type {
                    ChangeType::Added => "added",
                    ChangeType::Removed => "removed",
                    ChangeType::Modified => "modified",
                }
                .to_string(),
                key: c.key.clone(),
            })
            .collect();

        print_json(&CommandResult::success(DiffOutput {
            added: result.added,
            removed: result.removed,
            modified: result.modified,
            total_changes: result.total_changes(),
            changes,
        }))?;
    }

    Ok(())
}
