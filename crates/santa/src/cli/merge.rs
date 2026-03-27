use crate::merge::{Strategy, merge};
use crate::output::{
    CommandResult, OutputMode, print_info, print_json, print_kv, print_success, print_warning,
};
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct MergeOutput {
    rules_count: usize,
    conflicts_count: usize,
    output_path: Option<String>,
}

pub fn run(
    inputs: &[impl AsRef<Path>],
    output: Option<&Path>,
    strategy: Strategy,
    dry_run: bool,
    mode: OutputMode,
) -> Result<()> {
    // Parse each input file separately for merging
    let mut sets = Vec::new();
    for input in inputs {
        let rules = crate::parser::parse_file(input.as_ref())?;
        sets.push(rules);
    }

    // Merge
    let result = merge(&sets, strategy)?;

    let output_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new("merged-rules.yaml").to_path_buf());

    if mode == OutputMode::Human {
        if !result.conflicts.is_empty() {
            print_warning(&format!("{} conflicts resolved", result.conflicts.len()));
            for conflict in &result.conflicts {
                print_kv("  Conflict", &conflict.key);
            }
        }

        if dry_run {
            print_info("Dry run - no files will be written");
            print_kv("Rules", &result.rules.len().to_string());
            print_kv("Output", &output_path.display().to_string());
        } else {
            // Write merged rules as YAML
            let yaml = yaml_serde::to_string(result.rules.rules())?;
            std::fs::write(&output_path, yaml)?;
            print_success(&format!(
                "Merged {} rules to {}",
                result.rules.len(),
                output_path.display()
            ));
        }
    } else {
        print_json(&CommandResult::success(MergeOutput {
            rules_count: result.rules.len(),
            conflicts_count: result.conflicts.len(),
            output_path: if dry_run {
                None
            } else {
                Some(output_path.display().to_string())
            },
        }))?;

        if !dry_run {
            let yaml = yaml_serde::to_string(result.rules.rules())?;
            std::fs::write(&output_path, yaml)?;
        }
    }

    Ok(())
}
