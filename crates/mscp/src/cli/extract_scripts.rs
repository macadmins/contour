use crate::extractors::RuleExtractor;
use crate::managers::{ConstraintType, Constraints, OdvOverrides};
use crate::output::OutputMode;
use crate::transformers::script_helpers;
use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Script categories for organizing output
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScriptCategory {
    Ssh,
    Sshd,
    Sharing,
    Audit,
    Auth,
    System,
    Pwpolicy,
}

impl ScriptCategory {
    fn from_rule_id(rule_id: &str) -> Self {
        let id_lower = rule_id.to_lowercase();
        if id_lower.contains("sshd") {
            ScriptCategory::Sshd
        } else if id_lower.contains("ssh") {
            ScriptCategory::Ssh
        } else if id_lower.contains("sharing")
            || id_lower.contains("bluetooth")
            || id_lower.contains("airdrop")
            || id_lower.contains("airplay")
        {
            ScriptCategory::Sharing
        } else if id_lower.contains("audit") || id_lower.contains("asl") {
            ScriptCategory::Audit
        } else if id_lower.contains("auth") || id_lower.contains("pam") {
            ScriptCategory::Auth
        } else if id_lower.contains("pwpolicy") || id_lower.contains("password") {
            ScriptCategory::Pwpolicy
        } else {
            ScriptCategory::System
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ScriptCategory::Ssh => "ssh",
            ScriptCategory::Sshd => "sshd",
            ScriptCategory::Sharing => "sharing",
            ScriptCategory::Audit => "audit",
            ScriptCategory::Auth => "auth",
            ScriptCategory::System => "system",
            ScriptCategory::Pwpolicy => "pwpolicy",
        }
    }
}

/// Result of script extraction
#[derive(Debug)]
pub struct ExtractionResult {
    pub scripts_created: Vec<String>,
    pub profile_only_rules: Vec<String>,
    pub skipped_rules: Vec<String>,
    pub excluded_rules: Vec<String>,
}

/// Extract remediation scripts from mSCP rules
pub fn extract_scripts(
    mscp_repo: Option<PathBuf>,
    baseline: String,
    output: PathBuf,
    flat_output: bool,
    dry_run: bool,
    output_mode: OutputMode,
    constraints_path: Option<PathBuf>,
    odv_path: Option<PathBuf>,
) -> Result<()> {
    // Get rules for this baseline from repo or embedded data
    let rules = if let Some(ref repo_path) = mscp_repo {
        let extractor = RuleExtractor::new(repo_path);
        extractor
            .extract_rules_for_baseline(&baseline)
            .with_context(|| format!("Failed to extract rules for baseline '{baseline}'"))?
    } else {
        tracing::info!("No mSCP repo path — using embedded rule data");
        crate::extractors::rules_from_embedded(&baseline, "macOS")
            .with_context(|| format!("Failed to load embedded rules for baseline '{baseline}'"))?
    };

    if rules.is_empty() {
        if matches!(output_mode, OutputMode::Human) {
            println!("{}", "No rules found for baseline".yellow());
            println!("Hint: Make sure the baseline name matches a tag in the rule files");
        }
        return Ok(());
    }

    // Load script constraints if provided
    let excluded_rules: HashSet<String> = if let Some(path) = &constraints_path {
        // Try Jamf constraints first (most common for script extraction), then Fleet
        let manager = if path.to_string_lossy().contains("jamf") {
            Constraints::load(ConstraintType::Jamf, Some(path.clone()))?
        } else if path.to_string_lossy().contains("fleet") {
            Constraints::load(ConstraintType::Fleet, Some(path.clone()))?
        } else {
            // Default to Jamf for script constraints
            Constraints::load(ConstraintType::Jamf, Some(path.clone()))?
        };

        if matches!(output_mode, OutputMode::Human) && !manager.get_excluded_scripts().is_empty() {
            println!(
                "Loading {} script exclusions from {}",
                manager.get_excluded_scripts().len().to_string().yellow(),
                path.display()
            );
        }

        manager
            .get_excluded_scripts()
            .iter()
            .map(|s| s.rule_id.clone())
            .collect()
    } else {
        HashSet::new()
    };

    // Load ODV overrides (auto-detect if not specified)
    let odv_manager = OdvOverrides::try_load(&baseline, odv_path);
    if let Some(ref odv) = odv_manager
        && matches!(output_mode, OutputMode::Human)
        && !odv.is_empty()
    {
        let custom_count = odv
            .get_overrides()
            .iter()
            .filter(|o| o.custom_value.is_some())
            .count();
        if custom_count > 0 {
            println!(
                "Loaded {} ODV override{} for baseline '{}'",
                custom_count.to_string().cyan(),
                if custom_count == 1 { "" } else { "s" },
                baseline
            );
        }
    }

    // Create output directories
    if !dry_run {
        create_output_dirs(&output, flat_output)?;
    }

    let mut result = ExtractionResult {
        scripts_created: Vec::new(),
        profile_only_rules: Vec::new(),
        skipped_rules: Vec::new(),
        excluded_rules: Vec::new(),
    };

    for rule in rules {
        // Skip excluded scripts from constraints
        if excluded_rules.contains(&rule.id) {
            result.excluded_rules.push(rule.id.clone());
            continue;
        }

        // Skip mobileconfig-only rules
        if rule.mobileconfig && !rule.has_script_remediation() {
            result.profile_only_rules.push(rule.id.clone());
            continue;
        }

        // Skip rules without executable fixes
        if !rule.has_executable_fix() {
            result.skipped_rules.push(rule.id.clone());
            continue;
        }

        // Get the cleaned fix script
        let fix_script = match rule.get_fix_script() {
            Some(script) if !script.is_empty() => {
                // Apply ODV substitution if manager is loaded
                if let Some(ref odv) = odv_manager {
                    odv.substitute(&rule.id, &script)
                } else {
                    script
                }
            }
            _ => {
                result.skipped_rules.push(rule.id.clone());
                continue;
            }
        };

        // Determine category and output path
        let category = ScriptCategory::from_rule_id(&rule.id);
        let script_path = if flat_output {
            output.join(format!("{}.sh", rule.id))
        } else {
            output
                .join(category.as_str())
                .join(format!("{}.sh", rule.id))
        };

        // Generate script content
        let script_content = generate_script_content(&rule.id, &rule.title, &baseline, &fix_script);

        if dry_run {
            if matches!(output_mode, OutputMode::Human) {
                println!("  {} {}", "[DRY RUN]".cyan(), script_path.display());
            }
        } else {
            script_helpers::write_executable(&script_path, &script_content)
                .with_context(|| format!("Failed to write script: {}", script_path.display()))?;
        }

        let relative_path = if flat_output {
            format!("{}.sh", rule.id)
        } else {
            format!("{}/{}.sh", category.as_str(), rule.id)
        };
        result.scripts_created.push(relative_path);
    }

    // Output results
    match output_mode {
        OutputMode::Human => print_human_output(&result, &output, &baseline, dry_run),
        OutputMode::Json => print_json_output(&result, &output, &baseline)?,
    }

    Ok(())
}

fn create_output_dirs(output: &Path, flat_output: bool) -> Result<()> {
    fs::create_dir_all(output)?;

    if !flat_output {
        for category in &[
            ScriptCategory::Ssh,
            ScriptCategory::Sshd,
            ScriptCategory::Sharing,
            ScriptCategory::Audit,
            ScriptCategory::Auth,
            ScriptCategory::System,
            ScriptCategory::Pwpolicy,
        ] {
            fs::create_dir_all(output.join(category.as_str()))?;
        }
    }

    Ok(())
}

fn generate_script_content(rule_id: &str, title: &str, baseline: &str, fix_script: &str) -> String {
    format!(
        r"#!/bin/zsh
# mSCP Remediation Script
# Rule: {rule_id}
# Title: {title}
# Baseline: {baseline}
#
# This script performs REMEDIATION only (not detection/audit)
# Run the compliance script with --check for detection
#
# Generated by contour mscp - https://github.com/macadmins/contour

set -e

{fix_script}
"
    )
}

fn print_human_output(result: &ExtractionResult, output: &Path, baseline: &str, dry_run: bool) {
    let prefix = if dry_run { "[DRY RUN] " } else { "" };

    println!();
    println!(
        "{}Extracted {} remediation scripts for '{}' to {}",
        prefix,
        result.scripts_created.len().to_string().green().bold(),
        baseline.cyan(),
        output.display().to_string().cyan()
    );

    if !result.excluded_rules.is_empty() {
        println!(
            "  {} rules excluded (via constraints)",
            result.excluded_rules.len().to_string().yellow()
        );
    }

    if !result.profile_only_rules.is_empty() {
        println!(
            "  {} profile-only rules (no script needed)",
            result.profile_only_rules.len().to_string().dimmed()
        );
    }

    if !result.skipped_rules.is_empty() {
        println!(
            "  {} rules skipped (no executable fix)",
            result.skipped_rules.len().to_string().dimmed()
        );
    }

    if !result.scripts_created.is_empty() {
        println!();
        println!("Scripts by category:");

        // Group by category
        let mut by_category: std::collections::HashMap<&str, Vec<&str>> =
            std::collections::HashMap::new();
        for script in &result.scripts_created {
            let category = script.split('/').next().unwrap_or("flat");
            by_category
                .entry(category)
                .or_default()
                .push(script.as_str());
        }

        for (category, scripts) in &by_category {
            println!("  {}: {}", category.bold(), scripts.len());
        }
    }
}

fn print_json_output(result: &ExtractionResult, output: &Path, baseline: &str) -> Result<()> {
    let json = serde_json::json!({
        "baseline": baseline,
        "output_dir": output.display().to_string(),
        "scripts_created": result.scripts_created.len(),
        "excluded_rules": result.excluded_rules.len(),
        "profile_only_rules": result.profile_only_rules.len(),
        "skipped_rules": result.skipped_rules.len(),
        "scripts": result.scripts_created,
        "excluded": result.excluded_rules,
    });

    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}
