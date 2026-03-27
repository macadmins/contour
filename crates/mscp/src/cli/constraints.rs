//! CLI handlers for the constraints command.
//!
//! Provides interactive management of constraint files with fuzzy search.

use anyhow::{Context, Result};
use colored::Colorize;
use inquire::{Confirm, MultiSelect, Text};
use std::path::PathBuf;

use crate::managers::{
    ConstraintType, Constraints, ExcludedProfile, ExcludedScript, ProfileInfo, ScriptInfo,
    build_exclusion_plan, discover_categories,
};
use crate::output::OutputMode;

/// Add profiles to exclusion list via fuzzy search
pub fn constraints_add(
    constraint_type: ConstraintType,
    constraints_path: Option<PathBuf>,
    mscp_repo: Option<PathBuf>,
    baseline: Option<String>,
    output_mode: OutputMode,
) -> Result<()> {
    let mut manager = Constraints::load(constraint_type, constraints_path)?;

    // Determine mSCP repo path
    let mscp = mscp_repo.unwrap_or_else(|| PathBuf::from("./macos_security"));

    if !mscp.exists() {
        anyhow::bail!(
            "mSCP repository not found at: {}\nUse --mscp-repo to specify the path",
            mscp.display()
        );
    }

    if output_mode == OutputMode::Human {
        println!("\nDiscovering profiles from mSCP repository...");
    }

    // Discover available profiles
    let all_profiles = Constraints::discover_profiles(&mscp, baseline.as_deref())
        .context("Failed to discover profiles from mSCP repository")?;

    if all_profiles.is_empty() {
        if output_mode == OutputMode::Human {
            println!(
                "{} No profiles found. Make sure mSCP has been built with `generate_guidance`.",
                "Warning:".yellow()
            );
            if let Some(b) = &baseline {
                println!("  Searched for baseline: {b}");
            }
        }
        return Ok(());
    }

    // Filter out already excluded profiles
    let available: Vec<&ProfileInfo> = all_profiles
        .iter()
        .filter(|p| !manager.is_excluded(&p.filename))
        .collect();

    let excluded_count = all_profiles.len() - available.len();

    if output_mode == OutputMode::Human {
        println!(
            "Found {} profiles ({} available, {} already excluded)\n",
            all_profiles.len().to_string().cyan(),
            available.len().to_string().green(),
            excluded_count.to_string().yellow()
        );
    }

    if available.is_empty() {
        if output_mode == OutputMode::Human {
            println!("All profiles are already excluded.");
        }
        return Ok(());
    }

    // Build options for multi-select with fuzzy filtering
    let options: Vec<String> = available.iter().map(|p| p.filename.clone()).collect();

    // Multi-select with built-in fuzzy search (type to filter)
    let selected = MultiSelect::new(
        "Select profiles to exclude (type to filter, space to select, enter to confirm):",
        options,
    )
    .with_vim_mode(true)
    .with_page_size(15)
    .with_help_message("Type to fuzzy search, Space to toggle, Enter to confirm")
    .prompt();

    let selected = match selected {
        Ok(s) => s,
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => {
            if output_mode == OutputMode::Human {
                println!("\nOperation cancelled.");
            }
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    if selected.is_empty() {
        if output_mode == OutputMode::Human {
            println!("\nNo profiles selected.");
        }
        return Ok(());
    }

    // For each selected profile, prompt for details
    for filename in &selected {
        if output_mode == OutputMode::Human {
            println!("\n{}", format!("Adding: {filename}").cyan().bold());
        }

        let default_reason = match constraint_type {
            ConstraintType::Fleet => "Conflicts with Fleet native settings",
            ConstraintType::Jamf => "Conflicts with Jamf Pro native capabilities",
            ConstraintType::Munki => "Excluded from Munki processing",
        };

        let reason = Text::new("Reason for exclusion:")
            .with_default(default_reason)
            .with_help_message("Explain why this profile is excluded")
            .prompt()
            .unwrap_or_else(|_| default_reason.to_string());

        let alternative_prompt = match constraint_type {
            ConstraintType::Fleet => "Fleet alternative (optional):",
            ConstraintType::Jamf => "Jamf alternative (optional):",
            ConstraintType::Munki => "Alternative (optional):",
        };

        let alternative = Text::new(alternative_prompt)
            .with_help_message(
                "Describe how to achieve this setting natively (press Enter to skip)",
            )
            .prompt()
            .unwrap_or_default();

        manager.add_exclusion(ExcludedProfile {
            filename: filename.clone(),
            reason,
            fleet_alternative: alternative,
            exclude_munki_scripts: false,
            affected_rules: vec![],
        });

        if output_mode == OutputMode::Human {
            println!("{} Added {}", "✓".green(), filename.green());
        }
    }

    manager.save()?;

    if output_mode == OutputMode::Human {
        println!(
            "\n{} Saved {} exclusions to {}",
            "✓".green().bold(),
            selected.len().to_string().cyan(),
            manager.constraints_path().display().to_string().cyan()
        );
    }

    Ok(())
}

/// Remove profiles from exclusion list
pub fn constraints_remove(
    constraint_type: ConstraintType,
    constraints_path: Option<PathBuf>,
    output_mode: OutputMode,
) -> Result<()> {
    let mut manager = Constraints::load(constraint_type, constraints_path)?;

    let excluded = manager.get_excluded();

    if excluded.is_empty() {
        if output_mode == OutputMode::Human {
            println!("No profiles are currently excluded.");
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human {
        println!(
            "\nCurrently excluded ({} profiles):\n",
            excluded.len().to_string().cyan()
        );
    }

    // Build options for multi-select
    let options: Vec<String> = excluded.iter().map(|p| p.filename.clone()).collect();

    let selected = MultiSelect::new(
        "Select profiles to remove from exclusions (type to filter, space to select):",
        options,
    )
    .with_vim_mode(true)
    .with_page_size(15)
    .with_help_message("Type to fuzzy search, Space to toggle, Enter to confirm")
    .prompt();

    let selected = match selected {
        Ok(s) => s,
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => {
            if output_mode == OutputMode::Human {
                println!("\nOperation cancelled.");
            }
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    if selected.is_empty() {
        if output_mode == OutputMode::Human {
            println!("\nNo profiles selected for removal.");
        }
        return Ok(());
    }

    // Confirm removal
    let confirm = Confirm::new(&format!(
        "Remove {} profile(s) from exclusions?",
        selected.len()
    ))
    .with_default(false)
    .prompt()
    .unwrap_or(false);

    if !confirm {
        if output_mode == OutputMode::Human {
            println!("Operation cancelled.");
        }
        return Ok(());
    }

    // Remove selected profiles
    let mut removed_count = 0;
    for filename in &selected {
        if manager.remove_exclusion(filename) {
            removed_count += 1;
            if output_mode == OutputMode::Human {
                println!("{} Removed {}", "✓".green(), filename.green());
            }
        }
    }

    if removed_count > 0 {
        manager.save()?;
        if output_mode == OutputMode::Human {
            println!(
                "\n{} Removed {} exclusions from {}",
                "✓".green().bold(),
                removed_count.to_string().cyan(),
                manager.constraints_path().display().to_string().cyan()
            );
        }
    }

    Ok(())
}

/// List currently excluded profiles
pub fn constraints_list(
    constraint_type: ConstraintType,
    constraints_path: Option<PathBuf>,
    output_mode: OutputMode,
) -> Result<()> {
    let manager = Constraints::load(constraint_type, constraints_path)?;

    let excluded = manager.get_excluded();

    if output_mode == OutputMode::Json {
        let json = serde_json::json!({
            "constraint_type": format!("{constraint_type}"),
            "constraints_file": manager.constraints_path().display().to_string(),
            "excluded_profiles": excluded,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    // Human output
    println!(
        "\n{} Constraint Exclusions ({})\n",
        constraint_type.to_string().cyan().bold(),
        manager.constraints_path().display().to_string().dimmed()
    );

    if excluded.is_empty() {
        println!("No profiles are currently excluded.");
        return Ok(());
    }

    println!(
        "Excluded Profiles ({}):\n",
        excluded.len().to_string().cyan()
    );

    for profile in excluded {
        println!("  {} {}", "•".cyan(), profile.filename.green());
        println!("    {}: {}", "Reason".dimmed(), profile.reason);
        if !profile.fleet_alternative.is_empty() {
            println!(
                "    {}: {}",
                "Alternative".dimmed(),
                profile.fleet_alternative
            );
        }
        if profile.exclude_munki_scripts {
            println!("    {}: {}", "Munki scripts".dimmed(), "excluded".yellow());
        }
        if !profile.affected_rules.is_empty() {
            println!(
                "    {}: {}",
                "Affected rules".dimmed(),
                profile.affected_rules.join(", ")
            );
        }
        println!();
    }

    Ok(())
}

/// Add scripts to exclusion list via fuzzy search
pub fn constraints_add_script(
    constraint_type: ConstraintType,
    constraints_path: Option<PathBuf>,
    mscp_repo: Option<PathBuf>,
    baseline: Option<String>,
    output_mode: OutputMode,
) -> Result<()> {
    let mut manager = Constraints::load(constraint_type, constraints_path)?;

    // Determine mSCP repo path
    let mscp = mscp_repo.unwrap_or_else(|| PathBuf::from("./macos_security"));

    if !mscp.exists() {
        anyhow::bail!(
            "mSCP repository not found at: {}\nUse --mscp-repo to specify the path",
            mscp.display()
        );
    }

    if output_mode == OutputMode::Human {
        println!("\nDiscovering scripts from mSCP repository...");
    }

    // Discover available scripts
    let all_scripts = Constraints::discover_scripts(&mscp, baseline.as_deref())
        .context("Failed to discover scripts from mSCP repository")?;

    if all_scripts.is_empty() {
        if output_mode == OutputMode::Human {
            println!(
                "{} No scripts with executable fixes found.",
                "Warning:".yellow()
            );
            if let Some(b) = &baseline {
                println!("  Searched for baseline: {b}");
            }
        }
        return Ok(());
    }

    // Filter out already excluded scripts
    let available: Vec<&ScriptInfo> = all_scripts
        .iter()
        .filter(|s| !manager.is_script_excluded(&s.rule_id))
        .collect();

    let excluded_count = all_scripts.len() - available.len();

    if output_mode == OutputMode::Human {
        println!(
            "Found {} scripts ({} available, {} already excluded)\n",
            all_scripts.len().to_string().cyan(),
            available.len().to_string().green(),
            excluded_count.to_string().yellow()
        );
    }

    if available.is_empty() {
        if output_mode == OutputMode::Human {
            println!("All scripts are already excluded.");
        }
        return Ok(());
    }

    // Build options for multi-select with fuzzy filtering
    let options: Vec<String> = available
        .iter()
        .map(|s| format!("{} - {}", s.rule_id, s.title))
        .collect();

    // Multi-select with built-in fuzzy search (type to filter)
    let selected = MultiSelect::new(
        "Select scripts to exclude (type to filter, space to select, enter to confirm):",
        options.clone(),
    )
    .with_vim_mode(true)
    .with_page_size(15)
    .with_help_message("Type to fuzzy search (e.g., 'ssh'), Space to toggle, Enter to confirm")
    .prompt();

    let selected = match selected {
        Ok(s) => s,
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => {
            if output_mode == OutputMode::Human {
                println!("\nOperation cancelled.");
            }
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    if selected.is_empty() {
        if output_mode == OutputMode::Human {
            println!("\nNo scripts selected.");
        }
        return Ok(());
    }

    // Extract rule IDs from selected options
    let selected_rule_ids: Vec<&str> = selected
        .iter()
        .filter_map(|s| s.split(" - ").next())
        .collect();

    // For each selected script, prompt for details
    for rule_id in &selected_rule_ids {
        let script = available
            .iter()
            .find(|s| s.rule_id == *rule_id)
            .ok_or_else(|| anyhow::anyhow!("selected script not found in available list"))?;

        if output_mode == OutputMode::Human {
            println!(
                "\n{}",
                format!("Adding: {} - {}", rule_id, script.title)
                    .cyan()
                    .bold()
            );
        }

        let default_reason = match constraint_type {
            ConstraintType::Fleet => "Script managed externally",
            ConstraintType::Jamf => "Script managed by Jamf Pro or external tool",
            ConstraintType::Munki => "Excluded from Munki processing",
        };

        let reason = Text::new("Reason for exclusion:")
            .with_default(default_reason)
            .with_help_message("Explain why this script is excluded")
            .prompt()
            .unwrap_or_else(|_| default_reason.to_string());

        let alternative = Text::new("Alternative (optional):")
            .with_help_message("Describe how this is managed instead (press Enter to skip)")
            .prompt()
            .unwrap_or_default();

        manager.add_script_exclusion(ExcludedScript {
            rule_id: (*rule_id).to_string(),
            reason,
            alternative,
        });

        if output_mode == OutputMode::Human {
            println!("{} Added {}", "✓".green(), rule_id.green());
        }
    }

    manager.save()?;

    if output_mode == OutputMode::Human {
        println!(
            "\n{} Saved {} script exclusions to {}",
            "✓".green().bold(),
            selected_rule_ids.len().to_string().cyan(),
            manager.constraints_path().display().to_string().cyan()
        );
    }

    Ok(())
}

/// Remove scripts from exclusion list
pub fn constraints_remove_script(
    constraint_type: ConstraintType,
    constraints_path: Option<PathBuf>,
    output_mode: OutputMode,
) -> Result<()> {
    let mut manager = Constraints::load(constraint_type, constraints_path)?;

    let excluded = manager.get_excluded_scripts();

    if excluded.is_empty() {
        if output_mode == OutputMode::Human {
            println!("No scripts are currently excluded.");
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human {
        println!(
            "\nCurrently excluded ({} scripts):\n",
            excluded.len().to_string().cyan()
        );
    }

    // Build options for multi-select
    let options: Vec<String> = excluded.iter().map(|s| s.rule_id.clone()).collect();

    let selected = MultiSelect::new(
        "Select scripts to remove from exclusions (type to filter, space to select):",
        options,
    )
    .with_vim_mode(true)
    .with_page_size(15)
    .with_help_message("Type to fuzzy search, Space to toggle, Enter to confirm")
    .prompt();

    let selected = match selected {
        Ok(s) => s,
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => {
            if output_mode == OutputMode::Human {
                println!("\nOperation cancelled.");
            }
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    if selected.is_empty() {
        if output_mode == OutputMode::Human {
            println!("\nNo scripts selected for removal.");
        }
        return Ok(());
    }

    // Confirm removal
    let confirm = Confirm::new(&format!(
        "Remove {} script(s) from exclusions?",
        selected.len()
    ))
    .with_default(false)
    .prompt()
    .unwrap_or(false);

    if !confirm {
        if output_mode == OutputMode::Human {
            println!("Operation cancelled.");
        }
        return Ok(());
    }

    // Remove selected scripts
    let mut removed_count = 0;
    for rule_id in &selected {
        if manager.remove_script_exclusion(rule_id) {
            removed_count += 1;
            if output_mode == OutputMode::Human {
                println!("{} Removed {}", "✓".green(), rule_id.green());
            }
        }
    }

    if removed_count > 0 {
        manager.save()?;
        if output_mode == OutputMode::Human {
            println!(
                "\n{} Removed {} script exclusions from {}",
                "✓".green().bold(),
                removed_count.to_string().cyan(),
                manager.constraints_path().display().to_string().cyan()
            );
        }
    }

    Ok(())
}

/// List currently excluded scripts
pub fn constraints_list_scripts(
    constraint_type: ConstraintType,
    constraints_path: Option<PathBuf>,
    output_mode: OutputMode,
) -> Result<()> {
    let manager = Constraints::load(constraint_type, constraints_path)?;

    let excluded = manager.get_excluded_scripts();

    if output_mode == OutputMode::Json {
        let json = serde_json::json!({
            "constraint_type": format!("{constraint_type}"),
            "constraints_file": manager.constraints_path().display().to_string(),
            "excluded_scripts": excluded,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    // Human output
    println!(
        "\n{} Script Exclusions ({})\n",
        constraint_type.to_string().cyan().bold(),
        manager.constraints_path().display().to_string().dimmed()
    );

    if excluded.is_empty() {
        println!("No scripts are currently excluded.");
        return Ok(());
    }

    println!(
        "Excluded Scripts ({}):\n",
        excluded.len().to_string().cyan()
    );

    for script in excluded {
        println!("  {} {}", "•".cyan(), script.rule_id.green());
        println!("    {}: {}", "Reason".dimmed(), script.reason);
        if !script.alternative.is_empty() {
            println!("    {}: {}", "Alternative".dimmed(), script.alternative);
        }
        println!();
    }

    Ok(())
}

/// Add category-based exclusions (interactive picker or direct via --exclude)
pub fn constraints_add_categories(
    constraint_type: ConstraintType,
    constraints_path: Option<PathBuf>,
    mscp_repo: Option<PathBuf>,
    baseline: String,
    exclude: Option<Vec<String>>,
    output_mode: OutputMode,
) -> Result<()> {
    let mut manager = Constraints::load(constraint_type, constraints_path)?;

    // Determine mSCP repo path
    let mscp = mscp_repo.unwrap_or_else(|| PathBuf::from("./macos_security"));

    if !mscp.exists() {
        anyhow::bail!(
            "mSCP repository not found at: {}\nUse --mscp-repo to specify the path",
            mscp.display()
        );
    }

    // If --exclude provided, skip discovery and picker entirely
    let selected_names = if let Some(names) = exclude {
        names
    } else {
        // Interactive mode: discover and present picker
        if output_mode == OutputMode::Human {
            println!(
                "\nDiscovering categories for baseline '{}'...",
                baseline.cyan()
            );
        }

        let categories = discover_categories(&mscp, Some(&baseline))
            .context("Failed to discover categories from mSCP repository")?;

        if categories.is_empty() {
            if output_mode == OutputMode::Human {
                println!(
                    "{} No categories found for baseline '{baseline}'.",
                    "Warning:".yellow()
                );
            }
            return Ok(());
        }

        let dir_count = categories.iter().filter(|c| c.is_directory).count();
        let sub_count = categories.len() - dir_count;

        if output_mode == OutputMode::Human {
            println!(
                "Found {} directory categories and {} sub-categories\n",
                dir_count.to_string().cyan(),
                sub_count.to_string().cyan()
            );
        }

        // Build display options: directory categories first, then sub-categories
        let dir_categories: Vec<_> = categories.iter().filter(|c| c.is_directory).collect();
        let sub_categories: Vec<_> = categories.iter().filter(|c| !c.is_directory).collect();

        let mut options: Vec<String> = Vec::new();
        for cat in &dir_categories {
            let label = if cat.rule_count == 1 {
                format!("{} (1 rule)", cat.name)
            } else {
                format!("{} ({} rules)", cat.name, cat.rule_count)
            };
            options.push(label);
        }
        for cat in &sub_categories {
            let label = if cat.rule_count == 1 {
                format!("{} (1 rule)", cat.name)
            } else {
                format!("{} ({} rules)", cat.name, cat.rule_count)
            };
            options.push(label);
        }

        let selected = MultiSelect::new(
            "Select categories to exclude (type to filter, space to select, enter to confirm):",
            options,
        )
        .with_vim_mode(true)
        .with_page_size(15)
        .with_help_message("Type to fuzzy search, Space to toggle, Enter to confirm")
        .prompt();

        let selected = match selected {
            Ok(s) => s,
            Err(
                inquire::InquireError::OperationCanceled
                | inquire::InquireError::OperationInterrupted,
            ) => {
                if output_mode == OutputMode::Human {
                    println!("\nOperation cancelled.");
                }
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        if selected.is_empty() {
            if output_mode == OutputMode::Human {
                println!("\nNo categories selected.");
            }
            return Ok(());
        }

        // Extract category names from selected options (strip " (N rules)" suffix)
        selected
            .iter()
            .filter_map(|s| s.split(" (").next().map(String::from))
            .collect()
    };

    if output_mode == OutputMode::Human {
        println!("\nResolving exclusions...");
    }

    // Build exclusion plan
    let plan = build_exclusion_plan(&selected_names, &mscp, &baseline)
        .context("Failed to build exclusion plan")?;

    // Print resolution details
    if output_mode == OutputMode::Human {
        for resolved in &plan.resolved {
            let profile_count = resolved.affected_profiles.len();
            let script_count = resolved.affected_scripts.len();
            println!(
                "  {}: {} rules matched ({} profiles, {} scripts)",
                resolved.name.cyan(),
                resolved.matched_rules.len(),
                profile_count,
                script_count
            );
        }

        for unresolved in &plan.unresolved {
            println!(
                "  {} Category '{}' did not match any rules",
                "⚠".yellow(),
                unresolved
            );
        }

        // Print warnings for partial profile matches
        for warning in &plan.warnings {
            println!("\n{} {}", "⚠".yellow(), warning);
        }
    }

    // Merge into constraint file
    let result = manager.merge_category_exclusions(&plan);

    manager.save()?;

    if output_mode == OutputMode::Human {
        let already = result.profiles_skipped + result.scripts_skipped;
        println!(
            "\n{} Saved to {}",
            "✓".green().bold(),
            manager.constraints_path().display().to_string().cyan()
        );
        println!(
            "  {} profiles added, {} scripts added{}",
            result.profiles_added.to_string().cyan(),
            result.scripts_added.to_string().cyan(),
            if already > 0 {
                format!(" ({already} already existed)")
            } else {
                String::new()
            }
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_constraints_list_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-constraints.yml");

        // Should not error on empty/nonexistent file
        let result = constraints_list(ConstraintType::Fleet, Some(path), OutputMode::Json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_constraints_list_scripts_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-constraints.yml");

        // Should not error on empty/nonexistent file
        let result = constraints_list_scripts(ConstraintType::Jamf, Some(path), OutputMode::Json);
        assert!(result.is_ok());
    }
}
