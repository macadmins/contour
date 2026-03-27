use crate::generator::{GeneratorOptions, write_to_file};
use crate::models::{Policy, Rule, RuleSet, RuleType};
use crate::output::{CommandResult, OutputMode, print_json, print_success, print_warning};
use crate::parser::parse_file;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct AddOutput {
    added: bool,
    updated: bool,
    identifier: String,
    rule_type: String,
    total_rules: usize,
    regenerated: bool,
}

/// Add a rule to an existing rules file
/// Designed for use with Installomator posthooks
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
pub fn run(
    file: &Path,
    identifier: &str,
    rule_type: RuleType,
    policy: Policy,
    description: Option<&str>,
    group: Option<&str>,
    regenerate: Option<&Path>,
    org: Option<&str>,
    mode: OutputMode,
    interactive: bool,
) -> Result<()> {
    // Interactive mode: prompt for rule type if none was specified on CLI
    let (rule_type, identifier, description) = if interactive {
        interactive_add(rule_type, identifier, description)?
    } else {
        (
            rule_type,
            identifier.to_string(),
            description.map(|s| s.to_string()),
        )
    };
    let description = description.as_deref();

    // Load existing rules or create new file
    let mut rules = if file.exists() {
        parse_file(file).with_context(|| format!("Failed to parse {}", file.display()))?
    } else {
        RuleSet::new()
    };

    // Check if rule already exists
    let key = format!("{}:{}", rule_type.as_str(), identifier);
    let existing_idx = rules.rules().iter().position(|r| r.key() == key);

    let (added, updated) = if let Some(idx) = existing_idx {
        let existing = &rules.rules()[idx];

        if existing.policy == policy {
            // Same policy — skip
            if mode == OutputMode::Human {
                print_success(&format!(
                    "Rule {} already exists in {} with same policy",
                    identifier,
                    file.display()
                ));
            } else {
                print_json(&CommandResult::success(AddOutput {
                    added: false,
                    updated: false,
                    identifier: identifier.clone(),
                    rule_type: rule_type.as_str().to_string(),
                    total_rules: rules.len(),
                    regenerated: false,
                }))?;
            }
            return Ok(());
        }

        // Different policy — prompt or update
        let should_update = if mode == OutputMode::Human {
            let prompt = format!(
                "Rule {} exists as {}, update to {}?",
                identifier,
                existing.policy.as_str(),
                policy.as_str()
            );
            inquire::Confirm::new(&prompt)
                .with_default(false)
                .prompt()?
        } else {
            // JSON mode: update silently
            true
        };

        if should_update {
            // Update in place
            let rule = rules.rules_mut().get_mut(idx).unwrap();
            rule.policy = policy;
            if let Some(desc) = description {
                rule.description = Some(desc.to_string());
            }
            if let Some(grp) = group {
                rule.group = Some(grp.to_string());
            }
            (false, true)
        } else {
            if mode == OutputMode::Human {
                print_warning("Skipped — rule not updated");
            }
            return Ok(());
        }
    } else {
        // New rule
        let mut rule = Rule::new(rule_type, &identifier, policy);
        if let Some(desc) = description {
            rule = rule.with_description(desc);
        }
        if let Some(grp) = group {
            rule = rule.with_group(grp);
        }
        rules.add(rule);
        (true, false)
    };

    // Deduplicate and sort before writing
    rules.deduplicate();
    rules.sort();

    // Write updated rules file
    let yaml = yaml_serde::to_string(rules.rules())?;
    std::fs::write(file, &yaml).with_context(|| format!("Failed to write {}", file.display()))?;

    // Optionally regenerate mobileconfig
    let regenerated = if let Some(profile_path) = regenerate {
        let org_id = org.unwrap_or("com.example");
        let options = GeneratorOptions::new(org_id).with_deterministic_uuids(true);
        write_to_file(&rules, &options, profile_path)?;
        true
    } else {
        false
    };

    if mode == OutputMode::Human {
        let action = if updated { "Updated" } else { "Added" };
        print_success(&format!(
            "{} {} {} in {} ({} total rules)",
            action,
            rule_type.as_str(),
            identifier,
            file.display(),
            rules.len()
        ));
        if regenerated {
            print_success(&format!("Regenerated {}", regenerate.unwrap().display()));
        }
    } else {
        print_json(&CommandResult::success(AddOutput {
            added,
            updated,
            identifier: identifier.clone(),
            rule_type: rule_type.as_str().to_string(),
            total_rules: rules.len(),
            regenerated,
        }))?;
    }

    Ok(())
}

/// Interactive rule type wizard: prompt user to choose a rule type and enter an identifier.
fn interactive_add(
    default_type: RuleType,
    default_id: &str,
    default_desc: Option<&str>,
) -> Result<(RuleType, String, Option<String>)> {
    // If an identifier was already given on CLI, just use it with the default type
    if !default_id.is_empty()
        && default_id
            != "Must specify one of: --teamid, --binary, --certificate, --signingid, --cdhash"
    {
        return Ok((
            default_type,
            default_id.to_string(),
            default_desc.map(|s| s.to_string()),
        ));
    }

    let options = vec![
        "TeamID — Trust all apps from a developer (10-char identifier, e.g. EQHXZ8M8AV)",
        "SigningID — Trust a specific app (TeamID:BundleID, e.g. EQHXZ8M8AV:com.google.Chrome)",
        "Binary — Trust a specific binary (SHA-256 hash)",
        "Certificate — Trust a certificate (SHA-256 hash)",
        "CDHash — Trust a specific code directory hash (40-char)",
    ];

    let choice = inquire::Select::new("What type of rule do you want to add?", options)
        .with_help_message("Select the rule type that best matches your needs")
        .prompt()?;

    let rule_type = if choice.starts_with("TeamID") {
        RuleType::TeamId
    } else if choice.starts_with("SigningID") {
        RuleType::SigningId
    } else if choice.starts_with("Binary") {
        RuleType::Binary
    } else if choice.starts_with("Certificate") {
        RuleType::Certificate
    } else {
        RuleType::Cdhash
    };

    let id_prompt = match rule_type {
        RuleType::TeamId => "Enter TeamID (10-character identifier):",
        RuleType::SigningId => "Enter SigningID (TeamID:BundleID):",
        RuleType::Binary => "Enter binary SHA-256 hash:",
        RuleType::Certificate => "Enter certificate SHA-256 hash:",
        RuleType::Cdhash => "Enter CDHash (40-character hash):",
    };

    let identifier = inquire::Text::new(id_prompt).prompt()?;

    let description = if let Some(d) = default_desc {
        Some(d.to_string())
    } else {
        let desc = inquire::Text::new("Description (optional, press Enter to skip):")
            .with_default("")
            .prompt()?;
        if desc.is_empty() { None } else { Some(desc) }
    };

    Ok((rule_type, identifier, description))
}
