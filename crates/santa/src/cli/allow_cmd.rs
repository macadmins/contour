//! CSV-to-mobileconfig allowlist generation.
//!
//! Converts a CSV (from `contour santa scan` or Fleet export) directly into
//! a mobileconfig profile — no bundles, no discovery step.

use crate::cli::ScanRuleType;
use crate::discovery::parse_fleet_csv_file;
use crate::generator::{self, GeneratorOptions};
use crate::models::{Policy, Rule, RuleSet, RuleType};
use crate::output::{print_info, print_kv, print_success};
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

/// Run the allow command.
pub fn run(
    input: &Path,
    output: Option<&Path>,
    rule_type: ScanRuleType,
    org: &str,
    name: Option<&str>,
    deterministic_uuids: bool,
    dry_run: bool,
    json_output: bool,
) -> Result<()> {
    let output_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("santa-rules.mobileconfig"));

    // Resolve display name: explicit --name > ContourConfig org name > default
    let display_name = name.map(|n| n.to_string()).unwrap_or_else(|| {
        contour_core::config::ContourConfig::load_nearest()
            .map(|c| format!("{} Santa Allowlist Rules", c.organization.name))
            .unwrap_or_else(|| "Santa Allowlist Rules".to_string())
    });

    if !json_output {
        print_info("Converting CSV to Santa allowlist profile...");
        print_kv("Input", &input.display().to_string());
        print_kv("Output", &output_path.display().to_string());
        print_kv("Organization", org);
        print_kv("Profile name", &display_name);
        print_kv(
            "Rule type",
            match rule_type {
                ScanRuleType::TeamId => "team-id (vendor-level)",
                ScanRuleType::SigningId => "signing-id (app-level)",
            },
        );
        print_kv(
            "Deterministic UUIDs",
            if deterministic_uuids { "yes" } else { "no" },
        );
    }

    // Parse CSV
    let apps = parse_fleet_csv_file(input)?;

    if !json_output {
        print_kv("Apps loaded", &apps.len().to_string());
    }

    // Convert to rules
    let rules = records_to_rules(&apps, rule_type);

    if !json_output {
        print_kv("Rules generated", &rules.len().to_string());
    }

    if dry_run {
        if !json_output {
            println!();
            print_info("Dry run — rules that would be generated:");
            for rule in rules.rules() {
                println!(
                    "  {:?} {} — {}",
                    rule.rule_type,
                    rule.identifier,
                    rule.description.as_deref().unwrap_or("")
                );
            }
        } else {
            let result = AllowResult {
                input: input.display().to_string(),
                output: output_path.display().to_string(),
                rules_count: rules.len(),
                dry_run: true,
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    // Generate mobileconfig
    let options = GeneratorOptions::new(org)
        .with_identifier(&format!("{}.santa.allowlist", org))
        .with_display_name(&display_name)
        .with_description("Santa binary authorization allowlist rules")
        .with_deterministic_uuids(deterministic_uuids);

    generator::write_to_file(&rules, &options, &output_path)?;

    if json_output {
        let result = AllowResult {
            input: input.display().to_string(),
            output: output_path.display().to_string(),
            rules_count: rules.len(),
            dry_run: false,
        };
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!();
        print_success(&format!(
            "{} rules written to {}",
            rules.len(),
            output_path.display()
        ));
        println!();
        print_info("Next steps:");
        println!("  1. Review the generated profile");
        println!("  2. Deploy {} via MDM", output_path.display());
    }

    Ok(())
}

/// Convert AppRecordSet to Santa rules based on rule type.
fn records_to_rules(apps: &crate::cel::AppRecordSet, rule_type: ScanRuleType) -> RuleSet {
    let mut rules = RuleSet::new();

    match rule_type {
        ScanRuleType::TeamId => {
            let mut seen: HashMap<String, String> = HashMap::new();
            for app in apps.apps() {
                if let Some(team_id) = &app.team_id {
                    seen.entry(team_id.clone())
                        .or_insert_with(|| app.app_name.clone().unwrap_or_else(|| team_id.clone()));
                }
            }

            let mut team_ids: Vec<_> = seen.keys().cloned().collect();
            team_ids.sort();

            for team_id in team_ids {
                let desc = &seen[&team_id];
                let rule =
                    Rule::new(RuleType::TeamId, &team_id, Policy::Allowlist).with_description(desc);
                rules.add(rule);
            }
        }
        ScanRuleType::SigningId => {
            let mut seen: HashMap<String, String> = HashMap::new();
            for app in apps.apps() {
                if let Some(signing_id) = &app.signing_id {
                    seen.entry(signing_id.clone()).or_insert_with(|| {
                        app.app_name.clone().unwrap_or_else(|| signing_id.clone())
                    });
                }
            }

            let mut signing_ids: Vec<_> = seen.keys().cloned().collect();
            signing_ids.sort();

            for signing_id in signing_ids {
                let desc = &seen[&signing_id];
                let rule = Rule::new(RuleType::SigningId, &signing_id, Policy::Allowlist)
                    .with_description(desc);
                rules.add(rule);
            }
        }
    }

    rules
}

#[derive(Debug, serde::Serialize)]
struct AllowResult {
    input: String,
    output: String,
    rules_count: usize,
    dry_run: bool,
}
