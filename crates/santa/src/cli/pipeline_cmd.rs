//! Pipeline command implementation.
//!
//! Runs the full end-to-end pipeline from CSV to mobileconfig profiles.

use crate::bundle::{
    BundleSet, ConflictPolicy, DedupLevel, OrphanPolicy, RuleTypeStrategy, StageConfig,
};
use crate::generator::{Format, GeneratorOptions, write_to_file_format};
use crate::output::{print_bar_chart, print_error, print_info, print_kv, print_success};
use crate::pipeline::{LayerStageSummary, LockEntry, PipelineBuilder, PipelineLock};
use anyhow::Result;
use colored::Colorize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Run the pipeline command.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
pub fn run(
    input: &Path,
    bundles_path: &Path,
    output_dir: Option<&Path>,
    org: &str,
    dedup_level: DedupLevel,
    rule_type_strategy: RuleTypeStrategy,
    orphan_policy: OrphanPolicy,
    conflict_policy: ConflictPolicy,
    deterministic: bool,
    layer_stage: bool,
    stages: u8,
    dry_run: bool,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    // Load bundles
    print_info(&format!("Loading bundles: {}", bundles_path.display()));
    let bundles = BundleSet::from_toml_file(bundles_path)?;
    print_kv("Bundles loaded", &bundles.len().to_string());

    if bundles.is_empty() {
        print_error("No bundles defined. Run 'contour santa discover' first.");
        anyhow::bail!("No bundles defined");
    }

    // Get stage config based on CLI option
    let stage_config = match stages {
        2 => StageConfig::two_stages(),
        5 => StageConfig::five_stages(),
        _ => StageConfig::three_stages(),
    };

    // Build pipeline
    let mut builder = PipelineBuilder::new()
        .dedup_level(dedup_level)
        .rule_type_strategy(rule_type_strategy)
        .orphan_policy(orphan_policy)
        .conflict_policy(conflict_policy)
        .deterministic(deterministic)
        .org(org)
        .label_prefix("santa-");

    if layer_stage {
        builder = builder.stages(stage_config).enable_layer_stage_matrix(true);
    }

    let pipeline = builder.build();

    // Run pipeline
    print_info(&format!("Processing CSV: {}", input.display()));

    if layer_stage {
        // Run Layer × Stage matrix pipeline
        run_layer_stage_pipeline(
            &pipeline,
            input,
            &bundles,
            output_dir,
            org,
            deterministic,
            dry_run,
            json_output,
            verbose,
        )
    } else {
        // Run standard pipeline
        run_standard_pipeline(
            &pipeline,
            input,
            &bundles,
            output_dir,
            org,
            deterministic,
            dry_run,
            json_output,
            verbose,
        )
    }
}

/// Run the standard (non-Layer×Stage) pipeline.
fn run_standard_pipeline(
    pipeline: &crate::pipeline::Pipeline,
    input: &Path,
    bundles: &BundleSet,
    output_dir: Option<&Path>,
    org: &str,
    deterministic: bool,
    dry_run: bool,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    let result = pipeline.run(input, bundles)?;

    let summary = result.summary();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    // Display summary
    display_summary(&summary, verbose);

    if dry_run {
        print_info("Dry run - no files written");
        return Ok(());
    }

    // Write output files
    let output_dir = output_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("./profiles"));

    if !output_dir.exists() {
        std::fs::create_dir_all(&output_dir)?;
    }

    // Write rules by bundle
    let rules_by_bundle = result.rules_by_bundle();
    let mut written_files = Vec::new();

    for (bundle_name, rules) in &rules_by_bundle {
        if rules.is_empty() {
            continue;
        }

        let rules_vec: Vec<_> = rules.iter().map(|r| (*r).clone()).collect();
        let ruleset = crate::models::RuleSet::from_rules(rules_vec);

        // Write mobileconfig
        let profile_name = format!("santa-{}", bundle_name);
        let mobileconfig_path = output_dir.join(format!("{}.mobileconfig", profile_name));

        let options = GeneratorOptions::new(org)
            .with_identifier(&format!("{}.santa.{}", org, bundle_name))
            .with_display_name(&format!("Santa Rules - {}", bundle_name))
            .with_deterministic_uuids(deterministic);

        write_to_file_format(&ruleset, &options, &mobileconfig_path, Format::Mobileconfig)?;

        written_files.push(mobileconfig_path.clone());

        if verbose {
            print_kv(
                &format!("  {}", bundle_name),
                &format!("{} rules -> {}", rules.len(), mobileconfig_path.display()),
            );
        }
    }

    // Write combined rules YAML
    let rules_yaml_path = output_dir.join("rules.yaml");
    let rules_yaml = yaml_serde::to_string(result.rules.rules())?;
    std::fs::write(&rules_yaml_path, rules_yaml)?;
    written_files.push(rules_yaml_path);

    // Write coverage report
    let report_path = output_dir.join("coverage-report.yaml");
    let report = result.coverage_report();
    let report_yaml = yaml_serde::to_string(&report)?;
    std::fs::write(&report_path, report_yaml)?;
    written_files.push(report_path);

    // Write/update lock file
    let lock_path = output_dir.join("santa.lock");
    let mut lock = if lock_path.exists() {
        PipelineLock::from_yaml_file(&lock_path).unwrap_or_default()
    } else {
        PipelineLock::new()
    };

    // Track previous state for diff
    let previous_lock = lock.clone();

    for rule in result.rules.rules() {
        let key = rule.key();
        if !lock.has_rule(&key) {
            let entry = LockEntry::new(
                rule.rule_type.as_str(),
                &rule.identifier,
                rule.policy.as_str(),
                rule.group.as_deref().unwrap_or("unknown"),
            )
            .with_description(rule.description.clone().unwrap_or_default());
            lock.add_rule(key, entry);
        }
    }

    lock.to_yaml_file(&lock_path)?;
    written_files.push(lock_path.clone());

    // Show diff
    let diff = lock.diff(&previous_lock);
    if diff.has_changes() {
        println!();
        println!("{}", "Changes from previous run".bold());
        println!("{}", "-".repeat(40));
        if !diff.added.is_empty() {
            println!("  Added: {} rules", diff.added.len().to_string().green());
        }
        if !diff.removed.is_empty() {
            println!("  Removed: {} rules", diff.removed.len().to_string().red());
        }
        if !diff.changed.is_empty() {
            println!(
                "  Changed: {} rules",
                diff.changed.len().to_string().yellow()
            );
        }
    }

    // Final output
    println!();
    print_success(&format!(
        "Pipeline complete! {} files written to {}",
        written_files.len(),
        output_dir.display()
    ));

    for file in &written_files {
        println!("  - {}", file.display());
    }

    Ok(())
}

/// Run the Layer × Stage matrix pipeline.
fn run_layer_stage_pipeline(
    pipeline: &crate::pipeline::Pipeline,
    input: &Path,
    bundles: &BundleSet,
    output_dir: Option<&Path>,
    org: &str,
    deterministic: bool,
    dry_run: bool,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    let result = pipeline.run_layer_stage_matrix(input, bundles)?;

    let summary = result.summary();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    // Display Layer × Stage summary
    display_layer_stage_summary(&summary, verbose);

    if dry_run {
        print_info("Dry run - no files written");
        return Ok(());
    }

    // Write output files
    let output_dir = output_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("./profiles"));

    if !output_dir.exists() {
        std::fs::create_dir_all(&output_dir)?;
    }

    let mut written_files = Vec::new();

    // Write a mobileconfig for each Layer × Stage combination
    for profile in &result.profiles {
        if profile.rules.is_empty() {
            continue;
        }

        let profile_name = format!("santa-{}-{}", profile.layer, profile.stage);
        let mobileconfig_path = output_dir.join(format!("{}.mobileconfig", profile_name));

        let options = GeneratorOptions::new(org)
            .with_identifier(&format!(
                "{}.santa.{}.{}",
                org, profile.layer, profile.stage
            ))
            .with_display_name(&format!(
                "Santa Rules - {} ({})",
                profile.layer, profile.stage
            ))
            .with_deterministic_uuids(deterministic);

        write_to_file_format(
            &profile.rules,
            &options,
            &mobileconfig_path,
            Format::Mobileconfig,
        )?;

        written_files.push(mobileconfig_path.clone());

        if verbose {
            print_kv(
                &format!("  {}-{}", profile.layer, profile.stage),
                &format!(
                    "{} rules -> {}",
                    profile.rules.len(),
                    mobileconfig_path.display()
                ),
            );
        }
    }

    // Write a Fleet manifest with labels
    let manifest_path = output_dir.join("fleet-manifest.yaml");
    let manifest = generate_fleet_manifest(&result, org);
    std::fs::write(&manifest_path, manifest)?;
    written_files.push(manifest_path);

    // Write combined rules YAML
    let rules_yaml_path = output_dir.join("rules.yaml");
    let rules_yaml = yaml_serde::to_string(result.base_result.rules.rules())?;
    std::fs::write(&rules_yaml_path, rules_yaml)?;
    written_files.push(rules_yaml_path);

    // Write coverage report
    let report_path = output_dir.join("coverage-report.yaml");
    let report = result.base_result.coverage_report();
    let report_yaml = yaml_serde::to_string(&report)?;
    std::fs::write(&report_path, report_yaml)?;
    written_files.push(report_path);

    // Write/update lock file
    let lock_path = output_dir.join("santa.lock");
    let mut lock = if lock_path.exists() {
        PipelineLock::from_yaml_file(&lock_path).unwrap_or_default()
    } else {
        PipelineLock::new()
    };

    let previous_lock = lock.clone();

    for rule in result.base_result.rules.rules() {
        let key = rule.key();
        if !lock.has_rule(&key) {
            let entry = LockEntry::new(
                rule.rule_type.as_str(),
                &rule.identifier,
                rule.policy.as_str(),
                rule.group.as_deref().unwrap_or("unknown"),
            )
            .with_description(rule.description.clone().unwrap_or_default());
            lock.add_rule(key, entry);
        }
    }

    lock.to_yaml_file(&lock_path)?;
    written_files.push(lock_path.clone());

    // Show diff
    let diff = lock.diff(&previous_lock);
    if diff.has_changes() {
        println!();
        println!("{}", "Changes from previous run".bold());
        println!("{}", "-".repeat(40));
        if !diff.added.is_empty() {
            println!("  Added: {} rules", diff.added.len().to_string().green());
        }
        if !diff.removed.is_empty() {
            println!("  Removed: {} rules", diff.removed.len().to_string().red());
        }
        if !diff.changed.is_empty() {
            println!(
                "  Changed: {} rules",
                diff.changed.len().to_string().yellow()
            );
        }
    }

    // Final output
    println!();
    print_success(&format!(
        "Layer × Stage pipeline complete! {} files written to {}",
        written_files.len(),
        output_dir.display()
    ));

    for file in &written_files {
        println!("  - {}", file.display());
    }

    Ok(())
}

/// Generate Fleet GitOps manifest with labels for each Layer × Stage profile.
fn generate_fleet_manifest(result: &crate::pipeline::LayerStageResult, org: &str) -> String {
    let mut manifest = String::new();
    manifest.push_str("# Fleet GitOps manifest for Layer × Stage profiles\n");
    manifest.push_str("# Deploy profiles using Fleet labels for targeting\n");
    manifest.push_str("#\n");
    manifest.push_str("# Layers (audience): ");
    for layer in &result.layer_config.layers {
        manifest.push_str(&format!("{}, ", layer.name));
    }
    manifest.push_str("\n# Stages (rollout): ");
    for stage in &result.stage_config.stages {
        manifest.push_str(&format!("{}, ", stage.name));
    }
    manifest.push_str("\n\n");

    manifest.push_str("profiles:\n");

    for profile in &result.profiles {
        if profile.rules.is_empty() {
            continue;
        }

        manifest.push_str(&format!(
            "  - name: santa-{}-{}\n",
            profile.layer, profile.stage
        ));
        manifest.push_str(&format!(
            "    identifier: {}.santa.{}.{}\n",
            org, profile.layer, profile.stage
        ));
        manifest.push_str(&format!(
            "    file: santa-{}-{}.mobileconfig\n",
            profile.layer, profile.stage
        ));
        manifest.push_str(&format!("    rules: {}\n", profile.rules.len()));
        manifest.push_str("    labels:\n");
        manifest.push_str(&format!("      - santa-layer:{}\n", profile.layer));
        manifest.push_str(&format!("      - santa-stage:{}\n", profile.stage));
        manifest.push('\n');
    }

    manifest
}

/// Display pipeline summary.
fn display_summary(summary: &crate::pipeline::PipelineSummary, _verbose: bool) {
    println!();
    println!("{}", "Pipeline Summary".bold());
    println!("{}", "=".repeat(50));
    println!();

    println!("{:<25} {}", "Input apps:", summary.original_apps);
    println!("{:<25} {}", "After dedup:", summary.deduplicated_apps);
    println!(
        "{:<25} {}",
        "Rules generated:",
        summary.rules_generated.to_string().green()
    );
    println!("{:<25} {}", "Bundles used:", summary.bundles_used);

    if summary.orphans > 0 {
        println!(
            "{:<25} {}",
            "Orphans:",
            summary.orphans.to_string().yellow()
        );
    }
    if summary.conflicts > 0 {
        println!(
            "{:<25} {}",
            "Conflicts:",
            summary.conflicts.to_string().yellow()
        );
    }

    let coverage_str = format!("{:.1}%", summary.coverage);
    let coverage_colored = if summary.coverage >= 90.0 {
        coverage_str.green()
    } else if summary.coverage >= 70.0 {
        coverage_str.yellow()
    } else {
        coverage_str.red()
    };
    println!("{:<25} {}", "Coverage:", coverage_colored);

    // Rule type breakdown
    if !summary.by_type.is_empty() {
        println!();
        println!("{}", "By Rule Type:".bold());
        print_bar_chart(&to_bar_items(&summary.by_type));
    }

    // Bundle breakdown
    if !summary.by_bundle.is_empty() {
        println!();
        println!("{}", "By Bundle:".bold());
        print_bar_chart(&to_bar_items(&summary.by_bundle));
    }
}

/// Display Layer × Stage matrix summary.
fn display_layer_stage_summary(summary: &LayerStageSummary, verbose: bool) {
    println!();
    println!("{}", "Layer × Stage Pipeline Summary".bold());
    println!("{}", "=".repeat(50));
    println!();

    // Base stats
    println!(
        "{:<25} {}",
        "Input apps:", summary.base_summary.original_apps
    );
    println!(
        "{:<25} {}",
        "After dedup:", summary.base_summary.deduplicated_apps
    );
    println!(
        "{:<25} {}",
        "Base rules:",
        summary.base_summary.rules_generated.to_string().green()
    );
    println!();

    // Matrix dimensions
    println!("{:<25} {:?}", "Layers:", summary.layers);
    println!("{:<25} {:?}", "Stages:", summary.stages);
    println!("{:<25} {}", "Profiles:", summary.profiles.len());
    println!();

    // Matrix table
    if verbose {
        println!("{}", "Profile Matrix (rules per Layer × Stage):".bold());
        println!();

        // Header row
        print!("{:<15}", "");
        for stage in &summary.stages {
            print!("{:<12}", stage);
        }
        println!();
        println!("{}", "-".repeat(15 + summary.stages.len() * 12));

        // Data rows
        for layer in &summary.layers {
            print!("{:<15}", layer);
            for stage in &summary.stages {
                let count = summary
                    .profiles
                    .iter()
                    .find(|p| p.layer == *layer && p.stage == *stage)
                    .map(|p| p.rules)
                    .unwrap_or(0);
                let count_str = if count > 0 {
                    count.to_string().green().to_string()
                } else {
                    "-".dimmed().to_string()
                };
                print!("{:<12}", count_str);
            }
            println!();
        }
        println!();
    }

    // Coverage
    let coverage_str = format!("{:.1}%", summary.base_summary.coverage);
    let coverage_colored = if summary.base_summary.coverage >= 90.0 {
        coverage_str.green()
    } else if summary.base_summary.coverage >= 70.0 {
        coverage_str.yellow()
    } else {
        coverage_str.red()
    };
    println!("{:<25} {}", "Coverage:", coverage_colored);

    if summary.base_summary.orphans > 0 {
        println!(
            "{:<25} {}",
            "Orphans:",
            summary.base_summary.orphans.to_string().yellow()
        );
    }
    if summary.base_summary.conflicts > 0 {
        println!(
            "{:<25} {}",
            "Conflicts:",
            summary.base_summary.conflicts.to_string().yellow()
        );
    }

    // Rule type breakdown
    if !summary.base_summary.by_type.is_empty() {
        println!();
        println!("{}", "By Rule Type:".bold());
        print_bar_chart(&to_bar_items(&summary.base_summary.by_type));
    }

    // Bundle breakdown
    if !summary.base_summary.by_bundle.is_empty() {
        println!();
        println!("{}", "By Bundle:".bold());
        print_bar_chart(&to_bar_items(&summary.base_summary.by_bundle));
    }
}

/// Convert a HashMap to sorted (label, count) pairs for bar chart display.
fn to_bar_items(map: &HashMap<String, usize>) -> Vec<(&str, usize)> {
    let mut items: Vec<_> = map.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1));
    items
}
