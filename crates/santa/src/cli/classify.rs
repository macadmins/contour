//! Classify command implementation.
//!
//! Applies bundles to classify apps and report coverage.

use crate::bundle::{BundleSet, ConflictPolicy, OrphanPolicy};
use crate::coverage::{CoverageAnalyzer, CoverageReport};
use crate::discovery::parse_fleet_csv_file;
use crate::output::{print_error, print_info, print_kv, print_success, print_warning};
use anyhow::Result;
use colored::Colorize;
use std::path::Path;

/// Run the classify command.
pub fn run(
    input: &Path,
    bundles_path: &Path,
    output: Option<&Path>,
    orphan_policy: OrphanPolicy,
    conflict_policy: ConflictPolicy,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    // Load bundles
    print_info(&format!("Loading bundles: {}", bundles_path.display()));
    let bundles = BundleSet::from_toml_file(bundles_path)?;
    print_kv("Bundles loaded", &bundles.len().to_string());

    if bundles.is_empty() {
        print_warning(
            "No bundles defined. Run 'contour santa discover' first to generate bundle suggestions.",
        );
        return Ok(());
    }

    // Parse CSV
    print_info(&format!("Parsing CSV: {}", input.display()));
    let apps = parse_fleet_csv_file(input)?;
    print_kv("Apps loaded", &apps.len().to_string());

    // Run classification
    print_info("Classifying apps...");
    let analyzer = CoverageAnalyzer::new(orphan_policy, conflict_policy);

    let analysis = match analyzer.analyze(&bundles, apps.apps()) {
        Ok(a) => a,
        Err(e) => {
            print_error(&format!("Classification failed: {}", e));
            return Err(e);
        }
    };

    // Generate report
    let report = analysis.to_report();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Display results
    display_report(&report, verbose);

    // Show warnings
    if analysis.has_orphans() && orphan_policy == OrphanPolicy::Warn {
        println!();
        print_warning(&format!(
            "{} apps did not match any bundle (orphans)",
            analysis.orphans.len()
        ));
        if verbose {
            println!("  Sample orphans:");
            for app in analysis.orphans.iter().take(5) {
                println!("    - {}", app.display_name());
            }
        }
    }

    if analysis.has_conflicts() {
        println!();
        print_warning(&format!(
            "{} apps matched multiple bundles (conflicts resolved by {})",
            analysis.conflicts.len(),
            conflict_policy.as_str()
        ));
    }

    // Write output
    if let Some(output_path) = output {
        write_classification_yaml(&analysis, output_path)?;
        print_success(&format!(
            "Classification written to: {}",
            output_path.display()
        ));
    }

    // Final summary
    println!();
    if report.coverage_percentage >= 90.0 {
        print_success(&format!(
            "Coverage: {:.1}% - Excellent!",
            report.coverage_percentage
        ));
    } else if report.coverage_percentage >= 70.0 {
        print_info(&format!(
            "Coverage: {:.1}% - Good",
            report.coverage_percentage
        ));
    } else {
        print_warning(&format!(
            "Coverage: {:.1}% - Consider adding more bundles",
            report.coverage_percentage
        ));
    }

    Ok(())
}

/// Display the coverage report.
fn display_report(report: &CoverageReport, verbose: bool) {
    println!();
    println!("{}", "Classification Results".bold());
    println!("{}", "=".repeat(50));
    println!();

    println!("{:<25} {}", "Total apps:", report.total_apps);
    println!(
        "{:<25} {}",
        "Classified:",
        report.classified_apps.to_string().green()
    );
    println!(
        "{:<25} {}",
        "Orphans:",
        if report.orphan_count > 0 {
            report.orphan_count.to_string().yellow()
        } else {
            report.orphan_count.to_string().green()
        }
    );
    println!(
        "{:<25} {}",
        "Conflicts:",
        if report.conflict_count > 0 {
            report.conflict_count.to_string().yellow()
        } else {
            report.conflict_count.to_string().green()
        }
    );
    println!("{:<25} {:.1}%", "Coverage:", report.coverage_percentage);

    if !report.bundle_stats.is_empty() {
        println!();
        println!("{}", "Bundle Statistics".bold());
        println!("{}", "-".repeat(40));

        let mut sorted = report.bundle_stats.clone();
        sorted.sort_by(|a, b| b.app_count.cmp(&a.app_count));

        for stat in &sorted {
            let bar_len = ((stat.percentage / 100.0) * 30.0) as usize;
            let bar = "█".repeat(bar_len);
            let empty = "░".repeat(30 - bar_len);

            println!(
                "  {:<20} {:>4} apps  {}{} ({:.1}%)",
                stat.name.cyan(),
                stat.app_count,
                bar.green(),
                empty.dimmed(),
                stat.percentage
            );
        }
    }

    if verbose {
        // Show orphan suggestions
        if let Some(orphan_report) = &report.orphan_report {
            let suggestions = orphan_report.suggest_bundles();
            if !suggestions.is_empty() {
                println!();
                println!("{}", "Suggested New Bundles (from orphans)".bold());
                println!("{}", "-".repeat(40));

                for suggestion in suggestions.iter().take(5) {
                    println!(
                        "  {} - {} apps (TeamID: {})",
                        suggestion.name.cyan(),
                        suggestion.app_count,
                        suggestion.team_id
                    );
                    println!("    Sample: {}", suggestion.sample_apps.join(", ").dimmed());
                }
            }
        }
    }
}

/// Write classification results to YAML.
fn write_classification_yaml(
    analysis: &crate::coverage::CoverageAnalysis,
    path: &Path,
) -> Result<()> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct ClassificationOutput {
        total_apps: usize,
        classified_apps: usize,
        orphans: usize,
        conflicts: usize,
        coverage_percentage: f64,
        apps: Vec<AppClassification>,
    }

    #[derive(Serialize)]
    struct AppClassification {
        app_name: String,
        bundle: Option<String>,
        is_orphan: bool,
        has_conflict: bool,
    }

    let apps: Vec<AppClassification> = analysis
        .results
        .iter()
        .map(|r| AppClassification {
            app_name: r.app.display_name(),
            bundle: r.selected_bundle.clone(),
            is_orphan: r.is_orphan,
            has_conflict: r.has_conflict,
        })
        .collect();

    let output = ClassificationOutput {
        total_apps: analysis.total_apps,
        classified_apps: analysis.summary.classified_apps,
        orphans: analysis.orphans.len(),
        conflicts: analysis.conflicts.len(),
        coverage_percentage: analysis.coverage_percentage(),
        apps,
    };

    let yaml = yaml_serde::to_string(&output)?;
    std::fs::write(path, yaml)?;
    Ok(())
}
