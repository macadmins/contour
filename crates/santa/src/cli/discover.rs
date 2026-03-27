//! Discovery command implementation.
//!
//! Analyzes Fleet CSV data to discover patterns and suggest bundle definitions.

use crate::bundle::{BundleSet, DiscoveryConfig};
use crate::discovery::{DiscoveryEngine, DiscoveryResult, parse_fleet_csv_file};
use crate::output::{print_info, print_kv, print_success};
use anyhow::Result;
use colored::Colorize;
use inquire::{Confirm, MultiSelect, Text};
use std::path::Path;

/// Run the discover command.
pub fn run(
    input: &Path,
    output: Option<&Path>,
    threshold: f64,
    min_apps: usize,
    interactive: bool,
    json_output: bool,
) -> Result<()> {
    // Parse CSV
    print_info(&format!("Parsing CSV: {}", input.display()));
    let apps = parse_fleet_csv_file(input)?;
    print_kv("Apps loaded", &apps.len().to_string());

    // Configure discovery
    let config = DiscoveryConfig {
        threshold,
        min_apps,
        include_unsigned: false,
    };

    // Run discovery
    let mut engine = DiscoveryEngine::new(config);
    let result = engine.discover(&apps);

    print_kv("Patterns discovered", &result.len().to_string());
    print_kv("Total devices", &result.total_devices.to_string());

    if result.is_empty() {
        print_info("No patterns discovered. Try lowering --threshold or --min-apps.");
        return Ok(());
    }

    // Display or process results
    if json_output {
        let bundles = result.to_bundles();
        println!("{}", serde_json::to_string_pretty(&bundles)?);
        return Ok(());
    }

    // Show discovered patterns
    println!();
    println!("{}", "Discovered Patterns".bold());
    println!("{}", "=".repeat(60));

    for (i, pattern) in result.iter().enumerate() {
        println!(
            "\n{}. {} ({})",
            i + 1,
            pattern.name.cyan().bold(),
            pattern.pattern_type.as_str()
        );
        println!("   CEL:      {}", pattern.cel_expression.dimmed());
        println!(
            "   Devices:  {} ({:.1}%)",
            pattern.device_count,
            pattern.coverage_percentage(result.total_devices)
        );
        println!("   Apps:     {}", pattern.app_count);
        if !pattern.sample_apps.is_empty() {
            println!("   Sample:   {}", pattern.sample_apps.join(", ").dimmed());
        }
        println!("   Confidence: {:.0}%", pattern.confidence * 100.0);
    }

    // Interactive mode
    let bundles = if interactive {
        interactive_review(&result)?
    } else {
        result.to_bundles()
    };

    // Write output
    if let Some(output_path) = output {
        write_bundles(&bundles, output_path)?;
        print_success(&format!("Bundles written to: {}", output_path.display()));
    } else {
        // Print TOML to stdout
        println!("\n{}", "Generated bundles.toml".bold());
        println!("{}", "-".repeat(40));
        println!("{}", bundles.to_toml()?);
    }

    Ok(())
}

/// Interactive bundle review and editing.
fn interactive_review(result: &DiscoveryResult) -> Result<BundleSet> {
    println!();
    println!("{}", "Interactive Review".bold().green());
    println!("Select patterns to include as bundles.\n");

    // Create options for multi-select
    let options: Vec<String> = result
        .iter()
        .map(|p| {
            format!(
                "{} - {} devices, {} apps",
                p.name, p.device_count, p.app_count
            )
        })
        .collect();

    // Default: select all with high confidence
    let defaults: Vec<usize> = result
        .iter()
        .enumerate()
        .filter(|(_, p)| p.confidence >= 0.5)
        .map(|(i, _)| i)
        .collect();

    let selected = MultiSelect::new("Select bundles to include:", options)
        .with_default(&defaults)
        .with_page_size(15)
        .prompt()?;

    // Build bundle set from selections
    let patterns: Vec<_> = result.iter().collect();
    let mut bundles = BundleSet::new();

    for selection in selected {
        // Find the pattern index from the selection string
        let idx = patterns
            .iter()
            .position(|p| selection.starts_with(&p.name))
            .unwrap_or(0);

        let pattern = &patterns[idx];

        // Allow editing the bundle name
        let name = Text::new(&format!("Bundle name for {}:", pattern.name))
            .with_default(&pattern.name)
            .prompt()?;

        let mut bundle = pattern.to_bundle();
        bundle.name = name;

        // Allow editing the CEL expression
        if Confirm::new("Edit CEL expression?")
            .with_default(false)
            .prompt()?
        {
            let cel = Text::new("CEL expression:")
                .with_default(&bundle.cel_expression)
                .prompt()?;
            bundle.cel_expression = cel;
        }

        bundles.add(bundle);
    }

    Ok(bundles)
}

/// Write bundles to a TOML file.
fn write_bundles(bundles: &BundleSet, path: &Path) -> Result<()> {
    let toml_content = bundles.to_toml()?;

    // Add header comment
    let header = r#"# Bundle definitions for Santa rules
# Generated by: contour santa discover
#
# Edit this file to customize bundles before running:
#   contour santa classify --input data.csv --bundles bundles.toml
#
# CEL expression reference:
#   app.team_id     - Apple Team ID (e.g., "EQHXZ8M8AV")
#   app.signing_id  - Signing ID (e.g., "EQHXZ8M8AV:com.google.Chrome")
#   app.app_name    - Application name
#   app.bundle_id   - Bundle identifier
#   app.sha256      - Binary hash
#   app.version     - Version string
#   app.vendor      - Vendor/publisher name
#   app.device_count - Number of devices
#
# Example expressions:
#   has(app.team_id) && app.team_id == "EQHXZ8M8AV"
#   has(app.app_name) && app.app_name.contains("Chrome")
#   app.device_count > 100

"#;

    let content = format!("{}{}", header, toml_content);
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_write_bundles() {
        let bundles = BundleSet::new();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bundles.toml");

        write_bundles(&bundles, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Bundle definitions"));
    }
}
