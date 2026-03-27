use crate::deduplicator::{MultiBaselineLabelGenerator, ProfileDeduplicator, SharedProfileLibrary};
use crate::models::Platform;
use crate::output::{DeduplicationResult, OutputMode};
use crate::transformers::JamfScopingGenerator;
use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Deduplicate profiles across baselines
pub fn deduplicate_profiles(
    output_path: PathBuf,
    baseline_names: Option<Vec<String>>,
    platform_str: String,
    jamf_mode: bool,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    tracing::info!("Starting profile deduplication");
    tracing::info!("Output directory: {}", output_path.display());

    let mut result = DeduplicationResult {
        success: true,
        command: "deduplicate".to_string(),
        dry_run,
        profiles_analyzed: 0,
        duplicate_groups: 0,
        profiles_deduplicated: 0,
        space_saved_bytes: 0,
        warnings: Vec::new(),
        errors: Vec::new(),
    };

    // Parse platform
    let platform = parse_platform(&platform_str)?;

    // Auto-detect baselines if not specified
    let baselines = if let Some(names) = baseline_names {
        names
    } else {
        auto_detect_baselines(&output_path)?
    };

    if baselines.is_empty() {
        if output_mode == OutputMode::Human {
            println!("{}", "No baselines found to deduplicate".yellow());
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human {
        println!("{} {}", "Scanning baselines:".cyan(), baselines.join(", "));
    }

    // Scan for duplicates
    let deduplicator = ProfileDeduplicator::new(&output_path);
    let report = deduplicator.scan_baselines(&baselines)?;

    // Collect statistics
    result.profiles_analyzed = report.total_profiles;
    result.duplicate_groups = report.groups.len();
    result.space_saved_bytes = report.bytes_saved as usize;

    // Print report
    if output_mode == OutputMode::Human {
        report.print_summary();
    }

    if dry_run {
        if output_mode == OutputMode::Human {
            println!("\n{}", "✓ Dry run complete - no changes made".green());
        }
        // Output results
        match output_mode {
            OutputMode::Json => {
                crate::output::json::output_deduplication_result(&result)?;
            }
            OutputMode::Human => {
                // Already printed above
            }
        }
        return Ok(());
    }

    // Check if there are duplicates to process
    let shared_profiles = report.get_shared_profiles();
    if shared_profiles.is_empty() {
        if output_mode == OutputMode::Human {
            println!(
                "\n{}",
                "✓ No duplicate profiles found - nothing to deduplicate".green()
            );
        }
        match output_mode {
            OutputMode::Json => {
                crate::output::json::output_deduplication_result(&result)?;
            }
            OutputMode::Human => {
                // Already printed above
            }
        }
        return Ok(());
    }

    result.profiles_deduplicated = shared_profiles.len();

    // Perform deduplication
    if output_mode == OutputMode::Human {
        println!("\n{}", "Deduplicating profiles...".cyan());
    }
    let library = SharedProfileLibrary::new(&output_path);
    let mapping = library.deduplicate_profiles(&report)?;

    // Generate multi-baseline labels
    if output_mode == OutputMode::Human {
        println!("{}", "Generating shared profile labels...".cyan());
    }
    let label_generator = MultiBaselineLabelGenerator::new(&output_path);
    let labels = label_generator.generate_shared_labels(&mapping, platform)?;

    if !labels.is_empty() {
        let labels_file = label_generator.write_shared_labels(&labels)?;
        label_generator.add_to_default_yml()?;
        if output_mode == OutputMode::Human {
            println!(
                "{} {} shared labels at: {}",
                "✓ Generated".green(),
                labels.len(),
                labels_file.display().to_string().dimmed()
            );
        }
    }

    // Generate Jamf Smart Group scoping if enabled
    if jamf_mode {
        if output_mode == OutputMode::Human {
            println!(
                "{}",
                "Generating Jamf Smart Group scoping templates...".cyan()
            );
        }

        // Build shared profiles map
        let mut shared_profiles = HashMap::new();
        for canonical in mapping.shared_profiles.keys() {
            // Find which baselines use this profile
            let mut baseline_list = Vec::new();
            for profiles in mapping.baseline_mappings.values() {
                for profile_mapping in profiles.values() {
                    if profile_mapping.shared_path.ends_with(canonical) {
                        baseline_list.extend(profile_mapping.baselines.clone());
                        break;
                    }
                }
            }
            baseline_list.sort();
            baseline_list.dedup();
            shared_profiles.insert(canonical.clone(), baseline_list);
        }

        // Generate manifests for each baseline
        let jamf_generator = JamfScopingGenerator::new(&output_path);
        for baseline in &baselines {
            // Get profile list for this baseline
            let profile_list: Vec<String> = mapping
                .baseline_mappings
                .get(baseline)
                .map(|profiles| profiles.keys().cloned().collect())
                .unwrap_or_default();

            let manifest =
                jamf_generator.generate_manifest(baseline, &profile_list, &shared_profiles)?;

            jamf_generator.write_manifest(&manifest)?;
        }

        if output_mode == OutputMode::Human {
            println!(
                "{} Jamf scoping templates for {} baselines",
                "✓ Generated".green(),
                baselines.len()
            );
        }
    }

    // Update baseline.yml files to use shared paths
    if output_mode == OutputMode::Human {
        println!("{}", "Updating baseline.yml files...".cyan());
    }
    update_baseline_yamls(&output_path, &baselines, &mapping)?;

    // Clean up duplicate files
    if output_mode == OutputMode::Human {
        println!("{}", "Cleaning up duplicate profiles...".cyan());
    }
    library.cleanup_baseline_profiles(&mapping)?;

    // Update final statistics
    result.profiles_deduplicated = mapping.shared_profiles.len();

    // Output results
    match output_mode {
        OutputMode::Json => {
            crate::output::json::output_deduplication_result(&result)?;
        }
        OutputMode::Human => {
            // Print final summary
            mapping.print_summary();

            println!("\n{}", "✓ Deduplication complete!".green().bold());
            println!(
                "  {} {}",
                "Shared profiles:".cyan(),
                mapping.shared_profiles.len()
            );
            println!(
                "  {} {:.2} MB",
                "Storage saved:".cyan(),
                report.bytes_saved as f64 / 1024.0 / 1024.0
            );
        }
    }

    Ok(())
}

/// Parse platform string to Platform enum
fn parse_platform(platform_str: &str) -> Result<Platform> {
    match platform_str.to_lowercase().as_str() {
        "macos" => Ok(Platform::MacOS),
        "ios" | "ipados" => Ok(Platform::Ios),
        "visionos" => Ok(Platform::VisionOS),
        _ => {
            anyhow::bail!("Invalid platform: {platform_str}. Must be one of: macOS, iOS, visionOS")
        }
    }
}

/// Auto-detect baselines in the output directory
fn auto_detect_baselines(output_path: &PathBuf) -> Result<Vec<String>> {
    let mscp_dir = output_path.join("lib/mscp");

    if !mscp_dir.exists() {
        return Ok(Vec::new());
    }

    let mut baselines = Vec::new();

    for entry in std::fs::read_dir(&mscp_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Skip the shared profiles directory
            if path.file_name().and_then(|s| s.to_str()) == Some("profiles") {
                continue;
            }

            // Check if it has a profiles subdirectory
            let profiles_dir = path.join("profiles");
            if profiles_dir.exists()
                && profiles_dir.is_dir()
                && let Some(name) = path.file_name().and_then(|s| s.to_str())
            {
                baselines.push(name.to_string());
            }
        }
    }

    baselines.sort();
    Ok(baselines)
}

/// Update baseline.yml files to use shared profile paths
fn update_baseline_yamls(
    output_path: &PathBuf,
    baselines: &[String],
    mapping: &crate::deduplicator::shared_library::DeduplicationMapping,
) -> Result<()> {
    for baseline in baselines {
        let baseline_file = output_path
            .join("lib/mscp")
            .join(baseline)
            .join("baseline.yml");

        if !baseline_file.exists() {
            tracing::warn!("Baseline YAML not found: {}", baseline_file.display());
            continue;
        }

        // Read baseline.yml
        let content = std::fs::read_to_string(&baseline_file).with_context(|| {
            format!("Failed to read baseline YAML: {}", baseline_file.display())
        })?;

        let mut yaml: yaml_serde::Value = yaml_serde::from_str(&content).with_context(|| {
            format!("Failed to parse baseline YAML: {}", baseline_file.display())
        })?;

        // Update custom_settings paths
        let mut modified = false;

        if let Some(custom_settings) = yaml
            .get_mut("controls")
            .and_then(|c| c.get_mut("macos_settings"))
            .and_then(|m| m.get_mut("custom_settings"))
            .and_then(|s| s.as_sequence_mut())
        {
            for entry in custom_settings {
                // First, read the path (immutable borrow)
                let path_and_filename = entry.get("path").and_then(|p| p.as_str()).map(|path| {
                    let filename = std::path::Path::new(path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string();
                    (path.to_string(), filename)
                });

                if let Some((_path, filename)) = path_and_filename {
                    // Check if this profile has been deduplicated
                    if let Some(shared_path) = mapping.get_shared_path(baseline, &filename) {
                        // Update path to point to shared library (mutable borrow)
                        *entry.get_mut("path").unwrap() =
                            yaml_serde::Value::String(shared_path.to_string());
                        modified = true;

                        // Add multi-baseline labels
                        if let Some(baselines) =
                            mapping.get_baselines_for_profile(baseline, &filename)
                            && baselines.len() > 1
                        {
                            // Add baseline-specific labels
                            let baseline_labels: Vec<yaml_serde::Value> = baselines
                                .iter()
                                .map(|b| yaml_serde::Value::String(format!("mscp-{b}")))
                                .collect();

                            // Create or update labels_include_all
                            entry.as_mapping_mut().unwrap().insert(
                                yaml_serde::Value::String("labels_include_all".to_string()),
                                yaml_serde::Value::Sequence(baseline_labels),
                            );
                        }
                    }
                }
            }
        }

        if modified {
            // Write back
            let updated = yaml_serde::to_string(&yaml)?;
            std::fs::write(&baseline_file, updated).with_context(|| {
                format!("Failed to write baseline YAML: {}", baseline_file.display())
            })?;

            tracing::info!("✓ Updated {}/baseline.yml", baseline);
        }
    }

    Ok(())
}
