use crate::cli::glob_utils::{
    BatchResult, collect_profile_files_multi_with_depth, compute_batch_output_path,
    output_batch_json, print_batch_summary, print_dry_run_preview, should_batch_process_multi,
};
use crate::config::{ProfileConfig, renaming::ProfileRenamer};
use crate::output::OutputMode;
use crate::profile::parser;
use crate::uuid::{self, UuidConfig};
use anyhow::Result;
use colored::Colorize;
use rayon::prelude::*;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn handle_uuid(
    paths: &[String],
    output: Option<&str>,
    org_domain: Option<&str>,
    predictable: bool,
    config: Option<&ProfileConfig>,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    // Fall back to .contour/config.toml when no --org and no profile.toml org
    let contour_domain;
    let effective_org = if org_domain.is_some() || config.is_some() {
        org_domain
    } else if let Some(cfg) = contour_core::config::ContourConfig::load_nearest() {
        contour_domain = cfg.organization.domain;
        Some(contour_domain.as_str())
    } else {
        None
    };

    if should_batch_process_multi(paths) {
        handle_uuid_batch(
            paths,
            output,
            effective_org,
            predictable,
            config,
            recursive,
            max_depth,
            parallel,
            dry_run,
            output_mode,
        )
    } else {
        let path = &paths[0];
        if dry_run {
            if output_mode == OutputMode::Human {
                println!("{}", "Dry run mode - no files will be written\n".yellow());
                println!("Would process UUIDs: {path}");
            } else {
                let result = serde_json::json!({
                    "dry_run": true,
                    "would_process": [path],
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            return Ok(());
        }
        handle_uuid_single(
            path,
            output,
            effective_org,
            predictable,
            config,
            output_mode,
        )
    }
}

fn handle_uuid_batch(
    paths: &[String],
    output_dir: Option<&str>,
    org_domain: Option<&str>,
    predictable: bool,
    config: Option<&ProfileConfig>,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let files = collect_profile_files_multi_with_depth(paths, recursive, max_depth)?;

    if files.is_empty() {
        if output_mode == OutputMode::Human {
            println!("{}", "No .mobileconfig files found".yellow());
        } else {
            let result = serde_json::json!({
                "success": true,
                "total": 0,
                "message": "No .mobileconfig files found"
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human && !dry_run {
        println!(
            "{}",
            format!("Processing UUIDs for {} profile(s)...", files.len()).cyan()
        );
    }

    if dry_run {
        print_dry_run_preview(&files, output_dir, "-uuid", output_mode);
        return Ok(());
    }

    // Create output directory if specified
    if let Some(dir) = output_dir {
        fs::create_dir_all(dir)?;
    }

    let config_clone = config.cloned();
    let org_domain_owned = org_domain.map(String::from);

    let uuid_file = |input: &Path, output_path: &Path| -> Result<()> {
        uuid_single_file_internal(
            input,
            output_path,
            org_domain_owned.as_deref(),
            predictable,
            config_clone.as_ref(),
        )
    };

    let result = if parallel {
        process_parallel_with_output(&files, output_dir, "-uuid", uuid_file, output_mode)
    } else {
        process_sequential_with_output(&files, output_dir, "-uuid", uuid_file, output_mode)
    };

    // Output summary
    if output_mode == OutputMode::Human {
        print_batch_summary(&result, "UUID Processing");
    } else {
        output_batch_json(&result, "uuid")?;
    }

    if result.failed > 0 {
        anyhow::bail!("{} file(s) failed UUID processing", result.failed);
    }

    Ok(())
}

fn uuid_single_file_internal(
    input: &Path,
    output: &Path,
    org_domain: Option<&str>,
    predictable: bool,
    config: Option<&ProfileConfig>,
) -> Result<()> {
    let file = input.to_str().unwrap_or_default();
    let mut profile = parser::parse_profile_auto_unsign(file)?;

    // Get settings from config or CLI (config takes precedence for domain)
    let effective_org_domain = if let Some(cfg) = config {
        Some(cfg.organization.domain.as_str())
    } else {
        org_domain
    };

    // Config precedence for predictable setting
    let effective_predictable = if let Some(cfg) = config {
        cfg.uuid.predictable
    } else {
        predictable
    };

    let uuid_config = UuidConfig {
        org_domain: effective_org_domain.map(String::from),
        predictable: effective_predictable,
    };

    profile.payload_uuid = uuid::regenerate_uuid(
        &profile.payload_uuid,
        &uuid_config,
        &profile.payload_identifier,
    )?;

    for content in &mut profile.payload_content {
        content.payload_uuid = uuid::regenerate_uuid(
            &content.payload_uuid,
            &uuid_config,
            &content.payload_identifier,
        )?;
    }

    parser::write_profile(&profile, output)?;

    Ok(())
}

fn handle_uuid_single(
    file: &str,
    output: Option<&str>,
    org_domain: Option<&str>,
    predictable: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        println!("{}", "Processing UUIDs in configuration profile...".cyan());
    }

    let mut profile = parser::parse_profile_auto_unsign(file)?;

    if output_mode == OutputMode::Human {
        println!("{}", "✓ Profile parsed successfully".green());
    }

    // Get settings from config or CLI (config takes precedence for domain)
    let effective_org_domain = if let Some(cfg) = config {
        Some(cfg.organization.domain.as_str())
    } else {
        org_domain
    };

    // Config precedence for predictable setting
    let effective_predictable = if let Some(cfg) = config {
        cfg.uuid.predictable
    } else {
        predictable
    };

    let uuid_config = UuidConfig {
        org_domain: effective_org_domain.map(String::from),
        predictable: effective_predictable,
    };

    if output_mode == OutputMode::Human {
        println!();
        if predictable {
            println!(
                "{}",
                "Generating predictable UUIDs based on identifiers...".yellow()
            );
        } else {
            println!("{}", "Validating and preserving existing UUIDs...".yellow());
        }

        println!();
        println!("Main Profile UUID:");
        println!("  Before: {}", profile.payload_uuid);
    }

    profile.payload_uuid = uuid::regenerate_uuid(
        &profile.payload_uuid,
        &uuid_config,
        &profile.payload_identifier,
    )?;

    if output_mode == OutputMode::Human {
        println!("  After:  {}", profile.payload_uuid.green());
    }

    for (index, content) in profile.payload_content.iter_mut().enumerate() {
        if output_mode == OutputMode::Human {
            println!();
            println!("Payload Content [{index}]:");
            println!("  Before: {}", content.payload_uuid);
        }

        content.payload_uuid = uuid::regenerate_uuid(
            &content.payload_uuid,
            &uuid_config,
            &content.payload_identifier,
        )?;

        if output_mode == OutputMode::Human {
            println!("  After:  {}", content.payload_uuid.green());
        }
    }

    // Determine output path using config renaming or CLI output.
    // When no output is specified and no config renamer, update in place
    // after creating a .bak backup of the original file.
    let output_path = if let Some(output_file) = output {
        output_file.to_string()
    } else if let Some(cfg) = config {
        let renamer = ProfileRenamer::new(cfg);
        let path = renamer.generate_output_path(&profile, Some(Path::new(file)));
        path.to_string_lossy().to_string()
    } else {
        // In-place mode: back up original, then overwrite
        let bak_path = format!("{file}.bak");
        fs::copy(file, &bak_path)
            .map_err(|e| anyhow::anyhow!("Failed to create backup '{}': {}", bak_path, e))?;
        if output_mode == OutputMode::Human {
            println!();
            println!("{}", format!("  Backup: {bak_path}").dimmed());
        }
        file.to_string()
    };

    parser::write_profile(&profile, Path::new(&output_path))?;

    if output_mode == OutputMode::Human {
        println!();
        println!(
            "{}",
            format!("✓ UUIDs processed successfully: {output_path}").green()
        );
    }

    Ok(())
}

// Helper functions for processing with output paths
fn process_parallel_with_output<F>(
    files: &[std::path::PathBuf],
    output_dir: Option<&str>,
    suffix: &str,
    processor: F,
    output_mode: OutputMode,
) -> BatchResult
where
    F: Fn(&Path, &Path) -> Result<()> + Sync,
{
    let success_count = AtomicUsize::new(0);
    let failed_count = AtomicUsize::new(0);

    let results: Vec<(std::path::PathBuf, std::path::PathBuf, Result<()>)> = files
        .par_iter()
        .map(|file| {
            let output_path = compute_batch_output_path(file, output_dir, suffix);
            let result = processor(file, &output_path);
            match &result {
                Ok(()) => {
                    success_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    failed_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            (file.clone(), output_path, result)
        })
        .collect();

    let mut failures = Vec::new();
    for (file, output_path, result) in &results {
        match result {
            Ok(()) => {
                if output_mode == OutputMode::Human {
                    println!(
                        "{} {} -> {}",
                        "✓".green(),
                        file.display(),
                        output_path.display()
                    );
                }
            }
            Err(e) => {
                let err_msg = format!("{e:#}");
                failures.push((file.clone(), err_msg.clone()));
                if output_mode == OutputMode::Human {
                    println!("{} {}: {}", "✗".red(), file.display(), err_msg);
                }
            }
        }
    }

    BatchResult {
        total: files.len(),
        success: success_count.load(Ordering::Relaxed),
        failed: failed_count.load(Ordering::Relaxed),
        skipped: 0,
        with_warnings: 0,
        failures,
        warnings: Vec::new(),
    }
}

fn process_sequential_with_output<F>(
    files: &[std::path::PathBuf],
    output_dir: Option<&str>,
    suffix: &str,
    processor: F,
    output_mode: OutputMode,
) -> BatchResult
where
    F: Fn(&Path, &Path) -> Result<()>,
{
    let mut result = BatchResult {
        total: files.len(),
        success: 0,
        failed: 0,
        skipped: 0,
        with_warnings: 0,
        failures: Vec::new(),
        warnings: Vec::new(),
    };

    for (idx, file) in files.iter().enumerate() {
        let output_path = compute_batch_output_path(file, output_dir, suffix);

        if output_mode == OutputMode::Human {
            println!(
                "{}",
                format!(
                    "[{}/{}] Processing UUIDs: {}",
                    idx + 1,
                    files.len(),
                    file.display()
                )
                .cyan()
            );
        }

        match processor(file, &output_path) {
            Ok(()) => {
                result.success += 1;
                if output_mode == OutputMode::Human {
                    println!("{} -> {}", "✓".green(), output_path.display());
                }
            }
            Err(e) => {
                let err_msg = format!("{e:#}");
                result.failures.push((file.clone(), err_msg.clone()));
                result.failed += 1;
                if output_mode == OutputMode::Human {
                    println!("{}", format!("✗ Failed: {err_msg}").red());
                }
            }
        }
    }

    result
}
