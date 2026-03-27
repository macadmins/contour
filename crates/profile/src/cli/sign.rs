use crate::cli::glob_utils::{
    BatchResult, collect_profile_files_multi_with_depth, compute_batch_output_path,
    output_batch_json, print_batch_summary, print_dry_run_preview, process_parallel,
    process_sequential, should_batch_process_multi,
};
use crate::output::OutputMode;
use crate::signing::{
    SigningConfig, is_signed, list_signing_identities, sign_profile, verify_signature,
};
use anyhow::Result;
use colored::Colorize;
use std::fs;
use std::path::Path;

/// Sign a profile (with batch support)
pub fn handle_sign(
    paths: &[String],
    output: Option<&str>,
    identity: Option<&str>,
    keychain: Option<&str>,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if should_batch_process_multi(paths) {
        handle_sign_batch(
            paths,
            output,
            identity,
            keychain,
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
                println!("Would sign: {path}");
            } else {
                let result = serde_json::json!({
                    "dry_run": true,
                    "would_process": [path],
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            return Ok(());
        }
        handle_sign_single(path, output, identity, keychain, output_mode)
    }
}

fn handle_sign_batch(
    paths: &[String],
    output_dir: Option<&str>,
    identity: Option<&str>,
    keychain: Option<&str>,
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
            format!("Signing {} profile(s)...", files.len()).cyan()
        );
    }

    if dry_run {
        print_dry_run_preview(&files, output_dir, "-signed", output_mode);
        return Ok(());
    }

    // Create output directory if specified
    if let Some(dir) = output_dir {
        fs::create_dir_all(dir)?;
    }

    // Determine signing identity once
    let signer = if let Some(id) = identity {
        id.to_string()
    } else {
        let identities = list_signing_identities()?;
        let dev_id = identities
            .iter()
            .find(|i| i.is_developer_id)
            .or_else(|| identities.first());

        match dev_id {
            Some(id) => {
                if output_mode == OutputMode::Human {
                    println!("{} Auto-detected identity: {}", "ℹ".blue(), id.name.cyan());
                }
                id.name.clone()
            }
            None => anyhow::bail!(
                "No signing identity found. Install a Developer ID certificate or specify --identity"
            ),
        }
    };

    // Build signing config
    let mut config = SigningConfig::new(signer.clone());
    if let Some(kc) = keychain {
        config = config.with_keychain(kc.to_string());
    }

    // Create a closure that signs a single file
    let sign_file = |input: &Path, output: &Path| -> Result<()> {
        let result = sign_profile(input, output, &config)?;
        if !result.success {
            anyhow::bail!("Signing failed");
        }
        Ok(())
    };

    let result = if parallel {
        process_parallel_with_output(&files, output_dir, "-signed", sign_file, output_mode)
    } else {
        process_sequential_with_output(&files, output_dir, "-signed", sign_file, output_mode)
    };

    // Output summary
    if output_mode == OutputMode::Human {
        print_batch_summary(&result, "Signing");
    } else {
        output_batch_json(&result, "sign")?;
    }

    if result.failed > 0 {
        anyhow::bail!("{} file(s) failed to sign", result.failed);
    }

    Ok(())
}

fn handle_sign_single(
    file: &str,
    output: Option<&str>,
    identity: Option<&str>,
    keychain: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let input_path = Path::new(file);

    // Determine signing identity
    let signer = if let Some(id) = identity {
        id.to_string()
    } else {
        // Auto-detect Developer ID certificate
        let identities = list_signing_identities()?;
        let dev_id = identities
            .iter()
            .find(|i| i.is_developer_id)
            .or_else(|| identities.first());

        match dev_id {
            Some(id) => {
                if output_mode == OutputMode::Human {
                    println!("{} Auto-detected identity: {}", "ℹ".blue(), id.name.cyan());
                }
                id.name.clone()
            }
            None => anyhow::bail!(
                "No signing identity found. Install a Developer ID certificate or specify --identity"
            ),
        }
    };

    // Determine output path
    let output_path = if let Some(path) = output {
        Path::new(path).to_path_buf()
    } else {
        let stem = input_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("profile");
        let ext = input_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("mobileconfig");
        input_path.with_file_name(format!("{stem}-signed.{ext}"))
    };

    // Build signing config
    let mut config = SigningConfig::new(signer.clone());
    if let Some(kc) = keychain {
        config = config.with_keychain(kc.to_string());
    }

    // Sign the profile
    let result = sign_profile(input_path, &output_path, &config)?;

    if output_mode == OutputMode::Json {
        let json_result = serde_json::json!({
            "success": result.success,
            "input": file,
            "output": result.output_path.display().to_string(),
            "identity": result.signer_identity,
            "verified": result.verified
        });
        println!("{}", serde_json::to_string_pretty(&json_result)?);
    } else if result.success {
        println!("{} Profile signed successfully", "✓".green());
        println!("  {} {}", "Input:".bold(), file);
        println!("  {} {}", "Output:".bold(), result.output_path.display());
        println!("  {} {}", "Identity:".bold(), result.signer_identity);
        if result.verified {
            println!("  {} {}", "Verified:".bold(), "✓".green());
        }
    } else {
        println!("{} Signing failed", "✗".red());
    }

    Ok(())
}

/// Verify a signed profile (with batch support)
pub fn handle_verify(
    paths: &[String],
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if should_batch_process_multi(paths) {
        handle_verify_batch(paths, recursive, max_depth, parallel, output_mode)
    } else {
        handle_verify_single(&paths[0], output_mode)
    }
}

fn handle_verify_batch(
    paths: &[String],
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
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

    if output_mode == OutputMode::Human {
        println!(
            "{}",
            format!("Verifying {} profile(s)...", files.len()).cyan()
        );
    }

    // Create a closure that verifies a single file
    let verify_file = |file_path: &Path| -> Result<()> {
        let signed = is_signed(file_path)?;
        if !signed {
            anyhow::bail!("Profile is not signed");
        }
        let result = verify_signature(file_path)?;
        if !result.valid {
            anyhow::bail!(
                result
                    .error
                    .unwrap_or_else(|| "Verification failed".to_string())
            );
        }
        Ok(())
    };

    let result = if parallel {
        process_parallel(&files, verify_file, output_mode)
    } else {
        process_sequential(&files, verify_file, output_mode)
    };

    // Output summary
    if output_mode == OutputMode::Human {
        print_batch_summary(&result, "Verification");
    } else {
        output_batch_json(&result, "verify")?;
    }

    if result.failed > 0 {
        anyhow::bail!("{} file(s) failed verification", result.failed);
    }

    Ok(())
}

fn handle_verify_single(file: &str, output_mode: OutputMode) -> Result<()> {
    let path = Path::new(file);

    // Check if signed
    let signed = is_signed(path)?;

    if !signed {
        if output_mode == OutputMode::Json {
            let result = serde_json::json!({
                "file": file,
                "signed": false,
                "valid": null,
                "error": "Profile is not signed"
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!("{} Profile is not signed: {}", "!".yellow(), file);
        }
        return Ok(());
    }

    // Verify signature
    let result = verify_signature(path)?;

    if output_mode == OutputMode::Json {
        let json_result = serde_json::json!({
            "file": file,
            "signed": result.signed,
            "valid": result.valid,
            "signer": result.signer,
            "error": result.error
        });
        println!("{}", serde_json::to_string_pretty(&json_result)?);
    } else if result.valid {
        println!("{} Signature is valid", "✓".green());
        println!("  {} {}", "File:".bold(), file);
        if let Some(signer) = &result.signer {
            println!("  {} {}", "Signer:".bold(), signer);
        }
    } else {
        println!("{} Signature verification failed", "✗".red());
        println!("  {} {}", "File:".bold(), file);
        if let Some(error) = &result.error {
            println!("  {} {}", "Error:".bold(), error);
        }
    }

    Ok(())
}

/// List available signing identities
pub fn handle_list_identities(output_mode: OutputMode) -> Result<()> {
    let identities = list_signing_identities()?;

    if output_mode == OutputMode::Json {
        let json_identities: Vec<_> = identities
            .iter()
            .map(|i| {
                serde_json::json!({
                    "name": i.name,
                    "sha1": i.sha1,
                    "is_developer_id": i.is_developer_id
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_identities)?);
        return Ok(());
    }

    if identities.is_empty() {
        println!(
            "{}",
            "No signing identities found. Install a code signing certificate.".yellow()
        );
        return Ok(());
    }

    println!("{}", "Available signing identities:".bold());
    for identity in &identities {
        let dev_id_badge = if identity.is_developer_id {
            " [Developer ID]".green()
        } else {
            "".normal()
        };
        println!("  {} {}{}", "•".green(), identity.name.cyan(), dev_id_badge);
        println!("    {} {}", "SHA-1:".dimmed(), identity.sha1.dimmed());
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
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
                format!("[{}/{}] Signing: {}", idx + 1, files.len(), file.display()).cyan()
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
