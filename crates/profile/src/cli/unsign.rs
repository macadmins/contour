use crate::cli::glob_utils::{collect_profile_files_multi_with_depth, should_batch_process_multi};
use crate::config::ProfileConfig;
use crate::output::OutputMode;
use anyhow::{Context, Result};
use colored::Colorize;
use glob::glob;
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Result of a batch unsign operation
struct BatchUnsignResult {
    total: usize,
    success: usize,
    failed: usize,
    skipped: usize,
    failures: Vec<(PathBuf, String)>,
}

pub fn handle_unsign(
    paths: &[String],
    output: Option<&str>,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    dry_run: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    if should_batch_process_multi(paths) {
        // Batch mode
        handle_unsign_batch(
            paths,
            output,
            recursive,
            max_depth,
            parallel,
            dry_run,
            config,
            output_mode,
        )
    } else {
        // Single file mode
        let path = &paths[0];
        if dry_run {
            if output_mode == OutputMode::Human {
                println!("{}", "Dry run mode - no files will be written\n".yellow());
                println!("Would unsign: {path}");
            } else {
                let result = serde_json::json!({
                    "dry_run": true,
                    "would_process": [path],
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            return Ok(());
        }
        handle_unsign_single(path, output, config, output_mode)
    }
}

fn handle_unsign_batch(
    paths: &[String],
    output_dir: Option<&str>,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    dry_run: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human && !dry_run {
        println!("{}", "Batch unsigning configuration profiles...".cyan());
    }

    // Collect files to process
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
            format!("Found {} profile(s) to unsign", files.len()).cyan()
        );
    }

    if dry_run {
        if output_mode == OutputMode::Human {
            println!("{}", "\nDry run mode - no files will be written\n".yellow());
            for file in &files {
                let output_path = compute_output_path(file, output_dir, config);
                println!("  {} -> {}", file.display(), output_path.display());
            }
        } else {
            let items: Vec<_> = files
                .iter()
                .map(|f| {
                    let output_path = compute_output_path(f, output_dir, config);
                    serde_json::json!({
                        "input": f.to_string_lossy(),
                        "output": output_path.to_string_lossy(),
                    })
                })
                .collect();
            let result = serde_json::json!({
                "dry_run": true,
                "would_process": items,
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    // Create output directory if specified
    if let Some(dir) = output_dir {
        fs::create_dir_all(dir)?;
    }

    let result = if parallel {
        process_batch_parallel(&files, output_dir, config, output_mode)
    } else {
        process_batch_sequential(&files, output_dir, config, output_mode)
    };

    // Print summary
    if output_mode == OutputMode::Human {
        print_batch_summary(&result);
    } else {
        let json_result = serde_json::json!({
            "success": result.failed == 0,
            "total": result.total,
            "succeeded": result.success,
            "failed": result.failed,
            "skipped": result.skipped,
            "failures": result.failures.iter().map(|(p, e)| {
                serde_json::json!({
                    "file": p.to_string_lossy(),
                    "error": e,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json_result)?);
    }

    if result.failed > 0 {
        anyhow::bail!("{} file(s) failed to unsign", result.failed);
    }

    Ok(())
}

#[allow(dead_code, reason = "reserved for future use")]
fn collect_profile_files(path: &str, recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let is_glob = path.contains('*') || path.contains('?');

    if is_glob {
        // Handle glob pattern - convert user-friendly patterns to proper glob
        // User may specify: folder/*, folder/*.mobileconfig, or folder/**/*
        let pattern = if path.ends_with("/*") {
            // Pattern like "folder/*" - convert to mobileconfig glob
            format!("{}/*.mobileconfig", path.trim_end_matches("/*"))
        } else if path.ends_with('*') && !path.contains("**") {
            // Pattern like "folder*" or "folder/*pattern*"
            // If it doesn't already specify mobileconfig, add filter
            if path.contains(".mobileconfig") {
                path.to_string()
            } else {
                format!("{}*.mobileconfig", path.trim_end_matches('*'))
            }
        } else {
            path.to_string()
        };

        for entry in glob(&pattern).context("Invalid glob pattern")? {
            match entry {
                Ok(p) => {
                    if p.is_file()
                        && p.extension().and_then(|s: &std::ffi::OsStr| s.to_str())
                            == Some("mobileconfig")
                    {
                        files.push(p);
                    }
                }
                Err(e) => eprintln!("{}", format!("Warning: {e}").yellow()),
            }
        }

        // If recursive and pattern contains *, also try subdirectories
        if recursive && !path.contains("**") {
            // Build recursive pattern: folder/* becomes folder/**/*.mobileconfig
            let base_path = if path.ends_with("/*") {
                path.trim_end_matches("/*")
            } else if path.ends_with('*') {
                path.trim_end_matches('*').trim_end_matches('/')
            } else {
                path
            };

            let recursive_pattern = format!("{base_path}/**/*.mobileconfig");
            if let Ok(entries) = glob(&recursive_pattern) {
                for entry in entries {
                    if let Ok(p) = entry
                        && p.is_file()
                        && p.extension().and_then(|s: &std::ffi::OsStr| s.to_str())
                            == Some("mobileconfig")
                        && !files.contains(&p)
                    {
                        files.push(p);
                    }
                }
            }
        }
    } else {
        // Handle directory or single file
        let path_obj = Path::new(path);

        if path_obj.is_file() {
            if path_obj.extension().and_then(|s| s.to_str()) == Some("mobileconfig") {
                files.push(path_obj.to_path_buf());
            } else {
                anyhow::bail!("File must have .mobileconfig extension");
            }
        } else if path_obj.is_dir() {
            collect_from_directory(path_obj, recursive, &mut files)?;
        } else {
            anyhow::bail!("Path does not exist: {path}");
        }
    }

    files.sort();
    Ok(files)
}

#[allow(dead_code, reason = "reserved for future use")]
fn collect_from_directory(dir: &Path, recursive: bool, files: &mut Vec<PathBuf>) -> Result<()> {
    if recursive {
        for entry in walkdir::WalkDir::new(dir)
            .follow_links(true)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            let p = entry.path();
            if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("mobileconfig") {
                files.push(p.to_path_buf());
            }
        }
    } else {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("mobileconfig") {
                files.push(p);
            }
        }
    }
    Ok(())
}

fn compute_output_path(
    input: &Path,
    output_dir: Option<&str>,
    config: Option<&ProfileConfig>,
) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    let suffix = config.map_or("-unsigned", |c| c.output.unsigned_suffix.as_str());
    let filename = format!("{stem}{suffix}.mobileconfig");

    if let Some(dir) = output_dir {
        Path::new(dir).join(&filename)
    } else {
        input.parent().unwrap_or(Path::new(".")).join(&filename)
    }
}

fn process_batch_sequential(
    files: &[PathBuf],
    output_dir: Option<&str>,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> BatchUnsignResult {
    let mut result = BatchUnsignResult {
        total: files.len(),
        success: 0,
        failed: 0,
        skipped: 0,
        failures: Vec::new(),
    };

    for (idx, file) in files.iter().enumerate() {
        if output_mode == OutputMode::Human {
            println!(
                "{}",
                format!(
                    "\n[{}/{}] Unsigning: {}",
                    idx + 1,
                    files.len(),
                    file.display()
                )
                .cyan()
            );
        }

        let output_path = compute_output_path(file, output_dir, config);

        match unsign_file(file, &output_path, config) {
            Ok(()) => {
                result.success += 1;
                if output_mode == OutputMode::Human {
                    println!("{} -> {}", "✓".green(), output_path.display());
                }
            }
            Err(e) => {
                result.failed += 1;
                let err_msg = format!("{e:#}");
                result.failures.push((file.clone(), err_msg.clone()));
                if output_mode == OutputMode::Human {
                    println!("{}", format!("✗ Failed: {err_msg}").red());
                }
            }
        }
    }

    result
}

fn process_batch_parallel(
    files: &[PathBuf],
    output_dir: Option<&str>,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> BatchUnsignResult {
    let config_clone = config.cloned();
    let success_count = AtomicUsize::new(0);
    let failed_count = AtomicUsize::new(0);

    let results: Vec<(PathBuf, PathBuf, Result<()>)> = files
        .par_iter()
        .map(|file| {
            let output_path = compute_output_path(file, output_dir, config_clone.as_ref());
            let result = unsign_file(file, &output_path, config_clone.as_ref());

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

    BatchUnsignResult {
        total: files.len(),
        success: success_count.load(Ordering::Relaxed),
        failed: failed_count.load(Ordering::Relaxed),
        skipped: 0,
        failures,
    }
}

fn print_batch_summary(result: &BatchUnsignResult) {
    println!("\n{}", "Batch Unsign Summary:".cyan().bold());
    println!("  Total files:     {}", result.total);
    println!(
        "  {} {}",
        "✓".green(),
        format!("Unsigned:       {}", result.success).green()
    );

    if result.failed > 0 {
        println!(
            "  {} {}",
            "✗".red(),
            format!("Failed:         {}", result.failed).red()
        );
    }

    if result.skipped > 0 {
        println!(
            "  {} {}",
            "⊘".yellow(),
            format!("Skipped:        {}", result.skipped).yellow()
        );
    }

    if !result.failures.is_empty() {
        println!("\n{}", "Failed files:".red());
        for (path, error) in &result.failures {
            println!("  {} {}", "✗".red(), path.display());
            println!("    {}", error.dimmed());
        }
    }
}

fn handle_unsign_single(
    file: &str,
    output: Option<&str>,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        println!(
            "{}",
            "Removing signature from configuration profile...".cyan()
        );
    }

    let default_output;
    let output_path = if let Some(out) = output {
        out.to_string()
    } else {
        let path = Path::new(file);
        let stem = path.file_stem().unwrap().to_str().unwrap();
        let suffix = config.map_or("-unsigned", |c| c.output.unsigned_suffix.as_str());
        default_output = format!("{stem}{suffix}.mobileconfig");
        default_output.clone()
    };

    let output_path_ref = Path::new(&output_path);

    unsign_file(Path::new(file), output_path_ref, config)?;

    if output_mode == OutputMode::Human {
        println!(
            "{}",
            format!("✓ Unsigned profile saved to: {output_path}").green()
        );
    } else {
        let result = serde_json::json!({
            "success": true,
            "input": file,
            "output": output_path,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

fn unsign_file(input: &Path, output: &Path, _config: Option<&ProfileConfig>) -> Result<()> {
    // Create parent directory if it doesn't exist
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }

    let input_str = input.to_str().context("Invalid input path")?;
    let output_str = output.to_str().context("Invalid output path")?;

    // Try using macOS security command first (most reliable)
    if cfg!(target_os = "macos") && try_security_cms(input_str, output_str)? {
        let unsigned_data = fs::read(output).context("Failed to read unsigned profile")?;

        let formatted_data = reformat_xml(&unsigned_data)?;

        fs::write(output, &formatted_data)
            .with_context(|| format!("Failed to write formatted output: {output_str}"))?;

        return Ok(());
    }

    // Fallback to manual extraction
    let data = fs::read(input).with_context(|| format!("Failed to read file: {input_str}"))?;

    let unsigned_data = extract_unsigned_profile(&data)?;

    let formatted_data = reformat_xml(&unsigned_data)?;

    fs::write(output, &formatted_data)
        .with_context(|| format!("Failed to write output: {output_str}"))?;

    Ok(())
}

fn try_security_cms(input: &str, output: &str) -> Result<bool> {
    let result = Command::new("security")
        .args(["cms", "-D", "-i", input, "-o", output])
        .output();

    match result {
        Ok(output) if output.status.success() => Ok(true),
        Ok(output) => {
            if !output.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&output.stderr).yellow());
            }
            Ok(false)
        }
        Err(_) => Ok(false),
    }
}

fn extract_unsigned_profile(data: &[u8]) -> Result<Vec<u8>> {
    if is_xml_profile(data) {
        return Ok(data.to_vec());
    }

    if is_signed_profile(data) {
        return extract_xml_from_pkcs7_improved(data);
    }

    anyhow::bail!("Unknown profile format - not XML or signed PKCS#7");
}

fn is_xml_profile(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }

    data.starts_with(b"<?xml") || data.starts_with(b"<plist")
}

fn is_signed_profile(data: &[u8]) -> bool {
    if data.len() < 10 {
        return false;
    }

    data[0] == 0x30 && data[1] == 0x80
}

fn extract_xml_from_pkcs7_improved(data: &[u8]) -> Result<Vec<u8>> {
    let mut xml_start = None;
    let xml_marker = b"<?xml";

    for i in 0..data.len().saturating_sub(xml_marker.len()) {
        if &data[i..i + xml_marker.len()] == xml_marker {
            xml_start = Some(i);
            break;
        }
    }

    let start = xml_start.context("No XML content found in signed profile")?;

    let mut end = data.len();
    let end_marker = b"</plist>";

    for i in start..data.len().saturating_sub(end_marker.len()) {
        if &data[i..i + end_marker.len()] == end_marker {
            end = i + end_marker.len();
            break;
        }
    }

    if end > start {
        let mut xml_data = data[start..end].to_vec();

        xml_data.retain(|&b| b != 0);

        if !xml_data.is_empty()
            && (xml_data.starts_with(b"<?xml") || xml_data.starts_with(b"<plist"))
        {
            return Ok(xml_data);
        }
    }

    anyhow::bail!("Failed to extract valid XML from PKCS#7 envelope");
}

fn reformat_xml(data: &[u8]) -> Result<Vec<u8>> {
    let value: plist::Value = plist::from_bytes(data).context("Failed to parse XML as plist")?;

    let mut buffer = Vec::new();
    plist::to_writer_xml(&mut buffer, &value).context("Failed to reformat XML")?;

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_xml_profile() {
        assert!(is_xml_profile(b"<?xml version=\"1.0\"?>"));
        assert!(is_xml_profile(b"<plist version=\"1.0\">"));
        assert!(!is_xml_profile(b"random data"));
    }

    #[test]
    fn test_is_signed_profile() {
        // Signed profile starts with 0x30 0x80 and needs at least 10 bytes
        assert!(is_signed_profile(&[
            0x30, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        // XML profile (starts with <?)
        assert!(!is_signed_profile(&[
            0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20, 0x76, 0x65, 0x72, 0x73
        ]));
        // Too short data
        assert!(!is_signed_profile(&[0x30, 0x80, 0x00, 0x00]));
    }

    #[test]
    fn test_compute_output_path_with_dir() {
        let input = Path::new("/some/path/profile.mobileconfig");
        let output = compute_output_path(input, Some("/output"), None);
        assert_eq!(output, Path::new("/output/profile-unsigned.mobileconfig"));
    }

    #[test]
    fn test_compute_output_path_same_dir() {
        let input = Path::new("/some/path/profile.mobileconfig");
        let output = compute_output_path(input, None, None);
        assert_eq!(
            output,
            Path::new("/some/path/profile-unsigned.mobileconfig")
        );
    }
}
