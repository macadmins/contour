//! Shared utilities for glob/batch processing across CLI commands
//!
//! This module provides common functionality for processing multiple files
//! via glob patterns, directories, or file lists.

use anyhow::{Context, Result};
use colored::Colorize;
use glob::glob;
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;

use crate::output::OutputMode;

/// Result of a batch operation
#[derive(Debug)]
pub struct BatchResult {
    pub total: usize,
    pub success: usize,
    pub failed: usize,
    pub skipped: usize,
    pub with_warnings: usize,
    pub failures: Vec<(PathBuf, String)>,
    pub warnings: Vec<(PathBuf, Vec<String>)>,
}

impl BatchResult {
    pub fn new() -> Self {
        Self {
            total: 0,
            success: 0,
            failed: 0,
            skipped: 0,
            with_warnings: 0,
            failures: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[allow(dead_code, reason = "reserved for future use")]
    pub fn add_success(&mut self) {
        self.total += 1;
        self.success += 1;
    }

    #[allow(dead_code, reason = "reserved for future use")]
    pub fn add_success_with_warnings(&mut self, path: PathBuf, warnings: Vec<String>) {
        self.total += 1;
        self.success += 1;
        if !warnings.is_empty() {
            self.with_warnings += 1;
            self.warnings.push((path, warnings));
        }
    }

    #[allow(dead_code, reason = "reserved for future use")]
    pub fn add_failure(&mut self, path: PathBuf, error: String) {
        self.total += 1;
        self.failed += 1;
        self.failures.push((path, error));
    }

    #[allow(dead_code, reason = "reserved for future use")]
    pub fn add_skipped(&mut self) {
        self.total += 1;
        self.skipped += 1;
    }
}

impl Default for BatchResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a path string contains glob patterns
pub fn is_glob_pattern(path: &str) -> bool {
    path.contains('*') || path.contains('?')
}

/// Determine if we should use batch mode
#[allow(dead_code, reason = "reserved for future use")]
pub fn should_batch_process(path: &str) -> bool {
    is_glob_pattern(path) || Path::new(path).is_dir()
}

/// Check if a file is a mobileconfig profile
pub fn is_profile_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("mobileconfig"))
}

/// Collect profile files from a path with optional max depth
pub fn collect_profile_files_with_depth(
    path: &str,
    recursive: bool,
    max_depth: Option<usize>,
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if is_glob_pattern(path) {
        collect_from_glob(path, recursive, &mut files)?;
    } else {
        let path_obj = Path::new(path);
        if path_obj.is_file() {
            if is_profile_file(path_obj) {
                files.push(path_obj.to_path_buf());
            } else {
                anyhow::bail!("File must have .mobileconfig extension: {path}");
            }
        } else if path_obj.is_dir() {
            collect_from_directory(path_obj, recursive, max_depth, &mut files)?;
        } else {
            anyhow::bail!("Path does not exist: {path}");
        }
    }

    files.sort();
    Ok(files)
}

/// Collect profile files from multiple paths with optional max depth
/// This is the main entry point for commands that accept multiple file arguments.
pub fn collect_profile_files_multi_with_depth(
    paths: &[String],
    recursive: bool,
    max_depth: Option<usize>,
) -> Result<Vec<PathBuf>> {
    let mut all_files = Vec::new();

    for path in paths {
        // Check if it's a glob pattern
        if is_glob_pattern(path) {
            let files = collect_profile_files_with_depth(path, recursive, max_depth)?;
            for f in files {
                if !all_files.contains(&f) {
                    all_files.push(f);
                }
            }
        } else {
            let path_obj = Path::new(path);
            if path_obj.is_file() {
                if is_profile_file(path_obj) {
                    let canonical = path_obj.to_path_buf();
                    if !all_files.contains(&canonical) {
                        all_files.push(canonical);
                    }
                } else {
                    anyhow::bail!("File must have .mobileconfig extension: {path}");
                }
            } else if path_obj.is_dir() {
                let files = collect_profile_files_with_depth(path, recursive, max_depth)?;
                for f in files {
                    if !all_files.contains(&f) {
                        all_files.push(f);
                    }
                }
            } else {
                anyhow::bail!("Path does not exist: {path}");
            }
        }
    }

    all_files.sort();
    Ok(all_files)
}

/// Check if we should use batch mode for multiple paths
pub fn should_batch_process_multi(paths: &[String]) -> bool {
    // Batch mode if:
    // - More than one path provided
    // - Any path is a directory
    // - Any path is a glob pattern (though shell expansion should handle this)
    paths.len() > 1
        || paths.iter().any(|p| Path::new(p).is_dir())
        || paths.iter().any(|p| is_glob_pattern(p))
}

/// Collect files matching a glob pattern
fn collect_from_glob(pattern: &str, recursive: bool, files: &mut Vec<PathBuf>) -> Result<()> {
    // Smart pattern conversion for user convenience
    // "folder/*" becomes "folder/*.mobileconfig"
    let effective_pattern = if pattern.ends_with("/*") {
        format!("{}/*.mobileconfig", pattern.trim_end_matches("/*"))
    } else if pattern.ends_with('*') && !pattern.contains("**") {
        if pattern.contains(".mobileconfig") {
            pattern.to_string()
        } else {
            format!("{}*.mobileconfig", pattern.trim_end_matches('*'))
        }
    } else {
        pattern.to_string()
    };

    for entry in glob(&effective_pattern).context("Invalid glob pattern")? {
        match entry {
            Ok(p) => {
                if p.is_file() && is_profile_file(&p) {
                    files.push(p);
                }
            }
            Err(e) => eprintln!("{}", format!("Warning: {e}").yellow()),
        }
    }

    // Handle recursive for globs
    if recursive && !pattern.contains("**") {
        let base_path = extract_base_path(pattern);
        let recursive_pattern = format!("{base_path}/**/*.mobileconfig");

        if let Ok(entries) = glob(&recursive_pattern) {
            for entry in entries {
                if let Ok(p) = entry
                    && p.is_file()
                    && is_profile_file(&p)
                    && !files.contains(&p)
                {
                    files.push(p);
                }
            }
        }
    }

    Ok(())
}

/// Extract base path from a glob pattern
fn extract_base_path(pattern: &str) -> &str {
    if pattern.ends_with("/*") {
        pattern.trim_end_matches("/*")
    } else if pattern.ends_with('*') {
        pattern.trim_end_matches('*').trim_end_matches('/')
    } else {
        pattern
    }
}

/// Collect files from a directory
fn collect_from_directory(
    dir: &Path,
    recursive: bool,
    max_depth: Option<usize>,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    if recursive {
        let mut walker = WalkDir::new(dir).follow_links(true);
        if let Some(depth) = max_depth {
            walker = walker.max_depth(depth);
        }
        for entry in walker.into_iter().filter_map(std::result::Result::ok) {
            let p = entry.path();
            if p.is_file() && is_profile_file(p) {
                files.push(p.to_path_buf());
            }
        }
    } else {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_file() && is_profile_file(&p) {
                files.push(p);
            }
        }
    }
    Ok(())
}

/// Compute output path for batch operations
pub fn compute_batch_output_path(input: &Path, output_dir: Option<&str>, suffix: &str) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    let filename = format!("{stem}{suffix}.mobileconfig");

    if let Some(dir) = output_dir {
        Path::new(dir).join(&filename)
    } else {
        input.parent().unwrap_or(Path::new(".")).join(&filename)
    }
}

/// Print dry-run preview for batch operations
pub fn print_dry_run_preview(
    files: &[PathBuf],
    output_dir: Option<&str>,
    suffix: &str,
    output_mode: OutputMode,
) {
    if output_mode == OutputMode::Human {
        println!("{}", "\nDry run mode - no files will be written\n".yellow());
        for file in files {
            let output = compute_batch_output_path(file, output_dir, suffix);
            println!("  {} -> {}", file.display(), output.display());
        }
    } else {
        let items: Vec<_> = files
            .iter()
            .map(|f| {
                let output = compute_batch_output_path(f, output_dir, suffix);
                serde_json::json!({
                    "input": f.to_string_lossy(),
                    "output": output.to_string_lossy(),
                })
            })
            .collect();

        let result = serde_json::json!({
            "dry_run": true,
            "would_process": items,
        });
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    }
}

/// Print dry-run preview for read-only operations (no output paths)
#[allow(dead_code, reason = "reserved for future use")]
pub fn print_dry_run_preview_readonly(files: &[PathBuf], output_mode: OutputMode) {
    if output_mode == OutputMode::Human {
        println!(
            "{}",
            "\nDry run mode - files that would be processed:\n".yellow()
        );
        for file in files {
            println!("  {}", file.display());
        }
    } else {
        let items: Vec<_> = files
            .iter()
            .map(|f| f.to_string_lossy().to_string())
            .collect();

        let result = serde_json::json!({
            "dry_run": true,
            "would_process": items,
        });
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    }
}

/// Print batch summary (human-readable)
pub fn print_batch_summary(result: &BatchResult, operation_name: &str) {
    println!(
        "\n{}",
        format!("Batch {operation_name} Summary:").cyan().bold()
    );
    println!("  Total files:     {}", result.total);
    println!(
        "  {} {}",
        "✓".green(),
        format!("Succeeded:      {}", result.success).green()
    );

    if result.with_warnings > 0 {
        println!(
            "  {} {}",
            "⚠".yellow(),
            format!("With warnings:  {}", result.with_warnings).yellow()
        );
    }

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

    if !result.warnings.is_empty() {
        println!("\n{}", "Files with warnings:".yellow());
        for (path, warnings) in &result.warnings {
            println!("  {} {}", "⚠".yellow(), path.display());
            for warning in warnings {
                println!("    {} {}", "·".dimmed(), warning.yellow());
            }
        }
    }

    if !result.failures.is_empty() {
        // Categorize failures for a clearer report
        let categories = categorize_failures(&result.failures);

        println!("\n{}", "Failed files:".red());
        for category in &categories {
            println!(
                "\n  {} {} ({} file{})",
                "■".red(),
                category.label.bold(),
                category.files.len(),
                if category.files.len() == 1 { "" } else { "s" }
            );
            println!("    {}", category.hint.dimmed());
            for (path, _) in &category.files {
                println!("    {} {}", "✗".red(), path.display());
            }
        }
    }
}

/// A category of batch failures with a human-readable label and hint.
struct FailureCategory<'a> {
    label: &'static str,
    hint: &'static str,
    files: Vec<&'a (PathBuf, String)>,
}

/// Map an individual error message to a stable typed error code.
///
/// Used by [`output_batch_json`] to emit `error_code` alongside the prose
/// `error` field, so agents (and the pseudocode SOPs) can SWITCH on a stable
/// enum instead of substring-matching humans-readable text. See the SOP
/// pseudocode pilot's `normalize_profile` and `import_jamf_backup` procedures
/// for how agents consume these codes.
///
/// **Stability contract:** never rename existing variants. If a new failure
/// kind appears, prefer adding a new variant over reclassifying an existing
/// error to a different code — agents may already be branching on the old code.
fn error_code_for(error: &str) -> &'static str {
    // Identifier syntax issues — checked first because "contains spaces"
    // can appear inside larger validation messages.
    if error.contains("contains spaces") || error.contains("invalid identifier") {
        return "INVALID_IDENTIFIER";
    }
    // Plist/file-format problems.
    if error.contains("ExpectedEndOfEventStream")
        || error.contains("InvalidXmlSyntax")
        || error.contains("after placeholder substitution")
        || error.contains("InvalidDataString")
        || error.contains("not a dictionary")
        || error.contains("expected struct ConfigurationProfile")
        || error.contains("Serde(")
        || error.contains("Failed to parse plist")
        || error.contains("UnexpectedEof")
    {
        return "INVALID_FORMAT";
    }
    // Missing required structural fields.
    if error.contains("Profile structure errors") || error.contains("PayloadType") {
        return "MISSING_PAYLOAD_TYPE";
    }
    // Schema/policy validation failures.
    if error.contains("Validation failed") || error.contains("schema validation") {
        return "SCHEMA_VIOLATION";
    }
    // I/O — file not found, permission denied, etc.
    if error.contains("No such file")
        || error.contains("Permission denied")
        || error.contains("Failed to read")
    {
        return "IO_ERROR";
    }
    // Org-domain shape problems (e.g. malformed --org).
    if error.contains("--org is required") || error.contains("organization domain is required") {
        return "INVALID_ORG";
    }
    "UNKNOWN"
}

/// Classify failures into actionable categories.
fn categorize_failures(failures: &[(PathBuf, String)]) -> Vec<FailureCategory<'_>> {
    let mut plist_invalid = Vec::new();
    let mut plist_after_sub = Vec::new();
    let mut structure_errors = Vec::new();
    let mut other = Vec::new();

    for entry in failures {
        let err = &entry.1;
        if err.contains("ExpectedEndOfEventStream") || err.contains("InvalidXmlSyntax") {
            plist_invalid.push(entry);
        } else if err.contains("after placeholder substitution")
            || err.contains("InvalidDataString")
        {
            plist_after_sub.push(entry);
        } else if err.contains("Profile structure errors") {
            structure_errors.push(entry);
        } else {
            other.push(entry);
        }
    }

    let mut categories = Vec::new();

    if !plist_invalid.is_empty() {
        categories.push(FailureCategory {
            label: "Malformed plist",
            hint: "File is not valid XML/binary plist. Likely a test fixture or concatenated file.",
            files: plist_invalid,
        });
    }
    if !plist_after_sub.is_empty() {
        categories.push(FailureCategory {
            label: "Unrecognized placeholders in plist data",
            hint: "File contains template variables (e.g. Go %s, custom tokens) that break plist parsing.",
            files: plist_after_sub,
        });
    }
    if !structure_errors.is_empty() {
        categories.push(FailureCategory {
            label: "Missing required profile fields",
            hint: "Payload is missing PayloadType, PayloadIdentifier, or PayloadUUID.",
            files: structure_errors,
        });
    }
    if !other.is_empty() {
        categories.push(FailureCategory {
            label: "Other errors",
            hint: "See individual error messages for details.",
            files: other,
        });
    }

    categories
}

/// Output batch result as JSON
pub fn output_batch_json(result: &BatchResult, operation_name: &str) -> Result<()> {
    let categories = categorize_failures(&result.failures);
    let json_result = serde_json::json!({
        "operation": operation_name,
        "success": result.failed == 0,
        "total": result.total,
        "succeeded": result.success,
        "failed": result.failed,
        "skipped": result.skipped,
        "with_warnings": result.with_warnings,
        "failure_categories": categories.iter().map(|c| {
            serde_json::json!({
                "category": c.label,
                "hint": c.hint,
                "count": c.files.len(),
                "files": c.files.iter().map(|(p, e)| {
                    serde_json::json!({
                        "file": p.to_string_lossy(),
                        "error": e,
                        "error_code": error_code_for(e),
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
        "warnings": result.warnings.iter().map(|(p, w)| {
            serde_json::json!({
                "file": p.to_string_lossy(),
                "warnings": w,
            })
        }).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&json_result)?);
    Ok(())
}

/// Process files in parallel using a closure
pub fn process_parallel<F>(files: &[PathBuf], processor: F, output_mode: OutputMode) -> BatchResult
where
    F: Fn(&Path) -> Result<()> + Sync,
{
    let success_count = AtomicUsize::new(0);
    let failed_count = AtomicUsize::new(0);

    let results: Vec<(PathBuf, Result<()>)> = files
        .par_iter()
        .map(|file| {
            let result = processor(file);
            match &result {
                Ok(()) => {
                    success_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    failed_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            (file.clone(), result)
        })
        .collect();

    let mut failures = Vec::new();
    for (file, result) in &results {
        match result {
            Ok(()) => {
                if output_mode == OutputMode::Human {
                    println!("{} {}", "✓".green(), file.display());
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

/// Process files in parallel with warning collection
/// The processor returns Result<Vec<String>> where Vec<String> contains warnings
pub fn process_parallel_with_warnings<F>(
    files: &[PathBuf],
    processor: F,
    output_mode: OutputMode,
) -> BatchResult
where
    F: Fn(&Path) -> Result<Vec<String>> + Sync,
{
    let success_count = AtomicUsize::new(0);
    let failed_count = AtomicUsize::new(0);
    let warning_count = AtomicUsize::new(0);

    let results: Vec<(PathBuf, Result<Vec<String>>)> = files
        .par_iter()
        .map(|file| {
            let result = processor(file);
            match &result {
                Ok(warnings) => {
                    success_count.fetch_add(1, Ordering::Relaxed);
                    if !warnings.is_empty() {
                        warning_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    failed_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            (file.clone(), result)
        })
        .collect();

    let mut failures = Vec::new();
    let mut warnings = Vec::new();

    for (file, result) in results {
        match result {
            Ok(file_warnings) => {
                if file_warnings.is_empty() {
                    if output_mode == OutputMode::Human {
                        println!("{} {}", "✓".green(), file.display());
                    }
                } else {
                    if output_mode == OutputMode::Human {
                        println!(
                            "{} {} ({})",
                            "⚠".yellow(),
                            file.display(),
                            format!("{} warning(s)", file_warnings.len()).yellow()
                        );
                    }
                    warnings.push((file, file_warnings));
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
        with_warnings: warning_count.load(Ordering::Relaxed),
        failures,
        warnings,
    }
}

/// Process files sequentially using a closure
pub fn process_sequential<F>(
    files: &[PathBuf],
    processor: F,
    output_mode: OutputMode,
) -> BatchResult
where
    F: Fn(&Path) -> Result<()>,
{
    let mut result = BatchResult::new();
    result.total = files.len();

    for (idx, file) in files.iter().enumerate() {
        if output_mode == OutputMode::Human {
            println!(
                "{}",
                format!(
                    "[{}/{}] Processing: {}",
                    idx + 1,
                    files.len(),
                    file.display()
                )
                .cyan()
            );
        }

        match processor(file) {
            Ok(()) => {
                result.success += 1;
                if output_mode == OutputMode::Human {
                    println!("{} {}", "✓".green(), file.display());
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

/// Process files sequentially with warning collection
/// The processor returns Result<Vec<String>> where Vec<String> contains warnings
pub fn process_sequential_with_warnings<F>(
    files: &[PathBuf],
    processor: F,
    output_mode: OutputMode,
) -> BatchResult
where
    F: Fn(&Path) -> Result<Vec<String>>,
{
    let mut result = BatchResult::new();
    result.total = files.len();

    for (idx, file) in files.iter().enumerate() {
        if output_mode == OutputMode::Human {
            println!(
                "{}",
                format!(
                    "[{}/{}] Processing: {}",
                    idx + 1,
                    files.len(),
                    file.display()
                )
                .cyan()
            );
        }

        match processor(file) {
            Ok(file_warnings) => {
                result.success += 1;
                if file_warnings.is_empty() {
                    if output_mode == OutputMode::Human {
                        println!("{} {}", "✓".green(), file.display());
                    }
                } else {
                    result.with_warnings += 1;
                    if output_mode == OutputMode::Human {
                        println!(
                            "{} {} ({})",
                            "⚠".yellow(),
                            file.display(),
                            format!("{} warning(s)", file_warnings.len()).yellow()
                        );
                    }
                    result.warnings.push((file.clone(), file_warnings));
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

/// Process files and collect results with output paths (for write operations)
#[allow(dead_code, reason = "reserved for future use")]
pub fn process_parallel_with_output<F>(
    files: &[PathBuf],
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

    let results: Vec<(PathBuf, PathBuf, Result<()>)> = files
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

/// Process files sequentially with output paths (for write operations)
#[allow(dead_code, reason = "reserved for future use")]
pub fn process_sequential_with_output<F>(
    files: &[PathBuf],
    output_dir: Option<&str>,
    suffix: &str,
    processor: F,
    output_mode: OutputMode,
) -> BatchResult
where
    F: Fn(&Path, &Path) -> Result<()>,
{
    let mut result = BatchResult::new();
    result.total = files.len();

    for (idx, file) in files.iter().enumerate() {
        let output_path = compute_batch_output_path(file, output_dir, suffix);

        if output_mode == OutputMode::Human {
            println!(
                "{}",
                format!(
                    "[{}/{}] Processing: {}",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_glob_pattern() {
        assert!(is_glob_pattern("*.mobileconfig"));
        assert!(is_glob_pattern("dir/*.mobileconfig"));
        assert!(is_glob_pattern("file?.mobileconfig"));
        assert!(is_glob_pattern("dir/**/*.mobileconfig"));
        assert!(!is_glob_pattern("file.mobileconfig"));
        assert!(!is_glob_pattern("/path/to/dir"));
    }

    #[test]
    fn test_is_profile_file() {
        assert!(is_profile_file(Path::new("test.mobileconfig")));
        assert!(is_profile_file(Path::new("test.MOBILECONFIG")));
        assert!(is_profile_file(Path::new("/path/to/test.mobileconfig")));
        assert!(!is_profile_file(Path::new("test.txt")));
        assert!(!is_profile_file(Path::new("test")));
    }

    #[test]
    fn test_should_batch_process() {
        assert!(should_batch_process("dir/*"));
        assert!(should_batch_process("*.mobileconfig"));
        // Note: directory check requires actual filesystem
        assert!(!should_batch_process("file.mobileconfig"));
    }

    #[test]
    fn test_compute_batch_output_path_with_dir() {
        let input = Path::new("/some/path/profile.mobileconfig");
        let output = compute_batch_output_path(input, Some("/output"), "-signed");
        assert_eq!(output, Path::new("/output/profile-signed.mobileconfig"));
    }

    #[test]
    fn test_compute_batch_output_path_same_dir() {
        let input = Path::new("/some/path/profile.mobileconfig");
        let output = compute_batch_output_path(input, None, "-signed");
        assert_eq!(output, Path::new("/some/path/profile-signed.mobileconfig"));
    }

    #[test]
    fn test_compute_batch_output_path_empty_suffix() {
        let input = Path::new("/some/path/profile.mobileconfig");
        let output = compute_batch_output_path(input, None, "");
        assert_eq!(output, Path::new("/some/path/profile.mobileconfig"));
    }

    #[test]
    fn test_batch_result() {
        let mut result = BatchResult::new();
        assert_eq!(result.total, 0);

        result.add_success();
        assert_eq!(result.total, 1);
        assert_eq!(result.success, 1);

        result.add_failure(PathBuf::from("test.mobileconfig"), "error".to_string());
        assert_eq!(result.total, 2);
        assert_eq!(result.failed, 1);
        assert_eq!(result.failures.len(), 1);

        result.add_skipped();
        assert_eq!(result.total, 3);
        assert_eq!(result.skipped, 1);
    }

    #[test]
    fn test_error_code_for_known_categories() {
        // INVALID_IDENTIFIER — identifier syntax problems
        assert_eq!(
            error_code_for("PayloadIdentifier: 'foo bar' contains spaces"),
            "INVALID_IDENTIFIER"
        );
        // INVALID_FORMAT — plist parse failures and structural issues
        assert_eq!(error_code_for("ExpectedEndOfEventStream"), "INVALID_FORMAT");
        assert_eq!(
            error_code_for("Profile is not a dictionary: Serde(\"...\")"),
            "INVALID_FORMAT"
        );
        assert_eq!(
            error_code_for("Failed to parse plist (XML or binary): Io(...)"),
            "INVALID_FORMAT"
        );
        assert_eq!(
            error_code_for("UnexpectedEof: failed to fill whole buffer"),
            "INVALID_FORMAT"
        );
        // MISSING_PAYLOAD_TYPE
        assert_eq!(
            error_code_for("Profile structure errors: missing PayloadType"),
            "MISSING_PAYLOAD_TYPE"
        );
        // SCHEMA_VIOLATION
        assert_eq!(
            error_code_for("Validation failed after normalization: ..."),
            "SCHEMA_VIOLATION"
        );
        // IO_ERROR
        assert_eq!(error_code_for("No such file or directory"), "IO_ERROR");
        assert_eq!(
            error_code_for("Failed to read file: /tmp/missing"),
            "IO_ERROR"
        );
        // INVALID_ORG
        assert_eq!(
            error_code_for("--org is required (e.g., --org com.yourorg)"),
            "INVALID_ORG"
        );
        // UNKNOWN — fallback for anything unmatched
        assert_eq!(
            error_code_for("Some completely unexpected error string"),
            "UNKNOWN"
        );
    }
}
