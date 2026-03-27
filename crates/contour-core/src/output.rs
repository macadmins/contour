//! Output formatting for CLI tools.
//!
//! Provides dual output modes:
//! - Human: Colored terminal output for interactive use
//! - JSON: Machine-readable output for CI/CD integration

use anyhow::Context;
use colored::Colorize;
use serde::Serialize;
use std::collections::HashMap;

/// Output mode for CLI commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMode {
    /// Colored, human-readable terminal output.
    #[default]
    Human,
    /// Machine-readable JSON output for CI/CD.
    Json,
}

impl OutputMode {
    /// Create output mode from CLI flags.
    #[must_use]
    pub fn from_json_flag(json: bool) -> Self {
        if json { Self::Json } else { Self::Human }
    }
}

/// Result of a CLI command execution.
#[derive(Debug, Clone, Serialize)]
pub struct CommandResult<T: Serialize = ()> {
    /// Whether the command succeeded.
    pub success: bool,

    /// Name of the command that was executed.
    pub command: String,

    /// Command-specific data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    /// Number of items processed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed: Option<usize>,

    /// Error messages.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,

    /// Warning messages.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,

    /// Additional metadata.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl<T: Serialize> CommandResult<T> {
    /// Create a successful result.
    #[must_use]
    pub fn success(command: impl Into<String>) -> Self {
        Self {
            success: true,
            command: command.into(),
            data: None,
            processed: None,
            errors: Vec::new(),
            warnings: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Create a failed result.
    #[must_use]
    pub fn failure(command: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            success: false,
            command: command.into(),
            data: None,
            processed: None,
            errors: vec![error.into()],
            warnings: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Set the data field.
    #[must_use]
    pub fn with_data(mut self, data: T) -> Self {
        self.data = Some(data);
        self
    }

    /// Set the processed count.
    #[must_use]
    pub fn with_processed(mut self, count: usize) -> Self {
        self.processed = Some(count);
        self
    }

    /// Add an error message.
    #[must_use]
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.errors.push(error.into());
        self.success = false;
        self
    }

    /// Add a warning message.
    #[must_use]
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Add metadata.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.metadata.insert(key.into(), json_value);
        }
        self
    }

    /// Output the result based on the output mode.
    pub fn output(&self, mode: OutputMode) {
        match mode {
            OutputMode::Human => self.output_human(),
            OutputMode::Json => self.output_json(),
        }
    }

    fn output_human(&self) {
        if self.success {
            println!("{} {}", "✓".green(), self.command);
        } else {
            println!("{} {}", "✗".red(), self.command);
        }

        if let Some(count) = self.processed {
            println!("  {count} items processed");
        }

        for warning in &self.warnings {
            println!("  {} {}", "!".yellow(), warning);
        }

        for error in &self.errors {
            println!("  {} {}", "✗".red(), error);
        }
    }

    fn output_json(&self) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            println!("{json}");
        }
    }
}

/// Batch processing result.
#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    /// Total files found.
    pub total_files: usize,

    /// Successfully processed.
    pub processed: usize,

    /// Failed to process.
    pub failed: usize,

    /// Skipped (already processed, etc.).
    pub skipped: usize,
}

impl BatchResult {
    /// Create a new empty batch result.
    #[must_use]
    pub fn new() -> Self {
        Self {
            total_files: 0,
            processed: 0,
            failed: 0,
            skipped: 0,
        }
    }

    /// Check if the batch was fully successful.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }
}

impl Default for BatchResult {
    fn default() -> Self {
        Self::new()
    }
}

// ── Standalone print helpers ────────────────────────────────────

/// Print a success message with a green checkmark.
pub fn print_success(msg: &str) {
    println!("{} {}", "✓".green(), msg);
}

/// Print an error message to stderr with a red cross.
pub fn print_error(msg: &str) {
    eprintln!("{} {}", "✗".red(), msg);
}

/// Print a warning message with a yellow exclamation mark.
pub fn print_warning(msg: &str) {
    println!("{} {}", "!".yellow(), msg);
}

/// Print an informational message with a blue info symbol.
pub fn print_info(msg: &str) {
    println!("{} {}", "ℹ".blue(), msg);
}

/// Print a key-value pair, with the key dimmed.
pub fn print_kv(key: &str, value: &str) {
    println!("  {}: {}", key.dimmed(), value);
}

/// Print a value as pretty-printed JSON.
pub fn print_json<T: Serialize>(data: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(data)?);
    Ok(())
}

// ── File-system helpers ─────────────────────────────────────────

/// Sanitize an app name for use in a filename.
///
/// Replaces non-alphanumeric characters (except `-` and `_`) with `-`
/// and lowercases the result.
pub fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .to_lowercase()
}

/// Resolve the output directory from an `--output` flag or the input file's location.
///
/// If `output` is `None`, falls back to the parent directory of `input`.
/// If `output` points to a `.mobileconfig` file, uses its parent directory.
/// Creates the directory if it doesn't exist.
pub fn resolve_output_dir(
    output: Option<&std::path::Path>,
    input: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    use std::path::Path;

    let output_dir = output.map_or_else(
        || input.parent().unwrap_or(Path::new(".")).to_path_buf(),
        |p| {
            if p.extension().is_some_and(|e| e == "mobileconfig") {
                p.parent().unwrap_or(Path::new(".")).to_path_buf()
            } else {
                p.to_path_buf()
            }
        },
    );

    if !output_dir.exists() {
        std::fs::create_dir_all(&output_dir).with_context(|| {
            format!(
                "Failed to create output directory: {}",
                output_dir.display()
            )
        })?;
    }

    Ok(output_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_result_success() {
        let result: CommandResult = CommandResult::success("test");
        assert!(result.success);
        assert_eq!(result.command, "test");
    }

    #[test]
    fn test_command_result_failure() {
        let result: CommandResult = CommandResult::failure("test", "something went wrong");
        assert!(!result.success);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_output_mode_from_flag() {
        assert_eq!(OutputMode::from_json_flag(true), OutputMode::Json);
        assert_eq!(OutputMode::from_json_flag(false), OutputMode::Human);
    }

    #[test]
    fn test_print_helpers_no_panic() {
        print_success("test success");
        print_error("test error");
        print_warning("test warning");
        print_info("test info");
        print_kv("key", "value");
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("Zoom Workplace"), "zoom-workplace");
        assert_eq!(sanitize_filename("1Password 8"), "1password-8");
        assert_eq!(sanitize_filename("my_app-v2"), "my_app-v2");
    }

    #[test]
    fn test_resolve_output_dir_fallback_to_input_parent() {
        let input = std::path::Path::new("/tmp/contour-test/input.toml");
        let result = resolve_output_dir(None, input).unwrap();
        assert_eq!(result, std::path::PathBuf::from("/tmp/contour-test"));
    }

    #[test]
    fn test_resolve_output_dir_mobileconfig_uses_parent() {
        let input = std::path::Path::new("/tmp/input.toml");
        let output = std::path::Path::new("/tmp/out/profile.mobileconfig");
        let result = resolve_output_dir(Some(output), input).unwrap();
        assert_eq!(result, std::path::PathBuf::from("/tmp/out"));
    }
}
