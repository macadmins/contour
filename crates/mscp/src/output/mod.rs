pub use contour_core::output::OutputMode;

use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod json;

/// Print a bar chart breakdown from a sorted list of (label, count) pairs.
///
/// Bars are scaled proportionally so the longest bar is 30 characters wide.
pub fn print_bar_chart(items: &[(&str, usize)]) {
    if items.is_empty() {
        return;
    }

    let max_label = items.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    let max_count = items.iter().map(|(_, c)| *c).max().unwrap_or(1).max(1);
    let max_bar_width = 30;

    for (label, count) in items {
        let bar_len = if *count == 0 {
            0
        } else {
            ((*count as f64 / max_count as f64) * f64::from(max_bar_width)).ceil() as usize
        };
        let bar = "\u{2588}".repeat(bar_len);
        println!(
            "  {:>width$}  {:>4}  {}",
            label,
            count.to_string().bold(),
            bar.green(),
            width = max_label
        );
    }
}

/// Result of a command operation for JSON output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub command: String,
    pub baseline: Option<String>,
    pub output_dir: Option<String>,
    pub profiles_generated: usize,
    pub scripts_generated: usize,
    pub ddm_artifacts: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl CommandResult {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            success: true,
            command: command.into(),
            baseline: None,
            output_dir: None,
            profiles_generated: 0,
            scripts_generated: 0,
            ddm_artifacts: 0,
            warnings: Vec::new(),
            errors: Vec::new(),
            metadata: None,
        }
    }

    pub fn with_baseline(mut self, baseline: impl Into<String>) -> Self {
        self.baseline = Some(baseline.into());
        self
    }

    pub fn with_output_dir(mut self, output_dir: impl Into<String>) -> Self {
        self.output_dir = Some(output_dir.into());
        self
    }
}

/// Generate-all batch result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateAllResult {
    pub success: bool,
    pub command: String,
    pub total_baselines: usize,
    pub processed: usize,
    pub failed: usize,
    pub baselines: Vec<CommandResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl GenerateAllResult {
    pub fn new(total: usize) -> Self {
        Self {
            success: true,
            command: "generate-all".to_string(),
            total_baselines: total,
            processed: 0,
            failed: 0,
            baselines: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
        self.success = false;
    }
}

/// Validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub success: bool,
    pub command: String,
    pub output_dir: String,
    pub baselines_found: usize,
    pub team_files_checked: usize,
    pub team_files_valid: usize,
    pub team_files_invalid: usize,
    pub strict_mode: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn new(output_dir: impl Into<String>, strict: bool) -> Self {
        Self {
            success: true,
            command: "validate".to_string(),
            output_dir: output_dir.into(),
            baselines_found: 0,
            team_files_checked: 0,
            team_files_valid: 0,
            team_files_invalid: 0,
            strict_mode: strict,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
        self.success = false;
    }

    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }
}

/// Deduplication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationResult {
    pub success: bool,
    pub command: String,
    pub dry_run: bool,
    pub profiles_analyzed: usize,
    pub duplicate_groups: usize,
    pub profiles_deduplicated: usize,
    pub space_saved_bytes: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// Diff result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub success: bool,
    pub command: String,
    pub output_dir: String,
    pub baselines_compared: usize,
    pub baselines_with_changes: usize,
    pub baselines_no_previous: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub baseline_diffs: Vec<BaselineDiff>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiff {
    pub baseline_name: String,
    pub current_version: String,
    pub previous_version: Option<String>,
    pub profile_count: usize,
    pub script_count: usize,
    pub mscp_git_hash: String,
}

impl DiffResult {
    pub fn new(output_dir: impl Into<String>) -> Self {
        Self {
            success: true,
            command: "diff".to_string(),
            output_dir: output_dir.into(),
            baselines_compared: 0,
            baselines_with_changes: 0,
            baselines_no_previous: 0,
            baseline_diffs: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
        self.success = false;
    }

    pub fn add_baseline_diff(&mut self, diff: BaselineDiff) {
        if diff.previous_version.is_some() {
            self.baselines_with_changes += 1;
        } else {
            self.baselines_no_previous += 1;
        }
        self.baselines_compared += 1;
        self.baseline_diffs.push(diff);
    }
}
