pub use contour_core::output::{
    OutputMode, print_error, print_info, print_json, print_kv, print_success, print_warning,
};

use colored::Colorize;
use serde::Serialize;

/// Common result structure for JSON output
#[derive(Debug, Serialize)]
pub struct CommandResult<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl<T: Serialize> CommandResult<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn failure(errors: Vec<String>) -> Self {
        Self {
            success: false,
            data: None,
            errors,
            warnings: Vec::new(),
        }
    }

    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }
}

/// Print a bar chart breakdown from a sorted list of (label, count) pairs.
///
/// Bars are scaled proportionally so the longest bar is 30 characters wide.
///
/// ```text
///       ALLOWLIST  142  ██████████████████████████████
///       BLOCKLIST   28  ██████
///         MONITOR    3  █
/// ```
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
        let bar = "█".repeat(bar_len);
        println!(
            "  {:>width$}  {:>4}  {}",
            label,
            count.to_string().bold(),
            bar.green(),
            width = max_label
        );
    }
}

/// Print output based on mode
pub fn output<T: Serialize>(mode: OutputMode, result: CommandResult<T>) -> anyhow::Result<()> {
    match mode {
        OutputMode::Json => print_json(&result),
        OutputMode::Human => {
            for err in &result.errors {
                print_error(err);
            }
            for warn in &result.warnings {
                print_warning(warn);
            }
            Ok(())
        }
    }
}
