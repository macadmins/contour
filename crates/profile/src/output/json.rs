use crate::output::{BatchResult, CommandResult};
use anyhow::Result;

/// Output a command result as JSON
pub fn output_result(result: &CommandResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    println!("{json}");
    Ok(())
}

/// Output a command result as JSON and exit with appropriate code
/// Returns exit code: 0 for success, 1 for failure
pub fn output_result_and_exit(result: &CommandResult) -> ! {
    let json = serde_json::to_string_pretty(result).unwrap_or_else(|e| {
        format!(r#"{{"success": false, "error": "Failed to serialize result: {e}"}}"#)
    });
    println!("{json}");
    std::process::exit(i32::from(!result.success))
}

/// Output a batch result as JSON
pub fn output_batch_result(result: &BatchResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    println!("{json}");
    Ok(())
}

/// Output a batch result as JSON and exit with appropriate code
/// Returns exit code: 0 if no failures, 1 if any failures
pub fn output_batch_result_and_exit(result: &BatchResult) -> ! {
    let json = serde_json::to_string_pretty(result).unwrap_or_else(|e| {
        format!(r#"{{"success": false, "error": "Failed to serialize result: {e}"}}"#)
    });
    println!("{json}");
    std::process::exit(i32::from(result.failed != 0))
}
