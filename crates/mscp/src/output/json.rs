use crate::output::{
    CommandResult, DeduplicationResult, DiffResult, GenerateAllResult, ValidationResult,
};
use anyhow::Result;

/// Output a command result as JSON
pub fn output_result(result: &CommandResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    println!("{json}");

    // Exit with appropriate code
    if !result.success {
        std::process::exit(1);
    }

    Ok(())
}

/// Output a generate-all result as JSON
pub fn output_generate_all_result(result: &GenerateAllResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    println!("{json}");

    // Exit with appropriate code
    if !result.success {
        std::process::exit(1);
    }

    Ok(())
}

/// Output a validation result as JSON
pub fn output_validation_result(result: &ValidationResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    println!("{json}");

    // Exit with appropriate code
    if !result.success {
        std::process::exit(1);
    }

    Ok(())
}

/// Output a deduplication result as JSON
pub fn output_deduplication_result(result: &DeduplicationResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    println!("{json}");

    // Exit with appropriate code
    if !result.success {
        std::process::exit(1);
    }

    Ok(())
}

/// Output a diff result as JSON
pub fn output_diff_result(result: &DiffResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    println!("{json}");

    // Exit with appropriate code
    if !result.success {
        std::process::exit(1);
    }

    Ok(())
}
