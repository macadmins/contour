//! Validation types with warnings support.
//!
//! Based on Sleigh's exemplary validation system, providing:
//! - Structured validation errors
//! - Warning system for non-fatal issues
//! - Severity levels for flexible enforcement

use serde::Serialize;
use std::fmt;

/// Severity level for validation issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationSeverity {
    /// Informational message, does not affect validity.
    Info,
    /// Warning that should be reviewed but doesn't fail validation.
    Warning,
    /// Error that causes validation to fail.
    Error,
}

impl fmt::Display for ValidationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// A single validation issue.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationIssue {
    /// Severity of this issue.
    pub severity: ValidationSeverity,

    /// Machine-readable error code.
    pub code: String,

    /// Human-readable message.
    pub message: String,

    /// Optional location context (e.g., file path, line number, index).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,

    /// Optional field name where the issue occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl ValidationIssue {
    /// Create an error issue.
    #[must_use]
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: ValidationSeverity::Error,
            code: code.into(),
            message: message.into(),
            location: None,
            field: None,
        }
    }

    /// Create a warning issue.
    #[must_use]
    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: ValidationSeverity::Warning,
            code: code.into(),
            message: message.into(),
            location: None,
            field: None,
        }
    }

    /// Create an info issue.
    #[must_use]
    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: ValidationSeverity::Info,
            code: code.into(),
            message: message.into(),
            location: None,
            field: None,
        }
    }

    /// Set the location context.
    #[must_use]
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    /// Set the field name.
    #[must_use]
    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.code, self.message)?;
        if let Some(ref loc) = self.location {
            write!(f, " at {loc}")?;
        }
        if let Some(ref field) = self.field {
            write!(f, " (field: {field})")?;
        }
        Ok(())
    }
}

/// Result of a validation operation.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ValidationResult {
    /// All validation issues found.
    pub issues: Vec<ValidationIssue>,
}

impl ValidationResult {
    /// Create an empty (valid) result.
    #[must_use]
    pub fn new() -> Self {
        Self { issues: Vec::new() }
    }

    /// Add an issue to the result.
    pub fn add_issue(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }

    /// Add an error.
    pub fn add_error(&mut self, code: impl Into<String>, message: impl Into<String>) {
        self.issues.push(ValidationIssue::error(code, message));
    }

    /// Add a warning.
    pub fn add_warning(&mut self, code: impl Into<String>, message: impl Into<String>) {
        self.issues.push(ValidationIssue::warning(code, message));
    }

    /// Check if validation passed (no errors).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.has_errors()
    }

    /// Check if validation passed in strict mode (no errors or warnings).
    #[must_use]
    pub fn is_valid_strict(&self) -> bool {
        !self.has_errors() && !self.has_warnings()
    }

    /// Check if there are any errors.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|i| i.severity == ValidationSeverity::Error)
    }

    /// Check if there are any warnings.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.issues
            .iter()
            .any(|i| i.severity == ValidationSeverity::Warning)
    }

    /// Get all errors.
    #[must_use]
    pub fn errors(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Error)
            .collect()
    }

    /// Get all warnings.
    #[must_use]
    pub fn warnings(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Warning)
            .collect()
    }

    /// Merge another validation result into this one.
    pub fn merge(&mut self, other: Self) {
        self.issues.extend(other.issues);
    }

    /// Get error count.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.errors().len()
    }

    /// Get warning count.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.warnings().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_result_is_valid() {
        let result = ValidationResult::new();
        assert!(result.is_valid());
        assert!(result.is_valid_strict());
    }

    #[test]
    fn test_warning_still_valid() {
        let mut result = ValidationResult::new();
        result.add_warning("WARN001", "This is a warning");
        assert!(result.is_valid());
        assert!(!result.is_valid_strict());
    }

    #[test]
    fn test_error_not_valid() {
        let mut result = ValidationResult::new();
        result.add_error("ERR001", "This is an error");
        assert!(!result.is_valid());
        assert!(!result.is_valid_strict());
    }

    #[test]
    fn test_issue_display() {
        let issue = ValidationIssue::error("ERR001", "Something went wrong")
            .with_location("file.yaml:10")
            .with_field("identifier");
        let display = format!("{issue}");
        assert!(display.contains("ERR001"));
        assert!(display.contains("Something went wrong"));
        assert!(display.contains("file.yaml:10"));
        assert!(display.contains("identifier"));
    }

    #[test]
    fn test_merge_results() {
        let mut result1 = ValidationResult::new();
        result1.add_error("ERR001", "Error 1");

        let mut result2 = ValidationResult::new();
        result2.add_warning("WARN001", "Warning 1");

        result1.merge(result2);
        assert_eq!(result1.error_count(), 1);
        assert_eq!(result1.warning_count(), 1);
    }
}
