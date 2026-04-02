//! Output module for JSON/human-readable command results
//!
//! This module provides structured output for CI/CD integration.
//! Some builder methods are reserved for future use.
#![allow(dead_code, reason = "module under development")]

pub use contour_core::output::OutputMode;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod json;

/// Result of a command operation for JSON output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub command: String,
    pub input_file: Option<String>,
    pub output_file: Option<String>,
    /// Number of profiles processed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profiles_processed: Option<usize>,
    /// Number of payloads modified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payloads_modified: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transformations: Vec<Transformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Additional metadata for CI/CD integration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl CommandResult {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            success: true,
            command: command.into(),
            input_file: None,
            output_file: None,
            profiles_processed: None,
            payloads_modified: None,
            transformations: Vec::new(),
            validation: None,
            errors: Vec::new(),
            warnings: Vec::new(),
            metadata: None,
        }
    }

    pub fn with_input(mut self, input: impl Into<String>) -> Self {
        self.input_file = Some(input.into());
        self
    }

    pub fn with_output(mut self, output: impl Into<String>) -> Self {
        self.output_file = Some(output.into());
        self
    }

    pub fn with_profiles_processed(mut self, count: usize) -> Self {
        self.profiles_processed = Some(count);
        self
    }

    pub fn with_payloads_modified(mut self, count: usize) -> Self {
        self.payloads_modified = Some(count);
        self
    }

    pub fn set_profiles_processed(&mut self, count: usize) {
        self.profiles_processed = Some(count);
    }

    pub fn set_payloads_modified(&mut self, count: usize) {
        self.payloads_modified = Some(count);
    }

    pub fn add_transformation(&mut self, transformation: Transformation) {
        self.transformations.push(transformation);
    }

    pub fn set_validation(&mut self, validation: ValidationResult) {
        self.validation = Some(validation);
    }

    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
        self.success = false;
    }

    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    pub fn add_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        if self.metadata.is_none() {
            self.metadata = Some(HashMap::new());
        }
        self.metadata.as_mut().unwrap().insert(key.into(), value);
    }

    pub fn transformations(&self) -> &[Transformation] {
        &self.transformations
    }

    pub fn validation(&self) -> Option<&ValidationResult> {
        self.validation.as_ref()
    }
}

/// Transformation applied to a profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transformation {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
    pub reason: String,
}

impl Transformation {
    pub fn new(
        field: impl Into<String>,
        old_value: impl Into<String>,
        new_value: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            old_value: old_value.into(),
            new_value: new_value.into(),
            reason: reason.into(),
        }
    }
}

/// Validation result for JSON output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub profile_type: String,
    pub profile_version: i32,
    pub identifier: String,
    pub uuid: String,
    pub display_name: String,
    pub payload_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Batch processing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    pub total_files: usize,
    pub processed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub results: Vec<CommandResult>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub summary: HashMap<String, String>,
}

impl BatchResult {
    pub fn new(total: usize) -> Self {
        Self {
            total_files: total,
            processed: 0,
            failed: 0,
            skipped: 0,
            results: Vec::new(),
            summary: HashMap::new(),
        }
    }

    pub fn add_result(&mut self, result: CommandResult) {
        if result.success {
            self.processed += 1;
        } else {
            self.failed += 1;
        }
        self.results.push(result);
    }
}
