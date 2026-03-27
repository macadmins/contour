// Schema validators - public API
#![allow(dead_code, reason = "module under development")]

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Schema validator for `FleetDM` YAML files
#[derive(Debug)]
pub struct SchemaValidator {
    schemas_dir: Option<PathBuf>,
}

impl SchemaValidator {
    pub fn new<P: AsRef<Path>>(schemas_dir: Option<P>) -> Self {
        Self {
            schemas_dir: schemas_dir.map(|p| p.as_ref().to_path_buf()),
        }
    }

    /// Validate a YAML file against a JSON schema
    pub fn validate_team_yaml<P: AsRef<Path>>(&self, yaml_path: P) -> Result<ValidationResult> {
        let yaml_path = yaml_path.as_ref();

        // Read the YAML file
        let content = fs::read_to_string(yaml_path)
            .context(format!("Failed to read YAML file: {}", yaml_path.display()))?;

        // Parse YAML to JSON value
        let yaml_value: yaml_serde::Value =
            yaml_serde::from_str(&content).context("Failed to parse YAML")?;

        let json_value: Value =
            serde_json::to_value(&yaml_value).context("Failed to convert YAML to JSON")?;

        // If schemas_dir is provided, try to load and validate
        if let Some(ref schemas_dir) = self.schemas_dir {
            self.validate_with_schema(&json_value, schemas_dir)
        } else {
            // Basic validation without schema
            self.basic_validation(&json_value)
        }
    }

    /// Validate against JSON schema
    fn validate_with_schema(&self, value: &Value, schemas_dir: &Path) -> Result<ValidationResult> {
        // Look for team schema file
        let schema_path = schemas_dir.join("team.schema.json");

        if !schema_path.exists() {
            tracing::warn!(
                "Schema file not found: {}. Falling back to basic validation.",
                schema_path.display()
            );
            return self.basic_validation(value);
        }

        // Load schema
        let schema_content =
            fs::read_to_string(&schema_path).context("Failed to read schema file")?;
        let schema_value: Value =
            serde_json::from_str(&schema_content).context("Failed to parse schema JSON")?;

        // Compile schema
        let compiled_schema = jsonschema::validator_for(&schema_value)
            .map_err(|e| anyhow::anyhow!("Failed to compile schema: {e}"))?;

        // Validate using is_valid() and iter_errors() for detailed info
        if compiled_schema.is_valid(value) {
            Ok(ValidationResult {
                valid: true,
                errors: Vec::new(),
            })
        } else {
            let error_messages: Vec<String> = compiled_schema
                .iter_errors(value)
                .map(|e| format!("{e}"))
                .collect();

            Ok(ValidationResult {
                valid: false,
                errors: error_messages,
            })
        }
    }

    /// Basic validation without schema
    fn basic_validation(&self, value: &Value) -> Result<ValidationResult> {
        let mut errors = Vec::new();

        // Check basic structure
        if !value.is_object() {
            errors.push("Root must be an object".to_string());
            return Ok(ValidationResult {
                valid: false,
                errors,
            });
        }

        let obj = value.as_object().unwrap();

        // Check for required fields (basic Fleet team structure)
        if let Some(controls) = obj.get("controls") {
            if controls.is_object() {
                // Validate controls.macos_settings if exists
                if let Some(macos_settings) = controls.get("macos_settings")
                    && let Some(custom_settings) = macos_settings.get("custom_settings")
                {
                    if custom_settings.is_array() {
                        // Validate each custom setting has a path
                        for (i, setting) in custom_settings.as_array().unwrap().iter().enumerate() {
                            if !setting.is_object() {
                                errors.push(format!("custom_settings[{i}] must be an object"));
                            } else if setting.get("path").is_none() {
                                errors.push(format!("custom_settings[{i}] missing 'path' field"));
                            }
                        }
                    } else {
                        errors.push("'custom_settings' must be an array".to_string());
                    }
                }
            } else {
                errors.push("'controls' must be an object".to_string());
            }
        }

        Ok(ValidationResult {
            valid: errors.is_empty(),
            errors,
        })
    }

    /// Validate file paths referenced in YAML exist
    pub fn validate_file_paths<P: AsRef<Path>>(
        &self,
        yaml_path: P,
        base_dir: P,
    ) -> Result<PathValidationResult> {
        let yaml_path = yaml_path.as_ref();
        let base_dir = base_dir.as_ref();

        let content = fs::read_to_string(yaml_path)?;
        let yaml_value: yaml_serde::Value = yaml_serde::from_str(&content)?;
        let json_value: Value = serde_json::to_value(&yaml_value)?;

        let mut missing_paths = Vec::new();
        let mut found_paths = Vec::new();

        // Extract paths from custom_settings
        if let Some(controls) = json_value.get("controls") {
            if let Some(macos_settings) = controls.get("macos_settings")
                && let Some(custom_settings) = macos_settings.get("custom_settings")
                && let Some(settings_array) = custom_settings.as_array()
            {
                for setting in settings_array {
                    if let Some(path_str) = setting.get("path").and_then(|p| p.as_str()) {
                        // Remove leading ./ if exists
                        let path_clean = path_str.trim_start_matches("./");
                        let full_path = base_dir.join(path_clean);

                        if full_path.exists() {
                            found_paths.push(path_str.to_string());
                        } else {
                            missing_paths.push(path_str.to_string());
                        }
                    }
                }
            }

            // Extract paths from scripts
            if let Some(scripts) = controls.get("scripts")
                && let Some(scripts_array) = scripts.as_array()
            {
                for script in scripts_array {
                    if let Some(path_str) = script.get("path").and_then(|p| p.as_str()) {
                        let path_clean = path_str.trim_start_matches("./");
                        let full_path = base_dir.join(path_clean);

                        if full_path.exists() {
                            found_paths.push(path_str.to_string());
                        } else {
                            missing_paths.push(path_str.to_string());
                        }
                    }
                }
            }
        }

        Ok(PathValidationResult {
            valid: missing_paths.is_empty(),
            found_paths,
            missing_paths,
        })
    }
}

/// Validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

/// Path validation result
#[derive(Debug, Clone)]
pub struct PathValidationResult {
    pub valid: bool,
    pub found_paths: Vec<String>,
    pub missing_paths: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_validator_creation() {
        let validator = SchemaValidator::new(Some("/tmp/schemas"));
        assert!(validator.schemas_dir.is_some());
    }
}
