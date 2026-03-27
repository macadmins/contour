//! ODV (Organizational Defined Values) manager for customizing rule values.
//!
//! This module provides functionality to discover ODVs from mSCP rules,
//! create override files with baseline defaults, and substitute ODV values
//! in generated scripts and configurations.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::extractors::RuleExtractor;

/// Single ODV definition discovered from a rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdvDefinition {
    /// Rule ID that this ODV belongs to
    pub rule_id: String,
    /// Human-readable hint describing the ODV
    pub hint: String,
    /// Recommended default value
    pub recommended: yaml_serde::Value,
    /// Baseline-specific default values (`baseline_name` -> value)
    pub baseline_values: HashMap<String, yaml_serde::Value>,
}

/// ODV override entry in user's override file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdvOverride {
    /// Rule ID that this override applies to
    pub rule_id: String,
    /// Hint copied from rule for reference
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hint: String,
    /// Default value from baseline
    pub default_value: yaml_serde::Value,
    /// User's custom override value
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_value: Option<yaml_serde::Value>,
}

/// Complete ODV override file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdvOverrideFile {
    /// Baseline this override file applies to
    pub baseline: String,
    /// mSCP version/branch this was generated from
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mscp_version: Option<String>,
    /// List of ODV overrides
    pub overrides: Vec<OdvOverride>,
}

/// Resolves ODV overrides for baselines.
#[derive(Debug)]
pub struct OdvOverrides {
    #[expect(dead_code, reason = "Reserved for future use in diagnostic output")]
    baseline: String,
    overrides: OdvOverrideFile,
}

impl OdvOverrides {
    /// Discover all ODVs from rules in a baseline
    pub fn discover_odvs(
        mscp_repo: impl AsRef<Path>,
        baseline: &str,
    ) -> Result<Vec<OdvDefinition>> {
        let extractor = RuleExtractor::new(mscp_repo.as_ref());
        let rules = extractor.extract_rules_for_baseline(baseline)?;

        let mut odvs = Vec::new();

        for rule in rules {
            if let Some(odv_value) = &rule.odv
                && let Some(odv_map) = odv_value.as_mapping()
            {
                let hint = odv_map
                    .get(yaml_serde::Value::String("hint".to_string()))
                    .and_then(yaml_serde::Value::as_str)
                    .unwrap_or("")
                    .to_string();

                let recommended = odv_map
                    .get(yaml_serde::Value::String("recommended".to_string()))
                    .cloned()
                    .unwrap_or(yaml_serde::Value::Null);

                // Collect baseline-specific values
                let mut baseline_values = HashMap::new();
                for (key, value) in odv_map {
                    if let Some(key_str) = key.as_str() {
                        // Skip non-baseline keys
                        if key_str == "hint" || key_str == "recommended" {
                            continue;
                        }
                        baseline_values.insert(key_str.to_string(), value.clone());
                    }
                }

                odvs.push(OdvDefinition {
                    rule_id: rule.id.clone(),
                    hint,
                    recommended,
                    baseline_values,
                });
            }
        }

        // Sort by rule_id for consistent output
        odvs.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

        tracing::info!("Discovered {} ODVs for baseline '{baseline}'", odvs.len());

        Ok(odvs)
    }

    /// Create initial override file with baseline defaults
    pub fn create_override_file(
        mscp_repo: impl AsRef<Path>,
        baseline: &str,
        output_path: impl AsRef<Path>,
    ) -> Result<PathBuf> {
        let odvs = Self::discover_odvs(mscp_repo, baseline)?;

        // Build overrides from discovered ODVs
        let overrides: Vec<OdvOverride> = odvs
            .into_iter()
            .map(|odv| {
                // Get baseline-specific value or fall back to recommended
                let default_value = odv
                    .baseline_values
                    .get(baseline)
                    .cloned()
                    .unwrap_or(odv.recommended.clone());

                OdvOverride {
                    rule_id: odv.rule_id,
                    hint: odv.hint,
                    default_value,
                    custom_value: None,
                }
            })
            .collect();

        let override_file = OdvOverrideFile {
            baseline: baseline.to_string(),
            mscp_version: detect_mscp_version(),
            overrides,
        };

        // Determine output filename
        let output_dir = output_path.as_ref();
        let filename = format!("odv_{baseline}.yaml");
        let file_path = output_dir.join(&filename);

        // Serialize with header comment
        let yaml_content = yaml_serde::to_string(&override_file)
            .context("Failed to serialize ODV override file")?;

        let header = format!(
            r"# ODV Overrides for {baseline} baseline
# Edit custom_value to override defaults
# Generated by: contour mscp odv init --baseline {baseline}
#
# To apply these overrides:
#   contour mscp generate --baseline {baseline} --odv {filename}
#   contour mscp extract-scripts --baseline {baseline} --odv {filename}

"
        );

        let final_content = format!("{header}{yaml_content}");
        std::fs::write(&file_path, final_content)
            .with_context(|| format!("Failed to write ODV file: {}", file_path.display()))?;

        Ok(file_path)
    }

    /// Load existing override file
    pub fn load(baseline: &str, path: Option<PathBuf>) -> Result<Self> {
        // Auto-detect path if not specified
        let override_path = path.unwrap_or_else(|| PathBuf::from(format!("odv_{baseline}.yaml")));

        if !override_path.exists() {
            // Return empty manager if file doesn't exist
            return Ok(Self {
                baseline: baseline.to_string(),
                overrides: OdvOverrideFile {
                    baseline: baseline.to_string(),
                    mscp_version: None,
                    overrides: Vec::new(),
                },
            });
        }

        let content = std::fs::read_to_string(&override_path)
            .with_context(|| format!("Failed to read ODV file: {}", override_path.display()))?;

        let overrides: OdvOverrideFile = yaml_serde::from_str(&content)
            .with_context(|| format!("Failed to parse ODV file: {}", override_path.display()))?;

        Ok(Self {
            baseline: baseline.to_string(),
            overrides,
        })
    }

    /// Try to load an ODV file, returning None if it doesn't exist
    pub fn try_load(baseline: &str, path: Option<PathBuf>) -> Option<Self> {
        // Determine path to check
        let override_path = path.unwrap_or_else(|| PathBuf::from(format!("odv_{baseline}.yaml")));

        if override_path.exists() {
            Self::load(baseline, Some(override_path)).ok()
        } else {
            None
        }
    }

    /// Get effective ODV value for a rule (custom > baseline default)
    pub fn get_value(&self, rule_id: &str) -> Option<&yaml_serde::Value> {
        self.overrides
            .overrides
            .iter()
            .find(|o| o.rule_id == rule_id)
            .map(|o| o.custom_value.as_ref().unwrap_or(&o.default_value))
    }

    /// Get all overrides
    pub fn get_overrides(&self) -> &[OdvOverride] {
        &self.overrides.overrides
    }

    /// Check if this manager has any ODVs
    pub fn is_empty(&self) -> bool {
        self.overrides.overrides.is_empty()
    }

    /// Substitute $ODV in a string with the effective value for a rule
    ///
    /// Returns the string with $ODV replaced by the value, or the original
    /// string if no ODV is defined for the rule.
    pub fn substitute(&self, rule_id: &str, text: &str) -> String {
        if !text.contains("$ODV") {
            return text.to_string();
        }

        if let Some(value) = self.get_value(rule_id) {
            let replacement = value_to_string(value);
            text.replace("$ODV", &replacement)
        } else {
            text.to_string()
        }
    }
}

/// Convert a `yaml_serde::Value` to a string suitable for shell script substitution
fn value_to_string(value: &yaml_serde::Value) -> String {
    match value {
        yaml_serde::Value::Null => String::new(),
        yaml_serde::Value::Bool(b) => b.to_string(),
        yaml_serde::Value::Number(n) => n.to_string(),
        yaml_serde::Value::String(s) => s.clone(),
        yaml_serde::Value::Sequence(seq) => {
            // For sequences, join with spaces (common for shell arrays)
            seq.iter()
                .map(value_to_string)
                .collect::<Vec<_>>()
                .join(" ")
        }
        yaml_serde::Value::Mapping(_) => {
            // Mappings are serialized as YAML
            yaml_serde::to_string(value).unwrap_or_default()
        }
        yaml_serde::Value::Tagged(t) => value_to_string(&t.value),
    }
}

/// Detect mSCP version from git if available
fn detect_mscp_version() -> Option<String> {
    // Try to detect from common paths
    let paths = ["./macos_security", "../macos_security"];

    for path in paths {
        let repo_path = PathBuf::from(path);
        if let Ok(version) = get_git_branch(&repo_path) {
            return Some(version);
        }
    }

    None
}

/// Get current git branch from a repository
fn get_git_branch(repo_path: &Path) -> Result<String> {
    use std::process::Command;

    let output = Command::new("git")
        .arg("rev-parse")
        .arg("--abbrev-ref")
        .arg("HEAD")
        .current_dir(repo_path)
        .output()
        .context("Failed to get git branch")?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        anyhow::bail!("Git command failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_to_string() {
        assert_eq!(value_to_string(&yaml_serde::Value::Null), "");
        assert_eq!(value_to_string(&yaml_serde::Value::Bool(true)), "true");
        assert_eq!(value_to_string(&yaml_serde::Value::Number(15.into())), "15");
        assert_eq!(
            value_to_string(&yaml_serde::Value::String("test".to_string())),
            "test"
        );
    }

    #[test]
    fn test_substitute_no_odv() {
        let manager = OdvOverrides {
            baseline: "test".to_string(),
            overrides: OdvOverrideFile {
                baseline: "test".to_string(),
                mscp_version: None,
                overrides: vec![],
            },
        };

        let result = manager.substitute("some_rule", "echo hello");
        assert_eq!(result, "echo hello");
    }

    #[test]
    fn test_substitute_with_odv() {
        let manager = OdvOverrides {
            baseline: "test".to_string(),
            overrides: OdvOverrideFile {
                baseline: "test".to_string(),
                mscp_version: None,
                overrides: vec![OdvOverride {
                    rule_id: "pwpolicy_minimum_length_enforce".to_string(),
                    hint: "Minimum password length".to_string(),
                    default_value: yaml_serde::Value::Number(15.into()),
                    custom_value: Some(yaml_serde::Value::Number(16.into())),
                }],
            },
        };

        let result = manager.substitute(
            "pwpolicy_minimum_length_enforce",
            "pwpolicy -setglobalpolicy minChars=$ODV",
        );
        assert_eq!(result, "pwpolicy -setglobalpolicy minChars=16");
    }

    #[test]
    fn test_substitute_uses_default_when_no_custom() {
        let manager = OdvOverrides {
            baseline: "test".to_string(),
            overrides: OdvOverrideFile {
                baseline: "test".to_string(),
                mscp_version: None,
                overrides: vec![OdvOverride {
                    rule_id: "pwpolicy_minimum_length_enforce".to_string(),
                    hint: "Minimum password length".to_string(),
                    default_value: yaml_serde::Value::Number(15.into()),
                    custom_value: None,
                }],
            },
        };

        let result = manager.substitute(
            "pwpolicy_minimum_length_enforce",
            "pwpolicy -setglobalpolicy minChars=$ODV",
        );
        assert_eq!(result, "pwpolicy -setglobalpolicy minChars=15");
    }

    #[test]
    fn test_is_empty() {
        let empty_manager = OdvOverrides {
            baseline: "test".to_string(),
            overrides: OdvOverrideFile {
                baseline: "test".to_string(),
                mscp_version: None,
                overrides: vec![],
            },
        };
        assert!(empty_manager.is_empty());

        let non_empty_manager = OdvOverrides {
            baseline: "test".to_string(),
            overrides: OdvOverrideFile {
                baseline: "test".to_string(),
                mscp_version: None,
                overrides: vec![OdvOverride {
                    rule_id: "test".to_string(),
                    hint: String::new(),
                    default_value: yaml_serde::Value::Null,
                    custom_value: None,
                }],
            },
        };
        assert!(!non_empty_manager.is_empty());
    }
}
