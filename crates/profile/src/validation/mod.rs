//! Profile validation and custom rules.
//!
//! Provides validation of configuration profiles against Apple schemas and
//! custom organization rules defined in TOML configuration files.

pub mod schema_validator;

use crate::profile::ConfigurationProfile;
use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub use schema_validator::{SchemaValidator, Severity, ValidationOptions};

/// Custom validation rules configuration
#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationRules {
    /// Rules for profile-level validation
    #[serde(default)]
    pub profile: ProfileRules,

    /// Rules for payload content validation
    #[serde(default)]
    pub payload: PayloadRules,

    /// Custom rules defined by user
    #[serde(default)]
    pub custom: Vec<CustomRule>,
}

#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileRules {
    /// Required identifier prefix (e.g., "com.yourorg")
    #[serde(default)]
    pub identifier_prefix: Option<String>,

    /// Required organization name
    #[serde(default)]
    pub required_organization: bool,

    /// Required description
    #[serde(default)]
    pub required_description: bool,

    /// Display name pattern (regex)
    #[serde(default)]
    pub display_name_pattern: Option<String>,

    /// Maximum payload count
    #[serde(default)]
    pub max_payloads: Option<usize>,
}

#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadRules {
    /// Allowed payload types (whitelist)
    #[serde(default)]
    pub allowed_types: Vec<String>,

    /// Blocked payload types (blacklist)
    #[serde(default)]
    pub blocked_types: Vec<String>,

    /// Require unique identifiers across payloads
    #[serde(default = "default_true")]
    pub unique_identifiers: bool,
}

impl Default for PayloadRules {
    fn default() -> Self {
        Self {
            allowed_types: Vec::new(),
            blocked_types: Vec::new(),
            unique_identifiers: true, // Default to true for safety
        }
    }
}

#[allow(dead_code, reason = "reserved for future use")]
fn default_true() -> bool {
    true
}

#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    /// Rule name
    pub name: String,

    /// Rule description
    #[serde(default)]
    pub description: Option<String>,

    /// Severity: error or warning
    #[serde(default = "default_severity")]
    pub severity: String,

    /// Field path to check (dot notation, e.g., "PayloadContent.0.SSID_STR")
    pub field: String,

    /// Check type
    pub check: RuleCheck,
}

#[allow(dead_code, reason = "reserved for future use")]
fn default_severity() -> String {
    "error".to_string()
}

#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleCheck {
    /// Field must exist
    #[serde(rename = "exists")]
    Exists,

    /// Field must not exist
    #[serde(rename = "not_exists")]
    NotExists,

    /// Field must match pattern
    #[serde(rename = "pattern")]
    Pattern { pattern: String },

    /// Field must equal value
    #[serde(rename = "equals")]
    Equals { value: String },

    /// Field must not equal value
    #[serde(rename = "not_equals")]
    NotEquals { value: String },

    /// Field must be in list
    #[serde(rename = "one_of")]
    OneOf { values: Vec<String> },
}

/// Result of custom validation
#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug, Clone)]
pub struct CustomValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[allow(dead_code, reason = "validation rules API is planned for future use")]
impl ValidationRules {
    /// Load rules from TOML file
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read validation rules: {}", path.display()))?;

        let rules: ValidationRules =
            toml::from_str(&contents).with_context(|| "Failed to parse validation rules TOML")?;

        Ok(rules)
    }

    /// Load rules from config directory
    pub fn load_default() -> Result<Option<Self>> {
        // Check current directory
        let cwd = std::env::current_dir()?;
        let local_rules = cwd.join("validation-rules.toml");
        if local_rules.exists() {
            return Ok(Some(Self::load(&local_rules)?));
        }

        // Check profile-rules.toml
        let profile_rules = cwd.join("profile-rules.toml");
        if profile_rules.exists() {
            return Ok(Some(Self::load(&profile_rules)?));
        }

        // Check config directory
        if let Some(config_dir) = dirs::config_dir() {
            let config_rules = config_dir.join("profile").join("validation-rules.toml");
            if config_rules.exists() {
                return Ok(Some(Self::load(&config_rules)?));
            }
        }

        Ok(None)
    }

    /// Validate a profile against custom rules
    pub fn validate(&self, profile: &ConfigurationProfile) -> Result<CustomValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Profile-level rules
        if let Some(prefix) = &self.profile.identifier_prefix
            && !profile.payload_identifier.starts_with(prefix)
        {
            errors.push(format!(
                "PayloadIdentifier must start with '{}', got '{}'",
                prefix, profile.payload_identifier
            ));
        }

        if self.profile.required_organization && profile.payload_organization().is_none() {
            errors.push("PayloadOrganization is required but not set".to_string());
        }

        if self.profile.required_description && profile.payload_description().is_none() {
            errors.push("PayloadDescription is required but not set".to_string());
        }

        if let Some(pattern) = &self.profile.display_name_pattern {
            let re = Regex::new(pattern)
                .with_context(|| format!("Invalid display_name_pattern: {pattern}"))?;
            if !re.is_match(&profile.payload_display_name) {
                errors.push(format!(
                    "PayloadDisplayName '{}' does not match pattern '{}'",
                    profile.payload_display_name, pattern
                ));
            }
        }

        if let Some(max) = self.profile.max_payloads
            && profile.payload_content.len() > max
        {
            errors.push(format!(
                "Profile contains {} payloads, maximum allowed is {}",
                profile.payload_content.len(),
                max
            ));
        }

        // Payload-level rules
        if !self.payload.allowed_types.is_empty() {
            for (idx, content) in profile.payload_content.iter().enumerate() {
                if !self.payload.allowed_types.contains(&content.payload_type) {
                    errors.push(format!(
                        "PayloadContent[{}]: PayloadType '{}' is not in allowed list",
                        idx, content.payload_type
                    ));
                }
            }
        }

        if !self.payload.blocked_types.is_empty() {
            for (idx, content) in profile.payload_content.iter().enumerate() {
                if self.payload.blocked_types.contains(&content.payload_type) {
                    errors.push(format!(
                        "PayloadContent[{}]: PayloadType '{}' is blocked",
                        idx, content.payload_type
                    ));
                }
            }
        }

        if self.payload.unique_identifiers {
            let mut seen_ids = std::collections::HashSet::new();
            for (idx, content) in profile.payload_content.iter().enumerate() {
                if !seen_ids.insert(&content.payload_identifier) {
                    errors.push(format!(
                        "PayloadContent[{}]: Duplicate PayloadIdentifier '{}'",
                        idx, content.payload_identifier
                    ));
                }
            }
        }

        // Custom rules
        for rule in &self.custom {
            if let Some(msg) = self.check_custom_rule(profile, rule)? {
                if rule.severity == "error" {
                    errors.push(msg);
                } else {
                    warnings.push(msg);
                }
            }
        }

        Ok(CustomValidationResult {
            valid: errors.is_empty(),
            errors,
            warnings,
        })
    }

    fn check_custom_rule(
        &self,
        profile: &ConfigurationProfile,
        rule: &CustomRule,
    ) -> Result<Option<String>> {
        let value = self.get_field_value(profile, &rule.field);

        match &rule.check {
            RuleCheck::Exists => {
                if value.is_none() {
                    return Ok(Some(format!(
                        "{}: Field '{}' must exist",
                        rule.name, rule.field
                    )));
                }
            }
            RuleCheck::NotExists => {
                if value.is_some() {
                    return Ok(Some(format!(
                        "{}: Field '{}' must not exist",
                        rule.name, rule.field
                    )));
                }
            }
            RuleCheck::Pattern { pattern } => {
                if let Some(v) = value {
                    let re = Regex::new(pattern)?;
                    if !re.is_match(&v) {
                        return Ok(Some(format!(
                            "{}: Field '{}' value '{}' does not match pattern '{}'",
                            rule.name, rule.field, v, pattern
                        )));
                    }
                }
            }
            RuleCheck::Equals { value: expected } => {
                if let Some(v) = value
                    && v != *expected
                {
                    return Ok(Some(format!(
                        "{}: Field '{}' must equal '{}', got '{}'",
                        rule.name, rule.field, expected, v
                    )));
                }
            }
            RuleCheck::NotEquals { value: forbidden } => {
                if let Some(v) = value
                    && v == *forbidden
                {
                    return Ok(Some(format!(
                        "{}: Field '{}' must not equal '{}'",
                        rule.name, rule.field, forbidden
                    )));
                }
            }
            RuleCheck::OneOf { values } => {
                if let Some(v) = value
                    && !values.contains(&v)
                {
                    return Ok(Some(format!(
                        "{}: Field '{}' value '{}' must be one of: {}",
                        rule.name,
                        rule.field,
                        v,
                        values.join(", ")
                    )));
                }
            }
        }

        Ok(None)
    }

    fn get_field_value(&self, profile: &ConfigurationProfile, field: &str) -> Option<String> {
        let parts: Vec<&str> = field.split('.').collect();

        if parts.is_empty() {
            return None;
        }

        match parts[0] {
            "PayloadIdentifier" => Some(profile.payload_identifier.clone()),
            "PayloadDisplayName" => Some(profile.payload_display_name.clone()),
            "PayloadUUID" => Some(profile.payload_uuid.clone()),
            "PayloadType" => Some(profile.payload_type.clone()),
            "PayloadOrganization" => profile.payload_organization(),
            "PayloadDescription" => profile.payload_description(),
            "PayloadContent" => {
                if parts.len() < 2 {
                    return None;
                }
                let idx: usize = parts[1].parse().ok()?;
                let content = profile.payload_content.get(idx)?;

                if parts.len() == 2 {
                    return Some(format!("{content:?}"));
                }

                match parts[2] {
                    "PayloadType" => Some(content.payload_type.clone()),
                    "PayloadIdentifier" => Some(content.payload_identifier.clone()),
                    "PayloadUUID" => Some(content.payload_uuid.clone()),
                    key => content.content.get(key).map(|v| format!("{v:?}")),
                }
            }
            _ => profile
                .additional_fields
                .get(parts[0])
                .map(|v| format!("{v:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::PayloadContent;
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ========== Test Fixtures ==========

    fn create_test_profile() -> ConfigurationProfile {
        let mut additional_fields = HashMap::new();
        additional_fields.insert(
            "PayloadDescription".to_string(),
            plist::Value::String("A test profile".to_string()),
        );
        additional_fields.insert(
            "PayloadOrganization".to_string(),
            plist::Value::String("Test Org".to_string()),
        );

        let mut wifi_content = HashMap::new();
        wifi_content.insert(
            "PayloadDisplayName".to_string(),
            plist::Value::String("WiFi".to_string()),
        );

        ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "12345678-1234-1234-1234-123456789012".to_string(),
            payload_display_name: "Test Profile".to_string(),
            payload_content: vec![PayloadContent {
                payload_type: "com.apple.wifi.managed".to_string(),
                payload_version: 1,
                payload_identifier: "com.test.wifi".to_string(),
                payload_uuid: "87654321-4321-4321-4321-210987654321".to_string(),
                content: wifi_content,
            }],
            additional_fields,
        }
    }

    // ========== Default Rules Test ==========

    #[test]
    fn test_default_rules() {
        let rules = ValidationRules::default();
        assert!(rules.custom.is_empty());
        assert!(rules.profile.identifier_prefix.is_none());
        assert!(!rules.profile.required_organization);
        assert!(!rules.profile.required_description);
        assert!(rules.profile.display_name_pattern.is_none());
        assert!(rules.profile.max_payloads.is_none());
        assert!(rules.payload.allowed_types.is_empty());
        assert!(rules.payload.blocked_types.is_empty());
        assert!(rules.payload.unique_identifiers); // Default true
    }

    // ========== ProfileRules Tests ==========

    #[test]
    fn test_identifier_prefix_validation_pass() {
        let mut rules = ValidationRules::default();
        rules.profile.identifier_prefix = Some("com.test".to_string());

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_identifier_prefix_validation_fail() {
        let mut rules = ValidationRules::default();
        rules.profile.identifier_prefix = Some("com.example".to_string());

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("PayloadIdentifier"))
        );
    }

    #[test]
    fn test_required_organization_pass() {
        let mut rules = ValidationRules::default();
        rules.profile.required_organization = true;

        let profile = create_test_profile(); // Has organization
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_required_organization_fail() {
        let mut rules = ValidationRules::default();
        rules.profile.required_organization = true;

        let mut profile = create_test_profile();
        profile.set_payload_organization(None);

        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("PayloadOrganization"))
        );
    }

    #[test]
    fn test_required_description_pass() {
        let mut rules = ValidationRules::default();
        rules.profile.required_description = true;

        let profile = create_test_profile(); // Has description
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_required_description_fail() {
        let mut rules = ValidationRules::default();
        rules.profile.required_description = true;

        let mut profile = create_test_profile();
        profile.set_payload_description(None);

        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("PayloadDescription"))
        );
    }

    #[test]
    fn test_display_name_pattern_pass() {
        let mut rules = ValidationRules::default();
        rules.profile.display_name_pattern = Some(r"^Test.*$".to_string());

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_display_name_pattern_fail() {
        let mut rules = ValidationRules::default();
        rules.profile.display_name_pattern = Some(r"^Production.*$".to_string());

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("PayloadDisplayName"))
        );
    }

    #[test]
    fn test_display_name_pattern_invalid_regex() {
        let mut rules = ValidationRules::default();
        rules.profile.display_name_pattern = Some(r"[invalid".to_string());

        let profile = create_test_profile();
        let result = rules.validate(&profile);

        assert!(result.is_err()); // Invalid regex should error
    }

    #[test]
    fn test_max_payloads_pass() {
        let mut rules = ValidationRules::default();
        rules.profile.max_payloads = Some(5);

        let profile = create_test_profile(); // Has 1 payload
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_max_payloads_fail() {
        let mut rules = ValidationRules::default();
        rules.profile.max_payloads = Some(0);

        let profile = create_test_profile(); // Has 1 payload
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("payloads")));
    }

    #[test]
    fn test_max_payloads_exact_limit() {
        let mut rules = ValidationRules::default();
        rules.profile.max_payloads = Some(1);

        let profile = create_test_profile(); // Has exactly 1 payload
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    // ========== PayloadRules Tests ==========

    #[test]
    fn test_allowed_types_pass() {
        let mut rules = ValidationRules::default();
        rules.payload.allowed_types = vec!["com.apple.wifi.managed".to_string()];

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_allowed_types_fail() {
        let mut rules = ValidationRules::default();
        rules.payload.allowed_types = vec!["com.apple.vpn.managed".to_string()];

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("not in allowed list"))
        );
    }

    #[test]
    fn test_allowed_types_empty_means_all_allowed() {
        let rules = ValidationRules::default();

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_blocked_types_pass() {
        let mut rules = ValidationRules::default();
        rules.payload.blocked_types = vec!["com.apple.vpn.managed".to_string()];

        let profile = create_test_profile(); // Has wifi, not vpn
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_blocked_types_fail() {
        let mut rules = ValidationRules::default();
        rules.payload.blocked_types = vec!["com.apple.wifi.managed".to_string()];

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("blocked")));
    }

    #[test]
    fn test_unique_identifiers_pass() {
        let mut rules = ValidationRules::default();
        rules.payload.unique_identifiers = true;

        let profile = create_test_profile(); // Single payload, always unique
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_unique_identifiers_fail() {
        let mut rules = ValidationRules::default();
        rules.payload.unique_identifiers = true;

        let mut profile = create_test_profile();
        let duplicate = profile.payload_content[0].clone();
        profile.payload_content.push(duplicate);

        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("Duplicate")));
    }

    #[test]
    fn test_unique_identifiers_disabled() {
        let mut rules = ValidationRules::default();
        rules.payload.unique_identifiers = false;

        let mut profile = create_test_profile();
        let duplicate = profile.payload_content[0].clone();
        profile.payload_content.push(duplicate);

        let result = rules.validate(&profile).unwrap();

        assert!(result.valid); // Duplicates allowed when disabled
    }

    // ========== CustomRule Tests ==========

    #[test]
    fn test_custom_rule_exists_pass() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "require-identifier".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "PayloadIdentifier".to_string(),
            check: RuleCheck::Exists,
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_custom_rule_exists_fail() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "require-nonexistent".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "NonExistentField".to_string(),
            check: RuleCheck::Exists,
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("must exist")));
    }

    #[test]
    fn test_custom_rule_not_exists_pass() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "forbid-field".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "ForbiddenField".to_string(),
            check: RuleCheck::NotExists,
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_custom_rule_not_exists_fail() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "forbid-identifier".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "PayloadIdentifier".to_string(),
            check: RuleCheck::NotExists,
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("must not exist")));
    }

    #[test]
    fn test_custom_rule_equals_pass() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "check-type".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "PayloadType".to_string(),
            check: RuleCheck::Equals {
                value: "Configuration".to_string(),
            },
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_custom_rule_equals_fail() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "check-type".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "PayloadType".to_string(),
            check: RuleCheck::Equals {
                value: "Profile".to_string(),
            },
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("must equal")));
    }

    #[test]
    fn test_custom_rule_not_equals_pass() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "not-profile".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "PayloadType".to_string(),
            check: RuleCheck::NotEquals {
                value: "Profile".to_string(),
            },
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_custom_rule_not_equals_fail() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "not-configuration".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "PayloadType".to_string(),
            check: RuleCheck::NotEquals {
                value: "Configuration".to_string(),
            },
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("must not equal")));
    }

    #[test]
    fn test_custom_rule_pattern_pass() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "identifier-pattern".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "PayloadIdentifier".to_string(),
            check: RuleCheck::Pattern {
                pattern: r"^com\.test\..*$".to_string(),
            },
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_custom_rule_pattern_fail() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "identifier-pattern".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "PayloadIdentifier".to_string(),
            check: RuleCheck::Pattern {
                pattern: r"^org\.example\..*$".to_string(),
            },
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("does not match pattern"))
        );
    }

    #[test]
    fn test_custom_rule_one_of_pass() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "type-check".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "PayloadType".to_string(),
            check: RuleCheck::OneOf {
                values: vec!["Configuration".to_string(), "Profile".to_string()],
            },
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_custom_rule_one_of_fail() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "type-check".to_string(),
            description: None,
            severity: "error".to_string(),
            field: "PayloadType".to_string(),
            check: RuleCheck::OneOf {
                values: vec!["Profile".to_string(), "Settings".to_string()],
            },
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("must be one of")));
    }

    #[test]
    fn test_custom_rule_warning_severity() {
        let mut rules = ValidationRules::default();
        rules.custom.push(CustomRule {
            name: "soft-check".to_string(),
            description: None,
            severity: "warning".to_string(),
            field: "NonExistentField".to_string(),
            check: RuleCheck::Exists,
        });

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        // Warning doesn't affect validity
        assert!(result.valid);
        assert!(!result.warnings.is_empty());
    }

    // ========== Nested Field Access Tests ==========

    #[test]
    fn test_get_field_value_payload_content_type() {
        let rules = ValidationRules::default();
        let profile = create_test_profile();

        let value = rules.get_field_value(&profile, "PayloadContent.0.PayloadType");

        assert_eq!(value, Some("com.apple.wifi.managed".to_string()));
    }

    #[test]
    fn test_get_field_value_payload_content_identifier() {
        let rules = ValidationRules::default();
        let profile = create_test_profile();

        let value = rules.get_field_value(&profile, "PayloadContent.0.PayloadIdentifier");

        assert_eq!(value, Some("com.test.wifi".to_string()));
    }

    #[test]
    fn test_get_field_value_invalid_index() {
        let rules = ValidationRules::default();
        let profile = create_test_profile();

        let value = rules.get_field_value(&profile, "PayloadContent.99.PayloadType");

        assert!(value.is_none());
    }

    #[test]
    fn test_get_field_value_top_level_fields() {
        let rules = ValidationRules::default();
        let profile = create_test_profile();

        assert_eq!(
            rules.get_field_value(&profile, "PayloadIdentifier"),
            Some("com.test.profile".to_string())
        );
        assert_eq!(
            rules.get_field_value(&profile, "PayloadDisplayName"),
            Some("Test Profile".to_string())
        );
        assert_eq!(
            rules.get_field_value(&profile, "PayloadType"),
            Some("Configuration".to_string())
        );
    }

    #[test]
    fn test_get_field_value_optional_fields() {
        let rules = ValidationRules::default();
        let profile = create_test_profile();

        assert_eq!(
            rules.get_field_value(&profile, "PayloadOrganization"),
            Some("Test Org".to_string())
        );
        assert_eq!(
            rules.get_field_value(&profile, "PayloadDescription"),
            Some("A test profile".to_string())
        );
    }

    #[test]
    fn test_get_field_value_empty_path() {
        let rules = ValidationRules::default();
        let profile = create_test_profile();

        let value = rules.get_field_value(&profile, "");

        assert!(value.is_none());
    }

    // ========== CustomValidationResult Tests ==========

    #[test]
    fn test_validation_result_valid_when_no_errors() {
        let result = CustomValidationResult {
            valid: true,
            errors: vec![],
            warnings: vec!["Some warning".to_string()],
        };

        assert!(result.valid);
    }

    #[test]
    fn test_validation_result_invalid_when_errors() {
        let result = CustomValidationResult {
            valid: false,
            errors: vec!["An error".to_string()],
            warnings: vec![],
        };

        assert!(!result.valid);
    }

    // ========== TOML Loading Tests ==========

    #[test]
    fn test_validation_rules_load_from_file() {
        let toml_content = r#"
[profile]
identifier_prefix = "com.example"
required_organization = true

[payload]
blocked_types = ["com.apple.vpn.managed"]
unique_identifiers = true
"#;
        let mut file = NamedTempFile::with_suffix(".toml").unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let rules = ValidationRules::load(file.path()).unwrap();

        assert_eq!(
            rules.profile.identifier_prefix,
            Some("com.example".to_string())
        );
        assert!(rules.profile.required_organization);
        assert!(
            rules
                .payload
                .blocked_types
                .contains(&"com.apple.vpn.managed".to_string())
        );
    }

    #[test]
    fn test_validation_rules_load_with_custom_rules() {
        let toml_content = r#"
[[custom]]
name = "test-rule"
field = "PayloadIdentifier"
severity = "error"

[custom.check]
type = "pattern"
pattern = "^com\\.example\\..*$"
"#;
        let mut file = NamedTempFile::with_suffix(".toml").unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let rules = ValidationRules::load(file.path()).unwrap();

        assert_eq!(rules.custom.len(), 1);
        assert_eq!(rules.custom[0].name, "test-rule");
    }

    #[test]
    fn test_validation_rules_load_nonexistent_file() {
        let result = ValidationRules::load(Path::new("/nonexistent/file.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_rules_load_invalid_toml() {
        let mut file = NamedTempFile::with_suffix(".toml").unwrap();
        file.write_all(b"not valid toml [[[").unwrap();

        let result = ValidationRules::load(file.path());
        assert!(result.is_err());
    }

    // ========== Combined Rules Tests ==========

    #[test]
    fn test_multiple_rules_combined() {
        let mut rules = ValidationRules::default();
        rules.profile.identifier_prefix = Some("com.test".to_string());
        rules.profile.required_organization = true;
        rules.payload.allowed_types = vec!["com.apple.wifi.managed".to_string()];

        let profile = create_test_profile();
        let result = rules.validate(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_multiple_errors_accumulate() {
        let mut rules = ValidationRules::default();
        rules.profile.identifier_prefix = Some("org.example".to_string());
        rules.profile.required_organization = true;
        rules.profile.required_description = true;

        let mut profile = create_test_profile();
        profile.set_payload_organization(None);
        profile.set_payload_description(None);

        let result = rules.validate(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.len() >= 3);
    }
}
