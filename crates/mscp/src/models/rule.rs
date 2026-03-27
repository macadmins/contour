use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents an mSCP rule YAML file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MscpRule {
    /// Rule identifier (e.g., "`audit_acls_files_configure`")
    pub id: String,

    /// Human-readable title
    pub title: String,

    /// Discussion/description of the rule
    #[serde(default)]
    pub discussion: String,

    /// Check script (bash code)
    #[serde(default)]
    pub check: Option<String>,

    /// Expected result of check script
    #[serde(default)]
    pub result: Option<yaml_serde::Value>,

    /// Fix script (bash code or instructions)
    #[serde(default)]
    pub fix: Option<String>,

    /// References (CCE, CCI, 800-53, etc.)
    #[serde(default)]
    pub references: HashMap<String, yaml_serde::Value>,

    /// macOS versions supported
    #[serde(rename = "macOS", default)]
    pub macos: Vec<String>,

    /// Tags (baseline membership)
    #[serde(default)]
    pub tags: Vec<String>,

    /// Severity level
    #[serde(default)]
    pub severity: Option<String>,

    /// Whether this rule is implemented via mobileconfig
    #[serde(default)]
    pub mobileconfig: bool,

    /// mobileconfig information
    #[serde(default)]
    pub mobileconfig_info: Option<yaml_serde::Value>,

    /// ODV (Organization Defined Values)
    #[serde(default)]
    pub odv: Option<yaml_serde::Value>,
}

impl MscpRule {
    /// Check if this rule has both check and fix scripts (eligible for Munki nopkg)
    pub fn has_script_remediation(&self) -> bool {
        self.check.is_some() && self.fix.is_some() && !self.mobileconfig
    }

    /// Check if this rule belongs to a specific baseline
    pub fn is_in_baseline(&self, baseline: &str) -> bool {
        self.tags.iter().any(|tag| tag == baseline)
    }

    /// Get the check script cleaned up for embedding
    pub fn get_check_script(&self) -> Option<String> {
        self.check.as_ref().map(|s| s.trim().to_string())
    }

    /// Get the fix script cleaned up for embedding
    /// Removes `AsciiDoc` formatting (e.g., [source,bash] and ----)
    pub fn get_fix_script(&self) -> Option<String> {
        self.fix.as_ref().map(|s| {
            let mut lines: Vec<&str> = s.lines().collect();

            // Remove AsciiDoc markup
            // Pattern: [source,bash]\n----\nSCRIPT\n----
            if lines.len() > 2 {
                // Check for [source,bash] or similar
                if lines[0].starts_with('[') && lines[0].contains("source") {
                    lines.remove(0);
                }
                // Check for leading ----
                if !lines.is_empty() && lines[0].trim() == "----" {
                    lines.remove(0);
                }
                // Check for trailing ----
                if !lines.is_empty() && lines[lines.len() - 1].trim() == "----" {
                    lines.pop();
                }
            }

            lines.join("\n").trim().to_string()
        })
    }

    /// Check if fix is actually a script (not just instructions)
    pub fn has_executable_fix(&self) -> bool {
        if let Some(fix) = &self.fix {
            // Check if it contains shell commands
            !fix.to_lowercase()
                .contains("this is implemented by a configuration profile")
                && (fix.contains("/usr/bin/")
                    || fix.contains("/usr/sbin/")
                    || fix.contains("/usr/local/")
                    || fix.contains("/bin/")
                    || fix.contains("/sbin/")
                    || fix.contains("/System/")
                    || fix.contains("sudo"))
        } else {
            false
        }
    }

    /// Get expected result value for installcheck script.
    ///
    /// Handles all result shapes: `{ integer: 0 }`, `{ string: "foo" }`,
    /// `{ boolean: true }`, `{ base64: "..." }`, bare scalars, and `$ODV` placeholders.
    pub fn get_expected_result(&self) -> Option<String> {
        let value = self.result.as_ref()?;
        match value {
            // Mapping: { integer: 0 }, { string: "foo" }, { boolean: true }, { base64: "..." }
            yaml_serde::Value::Mapping(map) => {
                let v = map.values().next()?;
                match v {
                    yaml_serde::Value::Bool(b) => Some(b.to_string()),
                    yaml_serde::Value::Number(n) => Some(n.to_string()),
                    yaml_serde::Value::String(s) => Some(s.clone()),
                    yaml_serde::Value::Null => None,
                    _ => Some(format!("{v:?}")),
                }
            }
            // Bare scalar: result: '' or result: 42
            yaml_serde::Value::String(s) if s.is_empty() => None,
            yaml_serde::Value::String(s) => Some(s.clone()),
            yaml_serde::Value::Number(n) => Some(n.to_string()),
            yaml_serde::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    /// Get the result type key (e.g., "integer", "string", "boolean", "base64").
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn get_result_type(&self) -> Option<String> {
        let value = self.result.as_ref()?;
        if let yaml_serde::Value::Mapping(map) = value {
            map.keys().next().and_then(|k| k.as_str()).map(String::from)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_script_remediation() {
        let rule = MscpRule {
            id: "test_rule".to_string(),
            title: "Test".to_string(),
            discussion: String::new(),
            check: Some("echo test".to_string()),
            result: None,
            fix: Some("echo fix".to_string()),
            references: HashMap::new(),
            macos: vec![],
            tags: vec![],
            severity: None,
            mobileconfig: false,
            mobileconfig_info: None,
            odv: None,
        };

        assert!(rule.has_script_remediation());
    }

    #[test]
    fn test_clean_fix_script() {
        let rule = MscpRule {
            id: "test".to_string(),
            title: "Test".to_string(),
            discussion: String::new(),
            check: None,
            result: None,
            fix: Some("[source,bash]\n----\n/bin/chmod -RN /var/audit\n----".to_string()),
            references: HashMap::new(),
            macos: vec![],
            tags: vec![],
            severity: None,
            mobileconfig: false,
            mobileconfig_info: None,
            odv: None,
        };

        let cleaned = rule.get_fix_script().unwrap();
        assert_eq!(cleaned, "/bin/chmod -RN /var/audit");
    }

    /// Helper to build a result mapping like `{ integer: 0 }`
    fn result_mapping(key: &str, val: yaml_serde::Value) -> Option<yaml_serde::Value> {
        let mut map = yaml_serde::Mapping::new();
        map.insert(yaml_serde::Value::String(key.to_string()), val);
        Some(yaml_serde::Value::Mapping(map))
    }

    #[test]
    fn test_result_integer() {
        let rule = MscpRule {
            id: "t".into(),
            title: "T".into(),
            discussion: String::new(),
            check: None,
            fix: None,
            result: result_mapping("integer", yaml_serde::Value::Number(0.into())),
            references: HashMap::new(),
            macos: vec![],
            tags: vec![],
            severity: None,
            mobileconfig: false,
            mobileconfig_info: None,
            odv: None,
        };
        assert_eq!(rule.get_expected_result(), Some("0".to_string()));
        assert_eq!(rule.get_result_type(), Some("integer".to_string()));
    }

    #[test]
    fn test_result_boolean_true() {
        let rule = MscpRule {
            id: "t".into(),
            title: "T".into(),
            discussion: String::new(),
            check: None,
            fix: None,
            result: result_mapping("boolean", yaml_serde::Value::Bool(true)),
            references: HashMap::new(),
            macos: vec![],
            tags: vec![],
            severity: None,
            mobileconfig: false,
            mobileconfig_info: None,
            odv: None,
        };
        assert_eq!(rule.get_expected_result(), Some("true".to_string()));
    }

    /// Tahoe pattern: `boolean: 0` (YAML integer in boolean field)
    #[test]
    fn test_result_boolean_as_integer() {
        let rule = MscpRule {
            id: "t".into(),
            title: "T".into(),
            discussion: String::new(),
            check: None,
            fix: None,
            result: result_mapping("boolean", yaml_serde::Value::Number(0.into())),
            references: HashMap::new(),
            macos: vec![],
            tags: vec![],
            severity: None,
            mobileconfig: false,
            mobileconfig_info: None,
            odv: None,
        };
        assert_eq!(rule.get_expected_result(), Some("0".to_string()));
    }

    /// Tahoe pattern: `integer: $ODV` (string placeholder in integer field)
    #[test]
    fn test_result_odv_placeholder() {
        let rule = MscpRule {
            id: "t".into(),
            title: "T".into(),
            discussion: String::new(),
            check: None,
            fix: None,
            result: result_mapping("integer", yaml_serde::Value::String("$ODV".to_string())),
            references: HashMap::new(),
            macos: vec![],
            tags: vec![],
            severity: None,
            mobileconfig: false,
            mobileconfig_info: None,
            odv: None,
        };
        assert_eq!(rule.get_expected_result(), Some("$ODV".to_string()));
        assert_eq!(rule.get_result_type(), Some("integer".to_string()));
    }

    /// Tahoe pattern: `base64: $ODV` (new variant)
    #[test]
    fn test_result_base64_odv() {
        let rule = MscpRule {
            id: "t".into(),
            title: "T".into(),
            discussion: String::new(),
            check: None,
            fix: None,
            result: result_mapping("base64", yaml_serde::Value::String("$ODV".to_string())),
            references: HashMap::new(),
            macos: vec![],
            tags: vec![],
            severity: None,
            mobileconfig: false,
            mobileconfig_info: None,
            odv: None,
        };
        assert_eq!(rule.get_expected_result(), Some("$ODV".to_string()));
        assert_eq!(rule.get_result_type(), Some("base64".to_string()));
    }

    /// Tahoe pattern: `result: ''` (bare empty string)
    #[test]
    fn test_result_bare_empty_string() {
        let rule = MscpRule {
            id: "t".into(),
            title: "T".into(),
            discussion: String::new(),
            check: None,
            fix: None,
            result: Some(yaml_serde::Value::String(String::new())),
            references: HashMap::new(),
            macos: vec![],
            tags: vec![],
            severity: None,
            mobileconfig: false,
            mobileconfig_info: None,
            odv: None,
        };
        assert_eq!(rule.get_expected_result(), None);
        assert_eq!(rule.get_result_type(), None);
    }

    /// Roundtrip: parse YAML with all four Tahoe patterns
    #[test]
    fn test_deserialize_tahoe_patterns() {
        let yaml = r#"
id: test_bool_int
title: Test
discussion: ""
check: "echo 0"
result:
  boolean: 0
tags: []
"#;
        let rule: MscpRule = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(rule.get_expected_result(), Some("0".to_string()));

        let yaml = r#"
id: test_int_odv
title: Test
discussion: ""
check: "echo 900"
result:
  integer: $ODV
tags: []
"#;
        let rule: MscpRule = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(rule.get_expected_result(), Some("$ODV".to_string()));

        let yaml = r#"
id: test_base64_odv
title: Test
discussion: ""
check: "echo test"
result:
  base64: $ODV
tags: []
"#;
        let rule: MscpRule = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(rule.get_expected_result(), Some("$ODV".to_string()));
        assert_eq!(rule.get_result_type(), Some("base64".to_string()));

        let yaml = r#"
id: test_bare_empty
title: Test
discussion: ""
check: "echo test"
result: ''
tags: []
"#;
        let rule: MscpRule = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(rule.get_expected_result(), None);
    }
}
