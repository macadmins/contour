//! File Access Authorization (FAA) policy generation.
//!
//! Loads FAA policies from YAML and generates Apple plist files
//! conforming to Santa's WatchItems schema (spec section 5.4.4).

pub mod schema;

use anyhow::{Context, Result};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single FAA policy loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaaPolicy {
    /// Policy name (becomes the WatchItems dictionary key).
    pub name: String,
    /// Optional policy version string.
    #[serde(default)]
    pub version: Option<String>,
    /// Paths to watch (at least one required).
    pub paths: Vec<FaaPath>,
    /// Rule type governing how processes and paths interact.
    pub rule_type: FaaRuleType,
    /// Options controlling behavior (audit, silent, messages, etc.).
    #[serde(default)]
    pub options: FaaOptions,
    /// Process identity specifications.
    #[serde(default)]
    pub processes: Vec<ProcessIdentity>,
}

/// A path entry in an FAA policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaaPath {
    /// Absolute path to watch.
    pub path: String,
    /// Whether this path is a prefix match.
    #[serde(default)]
    pub is_prefix: bool,
}

/// FAA rule type enum matching Santa's plist schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaaRuleType {
    /// Only listed processes may access these paths.
    PathsWithAllowedProcesses,
    /// Listed processes are denied access to these paths.
    PathsWithDeniedProcesses,
    /// Listed processes may only access these paths.
    ProcessesWithAllowedPaths,
    /// Listed processes are denied access to these paths.
    ProcessesWithDeniedPaths,
}

impl FaaRuleType {
    /// Returns the plist string value for this rule type.
    fn plist_value(self) -> &'static str {
        match self {
            Self::PathsWithAllowedProcesses => "PathsWithAllowedProcesses",
            Self::PathsWithDeniedProcesses => "PathsWithDeniedProcesses",
            Self::ProcessesWithAllowedPaths => "ProcessesWithAllowedPaths",
            Self::ProcessesWithDeniedPaths => "ProcessesWithDeniedPaths",
        }
    }
}

/// Options for an FAA watch item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaaOptions {
    /// Whether to allow read access (default: false).
    #[serde(default)]
    pub allow_read_access: bool,
    /// Whether to only audit (log) without blocking (default: true).
    #[serde(default = "default_true")]
    pub audit_only: bool,
    /// Whether to suppress notification dialogs (default: false).
    #[serde(default)]
    pub silent: bool,
    /// Whether to suppress TTY messages (default: false).
    #[serde(default)]
    pub silent_tty: bool,
    /// Custom message shown in the block dialog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_message: Option<String>,
    /// URL for the "More Info" button in the block dialog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_detail_url: Option<String>,
    /// Label text for the "More Info" button.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_detail_text: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for FaaOptions {
    fn default() -> Self {
        Self {
            allow_read_access: false,
            audit_only: true,
            silent: false,
            silent_tty: false,
            block_message: None,
            event_detail_url: None,
            event_detail_text: None,
        }
    }
}

/// Process identity specification for FAA policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessIdentity {
    /// 10-character Apple Team ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Code signing identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    /// Whether this is an Apple platform binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_binary: Option<bool>,
    /// CDHash (40 hex characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdhash: Option<String>,
    /// SHA-256 of the signing certificate (64 hex characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha256: Option<String>,
    /// Absolute path to the binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
}

impl ProcessIdentity {
    /// Returns `true` if at least one identity field is set.
    pub fn has_identity(&self) -> bool {
        self.team_id.is_some()
            || self.signing_id.is_some()
            || self.platform_binary.is_some()
            || self.cdhash.is_some()
            || self.certificate_sha256.is_some()
            || self.binary_path.is_some()
    }
}

/// Top-level FAA policy file loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaaPolicyFile {
    /// Optional schema version.
    #[serde(default)]
    pub version: Option<String>,
    /// List of FAA policies.
    pub faa_policies: Vec<FaaPolicy>,
}

/// Validation error for FAA policies.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Policy name where the error occurred.
    pub policy: String,
    /// Description of the error.
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.policy, self.message)
    }
}

/// Validate an FAA policy file and return all errors found.
pub fn validate(policy_file: &FaaPolicyFile) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    for policy in &policy_file.faa_policies {
        // Paths must be non-empty and absolute.
        if policy.paths.is_empty() {
            errors.push(ValidationError {
                policy: policy.name.clone(),
                message: "Policy must have at least one path".to_string(),
            });
        }
        for faa_path in &policy.paths {
            if !faa_path.path.starts_with('/') {
                errors.push(ValidationError {
                    policy: policy.name.clone(),
                    message: format!("Path must be absolute: '{}'", faa_path.path),
                });
            }
        }

        // For path-centric rule types, processes are required.
        let needs_processes = matches!(
            policy.rule_type,
            FaaRuleType::PathsWithAllowedProcesses | FaaRuleType::PathsWithDeniedProcesses
        );
        if needs_processes && policy.processes.is_empty() {
            errors.push(ValidationError {
                policy: policy.name.clone(),
                message: format!(
                    "Rule type '{}' requires at least one process",
                    policy.rule_type.plist_value()
                ),
            });
        }

        // For process-centric rule types, processes are also required.
        let needs_processes_too = matches!(
            policy.rule_type,
            FaaRuleType::ProcessesWithAllowedPaths | FaaRuleType::ProcessesWithDeniedPaths
        );
        if needs_processes_too && policy.processes.is_empty() {
            errors.push(ValidationError {
                policy: policy.name.clone(),
                message: format!(
                    "Rule type '{}' requires at least one process",
                    policy.rule_type.plist_value()
                ),
            });
        }

        // Each process must have at least one identity field.
        for (i, proc) in policy.processes.iter().enumerate() {
            if !proc.has_identity() {
                errors.push(ValidationError {
                    policy: policy.name.clone(),
                    message: format!(
                        "Process #{} has no identity fields (need at least one of: team_id, signing_id, platform_binary, cdhash, certificate_sha256, binary_path)",
                        i + 1
                    ),
                });
            }
            // binary_path must be absolute if present.
            if let Some(ref bp) = proc.binary_path {
                if !bp.starts_with('/') {
                    errors.push(ValidationError {
                        policy: policy.name.clone(),
                        message: format!("Process #{} binary_path must be absolute: '{bp}'", i + 1),
                    });
                }
            }
        }
    }

    errors
}

/// Generate Apple plist XML bytes from FAA policies.
///
/// Produces the WatchItems dictionary structure per spec section 5.4.4.
pub fn generate_plist(policies: &FaaPolicyFile) -> Result<Vec<u8>> {
    let mut root = Dictionary::new();

    // Top-level Version.
    let version = policies.version.as_deref().unwrap_or("1.0");
    root.insert("Version".to_string(), Value::String(version.to_string()));

    // WatchItems dictionary: one entry per policy, keyed by name.
    let mut watch_items = Dictionary::new();
    for policy in &policies.faa_policies {
        let item = build_watch_item(policy)?;
        watch_items.insert(policy.name.clone(), Value::Dictionary(item));
    }
    root.insert("WatchItems".to_string(), Value::Dictionary(watch_items));

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &Value::Dictionary(root))
        .context("Failed to serialize FAA plist")?;
    Ok(buf)
}

/// Build a single WatchItem dictionary for one FAA policy.
fn build_watch_item(policy: &FaaPolicy) -> Result<Dictionary> {
    let mut item = Dictionary::new();

    // Paths array.
    let paths: Vec<Value> = policy
        .paths
        .iter()
        .map(|p| {
            let mut d = Dictionary::new();
            d.insert("Path".to_string(), Value::String(p.path.clone()));
            if p.is_prefix {
                d.insert("IsPrefix".to_string(), Value::Boolean(true));
            }
            Value::Dictionary(d)
        })
        .collect();
    item.insert("Paths".to_string(), Value::Array(paths));

    // Options dictionary.
    let mut options = Dictionary::new();
    options.insert(
        "RuleType".to_string(),
        Value::String(policy.rule_type.plist_value().to_string()),
    );
    options.insert(
        "AllowReadAccess".to_string(),
        Value::Boolean(policy.options.allow_read_access),
    );
    options.insert(
        "AuditOnly".to_string(),
        Value::Boolean(policy.options.audit_only),
    );

    if policy.options.silent {
        options.insert("EnableSilentMode".to_string(), Value::Boolean(true));
    }
    if policy.options.silent_tty {
        options.insert("EnableSilentTTYMode".to_string(), Value::Boolean(true));
    }
    if let Some(ref msg) = policy.options.block_message {
        options.insert("BlockMessage".to_string(), Value::String(msg.clone()));
    }
    if let Some(ref url) = policy.options.event_detail_url {
        options.insert("EventDetailURL".to_string(), Value::String(url.clone()));
    }
    if let Some(ref text) = policy.options.event_detail_text {
        options.insert("EventDetailText".to_string(), Value::String(text.clone()));
    }

    // Version if present on this policy.
    if let Some(ref ver) = policy.version {
        options.insert("Version".to_string(), Value::String(ver.clone()));
    }

    item.insert("Options".to_string(), Value::Dictionary(options));

    // Processes array.
    if !policy.processes.is_empty() {
        let processes: Vec<Value> = policy
            .processes
            .iter()
            .map(|p| {
                let mut d = Dictionary::new();
                if let Some(ref v) = p.team_id {
                    d.insert("TeamID".to_string(), Value::String(v.clone()));
                }
                if let Some(ref v) = p.signing_id {
                    d.insert("SigningID".to_string(), Value::String(v.clone()));
                }
                if let Some(v) = p.platform_binary {
                    d.insert("PlatformBinary".to_string(), Value::Boolean(v));
                }
                if let Some(ref v) = p.cdhash {
                    d.insert("CDHash".to_string(), Value::String(v.clone()));
                }
                if let Some(ref v) = p.certificate_sha256 {
                    d.insert("CertificateSha256".to_string(), Value::String(v.clone()));
                }
                if let Some(ref v) = p.binary_path {
                    d.insert("BinaryPath".to_string(), Value::String(v.clone()));
                }
                Value::Dictionary(d)
            })
            .collect();
        item.insert("Processes".to_string(), Value::Array(processes));
    }

    Ok(item)
}

/// Load FAA policies from a YAML or TOML file (auto-detected by extension).
pub fn load_policy_file(path: &Path) -> Result<FaaPolicyFile> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read FAA policy file: {}", path.display()))?;

    match path.extension().and_then(|e| e.to_str()) {
        Some("toml") => toml::from_str(&content)
            .with_context(|| format!("Failed to parse FAA policy TOML: {}", path.display())),
        Some("yaml" | "yml") => yaml_serde::from_str(&content)
            .with_context(|| format!("Failed to parse FAA policy YAML: {}", path.display())),
        _ => {
            // Try TOML first (more strict parser), fall back to YAML
            toml::from_str(&content).or_else(|_| {
                yaml_serde::from_str(&content)
                    .with_context(|| format!("Failed to parse FAA policy file: {}", path.display()))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy_file() -> FaaPolicyFile {
        FaaPolicyFile {
            version: Some("1.0".to_string()),
            faa_policies: vec![FaaPolicy {
                name: "protect-launch-agents".to_string(),
                version: Some("v1.0".to_string()),
                paths: vec![
                    FaaPath {
                        path: "/Library/LaunchAgents".to_string(),
                        is_prefix: true,
                    },
                    FaaPath {
                        path: "/Library/LaunchDaemons".to_string(),
                        is_prefix: true,
                    },
                ],
                rule_type: FaaRuleType::PathsWithAllowedProcesses,
                options: FaaOptions {
                    allow_read_access: false,
                    audit_only: true,
                    ..Default::default()
                },
                processes: vec![
                    ProcessIdentity {
                        team_id: Some("EQHXZ8M8AV".to_string()),
                        signing_id: Some("com.google.Chrome".to_string()),
                        platform_binary: None,
                        cdhash: None,
                        certificate_sha256: None,
                        binary_path: None,
                    },
                    ProcessIdentity {
                        team_id: None,
                        signing_id: None,
                        platform_binary: None,
                        cdhash: None,
                        certificate_sha256: None,
                        binary_path: Some("/usr/bin/cat".to_string()),
                    },
                ],
            }],
        }
    }

    #[test]
    fn test_generate_plist_structure() {
        let policy_file = sample_policy_file();
        let plist_bytes = generate_plist(&policy_file).unwrap();
        let plist_str = String::from_utf8(plist_bytes).unwrap();

        // Should contain the XML plist header.
        assert!(plist_str.contains("<?xml version=\"1.0\""));
        assert!(plist_str.contains("<!DOCTYPE plist"));

        // Should contain WatchItems key.
        assert!(plist_str.contains("<key>WatchItems</key>"));

        // Should contain the policy name as a key.
        assert!(plist_str.contains("<key>protect-launch-agents</key>"));

        // Should contain paths.
        assert!(plist_str.contains("<key>Path</key>"));
        assert!(plist_str.contains("/Library/LaunchAgents"));

        // Should contain IsPrefix.
        assert!(plist_str.contains("<key>IsPrefix</key>"));

        // Should contain the rule type.
        assert!(plist_str.contains("PathsWithAllowedProcesses"));

        // Should contain process identities.
        assert!(plist_str.contains("<key>TeamID</key>"));
        assert!(plist_str.contains("EQHXZ8M8AV"));
        assert!(plist_str.contains("<key>BinaryPath</key>"));
        assert!(plist_str.contains("/usr/bin/cat"));
    }

    #[test]
    fn test_yaml_roundtrip() {
        let policy_file = sample_policy_file();
        let yaml = yaml_serde::to_string(&policy_file).unwrap();
        let parsed: FaaPolicyFile = yaml_serde::from_str(&yaml).unwrap();

        assert_eq!(parsed.faa_policies.len(), 1);
        assert_eq!(parsed.faa_policies[0].name, "protect-launch-agents");
        assert_eq!(parsed.faa_policies[0].paths.len(), 2);
        assert_eq!(parsed.faa_policies[0].processes.len(), 2);
    }

    #[test]
    fn test_validate_missing_paths() {
        let policy_file = FaaPolicyFile {
            version: None,
            faa_policies: vec![FaaPolicy {
                name: "bad-policy".to_string(),
                version: None,
                paths: vec![],
                rule_type: FaaRuleType::PathsWithAllowedProcesses,
                options: FaaOptions::default(),
                processes: vec![ProcessIdentity {
                    team_id: Some("ABCDEF1234".to_string()),
                    signing_id: None,
                    platform_binary: None,
                    cdhash: None,
                    certificate_sha256: None,
                    binary_path: None,
                }],
            }],
        };

        let errors = validate(&policy_file);
        assert!(!errors.is_empty());
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("at least one path"))
        );
    }

    #[test]
    fn test_validate_non_absolute_path() {
        let policy_file = FaaPolicyFile {
            version: None,
            faa_policies: vec![FaaPolicy {
                name: "bad-paths".to_string(),
                version: None,
                paths: vec![FaaPath {
                    path: "relative/path".to_string(),
                    is_prefix: false,
                }],
                rule_type: FaaRuleType::ProcessesWithDeniedPaths,
                options: FaaOptions::default(),
                processes: vec![ProcessIdentity {
                    team_id: Some("ABCDEF1234".to_string()),
                    signing_id: None,
                    platform_binary: None,
                    cdhash: None,
                    certificate_sha256: None,
                    binary_path: None,
                }],
            }],
        };

        let errors = validate(&policy_file);
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("must be absolute"))
        );
    }

    #[test]
    fn test_validate_missing_process_identity() {
        let policy_file = FaaPolicyFile {
            version: None,
            faa_policies: vec![FaaPolicy {
                name: "no-identity".to_string(),
                version: None,
                paths: vec![FaaPath {
                    path: "/tmp/test".to_string(),
                    is_prefix: false,
                }],
                rule_type: FaaRuleType::PathsWithAllowedProcesses,
                options: FaaOptions::default(),
                processes: vec![ProcessIdentity {
                    team_id: None,
                    signing_id: None,
                    platform_binary: None,
                    cdhash: None,
                    certificate_sha256: None,
                    binary_path: None,
                }],
            }],
        };

        let errors = validate(&policy_file);
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("no identity fields"))
        );
    }

    #[test]
    fn test_validate_missing_processes_for_rule_type() {
        let policy_file = FaaPolicyFile {
            version: None,
            faa_policies: vec![FaaPolicy {
                name: "no-procs".to_string(),
                version: None,
                paths: vec![FaaPath {
                    path: "/tmp/test".to_string(),
                    is_prefix: false,
                }],
                rule_type: FaaRuleType::PathsWithAllowedProcesses,
                options: FaaOptions::default(),
                processes: vec![],
            }],
        };

        let errors = validate(&policy_file);
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("requires at least one process"))
        );
    }

    #[test]
    fn test_validate_valid_policy() {
        let policy_file = sample_policy_file();
        let errors = validate(&policy_file);
        assert!(errors.is_empty(), "Expected no errors, got: {errors:?}");
    }

    #[test]
    fn test_plist_version_defaults_to_1_0() {
        let policy_file = FaaPolicyFile {
            version: None,
            faa_policies: vec![],
        };
        let plist_bytes = generate_plist(&policy_file).unwrap();
        let plist_str = String::from_utf8(plist_bytes).unwrap();
        assert!(plist_str.contains("1.0"));
    }
}
