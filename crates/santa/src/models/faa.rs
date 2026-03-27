//! File Access Authorization (FAA) policy types for Santa.
//!
//! FAA allows defining file access rules based on processes and paths.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// FAA watch item rule type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum FAAWatchItemRuleType {
    /// Allow only specified processes to access the paths
    #[default]
    PathsWithAllowedProcesses,
    /// Block specified processes from accessing the paths
    PathsWithDeniedProcesses,
    /// Allow specified processes to access only the listed paths
    ProcessesWithAllowedPaths,
    /// Block specified processes from accessing the listed paths
    ProcessesWithDeniedPaths,
}

/// Path pattern for FAA watching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPattern {
    /// The path to watch
    pub path: String,
    /// Whether this is a prefix match
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_prefix: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

impl PathPattern {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            is_prefix: false,
        }
    }

    pub fn prefix(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            is_prefix: true,
        }
    }
}

/// Process matching criteria for FAA
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessMatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_binary: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdhash: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_sha256: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
}

impl ProcessMatch {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_signing_id(mut self, id: impl Into<String>) -> Self {
        self.signing_id = Some(id.into());
        self
    }

    #[must_use]
    pub fn with_team_id(mut self, id: impl Into<String>) -> Self {
        self.team_id = Some(id.into());
        self
    }

    #[must_use]
    pub fn platform_binary(mut self) -> Self {
        self.platform_binary = Some(true);
        self
    }

    #[must_use]
    pub fn with_binary_path(mut self, path: impl Into<String>) -> Self {
        self.binary_path = Some(path.into());
        self
    }
}

/// Options for an FAA watch item
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchItemOptions {
    pub rule_type: FAAWatchItemRuleType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_read_access: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_only: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_silent_mode: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_silent_tty_mode: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_detail_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_detail_text: Option<String>,
}

/// A single watch item in an FAA policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchItem {
    pub paths: Vec<PathPattern>,
    pub processes: Vec<ProcessMatch>,
    pub options: WatchItemOptions,
}

impl WatchItem {
    pub fn new(rule_type: FAAWatchItemRuleType) -> Self {
        Self {
            paths: Vec::new(),
            processes: Vec::new(),
            options: WatchItemOptions {
                rule_type,
                ..Default::default()
            },
        }
    }

    pub fn add_path(&mut self, path: PathPattern) {
        self.paths.push(path);
    }

    pub fn add_process(&mut self, process: ProcessMatch) {
        self.processes.push(process);
    }
}

/// Complete FAA policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FAAPolicy {
    pub version: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_detail_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_detail_text: Option<String>,

    pub watch_items: HashMap<String, WatchItem>,

    /// Rings this FAA policy belongs to (empty = all rings)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rings: Vec<String>,
}

impl FAAPolicy {
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            event_detail_url: None,
            event_detail_text: None,
            watch_items: HashMap::new(),
            rings: Vec::new(),
        }
    }

    pub fn add_watch_item(&mut self, name: impl Into<String>, item: WatchItem) {
        self.watch_items.insert(name.into(), item);
    }

    /// Check if this policy is in a specific ring
    pub fn is_in_ring(&self, ring: &str) -> bool {
        self.rings.is_empty() || self.rings.iter().any(|r| r == ring)
    }
}

/// Collection of FAA policies
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FAAPolicySet {
    pub policies: Vec<FAAPolicy>,
}

impl FAAPolicySet {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn add(&mut self, policy: FAAPolicy) {
        self.policies.push(policy);
    }

    pub fn len(&self) -> usize {
        self.policies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Filter policies by ring
    pub fn by_ring(&self, ring: &str) -> FAAPolicySet {
        FAAPolicySet {
            policies: self
                .policies
                .iter()
                .filter(|p| p.is_in_ring(ring))
                .cloned()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_faa_policy_creation() {
        let mut policy = FAAPolicy::new("1");

        let mut watch_item = WatchItem::new(FAAWatchItemRuleType::PathsWithAllowedProcesses);
        watch_item.add_path(PathPattern::prefix("/Users/Shared"));
        watch_item.add_process(ProcessMatch::new().with_team_id("EQHXZ8M8AV"));

        policy.add_watch_item("shared-folder-access", watch_item);

        assert_eq!(policy.watch_items.len(), 1);
        assert!(policy.watch_items.contains_key("shared-folder-access"));
    }

    #[test]
    fn test_faa_policy_serialization() {
        let mut policy = FAAPolicy::new("1");

        let mut watch_item = WatchItem::new(FAAWatchItemRuleType::PathsWithDeniedProcesses);
        watch_item.add_path(PathPattern::new("/etc/passwd"));

        policy.add_watch_item("protect-passwd", watch_item);

        let yaml = yaml_serde::to_string(&policy).unwrap();
        assert!(yaml.contains("version:"));
        assert!(yaml.contains("watch_items:"));
    }

    #[test]
    fn test_process_match_builder() {
        let process = ProcessMatch::new()
            .with_team_id("EQHXZ8M8AV")
            .with_signing_id("EQHXZ8M8AV:com.google.Chrome");

        assert_eq!(process.team_id, Some("EQHXZ8M8AV".to_string()));
        assert_eq!(
            process.signing_id,
            Some("EQHXZ8M8AV:com.google.Chrome".to_string())
        );
    }
}
