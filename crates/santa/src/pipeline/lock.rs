//! Lock file for GitOps reproducibility.
//!
//! Tracks the state of generated rules to ensure deterministic
//! builds and append-only changes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A lock file tracking generated rule state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineLock {
    /// Version of the lock file format.
    pub version: u32,
    /// When this lock was last updated.
    pub updated_at: DateTime<Utc>,
    /// SHA-256 of the input CSV.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    /// SHA-256 of the bundles.toml.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundles_hash: Option<String>,
    /// Generated rules by identifier.
    pub rules: HashMap<String, LockEntry>,
}

impl PipelineLock {
    /// Current lock file format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new empty lock.
    pub fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            updated_at: Utc::now(),
            input_hash: None,
            bundles_hash: None,
            rules: HashMap::new(),
        }
    }

    /// Add or update a rule entry.
    pub fn add_rule(&mut self, key: String, entry: LockEntry) {
        self.rules.insert(key, entry);
        self.updated_at = Utc::now();
    }

    /// Check if a rule exists in the lock.
    pub fn has_rule(&self, key: &str) -> bool {
        self.rules.contains_key(key)
    }

    /// Get a rule entry.
    pub fn get_rule(&self, key: &str) -> Option<&LockEntry> {
        self.rules.get(key)
    }

    /// Number of rules in the lock.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if lock is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Load lock from a YAML file.
    pub fn from_yaml_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read lock file: {}", e))?;
        Self::from_yaml(&content)
    }

    /// Parse lock from YAML string.
    pub fn from_yaml(content: &str) -> anyhow::Result<Self> {
        yaml_serde::from_str(content)
            .map_err(|e| anyhow::anyhow!("Failed to parse lock file: {}", e))
    }

    /// Serialize lock to YAML string.
    pub fn to_yaml(&self) -> anyhow::Result<String> {
        yaml_serde::to_string(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize lock file: {}", e))
    }

    /// Write lock to a YAML file.
    pub fn to_yaml_file(&self, path: &Path) -> anyhow::Result<()> {
        let content = self.to_yaml()?;
        std::fs::write(path, content)
            .map_err(|e| anyhow::anyhow!("Failed to write lock file: {}", e))
    }

    /// Compute diff against another lock.
    pub fn diff(&self, other: &PipelineLock) -> LockDiff {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();

        // Find added and changed
        for (key, entry) in &self.rules {
            match other.rules.get(key) {
                None => added.push(key.clone()),
                Some(old_entry) if old_entry != entry => changed.push(key.clone()),
                _ => {}
            }
        }

        // Find removed
        for key in other.rules.keys() {
            if !self.rules.contains_key(key) {
                removed.push(key.clone());
            }
        }

        LockDiff {
            added,
            removed,
            changed,
        }
    }

    /// Merge another lock into this one (union).
    pub fn merge(&mut self, other: &PipelineLock) {
        for (key, entry) in &other.rules {
            if !self.rules.contains_key(key) {
                self.rules.insert(key.clone(), entry.clone());
            }
        }
        self.updated_at = Utc::now();
    }
}

impl Default for PipelineLock {
    fn default() -> Self {
        Self::new()
    }
}

/// An entry in the lock file for a single rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockEntry {
    /// Rule type (TEAMID, SIGNINGID, etc.).
    pub rule_type: String,
    /// Rule identifier.
    pub identifier: String,
    /// Policy (ALLOWLIST, BLOCKLIST, etc.).
    pub policy: String,
    /// Bundle this rule came from.
    pub bundle: String,
    /// When this entry was created.
    pub created_at: DateTime<Utc>,
    /// Description/source app name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl LockEntry {
    /// Create a new lock entry.
    pub fn new(
        rule_type: impl Into<String>,
        identifier: impl Into<String>,
        policy: impl Into<String>,
        bundle: impl Into<String>,
    ) -> Self {
        Self {
            rule_type: rule_type.into(),
            identifier: identifier.into(),
            policy: policy.into(),
            bundle: bundle.into(),
            created_at: Utc::now(),
            description: None,
        }
    }

    /// Set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Get the rule key (type:identifier).
    pub fn key(&self) -> String {
        format!("{}:{}", self.rule_type, self.identifier)
    }
}

/// Diff between two lock files.
#[derive(Debug, Default)]
pub struct LockDiff {
    /// Rules that were added.
    pub added: Vec<String>,
    /// Rules that were removed.
    pub removed: Vec<String>,
    /// Rules that were changed.
    pub changed: Vec<String>,
}

impl LockDiff {
    /// Check if there are any changes.
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.changed.is_empty()
    }

    /// Total number of changes.
    pub fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }

    /// Check if the diff represents append-only changes (no removals or modifications).
    pub fn is_append_only(&self) -> bool {
        self.removed.is_empty() && self.changed.is_empty()
    }

    /// Format as human-readable string.
    pub fn to_human_readable(&self) -> String {
        let mut output = String::new();

        if !self.added.is_empty() {
            output.push_str(&format!("Added ({}):\n", self.added.len()));
            for key in &self.added {
                output.push_str(&format!("  + {}\n", key));
            }
        }

        if !self.removed.is_empty() {
            output.push_str(&format!("Removed ({}):\n", self.removed.len()));
            for key in &self.removed {
                output.push_str(&format!("  - {}\n", key));
            }
        }

        if !self.changed.is_empty() {
            output.push_str(&format!("Changed ({}):\n", self.changed.len()));
            for key in &self.changed {
                output.push_str(&format!("  ~ {}\n", key));
            }
        }

        if output.is_empty() {
            output.push_str("No changes\n");
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_entry_key() {
        let entry = LockEntry::new("TEAMID", "ABC1234567", "ALLOWLIST", "google");
        assert_eq!(entry.key(), "TEAMID:ABC1234567");
    }

    #[test]
    fn test_lock_add_rule() {
        let mut lock = PipelineLock::new();
        lock.add_rule(
            "TEAMID:ABC".to_string(),
            LockEntry::new("TEAMID", "ABC", "ALLOWLIST", "test"),
        );

        assert!(lock.has_rule("TEAMID:ABC"));
        assert!(!lock.has_rule("TEAMID:XYZ"));
    }

    #[test]
    fn test_lock_diff() {
        let mut lock1 = PipelineLock::new();
        lock1.add_rule(
            "A".to_string(),
            LockEntry::new("TEAMID", "A", "ALLOWLIST", "test"),
        );
        lock1.add_rule(
            "B".to_string(),
            LockEntry::new("TEAMID", "B", "ALLOWLIST", "test"),
        );

        let mut lock2 = PipelineLock::new();
        lock2.add_rule(
            "A".to_string(),
            LockEntry::new("TEAMID", "A", "ALLOWLIST", "test"),
        );
        lock2.add_rule(
            "C".to_string(),
            LockEntry::new("TEAMID", "C", "ALLOWLIST", "test"),
        );

        let diff = lock1.diff(&lock2);

        assert!(diff.added.contains(&"B".to_string())); // B is in lock1 but not lock2
        assert!(diff.removed.contains(&"C".to_string())); // C is in lock2 but not lock1
    }

    #[test]
    fn test_lock_yaml_roundtrip() {
        let mut lock = PipelineLock::new();
        lock.add_rule(
            "TEAMID:ABC".to_string(),
            LockEntry::new("TEAMID", "ABC", "ALLOWLIST", "test").with_description("Test app"),
        );

        let yaml = lock.to_yaml().unwrap();
        let parsed = PipelineLock::from_yaml(&yaml).unwrap();

        assert_eq!(parsed.len(), 1);
        assert!(parsed.has_rule("TEAMID:ABC"));
    }
}
