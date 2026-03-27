use crate::models::{Rule, RuleSet};
use std::collections::HashSet;

/// Type of change detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
}

/// A single change between two rule sets
#[derive(Debug, Clone)]
pub struct Change {
    pub change_type: ChangeType,
    pub key: String,
    pub old_rule: Option<Rule>,
    pub new_rule: Option<Rule>,
}

/// Diff result
#[derive(Debug)]
pub struct DiffResult {
    pub changes: Vec<Change>,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
}

impl DiffResult {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.added + self.removed + self.modified
    }
}

/// Compare two rule sets and return the differences
pub fn diff(old: &RuleSet, new: &RuleSet) -> DiffResult {
    let mut changes = Vec::new();
    let mut added = 0;
    let mut removed = 0;
    let mut modified = 0;

    // Build lookup maps
    let old_map: std::collections::HashMap<String, &Rule> =
        old.rules().iter().map(|r| (r.key(), r)).collect();
    let new_map: std::collections::HashMap<String, &Rule> =
        new.rules().iter().map(|r| (r.key(), r)).collect();

    let old_keys: HashSet<_> = old_map.keys().cloned().collect();
    let new_keys: HashSet<_> = new_map.keys().cloned().collect();

    // Find removed rules
    for key in old_keys.difference(&new_keys) {
        changes.push(Change {
            change_type: ChangeType::Removed,
            key: key.clone(),
            old_rule: old_map.get(key).copied().cloned(),
            new_rule: None,
        });
        removed += 1;
    }

    // Find added rules
    for key in new_keys.difference(&old_keys) {
        changes.push(Change {
            change_type: ChangeType::Added,
            key: key.clone(),
            old_rule: None,
            new_rule: new_map.get(key).copied().cloned(),
        });
        added += 1;
    }

    // Find modified rules
    for key in old_keys.intersection(&new_keys) {
        let old_rule = old_map.get(key).unwrap();
        let new_rule = new_map.get(key).unwrap();

        if rules_differ(old_rule, new_rule) {
            changes.push(Change {
                change_type: ChangeType::Modified,
                key: key.clone(),
                old_rule: Some((*old_rule).clone()),
                new_rule: Some((*new_rule).clone()),
            });
            modified += 1;
        }
    }

    // Sort changes by key for consistent output
    changes.sort_by(|a, b| a.key.cmp(&b.key));

    DiffResult {
        changes,
        added,
        removed,
        modified,
    }
}

/// Check if two rules differ (beyond just the key)
fn rules_differ(a: &Rule, b: &Rule) -> bool {
    a.policy != b.policy
        || a.custom_msg != b.custom_msg
        || a.custom_url != b.custom_url
        || a.description != b.description
        || a.group != b.group
        || !labels_equal(&a.labels, &b.labels)
}

/// Compare labels regardless of order
fn labels_equal(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let a_set: HashSet<_> = a.iter().collect();
    let b_set: HashSet<_> = b.iter().collect();
    a_set == b_set
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Policy, RuleType};

    #[test]
    fn test_diff_identical() {
        let mut set = RuleSet::new();
        set.add(Rule::new(RuleType::TeamId, "A", Policy::Allowlist));

        let result = diff(&set, &set);
        assert!(result.is_empty());
    }

    #[test]
    fn test_diff_added() {
        let old = RuleSet::new();
        let mut new = RuleSet::new();
        new.add(Rule::new(RuleType::TeamId, "A", Policy::Allowlist));

        let result = diff(&old, &new);
        assert_eq!(result.added, 1);
        assert_eq!(result.removed, 0);
        assert_eq!(result.modified, 0);
    }

    #[test]
    fn test_diff_removed() {
        let mut old = RuleSet::new();
        old.add(Rule::new(RuleType::TeamId, "A", Policy::Allowlist));
        let new = RuleSet::new();

        let result = diff(&old, &new);
        assert_eq!(result.added, 0);
        assert_eq!(result.removed, 1);
        assert_eq!(result.modified, 0);
    }

    #[test]
    fn test_diff_modified() {
        let mut old = RuleSet::new();
        old.add(Rule::new(RuleType::TeamId, "A", Policy::Allowlist));

        let mut new = RuleSet::new();
        new.add(Rule::new(RuleType::TeamId, "A", Policy::Blocklist));

        let result = diff(&old, &new);
        assert_eq!(result.added, 0);
        assert_eq!(result.removed, 0);
        assert_eq!(result.modified, 1);
    }
}
