use crate::models::{Rule, RuleSet};
use clap::ValueEnum;
use std::collections::HashMap;

/// Merge conflict resolution strategy
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum Strategy {
    /// Keep the first occurrence
    First,
    /// Keep the last occurrence
    #[default]
    Last,
    /// Error on conflicts
    Strict,
}

/// Conflict information
#[derive(Debug)]
pub struct Conflict {
    pub key: String,
    pub rules: Vec<Rule>,
}

/// Merge result
#[derive(Debug)]
pub struct MergeResult {
    pub rules: RuleSet,
    pub conflicts: Vec<Conflict>,
}

/// Merge multiple rule sets
pub fn merge(sets: &[RuleSet], strategy: Strategy) -> anyhow::Result<MergeResult> {
    let mut by_key: HashMap<String, Vec<Rule>> = HashMap::new();

    // Collect all rules by key
    for set in sets {
        for rule in set.rules() {
            by_key.entry(rule.key()).or_default().push(rule.clone());
        }
    }

    let mut rules = RuleSet::new();
    let mut conflicts = Vec::new();

    for (key, mut rule_list) in by_key {
        if rule_list.len() > 1 {
            // Conflict detected
            conflicts.push(Conflict {
                key: key.clone(),
                rules: rule_list.clone(),
            });

            match strategy {
                Strategy::First => {
                    rules.add(rule_list.remove(0));
                }
                Strategy::Last => {
                    rules.add(rule_list.pop().unwrap());
                }
                Strategy::Strict => {
                    anyhow::bail!("Conflict detected for rule: {key}");
                }
            }
        } else {
            rules.add(rule_list.pop().unwrap());
        }
    }

    Ok(MergeResult { rules, conflicts })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Policy, RuleType};

    #[test]
    fn test_merge_no_conflicts() {
        let mut set1 = RuleSet::new();
        set1.add(Rule::new(RuleType::TeamId, "A", Policy::Allowlist));

        let mut set2 = RuleSet::new();
        set2.add(Rule::new(RuleType::TeamId, "B", Policy::Allowlist));

        let result = merge(&[set1, set2], Strategy::Last).unwrap();
        assert_eq!(result.rules.len(), 2);
        assert!(result.conflicts.is_empty());
    }

    #[test]
    fn test_merge_with_conflict_last() {
        let mut set1 = RuleSet::new();
        set1.add(Rule::new(RuleType::TeamId, "A", Policy::Allowlist));

        let mut set2 = RuleSet::new();
        set2.add(Rule::new(RuleType::TeamId, "A", Policy::Blocklist));

        let result = merge(&[set1, set2], Strategy::Last).unwrap();
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.conflicts.len(), 1);
        // Last wins: Blocklist
        assert_eq!(result.rules.rules()[0].policy, Policy::Blocklist);
    }

    #[test]
    fn test_merge_with_conflict_first() {
        let mut set1 = RuleSet::new();
        set1.add(Rule::new(RuleType::TeamId, "A", Policy::Allowlist));

        let mut set2 = RuleSet::new();
        set2.add(Rule::new(RuleType::TeamId, "A", Policy::Blocklist));

        let result = merge(&[set1, set2], Strategy::First).unwrap();
        assert_eq!(result.rules.len(), 1);
        // First wins: Allowlist
        assert_eq!(result.rules.rules()[0].policy, Policy::Allowlist);
    }

    #[test]
    fn test_merge_strict_fails_on_conflict() {
        let mut set1 = RuleSet::new();
        set1.add(Rule::new(RuleType::TeamId, "A", Policy::Allowlist));

        let mut set2 = RuleSet::new();
        set2.add(Rule::new(RuleType::TeamId, "A", Policy::Blocklist));

        let result = merge(&[set1, set2], Strategy::Strict);
        assert!(result.is_err());
    }
}
