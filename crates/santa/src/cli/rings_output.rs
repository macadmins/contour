use anyhow::Result;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::merge::{Conflict, Strategy, merge};
use crate::models::{RingConfig, RuleSet};
use crate::parser::parse_baseline_file;

/// Unified output payload for rings-related commands (`rings generate`,
/// `fleet`, and `fleet --fragment`). One schema parseable with a single
/// `jq` filter across all three.
#[derive(Debug, Serialize)]
pub struct RingsOutput {
    pub rings_count: usize,
    pub editions: Vec<EditionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<PathBuf>,
    pub fragment: bool,
    pub dry_run: bool,
}

/// One emitted edition (per ring × category × part).
#[derive(Debug, Serialize)]
pub struct EditionInfo {
    pub ring: String,
    pub category: String,
    pub filename: String,
    pub rules_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fleet_labels: Vec<String>,
}

/// Load the baseline (if provided) and merge it into the supplied rules using
/// deny-wins conflict resolution. Returns the merged set plus one warning
/// string per resolved conflict so callers can route them to human or JSON
/// output channels uniformly.
pub fn apply_baseline_merge(
    rules: RuleSet,
    baseline_path: Option<&Path>,
) -> Result<(RuleSet, Vec<String>)> {
    let Some(path) = baseline_path else {
        return Ok((rules, Vec::new()));
    };
    let baseline = parse_baseline_file(path)?;
    // Baseline first so an input-side `Strategy::Last` tiebreak (when both
    // sides assert the same restrictiveness) keeps the input rule, matching
    // the principle of least surprise for users editing rules.yaml.
    let result = merge(&[baseline, rules], Strategy::DenyWins)?;
    let warnings = result
        .conflicts
        .iter()
        .filter(|c| has_policy_disagreement(c))
        .map(format_baseline_conflict)
        .collect();
    Ok((result.rules, warnings))
}

/// True when a conflict contains at least two rules with different policies.
/// Same-policy duplicates are silent — the baseline already had this rule.
pub fn has_policy_disagreement(conflict: &Conflict) -> bool {
    let first = conflict.rules.first().map(|r| r.policy);
    conflict.rules.iter().any(|r| Some(r.policy) != first)
}

fn format_baseline_conflict(conflict: &Conflict) -> String {
    let winner = conflict
        .rules
        .iter()
        .max_by_key(|r| r.policy.restrictiveness())
        .expect("conflict always has >= 2 rules");
    let losers: Vec<String> = conflict
        .rules
        .iter()
        .filter(|r| r.policy != winner.policy)
        .map(|r| r.policy.to_string())
        .collect();
    format!(
        "baseline conflict on {}: kept {} (deny-wins), overrode {}",
        conflict.key,
        winner.policy,
        losers.join(", ")
    )
}

/// Walk rules and return one warning per `rule.rings` entry that doesn't
/// match a ring name in the active config. Today these rules are silently
/// dropped from every edition — surfacing them prevents typo data loss.
pub fn collect_unknown_ring_warnings(rules: &RuleSet, ring_config: &RingConfig) -> Vec<String> {
    let valid: HashSet<&str> = ring_config.rings.iter().map(|r| r.name.as_str()).collect();
    let mut warnings = Vec::new();
    for rule in rules {
        for ring_name in &rule.rings {
            if !valid.contains(ring_name.as_str()) {
                warnings.push(format!(
                    "rule '{}' references unknown ring '{}' (rule will not appear in any edition)",
                    rule.identifier, ring_name
                ));
            }
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Policy, Rule, RuleType};

    #[test]
    fn warns_for_unknown_rings() {
        let config = RingConfig::from_num_rings(3);
        let mut rules = RuleSet::new();
        let mut good = Rule::new(RuleType::TeamId, "GOOD", Policy::Allowlist);
        good.rings = vec!["ring1".into()];
        rules.add(good);
        let mut bad = Rule::new(RuleType::TeamId, "BAD", Policy::Allowlist);
        bad.rings = vec!["ring1".into(), "ring99".into()];
        rules.add(bad);

        let warnings = collect_unknown_ring_warnings(&rules, &config);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("BAD"));
        assert!(warnings[0].contains("ring99"));
    }

    #[test]
    fn no_warning_for_empty_rings() {
        let config = RingConfig::from_num_rings(3);
        let mut rules = RuleSet::new();
        rules.add(Rule::new(RuleType::TeamId, "CORE", Policy::Allowlist));
        assert!(collect_unknown_ring_warnings(&rules, &config).is_empty());
    }
}
