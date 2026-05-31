use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::rule::RuleSet;

/// A deployment ring for staged rollouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring {
    /// Ring identifier (e.g., "ring0", "ring1", "canary", "production")
    pub name: String,

    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Ring priority/order (lower = earlier deployment)
    pub priority: u8,

    /// Profile identifier prefix for this ring
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_prefix: Option<String>,

    /// Maximum rules per profile (for splitting)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_rules_per_profile: Option<usize>,

    /// Fleet labels to target this ring
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fleet_labels: Vec<String>,
}

impl Ring {
    pub fn new(name: impl Into<String>, priority: u8) -> Self {
        Self {
            name: name.into(),
            description: None,
            priority,
            profile_prefix: None,
            max_rules_per_profile: None,
            fleet_labels: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    #[must_use]
    pub fn with_profile_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.profile_prefix = Some(prefix.into());
        self
    }

    #[must_use]
    pub fn with_max_rules(mut self, max: usize) -> Self {
        self.max_rules_per_profile = Some(max);
        self
    }

    #[must_use]
    pub fn with_fleet_labels(mut self, labels: Vec<String>) -> Self {
        self.fleet_labels = labels;
        self
    }
}

/// Ring assignment for a rule
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RingAssignment {
    /// Rings this rule belongs to (empty = all rings)
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub rings: HashSet<String>,
}

impl RingAssignment {
    pub fn new() -> Self {
        Self {
            rings: HashSet::new(),
        }
    }

    /// Assign to a specific ring
    pub fn add_ring(&mut self, ring: impl Into<String>) {
        self.rings.insert(ring.into());
    }

    /// Assign to multiple rings
    pub fn add_rings(&mut self, rings: impl IntoIterator<Item = impl Into<String>>) {
        for ring in rings {
            self.rings.insert(ring.into());
        }
    }

    /// Check if assigned to a specific ring (or all if empty)
    pub fn is_in_ring(&self, ring: &str) -> bool {
        self.rings.is_empty() || self.rings.contains(ring)
    }

    /// Check if assigned to all rings
    pub fn is_global(&self) -> bool {
        self.rings.is_empty()
    }
}

/// Ring configuration for a project
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RingConfig {
    /// Defined rings
    pub rings: Vec<Ring>,

    /// Default rings for new rules (if not specified)
    #[serde(default)]
    pub default_rings: Vec<String>,
}

impl RingConfig {
    pub fn new() -> Self {
        Self {
            rings: Vec::new(),
            default_rings: Vec::new(),
        }
    }

    /// Add a ring definition
    pub fn add_ring(&mut self, ring: Ring) {
        self.rings.push(ring);
    }

    /// Get rings sorted by priority
    pub fn rings_by_priority(&self) -> Vec<&Ring> {
        let mut sorted: Vec<_> = self.rings.iter().collect();
        sorted.sort_by_key(|r| r.priority);
        sorted
    }

    /// Get a ring by name
    pub fn get_ring(&self, name: &str) -> Option<&Ring> {
        self.rings.iter().find(|r| r.name == name)
    }

    /// Create a standard 5-ring configuration
    pub fn standard_five_rings() -> Self {
        let mut config = Self::new();
        config.add_ring(
            Ring::new("ring0", 0)
                .with_description("IT/Security team - immediate deployment")
                .with_fleet_labels(vec!["ring:0".to_string()]),
        );
        config.add_ring(
            Ring::new("ring1", 1)
                .with_description("Early adopters / Canary")
                .with_fleet_labels(vec!["ring:1".to_string()]),
        );
        config.add_ring(
            Ring::new("ring2", 2)
                .with_description("Pilot group - broader testing")
                .with_fleet_labels(vec!["ring:2".to_string()]),
        );
        config.add_ring(
            Ring::new("ring3", 3)
                .with_description("General availability - most users")
                .with_fleet_labels(vec!["ring:3".to_string()]),
        );
        config.add_ring(
            Ring::new("ring4", 4)
                .with_description("Critical/sensitive systems - delayed deployment")
                .with_fleet_labels(vec!["ring:4".to_string()]),
        );
        config
    }

    /// Create a custom N-ring configuration with sensible defaults.
    ///
    /// Each ring gets a `ring{i}` name, an incrementing priority, a clean
    /// description, and a default `ring:{i}` Fleet label. Used as the fallback
    /// when N is not 5 or 7, and as the template emitted by `rings init`.
    pub fn custom_rings(num_rings: u8) -> Self {
        let mut config = Self::new();
        for i in 0..num_rings {
            config.add_ring(
                Ring::new(format!("ring{i}"), i)
                    .with_description(format!("Ring {}", i + 1))
                    .with_fleet_labels(vec![format!("ring:{i}")]),
            );
        }
        config
    }

    /// Build a `RingConfig` from a `--num-rings` value. Returns the canonical
    /// 5- or 7-ring configs for those values, otherwise a custom config.
    pub fn from_num_rings(num_rings: u8) -> Self {
        match num_rings {
            5 => Self::standard_five_rings(),
            7 => Self::standard_seven_rings(),
            n => Self::custom_rings(n),
        }
    }

    /// Load a `RingConfig` from a YAML file (as produced by `rings init`).
    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read rings config from {}", path.display()))?;
        let config: Self = yaml_serde::from_str(&contents)
            .with_context(|| format!("failed to parse rings config at {}", path.display()))?;
        if config.rings.is_empty() {
            anyhow::bail!("rings config at {} defines no rings", path.display());
        }
        Ok(config)
    }

    /// Create a standard 7-ring configuration
    pub fn standard_seven_rings() -> Self {
        let mut config = Self::new();
        config.add_ring(
            Ring::new("ring0", 0)
                .with_description("IT/Security team - immediate")
                .with_fleet_labels(vec!["ring:0".to_string()]),
        );
        config.add_ring(
            Ring::new("ring1", 1)
                .with_description("Early adopters")
                .with_fleet_labels(vec!["ring:1".to_string()]),
        );
        config.add_ring(
            Ring::new("ring2", 2)
                .with_description("Pilot - engineering")
                .with_fleet_labels(vec!["ring:2".to_string()]),
        );
        config.add_ring(
            Ring::new("ring3", 3)
                .with_description("Pilot - broader")
                .with_fleet_labels(vec!["ring:3".to_string()]),
        );
        config.add_ring(
            Ring::new("ring4", 4)
                .with_description("General - wave 1")
                .with_fleet_labels(vec!["ring:4".to_string()]),
        );
        config.add_ring(
            Ring::new("ring5", 5)
                .with_description("General - wave 2")
                .with_fleet_labels(vec!["ring:5".to_string()]),
        );
        config.add_ring(
            Ring::new("ring6", 6)
                .with_description("Critical systems - final")
                .with_fleet_labels(vec!["ring:6".to_string()]),
        );
        config
    }
}

/// Tracks per-rule ring assignments for staged rollouts.
#[derive(Debug)]
pub struct RingAssignments {
    pub config: RingConfig,
    /// Rule assignments: rule key -> ring assignment
    pub assignments: HashMap<String, RingAssignment>,
}

impl RingAssignments {
    pub fn new(config: RingConfig) -> Self {
        Self {
            config,
            assignments: HashMap::new(),
        }
    }

    /// Assign a rule to rings
    pub fn assign_rule(&mut self, rule_key: &str, rings: &[&str]) {
        let assignment = self.assignments.entry(rule_key.to_string()).or_default();
        for ring in rings {
            assignment.add_ring(*ring);
        }
    }

    /// Assign a rule to all rings (global)
    pub fn assign_global(&mut self, rule_key: &str) {
        self.assignments
            .insert(rule_key.to_string(), RingAssignment::new());
    }

    /// Get rules for a specific ring
    pub fn rules_for_ring<'a>(&'a self, rules: &'a RuleSet, ring_name: &str) -> RuleSet {
        let filtered: Vec<_> = rules
            .rules()
            .iter()
            .filter(|rule| {
                let assignment = self.assignments.get(&rule.key());
                match assignment {
                    Some(a) => a.is_in_ring(ring_name),
                    None => true, // Unassigned rules go to all rings
                }
            })
            .cloned()
            .collect();

        RuleSet::from_rules(filtered)
    }

    /// Generate rule sets for all rings
    pub fn distribute(&self, rules: &RuleSet) -> HashMap<String, RuleSet> {
        let mut result = HashMap::new();

        for ring in &self.config.rings {
            let ring_rules = self.rules_for_ring(rules, &ring.name);
            result.insert(ring.name.clone(), ring_rules);
        }

        result
    }
}

/// Resolve a [`RingConfig`] from CLI inputs.
///
/// `--rings-config <path>` wins when supplied (loaded from YAML).
/// Otherwise `--num-rings N` selects a standard/custom config.
/// With neither, falls back to the canonical 5-ring config.
pub fn resolve_ring_config(
    num_rings: Option<u8>,
    rings_config_path: Option<&Path>,
) -> Result<RingConfig> {
    if let Some(path) = rings_config_path {
        return RingConfig::from_yaml_file(path);
    }
    Ok(RingConfig::from_num_rings(num_rings.unwrap_or(5)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Policy, Rule, RuleType};

    #[test]
    fn test_ring_assignment() {
        let mut assignment = RingAssignment::new();
        assert!(assignment.is_global());

        assignment.add_ring("ring0");
        assignment.add_ring("ring1");

        assert!(!assignment.is_global());
        assert!(assignment.is_in_ring("ring0"));
        assert!(assignment.is_in_ring("ring1"));
        assert!(!assignment.is_in_ring("ring2"));
    }

    #[test]
    fn test_standard_five_rings() {
        let config = RingConfig::standard_five_rings();
        assert_eq!(config.rings.len(), 5);

        let sorted = config.rings_by_priority();
        assert_eq!(sorted[0].name, "ring0");
        assert_eq!(sorted[4].name, "ring4");
    }

    #[test]
    fn test_custom_rings_populates_fleet_labels() {
        let config = RingConfig::custom_rings(3);
        assert_eq!(config.rings.len(), 3);
        for (i, ring) in config.rings.iter().enumerate() {
            assert_eq!(ring.name, format!("ring{i}"));
            assert_eq!(ring.priority, u8::try_from(i).unwrap());
            assert_eq!(ring.fleet_labels, vec![format!("ring:{i}")]);
        }
    }

    #[test]
    fn test_from_num_rings_dispatches() {
        assert_eq!(RingConfig::from_num_rings(5).rings.len(), 5);
        assert_eq!(RingConfig::from_num_rings(7).rings.len(), 7);
        assert_eq!(RingConfig::from_num_rings(3).rings.len(), 3);
    }

    #[test]
    fn test_resolve_ring_config_defaults_to_five() {
        let config = resolve_ring_config(None, None).unwrap();
        assert_eq!(config.rings.len(), 5);
    }

    #[test]
    fn test_resolve_ring_config_uses_num_rings() {
        let config = resolve_ring_config(Some(7), None).unwrap();
        assert_eq!(config.rings.len(), 7);
    }

    #[test]
    fn test_resolve_ring_config_loads_from_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let template = RingConfig::custom_rings(4);
        let yaml = yaml_serde::to_string(&template).unwrap();
        std::fs::write(tmp.path(), yaml).unwrap();

        let loaded = resolve_ring_config(None, Some(tmp.path())).unwrap();
        assert_eq!(loaded.rings.len(), 4);
        assert_eq!(loaded.rings[0].fleet_labels, vec!["ring:0".to_string()]);
    }

    #[test]
    fn test_from_yaml_file_rejects_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let empty = RingConfig::new();
        std::fs::write(tmp.path(), yaml_serde::to_string(&empty).unwrap()).unwrap();

        let err = RingConfig::from_yaml_file(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("defines no rings"));
    }

    #[test]
    fn test_ring_manager_distribute() {
        let config = RingConfig::standard_five_rings();
        let mut manager = RingAssignments::new(config);

        // Create test rules
        let mut rules = RuleSet::new();
        rules.add(Rule::new(RuleType::TeamId, "GLOBAL", Policy::Allowlist));
        rules.add(Rule::new(RuleType::TeamId, "RING0_ONLY", Policy::Allowlist));
        rules.add(Rule::new(RuleType::TeamId, "RING01", Policy::Allowlist));

        // Assign rules
        manager.assign_global("TEAMID:GLOBAL");
        manager.assign_rule("TEAMID:RING0_ONLY", &["ring0"]);
        manager.assign_rule("TEAMID:RING01", &["ring0", "ring1"]);

        let distributed = manager.distribute(&rules);

        // ring0 should have all 3 rules
        assert_eq!(distributed.get("ring0").unwrap().len(), 3);

        // ring1 should have GLOBAL and RING01
        assert_eq!(distributed.get("ring1").unwrap().len(), 2);

        // ring2 should only have GLOBAL
        assert_eq!(distributed.get("ring2").unwrap().len(), 1);
    }
}
