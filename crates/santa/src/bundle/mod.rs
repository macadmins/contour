//! Bundle definitions and management for CEL-based app classification.
//!
//! Bundles are named groups of applications that match a CEL expression.
//! They are used to classify apps from Fleet CSV exports and generate
//! appropriate Santa rules.

mod config;
mod layers;

pub use config::{
    BundleConfig, ConflictPolicy, DedupLevel, DiscoveryConfig, OrphanPolicy, PipelineConfig,
    RuleTypeStrategy,
};
pub use layers::{Layer, LayerConfig, LayerMappings, LayerStageAssignment, Stage, StageConfig};

use crate::models::{Policy, RuleType};
use serde::{Deserialize, Serialize};

/// A bundle definition for classifying applications.
///
/// Bundles use CEL expressions to match applications and specify
/// how to generate Santa rules for matched apps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Unique name for this bundle (e.g., "microsoft", "google", "zoom")
    pub name: String,

    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// CEL expression to match applications
    /// Available context: app.team_id, app.signing_id, app.app_name, app.sha256, app.version
    #[serde(rename = "cel")]
    pub cel_expression: String,

    /// Type of Santa rule to generate for matched apps
    #[serde(default)]
    pub rule_type: RuleType,

    /// The identifier for the rule (TeamID, SigningID, etc.)
    /// When present, allows direct rule generation without CEL evaluation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,

    /// Policy to apply (ALLOWLIST, BLOCKLIST, etc.)
    #[serde(default = "default_policy")]
    pub policy: Policy,

    /// Priority for conflict resolution (higher = takes precedence)
    #[serde(default)]
    pub priority: i32,

    /// Layer assignment (e.g., "core", "developers", "finance")
    /// Used for audience-based grouping
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,

    /// Stage assignment (e.g., "prod", "beta", "alpha")
    /// Used for staged rollout. Defaults to "prod" if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,

    /// Hint for which profile to place these rules in
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_hint: Option<String>,

    /// Auto-discovered metadata (not used for matching)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_coverage: Option<usize>,

    /// Number of apps that matched during discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_count: Option<usize>,

    /// Confidence score from discovery (0.0 - 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

fn default_policy() -> Policy {
    Policy::Allowlist
}

impl Bundle {
    /// Create a new bundle with the given name and CEL expression.
    pub fn new(name: impl Into<String>, cel_expression: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            cel_expression: cel_expression.into(),
            rule_type: RuleType::TeamId,
            identifier: None,
            policy: Policy::Allowlist,
            priority: 0,
            layer: None,
            stage: None,
            profile_hint: None,
            device_coverage: None,
            app_count: None,
            confidence: None,
        }
    }

    /// Builder: set identifier.
    #[must_use]
    pub fn with_identifier(mut self, id: impl Into<String>) -> Self {
        self.identifier = Some(id.into());
        self
    }

    /// Get the effective layer (defaults to "core").
    pub fn effective_layer(&self) -> &str {
        self.layer.as_deref().unwrap_or("core")
    }

    /// Get the effective stage (defaults to "prod").
    pub fn effective_stage(&self) -> &str {
        self.stage.as_deref().unwrap_or("prod")
    }

    /// Builder: set description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Builder: set rule type.
    #[must_use]
    pub fn with_rule_type(mut self, rule_type: RuleType) -> Self {
        self.rule_type = rule_type;
        self
    }

    /// Builder: set policy.
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Builder: set priority.
    #[must_use]
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Builder: set profile hint.
    #[must_use]
    pub fn with_profile_hint(mut self, hint: impl Into<String>) -> Self {
        self.profile_hint = Some(hint.into());
        self
    }

    /// Builder: set layer.
    #[must_use]
    pub fn with_layer(mut self, layer: impl Into<String>) -> Self {
        self.layer = Some(layer.into());
        self
    }

    /// Builder: set stage.
    #[must_use]
    pub fn with_stage(mut self, stage: impl Into<String>) -> Self {
        self.stage = Some(stage.into());
        self
    }

    /// Builder: set device coverage (discovery metadata).
    #[must_use]
    pub fn with_device_coverage(mut self, count: usize) -> Self {
        self.device_coverage = Some(count);
        self
    }

    /// Builder: set app count (discovery metadata).
    #[must_use]
    pub fn with_app_count(mut self, count: usize) -> Self {
        self.app_count = Some(count);
        self
    }

    /// Builder: set confidence score (discovery metadata).
    #[must_use]
    pub fn with_confidence(mut self, score: f64) -> Self {
        self.confidence = Some(score);
        self
    }

    /// Create a TeamID bundle for a specific vendor.
    pub fn for_team_id(name: impl Into<String>, team_id: &str) -> Self {
        let name = name.into();
        Self::new(
            &name,
            format!(r#"has(app.team_id) && app.team_id == "{team_id}""#),
        )
        .with_rule_type(RuleType::TeamId)
        .with_identifier(team_id)
        .with_description(format!("{name} (TeamID: {team_id})"))
    }

    /// Create a SigningID bundle for a specific app.
    pub fn for_signing_id(name: impl Into<String>, signing_id: &str) -> Self {
        let name = name.into();
        Self::new(
            &name,
            format!(r#"has(app.signing_id) && app.signing_id == "{signing_id}""#),
        )
        .with_rule_type(RuleType::SigningId)
        .with_identifier(signing_id)
        .with_description(format!("{name} (SigningID: {signing_id})"))
    }

    /// Create a bundle matching apps by name pattern.
    pub fn for_app_name_contains(name: impl Into<String>, pattern: &str) -> Self {
        let name = name.into();
        Self::new(
            &name,
            format!(r#"has(app.app_name) && app.app_name.contains("{pattern}")"#),
        )
        .with_description(format!("{name} (name contains: {pattern})"))
    }

    /// Convert this bundle to a Santa Rule.
    /// Returns None if the bundle has no identifier set.
    pub fn to_rule(&self) -> Option<crate::models::Rule> {
        let identifier = self.identifier.as_ref()?;
        Some(
            crate::models::Rule::new(self.rule_type, identifier, self.policy)
                .with_description(&self.name),
        )
    }
}

/// A collection of bundles for classification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BundleSet {
    /// The bundles in this set
    #[serde(rename = "bundles")]
    bundles: Vec<Bundle>,
}

impl BundleSet {
    /// Create an empty bundle set.
    pub fn new() -> Self {
        Self {
            bundles: Vec::new(),
        }
    }

    /// Create a bundle set from a vector of bundles.
    pub fn from_bundles(bundles: Vec<Bundle>) -> Self {
        Self { bundles }
    }

    /// Add a bundle to the set.
    pub fn add(&mut self, bundle: Bundle) {
        self.bundles.push(bundle);
    }

    /// Get all bundles.
    pub fn bundles(&self) -> &[Bundle] {
        &self.bundles
    }

    /// Get mutable access to bundles.
    pub fn bundles_mut(&mut self) -> &mut Vec<Bundle> {
        &mut self.bundles
    }

    /// Number of bundles.
    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Iterate over bundles.
    pub fn iter(&self) -> std::slice::Iter<'_, Bundle> {
        self.bundles.iter()
    }

    /// Find a bundle by name.
    pub fn by_name(&self, name: &str) -> Option<&Bundle> {
        self.bundles.iter().find(|b| b.name == name)
    }

    /// Get bundles sorted by priority (highest first).
    pub fn by_priority(&self) -> Vec<&Bundle> {
        let mut sorted: Vec<_> = self.bundles.iter().collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
        sorted
    }

    /// Consume and return the inner bundles.
    pub fn into_bundles(self) -> Vec<Bundle> {
        self.bundles
    }

    /// Load bundles from a TOML file.
    pub fn from_toml_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read bundle file {}: {e}", path.display()))?;
        Self::from_toml(&content)
    }

    /// Parse bundles from TOML string.
    pub fn from_toml(content: &str) -> anyhow::Result<Self> {
        toml::from_str(content).map_err(|e| anyhow::anyhow!("Failed to parse bundle TOML: {e}"))
    }

    /// Serialize bundles to TOML string.
    pub fn to_toml(&self) -> anyhow::Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize bundles to TOML: {e}"))
    }

    /// Write bundles to a TOML file.
    pub fn to_toml_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let content = self.to_toml()?;
        std::fs::write(path, content)
            .map_err(|e| anyhow::anyhow!("Failed to write bundle file {}: {e}", path.display()))
    }

    /// Convert bundles to Santa rules.
    /// Only bundles with an identifier set will be converted.
    pub fn to_rules(&self) -> crate::models::RuleSet {
        let rules: Vec<_> = self.bundles.iter().filter_map(Bundle::to_rule).collect();
        crate::models::RuleSet::from_rules(rules)
    }
}

impl IntoIterator for BundleSet {
    type Item = Bundle;
    type IntoIter = std::vec::IntoIter<Bundle>;

    fn into_iter(self) -> Self::IntoIter {
        self.bundles.into_iter()
    }
}

impl<'a> IntoIterator for &'a BundleSet {
    type Item = &'a Bundle;
    type IntoIter = std::slice::Iter<'a, Bundle>;

    fn into_iter(self) -> Self::IntoIter {
        self.bundles.iter()
    }
}

impl Extend<Bundle> for BundleSet {
    fn extend<T: IntoIterator<Item = Bundle>>(&mut self, iter: T) {
        self.bundles.extend(iter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_creation() {
        let bundle = Bundle::new(
            "microsoft",
            r#"has(app.team_id) && app.team_id == "UBF8T346G9""#,
        )
        .with_description("Microsoft Corporation")
        .with_rule_type(RuleType::TeamId)
        .with_policy(Policy::Allowlist);

        assert_eq!(bundle.name, "microsoft");
        assert_eq!(bundle.rule_type, RuleType::TeamId);
        assert_eq!(bundle.policy, Policy::Allowlist);
    }

    #[test]
    fn test_bundle_for_team_id() {
        let bundle = Bundle::for_team_id("Google", "EQHXZ8M8AV");
        assert!(bundle.cel_expression.contains("EQHXZ8M8AV"));
        assert_eq!(bundle.rule_type, RuleType::TeamId);
    }

    #[test]
    fn test_bundle_set_by_name() {
        let mut set = BundleSet::new();
        set.add(Bundle::new("microsoft", "cel1"));
        set.add(Bundle::new("google", "cel2"));

        assert!(set.by_name("microsoft").is_some());
        assert!(set.by_name("unknown").is_none());
    }

    #[test]
    fn test_bundle_set_by_priority() {
        let mut set = BundleSet::new();
        set.add(Bundle::new("low", "cel1").with_priority(1));
        set.add(Bundle::new("high", "cel2").with_priority(10));
        set.add(Bundle::new("medium", "cel3").with_priority(5));

        let sorted = set.by_priority();
        assert_eq!(sorted[0].name, "high");
        assert_eq!(sorted[1].name, "medium");
        assert_eq!(sorted[2].name, "low");
    }

    #[test]
    fn test_bundle_set_toml_roundtrip() {
        let mut set = BundleSet::new();
        set.add(
            Bundle::new(
                "microsoft",
                r#"has(app.team_id) && app.team_id == "UBF8T346G9""#,
            )
            .with_description("Microsoft Corporation")
            .with_rule_type(RuleType::TeamId)
            .with_priority(10),
        );

        let toml = set.to_toml().unwrap();
        let parsed = BundleSet::from_toml(&toml).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.bundles()[0].name, "microsoft");
    }
}
