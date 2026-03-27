//! Bundle configuration and policy settings.
//!
//! These settings control how the bundling pipeline behaves for
//! deduplication, orphan handling, conflicts, and rule type selection.

use super::layers::{LayerConfig, StageConfig};
use serde::{Deserialize, Serialize};

/// Deduplication level for apps across devices.
///
/// Controls how apps are grouped when the same software appears
/// on multiple devices with different hashes (version drift).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum DedupLevel {
    /// Group by TeamID - vendor-level rules (least maintenance)
    TeamId,
    /// Group by SigningID - app-level rules (balanced)
    #[default]
    SigningId,
    /// Group by SHA256 hash - binary-level rules (most specific, high churn)
    Binary,
    /// Use highest available identifier (adaptive)
    /// Prefers TeamID > SigningID > Binary
    Adaptive,
}

impl DedupLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            DedupLevel::TeamId => "team_id",
            DedupLevel::SigningId => "signing_id",
            DedupLevel::Binary => "binary",
            DedupLevel::Adaptive => "adaptive",
        }
    }
}

impl std::fmt::Display for DedupLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Policy for handling apps that match no bundle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum OrphanPolicy {
    /// Create an "uncategorized" bundle for orphan apps
    #[default]
    CatchAll,
    /// Log a warning and continue processing
    Warn,
    /// Fail the build if any orphans exist
    Error,
    /// Silently ignore orphan apps
    Ignore,
}

impl OrphanPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrphanPolicy::CatchAll => "catch_all",
            OrphanPolicy::Warn => "warn",
            OrphanPolicy::Error => "error",
            OrphanPolicy::Ignore => "ignore",
        }
    }
}

impl std::fmt::Display for OrphanPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Policy for handling apps that match multiple bundles.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    /// First matching bundle wins (order matters)
    FirstMatch,
    /// Most specific match wins (SigningID > TeamID > pattern)
    #[default]
    MostSpecific,
    /// Use priority numbers on bundles (highest wins)
    Priority,
    /// Fail on any conflict
    Error,
}

impl ConflictPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConflictPolicy::FirstMatch => "first_match",
            ConflictPolicy::MostSpecific => "most_specific",
            ConflictPolicy::Priority => "priority",
            ConflictPolicy::Error => "error",
        }
    }
}

impl std::fmt::Display for ConflictPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Strategy for selecting rule type when generating Santa rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RuleTypeStrategy {
    /// Use the rule type specified in the bundle
    #[default]
    Bundle,
    /// Always emit TeamID rules when available
    PreferTeamId,
    /// Always emit SigningID rules when available
    PreferSigningId,
    /// Always emit binary hash rules
    BinaryOnly,
}

impl RuleTypeStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleTypeStrategy::Bundle => "bundle",
            RuleTypeStrategy::PreferTeamId => "prefer_team_id",
            RuleTypeStrategy::PreferSigningId => "prefer_signing_id",
            RuleTypeStrategy::BinaryOnly => "binary_only",
        }
    }
}

impl std::fmt::Display for RuleTypeStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Configuration for a bundle file.
///
/// This is the top-level structure for bundles.toml files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BundleConfig {
    /// Discovery settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoveryConfig>,

    /// Pipeline settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline: Option<PipelineConfig>,
}

/// Discovery phase configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Minimum device coverage percentage to include in suggestions (0.0 - 1.0)
    #[serde(default = "default_threshold")]
    pub threshold: f64,

    /// Minimum number of apps from a vendor to suggest a bundle
    #[serde(default = "default_min_apps")]
    pub min_apps: usize,

    /// Include unsigned apps in discovery
    #[serde(default)]
    pub include_unsigned: bool,
}

fn default_threshold() -> f64 {
    0.05 // 5% of fleet
}

fn default_min_apps() -> usize {
    1
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            threshold: default_threshold(),
            min_apps: default_min_apps(),
            include_unsigned: false,
        }
    }
}

/// Pipeline phase configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Deduplication level
    #[serde(default)]
    pub dedup_level: DedupLevel,

    /// Orphan handling policy
    #[serde(default)]
    pub orphan_policy: OrphanPolicy,

    /// Conflict resolution policy
    #[serde(default)]
    pub conflict_policy: ConflictPolicy,

    /// Rule type selection strategy
    #[serde(default)]
    pub rule_type_strategy: RuleTypeStrategy,

    /// Enable deterministic output (sorted, reproducible)
    #[serde(default = "default_deterministic")]
    pub deterministic: bool,

    /// Organization identifier prefix for generated profiles
    #[serde(default = "default_org")]
    pub org: String,

    /// Label prefix for Fleet integration
    #[serde(default = "default_label_prefix")]
    pub label_prefix: String,

    /// Layer configuration for audience-based grouping
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layers: Option<LayerConfig>,

    /// Stage configuration for rollout phases
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stages: Option<StageConfig>,

    /// Enable layer × stage output matrix (generates multiple profiles per layer per stage)
    #[serde(default)]
    pub enable_layer_stage_matrix: bool,
}

fn default_deterministic() -> bool {
    true
}

fn default_org() -> String {
    "com.example".to_string()
}

fn default_label_prefix() -> String {
    "santa-".to_string()
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            dedup_level: DedupLevel::default(),
            orphan_policy: OrphanPolicy::default(),
            conflict_policy: ConflictPolicy::default(),
            rule_type_strategy: RuleTypeStrategy::default(),
            deterministic: default_deterministic(),
            org: default_org(),
            label_prefix: default_label_prefix(),
            layers: None,
            stages: None,
            enable_layer_stage_matrix: false,
        }
    }
}

impl PipelineConfig {
    /// Create a pipeline config with common production defaults.
    pub fn production() -> Self {
        Self {
            dedup_level: DedupLevel::SigningId,
            orphan_policy: OrphanPolicy::Error,
            conflict_policy: ConflictPolicy::MostSpecific,
            rule_type_strategy: RuleTypeStrategy::Bundle,
            deterministic: true,
            org: "com.example".to_string(),
            label_prefix: "santa-".to_string(),
            layers: Some(LayerConfig::standard()),
            stages: Some(StageConfig::default()),
            enable_layer_stage_matrix: true,
        }
    }

    /// Create a pipeline config for development/testing.
    pub fn development() -> Self {
        Self {
            dedup_level: DedupLevel::Adaptive,
            orphan_policy: OrphanPolicy::Warn,
            conflict_policy: ConflictPolicy::MostSpecific,
            rule_type_strategy: RuleTypeStrategy::Bundle,
            deterministic: true,
            org: "com.example".to_string(),
            label_prefix: "santa-".to_string(),
            layers: None,
            stages: None,
            enable_layer_stage_matrix: false,
        }
    }

    /// Create a pipeline config with layer × stage matrix enabled.
    pub fn with_layer_stage_matrix() -> Self {
        Self {
            layers: Some(LayerConfig::standard()),
            stages: Some(StageConfig::default()),
            enable_layer_stage_matrix: true,
            ..Self::default()
        }
    }

    /// Get the effective layer config (standard if not specified).
    pub fn effective_layers(&self) -> LayerConfig {
        self.layers.clone().unwrap_or_else(LayerConfig::standard)
    }

    /// Get the effective stage config (three_stages if not specified).
    pub fn effective_stages(&self) -> StageConfig {
        self.stages.clone().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_level_display() {
        assert_eq!(DedupLevel::TeamId.to_string(), "team_id");
        assert_eq!(DedupLevel::SigningId.to_string(), "signing_id");
        assert_eq!(DedupLevel::Binary.to_string(), "binary");
        assert_eq!(DedupLevel::Adaptive.to_string(), "adaptive");
    }

    #[test]
    fn test_orphan_policy_display() {
        assert_eq!(OrphanPolicy::CatchAll.to_string(), "catch_all");
        assert_eq!(OrphanPolicy::Error.to_string(), "error");
    }

    #[test]
    fn test_pipeline_config_defaults() {
        let config = PipelineConfig::default();
        assert_eq!(config.dedup_level, DedupLevel::SigningId);
        assert_eq!(config.orphan_policy, OrphanPolicy::CatchAll);
        assert!(config.deterministic);
    }

    #[test]
    fn test_config_serialization() {
        let config = PipelineConfig::production();
        let toml = toml::to_string_pretty(&config).unwrap();
        assert!(toml.contains("dedup_level"));
        assert!(toml.contains("orphan_policy"));
    }
}
