//! Layer and Stage models for two-dimensional rule organization.
//!
//! Layers represent audience groupings (Core, Developers, Finance).
//! Stages represent rollout phases (Alpha, Beta, Prod).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A layer represents an audience or purpose grouping.
///
/// Examples: Core (all machines), Developers, Finance, Security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    /// Unique name for this layer
    pub name: String,

    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Layers this one inherits from (e.g., developers inherits core)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inherits: Vec<String>,
}

impl Layer {
    /// Create a new layer.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            inherits: Vec::new(),
        }
    }

    /// Builder: set description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Builder: add inheritance.
    #[must_use]
    pub fn inherits_from(mut self, layer: impl Into<String>) -> Self {
        self.inherits.push(layer.into());
        self
    }
}

/// A stage represents a rollout phase for risk mitigation.
///
/// Stages cascade: Alpha includes Beta + Prod, Beta includes Prod.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Stage {
    /// Unique name for this stage
    pub name: String,

    /// Priority (higher = earlier in rollout, gets more rules)
    /// Alpha=100, Beta=50, Prod=0
    pub priority: i32,

    /// Fleet label for this stage
    pub fleet_label: String,
}

impl Stage {
    /// Create a new stage.
    pub fn new(name: impl Into<String>, priority: i32) -> Self {
        let name = name.into();
        let name_lower = name.to_lowercase();
        let fleet_label = format!("santa-stage:{name_lower}");
        Self {
            name,
            priority,
            fleet_label,
        }
    }

    /// Builder: set fleet label.
    #[must_use]
    pub fn with_fleet_label(mut self, label: impl Into<String>) -> Self {
        self.fleet_label = label.into();
        self
    }
}

/// Standard stage configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageConfig {
    /// Available stages, ordered by priority (highest first)
    pub stages: Vec<Stage>,
}

impl Default for StageConfig {
    fn default() -> Self {
        Self::three_stages()
    }
}

impl StageConfig {
    /// Standard 3-stage rollout: Alpha → Beta → Prod
    pub fn three_stages() -> Self {
        Self {
            stages: vec![
                Stage::new("alpha", 100),
                Stage::new("beta", 50),
                Stage::new("prod", 0),
            ],
        }
    }

    /// 5-stage rollout for larger organizations
    pub fn five_stages() -> Self {
        Self {
            stages: vec![
                Stage::new("canary", 100),
                Stage::new("alpha", 80),
                Stage::new("beta", 60),
                Stage::new("early", 40),
                Stage::new("prod", 0),
            ],
        }
    }

    /// Simple 2-stage: Test → Prod
    pub fn two_stages() -> Self {
        Self {
            stages: vec![Stage::new("test", 100), Stage::new("prod", 0)],
        }
    }

    /// Get stage by name.
    pub fn get(&self, name: &str) -> Option<&Stage> {
        self.stages
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }

    /// Get stages that should be included for a given stage (cascading).
    ///
    /// E.g., for "beta", returns ["beta", "prod"] (beta includes prod rules).
    /// For "alpha", returns ["alpha", "beta", "prod"].
    pub fn cascading_stages(&self, stage_name: &str) -> Vec<&Stage> {
        let target_priority = self.get(stage_name).map(|s| s.priority).unwrap_or(0);

        self.stages
            .iter()
            .filter(|s| s.priority <= target_priority)
            .collect()
    }

    /// Get all stage names.
    pub fn names(&self) -> Vec<&str> {
        self.stages.iter().map(|s| s.name.as_str()).collect()
    }
}

/// Layer configuration with inheritance resolution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LayerConfig {
    /// Defined layers
    #[serde(default)]
    pub layers: Vec<Layer>,
}

impl LayerConfig {
    /// Create a new layer config.
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// Add a layer.
    pub fn add(&mut self, layer: Layer) {
        self.layers.push(layer);
    }

    /// Get layer by name.
    pub fn get(&self, name: &str) -> Option<&Layer> {
        self.layers
            .iter()
            .find(|l| l.name.eq_ignore_ascii_case(name))
    }

    /// Resolve inheritance for a layer, returning all layers it includes.
    ///
    /// E.g., for "developers" which inherits "core", returns ["developers", "core"].
    pub fn resolve_inheritance(&self, layer_name: &str) -> Vec<String> {
        let mut result = vec![layer_name.to_string()];
        let mut to_process = vec![layer_name.to_string()];
        let mut seen = std::collections::HashSet::new();
        seen.insert(layer_name.to_string());

        while let Some(current) = to_process.pop() {
            if let Some(layer) = self.get(&current) {
                for inherited in &layer.inherits {
                    if seen.insert(inherited.clone()) {
                        result.push(inherited.clone());
                        to_process.push(inherited.clone());
                    }
                }
            }
        }

        result
    }

    /// Standard layer config for most organizations.
    pub fn standard() -> Self {
        Self {
            layers: vec![
                Layer::new("core").with_description("Essential apps for all machines"),
                Layer::new("developers")
                    .with_description("Development tools")
                    .inherits_from("core"),
                Layer::new("finance")
                    .with_description("Finance department apps")
                    .inherits_from("core"),
                Layer::new("security")
                    .with_description("Security team tools")
                    .inherits_from("core"),
            ],
        }
    }

    /// Get all layer names.
    pub fn names(&self) -> Vec<&str> {
        self.layers.iter().map(|l| l.name.as_str()).collect()
    }
}

/// Combined layer and stage assignment for a bundle or rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LayerStageAssignment {
    /// Layer this belongs to (e.g., "core", "developers")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,

    /// Stage this belongs to (e.g., "prod", "beta", "alpha")
    /// If not specified, defaults to "prod"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
}

impl LayerStageAssignment {
    /// Create a new assignment.
    pub fn new(layer: impl Into<String>, stage: impl Into<String>) -> Self {
        Self {
            layer: Some(layer.into()),
            stage: Some(stage.into()),
        }
    }

    /// Create assignment for a layer (defaults to prod stage).
    pub fn for_layer(layer: impl Into<String>) -> Self {
        Self {
            layer: Some(layer.into()),
            stage: None,
        }
    }

    /// Get the effective stage (defaults to "prod").
    pub fn effective_stage(&self) -> &str {
        self.stage.as_deref().unwrap_or("prod")
    }

    /// Get the effective layer (defaults to "core").
    pub fn effective_layer(&self) -> &str {
        self.layer.as_deref().unwrap_or("core")
    }
}

/// Mapping of team IDs to layers (simple format from design doc).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LayerMappings {
    /// Simple format: layer name -> list of team IDs
    #[serde(flatten)]
    pub mappings: HashMap<String, Vec<String>>,
}

impl LayerMappings {
    /// Create empty mappings.
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    /// Add a team ID to a layer.
    pub fn add(&mut self, layer: &str, team_id: &str) {
        self.mappings
            .entry(layer.to_string())
            .or_default()
            .push(team_id.to_string());
    }

    /// Get the layer for a team ID.
    pub fn layer_for_team_id(&self, team_id: &str) -> Option<&str> {
        for (layer, team_ids) in &self.mappings {
            if team_ids.iter().any(|t| t == team_id) {
                return Some(layer.as_str());
            }
        }
        None
    }

    /// Get all team IDs for a layer.
    pub fn team_ids_for_layer(&self, layer: &str) -> Vec<&str> {
        self.mappings
            .get(layer)
            .map_or_else(Vec::new, |ids| ids.iter().map(String::as_str).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_cascading() {
        let config = StageConfig::three_stages();

        let alpha_stages = config.cascading_stages("alpha");
        assert_eq!(alpha_stages.len(), 3); // alpha, beta, prod

        let beta_stages = config.cascading_stages("beta");
        assert_eq!(beta_stages.len(), 2); // beta, prod

        let prod_stages = config.cascading_stages("prod");
        assert_eq!(prod_stages.len(), 1); // prod only
    }

    #[test]
    fn test_layer_inheritance() {
        let config = LayerConfig::standard();

        let dev_layers = config.resolve_inheritance("developers");
        assert!(dev_layers.contains(&"developers".to_string()));
        assert!(dev_layers.contains(&"core".to_string()));

        let core_layers = config.resolve_inheritance("core");
        assert_eq!(core_layers.len(), 1);
        assert!(core_layers.contains(&"core".to_string()));
    }

    #[test]
    fn test_layer_mappings() {
        let mut mappings = LayerMappings::new();
        mappings.add("core", "EQHXZ8M8AV");
        mappings.add("core", "UBF8T346G9");
        mappings.add("developers", "5JLMAQMNFZ");

        assert_eq!(mappings.layer_for_team_id("EQHXZ8M8AV"), Some("core"));
        assert_eq!(mappings.layer_for_team_id("5JLMAQMNFZ"), Some("developers"));
        assert_eq!(mappings.layer_for_team_id("UNKNOWN"), None);
    }
}
