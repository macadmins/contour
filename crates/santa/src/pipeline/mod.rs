//! Pipeline orchestration for end-to-end bundle processing.
//!
//! This module coordinates the full workflow from CSV input to
//! mobileconfig output with all intermediate steps.

mod lock;

pub use lock::{LockEntry, PipelineLock};

use crate::bundle::{
    Bundle, BundleSet, ConflictPolicy, DedupLevel, LayerConfig, OrphanPolicy, PipelineConfig,
    RuleTypeStrategy, StageConfig,
};
use crate::cel::{AppRecord, AppRecordSet};
use crate::coverage::{
    CoverageAnalysis, CoverageAnalyzer, CoverageReport, create_catch_all_bundle,
};
use crate::discovery::parse_fleet_csv_file;
use crate::models::{Rule, RuleSet, RuleType};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// The main pipeline orchestrator.
#[derive(Debug)]
pub struct Pipeline {
    config: PipelineConfig,
}

impl Pipeline {
    /// Create a new pipeline with the given configuration.
    pub fn new(config: PipelineConfig) -> Self {
        Self { config }
    }

    /// Create a pipeline with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PipelineConfig::default())
    }

    /// Run the full pipeline from CSV to rules.
    pub fn run(&self, csv_path: &Path, bundles: &BundleSet) -> Result<PipelineResult> {
        // Phase 1: Parse and normalize
        let mut apps = parse_fleet_csv_file(csv_path).context("Failed to parse Fleet CSV")?;

        let original_count = apps.len();

        // Phase 2: Deduplicate
        self.deduplicate(&mut apps);

        // Phase 3: Prepare bundles (add catch-all if needed)
        let mut working_bundles = bundles.clone();
        if self.config.orphan_policy == OrphanPolicy::CatchAll {
            working_bundles.add(create_catch_all_bundle());
        }

        // Phase 4: Classify
        let analyzer =
            CoverageAnalyzer::new(self.config.orphan_policy, self.config.conflict_policy);
        let analysis = analyzer.analyze(&working_bundles, apps.apps())?;

        // Phase 5: Generate rules
        let rules = self.generate_rules(&analysis, &working_bundles)?;

        // Phase 6: Sort for determinism
        let rules = if self.config.deterministic {
            self.sort_rules(rules)
        } else {
            rules
        };

        Ok(PipelineResult {
            original_app_count: original_count,
            deduplicated_app_count: apps.len(),
            rules,
            analysis,
            config: self.config.clone(),
        })
    }

    /// Run the pipeline with Layer × Stage matrix output.
    ///
    /// This produces separate rule sets for each combination of layer and stage,
    /// respecting inheritance (layers inherit from parent layers) and cascading
    /// (stages include rules from lower-priority stages).
    pub fn run_layer_stage_matrix(
        &self,
        csv_path: &Path,
        bundles: &BundleSet,
    ) -> Result<LayerStageResult> {
        // Get layer and stage configs
        let layer_config = self.config.effective_layers();
        let stage_config = self.config.effective_stages();

        // Run base pipeline first
        let base_result = self.run(csv_path, bundles)?;

        // Group rules by their bundle's layer and stage
        let rules_by_layer_stage = self.partition_rules_by_layer_stage(&base_result.rules, bundles);

        // Generate the Layer × Stage matrix
        let mut profiles = Vec::new();

        for layer in &layer_config.layers {
            // Get all layers this layer inherits from
            let inherited_layers = layer_config.resolve_inheritance(&layer.name);

            for stage in &stage_config.stages {
                // Get all stages this stage includes (cascading)
                let cascading_stages = stage_config.cascading_stages(&stage.name);

                // Collect all rules for this layer × stage combination
                let mut combined_rules = RuleSet::new();

                for inherited_layer in &inherited_layers {
                    for cascading_stage in &cascading_stages {
                        let key = format!("{}:{}", inherited_layer, cascading_stage.name);
                        if let Some(rules) = rules_by_layer_stage.get(&key) {
                            for rule in rules {
                                combined_rules.add(rule.clone());
                            }
                        }
                    }
                }

                // Deduplicate rules (same identifier can come from multiple sources)
                let combined_rules = self.deduplicate_rules(combined_rules);

                let profile = LayerStageProfile::new(
                    &layer.name,
                    &stage.name,
                    combined_rules,
                    &self.config.label_prefix,
                );
                profiles.push(profile);
            }
        }

        Ok(LayerStageResult {
            base_result,
            profiles,
            layer_config,
            stage_config,
        })
    }

    /// Partition rules by their bundle's layer and stage assignment.
    fn partition_rules_by_layer_stage(
        &self,
        rules: &RuleSet,
        bundles: &BundleSet,
    ) -> HashMap<String, Vec<Rule>> {
        let mut result: HashMap<String, Vec<Rule>> = HashMap::new();

        for rule in rules.rules() {
            // Determine layer and stage from the rule's group (bundle name)
            let (layer, stage) = if let Some(group) = &rule.group {
                if let Some(bundle) = bundles.by_name(group) {
                    (
                        bundle.effective_layer().to_string(),
                        bundle.effective_stage().to_string(),
                    )
                } else {
                    ("core".to_string(), "prod".to_string())
                }
            } else {
                ("core".to_string(), "prod".to_string())
            };

            let key = format!("{}:{}", layer, stage);
            result.entry(key).or_default().push(rule.clone());
        }

        result
    }

    /// Remove duplicate rules (same rule_type:identifier).
    fn deduplicate_rules(&self, rules: RuleSet) -> RuleSet {
        let mut seen: HashMap<String, bool> = HashMap::new();
        let mut unique_rules = Vec::new();

        for rule in rules.into_rules() {
            let key = format!("{}:{}", rule.rule_type.as_str(), rule.identifier);
            if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(key) {
                e.insert(true);
                unique_rules.push(rule);
            }
        }

        if self.config.deterministic {
            unique_rules.sort_by(|a, b| {
                let type_cmp = a.rule_type.as_str().cmp(b.rule_type.as_str());
                if type_cmp != std::cmp::Ordering::Equal {
                    return type_cmp;
                }
                a.identifier.cmp(&b.identifier)
            });
        }

        RuleSet::from_rules(unique_rules)
    }

    /// Deduplicate apps based on configuration.
    fn deduplicate(&self, apps: &mut AppRecordSet) {
        match self.config.dedup_level {
            DedupLevel::TeamId => apps.dedup_by_team_id(),
            DedupLevel::SigningId => apps.dedup_by_signing_id(),
            DedupLevel::Binary => apps.dedup_by_sha256(),
            DedupLevel::Adaptive => {
                // Adaptive: group by best available identifier
                // This keeps TeamID apps grouped, SigningID apps grouped, etc.
                apps.dedup_by_signing_id();
            }
        }
    }

    /// Generate Santa rules from classification results.
    fn generate_rules(&self, analysis: &CoverageAnalysis, bundles: &BundleSet) -> Result<RuleSet> {
        let mut rules = RuleSet::new();
        let mut seen_identifiers: HashMap<String, bool> = HashMap::new();

        for result in &analysis.results {
            if result.is_orphan {
                continue;
            }

            let bundle_name = result.selected_bundle.as_ref().unwrap();
            let bundle = bundles.by_name(bundle_name);

            if let Some(bundle) = bundle {
                if let Some(rule) = self.app_to_rule(&result.app, bundle, &mut seen_identifiers) {
                    rules.add(rule);
                }
            }
        }

        Ok(rules)
    }

    /// Convert an app to a Santa rule based on bundle configuration.
    fn app_to_rule(
        &self,
        app: &AppRecord,
        bundle: &Bundle,
        seen: &mut HashMap<String, bool>,
    ) -> Option<Rule> {
        let (rule_type, identifier) = self.select_rule_type(app, bundle)?;

        // Check for duplicates
        let key = format!("{}:{}", rule_type.as_str(), identifier);
        if seen.contains_key(&key) {
            return None;
        }
        seen.insert(key, true);

        let description = format!("{} ({})", app.display_name(), bundle.name);

        let mut rule = Rule::new(rule_type, identifier, bundle.policy)
            .with_description(&description)
            .with_group(&bundle.name);

        // Add Fleet label
        let label = format!("{}{}", self.config.label_prefix, bundle.name);
        rule.labels.push(label);

        Some(rule)
    }

    /// Select rule type and identifier based on strategy.
    fn select_rule_type(&self, app: &AppRecord, bundle: &Bundle) -> Option<(RuleType, String)> {
        match self.config.rule_type_strategy {
            RuleTypeStrategy::Bundle => {
                // Use the rule type specified in the bundle
                match bundle.rule_type {
                    RuleType::TeamId => app.team_id.clone().map(|id| (RuleType::TeamId, id)),
                    RuleType::SigningId => {
                        app.signing_id.clone().map(|id| (RuleType::SigningId, id))
                    }
                    RuleType::Binary => app.sha256.clone().map(|id| (RuleType::Binary, id)),
                    RuleType::Certificate => {
                        app.sha256.clone().map(|id| (RuleType::Certificate, id))
                    }
                    RuleType::Cdhash => app.sha256.clone().map(|id| (RuleType::Cdhash, id)),
                }
            }
            RuleTypeStrategy::PreferTeamId => app
                .team_id
                .clone()
                .map(|id| (RuleType::TeamId, id))
                .or_else(|| app.signing_id.clone().map(|id| (RuleType::SigningId, id)))
                .or_else(|| app.sha256.clone().map(|id| (RuleType::Binary, id))),
            RuleTypeStrategy::PreferSigningId => app
                .signing_id
                .clone()
                .map(|id| (RuleType::SigningId, id))
                .or_else(|| app.team_id.clone().map(|id| (RuleType::TeamId, id)))
                .or_else(|| app.sha256.clone().map(|id| (RuleType::Binary, id))),
            RuleTypeStrategy::BinaryOnly => app.sha256.clone().map(|id| (RuleType::Binary, id)),
        }
    }

    /// Sort rules for deterministic output.
    fn sort_rules(&self, rules: RuleSet) -> RuleSet {
        let mut sorted: Vec<Rule> = rules.into_rules();

        sorted.sort_by(|a, b| {
            // First by rule type
            let type_cmp = a.rule_type.as_str().cmp(b.rule_type.as_str());
            if type_cmp != std::cmp::Ordering::Equal {
                return type_cmp;
            }
            // Then by identifier
            a.identifier.cmp(&b.identifier)
        });

        RuleSet::from_rules(sorted)
    }
}

/// A profile output in the Layer × Stage matrix.
#[derive(Debug, Clone)]
pub struct LayerStageProfile {
    /// Layer name (e.g., "core", "developers")
    pub layer: String,
    /// Stage name (e.g., "prod", "beta", "alpha")
    pub stage: String,
    /// Rules for this layer × stage combination
    pub rules: RuleSet,
    /// Fleet label for this profile
    pub fleet_label: String,
    /// Profile identifier suffix (layer-stage)
    pub identifier_suffix: String,
}

impl LayerStageProfile {
    /// Create a new layer-stage profile.
    pub fn new(layer: &str, stage: &str, rules: RuleSet, label_prefix: &str) -> Self {
        let fleet_label = format!("{}{}-{}", label_prefix, layer, stage);
        let identifier_suffix = format!("{}-{}", layer, stage);
        Self {
            layer: layer.to_string(),
            stage: stage.to_string(),
            rules,
            fleet_label,
            identifier_suffix,
        }
    }

    /// Get display name for this profile.
    pub fn display_name(&self) -> String {
        format!("{} ({})", self.layer, self.stage)
    }
}

/// Result of running the pipeline.
#[derive(Debug)]
pub struct PipelineResult {
    /// Number of apps before deduplication.
    pub original_app_count: usize,
    /// Number of apps after deduplication.
    pub deduplicated_app_count: usize,
    /// Generated Santa rules.
    pub rules: RuleSet,
    /// Coverage analysis.
    pub analysis: CoverageAnalysis,
    /// Pipeline configuration used.
    pub config: PipelineConfig,
}

impl PipelineResult {
    /// Get coverage percentage.
    pub fn coverage_percentage(&self) -> f64 {
        self.analysis.coverage_percentage()
    }

    /// Generate a coverage report.
    pub fn coverage_report(&self) -> CoverageReport {
        self.analysis.to_report()
    }

    /// Get rules grouped by bundle.
    pub fn rules_by_bundle(&self) -> HashMap<String, Vec<&Rule>> {
        let mut by_bundle: HashMap<String, Vec<&Rule>> = HashMap::new();

        for rule in self.rules.rules() {
            if let Some(group) = &rule.group {
                by_bundle.entry(group.clone()).or_default().push(rule);
            }
        }

        by_bundle
    }

    /// Summary statistics.
    pub fn summary(&self) -> PipelineSummary {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_bundle: HashMap<String, usize> = HashMap::new();

        for rule in self.rules.rules() {
            *by_type
                .entry(rule.rule_type.as_str().to_string())
                .or_default() += 1;
            let group = rule.group.clone().unwrap_or_else(|| "(orphan)".to_string());
            *by_bundle.entry(group).or_default() += 1;
        }

        PipelineSummary {
            original_apps: self.original_app_count,
            deduplicated_apps: self.deduplicated_app_count,
            rules_generated: self.rules.len(),
            bundles_used: self.analysis.summary.bundles_used.len(),
            orphans: self.analysis.orphans.len(),
            conflicts: self.analysis.conflicts.len(),
            coverage: self.coverage_percentage(),
            by_type,
            by_bundle,
        }
    }
}

/// Result of running the Layer × Stage matrix pipeline.
#[derive(Debug)]
pub struct LayerStageResult {
    /// The base pipeline result (before matrix splitting).
    pub base_result: PipelineResult,
    /// Profiles for each Layer × Stage combination.
    pub profiles: Vec<LayerStageProfile>,
    /// Layer configuration used.
    pub layer_config: LayerConfig,
    /// Stage configuration used.
    pub stage_config: StageConfig,
}

impl LayerStageResult {
    /// Get summary of the Layer × Stage matrix.
    pub fn summary(&self) -> LayerStageSummary {
        let mut profile_stats = Vec::new();
        let mut total_rules = 0;

        for profile in &self.profiles {
            let rule_count = profile.rules.len();
            total_rules += rule_count;
            profile_stats.push(ProfileStat {
                layer: profile.layer.clone(),
                stage: profile.stage.clone(),
                rules: rule_count,
                fleet_label: profile.fleet_label.clone(),
            });
        }

        LayerStageSummary {
            layers: self
                .layer_config
                .names()
                .into_iter()
                .map(String::from)
                .collect(),
            stages: self
                .stage_config
                .names()
                .into_iter()
                .map(String::from)
                .collect(),
            profiles: profile_stats,
            total_rules,
            base_summary: self.base_result.summary(),
        }
    }

    /// Get profiles for a specific layer.
    pub fn profiles_for_layer(&self, layer: &str) -> Vec<&LayerStageProfile> {
        self.profiles.iter().filter(|p| p.layer == layer).collect()
    }

    /// Get profiles for a specific stage.
    pub fn profiles_for_stage(&self, stage: &str) -> Vec<&LayerStageProfile> {
        self.profiles.iter().filter(|p| p.stage == stage).collect()
    }

    /// Get a specific profile by layer and stage.
    pub fn profile(&self, layer: &str, stage: &str) -> Option<&LayerStageProfile> {
        self.profiles
            .iter()
            .find(|p| p.layer == layer && p.stage == stage)
    }
}

/// Summary of the Layer × Stage matrix output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LayerStageSummary {
    /// All layer names.
    pub layers: Vec<String>,
    /// All stage names.
    pub stages: Vec<String>,
    /// Stats for each profile.
    pub profiles: Vec<ProfileStat>,
    /// Total rules across all profiles (may have overlap due to inheritance).
    pub total_rules: usize,
    /// Base pipeline summary.
    pub base_summary: PipelineSummary,
}

/// Statistics for a single profile.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfileStat {
    /// Layer name.
    pub layer: String,
    /// Stage name.
    pub stage: String,
    /// Number of rules in this profile.
    pub rules: usize,
    /// Fleet label for this profile.
    pub fleet_label: String,
}

/// Pipeline summary statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PipelineSummary {
    pub original_apps: usize,
    pub deduplicated_apps: usize,
    pub rules_generated: usize,
    pub bundles_used: usize,
    pub orphans: usize,
    pub conflicts: usize,
    pub coverage: f64,
    /// Rule count by type (TEAMID, BINARY, SIGNINGID, etc.)
    pub by_type: HashMap<String, usize>,
    /// Rule count by bundle/group
    pub by_bundle: HashMap<String, usize>,
}

/// Builder for creating pipeline with fluent API.
#[derive(Debug)]
pub struct PipelineBuilder {
    config: PipelineConfig,
}

impl PipelineBuilder {
    /// Create a new pipeline builder.
    pub fn new() -> Self {
        Self {
            config: PipelineConfig::default(),
        }
    }

    /// Set deduplication level.
    pub fn dedup_level(mut self, level: DedupLevel) -> Self {
        self.config.dedup_level = level;
        self
    }

    /// Set orphan policy.
    pub fn orphan_policy(mut self, policy: OrphanPolicy) -> Self {
        self.config.orphan_policy = policy;
        self
    }

    /// Set conflict policy.
    pub fn conflict_policy(mut self, policy: ConflictPolicy) -> Self {
        self.config.conflict_policy = policy;
        self
    }

    /// Set rule type strategy.
    pub fn rule_type_strategy(mut self, strategy: RuleTypeStrategy) -> Self {
        self.config.rule_type_strategy = strategy;
        self
    }

    /// Enable deterministic output.
    pub fn deterministic(mut self, value: bool) -> Self {
        self.config.deterministic = value;
        self
    }

    /// Set organization identifier.
    pub fn org(mut self, org: impl Into<String>) -> Self {
        self.config.org = org.into();
        self
    }

    /// Set label prefix.
    pub fn label_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.label_prefix = prefix.into();
        self
    }

    /// Set layer configuration.
    pub fn layers(mut self, layers: LayerConfig) -> Self {
        self.config.layers = Some(layers);
        self
    }

    /// Set stage configuration.
    pub fn stages(mut self, stages: StageConfig) -> Self {
        self.config.stages = Some(stages);
        self
    }

    /// Enable Layer × Stage matrix output.
    pub fn enable_layer_stage_matrix(mut self, enable: bool) -> Self {
        self.config.enable_layer_stage_matrix = enable;
        self
    }

    /// Configure for Layer × Stage matrix with standard configs.
    pub fn with_layer_stage_matrix(self) -> Self {
        self.layers(LayerConfig::standard())
            .stages(StageConfig::default())
            .enable_layer_stage_matrix(true)
    }

    /// Build the pipeline.
    pub fn build(self) -> Pipeline {
        Pipeline::new(self.config)
    }
}

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_builder() {
        let pipeline = PipelineBuilder::new()
            .dedup_level(DedupLevel::TeamId)
            .orphan_policy(OrphanPolicy::Warn)
            .deterministic(true)
            .build();

        assert_eq!(pipeline.config.dedup_level, DedupLevel::TeamId);
        assert_eq!(pipeline.config.orphan_policy, OrphanPolicy::Warn);
        assert!(pipeline.config.deterministic);
    }
}
