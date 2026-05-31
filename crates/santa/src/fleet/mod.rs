//! Fleet GitOps output format
//!
//! Generates Fleet-compatible directory structure with:
//! - profiles/ directory with mobileconfig files
//! - fleet files with profile references and labels

use crate::generator::{GeneratorOptions, generate};
use crate::models::{ProfileCategory, ProfileNaming, Ring, RingConfig, RuleCategory, RuleSet};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Fleet profile reference in a fleet config file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetProfile {
    /// Path to the mobileconfig file (relative to gitops root)
    pub path: String,

    /// Labels to target this profile (e.g., ring:0, ring:1)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

/// A single fleet's configuration entry within the GitOps manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    /// Fleet name
    pub name: String,

    /// macOS profiles for this fleet
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub macos_profiles: Vec<FleetProfile>,
}

/// Fleet GitOps manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetManifest {
    /// Fleets configuration
    #[serde(default)]
    pub fleets: Vec<FleetConfig>,
}

/// One emitted edition (per ring × category × split-part) from the Fleet generator.
#[derive(Debug, Clone)]
pub struct FleetEdition {
    pub ring: String,
    pub category: String,
    pub filename: String,
    pub rules_count: usize,
    pub part: Option<usize>,
    pub fleet_labels: Vec<String>,
}

/// Result of Fleet generation
#[derive(Debug)]
pub struct FleetGenerationResult {
    pub manifest_path: String,
    pub editions: Vec<FleetEdition>,
}

/// Configuration for Fleet output generation
#[derive(Debug, Clone)]
pub struct FleetOutputConfig {
    /// Organization identifier prefix
    pub org: String,
    /// Profile name prefix
    pub prefix: String,
    /// Fleet name for profiles
    pub fleet_name: String,
    /// Ring configuration
    pub ring_config: RingConfig,
    /// Base path for profiles in manifest (e.g., "platforms/profiles")
    pub profiles_base_path: String,
    /// Use deterministic UUIDs
    pub deterministic_uuids: bool,
    /// Maximum rules per edition (splits into santa1a-001, santa1a-002, ...)
    pub max_rules: Option<usize>,
}

impl Default for FleetOutputConfig {
    fn default() -> Self {
        let layout = contour_core::fleet_layout::FleetLayout::default();
        Self {
            org: "com.example".to_string(),
            prefix: "santa".to_string(),
            fleet_name: "Workstations".to_string(),
            ring_config: RingConfig::standard_five_rings(),
            profiles_base_path: format!("{}/profiles", layout.platforms_dir),
            deterministic_uuids: true,
            max_rules: None,
        }
    }
}

/// Generate Fleet GitOps output
pub fn generate_fleet_output(
    rules: &RuleSet,
    config: &FleetOutputConfig,
    output_dir: &Path,
) -> Result<FleetGenerationResult> {
    let naming = ProfileNaming::new(&config.prefix);
    let profiles_dir = output_dir.join(&config.profiles_base_path);
    std::fs::create_dir_all(&profiles_dir).with_context(|| {
        format!(
            "Failed to create profiles directory: {}",
            profiles_dir.display()
        )
    })?;

    let mut editions = Vec::new();
    let mut fleet_profiles = Vec::new();

    for ring in config.ring_config.rings_by_priority() {
        let ring_rules = rules.by_ring(&ring.name);
        if ring_rules.is_empty() {
            continue;
        }

        for profile_cat in ProfileCategory::all() {
            let rule_cat = match profile_cat {
                ProfileCategory::Software => RuleCategory::Software,
                ProfileCategory::Cel => RuleCategory::Cel,
                ProfileCategory::Faa => RuleCategory::Faa,
            };

            let category_rules = ring_rules.by_category(rule_cat);
            if category_rules.is_empty() {
                continue;
            }

            let chunks = category_rules.split_into_chunks(config.max_rules);
            let needs_split = chunks.len() > 1;

            for (idx, chunk_rules) in chunks.iter().enumerate() {
                let part = idx + 1;
                let (profile_name, identifier, display_name) = if needs_split {
                    (
                        naming.generate_split(ring.priority, *profile_cat, part),
                        naming.generate_identifier_split(
                            &config.org,
                            ring.priority,
                            *profile_cat,
                            part,
                        ),
                        format!(
                            "{} - Ring {} (Part {})",
                            profile_cat.display_name(),
                            ring.priority + 1,
                            part
                        ),
                    )
                } else {
                    (
                        naming.generate(ring.priority, *profile_cat),
                        naming.generate_identifier(&config.org, ring.priority, *profile_cat),
                        format!(
                            "{} - Ring {}",
                            profile_cat.display_name(),
                            ring.priority + 1
                        ),
                    )
                };

                let filename = format!("{profile_name}.mobileconfig");
                let filepath = profiles_dir.join(&filename);

                let options = GeneratorOptions::new(&config.org)
                    .with_identifier(&identifier)
                    .with_display_name(&display_name)
                    .with_deterministic_uuids(config.deterministic_uuids);

                let content = generate(chunk_rules, &options)?;
                std::fs::write(&filepath, content)
                    .with_context(|| format!("Failed to write profile: {}", filepath.display()))?;

                let relative_path = format!("{}/{}", config.profiles_base_path, filename);

                fleet_profiles.push(FleetProfile {
                    path: relative_path,
                    labels: ring.fleet_labels.clone(),
                });

                editions.push(FleetEdition {
                    ring: ring.name.clone(),
                    category: profile_cat.display_name().to_string(),
                    filename,
                    rules_count: chunk_rules.len(),
                    part: if needs_split { Some(part) } else { None },
                    fleet_labels: ring.fleet_labels.clone(),
                });
            }
        }
    }

    // Generate Fleet manifest
    let manifest = FleetManifest {
        fleets: vec![FleetConfig {
            name: config.fleet_name.clone(),
            macos_profiles: fleet_profiles,
        }],
    };

    let manifest_path = output_dir.join("default.yml");
    let manifest_yaml = yaml_serde::to_string(&manifest)?;
    std::fs::write(&manifest_path, manifest_yaml)
        .with_context(|| format!("Failed to write manifest: {}", manifest_path.display()))?;

    Ok(FleetGenerationResult {
        manifest_path: manifest_path.display().to_string(),
        editions,
    })
}

/// Generate labels for Fleet targeting based on ring
pub fn ring_to_fleet_labels(ring: &Ring) -> Vec<String> {
    if ring.fleet_labels.is_empty() {
        // Default label format
        vec![format!("ring:{}", ring.priority)]
    } else {
        ring.fleet_labels.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Policy, Rule, RuleType};
    use tempfile::TempDir;

    #[test]
    fn test_fleet_profile_serialization() {
        let profile = FleetProfile {
            path: "platforms/profiles/santa1a.mobileconfig".to_string(),
            labels: vec!["ring:0".to_string()],
        };

        let yaml = yaml_serde::to_string(&profile).unwrap();
        assert!(yaml.contains("path:"));
        assert!(yaml.contains("labels:"));
    }

    #[test]
    fn test_generate_fleet_output() {
        let tmp_dir = TempDir::new().unwrap();
        let mut rules = RuleSet::new();
        rules.add(Rule::new(RuleType::TeamId, "EQHXZ8M8AV", Policy::Allowlist));

        let config = FleetOutputConfig::default();
        let result = generate_fleet_output(&rules, &config, tmp_dir.path()).unwrap();

        assert!(!result.editions.is_empty());
        assert!(tmp_dir.path().join("default.yml").exists());
        assert!(tmp_dir.path().join("platforms/profiles").exists());
    }

    #[test]
    fn test_generate_fleet_output_splits_on_max_rules() {
        let tmp_dir = TempDir::new().unwrap();
        let mut rules = RuleSet::new();
        for i in 0..5u32 {
            // 10-char team IDs so the generator stays happy
            let id = format!("TEAM{i:0>6}");
            let mut rule = Rule::new(RuleType::TeamId, id, Policy::Allowlist);
            rule.rings = vec!["ring0".to_string()];
            rules.add(rule);
        }
        let config = FleetOutputConfig {
            max_rules: Some(2),
            ..FleetOutputConfig::default()
        };
        let result = generate_fleet_output(&rules, &config, tmp_dir.path()).unwrap();

        let parts: Vec<_> = result
            .editions
            .iter()
            .filter(|e| e.part.is_some())
            .collect();
        assert_eq!(parts.len(), 3, "5 rules / max 2 → 3 parts");
    }

    #[test]
    fn test_ring_to_fleet_labels() {
        let ring = Ring::new("ring0", 0);
        let labels = ring_to_fleet_labels(&ring);
        assert_eq!(labels, vec!["ring:0"]);

        let ring_with_labels = Ring::new("canary", 0)
            .with_fleet_labels(vec!["deployment:canary".to_string(), "ring:0".to_string()]);
        let labels = ring_to_fleet_labels(&ring_with_labels);
        assert_eq!(labels.len(), 2);
    }
}
