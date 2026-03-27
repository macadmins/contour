//! Fleet GitOps output format
//!
//! Generates Fleet-compatible directory structure with:
//! - profiles/ directory with mobileconfig files
//! - team files with profile references and labels

use crate::generator::{GeneratorOptions, generate};
use crate::models::{ProfileCategory, ProfileNaming, Ring, RingConfig, RuleCategory, RuleSet};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Fleet profile reference in team file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetProfile {
    /// Path to the mobileconfig file (relative to gitops root)
    pub path: String,

    /// Labels to target this profile (e.g., ring:0, ring:1)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

/// Fleet team configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetTeam {
    /// Team name
    pub name: String,

    /// macOS profiles for this team
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub macos_profiles: Vec<FleetProfile>,
}

/// Fleet GitOps manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetManifest {
    /// Fleets configuration
    #[serde(default)]
    pub fleets: Vec<FleetTeam>,
}

/// Result of Fleet generation
#[derive(Debug)]
pub struct FleetGenerationResult {
    pub profiles_written: usize,
    pub manifest_path: String,
    pub profile_paths: Vec<String>,
}

/// Configuration for Fleet output generation
#[derive(Debug, Clone)]
pub struct FleetOutputConfig {
    /// Organization identifier prefix
    pub org: String,
    /// Profile name prefix
    pub prefix: String,
    /// Team name for profiles
    pub team_name: String,
    /// Ring configuration
    pub ring_config: RingConfig,
    /// Base path for profiles in manifest (e.g., "platforms/profiles")
    pub profiles_base_path: String,
    /// Use deterministic UUIDs
    pub deterministic_uuids: bool,
}

impl Default for FleetOutputConfig {
    fn default() -> Self {
        let layout = contour_core::fleet_layout::FleetLayout::default();
        Self {
            org: "com.example".to_string(),
            prefix: "santa".to_string(),
            team_name: "Workstations".to_string(),
            ring_config: RingConfig::standard_five_rings(),
            profiles_base_path: format!("{}/profiles", layout.platforms_dir),
            deterministic_uuids: true,
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

    let mut profile_paths = Vec::new();
    let mut fleet_profiles = Vec::new();

    for ring in config.ring_config.rings_by_priority() {
        let ring_rules = rules.by_ring(&ring.name);
        if ring_rules.is_empty() {
            continue;
        }

        // Generate profiles for each category
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

            let profile_name = naming.generate(ring.priority, *profile_cat);
            let identifier = naming.generate_identifier(&config.org, ring.priority, *profile_cat);
            let filename = format!("{}.mobileconfig", profile_name);
            let filepath = profiles_dir.join(&filename);

            // Generate mobileconfig
            let options = GeneratorOptions::new(&config.org)
                .with_identifier(&identifier)
                .with_display_name(&format!(
                    "{} - Ring {}",
                    profile_cat.display_name(),
                    ring.priority + 1
                ))
                .with_deterministic_uuids(config.deterministic_uuids);

            let content = generate(&category_rules, &options)?;
            std::fs::write(&filepath, content)
                .with_context(|| format!("Failed to write profile: {}", filepath.display()))?;

            let relative_path = format!("{}/{}", config.profiles_base_path, filename);
            profile_paths.push(relative_path.clone());

            // Add to Fleet profiles with ring labels
            fleet_profiles.push(FleetProfile {
                path: relative_path,
                labels: ring.fleet_labels.clone(),
            });
        }
    }

    // Generate Fleet manifest
    let manifest = FleetManifest {
        fleets: vec![FleetTeam {
            name: config.team_name.clone(),
            macos_profiles: fleet_profiles,
        }],
    };

    let manifest_path = output_dir.join("default.yml");
    let manifest_yaml = yaml_serde::to_string(&manifest)?;
    std::fs::write(&manifest_path, manifest_yaml)
        .with_context(|| format!("Failed to write manifest: {}", manifest_path.display()))?;

    Ok(FleetGenerationResult {
        profiles_written: profile_paths.len(),
        manifest_path: manifest_path.display().to_string(),
        profile_paths,
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

        assert!(result.profiles_written > 0);
        assert!(tmp_dir.path().join("default.yml").exists());
        assert!(tmp_dir.path().join("platforms/profiles").exists());
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
