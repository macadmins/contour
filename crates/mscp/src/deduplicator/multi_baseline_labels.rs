use crate::deduplicator::shared_library::DeduplicationMapping;
use crate::models::Platform;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Multi-baseline label generator
#[derive(Debug)]
pub struct MultiBaselineLabelGenerator {
    /// Output base path
    output_base: PathBuf,
}

/// Label for a shared profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedProfileLabel {
    /// Label name (e.g., "mscp-shared-firewall")
    pub name: String,

    /// Description
    pub description: String,

    /// Label type
    pub label_membership_type: String,

    /// Platform (darwin, ios, etc.)
    pub platform: String,

    /// Query to match hosts
    pub query: String,
}

impl MultiBaselineLabelGenerator {
    /// Create a new multi-baseline label generator
    pub fn new<P: AsRef<Path>>(output_base: P) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
        }
    }

    /// Generate labels for shared profiles
    pub fn generate_shared_labels(
        &self,
        mapping: &DeduplicationMapping,
        platform: Platform,
    ) -> Result<Vec<SharedProfileLabel>> {
        let mut labels = Vec::new();

        // Get all unique shared profiles
        for canonical_filename in mapping.shared_profiles.keys() {
            // Find which baselines use this profile
            let baselines = self.find_baselines_for_shared_profile(mapping, canonical_filename);

            if baselines.len() > 1 {
                // Create a shared label for this profile
                let label = self.create_shared_label(canonical_filename, &baselines, platform)?;
                labels.push(label);
            }
        }

        Ok(labels)
    }

    /// Find all baselines that use a specific shared profile
    fn find_baselines_for_shared_profile(
        &self,
        mapping: &DeduplicationMapping,
        canonical_filename: &str,
    ) -> Vec<String> {
        let mut baselines = Vec::new();

        for profiles in mapping.baseline_mappings.values() {
            for profile_mapping in profiles.values() {
                if profile_mapping.shared_path.ends_with(canonical_filename) {
                    baselines.extend(profile_mapping.baselines.clone());
                    break;
                }
            }
        }

        // Deduplicate
        baselines.sort();
        baselines.dedup();
        baselines
    }

    /// Create a shared label for a profile
    fn create_shared_label(
        &self,
        canonical_filename: &str,
        baselines: &[String],
        platform: Platform,
    ) -> Result<SharedProfileLabel> {
        // Generate label name from filename
        // e.g., "com.apple.security.firewall.mobileconfig" -> "mscp-shared-firewall"
        let label_name = self.generate_label_name(canonical_filename);

        // Generate description
        let description = format!(
            "Hosts that should receive {} (used by: {})",
            canonical_filename,
            baselines.join(", ")
        );

        // Create query that matches any of the baseline labels
        let baseline_labels: Vec<String> = baselines.iter().map(|b| format!("mscp-{b}")).collect();

        let query = if baseline_labels.len() == 1 {
            format!(
                "SELECT 1 FROM osquery_labels WHERE name = '{}';",
                baseline_labels[0]
            )
        } else {
            let conditions: Vec<String> = baseline_labels
                .iter()
                .map(|label| format!("name = '{label}'"))
                .collect();
            format!(
                "SELECT 1 FROM osquery_labels WHERE {} LIMIT 1;",
                conditions.join(" OR ")
            )
        };

        Ok(SharedProfileLabel {
            name: label_name,
            description,
            label_membership_type: "dynamic".to_string(),
            platform: platform.to_fleet_label_platform().to_string(),
            query,
        })
    }

    /// Generate a label name from a filename
    fn generate_label_name(&self, filename: &str) -> String {
        // Remove .mobileconfig extension
        let name = filename.trim_end_matches(".mobileconfig");

        // Extract meaningful part from reverse domain notation
        // e.g., "com.apple.security.firewall" -> "firewall"
        let parts: Vec<&str> = name.split('.').collect();
        let meaningful_part = parts.last().unwrap_or(&"unknown");

        format!("mscp-shared-{meaningful_part}")
    }

    /// Write shared labels to a file
    pub fn write_shared_labels(&self, labels: &[SharedProfileLabel]) -> Result<PathBuf> {
        let labels_dir = self.output_base.join("lib/all/labels");
        std::fs::create_dir_all(&labels_dir)?;

        let labels_file = labels_dir.join("mscp-shared-profiles.labels.yml");

        let yaml = yaml_serde::to_string(&labels)?;
        std::fs::write(&labels_file, yaml)
            .with_context(|| format!("Failed to write shared labels: {}", labels_file.display()))?;

        tracing::info!(
            "Generated {} shared profile labels at: {}",
            labels.len(),
            labels_file.display()
        );

        Ok(labels_file)
    }

    /// Update default.yml to include shared labels
    pub fn add_to_default_yml(&self) -> Result<()> {
        let default_file = self.output_base.join("default.yml");

        if !default_file.exists() {
            tracing::warn!("default.yml not found at: {}", default_file.display());
            return Ok(());
        }

        let content = std::fs::read_to_string(&default_file)?;
        let mut default: yaml_serde::Value = yaml_serde::from_str(&content)?;

        // Get or create labels array
        if default.get("labels").is_none() {
            default["labels"] = yaml_serde::Value::Sequence(vec![]);
        }

        let labels = default
            .get_mut("labels")
            .and_then(|v| v.as_sequence_mut())
            .context("'labels' must be an array in default.yml")?;

        // Create label path entry
        let label_path_value = "./lib/all/labels/mscp-shared-profiles.labels.yml";

        // Check if already present
        let already_exists = labels.iter().any(|entry| {
            entry
                .get("path")
                .and_then(|p| p.as_str())
                .is_some_and(|p| p == label_path_value)
        });

        if already_exists {
            tracing::info!("Shared profile labels already present in default.yml");
        } else {
            // Add new label path
            let mut label_entry = yaml_serde::Mapping::new();
            label_entry.insert(
                yaml_serde::Value::String("path".to_string()),
                yaml_serde::Value::String(label_path_value.to_string()),
            );
            labels.push(yaml_serde::Value::Mapping(label_entry));

            // Write back
            let updated = yaml_serde::to_string(&default)?;
            std::fs::write(&default_file, updated)?;

            tracing::info!("Updated default.yml with shared profile labels");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_label_name() {
        let generator = MultiBaselineLabelGenerator::new("/tmp");

        assert_eq!(
            generator.generate_label_name("com.apple.security.firewall.mobileconfig"),
            "mscp-shared-firewall"
        );

        assert_eq!(
            generator.generate_label_name("com.apple.MCX.mobileconfig"),
            "mscp-shared-MCX"
        );

        assert_eq!(
            generator.generate_label_name("test.mobileconfig"),
            "mscp-shared-test"
        );
    }

    #[test]
    fn test_create_shared_label() {
        let generator = MultiBaselineLabelGenerator::new("/tmp");

        let label = generator
            .create_shared_label(
                "com.apple.security.firewall.mobileconfig",
                &["800-53r5_high".to_string(), "cis_lvl1".to_string()],
                Platform::MacOS,
            )
            .unwrap();

        assert_eq!(label.name, "mscp-shared-firewall");
        assert_eq!(label.platform, "darwin");
        assert!(label.query.contains("mscp-800-53r5_high"));
        assert!(label.query.contains("mscp-cis_lvl1"));
        assert!(label.query.contains("OR"));
    }
}
