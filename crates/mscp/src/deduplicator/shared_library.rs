use crate::deduplicator::profile_deduplicator::{DeduplicationReport, ProfileGroup};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Manages the shared profile library at lib/mscp/profiles/
#[derive(Debug)]
pub struct SharedProfileLibrary {
    /// Output base path
    output_base: PathBuf,

    /// Shared profiles directory
    shared_dir: PathBuf,
}

impl SharedProfileLibrary {
    /// Create a new shared library manager
    pub fn new<P: AsRef<Path>>(output_base: P) -> Self {
        let output_base = output_base.as_ref().to_path_buf();
        let shared_dir = output_base.join("lib/mscp/profiles");

        Self {
            output_base,
            shared_dir,
        }
    }

    /// Initialize the shared profiles directory
    pub fn initialize(&self) -> Result<()> {
        if !self.shared_dir.exists() {
            std::fs::create_dir_all(&self.shared_dir).with_context(|| {
                format!(
                    "Failed to create shared profiles directory: {}",
                    self.shared_dir.display()
                )
            })?;
            tracing::info!(
                "Created shared profiles directory: {}",
                self.shared_dir.display()
            );
        }
        Ok(())
    }

    /// Move duplicate profiles to shared library
    pub fn deduplicate_profiles(
        &self,
        report: &DeduplicationReport,
    ) -> Result<DeduplicationMapping> {
        self.initialize()?;

        let mut mapping = DeduplicationMapping::new();
        let shared_profiles = report.get_shared_profiles();

        tracing::info!(
            "Moving {} shared profiles to library",
            shared_profiles.len()
        );

        for group in shared_profiles {
            self.process_profile_group(group, &mut mapping)?;
        }

        tracing::info!(
            "Deduplication complete: {} profiles moved to shared library",
            mapping.shared_profiles.len()
        );
        Ok(mapping)
    }

    /// Process a single profile group
    fn process_profile_group(
        &self,
        group: &ProfileGroup,
        mapping: &mut DeduplicationMapping,
    ) -> Result<()> {
        let shared_path = self.shared_dir.join(&group.canonical_filename);

        // Use the first profile as the source
        let source_profile = &group.profiles[0];

        // Copy to shared library if not already there
        if !shared_path.exists() {
            std::fs::copy(&source_profile.path, &shared_path).with_context(|| {
                format!(
                    "Failed to copy profile to shared library: {}",
                    shared_path.display()
                )
            })?;

            tracing::info!("Copied {} to shared library", group.canonical_filename);
        }

        // Record the mapping for all profiles in this group
        for profile in &group.profiles {
            let relative_shared_path = format!("../profiles/{}", group.canonical_filename);

            mapping.add_mapping(
                profile.baseline_name.clone(),
                profile.filename.clone(),
                relative_shared_path.clone(),
                group.get_unique_baselines().into_iter().collect(),
            );
        }

        mapping
            .shared_profiles
            .insert(group.canonical_filename.clone(), shared_path);

        Ok(())
    }

    /// Remove baseline-specific profiles that have been moved to shared library
    pub fn cleanup_baseline_profiles(&self, mapping: &DeduplicationMapping) -> Result<()> {
        tracing::info!("Cleaning up baseline-specific duplicate profiles");

        let mut removed_count = 0;

        for (baseline, profiles) in &mapping.baseline_mappings {
            for original_filename in profiles.keys() {
                let baseline_profile = self
                    .output_base
                    .join("lib/mscp")
                    .join(baseline)
                    .join("profiles")
                    .join(original_filename);

                if baseline_profile.exists() {
                    std::fs::remove_file(&baseline_profile).with_context(|| {
                        format!(
                            "Failed to remove duplicate profile: {}",
                            baseline_profile.display()
                        )
                    })?;
                    removed_count += 1;
                }
            }
        }

        tracing::info!(
            "Removed {} duplicate profiles from baseline directories",
            removed_count
        );
        Ok(())
    }
}

/// Mapping of baseline profiles to shared library paths
#[derive(Debug)]
pub struct DeduplicationMapping {
    /// Map of baseline -> (`original_filename` -> `ProfileMapping`)
    pub baseline_mappings: HashMap<String, HashMap<String, ProfileMapping>>,

    /// Map of canonical filename -> shared path
    pub shared_profiles: HashMap<String, PathBuf>,
}

/// Information about a deduplicated profile
#[derive(Debug, Clone)]
pub struct ProfileMapping {
    /// Relative path to shared profile (e.g., "../profiles/com.apple.security.firewall.mobileconfig")
    pub shared_path: String,

    /// All baselines that use this profile
    pub baselines: Vec<String>,
}

impl DeduplicationMapping {
    /// Create a new empty mapping
    pub fn new() -> Self {
        Self {
            baseline_mappings: HashMap::new(),
            shared_profiles: HashMap::new(),
        }
    }

    /// Add a profile mapping
    pub fn add_mapping(
        &mut self,
        baseline: String,
        original_filename: String,
        shared_path: String,
        baselines: Vec<String>,
    ) {
        let profile_mapping = ProfileMapping {
            shared_path: shared_path.clone(),
            baselines,
        };

        self.baseline_mappings
            .entry(baseline)
            .or_default()
            .insert(original_filename, profile_mapping);
    }

    /// Get the shared path for a profile in a specific baseline
    pub fn get_shared_path(&self, baseline: &str, filename: &str) -> Option<&str> {
        self.baseline_mappings
            .get(baseline)
            .and_then(|profiles| profiles.get(filename))
            .map(|mapping| mapping.shared_path.as_str())
    }

    /// Get all baselines that use a specific profile
    pub fn get_baselines_for_profile(&self, baseline: &str, filename: &str) -> Option<&[String]> {
        self.baseline_mappings
            .get(baseline)
            .and_then(|profiles| profiles.get(filename))
            .map(|mapping| mapping.baselines.as_slice())
    }

    /// Print a summary of the mapping
    pub fn print_summary(&self) {
        println!("\n=== Deduplication Mapping ===");
        println!("Shared profiles: {}", self.shared_profiles.len());
        println!("Affected baselines: {}", self.baseline_mappings.len());

        for (baseline, profiles) in &self.baseline_mappings {
            println!("\n{}: {} profiles deduplicated", baseline, profiles.len());
        }
    }
}

impl Default for DeduplicationMapping {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplication_mapping() {
        let mut mapping = DeduplicationMapping::new();

        mapping.add_mapping(
            "800-53r5_high".to_string(),
            "firewall.mobileconfig".to_string(),
            "../profiles/firewall.mobileconfig".to_string(),
            vec!["800-53r5_high".to_string(), "cis_lvl1".to_string()],
        );

        assert_eq!(
            mapping.get_shared_path("800-53r5_high", "firewall.mobileconfig"),
            Some("../profiles/firewall.mobileconfig")
        );

        let baselines = mapping
            .get_baselines_for_profile("800-53r5_high", "firewall.mobileconfig")
            .unwrap();
        assert_eq!(baselines.len(), 2);
        assert!(baselines.contains(&"800-53r5_high".to_string()));
        assert!(baselines.contains(&"cis_lvl1".to_string()));
    }
}
