use crate::models::MscpBaseline;
use crate::versioning::GitInfo;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Manifest file manager for version tracking
#[derive(Debug)]
pub struct ManifestStore {
    output_base: PathBuf,
}

impl ManifestStore {
    pub fn new<P: AsRef<Path>>(output_base: P) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
        }
    }

    /// Load existing manifest or create new one
    pub fn load_or_create(&self) -> Result<Manifest> {
        let manifest_path = self.get_manifest_path();

        if manifest_path.exists() {
            let content = fs::read_to_string(&manifest_path)?;
            let manifest: Manifest = serde_json::from_str(&content)?;
            tracing::info!("Loaded existing manifest from: {:?}", manifest_path);
            Ok(manifest)
        } else {
            tracing::info!("Creating new manifest");
            Ok(Manifest::new())
        }
    }

    /// Save manifest to file
    pub fn save(&self, manifest: &Manifest) -> Result<PathBuf> {
        let manifest_path = self.get_manifest_path();

        // Create parent directories
        if let Some(parent) = manifest_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(manifest)?;
        fs::write(&manifest_path, json)?;

        tracing::info!("Saved manifest to: {:?}", manifest_path);
        Ok(manifest_path)
    }

    /// Get the manifest file path (mscp/versions/manifest.json, Fleet v4.83+ top-level)
    fn get_manifest_path(&self) -> PathBuf {
        self.output_base
            .join("mscp")
            .join("versions")
            .join("manifest.json")
    }

    /// Add a baseline to the manifest
    pub fn add_baseline(
        &self,
        manifest: &mut Manifest,
        baseline: &MscpBaseline,
        git_info: &GitInfo,
        version_id: &str,
        profile_hashes: Vec<ProfileInfo>,
    ) {
        let baseline_entry = BaselineEntry {
            name: baseline.name.clone(),
            mscp_git_hash: git_info.hash.clone(),
            mscp_git_tag: git_info.tag.clone(),
            version_id: version_id.to_string(),
            generation_date: chrono::Utc::now().to_rfc3339(),
            profile_count: baseline.mobileconfigs.len(),
            script_count: usize::from(baseline.compliance_script.is_some()),
            output_hash_sha256: String::new(), // TODO: Calculate overall hash
            profiles: profile_hashes,
        };

        // Check if baseline already exists and move to previous versions
        if let Some(existing_index) = manifest
            .baselines
            .iter()
            .position(|b| b.name == baseline.name)
        {
            let existing = manifest.baselines.remove(existing_index);
            manifest.previous_versions.push(PreviousVersion {
                baseline_name: existing.name.clone(),
                version_id: existing.version_id.clone(),
                date: existing.generation_date.clone(),
            });
        }

        manifest.baselines.push(baseline_entry);
    }
}

/// Main manifest structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: String,
    pub generated_at: String,
    pub postprocessor_version: String,
    pub baselines: Vec<BaselineEntry>,
    pub previous_versions: Vec<PreviousVersion>,
}

impl Manifest {
    pub fn new() -> Self {
        Self {
            format_version: "1.0".to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            postprocessor_version: env!("CARGO_PKG_VERSION").to_string(),
            baselines: Vec::new(),
            previous_versions: Vec::new(),
        }
    }

    /// Update the `generated_at` timestamp
    pub fn update_timestamp(&mut self) {
        self.generated_at = chrono::Utc::now().to_rfc3339();
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}

/// Entry for a single baseline in the manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub name: String,
    pub mscp_git_hash: String,
    pub mscp_git_tag: Option<String>,
    pub version_id: String,
    pub generation_date: String,
    pub profile_count: usize,
    pub script_count: usize,
    pub output_hash_sha256: String,
    pub profiles: Vec<ProfileInfo>,
}

/// Information about a single profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub filename: String,
    pub payload_identifier: Option<String>,
    pub hash: String,
}

/// Previous version reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousVersion {
    pub baseline_name: String,
    pub version_id: String,
    pub date: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_creation() {
        let manifest = Manifest::new();
        assert_eq!(manifest.format_version, "1.0");
        assert_eq!(manifest.baselines.len(), 0);
    }
}
