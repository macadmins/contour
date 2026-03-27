use crate::models::MscpBaseline;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

/// Transformer for mobileconfig profiles
#[derive(Debug)]
pub struct ProfileTransformer {
    output_base: PathBuf,
    jamf_mode: bool,
    fleet_output: bool,
}

impl ProfileTransformer {
    pub fn new<P: AsRef<Path>>(output_base: P, jamf_mode: bool, fleet_output: bool) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
            jamf_mode,
            fleet_output,
        }
    }

    /// Transform mobileconfig files from mSCP to Fleet/Jamf/plain structure
    /// Returns list of (`source_path`, `dest_path`) tuples
    pub fn transform(&self, baseline: &MscpBaseline) -> Result<Vec<(PathBuf, PathBuf)>> {
        let mut file_mappings = Vec::new();

        // Create output directory based on mode
        let profiles_dir = if self.jamf_mode {
            // Jamf mode: Direct structure {output}/{baseline_name}/
            self.output_base.join(&baseline.name)
        } else if self.fleet_output {
            // Fleet mode: GitOps structure lib/mscp/{baseline_name}/profiles/
            self.output_base
                .join("lib")
                .join("mscp")
                .join(&baseline.name)
                .join("profiles")
        } else {
            // Plain mode: mscp/{baseline_name}/profiles/
            self.output_base
                .join("mscp")
                .join(&baseline.name)
                .join("profiles")
        };

        fs::create_dir_all(&profiles_dir)?;
        tracing::info!("Created profiles directory: {:?}", profiles_dir);

        for config in &baseline.mobileconfigs {
            let dest_path = profiles_dir.join(&config.filename);
            file_mappings.push((config.path.clone(), dest_path));
        }

        tracing::info!(
            "Mapped {} mobileconfig files for baseline '{}'",
            file_mappings.len(),
            baseline.name
        );

        Ok(file_mappings)
    }

    /// Copy the mobileconfig files to their destinations
    pub fn copy_files(&self, file_mappings: &[(PathBuf, PathBuf)]) -> Result<()> {
        for (source, dest) in file_mappings {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(source, dest)?;
            tracing::debug!("Copied: {} -> {}", source.display(), dest.display());
        }
        tracing::info!("Copied {} mobileconfig files", file_mappings.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_transformer_creation() {
        let transformer = ProfileTransformer::new("/tmp/test", false, false);
        assert!(transformer.output_base.to_str().unwrap().contains("test"));
    }
}
