use crate::models::MscpBaseline;
use crate::models::ddm::DdmDeclarationType;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

/// Transformer for DDM artifacts
#[derive(Debug)]
pub struct DdmTransformer {
    output_base: PathBuf,
    jamf_mode: bool,
    fleet_output: bool,
}

impl DdmTransformer {
    pub fn new<P: AsRef<Path>>(output_base: P, jamf_mode: bool, fleet_output: bool) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
            jamf_mode,
            fleet_output,
        }
    }

    /// Transform DDM artifacts from mSCP to Fleet/Jamf/plain structure
    /// Returns list of (`source_path`, `dest_path`) tuples for JSON and ZIP files
    pub fn transform(&self, baseline: &MscpBaseline) -> Result<Vec<(PathBuf, PathBuf)>> {
        if baseline.ddm_artifacts.is_empty() {
            tracing::info!("No DDM artifacts to transform");
            return Ok(Vec::new());
        }

        let mut file_mappings = Vec::new();

        if self.fleet_output && !self.jamf_mode {
            return Ok(Self::fleet_mappings(&self.output_base, baseline));
        }

        // Create base DDM directory based on mode
        let ddm_base = if self.jamf_mode {
            // Jamf mode: Direct structure {output}/{baseline_name}/declarative/
            self.output_base.join(&baseline.name).join("declarative")
        } else {
            // Plain mode: mscp/{baseline_name}/declarative/
            self.output_base
                .join("mscp")
                .join(&baseline.name)
                .join("declarative")
        };

        for artifact in &baseline.ddm_artifacts {
            // Create subdirectory for this declaration type
            let type_dir = ddm_base.join(artifact.declaration_type.subdirectory());
            fs::create_dir_all(&type_dir)?;

            // Map JSON file
            let json_filename = artifact
                .json_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown.json");
            let json_dest = type_dir.join(json_filename);
            file_mappings.push((artifact.json_path.clone(), json_dest));

            // Map ZIP file if it exists (for assets)
            if let Some(ref zip_path) = artifact.asset_path {
                let zip_filename = zip_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown.zip");
                let zip_dest = type_dir.join(zip_filename);
                file_mappings.push((zip_path.clone(), zip_dest));
            }
        }

        tracing::info!(
            "Mapped {} DDM files for baseline '{}'",
            file_mappings.len(),
            baseline.name
        );

        Ok(file_mappings)
    }

    /// Fleet: configuration declarations only, flat in
    /// `platforms/<os>/declaration-profiles/<baseline>/`, as `fleetctl new`
    /// lays them out. Fleet writes its own activations, so mSCP's are not
    /// shipped, and it takes no asset declarations.
    fn fleet_mappings(output_base: &Path, baseline: &MscpBaseline) -> Vec<(PathBuf, PathBuf)> {
        let dir = output_base
            .join(
                contour_core::fleet_layout::FleetLayout::default()
                    .apple_declarations_subdir(baseline.platform.mscp_dir_name()),
            )
            .join(&baseline.name);
        baseline
            .ddm_artifacts
            .iter()
            .filter(|a| {
                if a.declaration_type == DdmDeclarationType::Asset {
                    tracing::warn!(
                        "Skipping asset declaration {} — Fleet does not accept asset declarations",
                        a.json_path.display()
                    );
                }
                a.declaration_type == DdmDeclarationType::Configuration
            })
            .filter_map(|a| {
                let name = a.json_path.file_name()?;
                Some((a.json_path.clone(), dir.join(name)))
            })
            .collect()
    }

    /// Copy the DDM files to their destinations
    pub fn copy_files(&self, file_mappings: &[(PathBuf, PathBuf)]) -> Result<()> {
        for (source, dest) in file_mappings {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(source, dest)?;
            tracing::debug!("Copied DDM: {} -> {}", source.display(), dest.display());
        }
        tracing::info!("Copied {} DDM files", file_mappings.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ddm_transformer_creation() {
        let transformer = DdmTransformer::new("/tmp/test", false, false);
        assert!(transformer.output_base.to_str().unwrap().contains("test"));
    }
}
