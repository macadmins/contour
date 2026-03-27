use crate::extractors::VersionYaml;
use crate::models::{MobileConfigFile, MscpBaseline, Platform};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Extracts mSCP baseline output from a build directory
#[derive(Debug)]
pub struct MscpOutputExtractor {
    build_path: PathBuf,
    baseline_name: String,
    mscp_repo_path: Option<PathBuf>,
}

impl MscpOutputExtractor {
    pub fn new<P: AsRef<Path>>(build_path: P, baseline_name: String) -> Self {
        Self {
            build_path: build_path.as_ref().to_path_buf(),
            baseline_name,
            mscp_repo_path: None,
        }
    }

    /// Set mSCP repository path for platform detection
    pub fn with_repo_path<P: AsRef<Path>>(mut self, repo_path: P) -> Self {
        self.mscp_repo_path = Some(repo_path.as_ref().to_path_buf());
        self
    }

    /// Extract the mSCP baseline structure
    pub fn extract(&self) -> Result<MscpBaseline> {
        tracing::info!("Extracting mSCP baseline from: {:?}", self.build_path);

        if !self.build_path.exists() {
            anyhow::bail!(
                "mSCP build directory does not exist: {}",
                self.build_path.display()
            );
        }

        // Guard: detect if user passed the mSCP repo root instead of a build output directory
        if self
            .build_path
            .join("scripts/generate_guidance.py")
            .exists()
        {
            anyhow::bail!(
                "The --input path appears to be the mSCP repository root, not a build output directory.\n\n\
                 You probably want one of:\n\
                 1. contour mscp generate --mscp-repo {} --baseline {} --output <DIR>\n\
                    (runs mSCP generation + processing in one step)\n\
                 2. contour mscp process --input {}/build/{} --baseline {}\n\
                    (if you already ran generate_guidance.py manually)",
                self.build_path.display(),
                self.baseline_name,
                self.build_path.display(),
                self.baseline_name,
                self.baseline_name,
            );
        }

        // Detect platform from VERSION.yaml if repo path provided
        let platform = if let Some(ref repo_path) = self.mscp_repo_path {
            match VersionYaml::load(repo_path) {
                Ok(version) => {
                    let p = version.to_platform();
                    tracing::info!("Detected platform: {} from VERSION.yaml", p);
                    p
                }
                Err(e) => {
                    tracing::warn!("Failed to load VERSION.yaml: {}. Defaulting to macOS.", e);
                    Platform::MacOS
                }
            }
        } else {
            tracing::info!("No repo path provided, defaulting to macOS platform");
            Platform::MacOS
        };

        let mobileconfigs = self.find_mobileconfigs()?;
        let ddm_artifacts = crate::extractors::ddm::extract_ddm_artifacts(&self.build_path)?;
        let compliance_script = self.find_compliance_script()?;

        // iOS/visionOS typically don't have compliance scripts
        if compliance_script.is_none() && platform != Platform::MacOS {
            tracing::info!(
                "{:?} platform detected - compliance scripts are MDM-only (expected)",
                platform
            );
        }

        tracing::info!(
            "Found {} mobileconfig files, {} DDM artifacts, and {} compliance scripts",
            mobileconfigs.len(),
            ddm_artifacts.len(),
            i32::from(compliance_script.is_some())
        );

        Ok(MscpBaseline {
            name: self.baseline_name.clone(),
            build_path: self.build_path.clone(),
            platform,
            mobileconfigs,
            ddm_artifacts,
            compliance_script,
            mscp_git_hash: None, // Will be filled in by versioning module
            mscp_git_tag: None,
        })
    }

    /// Find all .mobileconfig files in the build directory
    fn find_mobileconfigs(&self) -> Result<Vec<MobileConfigFile>> {
        let mut configs = Vec::new();

        // Look in mobileconfigs/ subdirectory first
        let mobileconfigs_dir = self.build_path.join("mobileconfigs");
        let search_dir = if mobileconfigs_dir.exists() {
            mobileconfigs_dir
        } else {
            self.build_path.clone()
        };

        for entry in WalkDir::new(&search_dir)
            .max_depth(2)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("mobileconfig") {
                let config = self.parse_mobileconfig_file(path)?;
                configs.push(config);
            }
        }

        Ok(configs)
    }

    /// Parse a single mobileconfig file (minimal extraction)
    fn parse_mobileconfig_file(&self, path: &Path) -> Result<MobileConfigFile> {
        let content = fs::read(path).context("Failed to read mobileconfig file")?;
        let hash_bytes = Sha256::digest(&content);
        use std::fmt::Write as _;
        let hash = hash_bytes
            .iter()
            .fold(String::with_capacity(64), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            });
        let size = content.len() as u64;

        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown.mobileconfig")
            .to_string();

        // Try to extract PayloadIdentifier using the mobileconfig parser
        let (payload_identifier, payload_type) =
            crate::extractors::mobileconfig::extract_basic_info(path).unwrap_or((None, None));

        Ok(MobileConfigFile {
            filename,
            path: path.to_path_buf(),
            payload_identifier,
            payload_type,
            hash,
            size,
        })
    }

    /// Find the compliance script
    fn find_compliance_script(&self) -> Result<Option<PathBuf>> {
        // Look for {baseline}_compliance.sh
        let script_name = format!("{}_compliance.sh", self.baseline_name);
        let script_path = self.build_path.join(&script_name);

        if script_path.exists() {
            Ok(Some(script_path))
        } else {
            // Try without the .sh extension or other variations
            for entry in fs::read_dir(&self.build_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file()
                    && let Some(filename) = path.file_name().and_then(|s| s.to_str())
                    && filename.contains("compliance")
                    && std::path::Path::new(filename)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("sh"))
                {
                    return Ok(Some(path));
                }
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extractor_creation() {
        let extractor = MscpOutputExtractor::new("/tmp/test", "cis_lvl1".to_string());
        assert_eq!(extractor.baseline_name, "cis_lvl1");
    }
}
