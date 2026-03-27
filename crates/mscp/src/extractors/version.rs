use crate::models::Platform;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Parse VERSION.yaml from mSCP repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionYaml {
    pub os: String,
    pub platform: String,
    pub version: String,
    #[serde(default)]
    pub cpe: Option<String>,
}

impl VersionYaml {
    /// Load VERSION.yaml from mSCP repository
    pub fn load<P: AsRef<Path>>(mscp_repo_path: P) -> Result<Self> {
        let version_path = mscp_repo_path.as_ref().join("VERSION.yaml");

        if !version_path.exists() {
            anyhow::bail!(
                "VERSION.yaml not found at: {}. Is this a valid mSCP repository?",
                version_path.display()
            );
        }

        let content = fs::read_to_string(&version_path).context("Failed to read VERSION.yaml")?;

        let version: VersionYaml =
            yaml_serde::from_str(&content).context("Failed to parse VERSION.yaml")?;

        tracing::debug!(
            "Detected platform: {} (OS: {})",
            version.platform,
            version.os
        );
        Ok(version)
    }

    /// Convert platform string to Platform enum
    pub fn to_platform(&self) -> Platform {
        match self.platform.as_str() {
            "macOS" => Platform::MacOS,
            "iOS/iPadOS" => Platform::Ios,
            "visionOS" => Platform::VisionOS,
            _ => {
                tracing::warn!("Unknown platform '{}', defaulting to macOS", self.platform);
                Platform::MacOS
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_conversion() {
        let version = VersionYaml {
            os: "18.0".to_string(),
            platform: "iOS/iPadOS".to_string(),
            version: "iOS 18 Guidance".to_string(),
            cpe: Some("o:apple:ios:18.0".to_string()),
        };

        assert_eq!(version.to_platform(), Platform::Ios);
    }
}
