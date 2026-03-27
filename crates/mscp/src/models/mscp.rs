use crate::models::DdmArtifact;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Represents the output structure from mSCP baseline generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MscpBaseline {
    /// Baseline name (e.g., "`cis_lvl1`", "800-53r5_high")
    pub name: String,

    /// Path to the mSCP build directory (e.g., ./`macos_security/build/cis_lvl1`)
    pub build_path: PathBuf,

    /// Platform (e.g., "macOS", "iOS/iPadOS", "visionOS")
    pub platform: Platform,

    /// List of mobileconfig files found
    pub mobileconfigs: Vec<MobileConfigFile>,

    /// DDM (Declarative Device Management) artifacts
    pub ddm_artifacts: Vec<DdmArtifact>,

    /// Compliance script (if exists)
    pub compliance_script: Option<PathBuf>,

    /// Git hash of the mSCP repo when this baseline was generated
    pub mscp_git_hash: Option<String>,

    /// Git tag (e.g., "tahoe-1.0")
    pub mscp_git_tag: Option<String>,
}

/// Supported Apple platforms
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Platform {
    #[serde(rename = "macOS")]
    MacOS,
    #[serde(rename = "iOS/iPadOS")]
    Ios,
    #[serde(rename = "visionOS")]
    VisionOS,
}

impl Platform {
    /// Convert to Fleet label platform value
    ///
    /// Fleet uses osquery platform conventions:
    /// - darwin: macOS
    /// - ios: iOS (iPhone)
    /// - ipados: iPadOS (iPad) - NOT USED for visionOS
    /// - visionos: visionOS (Apple Vision Pro)
    pub fn to_fleet_label_platform(self) -> &'static str {
        match self {
            Platform::MacOS => "darwin",
            Platform::Ios => "ios",
            Platform::VisionOS => "visionos",
        }
    }

    /// Get human-readable platform name
    pub fn display_name(&self) -> &str {
        match self {
            Platform::MacOS => "macOS",
            Platform::Ios => "iOS/iPadOS",
            Platform::VisionOS => "visionOS",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_to_fleet_label_mapping() {
        // Critical: Ensure correct Fleet platform values
        assert_eq!(Platform::MacOS.to_fleet_label_platform(), "darwin");
        assert_eq!(Platform::Ios.to_fleet_label_platform(), "ios");
        assert_eq!(Platform::VisionOS.to_fleet_label_platform(), "visionos");
    }

    #[test]
    fn test_visionos_not_ipados() {
        // Regression test: VisionOS should NOT map to "ipados"
        let visionos_platform = Platform::VisionOS.to_fleet_label_platform();
        assert_ne!(
            visionos_platform, "ipados",
            "VisionOS must not map to ipados"
        );
        assert_eq!(visionos_platform, "visionos");
    }

    #[test]
    fn test_platform_display_names() {
        assert_eq!(Platform::MacOS.display_name(), "macOS");
        assert_eq!(Platform::Ios.display_name(), "iOS/iPadOS");
        assert_eq!(Platform::VisionOS.display_name(), "visionOS");
    }
}

/// Represents a single mobileconfig file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileConfigFile {
    /// Original filename (e.g., "`os_firewall_enabled.mobileconfig`")
    pub filename: String,

    /// Full path to the file
    pub path: PathBuf,

    /// Parsed payload identifier (e.g., "com.apple.security.firewall")
    pub payload_identifier: Option<String>,

    /// Parsed payload type (e.g., "com.apple.security.firewall")
    pub payload_type: Option<String>,

    /// SHA256 hash of the file content
    pub hash: String,

    /// File size in bytes
    pub size: u64,
}

/// Represents parsed mobileconfig content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileConfigContent {
    pub payload_identifier: String,
    pub payload_type: String,
    pub payload_uuid: String,
    pub payload_display_name: Option<String>,
    pub payload_description: Option<String>,
    pub payload_organization: Option<String>,
    pub payload_content: Vec<PayloadItem>,
}

/// Represents a single payload item within a mobileconfig
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadItem {
    pub payload_type: String,
    pub payload_identifier: String,
    pub payload_uuid: String,
    pub payload_display_name: Option<String>,
    /// Raw plist value (stored as JSON for simplicity)
    pub payload_content: serde_json::Value,
}
