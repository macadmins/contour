// DDM models - public API
#![allow(dead_code, reason = "module under development")]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// DDM (Declarative Device Management) artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdmArtifact {
    /// Type of DDM declaration
    pub declaration_type: DdmDeclarationType,

    /// Declaration identifier (e.g., "pam", "sshd", "sudo")
    pub identifier: String,

    /// Path to the JSON declaration file
    pub json_path: PathBuf,

    /// Optional associated asset (ZIP file)
    pub asset_path: Option<PathBuf>,

    /// SHA256 hash of the JSON file
    pub hash: String,

    /// File size in bytes
    pub size: u64,
}

/// Types of DDM declarations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DdmDeclarationType {
    /// Configuration declaration (org.mscp.{baseline}.config.{service}.json)
    Configuration,

    /// Asset declaration (org.mscp.{baseline}.asset.{service}.json + {service}.zip)
    Asset,

    /// Activation declaration (org.mscp.{baseline}.activation.{service}.json)
    Activation,
}

impl DdmDeclarationType {
    /// Get the subdirectory name for this declaration type
    pub fn subdirectory(&self) -> &str {
        match self {
            DdmDeclarationType::Configuration => "configurations",
            DdmDeclarationType::Asset => "assets",
            DdmDeclarationType::Activation => "activations",
        }
    }

    /// Parse declaration type from filename
    pub fn from_filename(filename: &str) -> Option<Self> {
        if filename.contains(".config.") {
            Some(DdmDeclarationType::Configuration)
        } else if filename.contains(".asset.") {
            Some(DdmDeclarationType::Asset)
        } else if filename.contains(".activation.") {
            Some(DdmDeclarationType::Activation)
        } else {
            None
        }
    }
}

/// Parsed DDM declaration content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdmDeclarationContent {
    /// Declaration identifier
    pub identifier: String,

    /// Declaration type (from manifest)
    pub declaration_type: String,

    /// Payload content (varies by type)
    pub payload: serde_json::Value,

    /// Server token (if present)
    pub server_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_declaration_type_from_filename() {
        assert_eq!(
            DdmDeclarationType::from_filename("org.mscp.cis_lvl1.config.pam.json"),
            Some(DdmDeclarationType::Configuration)
        );
        assert_eq!(
            DdmDeclarationType::from_filename("org.mscp.cis_lvl1.asset.sshd.json"),
            Some(DdmDeclarationType::Asset)
        );
        assert_eq!(
            DdmDeclarationType::from_filename("org.mscp.cis_lvl1.activation.sudo.json"),
            Some(DdmDeclarationType::Activation)
        );
        assert_eq!(DdmDeclarationType::from_filename("regular.json"), None);
    }

    #[test]
    fn test_subdirectory() {
        assert_eq!(
            DdmDeclarationType::Configuration.subdirectory(),
            "configurations"
        );
        assert_eq!(DdmDeclarationType::Asset.subdirectory(), "assets");
        assert_eq!(DdmDeclarationType::Activation.subdirectory(), "activations");
    }
}
