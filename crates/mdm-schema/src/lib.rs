//! Shared MDM payload type schemas and embedded Parquet data.
//!
//! Two datasets:
//! - `capabilities` — Apple device-management (MDM profiles + DDM declarations)
//! - `profiles` — ProfileCreator/PayloadSchemas (community-maintained)

pub mod capabilities;
pub mod profiles;
pub mod types;

pub use types::*;

/// Embedded capabilities Parquet data (Apple device-management).
pub fn embedded_capabilities() -> &'static [u8] {
    include_bytes!("../data/capabilities.parquet")
}

/// Embedded profile manifests Parquet data (ProfileCreator).
pub fn embedded_profile_manifests() -> &'static [u8] {
    include_bytes!("../data/profilecreator.parquet")
}

/// Embedded schema version metadata (upstream SHAs, generation date).
pub fn schema_versions_toml() -> &'static str {
    include_str!("../data/schema-versions.toml")
}

/// Parsed schema version info for a single upstream source.
#[derive(Debug, Clone)]
pub struct SchemaVersionInfo {
    pub apple_device_management_commit: String,
    pub apple_device_management_date: String,
    pub profile_manifests_commit: String,
    pub profile_manifests_date: String,
    pub generation_date: String,
}

/// Parse the embedded schema-versions.toml into structured version info.
pub fn schema_versions() -> SchemaVersionInfo {
    let Ok(toml) = toml::from_str::<toml::Value>(schema_versions_toml()) else {
        return SchemaVersionInfo {
            apple_device_management_commit: String::new(),
            apple_device_management_date: String::new(),
            profile_manifests_commit: String::new(),
            profile_manifests_date: String::new(),
            generation_date: String::new(),
        };
    };

    let get = |section: &str, key: &str| -> String {
        toml.get(section)
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    SchemaVersionInfo {
        apple_device_management_commit: get("apple_device_management", "commit"),
        apple_device_management_date: get("apple_device_management", "date"),
        profile_manifests_commit: get("profile_manifests", "commit"),
        profile_manifests_date: get("profile_manifests", "date"),
        generation_date: get("generation", "date"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_embedded_profile_manifests() {
        let manifests = profiles::read(embedded_profile_manifests())
            .expect("Failed to read embedded profile manifests");
        assert!(
            manifests.len() > 200,
            "Expected 200+ manifests, got {}",
            manifests.len()
        );
        assert!(
            manifests
                .iter()
                .any(|m| m.payload_type == "com.apple.wifi.managed")
        );
        assert!(manifests.iter().any(|m| m.category == "apps"));
        assert!(manifests.iter().any(|m| m.category == "prefs"));
    }

    #[test]
    fn test_read_embedded_capabilities() {
        let caps = capabilities::read(embedded_capabilities())
            .expect("Failed to read embedded capabilities");
        assert!(!caps.is_empty());
        assert!(
            caps.iter()
                .any(|c| c.payload_type == "com.apple.wifi.managed")
        );
    }

    #[test]
    fn test_capabilities_contain_ddm_declarations() {
        let caps = capabilities::read(embedded_capabilities())
            .expect("Failed to read embedded capabilities");

        let ddm: Vec<_> = caps
            .iter()
            .filter(|c| c.kind == PayloadKind::DdmDeclaration)
            .collect();

        // 42 DDM declarations from Apple device-management YAML
        assert!(
            ddm.len() >= 40,
            "Expected 40+ DDM declarations, got {}",
            ddm.len()
        );

        // Verify all four DDM categories are present
        assert!(
            ddm.iter()
                .any(|c| c.ddm_category == Some(DdmCategory::Configuration))
        );
        assert!(
            ddm.iter()
                .any(|c| c.ddm_category == Some(DdmCategory::Asset))
        );
        assert!(
            ddm.iter()
                .any(|c| c.ddm_category == Some(DdmCategory::Activation))
        );
        assert!(
            ddm.iter()
                .any(|c| c.ddm_category == Some(DdmCategory::Management))
        );

        // Spot-check specific declarations from Apple's device-management repo
        assert!(
            ddm.iter()
                .any(|c| c.payload_type == "com.apple.configuration.passcode.settings")
        );
        assert!(
            ddm.iter()
                .any(|c| c.payload_type == "com.apple.configuration.softwareupdate.settings")
        );
        assert!(
            ddm.iter()
                .any(|c| c.payload_type == "com.apple.activation.simple")
        );

        // DDM declarations should have keys
        let passcode = ddm
            .iter()
            .find(|c| c.payload_type == "com.apple.configuration.passcode.settings")
            .unwrap();
        assert!(!passcode.keys.is_empty(), "Passcode DDM should have keys");
        assert!(passcode.keys.iter().any(|k| k.name == "RequirePasscode"));
    }
}
