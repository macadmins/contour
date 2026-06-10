//! Shared MDM payload type schemas and embedded Parquet data.
//!
//! Three datasets:
//! - `capabilities` — Apple device-management (MDM profiles + DDM declarations)
//! - `profiles` — ProfileCreator/PayloadSchemas (community-maintained)
//! - `skip_keys` — Setup Assistant skip keys with platform gating

pub mod capabilities;
pub mod profiles;
pub mod skip_keys;
pub mod types;

pub use types::*;

/// Embedded capabilities Parquet data (Apple device-management).
pub fn embedded_capabilities() -> &'static [u8] {
    include_bytes!("../data/capabilities.parquet")
}

/// Embedded **beta** capabilities Parquet data (Apple device-management seed).
///
/// Built from Apple's pre-release OS seed (e.g. `seed_OS_27_0`) and published
/// to `data/beta/` by the posture pipeline. Carries the same shape as
/// [`embedded_capabilities`] plus seed-only declarations and keys (for example
/// `com.apple.configuration.app.settings` and `package`'s `UninstallBehavior`).
/// Consumers opt in explicitly so the stable channel is never affected.
pub fn embedded_capabilities_beta() -> &'static [u8] {
    include_bytes!("../data/beta/capabilities.parquet")
}

/// Embedded profile manifests Parquet data (ProfileCreator).
pub fn embedded_profile_manifests() -> &'static [u8] {
    include_bytes!("../data/profilecreator.parquet")
}

/// Embedded skip keys Parquet data (Setup Assistant skip keys).
pub fn embedded_skip_keys() -> &'static [u8] {
    include_bytes!("../data/skip_keys.parquet")
}

/// Embedded **beta** skip keys Parquet data (Apple device-management seed).
///
/// Mirrors [`embedded_capabilities_beta`] for skip keys: built from the OS seed
/// and published to `data/beta/` by the posture pipeline. Carries the stable set
/// plus seed-only keys (for example `AccessibilityAppearance` and `LiquidGlass`
/// introduced in OS 27.0). Consumers opt in explicitly via `--beta`.
pub fn embedded_skip_keys_beta() -> &'static [u8] {
    include_bytes!("../data/beta/skip_keys.parquet")
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
    /// Beta seed pin (empty when no seed channel is recorded). Provenance for the
    /// `data/beta/` parquet exposed via the `*_beta` accessors and `--beta`.
    pub apple_device_management_seed_commit: String,
    pub apple_device_management_seed_date: String,
    pub apple_device_management_seed_release: String,
    pub profile_manifests_commit: String,
    pub profile_manifests_date: String,
    pub generation_date: String,
}

/// Parse the embedded schema-versions.toml into structured version info.
pub fn schema_versions() -> SchemaVersionInfo {
    parse_schema_versions(schema_versions_toml())
}

/// Parse a schema-versions TOML string. Split out from [`schema_versions`] so the
/// parsing — including the optional `[apple_device_management_seed]` pin — can be
/// unit-tested deterministically without depending on the pipeline-fetched file.
fn parse_schema_versions(toml_str: &str) -> SchemaVersionInfo {
    let Ok(toml) = toml::from_str::<toml::Value>(toml_str) else {
        return SchemaVersionInfo {
            apple_device_management_commit: String::new(),
            apple_device_management_date: String::new(),
            apple_device_management_seed_commit: String::new(),
            apple_device_management_seed_date: String::new(),
            apple_device_management_seed_release: String::new(),
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
        apple_device_management_seed_commit: get("apple_device_management_seed", "commit"),
        apple_device_management_seed_date: get("apple_device_management_seed", "date"),
        apple_device_management_seed_release: get("apple_device_management_seed", "release"),
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
    fn test_read_embedded_skip_keys() {
        let keys =
            skip_keys::read(embedded_skip_keys()).expect("Failed to read embedded skip_keys");
        assert!(
            keys.len() >= 20,
            "Expected at least 20 skip keys, got {}",
            keys.len()
        );
    }

    #[test]
    fn test_beta_skip_keys_contain_seed_additions() {
        let keys = skip_keys::read(embedded_skip_keys_beta())
            .expect("Failed to read embedded beta skip_keys");
        assert!(
            keys.len() >= 20,
            "Expected 20+ beta skip keys, got {}",
            keys.len()
        );
        // Seed-only skip keys introduced in OS 27.0.
        assert!(
            keys.iter().any(|k| k.key == "AccessibilityAppearance"),
            "beta skip_keys should carry the 27.0 AccessibilityAppearance key"
        );
        assert!(
            keys.iter().any(|k| k.key == "LiquidGlass"),
            "beta skip_keys should carry the 27.0 LiquidGlass key"
        );
    }

    #[test]
    fn test_stable_skip_keys_lack_seed_additions() {
        // Guard: the stable channel must NOT carry seed-only skip keys.
        let keys =
            skip_keys::read(embedded_skip_keys()).expect("Failed to read embedded skip_keys");
        assert!(
            !keys.iter().any(|k| k.key == "AccessibilityAppearance"),
            "stable skip_keys must not contain the 27.0 AccessibilityAppearance key"
        );
        assert!(
            !keys.iter().any(|k| k.key == "LiquidGlass"),
            "stable skip_keys must not contain the 27.0 LiquidGlass key"
        );
    }

    #[test]
    fn parse_schema_versions_extracts_seed_pin() {
        // Deterministic: tests the parser, not the pipeline-fetched (gitignored)
        // schema-versions.toml, whose seed section is supplied by posture-ingest.
        let toml = r#"
[apple_device_management]
commit = "67045e2"
date = "2026-03-25"

[apple_device_management_seed]
commit = "1548d422768fe7a125e4a6f30ee0cb121a0cc333"
date = "2026-06-08"
release = "seed_OS_27_0"
"#;
        let sv = parse_schema_versions(toml);
        assert_eq!(sv.apple_device_management_commit, "67045e2");
        assert_eq!(
            sv.apple_device_management_seed_commit,
            "1548d422768fe7a125e4a6f30ee0cb121a0cc333"
        );
        assert_eq!(sv.apple_device_management_seed_release, "seed_OS_27_0");
    }

    #[test]
    fn parse_schema_versions_tolerates_missing_seed() {
        // Stable-only data (no seed section) must parse with empty seed fields,
        // not panic — the seed channel is optional.
        let sv = parse_schema_versions("[apple_device_management]\ncommit = \"abc\"\n");
        assert_eq!(sv.apple_device_management_commit, "abc");
        assert!(sv.apple_device_management_seed_commit.is_empty());
        assert!(sv.apple_device_management_seed_release.is_empty());
    }

    #[test]
    fn test_beta_capabilities_contain_seed_additions() {
        let caps = capabilities::read(embedded_capabilities_beta())
            .expect("Failed to read embedded beta capabilities");
        assert!(!caps.is_empty());

        // Seed-only declaration: app.settings (introduced 27.0).
        assert!(
            caps.iter()
                .any(|c| c.payload_type == "com.apple.configuration.app.settings"),
            "beta dataset should carry com.apple.configuration.app.settings"
        );

        // Seed-only key on an existing declaration: package gained UninstallBehavior.
        let package = caps
            .iter()
            .find(|c| c.payload_type == "com.apple.configuration.package")
            .expect("beta dataset should carry com.apple.configuration.package");
        assert!(
            package.keys.iter().any(|k| k.name == "UninstallBehavior"),
            "package should expose the 27.0 UninstallBehavior key in the beta dataset"
        );
        assert!(
            package.keys.iter().any(|k| k.name == "Remove"),
            "package UninstallBehavior should include the Remove subkey"
        );
    }

    #[test]
    fn test_stable_capabilities_lack_seed_additions() {
        // Guard: the stable channel must NOT carry seed-only additions, so the
        // beta accessor is the only path to 27.0 keys.
        let caps = capabilities::read(embedded_capabilities())
            .expect("Failed to read embedded capabilities");
        assert!(
            !caps
                .iter()
                .any(|c| c.payload_type == "com.apple.configuration.app.settings"),
            "stable dataset must not contain the 27.0 app.settings declaration"
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
