//! Shared MDM payload type schemas and embedded Parquet data.
//!
//! Three datasets:
//! - `capabilities` — Apple device-management (MDM profiles + DDM declarations)
//! - `profiles` — ProfileCreator/PayloadSchemas (community-maintained)
//! - `skip_keys` — Setup Assistant skip keys with platform gating

pub mod capabilities;
pub mod examples;
pub mod profiles;
pub mod skip_keys;
pub mod types;

pub use types::*;

/// Embedded capabilities Parquet data (Apple device-management).
pub fn embedded_capabilities() -> &'static [u8] {
    include_bytes!("../data/capabilities.parquet")
}

/// Embedded examples Parquet data (Apple example configs).
pub fn embedded_examples() -> &'static [u8] {
    include_bytes!("../data/examples.parquet")
}

/// Embedded **beta** examples Parquet data (Apple device-management seed).
pub fn embedded_examples_beta() -> &'static [u8] {
    include_bytes!("../data/beta/examples.parquet")
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
    fn string_defaults_are_decoded_not_json_encoded() {
        // The parquet stores scalar defaults JSON-encoded in a text column
        // ("Allowed" arrives as the 9-char text `"Allowed"`). The reader must
        // decode that, or every consumer renders defaults with embedded quotes.
        let caps = capabilities::read(embedded_capabilities())
            .expect("Failed to read embedded capabilities");
        let swu = caps
            .iter()
            .find(|c| c.payload_type == "com.apple.configuration.softwareupdate.settings")
            .expect("softwareupdate.settings capability");
        let download = swu
            .keys
            .iter()
            .find(|k| k.name == "Download")
            .expect("AutomaticActions.Download key");
        assert_eq!(
            download.default_value,
            Some(serde_json::Value::String("Allowed".to_string())),
            "string default must not carry embedded JSON quotes"
        );

        // Boolean-ish defaults come through as real JSON booleans now.
        let notifications = swu
            .keys
            .iter()
            .find(|k| k.name == "Notifications")
            .expect("Notifications key");
        assert_eq!(
            notifications.default_value,
            Some(serde_json::Value::Bool(true))
        );
    }

    /// Build a one-row capabilities parquet in memory. With
    /// `with_rangelist`, the `key_rangelist` column (posture-ingest ≥ 41
    /// cols) is appended, carrying `["Allowed","AlwaysOn"]`.
    fn one_row_capabilities_parquet(with_rangelist: bool) -> Vec<u8> {
        use arrow::array::{ArrayRef, StringArray, UInt32Array, new_null_array};
        use arrow::datatypes::{DataType, Field, Schema};
        use std::sync::Arc;

        let mut fields: Vec<Field> = capabilities::schema()
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect();
        if with_rangelist {
            fields.push(Field::new("key_rangelist", DataType::Utf8, true));
        }
        let schema = Arc::new(Schema::new(fields));

        let arrays: Vec<ArrayRef> = schema
            .fields()
            .iter()
            .map(|f| match f.name().as_str() {
                "payload_type" => {
                    Arc::new(StringArray::from(vec!["com.test.configuration.enum"])) as ArrayRef
                }
                "kind" => Arc::new(StringArray::from(vec!["DdmDeclaration"])),
                "title" => Arc::new(StringArray::from(vec!["Enum Test"])),
                "platform" => Arc::new(StringArray::from(vec!["macOS"])),
                "key_name" => Arc::new(StringArray::from(vec!["Download"])),
                "key_data_type" => Arc::new(StringArray::from(vec!["string"])),
                "depth" => Arc::new(UInt32Array::from(vec![0u32])),
                "key_rangelist" => Arc::new(StringArray::from(vec![r#"["Allowed","AlwaysOn"]"#])),
                _ => new_null_array(f.data_type(), 1),
            })
            .collect();

        let batch = arrow::record_batch::RecordBatch::try_new(schema.clone(), arrays).unwrap();
        let mut buf = Vec::new();
        let mut writer = parquet::arrow::ArrowWriter::try_new(&mut buf, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        buf
    }

    /// A parquet carrying the `key_rangelist` column must surface it as
    /// `PayloadKey::range_list` (JSON-encoded string array, nullable).
    #[test]
    fn range_list_column_is_read_when_present() {
        let buf = one_row_capabilities_parquet(true);
        let caps = capabilities::read(&buf).expect("read parquet with key_rangelist");
        let key = &caps[0].keys[0];
        assert_eq!(key.name, "Download");
        assert_eq!(
            key.range_list,
            Some(vec!["Allowed".to_string(), "AlwaysOn".to_string()])
        );
    }

    /// A 40-column parquet (pre-key_rangelist) must keep reading, with
    /// `range_list: None` on every key.
    #[test]
    fn read_tolerates_missing_range_list_column() {
        let buf = one_row_capabilities_parquet(false);
        let caps = capabilities::read(&buf).expect("read 40-col parquet");
        assert_eq!(caps[0].keys[0].range_list, None);
    }

    /// The shipped stable parquet (posture-ingest 41 cols) carries Apple's
    /// rangelists — the data behind offline enum validation. Pin the
    /// canonical example end-to-end.
    #[test]
    fn embedded_capabilities_carry_rangelists() {
        let caps = capabilities::read(embedded_capabilities())
            .expect("Failed to read embedded capabilities");
        let swu = caps
            .iter()
            .find(|c| c.payload_type == "com.apple.configuration.softwareupdate.settings")
            .expect("softwareupdate.settings capability");
        let download = swu
            .keys
            .iter()
            .find(|k| k.name == "Download")
            .expect("AutomaticActions.Download key");
        assert_eq!(
            download.range_list,
            Some(vec![
                "Allowed".to_string(),
                "AlwaysOn".to_string(),
                "AlwaysOff".to_string(),
            ])
        );
    }

    #[test]
    fn test_beta_examples_contain_app_settings() {
        let ex = examples::read(embedded_examples_beta()).expect("read beta examples");
        assert!(
            ex.iter()
                .filter(|e| e.payload_type == "com.apple.configuration.app.settings")
                .count()
                >= 2,
            "beta app.settings should have 2 examples"
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
    fn beta_skip_keys_superset_of_stable() {
        // Version-independent invariant: beta ⊇ stable holds for every OS, so this
        // survives OS GA (when seed keys graduate into stable). No key-name literals.
        use std::collections::BTreeSet;
        let stable: BTreeSet<String> = skip_keys::read(embedded_skip_keys())
            .expect("stable skip_keys")
            .into_iter()
            .map(|k| k.key)
            .collect();
        let beta: BTreeSet<String> = skip_keys::read(embedded_skip_keys_beta())
            .expect("beta skip_keys")
            .into_iter()
            .map(|k| k.key)
            .collect();
        assert!(
            beta.is_superset(&stable),
            "beta skip_keys must be a superset of stable; missing from beta: {:?}",
            stable.difference(&beta).collect::<Vec<_>>()
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
    fn beta_capabilities_superset_of_stable() {
        // Version-independent invariant: beta ⊇ stable, true for every OS. Survives
        // GA (seed declarations graduate into stable) with no edits.
        use std::collections::BTreeSet;
        let stable: BTreeSet<String> = capabilities::read(embedded_capabilities())
            .expect("stable capabilities")
            .into_iter()
            .map(|c| c.payload_type)
            .collect();
        let beta: BTreeSet<String> = capabilities::read(embedded_capabilities_beta())
            .expect("beta capabilities")
            .into_iter()
            .map(|c| c.payload_type)
            .collect();
        assert!(
            beta.is_superset(&stable),
            "beta capabilities must be a superset of stable; missing from beta: {:?}",
            stable.difference(&beta).collect::<Vec<_>>()
        );
    }

    #[test]
    fn beta_has_seed_additions_when_pinned() {
        // GA-proof: when a seed is pinned, beta must STRICTLY exceed stable (a seed
        // adds declarations and/or skip keys — historically app.settings, the
        // network.vpn.* family, AccessibilityAppearance, LiquidGlass for OS 27).
        // In the empty-beta window (post-GA, before the next seed), there is no pin
        // and beta == stable. Driven entirely by the seed pin — no OS-version literals.
        use std::collections::BTreeSet;
        let pinned = !schema_versions()
            .apple_device_management_seed_commit
            .is_empty();

        let stable_caps: BTreeSet<String> = capabilities::read(embedded_capabilities())
            .expect("stable caps")
            .into_iter()
            .map(|c| c.payload_type)
            .collect();
        let beta_caps: BTreeSet<String> = capabilities::read(embedded_capabilities_beta())
            .expect("beta caps")
            .into_iter()
            .map(|c| c.payload_type)
            .collect();
        let stable_keys: BTreeSet<String> = skip_keys::read(embedded_skip_keys())
            .expect("stable skip_keys")
            .into_iter()
            .map(|k| k.key)
            .collect();
        let beta_keys: BTreeSet<String> = skip_keys::read(embedded_skip_keys_beta())
            .expect("beta skip_keys")
            .into_iter()
            .map(|k| k.key)
            .collect();

        if pinned {
            let cap_added = beta_caps.difference(&stable_caps).count();
            let key_added = beta_keys.difference(&stable_keys).count();
            assert!(
                cap_added + key_added > 0,
                "a pinned seed must add declarations or skip keys to beta \
                 (caps +{cap_added}, keys +{key_added})"
            );
        } else {
            assert_eq!(
                beta_caps, stable_caps,
                "with no seed pinned, beta capabilities must equal stable"
            );
            assert_eq!(
                beta_keys, stable_keys,
                "with no seed pinned, beta skip keys must equal stable"
            );
        }
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
