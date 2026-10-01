//! Shared MDM payload type schemas and embedded Parquet data.
//!
//! Three datasets:
//! - `capabilities` — Apple device-management (MDM profiles + DDM declarations)
//! - `profiles` — ProfileCreator/PayloadSchemas (community-maintained)
//! - `skip_keys` — Setup Assistant skip keys with platform gating
//! - `app_schema` — for domains described from an App Schema v1
//!   document: the keys a profile must not set, keys read from another
//!   domain, and the document's rules

pub mod app_schema;
pub mod capabilities;
pub mod examples;
pub mod mdm_errors;
/// MDM payload type → DDM declaration migration registry. Lives here rather
/// than in the profile crate so read-only consumers (schema lookups, the MCP
/// server) can answer "what supersedes this deprecated payload?" without
/// linking a crate that writes MDM artifacts.
pub mod migration;
pub mod profiles;
pub mod service_config;
pub mod skip_keys;
pub mod source_versions;
pub mod status_items;
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

// ── The beta channel is dormant ─────────────────────────────────────────────
//
// Every `*_beta` accessor below returns the STABLE bytes. With no OS seed
// open there is no pre-release schema to serve, so `--beta` refuses rather
// than answer with the released schema under another name. What 27.0
// introduced as seed-only — app.settings, LiquidGlass,
// AccessibilityAppearance, package UninstallBehavior — is in the stable set.
//
// When Apple opens the next seed and a seed dataset is published again,
// point these accessors back at `include_bytes!` of
// `data/beta/…`, and restore the seed-additions test that
// `beta_accessors_currently_mirror_stable` replaced. [`beta_is_retired`] then
// turns false on its own, and the CLI stops telling users `--beta` is a no-op.
// ─────────────────────────────────────────────────────────────────────────────

/// Embedded **beta** examples. Retired — returns the stable bytes (see above).
pub fn embedded_examples_beta() -> &'static [u8] {
    embedded_examples()
}

/// Embedded **beta** capabilities. Retired — returns the stable bytes; see the
/// banner above for why, and what to change when the next seed opens.
pub fn embedded_capabilities_beta() -> &'static [u8] {
    embedded_capabilities()
}

/// Whether the beta channel is retired: its accessors serve the stable bytes,
/// so `--beta` changes nothing.
///
/// Pointer equality rather than a key diff, because it reflects the switch
/// itself — the same comparison `beta_accessors_currently_mirror_stable` pins.
/// Re-point the accessors at a real seed and this turns false with no other
/// change, so anything warning about a retired channel falls silent by itself.
/// Both must mirror stable: a half-finished re-pointing is not "retired".
pub fn beta_is_retired() -> bool {
    std::ptr::eq(embedded_capabilities_beta(), embedded_capabilities())
        && std::ptr::eq(embedded_skip_keys_beta(), embedded_skip_keys())
}

/// Embedded source provenance: which upstream commit each table came from.
/// Zero bytes when the dataset predates the table; the reader treats that as
/// empty and FormSpec's `source.upstream_ref` stays null.
pub fn embedded_source_versions() -> &'static [u8] {
    include_bytes!("../data/source_versions.parquet")
}

/// Embedded DDM status item types — the other half of DDM: what a device
/// reports back. Zero bytes on a dataset that predates the table.
pub fn embedded_status_items() -> &'static [u8] {
    include_bytes!("../data/status_items.parquet")
}

/// Embedded MDM error codes Apple documents, per platform.
pub fn embedded_mdm_errors() -> &'static [u8] {
    include_bytes!("../data/mdm_errors.parquet")
}

/// Embedded Windows CSP capabilities Parquet data.
///
/// Windows Configuration Service Provider nodes parsed from Microsoft's
/// DDF v2 files, in the same column layout as [`embedded_capabilities`]
/// (`csp_name` populated, kinds `CspSetting`/`AdmxPolicy`, MSFT
/// AllowedValues enumerations in `key_rangelist`). Kept as a dedicated
/// file so Apple-only consumers never pay for it; read it with
/// [`capabilities::read`].
pub fn embedded_windows_capabilities() -> &'static [u8] {
    include_bytes!("../data/windows_capabilities.parquet")
}

/// Embedded App Schema key facts Parquet data.
///
/// Read with [`app_schema::keys::read`]; joins `capabilities` on
/// `domain = payload_type`.
pub fn embedded_app_schema_keys() -> &'static [u8] {
    include_bytes!("../data/app_schema_keys.parquet")
}

/// Embedded App Schema rules Parquet data.
///
/// Read with [`app_schema::rules::read`].
pub fn embedded_app_schema_rules() -> &'static [u8] {
    include_bytes!("../data/app_schema_rules.parquet")
}

/// Embedded skip keys Parquet data (Setup Assistant skip keys).
pub fn embedded_skip_keys() -> &'static [u8] {
    include_bytes!("../data/skip_keys.parquet")
}

/// Embedded **beta** skip keys. Retired — returns the stable bytes; see the
/// banner above [`embedded_examples_beta`]. `LiquidGlass` and
/// `AccessibilityAppearance`, once seed-only, are in the stable set.
pub fn embedded_skip_keys_beta() -> &'static [u8] {
    embedded_skip_keys()
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
    /// What produced the dataset — the pipeline revision it was built at — so
    /// a test that needs a newer build can say which build it got.
    pub generation_source: String,
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
            generation_source: String::new(),
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
        generation_source: get("generation", "source"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys a profile must not set, for domains described from an app's own
    /// source. ProfileManifests has no way to say any of this.
    #[test]
    fn app_schema_keys_read_with_their_kinds() {
        let keys =
            app_schema::keys::read(embedded_app_schema_keys()).expect("read app_schema_keys");
        assert!(!keys.is_empty(), "expected App Schema key facts");

        let kinds: std::collections::HashSet<&str> = keys.iter().map(|k| k.kind.as_str()).collect();
        for expected in ["runtime", "dynamic", "removed", "external"] {
            assert!(
                kinds.contains(expected),
                "missing kind {expected}: {kinds:?}"
            );
        }
        assert!(
            kinds
                .iter()
                .all(|k| ["runtime", "dynamic", "removed", "external", "deprecated"].contains(k)),
            "unknown kind in {kinds:?}"
        );

        // Setting a runtime, dynamic or removed key in a profile is wrong;
        // an external key belongs to another payload and is not.
        assert!(keys.iter().filter(|k| k.is_profile_mistake()).count() > 0);
        assert!(
            keys.iter()
                .filter(|k| k.kind == "external")
                .all(|k| !k.is_profile_mistake() && k.replacement_domain.is_some())
        );

        // A dynamic key carries the template and where its placeholder comes from.
        let dynamic = keys.iter().find(|k| k.kind == "dynamic").unwrap();
        assert!(dynamic.template.is_some());
        assert!(dynamic.placeholders.as_deref().unwrap().contains('/'));

        // Removed keys exist, and where one names a replacement that
        // replacement is a real name.
        //
        // NOT "every removed key names a replacement". A key can be withdrawn
        // with nothing put in its place, and a document is right to say so:
        // SAP's EnableTCP is gone from the 2.x RemoteLogging block, which
        // carries UseTLS, and SAP does not state whether that is a rename.
        // Requiring a replacement here would push every converter to invent
        // one, which is the opposite of what these documents are for.
        let removed: Vec<_> = keys.iter().filter(|k| k.kind == "removed").collect();
        assert!(!removed.is_empty(), "no removed keys in the dataset");
        for k in &removed {
            assert!(!k.key.is_empty(), "a removed key with no name: {k:?}");
            if let Some(r) = k.replacement_key.as_deref() {
                assert!(!r.trim().is_empty(), "{} names an empty replacement", k.key);
            }
            if let Some(d) = k.replacement_domain.as_deref() {
                assert!(!d.trim().is_empty(), "{} names an empty domain", k.key);
            }
        }
    }

    /// Every App Schema fact names a domain the capability data describes.
    #[test]
    fn app_schema_facts_join_the_capabilities() {
        let capabilities = capabilities::read(embedded_capabilities()).expect("read capabilities");
        let described: std::collections::HashSet<&str> = capabilities
            .iter()
            .map(|c| c.payload_type.as_str())
            .collect();

        let keys = app_schema::keys::read(embedded_app_schema_keys()).unwrap();
        let rules = app_schema::rules::read(embedded_app_schema_rules()).unwrap();
        for domain in keys
            .iter()
            .map(|k| k.domain.as_str())
            .chain(rules.iter().map(|r| r.domain.as_str()))
        {
            assert!(
                described.contains(domain),
                "{domain} has facts but no capability"
            );
        }
    }

    /// Rules keep their predicates as JSON in the format's grammar.
    #[test]
    fn app_schema_rules_read_with_evaluable_predicates() {
        let rules =
            app_schema::rules::read(embedded_app_schema_rules()).expect("read app_schema_rules");
        assert!(!rules.is_empty());
        for rule in &rules {
            assert!(
                ["error", "warning", "info"].contains(&rule.severity.as_str()),
                "{rule:?}"
            );
            assert!(!rule.message.is_empty());
            // A rule either asserts something or records an effect.
            assert!(
                rule.assert_predicate.is_some() ^ rule.effect.is_some(),
                "{}: needs exactly one of assert/effect",
                rule.rule_id
            );
            for json in [&rule.when_predicate, &rule.assert_predicate, &rule.effect]
                .into_iter()
                .flatten()
            {
                serde_json::from_str::<serde_json::Value>(json)
                    .unwrap_or_else(|e| panic!("{}: {e}", rule.rule_id));
            }
        }
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
    /// `with_rangelist`, the `key_rangelist` column (the ≥ 41-column layout)
    /// is appended, carrying `["Allowed","AlwaysOn"]`.
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

    /// The shipped stable parquet (41+ columns) carries Apple's
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

    /// The Windows CSP dataset shares the capabilities layout — the same
    /// reader must parse it, with kinds mapped and MSFT AllowedValues
    /// enumerations arriving through `range_list`.
    #[test]
    fn windows_capabilities_read_with_kinds_and_rangelists() {
        let caps =
            capabilities::read(embedded_windows_capabilities()).expect("read windows_capabilities");
        assert!(caps.len() > 100, "expected 100+ CSPs, got {}", caps.len());
        assert!(
            caps.iter().any(|c| c.kind == PayloadKind::CspSetting),
            "expected CspSetting capabilities"
        );
        assert!(
            caps.iter().any(|c| c.kind == PayloadKind::AdmxPolicy),
            "expected AdmxPolicy capabilities"
        );
        assert!(
            caps.iter()
                .flat_map(|c| &c.keys)
                .any(|k| k.range_list.as_ref().is_some_and(|v| !v.is_empty())),
            "expected MSFT AllowedValues enumerations in range_list"
        );
        assert!(
            caps.iter().any(|c| c.csp_name.is_some()),
            "expected csp_name to be populated"
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
        // schema-versions.toml, whose seed section the dataset pipeline supplies.
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
    fn beta_accessors_currently_mirror_stable() {
        // With no seed dataset, every `*_beta` accessor returns the stable
        // bytes (see the banner above them). This asserts that mapping
        // directly: byte equality, not set equality, so a half-finished
        // re-pointing at `data/beta/` cannot pass.
        //
        // While a seed is carried, the right invariant is that beta strictly
        // exceeds stable; restore that test together with the `data/beta/`
        // includes when a seed dataset is published again.
        assert_eq!(
            embedded_capabilities_beta().as_ptr(),
            embedded_capabilities().as_ptr(),
            "beta capabilities must be the stable bytes while beta is retired"
        );
        assert_eq!(
            embedded_skip_keys_beta().as_ptr(),
            embedded_skip_keys().as_ptr(),
            "beta skip keys must be the stable bytes while beta is retired"
        );
        assert_eq!(
            embedded_examples_beta().as_ptr(),
            embedded_examples().as_ptr(),
            "beta examples must be the stable bytes while beta is retired"
        );
        // The function the CLI asks must agree with the mapping pinned here.
        assert!(
            beta_is_retired(),
            "beta_is_retired must report the retired mapping"
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

/// Is a distinct pre-release seed dataset compiled in?
///
/// Beta is dormant, not abolished. The dataset pipeline builds it from
/// Apple's seed schema when a seed holds additions over the release branch;
/// a future seed brings it back.
///
/// This asks the bytes rather than a constant. The `*_beta` accessors above
/// currently delegate to the stable ones, which makes the two slices the
/// same memory; a real seed table would be a separate `include_bytes!` at a
/// different address. So the answer follows the dataset, and every surface
/// that reads it re-enables itself when beta returns.
pub fn beta_dataset_is_carried() -> bool {
    let stable = embedded_capabilities();
    let beta = embedded_capabilities_beta();
    !std::ptr::eq(stable.as_ptr(), beta.as_ptr()) || stable.len() != beta.len()
}

/// What to tell someone who asked for beta when no seed dataset is carried.
///
/// One copy, because two surfaces describing one channel is how this went
/// wrong in the first place: `--help` promised seed-only keys, the SOP
/// promised a superset, and the dataset had neither. Every refusal — the
/// Apple schema registry and mSCP's rule queries alike — prints this.
pub const BETA_DISABLED_MESSAGE: &str = "the beta channel is disabled in this build: no pre-release seed dataset is \
     compiled in.\n\n\
     It is dormant rather than removed. The dataset pipeline builds beta from Apple's OS seed \
     schema when a seed holds additions over the release branch. When a future seed carries seed-only declarations, keys or \
     rules, they are published and this flag starts working again with no change \
     here.\n\n\
     Until then `--beta` and `--channel beta` refuse rather than return the stable \
     dataset under a different name: a command that silently answers a question you \
     did not ask is worse than one that declines. Re-run without the flag for the \
     stable dataset, which is what this binary carries.";
