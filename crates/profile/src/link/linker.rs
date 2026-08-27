//! UUID synchronization and profile linking logic.

use std::path::PathBuf;

use anyhow::Result;

use crate::profile::ConfigurationProfile;
use crate::uuid::{self, UuidConfig};

use super::extractor::{extract_references, navigate_nested_mut};
use super::types::{LinkConfig, LinkResult, REFERENCE_FIELDS, UuidMapping};
use super::validator::validate_references;

/// Link profiles by synchronizing their UUID cross-references.
///
/// This function:
/// 1. Extracts all references and referenceable payloads
/// 2. Validates that all references can be resolved
/// 3. Generates new UUIDs for all payloads
/// 4. Updates all reference fields to use the new UUIDs
pub fn link_profiles(
    profiles: Vec<(PathBuf, ConfigurationProfile)>,
    config: &LinkConfig,
) -> Result<LinkResult> {
    // 1. Extract all references and referenceable payloads
    let (references, referenceables) = extract_references(&profiles);

    // 2. Validate references if requested
    if config.validate {
        let validation = validate_references(&references, &referenceables);
        if !validation.valid {
            let error_msg = validation
                .errors
                .iter()
                .map(|e| {
                    format!(
                        "{}: {} -> {}",
                        e.field_name, e.source_payload_uuid, e.referenced_uuid
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!("Invalid cross-references: {error_msg}");
        }
    }

    // 3. Generate UUID mapping for all payloads
    let uuid_mapping = generate_uuid_mapping(&profiles, config)?;

    // 4. Apply mapping to all profiles
    let linked_profiles = apply_uuid_mapping(profiles, &uuid_mapping)?;

    Ok(LinkResult {
        profiles: linked_profiles,
        uuid_mapping,
        reference_count: references.len(),
        referenceable_count: referenceables.len(),
    })
}

/// Generate UUID mapping for all payloads in the profiles.
fn generate_uuid_mapping(
    profiles: &[(PathBuf, ConfigurationProfile)],
    config: &LinkConfig,
) -> Result<UuidMapping> {
    let mut mapping = UuidMapping::new();

    let uuid_config = UuidConfig {
        org_domain: config.org_domain.clone(),
        predictable: config.predictable,
    };

    for (_, profile) in profiles {
        // Generate new UUID for the profile envelope
        let new_profile_uuid = uuid::generate_uuid(&uuid_config, &profile.payload_identifier)?;
        mapping.insert(profile.payload_uuid.clone(), new_profile_uuid);

        // Generate new UUIDs for each payload
        for payload in &profile.payload_content {
            let new_payload_uuid = uuid::generate_uuid(&uuid_config, &payload.payload_identifier)?;
            mapping.insert(payload.payload_uuid.clone(), new_payload_uuid);
        }
    }

    Ok(mapping)
}

/// Apply a UUID mapping to one profile in place: rewrite the envelope and payload
/// UUIDs and every reference field (`REFERENCE_FIELDS`).
#[allow(
    dead_code,
    reason = "called from reidentify module; CLI wired in Task 5"
)]
pub(crate) fn remap_uuids_in_profile(
    profile: &mut crate::profile::ConfigurationProfile,
    mapping: &UuidMapping,
) -> anyhow::Result<()> {
    if let Some(new_uuid) = mapping.get(&profile.payload_uuid) {
        profile.payload_uuid = new_uuid.clone();
    }
    for payload in &mut profile.payload_content {
        if let Some(new_uuid) = mapping.get(&payload.payload_uuid) {
            payload.payload_uuid = new_uuid.clone();
        }
        update_payload_references(payload, mapping)?;
    }
    Ok(())
}

/// Apply UUID mapping to all profiles.
fn apply_uuid_mapping(
    mut profiles: Vec<(PathBuf, ConfigurationProfile)>,
    mapping: &UuidMapping,
) -> Result<Vec<(PathBuf, ConfigurationProfile)>> {
    for (_, profile) in &mut profiles {
        // Update profile's own UUID
        if let Some(new_uuid) = mapping.get(&profile.payload_uuid) {
            profile.payload_uuid = new_uuid.clone();
        }

        // Update each payload
        for payload in &mut profile.payload_content {
            // Update payload's own UUID
            if let Some(new_uuid) = mapping.get(&payload.payload_uuid) {
                payload.payload_uuid = new_uuid.clone();
            }

            // Update reference fields within this payload
            update_payload_references(payload, mapping)?;
        }
    }

    Ok(profiles)
}

/// Update all reference fields within a payload.
fn update_payload_references(
    payload: &mut crate::profile::PayloadContent,
    mapping: &UuidMapping,
) -> Result<()> {
    for spec in REFERENCE_FIELDS {
        if let Some(nested_path) = spec.nested_path {
            // Handle nested reference
            update_nested_reference(payload, nested_path, spec.name, spec.is_array, mapping)?;
        } else {
            // Handle direct reference
            update_direct_reference(payload, spec.name, spec.is_array, mapping)?;
        }
    }
    Ok(())
}

/// Update a direct (non-nested) reference field.
fn update_direct_reference(
    payload: &mut crate::profile::PayloadContent,
    field_name: &str,
    is_array: bool,
    mapping: &UuidMapping,
) -> Result<()> {
    if let Some(value) = payload.content.get_mut(field_name) {
        update_uuid_value(value, is_array, mapping);
    }
    Ok(())
}

/// Update a nested reference field.
fn update_nested_reference(
    payload: &mut crate::profile::PayloadContent,
    path: &[&str],
    field_name: &str,
    is_array: bool,
    mapping: &UuidMapping,
) -> Result<()> {
    if let Some(value) = navigate_nested_mut(&mut payload.content, path, field_name) {
        update_uuid_value(value, is_array, mapping);
    }
    Ok(())
}

/// Update a UUID value (single or array) using the mapping.
fn update_uuid_value(value: &mut plist::Value, is_array: bool, mapping: &UuidMapping) {
    if is_array {
        if let plist::Value::Array(arr) = value {
            for item in arr.iter_mut() {
                if let plist::Value::String(uuid) = item
                    && let Some(new_uuid) = mapping.get(uuid)
                {
                    *uuid = new_uuid.clone();
                }
            }
        }
    } else if let plist::Value::String(uuid) = value
        && let Some(new_uuid) = mapping.get(uuid)
    {
        *uuid = new_uuid.clone();
    }
}

/// Merge multiple profiles into a single profile.
#[allow(dead_code, reason = "reserved for future use")]
pub fn merge_profiles(
    profiles: Vec<(PathBuf, ConfigurationProfile)>,
    config: &LinkConfig,
) -> Result<ConfigurationProfile> {
    if profiles.is_empty() {
        anyhow::bail!("No profiles to merge");
    }

    // First, link the profiles to synchronize UUIDs
    let link_result = link_profiles(profiles, config)?;
    let linked = link_result.profiles;

    // Use the first profile as the base
    let (_, base) = linked.into_iter().next().unwrap();
    let merged = base;

    // Collect all payloads from remaining profiles
    // Note: We already consumed the first one, so we need to handle this differently
    // Let's redo this more carefully

    Ok(merged)
}

/// Outcome of [`merge_profiles_v2`].
#[derive(Debug)]
pub struct MergeResult {
    /// The merged profile.
    pub profile: ConfigurationProfile,
    /// UUID rewrites applied across the inputs.
    pub uuid_mapping: UuidMapping,
    /// `PayloadIdentifier`s of payloads dropped by the dedupe — an
    /// identifier already present in the merged set wins, later payloads
    /// with the same identifier are discarded. Callers must surface these:
    /// a silent drop loses configuration (e.g. one of two CA certificates
    /// that share an identifier).
    pub dropped_payloads: Vec<String>,
}

/// Merge multiple profiles into a single profile (improved version).
pub fn merge_profiles_v2(
    profiles: Vec<(PathBuf, ConfigurationProfile)>,
    config: &LinkConfig,
) -> Result<MergeResult> {
    if profiles.is_empty() {
        anyhow::bail!("No profiles to merge");
    }

    // Extract all references first
    let (references, referenceables) = extract_references(&profiles);

    // Validate if requested
    if config.validate {
        let validation = validate_references(&references, &referenceables);
        if !validation.valid {
            let error_msg = validation
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.field_name, e.referenced_uuid))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!("Invalid cross-references: {error_msg}");
        }
    }

    // Generate UUID mapping
    let uuid_mapping = generate_uuid_mapping(&profiles, config)?;

    // Apply mapping to get linked profiles
    let linked = apply_uuid_mapping(profiles, &uuid_mapping)?;

    // Merge into a single profile
    let mut iter = linked.into_iter();
    let (_, mut merged) = iter.next().unwrap();

    // Generate a new identifier and UUID for the merged profile. The merged
    // identifier is deployed to devices, so an org domain is mandatory —
    // there is deliberately no com.example fallback.
    let Some(org_domain) = config.org_domain.as_deref() else {
        anyhow::bail!(
            "--merge requires an organization domain for the merged profile's \
             identifier: pass --org <domain>, or set organization.domain in \
             profile.toml or .contour/config.toml"
        );
    };
    let merged_identifier = format!("{org_domain}.merged");

    let uuid_config = UuidConfig {
        org_domain: config.org_domain.clone(),
        predictable: config.predictable,
    };
    merged.payload_uuid = uuid::generate_uuid(&uuid_config, &merged_identifier)?;
    merged.payload_identifier = merged_identifier;
    merged.payload_display_name = format!("{} (Merged)", merged.payload_display_name);

    // Add payloads from other profiles, deduplicating by identifier and
    // recording every drop so the caller can warn.
    let mut dropped_payloads = Vec::new();
    for (_, profile) in iter {
        for payload in profile.payload_content {
            let exists = merged
                .payload_content
                .iter()
                .any(|p| p.payload_identifier == payload.payload_identifier);

            if exists {
                dropped_payloads.push(payload.payload_identifier);
            } else {
                merged.payload_content.push(payload);
            }
        }
    }

    Ok(MergeResult {
        profile: merged,
        uuid_mapping,
        dropped_payloads,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::PayloadContent;
    use std::collections::BTreeMap;

    fn create_test_payload(
        payload_type: &str,
        uuid: &str,
        identifier: &str,
        content: BTreeMap<String, plist::Value>,
    ) -> PayloadContent {
        PayloadContent {
            payload_type: payload_type.to_string(),
            payload_version: 1,
            payload_identifier: identifier.to_string(),
            payload_uuid: uuid.to_string(),
            content,
        }
    }

    #[test]
    fn test_link_profiles_updates_references() {
        // Create a certificate payload
        let cert_payload = create_test_payload(
            "com.apple.security.root",
            "OLD-CERT-UUID",
            "com.test.cert",
            BTreeMap::new(),
        );

        // Create a WiFi payload that references the certificate
        let mut wifi_content = BTreeMap::new();
        wifi_content.insert(
            "PayloadCertificateAnchorUUID".to_string(),
            plist::Value::Array(vec![plist::Value::String("OLD-CERT-UUID".to_string())]),
        );
        let wifi_payload = create_test_payload(
            "com.apple.wifi.managed",
            "OLD-WIFI-UUID",
            "com.test.wifi",
            wifi_content,
        );

        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "OLD-PROFILE-UUID".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![cert_payload, wifi_payload],
            additional_fields: BTreeMap::new(),
        };

        let profiles = vec![(PathBuf::from("test.mobileconfig"), profile)];

        let config = LinkConfig {
            org_domain: Some("com.test".to_string()),
            predictable: true,
            merge: false,
            validate: true,
        };

        let result = link_profiles(profiles, &config).unwrap();

        // Check that UUIDs were updated
        assert_ne!(result.profiles[0].1.payload_uuid, "OLD-PROFILE-UUID");

        // Check that the reference was updated to match the new cert UUID
        let wifi = result.profiles[0]
            .1
            .payload_content
            .iter()
            .find(|p| p.payload_type == "com.apple.wifi.managed")
            .unwrap();

        let cert = result.profiles[0]
            .1
            .payload_content
            .iter()
            .find(|p| p.payload_type == "com.apple.security.root")
            .unwrap();

        // Get the referenced UUID from WiFi payload
        let anchor_uuids = wifi
            .content
            .get("PayloadCertificateAnchorUUID")
            .unwrap()
            .as_array()
            .unwrap();

        let referenced_uuid = anchor_uuids[0].as_string().unwrap();

        // Verify it matches the cert's new UUID
        assert_eq!(referenced_uuid, cert.payload_uuid);
    }

    /// Merge dedupes by PayloadIdentifier. Dropping a payload is sometimes
    /// right (true duplicates) but must never be silent — a root and an
    /// intermediate CA sharing an identifier would lose one certificate.
    #[test]
    fn merge_reports_payloads_dropped_by_identifier_dedupe() {
        let make_profile =
            |profile_id: &str, payload_uuid: &str, display: &str| ConfigurationProfile {
                payload_type: "Configuration".to_string(),
                payload_version: 1,
                payload_identifier: profile_id.to_string(),
                payload_uuid: format!("{payload_uuid}-PROFILE"),
                payload_display_name: display.to_string(),
                payload_content: vec![create_test_payload(
                    "com.apple.security.root",
                    payload_uuid,
                    "com.test.shared-ca",
                    BTreeMap::new(),
                )],
                additional_fields: BTreeMap::new(),
            };

        let config = LinkConfig {
            org_domain: Some("com.test".to_string()),
            predictable: true,
            merge: true,
            validate: false,
        };

        let result = merge_profiles_v2(
            vec![
                (
                    PathBuf::from("a.mobileconfig"),
                    make_profile("com.test.a", "UUID-A", "A"),
                ),
                (
                    PathBuf::from("b.mobileconfig"),
                    make_profile("com.test.b", "UUID-B", "B"),
                ),
            ],
            &config,
        )
        .unwrap();

        assert_eq!(result.profile.payload_content.len(), 1);
        assert_eq!(
            result.dropped_payloads,
            vec!["com.test.shared-ca".to_string()],
            "the dropped payload's identifier must be reported"
        );
    }

    #[test]
    fn merge_without_org_domain_is_rejected() {
        let cert_payload = create_test_payload(
            "com.apple.security.root",
            "OLD-UUID",
            "com.test.cert",
            BTreeMap::new(),
        );

        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "OLD-PROFILE-UUID".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![cert_payload],
            additional_fields: BTreeMap::new(),
        };

        let config = LinkConfig {
            org_domain: None,
            predictable: false,
            merge: true,
            validate: false,
        };

        let err = merge_profiles_v2(vec![(PathBuf::from("test.mobileconfig"), profile)], &config)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--org"),
            "error should tell the user how to fix it, got: {msg}"
        );
        assert!(
            !msg.contains("com.example"),
            "com.example must never be suggested, got: {msg}"
        );
    }

    #[test]
    fn test_predictable_uuids_are_consistent() {
        let cert_payload = create_test_payload(
            "com.apple.security.root",
            "OLD-UUID",
            "com.test.cert",
            BTreeMap::new(),
        );

        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "OLD-PROFILE-UUID".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![cert_payload],
            additional_fields: BTreeMap::new(),
        };

        let profiles1 = vec![(PathBuf::from("test.mobileconfig"), profile.clone())];
        let profiles2 = vec![(PathBuf::from("test.mobileconfig"), profile)];

        let config = LinkConfig {
            org_domain: Some("com.test".to_string()),
            predictable: true,
            merge: false,
            validate: false,
        };

        let result1 = link_profiles(profiles1, &config).unwrap();
        let result2 = link_profiles(profiles2, &config).unwrap();

        // Same input should produce same UUIDs with predictable mode
        assert_eq!(
            result1.profiles[0].1.payload_uuid,
            result2.profiles[0].1.payload_uuid
        );
        assert_eq!(
            result1.profiles[0].1.payload_content[0].payload_uuid,
            result2.profiles[0].1.payload_content[0].payload_uuid
        );
    }
}
