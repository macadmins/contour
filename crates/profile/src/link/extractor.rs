//! Extract UUID references from configuration profiles.

use std::collections::HashMap;
use std::path::Path;

use crate::profile::{ConfigurationProfile, PayloadContent};

use super::types::{
    REFERENCE_FIELDS, ReferenceFieldSpec, ReferenceablePayload, UuidReference,
    is_referenceable_type,
};

/// Extract all UUID references and referenceable payloads from a set of profiles.
///
/// Returns a tuple of (references, referenceables) where:
/// - references: All UUID reference fields found in the profiles
/// - referenceables: All payloads that can be referenced (certificates, etc.)
pub fn extract_references(
    profiles: &[(impl AsRef<Path>, ConfigurationProfile)],
) -> (Vec<UuidReference>, Vec<ReferenceablePayload>) {
    let mut references = Vec::new();
    let mut referenceables = Vec::new();

    for (path, profile) in profiles {
        let path = path.as_ref();

        for payload in &profile.payload_content {
            // Check if this payload is referenceable (certificate types)
            if is_referenceable_type(&payload.payload_type) {
                referenceables.push(ReferenceablePayload {
                    source_profile: path.to_path_buf(),
                    payload_uuid: payload.payload_uuid.clone(),
                    payload_type: payload.payload_type.clone(),
                    payload_identifier: payload.payload_identifier.clone(),
                    display_name: payload.payload_display_name(),
                });
            }

            // Extract references from this payload
            for spec in REFERENCE_FIELDS {
                if let Some(refs) = extract_field_references(path, payload, spec) {
                    references.extend(refs);
                }
            }
        }
    }

    (references, referenceables)
}

/// Extract references from a specific field in a payload.
fn extract_field_references(
    path: &Path,
    payload: &PayloadContent,
    spec: &ReferenceFieldSpec,
) -> Option<Vec<UuidReference>> {
    let mut refs = Vec::new();

    // Navigate to the value (direct or nested)
    let value = if let Some(nested_path) = spec.nested_path {
        navigate_nested(&payload.content, nested_path, spec.name)?
    } else {
        payload.content.get(spec.name)?
    };

    if spec.is_array {
        // Handle array of UUIDs
        if let plist::Value::Array(arr) = value {
            for (idx, item) in arr.iter().enumerate() {
                if let plist::Value::String(uuid) = item {
                    refs.push(UuidReference {
                        source_profile: path.to_path_buf(),
                        source_payload_uuid: payload.payload_uuid.clone(),
                        source_payload_type: payload.payload_type.clone(),
                        source_payload_identifier: payload.payload_identifier.clone(),
                        field_name: spec.name.to_string(),
                        referenced_uuid: uuid.clone(),
                        nested_path: spec
                            .nested_path
                            .map(|p| p.iter().map(|s| (*s).to_string()).collect())
                            .unwrap_or_default(),
                        is_array_element: true,
                        array_index: Some(idx),
                    });
                }
            }
        }
    } else {
        // Handle single UUID
        if let plist::Value::String(uuid) = value {
            refs.push(UuidReference {
                source_profile: path.to_path_buf(),
                source_payload_uuid: payload.payload_uuid.clone(),
                source_payload_type: payload.payload_type.clone(),
                source_payload_identifier: payload.payload_identifier.clone(),
                field_name: spec.name.to_string(),
                referenced_uuid: uuid.clone(),
                nested_path: spec
                    .nested_path
                    .map(|p| p.iter().map(|s| (*s).to_string()).collect())
                    .unwrap_or_default(),
                is_array_element: false,
                array_index: None,
            });
        }
    }

    if refs.is_empty() { None } else { Some(refs) }
}

/// Navigate into nested dictionaries to find a value.
fn navigate_nested<'a>(
    content: &'a HashMap<String, plist::Value>,
    path: &[&str],
    field_name: &str,
) -> Option<&'a plist::Value> {
    let mut current: &plist::Value = content.get(path[0])?;

    // Navigate through intermediate path elements
    for key in &path[1..] {
        if let plist::Value::Dictionary(dict) = current {
            current = dict.get(key)?;
        } else {
            return None;
        }
    }

    // Get the final field from the last dictionary
    if let plist::Value::Dictionary(dict) = current {
        dict.get(field_name)
    } else {
        None
    }
}

/// Navigate into nested dictionaries and return a mutable reference.
#[allow(
    clippy::implicit_hasher,
    reason = "generic hasher not needed for this use case"
)]
pub fn navigate_nested_mut<'a>(
    content: &'a mut HashMap<String, plist::Value>,
    path: &[&str],
    field_name: &str,
) -> Option<&'a mut plist::Value> {
    let first_key = path[0];
    let mut current: &mut plist::Value = content.get_mut(first_key)?;

    // Navigate through intermediate path elements
    for key in &path[1..] {
        if let plist::Value::Dictionary(dict) = current {
            current = dict.get_mut(key)?;
        } else {
            return None;
        }
    }

    // Get the final field from the last dictionary
    if let plist::Value::Dictionary(dict) = current {
        dict.get_mut(field_name)
    } else {
        None
    }
}

/// Get a summary of extracted references for display.
pub fn summarize_extraction(
    references: &[UuidReference],
    referenceables: &[ReferenceablePayload],
) -> ExtractionSummary {
    use std::collections::HashSet;

    let unique_referenced: HashSet<_> = references.iter().map(|r| &r.referenced_uuid).collect();
    let available: HashSet<_> = referenceables.iter().map(|r| &r.payload_uuid).collect();

    let orphans: Vec<_> = unique_referenced
        .iter()
        .filter(|uuid| !available.contains(*uuid))
        .map(|uuid| (*uuid).clone())
        .collect();

    ExtractionSummary {
        total_references: references.len(),
        unique_referenced_uuids: unique_referenced.len(),
        referenceable_payloads: referenceables.len(),
        orphan_references: orphans,
    }
}

/// Summary of extraction results.
#[derive(Debug)]
pub struct ExtractionSummary {
    /// Total number of UUID references found
    pub total_references: usize,
    /// Number of unique UUIDs referenced
    pub unique_referenced_uuids: usize,
    /// Number of referenceable payloads found
    pub referenceable_payloads: usize,
    /// UUIDs that are referenced but not found in any payload
    pub orphan_references: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_payload(
        payload_type: &str,
        uuid: &str,
        identifier: &str,
        content: HashMap<String, plist::Value>,
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
    fn test_extract_direct_reference() {
        let mut content = HashMap::new();
        content.insert(
            "PayloadCertificateUUID".to_string(),
            plist::Value::String("CERT-UUID-123".to_string()),
        );

        let payload = create_test_payload(
            "com.apple.wifi.managed",
            "WIFI-UUID-456",
            "com.test.wifi",
            content,
        );

        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "PROFILE-UUID".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![payload],
            additional_fields: HashMap::new(),
        };

        let profiles = vec![(std::path::PathBuf::from("test.mobileconfig"), profile)];
        let (references, _) = extract_references(&profiles);

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].referenced_uuid, "CERT-UUID-123");
        assert_eq!(references[0].field_name, "PayloadCertificateUUID");
        assert!(!references[0].is_array_element);
    }

    #[test]
    fn test_extract_nested_reference() {
        let mut eap_config = plist::Dictionary::new();
        eap_config.insert(
            "TLSTrustedCertificates".to_string(),
            plist::Value::Array(vec![
                plist::Value::String("CA-UUID-1".to_string()),
                plist::Value::String("CA-UUID-2".to_string()),
            ]),
        );

        let mut content = HashMap::new();
        content.insert(
            "EAPClientConfiguration".to_string(),
            plist::Value::Dictionary(eap_config),
        );

        let payload = create_test_payload(
            "com.apple.wifi.managed",
            "WIFI-UUID",
            "com.test.wifi",
            content,
        );

        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "PROFILE-UUID".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![payload],
            additional_fields: HashMap::new(),
        };

        let profiles = vec![(std::path::PathBuf::from("test.mobileconfig"), profile)];
        let (references, _) = extract_references(&profiles);

        let tls_refs: Vec<_> = references
            .iter()
            .filter(|r| r.field_name == "TLSTrustedCertificates")
            .collect();

        assert_eq!(tls_refs.len(), 2);
        assert!(tls_refs[0].is_array_element);
        assert_eq!(tls_refs[0].array_index, Some(0));
        assert_eq!(tls_refs[0].referenced_uuid, "CA-UUID-1");
        assert_eq!(tls_refs[1].array_index, Some(1));
        assert_eq!(tls_refs[1].referenced_uuid, "CA-UUID-2");
    }

    #[test]
    fn test_extract_referenceable_payloads() {
        let cert_payload = create_test_payload(
            "com.apple.security.root",
            "CERT-UUID",
            "com.test.cert",
            HashMap::new(),
        );

        let scep_payload = create_test_payload(
            "com.apple.security.scep",
            "SCEP-UUID",
            "com.test.scep",
            HashMap::new(),
        );

        let wifi_payload = create_test_payload(
            "com.apple.wifi.managed",
            "WIFI-UUID",
            "com.test.wifi",
            HashMap::new(),
        );

        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "PROFILE-UUID".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![cert_payload, scep_payload, wifi_payload],
            additional_fields: HashMap::new(),
        };

        let profiles = vec![(std::path::PathBuf::from("test.mobileconfig"), profile)];
        let (_, referenceables) = extract_references(&profiles);

        assert_eq!(referenceables.len(), 2);
        assert!(referenceables.iter().any(|r| r.payload_uuid == "CERT-UUID"));
        assert!(referenceables.iter().any(|r| r.payload_uuid == "SCEP-UUID"));
    }
}
