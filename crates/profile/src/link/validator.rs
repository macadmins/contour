//! Validation of cross-references between profiles.

use std::collections::HashMap;
use std::path::Path;

use crate::profile::ConfigurationProfile;

use super::extractor::extract_references;
use super::types::{
    LinkErrorType, LinkValidationError, LinkValidationResult, REFERENCE_FIELDS,
    ReferenceablePayload, UuidReference,
};

/// Validate that all cross-references in the profiles are satisfied.
///
/// Checks that:
/// 1. All referenced UUIDs exist in some payload
/// 2. Referenced payloads have the correct type for the reference field
#[allow(dead_code, reason = "reserved for future use")]
pub fn validate_cross_references(
    profiles: &[(impl AsRef<Path>, ConfigurationProfile)],
) -> LinkValidationResult {
    let (references, referenceables) = extract_references(profiles);
    validate_references(&references, &referenceables)
}

/// Validate references against available referenceable payloads.
pub fn validate_references(
    references: &[UuidReference],
    referenceables: &[ReferenceablePayload],
) -> LinkValidationResult {
    // Build lookup for available payloads
    let available: HashMap<&str, &ReferenceablePayload> = referenceables
        .iter()
        .map(|r| (r.payload_uuid.as_str(), r))
        .collect();

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    for reference in references {
        match available.get(reference.referenced_uuid.as_str()) {
            None => {
                errors.push(LinkValidationError {
                    source_payload_uuid: reference.source_payload_uuid.clone(),
                    field_name: reference.field_name.clone(),
                    referenced_uuid: reference.referenced_uuid.clone(),
                    error_type: LinkErrorType::MissingReference,
                });
            }
            Some(target) => {
                // Check type compatibility
                if let Some(spec) =
                    find_reference_spec(&reference.field_name, &reference.nested_path)
                    && !spec.target_types.contains(&target.payload_type.as_str())
                {
                    errors.push(LinkValidationError {
                        source_payload_uuid: reference.source_payload_uuid.clone(),
                        field_name: reference.field_name.clone(),
                        referenced_uuid: reference.referenced_uuid.clone(),
                        error_type: LinkErrorType::TypeMismatch {
                            expected: spec.target_types.iter().map(|s| (*s).to_string()).collect(),
                            actual: target.payload_type.clone(),
                        },
                    });
                }
            }
        }
    }

    // Check for duplicate UUIDs across profiles
    let mut uuid_sources: HashMap<&str, Vec<&Path>> = HashMap::new();
    for refable in referenceables {
        uuid_sources
            .entry(refable.payload_uuid.as_str())
            .or_default()
            .push(refable.source_profile.as_path());
    }

    for (uuid, sources) in uuid_sources {
        if sources.len() > 1 {
            warnings.push(format!(
                "UUID {} appears in multiple profiles: {:?}",
                uuid,
                sources
                    .iter()
                    .map(|p| p.file_name().unwrap_or_default().to_string_lossy())
                    .collect::<Vec<_>>()
            ));
        }
    }

    LinkValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    }
}

/// Find the reference field specification for a given field name and path.
fn find_reference_spec(
    field_name: &str,
    nested_path: &[String],
) -> Option<&'static super::types::ReferenceFieldSpec> {
    REFERENCE_FIELDS.iter().find(|spec| {
        if spec.name != field_name {
            return false;
        }

        match (spec.nested_path, nested_path.is_empty()) {
            (None, true) => true,
            (Some(spec_path), false) => {
                let spec_vec: Vec<String> = spec_path.iter().map(|s| (*s).to_string()).collect();
                spec_vec == *nested_path
            }
            _ => false,
        }
    })
}

/// Format validation errors for display.
pub fn format_validation_errors(result: &LinkValidationResult) -> String {
    let mut output = String::new();

    if result.valid {
        output.push_str("All cross-references are valid.\n");
    } else {
        output.push_str(&format!(
            "Found {} validation error(s):\n",
            result.errors.len()
        ));

        for error in &result.errors {
            match &error.error_type {
                LinkErrorType::MissingReference => {
                    output.push_str(&format!(
                        "  - Missing reference: {} in field '{}' (from payload {})\n",
                        error.referenced_uuid, error.field_name, error.source_payload_uuid
                    ));
                }
                LinkErrorType::TypeMismatch { expected, actual } => {
                    output.push_str(&format!(
                        "  - Type mismatch: {} in field '{}' - expected {:?}, got '{}'\n",
                        error.referenced_uuid, error.field_name, expected, actual
                    ));
                }
            }
        }
    }

    if !result.warnings.is_empty() {
        output.push_str(&format!("\n{} warning(s):\n", result.warnings.len()));
        for warning in &result.warnings {
            output.push_str(&format!("  - {warning}\n"));
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::PayloadContent;
    use std::path::PathBuf;

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
    fn test_valid_reference() {
        // Create a certificate payload
        let cert_payload = create_test_payload(
            "com.apple.security.root",
            "CERT-UUID-123",
            "com.test.cert",
            HashMap::new(),
        );

        // Create a WiFi payload that references the certificate
        let mut wifi_content = HashMap::new();
        wifi_content.insert(
            "PayloadCertificateAnchorUUID".to_string(),
            plist::Value::Array(vec![plist::Value::String("CERT-UUID-123".to_string())]),
        );
        let wifi_payload = create_test_payload(
            "com.apple.wifi.managed",
            "WIFI-UUID",
            "com.test.wifi",
            wifi_content,
        );

        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "PROFILE-UUID".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![cert_payload, wifi_payload],
            additional_fields: HashMap::new(),
        };

        let profiles = vec![(PathBuf::from("test.mobileconfig"), profile)];
        let result = validate_cross_references(&profiles);

        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_missing_reference() {
        // Create a WiFi payload that references a non-existent certificate
        let mut wifi_content = HashMap::new();
        wifi_content.insert(
            "PayloadCertificateAnchorUUID".to_string(),
            plist::Value::Array(vec![plist::Value::String("MISSING-UUID".to_string())]),
        );
        let wifi_payload = create_test_payload(
            "com.apple.wifi.managed",
            "WIFI-UUID",
            "com.test.wifi",
            wifi_content,
        );

        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "PROFILE-UUID".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![wifi_payload],
            additional_fields: HashMap::new(),
        };

        let profiles = vec![(PathBuf::from("test.mobileconfig"), profile)];
        let result = validate_cross_references(&profiles);

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(matches!(
            result.errors[0].error_type,
            LinkErrorType::MissingReference
        ));
    }

    #[test]
    fn test_type_mismatch() {
        // Create an SCEP payload (identity cert, not CA)
        let scep_payload = create_test_payload(
            "com.apple.security.scep",
            "SCEP-UUID",
            "com.test.scep",
            HashMap::new(),
        );

        // Create a WiFi payload that tries to use SCEP as a CA anchor (wrong type)
        let mut wifi_content = HashMap::new();
        wifi_content.insert(
            "PayloadCertificateAnchorUUID".to_string(),
            plist::Value::Array(vec![plist::Value::String("SCEP-UUID".to_string())]),
        );
        let wifi_payload = create_test_payload(
            "com.apple.wifi.managed",
            "WIFI-UUID",
            "com.test.wifi",
            wifi_content,
        );

        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "PROFILE-UUID".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![scep_payload, wifi_payload],
            additional_fields: HashMap::new(),
        };

        let profiles = vec![(PathBuf::from("test.mobileconfig"), profile)];
        let result = validate_cross_references(&profiles);

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(matches!(
            result.errors[0].error_type,
            LinkErrorType::TypeMismatch { .. }
        ));
    }
}
