use super::ConfigurationProfile;
use anyhow::Result;

#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn validate_profile(profile: &ConfigurationProfile) -> Result<ValidationResult> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Top-level PayloadType must be "Configuration"
    if profile.payload_type != "Configuration" {
        errors.push(format!(
            "Invalid PayloadType: expected 'Configuration', got '{}'",
            profile.payload_type
        ));
    }

    // PayloadVersion should be 1
    if profile.payload_version != 1 {
        errors.push(format!(
            "Invalid PayloadVersion: expected 1, got {}",
            profile.payload_version
        ));
    }

    // PayloadIdentifier validation
    if profile.payload_identifier.is_empty() {
        errors.push("PayloadIdentifier cannot be empty".to_string());
    } else {
        validate_identifier_format(
            &profile.payload_identifier,
            "PayloadIdentifier",
            &mut errors,
            &mut warnings,
        );
    }

    // PayloadUUID validation
    if profile.payload_uuid.is_empty() {
        errors.push("PayloadUUID cannot be empty".to_string());
    } else if !is_valid_uuid(&profile.payload_uuid) {
        errors.push(format!(
            "Invalid PayloadUUID format: {}",
            profile.payload_uuid
        ));
    }

    // PayloadDisplayName warning
    if profile.payload_display_name.is_empty() {
        warnings.push("PayloadDisplayName is empty".to_string());
    }

    // PayloadScope validation (if present)
    if let Some(scope) = profile.additional_fields.get("PayloadScope")
        && let Some(scope_str) = scope.as_string()
    {
        validate_payload_scope(scope_str, "Profile", &mut errors, &mut warnings);
    }

    // PayloadContent validation
    if profile.payload_content.is_empty() {
        errors.push("PayloadContent is empty - profile has no configuration items".to_string());
    }

    for (index, content) in profile.payload_content.iter().enumerate() {
        // PayloadIdentifier
        if content.payload_identifier.is_empty() {
            errors.push(format!(
                "PayloadContent[{index}]: PayloadIdentifier cannot be empty"
            ));
        } else {
            validate_identifier_format(
                &content.payload_identifier,
                &format!("PayloadContent[{index}].PayloadIdentifier"),
                &mut errors,
                &mut warnings,
            );
        }

        // PayloadUUID
        if content.payload_uuid.is_empty() {
            errors.push(format!(
                "PayloadContent[{index}]: PayloadUUID cannot be empty"
            ));
        } else if !is_valid_uuid(&content.payload_uuid) {
            errors.push(format!(
                "PayloadContent[{}]: Invalid PayloadUUID format: {}",
                index, content.payload_uuid
            ));
        }

        // PayloadVersion in nested payload
        if content.payload_version != 1 {
            warnings.push(format!(
                "PayloadContent[{}]: PayloadVersion is {}, expected 1",
                index, content.payload_version
            ));
        }

        // PayloadScope in nested payload (if present)
        if let Some(scope) = content.content.get("PayloadScope")
            && let Some(scope_str) = scope.as_string()
        {
            validate_payload_scope(
                scope_str,
                &format!("PayloadContent[{index}]"),
                &mut errors,
                &mut warnings,
            );
        }
    }

    Ok(ValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    })
}

fn is_valid_uuid(uuid: &str) -> bool {
    uuid::Uuid::parse_str(uuid).is_ok()
}

/// Validate reverse-DNS style identifier format
fn validate_identifier_format(
    identifier: &str,
    field_name: &str,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    // Check for basic reverse-DNS structure
    let parts: Vec<&str> = identifier.split('.').collect();

    if parts.len() < 2 {
        warnings.push(format!(
            "{field_name}: '{identifier}' should be in reverse-DNS format (e.g., 'com.example.profile')"
        ));
        return;
    }

    // Check for empty segments
    if parts.iter().any(|p| p.is_empty()) {
        errors.push(format!(
            "{field_name}: '{identifier}' contains empty segments (consecutive dots)"
        ));
        return;
    }

    // Check for invalid characters
    // Valid: alphanumeric, hyphen, underscore
    let invalid_chars: Vec<char> = identifier
        .chars()
        .filter(|c| !c.is_alphanumeric() && *c != '.' && *c != '-' && *c != '_')
        .collect();

    if !invalid_chars.is_empty() {
        let unique_invalid: std::collections::HashSet<char> = invalid_chars.into_iter().collect();
        // Provide a friendlier message for spaces
        if unique_invalid.contains(&' ') {
            errors.push(format!(
                "{field_name}: '{identifier}' contains spaces which are not allowed in identifiers"
            ));
        } else {
            errors.push(format!(
                "{field_name}: '{identifier}' contains invalid characters: {unique_invalid:?}"
            ));
        }
        return;
    }

    // Check first segment (should be TLD-like: com, org, net, io, etc.)
    let first_segment = parts[0].to_lowercase();
    let common_tlds = [
        "com", "org", "net", "io", "edu", "gov", "mil", "co", "me", "us", "uk", "de", "fr", "jp",
        "au", "ca",
    ];
    if !common_tlds.contains(&first_segment.as_str()) && first_segment.len() > 4 {
        warnings.push(format!(
            "{}: First segment '{}' doesn't look like a TLD - expected reverse-DNS format",
            field_name, parts[0]
        ));
    }
}

/// Validate PayloadScope value
fn validate_payload_scope(
    scope: &str,
    context: &str,
    errors: &mut Vec<String>,
    _warnings: &mut Vec<String>,
) {
    match scope {
        "User" | "System" => {
            // Valid values
        }
        "" => {
            // Empty is technically allowed (defaults to System)
        }
        _ => {
            errors.push(format!(
                "{context}: Invalid PayloadScope '{scope}' - must be 'User' or 'System'"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::PayloadContent;
    use std::collections::HashMap;

    // ========== Test Fixtures ==========

    fn create_valid_profile() -> ConfigurationProfile {
        let mut additional_fields = HashMap::new();
        additional_fields.insert(
            "PayloadDescription".to_string(),
            plist::Value::String("A test profile".to_string()),
        );
        additional_fields.insert(
            "PayloadOrganization".to_string(),
            plist::Value::String("Test Org".to_string()),
        );

        let mut content = HashMap::new();
        content.insert(
            "PayloadDisplayName".to_string(),
            plist::Value::String("WiFi".to_string()),
        );

        ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "12345678-1234-1234-1234-123456789012".to_string(),
            payload_display_name: "Test Profile".to_string(),
            payload_content: vec![PayloadContent {
                payload_type: "com.apple.wifi.managed".to_string(),
                payload_version: 1,
                payload_identifier: "com.test.wifi".to_string(),
                payload_uuid: "87654321-4321-4321-4321-210987654321".to_string(),
                content,
            }],
            additional_fields,
        }
    }

    fn create_minimal_profile() -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "12345678-1234-1234-1234-123456789012".to_string(),
            payload_display_name: "Test Profile".to_string(),
            payload_content: vec![PayloadContent {
                payload_type: "com.apple.loginwindow".to_string(),
                payload_version: 1,
                payload_identifier: "com.test.loginwindow".to_string(),
                payload_uuid: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".to_string(),
                content: HashMap::new(),
            }],
            additional_fields: HashMap::new(),
        }
    }

    // ========== Valid Profile Tests ==========

    #[test]
    fn test_validate_valid_profile() {
        let profile = create_valid_profile();
        let result = validate_profile(&profile).unwrap();

        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_minimal_valid_profile() {
        let profile = create_minimal_profile();
        let result = validate_profile(&profile).unwrap();

        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    // ========== PayloadType Validation ==========

    #[test]
    fn test_validate_invalid_payload_type() {
        let mut profile = create_valid_profile();
        profile.payload_type = "Profile".to_string(); // Should be "Configuration"

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("PayloadType") && e.contains("Configuration"))
        );
    }

    #[test]
    fn test_validate_empty_payload_type() {
        let mut profile = create_valid_profile();
        profile.payload_type = String::new();

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("PayloadType")));
    }

    // ========== PayloadVersion Validation ==========

    #[test]
    fn test_validate_invalid_payload_version() {
        let mut profile = create_valid_profile();
        profile.payload_version = 2; // Should be 1

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("PayloadVersion")));
    }

    #[test]
    fn test_validate_zero_payload_version() {
        let mut profile = create_valid_profile();
        profile.payload_version = 0;

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
    }

    #[test]
    fn test_validate_negative_payload_version() {
        let mut profile = create_valid_profile();
        profile.payload_version = -1;

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
    }

    // ========== PayloadIdentifier Validation ==========

    #[test]
    fn test_validate_empty_payload_identifier() {
        let mut profile = create_valid_profile();
        profile.payload_identifier = String::new();

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("PayloadIdentifier") && e.contains("empty"))
        );
    }

    #[test]
    fn test_validate_valid_payload_identifier() {
        let mut profile = create_valid_profile();
        profile.payload_identifier = "com.example.long.identifier.path".to_string();

        let result = validate_profile(&profile).unwrap();

        assert!(result.valid);
    }

    // ========== PayloadUUID Validation ==========

    #[test]
    fn test_validate_empty_payload_uuid() {
        let mut profile = create_valid_profile();
        profile.payload_uuid = String::new();

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("PayloadUUID") && e.contains("empty"))
        );
    }

    #[test]
    fn test_validate_invalid_uuid_format() {
        let mut profile = create_valid_profile();
        profile.payload_uuid = "not-a-valid-uuid".to_string();

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("PayloadUUID") && e.contains("Invalid"))
        );
    }

    #[test]
    fn test_validate_valid_uuid_lowercase() {
        let mut profile = create_valid_profile();
        profile.payload_uuid = "12345678-1234-1234-1234-123456789012".to_string();

        let result = validate_profile(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_validate_valid_uuid_uppercase() {
        let mut profile = create_valid_profile();
        profile.payload_uuid = "ABCDEF12-3456-7890-ABCD-EF1234567890".to_string();

        let result = validate_profile(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_validate_valid_uuid_mixed_case() {
        let mut profile = create_valid_profile();
        profile.payload_uuid = "AbCdEf12-3456-7890-AbCd-Ef1234567890".to_string();

        let result = validate_profile(&profile).unwrap();

        assert!(result.valid);
    }

    // ========== PayloadDisplayName Validation ==========

    #[test]
    fn test_validate_empty_display_name_warning() {
        let mut profile = create_valid_profile();
        profile.payload_display_name = String::new();

        let result = validate_profile(&profile).unwrap();

        // Empty display name should be a warning, not error
        assert!(result.valid);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("PayloadDisplayName") && w.contains("empty"))
        );
    }

    #[test]
    fn test_validate_display_name_present_no_warning() {
        let profile = create_valid_profile();

        let result = validate_profile(&profile).unwrap();

        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("PayloadDisplayName"))
        );
    }

    // ========== PayloadContent Validation ==========

    #[test]
    fn test_validate_empty_payload_content() {
        let mut profile = create_valid_profile();
        profile.payload_content.clear();

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("PayloadContent") && e.contains("empty"))
        );
    }

    #[test]
    fn test_validate_content_empty_identifier() {
        let mut profile = create_valid_profile();
        profile.payload_content[0].payload_identifier = String::new();

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| {
            e.contains("PayloadContent[0]")
                && e.contains("PayloadIdentifier")
                && e.contains("empty")
        }));
    }

    #[test]
    fn test_validate_content_empty_uuid() {
        let mut profile = create_valid_profile();
        profile.payload_content[0].payload_uuid = String::new();

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| {
            e.contains("PayloadContent[0]") && e.contains("PayloadUUID") && e.contains("empty")
        }));
    }

    #[test]
    fn test_validate_content_invalid_uuid() {
        let mut profile = create_valid_profile();
        profile.payload_content[0].payload_uuid = "invalid".to_string();

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| {
            e.contains("PayloadContent[0]") && e.contains("PayloadUUID") && e.contains("Invalid")
        }));
    }

    // ========== Multiple PayloadContent Tests ==========

    #[test]
    fn test_validate_multiple_payloads_all_valid() {
        let mut profile = create_valid_profile();
        profile.payload_content.push(PayloadContent {
            payload_type: "com.apple.vpn.managed".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.vpn".to_string(),
            payload_uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            content: HashMap::new(),
        });

        let result = validate_profile(&profile).unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_validate_multiple_payloads_one_invalid() {
        let mut profile = create_valid_profile();
        profile.payload_content.push(PayloadContent {
            payload_type: "com.apple.vpn.managed".to_string(),
            payload_version: 1,
            payload_identifier: String::new(), // Invalid
            payload_uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            content: HashMap::new(),
        });

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("PayloadContent[1]"))
        );
    }

    #[test]
    fn test_validate_multiple_payloads_multiple_errors() {
        let mut profile = create_valid_profile();
        profile.payload_content[0].payload_identifier = String::new();
        profile.payload_content.push(PayloadContent {
            payload_type: "com.apple.vpn.managed".to_string(),
            payload_version: 1,
            payload_identifier: String::new(),
            payload_uuid: "invalid-uuid".to_string(),
            content: HashMap::new(),
        });

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.len() >= 3); // At least 3 errors
    }

    // ========== is_valid_uuid Tests ==========

    #[test]
    fn test_is_valid_uuid_standard() {
        assert!(is_valid_uuid("12345678-1234-1234-1234-123456789012"));
    }

    #[test]
    fn test_is_valid_uuid_uppercase() {
        assert!(is_valid_uuid("ABCDEF12-3456-7890-ABCD-EF1234567890"));
    }

    #[test]
    fn test_is_valid_uuid_lowercase() {
        assert!(is_valid_uuid("abcdef12-3456-7890-abcd-ef1234567890"));
    }

    #[test]
    fn test_is_valid_uuid_invalid_short() {
        assert!(!is_valid_uuid("12345678-1234-1234-1234"));
    }

    #[test]
    fn test_is_valid_uuid_hyphenless_is_valid() {
        // Hyphenless format is valid per RFC 4122
        assert!(is_valid_uuid("123456781234123412341234567890ab"));
    }

    #[test]
    fn test_is_valid_uuid_invalid_empty() {
        assert!(!is_valid_uuid(""));
    }

    #[test]
    fn test_is_valid_uuid_invalid_text() {
        assert!(!is_valid_uuid("not-a-uuid-at-all"));
    }

    #[test]
    fn test_is_valid_uuid_invalid_wrong_chars() {
        assert!(!is_valid_uuid("GGGGGGGG-1234-1234-1234-123456789012"));
    }

    // ========== ValidationResult Tests ==========

    #[test]
    fn test_validation_result_valid_when_no_errors() {
        let profile = create_valid_profile();
        let result = validate_profile(&profile).unwrap();

        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validation_result_invalid_when_errors() {
        let mut profile = create_valid_profile();
        profile.payload_type = "Invalid".to_string();

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validation_result_valid_with_warnings() {
        let mut profile = create_valid_profile();
        profile.payload_display_name = String::new();

        let result = validate_profile(&profile).unwrap();

        // Warnings don't affect validity
        assert!(result.valid);
        assert!(!result.warnings.is_empty());
    }

    // ========== Edge Cases ==========

    #[test]
    fn test_validate_multiple_errors_accumulate() {
        let mut profile = create_valid_profile();
        profile.payload_type = "Invalid".to_string();
        profile.payload_version = 99;
        profile.payload_identifier = String::new();
        profile.payload_uuid = "bad".to_string();

        let result = validate_profile(&profile).unwrap();

        assert!(!result.valid);
        assert!(result.errors.len() >= 4);
    }

    #[test]
    fn test_validate_content_index_in_error_message() {
        let mut profile = create_valid_profile();
        profile.payload_content.push(PayloadContent {
            payload_type: "com.apple.test".to_string(),
            payload_version: 1,
            payload_identifier: String::new(),
            payload_uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            content: HashMap::new(),
        });

        let result = validate_profile(&profile).unwrap();

        // Error message should reference PayloadContent[1]
        assert!(result.errors.iter().any(|e| e.contains("[1]")));
    }

    // ========== Identifier Format Tests ==========

    #[test]
    fn test_validate_identifier_format_valid() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_identifier_format("com.example.profile", "test", &mut errors, &mut warnings);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_identifier_format_single_segment_warning() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_identifier_format("profile", "test", &mut errors, &mut warnings);
        assert!(warnings.iter().any(|w| w.contains("reverse-DNS format")));
    }

    #[test]
    fn test_validate_identifier_format_empty_segment_error() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_identifier_format("com..profile", "test", &mut errors, &mut warnings);
        assert!(errors.iter().any(|e| e.contains("empty segments")));
    }

    #[test]
    fn test_validate_identifier_format_invalid_chars_error() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_identifier_format("com.example.profile!", "test", &mut errors, &mut warnings);
        assert!(errors.iter().any(|e| e.contains("invalid characters")));
    }

    #[test]
    fn test_validate_identifier_format_spaces_error() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_identifier_format("com.example.my profile", "test", &mut errors, &mut warnings);
        assert!(errors.iter().any(|e| e.contains("spaces")));
    }

    #[test]
    fn test_validate_identifier_format_unusual_tld_warning() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_identifier_format(
            "unusual.example.profile",
            "test",
            &mut errors,
            &mut warnings,
        );
        assert!(warnings.iter().any(|w| w.contains("TLD")));
    }

    #[test]
    fn test_validate_identifier_format_hyphen_underscore_ok() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_identifier_format(
            "com.example.my-profile_v1",
            "test",
            &mut errors,
            &mut warnings,
        );
        assert!(errors.is_empty());
    }

    // ========== PayloadScope Tests ==========

    #[test]
    fn test_validate_payload_scope_user() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_payload_scope("User", "test", &mut errors, &mut warnings);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_payload_scope_system() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_payload_scope("System", "test", &mut errors, &mut warnings);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_payload_scope_invalid() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_payload_scope("Invalid", "test", &mut errors, &mut warnings);
        assert!(errors.iter().any(|e| e.contains("Invalid PayloadScope")));
    }

    #[test]
    fn test_validate_payload_scope_lowercase_invalid() {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_payload_scope("user", "test", &mut errors, &mut warnings);
        assert!(errors.iter().any(|e| e.contains("Invalid PayloadScope")));
    }

    #[test]
    fn test_validate_profile_with_invalid_scope() {
        let mut profile = create_valid_profile();
        profile.additional_fields.insert(
            "PayloadScope".to_string(),
            plist::Value::String("Invalid".to_string()),
        );

        let result = validate_profile(&profile).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("PayloadScope")));
    }

    #[test]
    fn test_validate_profile_with_valid_scope() {
        let mut profile = create_valid_profile();
        profile.additional_fields.insert(
            "PayloadScope".to_string(),
            plist::Value::String("System".to_string()),
        );

        let result = validate_profile(&profile).unwrap();
        assert!(result.valid);
    }

    // ========== Nested Payload Version Tests ==========

    #[test]
    fn test_validate_nested_payload_version_warning() {
        let mut profile = create_valid_profile();
        profile.payload_content[0].payload_version = 2;

        let result = validate_profile(&profile).unwrap();
        // Should be valid but with warning
        assert!(result.valid);
        assert!(result.warnings.iter().any(|w| w.contains("PayloadVersion")));
    }
}
