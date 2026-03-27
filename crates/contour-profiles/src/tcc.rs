use plist::{Dictionary, Value};

/// Identifier type for TCC entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierType {
    /// Application identified by bundle ID (e.g., "com.example.app")
    BundleID,
    /// Binary identified by file path (e.g., "/usr/local/bin/tool")
    Path,
}

impl IdentifierType {
    fn as_str(self) -> &'static str {
        match self {
            Self::BundleID => "bundleID",
            Self::Path => "path",
        }
    }
}

/// TCC Authorization value for macOS 11+.
///
/// Replaces the legacy `Allowed` boolean key with the `Authorization` string key
/// per the `com.apple.TCC.configuration-profile-policy` spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TccAuthorization {
    /// Grant access to the service.
    Allow,
    /// Deny access to the service.
    Deny,
    /// Allow standard (non-admin) users to toggle the permission.
    /// Only valid for ScreenCapture and ListenEvent.
    AllowStandardUserToSetSystemService,
}

impl TccAuthorization {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::Deny => "Deny",
            Self::AllowStandardUserToSetSystemService => "AllowStandardUserToSetSystemService",
        }
    }
}

/// Build a TCC entry using the modern `Authorization` string key (macOS 11+).
///
/// This creates the dictionary structure expected inside the Services dictionary
/// of a `com.apple.TCC.configuration-profile-policy` payload, using the
/// `Authorization` key instead of the legacy `Allowed` boolean.
pub fn build_tcc_entry_with_authorization(
    identifier: &str,
    code_requirement: &str,
    authorization: TccAuthorization,
    identifier_type: IdentifierType,
) -> Value {
    let mut entry = Dictionary::new();
    entry.insert(
        "Identifier".to_string(),
        Value::String(identifier.to_string()),
    );
    entry.insert(
        "IdentifierType".to_string(),
        Value::String(identifier_type.as_str().to_string()),
    );
    entry.insert(
        "CodeRequirement".to_string(),
        Value::String(code_requirement.to_string()),
    );
    entry.insert("StaticCode".to_string(), Value::Boolean(false));
    entry.insert(
        "Authorization".to_string(),
        Value::String(authorization.as_str().to_string()),
    );
    Value::Dictionary(entry)
}

/// Build a TCC entry dictionary for a single app/service combination.
///
/// This creates the dictionary structure expected inside the Services dictionary
/// of a `com.apple.TCC.configuration-profile-policy` payload.
///
/// Uses `IdentifierType: bundleID` — for path-based binaries, use
/// `build_tcc_entry_with_type`.
///
/// This is a convenience wrapper around `build_tcc_entry_with_authorization`.
pub fn build_tcc_entry(bundle_id: &str, code_requirement: &str, allowed: bool) -> Value {
    build_tcc_entry_with_type(
        bundle_id,
        code_requirement,
        allowed,
        IdentifierType::BundleID,
    )
}

/// Build a TCC entry with an explicit identifier type.
///
/// Use `IdentifierType::Path` for non-bundled binaries (e.g., `/usr/local/munki/managedsoftwareupdate`).
/// Use `IdentifierType::BundleID` for app bundles.
///
/// This is a convenience wrapper around `build_tcc_entry_with_authorization`.
pub fn build_tcc_entry_with_type(
    identifier: &str,
    code_requirement: &str,
    allowed: bool,
    identifier_type: IdentifierType,
) -> Value {
    let auth = if allowed {
        TccAuthorization::Allow
    } else {
        TccAuthorization::Deny
    };
    build_tcc_entry_with_authorization(identifier, code_requirement, auth, identifier_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tcc_entry_with_authorization_allow() {
        let entry = build_tcc_entry_with_authorization(
            "com.example.app",
            "identifier \"com.example.app\"",
            TccAuthorization::Allow,
            IdentifierType::BundleID,
        );
        if let Value::Dictionary(dict) = entry {
            assert_eq!(
                dict.get("Identifier").unwrap().as_string().unwrap(),
                "com.example.app"
            );
            assert_eq!(
                dict.get("IdentifierType").unwrap().as_string().unwrap(),
                "bundleID"
            );
            assert_eq!(
                dict.get("Authorization").unwrap().as_string().unwrap(),
                "Allow"
            );
            assert!(!dict.get("StaticCode").unwrap().as_boolean().unwrap());
            assert!(
                dict.get("Allowed").is_none(),
                "Should not have legacy Allowed key"
            );
        } else {
            panic!("Expected Dictionary");
        }
    }

    #[test]
    fn test_build_tcc_entry_with_authorization_deny() {
        let entry = build_tcc_entry_with_authorization(
            "com.example.app",
            "req",
            TccAuthorization::Deny,
            IdentifierType::BundleID,
        );
        if let Value::Dictionary(dict) = entry {
            assert_eq!(
                dict.get("Authorization").unwrap().as_string().unwrap(),
                "Deny"
            );
        } else {
            panic!("Expected Dictionary");
        }
    }

    #[test]
    fn test_build_tcc_entry_with_authorization_standard_user() {
        let entry = build_tcc_entry_with_authorization(
            "com.example.app",
            "req",
            TccAuthorization::AllowStandardUserToSetSystemService,
            IdentifierType::BundleID,
        );
        if let Value::Dictionary(dict) = entry {
            assert_eq!(
                dict.get("Authorization").unwrap().as_string().unwrap(),
                "AllowStandardUserToSetSystemService"
            );
        } else {
            panic!("Expected Dictionary");
        }
    }

    #[test]
    fn test_legacy_wrapper_uses_authorization_key() {
        // Legacy wrappers should now produce Authorization key, not Allowed
        let entry = build_tcc_entry("com.example.app", "identifier \"com.example.app\"", true);
        if let Value::Dictionary(dict) = entry {
            assert_eq!(
                dict.get("Authorization").unwrap().as_string().unwrap(),
                "Allow"
            );
            assert!(
                dict.get("Allowed").is_none(),
                "Legacy wrapper should use Authorization, not Allowed"
            );
        } else {
            panic!("Expected Dictionary");
        }
    }

    #[test]
    fn test_legacy_wrapper_denied() {
        let entry = build_tcc_entry("com.example.app", "req", false);
        if let Value::Dictionary(dict) = entry {
            assert_eq!(
                dict.get("Authorization").unwrap().as_string().unwrap(),
                "Deny"
            );
        } else {
            panic!("Expected Dictionary");
        }
    }

    #[test]
    fn test_build_tcc_entry_path_type() {
        let entry = build_tcc_entry_with_type(
            "/usr/local/munki/managedsoftwareupdate",
            "identifier managedsoftwareupdate and anchor apple generic",
            true,
            IdentifierType::Path,
        );
        if let Value::Dictionary(dict) = entry {
            assert_eq!(
                dict.get("Identifier").unwrap().as_string().unwrap(),
                "/usr/local/munki/managedsoftwareupdate"
            );
            assert_eq!(
                dict.get("IdentifierType").unwrap().as_string().unwrap(),
                "path"
            );
            assert_eq!(
                dict.get("Authorization").unwrap().as_string().unwrap(),
                "Allow"
            );
        } else {
            panic!("Expected Dictionary");
        }
    }
}
