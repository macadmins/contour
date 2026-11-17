//! Curated patterns for well-known sensitive field names.
//!
//! The embedded Apple schema marks no fields `sensitive`, so this table is the
//! fallback that flags obvious credential keys (`Password`, `SharedSecret`, …)
//! by name. Kept as a small constant list so it is easy to audit and extend.

/// Case-insensitive substrings that mark a field name as a likely credential.
///
/// Matched as substrings so `AuthPassword`, `ProxyPassword`, and
/// `IncomingPassword` all hit `password`.
const SENSITIVE_SUBSTRINGS: &[&str] = &[
    "password",
    "passphrase",
    "sharedsecret",
    "privatekey",
    "secret",
    "authtoken",
    "token",
    "credential",
];

/// True when `field_name` looks like a well-known credential key.
pub fn is_known_sensitive_name(field_name: &str) -> bool {
    let lower = field_name.to_ascii_lowercase();
    SENSITIVE_SUBSTRINGS.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_common_password_keys() {
        assert!(is_known_sensitive_name("Password"));
        assert!(is_known_sensitive_name("AuthPassword"));
        assert!(is_known_sensitive_name("ProxyPassword"));
        assert!(is_known_sensitive_name("SharedSecret"));
        assert!(is_known_sensitive_name("ClientSecret"));
        assert!(is_known_sensitive_name("provisioningToken"));
    }

    #[test]
    fn ignores_non_credential_keys() {
        assert!(!is_known_sensitive_name("PayloadType"));
        assert!(!is_known_sensitive_name("SSID_STR"));
        assert!(!is_known_sensitive_name("EncryptionType"));
        assert!(!is_known_sensitive_name("DisplayName"));
    }
}
