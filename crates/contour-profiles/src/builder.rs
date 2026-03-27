use anyhow::{Context, Result};
use plist::{Dictionary, Value};

use crate::uuid::deterministic_uuid;

/// Builder for Apple mobileconfig profiles.
///
/// Wraps payload dictionaries into the standard Apple Configuration Profile
/// XML plist format, including all required metadata fields.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileBuilder {
    org: String,
    identifier: String,
    display_name: String,
    description: String,
    removal_disallowed: bool,
}

impl ProfileBuilder {
    /// Create a new profile builder with the given organization and identifier.
    ///
    /// The identifier should be a reverse-domain string (e.g., `com.example.pppc`).
    pub fn new(org: &str, identifier: &str) -> Self {
        Self {
            org: org.to_string(),
            identifier: identifier.to_string(),
            display_name: String::new(),
            description: String::new(),
            removal_disallowed: false,
        }
    }

    /// Set the profile display name.
    #[must_use]
    pub fn display_name(mut self, name: &str) -> Self {
        self.display_name = name.to_string();
        self
    }

    /// Set the profile description.
    #[must_use]
    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Set whether the profile can be removed by the user.
    #[must_use]
    pub fn removal_disallowed(mut self, val: bool) -> Self {
        self.removal_disallowed = val;
        self
    }

    /// Build the profile, wrapping the given payload content dictionary
    /// into a complete mobileconfig XML plist.
    ///
    /// `payload_type` is the Apple payload type string
    /// (e.g., `com.apple.TCC.configuration-profile-policy`).
    ///
    /// `payload_content` is the inner payload dictionary containing the
    /// type-specific configuration keys.
    pub fn build(self, payload_type: &str, payload_content: Dictionary) -> Result<Vec<u8>> {
        let payload_id = format!("{}.payload", self.identifier);

        let profile_uuid = deterministic_uuid(&self.identifier);
        let payload_uuid = deterministic_uuid(&payload_id);

        // Build inner payload: specific content first, then metadata
        let mut payload = Dictionary::new();

        for (k, v) in payload_content {
            payload.insert(k, v);
        }

        payload.insert(
            "PayloadType".to_string(),
            Value::String(payload_type.to_string()),
        );
        payload.insert("PayloadEnabled".to_string(), Value::Boolean(true));
        payload.insert("PayloadVersion".to_string(), Value::Integer(1.into()));
        payload.insert("PayloadIdentifier".to_string(), Value::String(payload_id));
        payload.insert("PayloadUUID".to_string(), Value::String(payload_uuid));
        payload.insert(
            "PayloadDisplayName".to_string(),
            Value::String(self.display_name.clone()),
        );
        payload.insert(
            "PayloadOrganization".to_string(),
            Value::String(self.org.clone()),
        );

        // Build profile wrapper
        let mut profile = Dictionary::new();
        profile.insert("PayloadVersion".to_string(), Value::Integer(1.into()));
        profile.insert(
            "PayloadDescription".to_string(),
            Value::String(self.description),
        );
        profile.insert(
            "PayloadScope".to_string(),
            Value::String("System".to_string()),
        );
        profile.insert(
            "PayloadType".to_string(),
            Value::String("Configuration".to_string()),
        );
        profile.insert(
            "PayloadContent".to_string(),
            Value::Array(vec![Value::Dictionary(payload)]),
        );
        profile.insert("PayloadOrganization".to_string(), Value::String(self.org));
        profile.insert("PayloadUUID".to_string(), Value::String(profile_uuid));
        profile.insert(
            "PayloadDisplayName".to_string(),
            Value::String(self.display_name),
        );
        profile.insert(
            "PayloadIdentifier".to_string(),
            Value::String(self.identifier),
        );
        profile.insert(
            "PayloadRemovalDisallowed".to_string(),
            Value::Boolean(self.removal_disallowed),
        );
        profile.insert("PayloadEnabled".to_string(), Value::Boolean(true));

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &Value::Dictionary(profile))
            .context("Failed to serialize profile")?;

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_builder_basic() {
        let mut content = Dictionary::new();
        content.insert(
            "TestKey".to_string(),
            Value::String("TestValue".to_string()),
        );

        let result = ProfileBuilder::new("com.example", "com.example.test")
            .display_name("Test Profile")
            .description("A test profile")
            .removal_disallowed(true)
            .build("com.example.payload", content);

        assert!(result.is_ok());

        let xml = String::from_utf8(result.unwrap()).unwrap();
        assert!(xml.contains("Configuration"));
        assert!(xml.contains("com.example.test"));
        assert!(xml.contains("Test Profile"));
        assert!(xml.contains("A test profile"));
        assert!(xml.contains("TestKey"));
        assert!(xml.contains("TestValue"));
        assert!(xml.contains("com.example.payload"));
    }

    #[test]
    fn test_profile_builder_deterministic() {
        let mut content = Dictionary::new();
        content.insert("Key".to_string(), Value::Boolean(true));

        let result1 = ProfileBuilder::new("com.example", "com.example.det")
            .display_name("Det")
            .build("com.example.type", content.clone())
            .unwrap();

        let result2 = ProfileBuilder::new("com.example", "com.example.det")
            .display_name("Det")
            .build("com.example.type", content)
            .unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_profile_key_ordering() {
        let content = Dictionary::new();

        let result = ProfileBuilder::new("com.example", "com.example.order")
            .display_name("Order Test")
            .description("Test ordering")
            .build("com.example.type", content)
            .unwrap();

        let xml = String::from_utf8(result).unwrap();

        let payload_content_pos = xml.find("<key>PayloadContent</key>").unwrap();
        let payload_uuid_pos = xml.find("<key>PayloadUUID</key>").unwrap();
        let payload_id_pos = xml.find("<key>PayloadIdentifier</key>").unwrap();

        // PayloadContent should appear before outer PayloadUUID and PayloadIdentifier
        assert!(payload_content_pos < payload_uuid_pos);
        assert!(payload_content_pos < payload_id_pos);
    }
}
