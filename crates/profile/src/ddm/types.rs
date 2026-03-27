//! DDM type definitions
//!
//! Defines the structure of DDM declarations as used in Apple's
//! declarative device management protocol.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A DDM declaration
///
/// DDM declarations are JSON objects with three required fields:
/// - Type: The declaration type (e.g., com.apple.configuration.passcode.settings)
/// - Identifier: Unique identifier for this declaration
/// - Payload: The actual configuration data
///
/// Optional fields:
/// - ServerToken: Server-provided token for change tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Declaration {
    /// The declaration type (e.g., com.apple.configuration.passcode.settings)
    #[serde(rename = "Type")]
    pub declaration_type: String,

    /// Unique identifier for this declaration
    pub identifier: String,

    /// Server token for change tracking (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_token: Option<String>,

    /// The payload containing the actual configuration
    pub payload: DeclarationPayload,
}

/// The payload of a DDM declaration
///
/// Contains the actual configuration values as key-value pairs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeclarationPayload(pub HashMap<String, serde_json::Value>);

impl DeclarationPayload {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }

    pub fn insert(&mut self, key: String, value: serde_json::Value) {
        self.0.insert(key, value);
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &serde_json::Value)> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Categories of DDM declarations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeclarationType {
    /// Configuration declarations define device settings
    Configuration,
    /// Activation declarations enable features based on conditions
    Activation,
    /// Asset declarations manage credentials and resources
    Asset,
    /// Management declarations control enrollment and administration
    Management,
}

impl DeclarationType {
    /// Parse from declaration type string (e.g., "com.apple.configuration.passcode.settings")
    pub fn from_type_string(type_str: &str) -> Option<Self> {
        if type_str.contains(".configuration.") {
            Some(Self::Configuration)
        } else if type_str.contains(".activation.") {
            Some(Self::Activation)
        } else if type_str.contains(".asset.") {
            Some(Self::Asset)
        } else if type_str.contains(".management.") {
            Some(Self::Management)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Activation => "activation",
            Self::Asset => "asset",
            Self::Management => "management",
        }
    }
}

impl std::fmt::Display for DeclarationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Declaration {
    /// Create a new declaration
    pub fn new(declaration_type: &str, identifier: &str) -> Self {
        Self {
            declaration_type: declaration_type.to_string(),
            identifier: identifier.to_string(),
            server_token: None,
            payload: DeclarationPayload::new(),
        }
    }

    /// Get the declaration category
    pub fn category(&self) -> Option<DeclarationType> {
        DeclarationType::from_type_string(&self.declaration_type)
    }

    /// Get a short name for the declaration type
    /// e.g., "passcode.settings" from "com.apple.configuration.passcode.settings"
    pub fn short_name(&self) -> &str {
        self.declaration_type
            .strip_prefix("com.apple.")
            .map_or(&self.declaration_type, |s| {
                // Skip the category part (configuration, activation, asset, management)
                if let Some(idx) = s.find('.') {
                    &s[idx + 1..]
                } else {
                    s
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Declaration Tests ==========

    #[test]
    fn test_declaration_new() {
        let decl = Declaration::new("com.apple.configuration.test", "test.identifier");
        assert_eq!(decl.declaration_type, "com.apple.configuration.test");
        assert_eq!(decl.identifier, "test.identifier");
        assert!(decl.server_token.is_none());
        assert!(decl.payload.is_empty());
    }

    #[test]
    fn test_declaration_category() {
        let decl = Declaration::new("com.apple.configuration.passcode.settings", "test.id");
        assert_eq!(decl.category(), Some(DeclarationType::Configuration));

        let decl = Declaration::new("com.apple.activation.simple", "test.id");
        assert_eq!(decl.category(), Some(DeclarationType::Activation));

        let decl = Declaration::new("com.apple.asset.credential.certificate", "test.id");
        assert_eq!(decl.category(), Some(DeclarationType::Asset));

        let decl = Declaration::new("com.apple.management.status-subscriptions", "test.id");
        assert_eq!(decl.category(), Some(DeclarationType::Management));
    }

    #[test]
    fn test_declaration_category_none() {
        let decl = Declaration::new("com.example.custom.type", "test.id");
        assert_eq!(decl.category(), None);
    }

    #[test]
    fn test_short_name() {
        // short_name extracts everything after the category
        let decl = Declaration::new("com.apple.configuration.passcode.settings", "test.id");
        assert_eq!(decl.short_name(), "passcode.settings");

        let decl = Declaration::new("com.apple.asset.credential.certificate", "test.id");
        assert_eq!(decl.short_name(), "credential.certificate");

        let decl = Declaration::new("com.apple.activation.simple", "test.id");
        assert_eq!(decl.short_name(), "simple");
    }

    #[test]
    fn test_short_name_non_apple() {
        let decl = Declaration::new("org.example.custom", "test.id");
        assert_eq!(decl.short_name(), "org.example.custom");
    }

    // ========== DeclarationType Tests ==========

    #[test]
    fn test_declaration_type_from_type_string() {
        assert_eq!(
            DeclarationType::from_type_string("com.apple.configuration.passcode"),
            Some(DeclarationType::Configuration)
        );
        assert_eq!(
            DeclarationType::from_type_string("com.apple.activation.simple"),
            Some(DeclarationType::Activation)
        );
        assert_eq!(
            DeclarationType::from_type_string("com.apple.asset.credential"),
            Some(DeclarationType::Asset)
        );
        assert_eq!(
            DeclarationType::from_type_string("com.apple.management.status"),
            Some(DeclarationType::Management)
        );
    }

    #[test]
    fn test_declaration_type_from_type_string_none() {
        assert_eq!(DeclarationType::from_type_string("com.apple.other"), None);
        assert_eq!(DeclarationType::from_type_string(""), None);
        assert_eq!(DeclarationType::from_type_string("configuration"), None);
    }

    #[test]
    fn test_declaration_type_as_str() {
        assert_eq!(DeclarationType::Configuration.as_str(), "configuration");
        assert_eq!(DeclarationType::Activation.as_str(), "activation");
        assert_eq!(DeclarationType::Asset.as_str(), "asset");
        assert_eq!(DeclarationType::Management.as_str(), "management");
    }

    #[test]
    fn test_declaration_type_display() {
        assert_eq!(
            format!("{}", DeclarationType::Configuration),
            "configuration"
        );
        assert_eq!(format!("{}", DeclarationType::Activation), "activation");
        assert_eq!(format!("{}", DeclarationType::Asset), "asset");
        assert_eq!(format!("{}", DeclarationType::Management), "management");
    }

    // ========== DeclarationPayload Tests ==========

    #[test]
    fn test_declaration_payload_new() {
        let payload = DeclarationPayload::new();
        assert!(payload.is_empty());
        assert_eq!(payload.len(), 0);
    }

    #[test]
    fn test_declaration_payload_default() {
        let payload = DeclarationPayload::default();
        assert!(payload.is_empty());
    }

    #[test]
    fn test_declaration_payload_insert_and_get() {
        let mut payload = DeclarationPayload::new();
        payload.insert("key1".to_string(), serde_json::json!("value1"));
        payload.insert("key2".to_string(), serde_json::json!(42));

        assert_eq!(payload.len(), 2);
        assert!(!payload.is_empty());

        assert_eq!(payload.get("key1"), Some(&serde_json::json!("value1")));
        assert_eq!(payload.get("key2"), Some(&serde_json::json!(42)));
        assert_eq!(payload.get("nonexistent"), None);
    }

    #[test]
    fn test_declaration_payload_keys() {
        let mut payload = DeclarationPayload::new();
        payload.insert("alpha".to_string(), serde_json::json!(1));
        payload.insert("beta".to_string(), serde_json::json!(2));

        let keys: Vec<_> = payload.keys().collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&&"alpha".to_string()));
        assert!(keys.contains(&&"beta".to_string()));
    }

    #[test]
    fn test_declaration_payload_iter() {
        let mut payload = DeclarationPayload::new();
        payload.insert("key".to_string(), serde_json::json!("value"));

        let items: Vec<_> = payload.iter().collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, "key");
        assert_eq!(items[0].1, &serde_json::json!("value"));
    }

    #[test]
    fn test_declaration_payload_various_types() {
        let mut payload = DeclarationPayload::new();
        payload.insert("string".to_string(), serde_json::json!("text"));
        payload.insert("number".to_string(), serde_json::json!(123));
        payload.insert("boolean".to_string(), serde_json::json!(true));
        payload.insert("array".to_string(), serde_json::json!([1, 2, 3]));
        payload.insert("object".to_string(), serde_json::json!({"nested": "value"}));

        assert_eq!(payload.len(), 5);
        assert_eq!(payload.get("string"), Some(&serde_json::json!("text")));
        assert_eq!(payload.get("boolean"), Some(&serde_json::json!(true)));
    }

    // ========== Serialization Tests ==========

    #[test]
    fn test_declaration_serialize() {
        let mut decl = Declaration::new("com.apple.configuration.test", "test.id");
        decl.server_token = Some("token123".to_string());
        decl.payload
            .insert("Key".to_string(), serde_json::json!("value"));

        let json = serde_json::to_string(&decl).unwrap();
        assert!(json.contains("com.apple.configuration.test"));
        assert!(json.contains("test.id"));
        assert!(json.contains("token123"));
        assert!(json.contains("Key"));
    }

    #[test]
    fn test_declaration_deserialize() {
        let json = r#"{
            "Type": "com.apple.configuration.test",
            "Identifier": "my.identifier",
            "ServerToken": "abc",
            "Payload": {"Setting": true}
        }"#;

        let decl: Declaration = serde_json::from_str(json).unwrap();
        assert_eq!(decl.declaration_type, "com.apple.configuration.test");
        assert_eq!(decl.identifier, "my.identifier");
        assert_eq!(decl.server_token, Some("abc".to_string()));
        assert!(decl.payload.get("Setting").is_some());
    }

    #[test]
    fn test_declaration_deserialize_without_server_token() {
        let json = r#"{
            "Type": "com.apple.configuration.test",
            "Identifier": "my.identifier",
            "Payload": {}
        }"#;

        let decl: Declaration = serde_json::from_str(json).unwrap();
        assert!(decl.server_token.is_none());
    }

    #[test]
    fn test_declaration_serialize_omits_none_server_token() {
        let decl = Declaration::new("com.apple.configuration.test", "test.id");
        let json = serde_json::to_string(&decl).unwrap();
        assert!(!json.contains("ServerToken"));
    }
}
