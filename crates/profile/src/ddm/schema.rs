//! DDM schema definitions
//!
//! Loads and manages DDM declaration schemas from Apple's device-management repository.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// DDM schema registry
#[derive(Debug, Default)]
pub struct DdmSchemaRegistry {
    schemas: HashMap<String, DdmDeclarationSchema>,
}

/// Schema for a DDM declaration type
#[derive(Debug, Clone)]
pub struct DdmDeclarationSchema {
    /// Declaration type (e.g., com.apple.configuration.passcode.settings)
    pub declaration_type: String,
    /// Human-readable title
    pub title: String,
    /// Description
    pub description: String,
    /// Category (configuration, activation, asset, management)
    pub category: String,
    /// Supported platforms
    pub platforms: Vec<DdmPlatformSupport>,
    /// Payload keys/fields
    pub payload_keys: Vec<DdmPayloadKey>,
    /// Whether multiple instances can apply
    pub apply: String,
}

/// Platform support information
#[derive(Debug, Clone)]
pub struct DdmPlatformSupport {
    pub platform: String,
    pub introduced: String,
    pub allowed_enrollments: Vec<String>,
    pub allowed_scopes: Vec<String>,
}

/// A payload key/field in a DDM declaration
#[derive(Debug, Clone)]
pub struct DdmPayloadKey {
    pub key: String,
    pub title: String,
    pub field_type: String,
    pub presence: String,
    pub description: String,
    pub default: Option<String>,
    pub allowed_values: Vec<String>,
    pub subkeys: Vec<DdmPayloadKey>,
}

// Serde structures for parsing Apple's YAML format
#[derive(Debug, Deserialize)]
struct AppleDdmYaml {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    payload: AppleDdmPayload,
    #[serde(default)]
    payloadkeys: Vec<AppleDdmPayloadKey>,
}

#[derive(Debug, Deserialize, Default)]
struct AppleDdmPayload {
    #[serde(default)]
    declarationtype: String,
    #[serde(default)]
    apply: String,
    #[serde(rename = "supportedOS", default)]
    supported_os: HashMap<String, AppleDdmPlatform>,
}

#[derive(Debug, Deserialize, Default)]
struct AppleDdmPlatform {
    #[serde(default)]
    introduced: String,
    #[serde(rename = "allowed-enrollments", default)]
    allowed_enrollments: Vec<String>,
    #[serde(rename = "allowed-scopes", default)]
    allowed_scopes: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AppleDdmPayloadKey {
    #[serde(default)]
    key: String,
    #[serde(default)]
    title: String,
    #[serde(rename = "type", default)]
    field_type: String,
    #[serde(default)]
    presence: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    default: Option<yaml_serde::Value>,
    #[serde(rename = "rangelist", default)]
    range_list: Vec<yaml_serde::Value>,
    #[serde(default)]
    subkeys: Vec<AppleDdmPayloadKey>,
}

impl DdmSchemaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load DDM schemas from Apple's device-management repository
    pub fn from_directory(path: &Path) -> Result<Self> {
        let mut registry = Self::new();

        // Check for declarative/declarations directory structure
        let declarations_dir = path.join("declarative").join("declarations");
        if declarations_dir.exists() {
            registry.load_declarations_dir(&declarations_dir)?;
        } else if path.join("configurations").exists() {
            // Already in declarations directory
            registry.load_declarations_dir(path)?;
        } else {
            anyhow::bail!(
                "Not a valid DDM schema directory. Expected 'declarative/declarations' structure."
            );
        }

        Ok(registry)
    }

    /// Load all declaration schemas from the declarations directory
    fn load_declarations_dir(&mut self, path: &Path) -> Result<()> {
        // Load each category
        for category in &["configurations", "activations", "assets", "management"] {
            let category_dir = path.join(category);
            if category_dir.exists() {
                self.load_category_dir(&category_dir, category)?;
            }
        }

        Ok(())
    }

    /// Load schemas from a category directory
    fn load_category_dir(&mut self, path: &Path, category: &str) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();

            if file_path
                .extension()
                .is_some_and(|e| e == "yaml" || e == "yml")
                && let Ok(schema) = self.parse_yaml_schema(&file_path, category)
            {
                self.schemas.insert(schema.declaration_type.clone(), schema);
            }
        }

        Ok(())
    }

    /// Parse a single DDM YAML schema file
    fn parse_yaml_schema(&self, path: &Path, category: &str) -> Result<DdmDeclarationSchema> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read DDM schema: {}", path.display()))?;

        let yaml: AppleDdmYaml = yaml_serde::from_str(&contents)
            .with_context(|| format!("Failed to parse DDM YAML: {}", path.display()))?;

        // Convert to our schema format
        let platforms: Vec<DdmPlatformSupport> = yaml
            .payload
            .supported_os
            .iter()
            .map(|(platform, info)| DdmPlatformSupport {
                platform: platform.clone(),
                introduced: info.introduced.clone(),
                allowed_enrollments: info.allowed_enrollments.clone(),
                allowed_scopes: info.allowed_scopes.clone(),
            })
            .collect();

        let payload_keys: Vec<DdmPayloadKey> = yaml
            .payloadkeys
            .iter()
            .map(|k| Self::convert_payload_key(k))
            .collect();

        Ok(DdmDeclarationSchema {
            declaration_type: yaml.payload.declarationtype,
            title: yaml.title,
            description: yaml.description,
            category: category.to_string(),
            platforms,
            payload_keys,
            apply: yaml.payload.apply,
        })
    }

    /// Convert Apple's payload key format to ours
    fn convert_payload_key(key: &AppleDdmPayloadKey) -> DdmPayloadKey {
        let allowed_values: Vec<String> = key
            .range_list
            .iter()
            .filter_map(|v| match v {
                yaml_serde::Value::String(s) => Some(s.clone()),
                yaml_serde::Value::Number(n) => Some(n.to_string()),
                yaml_serde::Value::Bool(b) => Some(b.to_string()),
                _ => None,
            })
            .collect();

        let default = key.default.as_ref().and_then(|d| match d {
            yaml_serde::Value::String(s) => Some(s.clone()),
            yaml_serde::Value::Number(n) => Some(n.to_string()),
            yaml_serde::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        });

        let subkeys: Vec<DdmPayloadKey> = key
            .subkeys
            .iter()
            .map(|k| Self::convert_payload_key(k))
            .collect();

        DdmPayloadKey {
            key: key.key.clone(),
            title: key.title.clone(),
            field_type: key.field_type.clone(),
            presence: key.presence.clone(),
            description: key.content.clone(),
            default,
            allowed_values,
            subkeys,
        }
    }

    /// Get a schema by declaration type
    pub fn get(&self, declaration_type: &str) -> Option<&DdmDeclarationSchema> {
        self.schemas.get(declaration_type)
    }

    /// Get schema by short name (e.g., "passcode.settings")
    pub fn get_by_name(&self, name: &str) -> Option<&DdmDeclarationSchema> {
        // Try exact match first
        if let Some(schema) = self.schemas.get(name) {
            return Some(schema);
        }

        // Try matching by suffix
        let name_lower = name.to_lowercase();
        self.schemas.values().find(|s| {
            s.declaration_type.to_lowercase().ends_with(&name_lower)
                || s.title.to_lowercase().contains(&name_lower)
        })
    }

    /// List all schemas
    pub fn list(&self) -> Vec<&DdmDeclarationSchema> {
        let mut schemas: Vec<_> = self.schemas.values().collect();
        schemas.sort_by(|a, b| a.declaration_type.cmp(&b.declaration_type));
        schemas
    }

    /// List schemas by category
    pub fn by_category(&self, category: &str) -> Vec<&DdmDeclarationSchema> {
        let mut schemas: Vec<_> = self
            .schemas
            .values()
            .filter(|s| s.category == category)
            .collect();
        schemas.sort_by(|a, b| a.declaration_type.cmp(&b.declaration_type));
        schemas
    }

    /// Search schemas
    pub fn search(&self, query: &str) -> Vec<&DdmDeclarationSchema> {
        let query_lower = query.to_lowercase();
        let mut results: Vec<_> = self
            .schemas
            .values()
            .filter(|s| {
                s.declaration_type.to_lowercase().contains(&query_lower)
                    || s.title.to_lowercase().contains(&query_lower)
                    || s.description.to_lowercase().contains(&query_lower)
            })
            .collect();
        results.sort_by(|a, b| a.declaration_type.cmp(&b.declaration_type));
        results
    }

    /// Get number of schemas
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }
}

impl DdmDeclarationSchema {
    /// Get required fields
    pub fn required_fields(&self) -> Vec<&DdmPayloadKey> {
        self.payload_keys
            .iter()
            .filter(|k| k.presence == "required")
            .collect()
    }

    /// Get all platform names
    pub fn platform_names(&self) -> Vec<&str> {
        self.platforms.iter().map(|p| p.platform.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== DdmSchemaRegistry Basic Tests ==========

    #[test]
    fn test_ddm_schema_registry_new() {
        let registry = DdmSchemaRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_ddm_schema_registry_default() {
        let registry = DdmSchemaRegistry::default();
        assert!(registry.is_empty());
    }

    // ========== Schema Operations Tests ==========

    fn create_test_schema(
        declaration_type: &str,
        title: &str,
        category: &str,
    ) -> DdmDeclarationSchema {
        DdmDeclarationSchema {
            declaration_type: declaration_type.to_string(),
            title: title.to_string(),
            description: format!("Test schema for {}", title),
            category: category.to_string(),
            platforms: vec![DdmPlatformSupport {
                platform: "macOS".to_string(),
                introduced: "14.0".to_string(),
                allowed_enrollments: vec!["supervised".to_string()],
                allowed_scopes: vec!["system".to_string()],
            }],
            payload_keys: vec![],
            apply: "once".to_string(),
        }
    }

    #[test]
    fn test_ddm_schema_registry_get() {
        let mut registry = DdmSchemaRegistry::new();
        let schema = create_test_schema("com.apple.configuration.test", "Test", "configurations");
        registry
            .schemas
            .insert(schema.declaration_type.clone(), schema);

        let result = registry.get("com.apple.configuration.test");
        assert!(result.is_some());
        assert_eq!(result.unwrap().title, "Test");
    }

    #[test]
    fn test_ddm_schema_registry_get_not_found() {
        let registry = DdmSchemaRegistry::new();
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_ddm_schema_registry_get_by_name_exact() {
        let mut registry = DdmSchemaRegistry::new();
        let schema = create_test_schema(
            "com.apple.configuration.passcode.settings",
            "Passcode Settings",
            "configurations",
        );
        registry
            .schemas
            .insert(schema.declaration_type.clone(), schema);

        let result = registry.get_by_name("com.apple.configuration.passcode.settings");
        assert!(result.is_some());
    }

    #[test]
    fn test_ddm_schema_registry_get_by_name_suffix() {
        let mut registry = DdmSchemaRegistry::new();
        let schema = create_test_schema(
            "com.apple.configuration.passcode.settings",
            "Passcode Settings",
            "configurations",
        );
        registry
            .schemas
            .insert(schema.declaration_type.clone(), schema);

        let result = registry.get_by_name("passcode.settings");
        assert!(result.is_some());
    }

    #[test]
    fn test_ddm_schema_registry_get_by_name_title() {
        let mut registry = DdmSchemaRegistry::new();
        let schema = create_test_schema(
            "com.apple.configuration.test",
            "Passcode Settings",
            "configurations",
        );
        registry
            .schemas
            .insert(schema.declaration_type.clone(), schema);

        let result = registry.get_by_name("passcode");
        assert!(result.is_some());
    }

    #[test]
    fn test_ddm_schema_registry_list() {
        let mut registry = DdmSchemaRegistry::new();
        registry.schemas.insert(
            "com.apple.b".to_string(),
            create_test_schema("com.apple.b", "B", "configurations"),
        );
        registry.schemas.insert(
            "com.apple.a".to_string(),
            create_test_schema("com.apple.a", "A", "configurations"),
        );

        let list = registry.list();
        assert_eq!(list.len(), 2);
        // Should be sorted
        assert_eq!(list[0].declaration_type, "com.apple.a");
        assert_eq!(list[1].declaration_type, "com.apple.b");
    }

    #[test]
    fn test_ddm_schema_registry_by_category() {
        let mut registry = DdmSchemaRegistry::new();
        registry.schemas.insert(
            "config1".to_string(),
            create_test_schema("config1", "Config 1", "configurations"),
        );
        registry.schemas.insert(
            "asset1".to_string(),
            create_test_schema("asset1", "Asset 1", "assets"),
        );
        registry.schemas.insert(
            "config2".to_string(),
            create_test_schema("config2", "Config 2", "configurations"),
        );

        let configs = registry.by_category("configurations");
        assert_eq!(configs.len(), 2);

        let assets = registry.by_category("assets");
        assert_eq!(assets.len(), 1);

        let empty = registry.by_category("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_ddm_schema_registry_search() {
        let mut registry = DdmSchemaRegistry::new();
        registry.schemas.insert(
            "com.apple.configuration.wifi".to_string(),
            create_test_schema(
                "com.apple.configuration.wifi",
                "WiFi Configuration",
                "configurations",
            ),
        );
        registry.schemas.insert(
            "com.apple.configuration.passcode".to_string(),
            create_test_schema(
                "com.apple.configuration.passcode",
                "Passcode",
                "configurations",
            ),
        );

        let results = registry.search("wifi");
        assert_eq!(results.len(), 1);
        assert!(results[0].title.contains("WiFi"));

        let results = registry.search("configuration");
        assert_eq!(results.len(), 2);

        let results = registry.search("nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn test_ddm_schema_registry_search_case_insensitive() {
        let mut registry = DdmSchemaRegistry::new();
        registry.schemas.insert(
            "test".to_string(),
            create_test_schema("test", "WiFi Settings", "configurations"),
        );

        assert!(!registry.search("WIFI").is_empty());
        assert!(!registry.search("wifi").is_empty());
        assert!(!registry.search("WiFi").is_empty());
    }

    #[test]
    fn test_ddm_schema_registry_len_and_is_empty() {
        let mut registry = DdmSchemaRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.schemas.insert(
            "test".to_string(),
            create_test_schema("test", "Test", "configurations"),
        );
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    // ========== DdmDeclarationSchema Tests ==========

    #[test]
    fn test_ddm_declaration_schema_required_fields() {
        let schema = DdmDeclarationSchema {
            declaration_type: "test".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            category: "configurations".to_string(),
            platforms: vec![],
            payload_keys: vec![
                DdmPayloadKey {
                    key: "Required1".to_string(),
                    title: "Required Field 1".to_string(),
                    field_type: "string".to_string(),
                    presence: "required".to_string(),
                    description: "A required field".to_string(),
                    default: None,
                    allowed_values: vec![],
                    subkeys: vec![],
                },
                DdmPayloadKey {
                    key: "Optional1".to_string(),
                    title: "Optional Field 1".to_string(),
                    field_type: "boolean".to_string(),
                    presence: "optional".to_string(),
                    description: "An optional field".to_string(),
                    default: Some("true".to_string()),
                    allowed_values: vec![],
                    subkeys: vec![],
                },
                DdmPayloadKey {
                    key: "Required2".to_string(),
                    title: "Required Field 2".to_string(),
                    field_type: "integer".to_string(),
                    presence: "required".to_string(),
                    description: "Another required field".to_string(),
                    default: None,
                    allowed_values: vec![],
                    subkeys: vec![],
                },
            ],
            apply: "once".to_string(),
        };

        let required = schema.required_fields();
        assert_eq!(required.len(), 2);
        assert!(required.iter().any(|k| k.key == "Required1"));
        assert!(required.iter().any(|k| k.key == "Required2"));
    }

    #[test]
    fn test_ddm_declaration_schema_platform_names() {
        let schema = DdmDeclarationSchema {
            declaration_type: "test".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            category: "configurations".to_string(),
            platforms: vec![
                DdmPlatformSupport {
                    platform: "macOS".to_string(),
                    introduced: "14.0".to_string(),
                    allowed_enrollments: vec![],
                    allowed_scopes: vec![],
                },
                DdmPlatformSupport {
                    platform: "iOS".to_string(),
                    introduced: "17.0".to_string(),
                    allowed_enrollments: vec![],
                    allowed_scopes: vec![],
                },
            ],
            payload_keys: vec![],
            apply: "once".to_string(),
        };

        let platforms = schema.platform_names();
        assert_eq!(platforms.len(), 2);
        assert!(platforms.contains(&"macOS"));
        assert!(platforms.contains(&"iOS"));
    }

    #[test]
    fn test_ddm_declaration_schema_no_platforms() {
        let schema = DdmDeclarationSchema {
            declaration_type: "test".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            category: "configurations".to_string(),
            platforms: vec![],
            payload_keys: vec![],
            apply: "once".to_string(),
        };

        assert!(schema.platform_names().is_empty());
    }

    // ========== DdmPayloadKey Tests ==========

    #[test]
    fn test_ddm_payload_key_with_subkeys() {
        let key = DdmPayloadKey {
            key: "ParentKey".to_string(),
            title: "Parent".to_string(),
            field_type: "dictionary".to_string(),
            presence: "optional".to_string(),
            description: "A dictionary with subkeys".to_string(),
            default: None,
            allowed_values: vec![],
            subkeys: vec![
                DdmPayloadKey {
                    key: "ChildKey1".to_string(),
                    title: "Child 1".to_string(),
                    field_type: "string".to_string(),
                    presence: "required".to_string(),
                    description: "First child".to_string(),
                    default: None,
                    allowed_values: vec![],
                    subkeys: vec![],
                },
                DdmPayloadKey {
                    key: "ChildKey2".to_string(),
                    title: "Child 2".to_string(),
                    field_type: "integer".to_string(),
                    presence: "optional".to_string(),
                    description: "Second child".to_string(),
                    default: Some("0".to_string()),
                    allowed_values: vec![],
                    subkeys: vec![],
                },
            ],
        };

        assert_eq!(key.subkeys.len(), 2);
        assert_eq!(key.subkeys[0].key, "ChildKey1");
        assert_eq!(key.subkeys[1].key, "ChildKey2");
    }

    #[test]
    fn test_ddm_payload_key_with_allowed_values() {
        let key = DdmPayloadKey {
            key: "EnumKey".to_string(),
            title: "Enum".to_string(),
            field_type: "string".to_string(),
            presence: "required".to_string(),
            description: "An enum field".to_string(),
            default: Some("option1".to_string()),
            allowed_values: vec![
                "option1".to_string(),
                "option2".to_string(),
                "option3".to_string(),
            ],
            subkeys: vec![],
        };

        assert_eq!(key.allowed_values.len(), 3);
        assert!(key.allowed_values.contains(&"option1".to_string()));
    }

    // ========== DdmPlatformSupport Tests ==========

    #[test]
    fn test_ddm_platform_support() {
        let platform = DdmPlatformSupport {
            platform: "macOS".to_string(),
            introduced: "14.0".to_string(),
            allowed_enrollments: vec!["device".to_string(), "supervised".to_string()],
            allowed_scopes: vec!["system".to_string(), "user".to_string()],
        };

        assert_eq!(platform.platform, "macOS");
        assert_eq!(platform.introduced, "14.0");
        assert_eq!(platform.allowed_enrollments.len(), 2);
        assert_eq!(platform.allowed_scopes.len(), 2);
    }
}
