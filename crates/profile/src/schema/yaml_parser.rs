//! Parser for Apple device-management YAML format
//!
//! Apple provides official payload schemas in YAML format.
//! See: https://github.com/apple/device-management

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use super::types::{FieldDefinition, FieldFlags, FieldType, PayloadManifest, Platform, Platforms};

/// Root structure of Apple's YAML manifest
#[derive(Debug, Deserialize)]
struct AppleManifest {
    title: String,
    #[serde(default)]
    description: Option<String>,
    payload: ApplePayload,
    /// DDM declarations use payloadkeys at root level
    #[serde(default)]
    payloadkeys: Option<Vec<AppleField>>,
    /// Related status items (ignored but allowed)
    #[serde(default, rename = "related-status-items")]
    related_status_items: Option<yaml_serde::Value>,
}

/// Payload section of Apple manifest
#[derive(Debug, Deserialize)]
struct ApplePayload {
    /// MDM profiles use payloadtype
    #[serde(default)]
    payloadtype: Option<String>,
    /// DDM declarations use declarationtype
    #[serde(default)]
    declarationtype: Option<String>,
    #[serde(default, rename = "supportedOS")]
    supported_os: Option<AppleSupportedOS>,
    /// Content: either a string description (DDM) or list of fields (MDM)
    #[serde(default, rename = "content")]
    content: Option<yaml_serde::Value>,
    /// DDM declarations use apply
    #[serde(default)]
    apply: Option<String>,
}

/// Supported OS versions
#[derive(Debug, Deserialize)]
#[expect(non_snake_case, reason = "matches external schema field names")]
struct AppleSupportedOS {
    iOS: Option<AppleOSRequirement>,
    macOS: Option<AppleOSRequirement>,
    tvOS: Option<AppleOSRequirement>,
    watchOS: Option<AppleOSRequirement>,
    visionOS: Option<AppleOSRequirement>,
}

/// OS requirement with minimum version
#[derive(Debug, Deserialize, Default)]
struct AppleOSRequirement {
    #[serde(default)]
    introduced: Option<String>,
    /// Allowed enrollments (DDM)
    #[serde(default, rename = "allowed-enrollments")]
    allowed_enrollments: Option<Vec<String>>,
    /// Allowed scopes (DDM)
    #[serde(default, rename = "allowed-scopes")]
    allowed_scopes: Option<Vec<String>>,
    /// SharediPad config (DDM)
    #[serde(default)]
    sharedipad: Option<yaml_serde::Value>,
    /// Deprecated version
    #[serde(default)]
    deprecated: Option<String>,
    /// Userenrollment (DDM)
    #[serde(default)]
    userenrollment: Option<yaml_serde::Value>,
    /// Supervised (MDM)
    #[serde(default)]
    supervised: Option<bool>,
    /// Requires DEP (MDM)
    #[serde(default, rename = "requires-dep")]
    requires_dep: Option<bool>,
    /// User-approved MDM
    #[serde(default, rename = "userapprovedmdm")]
    user_approved_mdm: Option<bool>,
    /// Allowed payloads (MDM)
    #[serde(default, rename = "allowed-payloads")]
    allowed_payloads: Option<yaml_serde::Value>,
    /// Multiple mode
    #[serde(default)]
    multiple: Option<bool>,
    /// Device channel
    #[serde(default, rename = "devicechannel")]
    device_channel: Option<bool>,
    /// User channel
    #[serde(default, rename = "userchannel")]
    user_channel: Option<bool>,
}

/// Field definition in Apple format
#[derive(Debug, Deserialize, Clone)]
struct AppleField {
    key: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(rename = "type")]
    field_type: String,
    #[serde(default)]
    presence: Option<String>,
    #[serde(default)]
    default: Option<yaml_serde::Value>,
    #[serde(default)]
    rangelist: Option<Vec<yaml_serde::Value>>,
    #[serde(default)]
    supervised: Option<bool>,
    #[serde(default)]
    sensitive: Option<bool>,
    /// DDM uses 'content' for field description
    #[serde(default)]
    content: Option<String>,
    /// Asset types (DDM) - ignored but allowed
    #[serde(default)]
    assettypes: Option<Vec<String>>,
    /// Subkeys for nested fields
    #[serde(default)]
    subkeys: Option<Vec<AppleField>>,
    /// Combine mode (DDM)
    #[serde(default)]
    combine: Option<String>,
    /// Repetition (DDM)
    #[serde(default)]
    repetition: Option<yaml_serde::Value>,
    /// Per-field supportedOS (rare but exists in some DDM)
    #[serde(default, rename = "supportedOS")]
    supported_os: Option<yaml_serde::Value>,
}

/// Parse an Apple device-management YAML file into a PayloadManifest
pub fn parse_yaml_manifest(content: &str) -> Result<PayloadManifest> {
    // Try normal parsing first
    let manifest: AppleManifest = match yaml_serde::from_str(content) {
        Ok(m) => m,
        Err(e) => {
            // If recursion limit exceeded, try simplified parsing (top-level keys only)
            if e.to_string().contains("recursion limit") {
                return parse_yaml_manifest_simplified(content);
            }
            anyhow::bail!("YAML parse error: {e}")
        }
    };

    // Get payload type - DDM uses declarationtype, MDM uses payloadtype
    let payload_type = manifest
        .payload
        .declarationtype
        .clone()
        .or(manifest.payload.payloadtype.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // Parse platforms from supportedOS
    let platforms = parse_supported_os(&manifest.payload.supported_os);

    // Parse min versions
    let min_versions = parse_min_versions(&manifest.payload.supported_os);

    // Categorize - DDM types get ddm-* categories
    let category = if manifest.payload.declarationtype.is_some() {
        categorize_ddm_type(&payload_type)
    } else {
        categorize_payload_type(&payload_type)
    };

    // Parse fields - DDM uses payloadkeys at root, MDM uses content in payload
    // content can be a string (DDM description) or array (MDM fields)
    let content_fields: Option<Vec<AppleField>> = manifest.payload.content.as_ref().and_then(|c| {
        match c {
            yaml_serde::Value::Sequence(_) => yaml_serde::from_value(c.clone()).ok(),
            _ => None, // String or other - not fields
        }
    });
    let fields_source = manifest.payloadkeys.as_ref().or(content_fields.as_ref());
    let (fields, field_order) = parse_content_fields(&fields_source.cloned())?;

    Ok(PayloadManifest {
        payload_type,
        title: manifest.title,
        description: manifest.description.unwrap_or_default(),
        platforms,
        min_versions,
        category,
        fields,
        field_order,
        segments: vec![],
    })
}

/// Simplified YAML manifest for deeply nested files (recursion limit workaround)
#[derive(Debug, Deserialize)]
struct SimplifiedManifest {
    title: String,
    #[serde(default)]
    description: Option<String>,
    payload: SimplifiedPayload,
    #[serde(default)]
    payloadkeys: Option<Vec<SimplifiedField>>,
}

#[derive(Debug, Deserialize)]
struct SimplifiedPayload {
    #[serde(default)]
    payloadtype: Option<String>,
    #[serde(default)]
    declarationtype: Option<String>,
    #[serde(default, rename = "supportedOS")]
    supported_os: Option<yaml_serde::Value>,
    #[serde(default)]
    apply: Option<String>,
}

/// Simplified field - no subkeys to avoid recursion
#[derive(Debug, Deserialize)]
struct SimplifiedField {
    key: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(rename = "type")]
    field_type: String,
    #[serde(default)]
    presence: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

/// Parse YAML with simplified structure (for files that hit recursion limit)
fn parse_yaml_manifest_simplified(content: &str) -> Result<PayloadManifest> {
    let manifest: SimplifiedManifest =
        yaml_serde::from_str(content).context("Failed to parse YAML with simplified structure")?;

    let payload_type = manifest
        .payload
        .declarationtype
        .clone()
        .or(manifest.payload.payloadtype.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // Parse supportedOS from Value
    let (platforms, min_versions) = if let Some(ref os_value) = manifest.payload.supported_os {
        parse_supported_os_from_value(os_value)
    } else {
        (
            Platforms {
                ios: true,
                macos: true,
                ..Default::default()
            },
            HashMap::new(),
        )
    };

    let category = if manifest.payload.declarationtype.is_some() {
        categorize_ddm_type(&payload_type)
    } else {
        categorize_payload_type(&payload_type)
    };

    // Parse only top-level fields (no subkeys)
    let mut fields = HashMap::new();
    let mut field_order = Vec::new();

    if let Some(ref keys) = manifest.payloadkeys {
        for field in keys {
            let required = field.presence.as_ref().is_some_and(|p| p == "required");
            let title = field.title.clone().unwrap_or_else(|| field.key.clone());

            let def = FieldDefinition {
                name: field.key.clone(),
                field_type: parse_apple_type(&field.field_type),
                title,
                description: field.content.clone().unwrap_or_default(),
                flags: FieldFlags {
                    required,
                    supervised: false,
                    sensitive: false,
                },
                default: None,
                allowed_values: Vec::new(),
                depth: 0,
                parent_key: None,
                platforms: Vec::new(),
                min_version: None,
            };
            field_order.push(def.name.clone());
            fields.insert(def.name.clone(), def);
        }
    }

    Ok(PayloadManifest {
        payload_type,
        title: manifest.title,
        description: manifest.description.unwrap_or_default(),
        platforms,
        min_versions,
        category,
        fields,
        field_order,
        segments: vec![],
    })
}

/// Parse supportedOS from yaml_serde::Value
fn parse_supported_os_from_value(
    value: &yaml_serde::Value,
) -> (Platforms, HashMap<Platform, String>) {
    let mut platforms = Platforms::default();
    let mut versions = HashMap::new();

    if let yaml_serde::Value::Mapping(map) = value {
        for (key, val) in map {
            if let yaml_serde::Value::String(os_name) = key {
                let introduced = val
                    .get("introduced")
                    .and_then(|v| v.as_str())
                    .filter(|s| *s != "n/a");

                match os_name.as_str() {
                    "iOS" => {
                        if introduced.is_some() {
                            platforms.ios = true;
                        }
                        if let Some(v) = introduced {
                            versions.insert(Platform::Ios, v.to_string());
                        }
                    }
                    "macOS" => {
                        if introduced.is_some() {
                            platforms.macos = true;
                        }
                        if let Some(v) = introduced {
                            versions.insert(Platform::MacOS, v.to_string());
                        }
                    }
                    "tvOS" => {
                        if introduced.is_some() {
                            platforms.tvos = true;
                        }
                        if let Some(v) = introduced {
                            versions.insert(Platform::TvOS, v.to_string());
                        }
                    }
                    "watchOS" => {
                        if introduced.is_some() {
                            platforms.watchos = true;
                        }
                        if let Some(v) = introduced {
                            versions.insert(Platform::WatchOS, v.to_string());
                        }
                    }
                    "visionOS" => {
                        if introduced.is_some() {
                            platforms.visionos = true;
                        }
                        if let Some(v) = introduced {
                            versions.insert(Platform::VisionOS, v.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Default to iOS and macOS if nothing set
    if !platforms.ios
        && !platforms.macos
        && !platforms.tvos
        && !platforms.watchos
        && !platforms.visionos
    {
        platforms.ios = true;
        platforms.macos = true;
    }

    (platforms, versions)
}

/// Categorize DDM declaration type
fn categorize_ddm_type(decl_type: &str) -> String {
    if decl_type.contains(".activation") {
        "activation".to_string()
    } else if decl_type.contains(".asset") {
        "asset".to_string()
    } else if decl_type.contains(".configuration") {
        "configuration".to_string()
    } else if decl_type.contains(".management") {
        "management".to_string()
    } else {
        "ddm".to_string()
    }
}

/// Parse a YAML file from path
pub fn parse_yaml_file(path: &Path) -> Result<PayloadManifest> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;
    parse_yaml_manifest(&content)
}

/// Load all manifests from Apple device-management directory
pub fn load_from_apple_dm_dir(dir: &Path) -> Result<Vec<PayloadManifest>> {
    let mut manifests = Vec::new();

    // Apple device-management structure:
    // mdm/profiles/*.yaml - MDM profile payloads
    // declarative/declarations/{activations,assets,configurations,management}/*.yaml - DDM

    // Load MDM profiles
    let profiles_dir = dir.join("mdm").join("profiles");
    if profiles_dir.exists() {
        manifests.extend(load_yaml_directory(&profiles_dir)?);
    }

    // Load DDM declarations
    let decl_base = dir.join("declarative").join("declarations");
    if decl_base.exists() {
        for subdir in &["activations", "assets", "configurations", "management"] {
            let subdir_path = decl_base.join(subdir);
            if subdir_path.exists() {
                manifests.extend(load_yaml_directory(&subdir_path)?);
            }
        }
    }

    // Fallback: Maybe dir is already pointing to a specific directory
    if manifests.is_empty() {
        manifests = load_yaml_directory(dir)?;
    }

    Ok(manifests)
}

/// Load all .yaml manifests from a directory
fn load_yaml_directory(dir: &Path) -> Result<Vec<PayloadManifest>> {
    let mut manifests = Vec::new();

    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        let ext = path.extension().and_then(|s| s.to_str());
        if ext == Some("yaml") || ext == Some("yml") {
            match parse_yaml_file(&path) {
                Ok(manifest) => manifests.push(manifest),
                Err(e) => {
                    // Log warning but continue
                    eprintln!("Warning: Failed to parse {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(manifests)
}

/// Parse supportedOS into Platforms
fn parse_supported_os(supported: &Option<AppleSupportedOS>) -> Platforms {
    let mut result = Platforms::default();

    if let Some(os) = supported {
        if os.iOS.is_some() {
            result.ios = true;
        }
        if os.macOS.is_some() {
            result.macos = true;
        }
        if os.tvOS.is_some() {
            result.tvos = true;
        }
        if os.watchOS.is_some() {
            result.watchos = true;
        }
        if os.visionOS.is_some() {
            result.visionos = true;
        }
    }

    // Default to iOS and macOS if not specified
    if !result.macos && !result.ios && !result.tvos && !result.watchos && !result.visionos {
        result.ios = true;
        result.macos = true;
    }

    result
}

/// Parse minimum versions from supportedOS
fn parse_min_versions(supported: &Option<AppleSupportedOS>) -> HashMap<Platform, String> {
    let mut versions = HashMap::new();

    if let Some(os) = supported {
        if let Some(ref ios) = os.iOS
            && let Some(ref v) = ios.introduced
        {
            versions.insert(Platform::Ios, v.clone());
        }
        if let Some(ref macos) = os.macOS
            && let Some(ref v) = macos.introduced
        {
            versions.insert(Platform::MacOS, v.clone());
        }
        if let Some(ref tvos) = os.tvOS
            && let Some(ref v) = tvos.introduced
        {
            versions.insert(Platform::TvOS, v.clone());
        }
        if let Some(ref watchos) = os.watchOS
            && let Some(ref v) = watchos.introduced
        {
            versions.insert(Platform::WatchOS, v.clone());
        }
        if let Some(ref visionos) = os.visionOS
            && let Some(ref v) = visionos.introduced
        {
            versions.insert(Platform::VisionOS, v.clone());
        }
    }

    versions
}

/// Parse content fields into FieldDefinitions
fn parse_content_fields(
    content: &Option<Vec<AppleField>>,
) -> Result<(HashMap<String, FieldDefinition>, Vec<String>)> {
    let mut fields = HashMap::new();
    let mut field_order = Vec::new();

    if let Some(content_fields) = content {
        for field in content_fields {
            let def = parse_apple_field(field, 0);
            field_order.push(def.name.clone());
            fields.insert(def.name.clone(), def);
        }
    }

    Ok((fields, field_order))
}

/// Parse a single Apple field into FieldDefinition
fn parse_apple_field(field: &AppleField, depth: usize) -> FieldDefinition {
    let field_type = parse_apple_type(&field.field_type);

    let title = field.title.clone().unwrap_or_else(|| field.key.clone());

    // Parse presence to required flag
    let required = field.presence.as_ref().is_some_and(|p| p == "required");

    let flags = FieldFlags {
        required,
        supervised: field.supervised.unwrap_or(false),
        sensitive: field
            .sensitive
            .unwrap_or_else(|| field.key.to_lowercase().contains("password")),
    };

    // Parse default
    let default = field.default.as_ref().map(format_yaml_value);

    // Parse rangelist
    let allowed_values = field
        .rangelist
        .as_ref()
        .map(|list| list.iter().map(format_yaml_value).collect())
        .unwrap_or_default();

    FieldDefinition {
        name: field.key.clone(),
        field_type,
        title,
        description: field.content.clone().unwrap_or_default(),
        flags,
        default,
        allowed_values,
        depth: depth as u8,
        parent_key: None,
        platforms: Vec::new(),
        min_version: None,
    }
}

/// Convert Apple type string to FieldType
fn parse_apple_type(s: &str) -> FieldType {
    // Apple uses <type> format
    let s = s.trim_matches(|c| c == '<' || c == '>');
    match s.to_lowercase().as_str() {
        "string" => FieldType::String,
        "integer" => FieldType::Integer,
        "boolean" => FieldType::Boolean,
        "array" => FieldType::Array,
        "dictionary" => FieldType::Dictionary,
        "data" => FieldType::Data,
        "date" => FieldType::Date,
        "real" => FieldType::Real,
        _ => FieldType::String,
    }
}

/// Format YAML value as string
fn format_yaml_value(value: &yaml_serde::Value) -> String {
    match value {
        yaml_serde::Value::String(s) => s.clone(),
        yaml_serde::Value::Number(n) => n.to_string(),
        yaml_serde::Value::Bool(b) => b.to_string(),
        yaml_serde::Value::Sequence(a) => format!("[{} items]", a.len()),
        yaml_serde::Value::Mapping(m) => format!("{{{} keys}}", m.len()),
        yaml_serde::Value::Null => "null".to_string(),
        yaml_serde::Value::Tagged(t) => format_yaml_value(&t.value),
    }
}

/// Categorize payload type
fn categorize_payload_type(payload_type: &str) -> String {
    if payload_type.starts_with("com.apple.") {
        "apple".to_string()
    } else {
        "prefs".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Type Parsing Tests ==========

    #[test]
    fn test_parse_apple_type() {
        assert!(matches!(parse_apple_type("<string>"), FieldType::String));
        assert!(matches!(parse_apple_type("<integer>"), FieldType::Integer));
        assert!(matches!(parse_apple_type("<boolean>"), FieldType::Boolean));
        assert!(matches!(parse_apple_type("<array>"), FieldType::Array));
        assert!(matches!(
            parse_apple_type("<dictionary>"),
            FieldType::Dictionary
        ));
    }

    #[test]
    fn test_parse_apple_type_data_date_real() {
        assert!(matches!(parse_apple_type("<data>"), FieldType::Data));
        assert!(matches!(parse_apple_type("<date>"), FieldType::Date));
        assert!(matches!(parse_apple_type("<real>"), FieldType::Real));
    }

    #[test]
    fn test_parse_apple_type_without_brackets() {
        assert!(matches!(parse_apple_type("string"), FieldType::String));
        assert!(matches!(parse_apple_type("integer"), FieldType::Integer));
    }

    #[test]
    fn test_parse_apple_type_case_insensitive() {
        assert!(matches!(parse_apple_type("<STRING>"), FieldType::String));
        assert!(matches!(parse_apple_type("<Integer>"), FieldType::Integer));
    }

    #[test]
    fn test_parse_apple_type_unknown_defaults_to_string() {
        assert!(matches!(parse_apple_type("<unknown>"), FieldType::String));
        assert!(matches!(parse_apple_type("xyz"), FieldType::String));
    }

    // ========== Format YAML Value Tests ==========

    #[test]
    fn test_format_yaml_value_string() {
        let value = yaml_serde::Value::String("test".to_string());
        assert_eq!(format_yaml_value(&value), "test");
    }

    #[test]
    fn test_format_yaml_value_number() {
        let value = yaml_serde::Value::Number(42.into());
        assert_eq!(format_yaml_value(&value), "42");
    }

    #[test]
    fn test_format_yaml_value_bool() {
        let value = yaml_serde::Value::Bool(true);
        assert_eq!(format_yaml_value(&value), "true");

        let value = yaml_serde::Value::Bool(false);
        assert_eq!(format_yaml_value(&value), "false");
    }

    #[test]
    fn test_format_yaml_value_null() {
        let value = yaml_serde::Value::Null;
        assert_eq!(format_yaml_value(&value), "null");
    }

    #[test]
    fn test_format_yaml_value_sequence() {
        let value = yaml_serde::Value::Sequence(vec![
            yaml_serde::Value::String("a".to_string()),
            yaml_serde::Value::String("b".to_string()),
        ]);
        assert_eq!(format_yaml_value(&value), "[2 items]");
    }

    #[test]
    fn test_format_yaml_value_mapping() {
        let mut map = yaml_serde::Mapping::new();
        map.insert(
            yaml_serde::Value::String("key".to_string()),
            yaml_serde::Value::String("value".to_string()),
        );
        let value = yaml_serde::Value::Mapping(map);
        assert_eq!(format_yaml_value(&value), "{1 keys}");
    }

    // ========== Categorize Tests ==========

    #[test]
    fn test_categorize_payload_type_apple() {
        assert_eq!(categorize_payload_type("com.apple.wifi.managed"), "apple");
        assert_eq!(categorize_payload_type("com.apple.security"), "apple");
    }

    #[test]
    fn test_categorize_payload_type_prefs() {
        assert_eq!(categorize_payload_type("com.example.custom"), "prefs");
        assert_eq!(categorize_payload_type("org.myorg.config"), "prefs");
    }

    // ========== Simple YAML Parsing Tests ==========

    #[test]
    fn test_parse_simple_yaml() {
        let yaml = r"
title: Test Payload
description: A test payload
payload:
    payloadtype: com.apple.test
    content:
        - key: TestKey
          type: <string>
          presence: required
        - key: OptionalKey
          type: <boolean>
          default: true
";

        let manifest = parse_yaml_manifest(yaml).expect("Failed to parse YAML");
        assert_eq!(manifest.title, "Test Payload");
        assert_eq!(manifest.payload_type, "com.apple.test");
        assert_eq!(manifest.fields.len(), 2);

        let test_key = manifest.fields.get("TestKey").unwrap();
        assert!(test_key.flags.required);

        let optional_key = manifest.fields.get("OptionalKey").unwrap();
        assert!(!optional_key.flags.required);
        assert_eq!(optional_key.default, Some("true".to_string()));
    }

    #[test]
    fn test_parse_yaml_without_description() {
        let yaml = r"
title: Minimal Payload
payload:
    payloadtype: com.apple.minimal
";

        let manifest = parse_yaml_manifest(yaml).expect("Failed to parse YAML");
        assert_eq!(manifest.title, "Minimal Payload");
        assert_eq!(manifest.description, "");
    }

    #[test]
    fn test_parse_yaml_without_payload_type() {
        let yaml = r"
title: No Type
payload:
    content: []
";

        let manifest = parse_yaml_manifest(yaml).expect("Failed to parse YAML");
        assert_eq!(manifest.payload_type, "unknown");
    }

    #[test]
    fn test_parse_yaml_with_supported_os() {
        let yaml = r#"
title: OS Specific
payload:
    payloadtype: com.apple.ostest
    supportedOS:
        macOS:
            introduced: "10.15"
        iOS:
            introduced: "13.0"
"#;

        let manifest = parse_yaml_manifest(yaml).expect("Failed to parse YAML");
        assert!(manifest.platforms.macos);
        assert!(manifest.platforms.ios);
        assert!(!manifest.platforms.tvos);
        assert_eq!(
            manifest.min_versions.get(&Platform::MacOS),
            Some(&"10.15".to_string())
        );
        assert_eq!(
            manifest.min_versions.get(&Platform::Ios),
            Some(&"13.0".to_string())
        );
    }

    #[test]
    fn test_parse_yaml_with_rangelist() {
        let yaml = r"
title: Enum Test
payload:
    payloadtype: com.apple.enumtest
    content:
        - key: SecurityType
          type: <string>
          rangelist:
            - None
            - WEP
            - WPA
            - WPA2
";

        let manifest = parse_yaml_manifest(yaml).expect("Failed to parse YAML");
        let field = manifest.fields.get("SecurityType").unwrap();
        assert_eq!(field.allowed_values, vec!["None", "WEP", "WPA", "WPA2"]);
    }

    #[test]
    fn test_parse_yaml_with_supervised_field() {
        let yaml = r"
title: Supervised Test
payload:
    payloadtype: com.apple.supervised
    content:
        - key: SupervisedOnly
          type: <boolean>
          supervised: true
";

        let manifest = parse_yaml_manifest(yaml).expect("Failed to parse YAML");
        let field = manifest.fields.get("SupervisedOnly").unwrap();
        assert!(field.flags.supervised);
    }

    #[test]
    fn test_parse_yaml_with_sensitive_field() {
        let yaml = r"
title: Sensitive Test
payload:
    payloadtype: com.apple.sensitive
    content:
        - key: SecretKey
          type: <string>
          sensitive: true
";

        let manifest = parse_yaml_manifest(yaml).expect("Failed to parse YAML");
        let field = manifest.fields.get("SecretKey").unwrap();
        assert!(field.flags.sensitive);
    }

    #[test]
    fn test_parse_yaml_password_field_auto_sensitive() {
        let yaml = r"
title: Password Test
payload:
    payloadtype: com.apple.password
    content:
        - key: Password
          type: <string>
";

        let manifest = parse_yaml_manifest(yaml).expect("Failed to parse YAML");
        let field = manifest.fields.get("Password").unwrap();
        // Password fields are auto-detected as sensitive
        assert!(field.flags.sensitive);
    }

    #[test]
    fn test_parse_yaml_invalid() {
        let yaml = "not: valid: yaml: : :";
        let result = parse_yaml_manifest(yaml);
        assert!(result.is_err());
    }

    // ========== Platform Parsing Tests ==========

    #[test]
    fn test_parse_supported_os_none() {
        let platforms = parse_supported_os(&None);
        // Defaults to iOS and macOS
        assert!(platforms.macos);
        assert!(platforms.ios);
    }

    #[test]
    fn test_parse_supported_os_all() {
        let os = AppleSupportedOS {
            iOS: Some(AppleOSRequirement {
                introduced: Some("13.0".to_string()),
                ..Default::default()
            }),
            macOS: Some(AppleOSRequirement {
                introduced: Some("10.15".to_string()),
                ..Default::default()
            }),
            tvOS: Some(AppleOSRequirement {
                introduced: Some("13.0".to_string()),
                ..Default::default()
            }),
            watchOS: Some(AppleOSRequirement {
                introduced: Some("6.0".to_string()),
                ..Default::default()
            }),
            visionOS: Some(AppleOSRequirement {
                introduced: Some("1.0".to_string()),
                ..Default::default()
            }),
        };
        let platforms = parse_supported_os(&Some(os));
        assert!(platforms.macos);
        assert!(platforms.ios);
        assert!(platforms.tvos);
        assert!(platforms.watchos);
        assert!(platforms.visionos);
    }

    #[test]
    fn test_parse_min_versions_from_supported_os() {
        let os = AppleSupportedOS {
            iOS: Some(AppleOSRequirement {
                introduced: Some("14.0".to_string()),
                ..Default::default()
            }),
            macOS: Some(AppleOSRequirement {
                introduced: Some("11.0".to_string()),
                ..Default::default()
            }),
            tvOS: None,
            watchOS: None,
            visionOS: None,
        };
        let versions = parse_min_versions(&Some(os));
        assert_eq!(versions.get(&Platform::Ios), Some(&"14.0".to_string()));
        assert_eq!(versions.get(&Platform::MacOS), Some(&"11.0".to_string()));
        assert!(!versions.contains_key(&Platform::TvOS));
    }
}
