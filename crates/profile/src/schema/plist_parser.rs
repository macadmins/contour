//! Parser for ProfileManifests plist format
//!
//! ProfileManifests uses .plist files with pfm_* keys to define payload schemas.
//! See: https://github.com/ProfileManifests/ProfileManifests

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

use super::types::{FieldDefinition, FieldFlags, FieldType, PayloadManifest, Platforms, Segment};

/// Parse a ProfileManifests plist file into a PayloadManifest
pub fn parse_plist_manifest(content: &[u8]) -> Result<PayloadManifest> {
    let value: plist::Value =
        plist::from_bytes(content).context("Failed to parse plist content")?;

    let dict = value
        .as_dictionary()
        .ok_or_else(|| anyhow::anyhow!("Expected plist dictionary at root"))?;

    // Extract domain (payload type)
    let payload_type = dict
        .get("pfm_domain")
        .and_then(|v| v.as_string())
        .ok_or_else(|| anyhow::anyhow!("Missing pfm_domain"))?
        .to_string();

    // Extract title
    let title = dict
        .get("pfm_title")
        .and_then(|v| v.as_string())
        .unwrap_or(&payload_type)
        .to_string();

    // Extract description
    let description = dict
        .get("pfm_description")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();

    // Extract platforms
    let platforms = parse_platforms(dict);

    // Determine category from payload_type
    let category = categorize_payload_type(&payload_type);

    // Parse subkeys into fields
    let (fields, field_order) = parse_subkeys(dict)?;

    // Parse segments (pfm_segments)
    let segments = parse_segments(dict);

    Ok(PayloadManifest {
        payload_type,
        title,
        description,
        platforms,
        min_versions: HashMap::new(),
        category,
        fields,
        field_order,
        segments,
    })
}

/// Parse a ProfileManifests plist file from path
pub fn parse_plist_file(path: &Path) -> Result<PayloadManifest> {
    let content =
        std::fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;
    parse_plist_manifest(&content)
}

/// Load all manifests from a ProfileManifests directory structure
pub fn load_from_profile_manifests_dir(dir: &Path) -> Result<Vec<PayloadManifest>> {
    let mut manifests = Vec::new();

    // ProfileManifests structure:
    // Manifests/ManifestsApple/*.plist
    // Manifests/ManagedPreferencesApple/*.plist
    // Manifests/ManagedPreferencesApplications/*.plist
    // Manifests/ManagedPreferencesDeveloper/*.plist

    let subdirs = [
        "ManifestsApple",
        "ManagedPreferencesApple",
        "ManagedPreferencesApplications",
        "ManagedPreferencesDeveloper",
    ];

    for subdir in subdirs {
        let subdir_path = dir.join(subdir);
        if subdir_path.exists() {
            manifests.extend(load_plist_directory(&subdir_path)?);
        }
    }

    // Also check if dir itself contains plist files
    if manifests.is_empty() {
        manifests = load_plist_directory(dir)?;
    }

    Ok(manifests)
}

/// Load all .plist manifests from a directory
fn load_plist_directory(dir: &Path) -> Result<Vec<PayloadManifest>> {
    let mut manifests = Vec::new();

    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("plist") {
            match parse_plist_file(&path) {
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

/// Parse pfm_platforms into Platforms
fn parse_platforms(dict: &plist::Dictionary) -> Platforms {
    let mut result = Platforms::default();

    // Check for pfm_platforms array
    if let Some(pfm_platforms) = dict.get("pfm_platforms").and_then(|v| v.as_array()) {
        for p in pfm_platforms {
            if let Some(s) = p.as_string() {
                match s.to_lowercase().as_str() {
                    "macos" | "osx" => result.macos = true,
                    "ios" => result.ios = true,
                    "tvos" => result.tvos = true,
                    "watchos" => result.watchos = true,
                    "visionos" => result.visionos = true,
                    _ => {}
                }
            }
        }
    }

    // Check individual platform flags
    if dict
        .get("pfm_macos_min")
        .or(dict.get("pfm_macos_max"))
        .is_some()
    {
        result.macos = true;
    }

    if dict
        .get("pfm_ios_min")
        .or(dict.get("pfm_ios_max"))
        .is_some()
    {
        result.ios = true;
    }

    if dict
        .get("pfm_tvos_min")
        .or(dict.get("pfm_tvos_max"))
        .is_some()
    {
        result.tvos = true;
    }

    // Default to macOS if no platforms specified
    if !result.macos && !result.ios && !result.tvos && !result.watchos && !result.visionos {
        result.macos = true;
    }

    result
}

/// Parse pfm_segments dictionary into Segment structs.
/// pfm_segments maps segment names to arrays of field name strings.
fn parse_segments(dict: &plist::Dictionary) -> Vec<Segment> {
    let Some(plist::Value::Dictionary(seg_dict)) = dict.get("pfm_segments") else {
        return vec![];
    };
    seg_dict
        .iter()
        .map(|(name, val)| {
            let field_names = val
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_string().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            Segment {
                name: name.clone(),
                field_names,
            }
        })
        .collect()
}

/// Parse pfm_subkeys into field definitions, recursing into nested subkeys.
fn parse_subkeys(
    dict: &plist::Dictionary,
) -> Result<(HashMap<String, FieldDefinition>, Vec<String>)> {
    let mut fields = HashMap::new();
    let mut field_order = Vec::new();

    if let Some(subkeys) = dict.get("pfm_subkeys").and_then(|v| v.as_array()) {
        collect_fields(subkeys, 0, &mut fields, &mut field_order);
    }

    Ok((fields, field_order))
}

/// Recursively collect fields from pfm_subkeys, tracking nesting depth.
fn collect_fields(
    subkeys: &[plist::Value],
    depth: u8,
    fields: &mut HashMap<String, FieldDefinition>,
    field_order: &mut Vec<String>,
) {
    for subkey in subkeys {
        let Some(subkey_dict) = subkey.as_dictionary() else {
            continue;
        };
        let Some(field) = parse_field(subkey_dict, depth as usize) else {
            continue;
        };

        // Skip standard payload keys (PayloadType, PayloadUUID, etc.)
        if is_standard_payload_key(&field.name) {
            continue;
        }

        // Skip duplicate names (can happen with segmented controls)
        if fields.contains_key(&field.name) {
            continue;
        }

        let name = field.name.clone();
        field_order.push(name.clone());
        fields.insert(name, field);

        // Recurse into child subkeys
        if let Some(child_subkeys) = subkey_dict.get("pfm_subkeys").and_then(|v| v.as_array()) {
            collect_fields(child_subkeys, depth + 1, fields, field_order);
        }
    }
}

/// Parse a single field from pfm_subkeys
fn parse_field(dict: &plist::Dictionary, depth: usize) -> Option<FieldDefinition> {
    let name = dict.get("pfm_name").and_then(|v| v.as_string())?;

    let field_type = dict
        .get("pfm_type")
        .and_then(|v| v.as_string())
        .map_or(FieldType::String, parse_pfm_type);

    let title = dict
        .get("pfm_title")
        .and_then(|v| v.as_string())
        .unwrap_or(name)
        .to_string();

    let description = dict
        .get("pfm_description")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();

    // Parse required flag
    let required = dict
        .get("pfm_require")
        .and_then(|v| v.as_string())
        .is_some_and(|s| s == "always" || s == "push");

    // Parse sensitive flag (pfm_sensitive or contains "password" in name)
    let sensitive = dict
        .get("pfm_sensitive")
        .and_then(plist::Value::as_boolean)
        .unwrap_or_else(|| name.to_lowercase().contains("password"));

    // Parse supervised flag
    let supervised = dict
        .get("pfm_supervised")
        .and_then(plist::Value::as_boolean)
        .unwrap_or(false);

    let flags = FieldFlags {
        required,
        supervised,
        sensitive,
    };

    // Parse default value
    let default = dict.get("pfm_default").map(format_plist_value);

    // Parse allowed values (pfm_range_list)
    let allowed_values = dict
        .get("pfm_range_list")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(format_plist_value).collect())
        .unwrap_or_default();

    Some(FieldDefinition {
        name: name.to_string(),
        field_type,
        title,
        description,
        flags,
        default,
        allowed_values,
        depth: depth as u8,
        platforms: Vec::new(),
        min_version: None,
    })
}

/// Convert pfm_type string to FieldType
fn parse_pfm_type(s: &str) -> FieldType {
    match s.to_lowercase().as_str() {
        "string" => FieldType::String,
        "integer" => FieldType::Integer,
        "boolean" | "bool" => FieldType::Boolean,
        "array" => FieldType::Array,
        "dictionary" | "dict" => FieldType::Dictionary,
        "data" => FieldType::Data,
        "date" => FieldType::Date,
        "real" | "float" => FieldType::Real,
        _ => FieldType::String,
    }
}

/// Format plist value as string
fn format_plist_value(value: &plist::Value) -> String {
    match value {
        plist::Value::String(s) => s.clone(),
        plist::Value::Integer(i) => i.to_string(),
        plist::Value::Real(f) => f.to_string(),
        plist::Value::Boolean(b) => b.to_string(),
        plist::Value::Data(d) => format!("<{} bytes>", d.len()),
        plist::Value::Date(d) => format!("{d:?}"),
        plist::Value::Array(a) => format!("[{} items]", a.len()),
        plist::Value::Dictionary(d) => format!("{{{} keys}}", d.len()),
        _ => "(unknown)".to_string(),
    }
}

/// Check if this is a standard payload key that should be skipped
fn is_standard_payload_key(name: &str) -> bool {
    matches!(
        name,
        "PayloadType"
            | "PayloadVersion"
            | "PayloadIdentifier"
            | "PayloadUUID"
            | "PayloadDisplayName"
            | "PayloadDescription"
            | "PayloadOrganization"
    )
}

/// Categorize payload type
fn categorize_payload_type(payload_type: &str) -> String {
    if payload_type.starts_with("com.apple.") {
        "apple".to_string()
    } else if payload_type.starts_with("com.google.")
        || payload_type.starts_with("com.microsoft.")
        || payload_type.starts_with("com.adobe.")
        || payload_type.starts_with("com.mozilla.")
        || payload_type.starts_with("com.1password.")
        || payload_type.starts_with("com.jamf.")
    {
        "apps".to_string()
    } else {
        "prefs".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Type Parsing Tests ==========

    #[test]
    fn test_parse_pfm_type() {
        assert!(matches!(parse_pfm_type("string"), FieldType::String));
        assert!(matches!(parse_pfm_type("integer"), FieldType::Integer));
        assert!(matches!(parse_pfm_type("boolean"), FieldType::Boolean));
        assert!(matches!(parse_pfm_type("array"), FieldType::Array));
        assert!(matches!(
            parse_pfm_type("dictionary"),
            FieldType::Dictionary
        ));
        assert!(matches!(parse_pfm_type("data"), FieldType::Data));
    }

    #[test]
    fn test_parse_pfm_type_variants() {
        assert!(matches!(parse_pfm_type("bool"), FieldType::Boolean));
        assert!(matches!(parse_pfm_type("dict"), FieldType::Dictionary));
        assert!(matches!(parse_pfm_type("float"), FieldType::Real));
        assert!(matches!(parse_pfm_type("real"), FieldType::Real));
        assert!(matches!(parse_pfm_type("date"), FieldType::Date));
    }

    #[test]
    fn test_parse_pfm_type_case_insensitive() {
        assert!(matches!(parse_pfm_type("STRING"), FieldType::String));
        assert!(matches!(parse_pfm_type("Integer"), FieldType::Integer));
        assert!(matches!(parse_pfm_type("BOOLEAN"), FieldType::Boolean));
    }

    #[test]
    fn test_parse_pfm_type_unknown_defaults_to_string() {
        assert!(matches!(parse_pfm_type("unknown"), FieldType::String));
        assert!(matches!(parse_pfm_type("xyz"), FieldType::String));
    }

    // ========== Standard Payload Key Tests ==========

    #[test]
    fn test_is_standard_payload_key() {
        assert!(is_standard_payload_key("PayloadType"));
        assert!(is_standard_payload_key("PayloadUUID"));
        assert!(!is_standard_payload_key("SSID_STR"));
        assert!(!is_standard_payload_key("AutoJoin"));
    }

    #[test]
    fn test_is_standard_payload_key_all() {
        assert!(is_standard_payload_key("PayloadType"));
        assert!(is_standard_payload_key("PayloadVersion"));
        assert!(is_standard_payload_key("PayloadIdentifier"));
        assert!(is_standard_payload_key("PayloadUUID"));
        assert!(is_standard_payload_key("PayloadDisplayName"));
        assert!(is_standard_payload_key("PayloadDescription"));
        assert!(is_standard_payload_key("PayloadOrganization"));
    }

    // ========== Categorize Tests ==========

    #[test]
    fn test_categorize_payload_type() {
        assert_eq!(categorize_payload_type("com.apple.wifi.managed"), "apple");
        assert_eq!(categorize_payload_type("com.google.Chrome"), "apps");
        assert_eq!(categorize_payload_type("com.microsoft.Edge"), "apps");
        assert_eq!(categorize_payload_type("org.example.custom"), "prefs");
    }

    #[test]
    fn test_categorize_payload_type_apps() {
        assert_eq!(categorize_payload_type("com.google.Chrome"), "apps");
        assert_eq!(categorize_payload_type("com.microsoft.Office"), "apps");
        assert_eq!(categorize_payload_type("com.adobe.Reader"), "apps");
        assert_eq!(categorize_payload_type("com.mozilla.Firefox"), "apps");
        assert_eq!(categorize_payload_type("com.1password.something"), "apps");
        assert_eq!(categorize_payload_type("com.jamf.connect"), "apps");
    }

    // ========== Format Plist Value Tests ==========

    #[test]
    fn test_format_plist_value_string() {
        let value = plist::Value::String("test".to_string());
        assert_eq!(format_plist_value(&value), "test");
    }

    #[test]
    fn test_format_plist_value_integer() {
        let value = plist::Value::Integer(42.into());
        assert_eq!(format_plist_value(&value), "42");
    }

    #[test]
    fn test_format_plist_value_real() {
        let value = plist::Value::Real(4.25);
        assert_eq!(format_plist_value(&value), "4.25");
    }

    #[test]
    fn test_format_plist_value_boolean() {
        let value = plist::Value::Boolean(true);
        assert_eq!(format_plist_value(&value), "true");

        let value = plist::Value::Boolean(false);
        assert_eq!(format_plist_value(&value), "false");
    }

    #[test]
    fn test_format_plist_value_data() {
        let value = plist::Value::Data(vec![1, 2, 3, 4, 5]);
        assert_eq!(format_plist_value(&value), "<5 bytes>");
    }

    #[test]
    fn test_format_plist_value_array() {
        let value = plist::Value::Array(vec![
            plist::Value::String("a".to_string()),
            plist::Value::String("b".to_string()),
        ]);
        assert_eq!(format_plist_value(&value), "[2 items]");
    }

    #[test]
    fn test_format_plist_value_dictionary() {
        let mut dict = plist::Dictionary::new();
        dict.insert("key".to_string(), plist::Value::String("value".to_string()));
        let value = plist::Value::Dictionary(dict);
        assert_eq!(format_plist_value(&value), "{1 keys}");
    }

    // ========== Plist Manifest Parsing Tests ==========

    fn create_test_plist() -> Vec<u8> {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "pfm_domain".to_string(),
            plist::Value::String("com.apple.test".to_string()),
        );
        dict.insert(
            "pfm_title".to_string(),
            plist::Value::String("Test Manifest".to_string()),
        );
        dict.insert(
            "pfm_description".to_string(),
            plist::Value::String("Test description".to_string()),
        );

        // Add subkeys
        let mut subkey1 = plist::Dictionary::new();
        subkey1.insert(
            "pfm_name".to_string(),
            plist::Value::String("TestField".to_string()),
        );
        subkey1.insert(
            "pfm_type".to_string(),
            plist::Value::String("string".to_string()),
        );
        subkey1.insert(
            "pfm_title".to_string(),
            plist::Value::String("Test Field".to_string()),
        );
        subkey1.insert(
            "pfm_description".to_string(),
            plist::Value::String("A test field".to_string()),
        );
        subkey1.insert(
            "pfm_require".to_string(),
            plist::Value::String("always".to_string()),
        );

        dict.insert(
            "pfm_subkeys".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(subkey1)]),
        );

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &plist::Value::Dictionary(dict)).unwrap();
        buffer
    }

    #[test]
    fn test_parse_plist_manifest_basic() {
        let content = create_test_plist();
        let manifest = parse_plist_manifest(&content).unwrap();

        assert_eq!(manifest.payload_type, "com.apple.test");
        assert_eq!(manifest.title, "Test Manifest");
        assert_eq!(manifest.description, "Test description");
        assert_eq!(manifest.category, "apple");
    }

    #[test]
    fn test_parse_plist_manifest_fields() {
        let content = create_test_plist();
        let manifest = parse_plist_manifest(&content).unwrap();

        assert_eq!(manifest.fields.len(), 1);
        let field = manifest.fields.get("TestField").unwrap();
        assert_eq!(field.name, "TestField");
        assert_eq!(field.field_type, FieldType::String);
        assert!(field.flags.required);
    }

    #[test]
    fn test_parse_plist_manifest_missing_domain() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "pfm_title".to_string(),
            plist::Value::String("No Domain".to_string()),
        );

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &plist::Value::Dictionary(dict)).unwrap();

        let result = parse_plist_manifest(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_plist_manifest_excludes_standard_keys() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "pfm_domain".to_string(),
            plist::Value::String("com.apple.test".to_string()),
        );
        dict.insert(
            "pfm_title".to_string(),
            plist::Value::String("Test".to_string()),
        );

        // Add standard payload keys that should be excluded
        let standard_key = {
            let mut sk = plist::Dictionary::new();
            sk.insert(
                "pfm_name".to_string(),
                plist::Value::String("PayloadType".to_string()),
            );
            sk.insert(
                "pfm_type".to_string(),
                plist::Value::String("string".to_string()),
            );
            sk
        };
        let custom_key = {
            let mut ck = plist::Dictionary::new();
            ck.insert(
                "pfm_name".to_string(),
                plist::Value::String("CustomField".to_string()),
            );
            ck.insert(
                "pfm_type".to_string(),
                plist::Value::String("string".to_string()),
            );
            ck
        };

        dict.insert(
            "pfm_subkeys".to_string(),
            plist::Value::Array(vec![
                plist::Value::Dictionary(standard_key),
                plist::Value::Dictionary(custom_key),
            ]),
        );

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &plist::Value::Dictionary(dict)).unwrap();

        let manifest = parse_plist_manifest(&buffer).unwrap();

        // PayloadType should be excluded
        assert!(!manifest.fields.contains_key("PayloadType"));
        // CustomField should be included
        assert!(manifest.fields.contains_key("CustomField"));
    }

    #[test]
    fn test_parse_plist_manifest_sensitive_password_field() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "pfm_domain".to_string(),
            plist::Value::String("com.apple.test".to_string()),
        );

        let mut password_field = plist::Dictionary::new();
        password_field.insert(
            "pfm_name".to_string(),
            plist::Value::String("Password".to_string()),
        );
        password_field.insert(
            "pfm_type".to_string(),
            plist::Value::String("string".to_string()),
        );

        dict.insert(
            "pfm_subkeys".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(password_field)]),
        );

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &plist::Value::Dictionary(dict)).unwrap();

        let manifest = parse_plist_manifest(&buffer).unwrap();
        let field = manifest.fields.get("Password").unwrap();
        assert!(
            field.flags.sensitive,
            "Password field should be auto-detected as sensitive"
        );
    }

    #[test]
    fn test_parse_plist_manifest_with_range_list() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "pfm_domain".to_string(),
            plist::Value::String("com.apple.test".to_string()),
        );

        let mut enum_field = plist::Dictionary::new();
        enum_field.insert(
            "pfm_name".to_string(),
            plist::Value::String("EnumField".to_string()),
        );
        enum_field.insert(
            "pfm_type".to_string(),
            plist::Value::String("string".to_string()),
        );
        enum_field.insert(
            "pfm_range_list".to_string(),
            plist::Value::Array(vec![
                plist::Value::String("Option1".to_string()),
                plist::Value::String("Option2".to_string()),
                plist::Value::String("Option3".to_string()),
            ]),
        );

        dict.insert(
            "pfm_subkeys".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(enum_field)]),
        );

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &plist::Value::Dictionary(dict)).unwrap();

        let manifest = parse_plist_manifest(&buffer).unwrap();
        let field = manifest.fields.get("EnumField").unwrap();
        assert_eq!(field.allowed_values, vec!["Option1", "Option2", "Option3"]);
    }

    #[test]
    fn test_parse_plist_manifest_with_default() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "pfm_domain".to_string(),
            plist::Value::String("com.apple.test".to_string()),
        );

        let mut bool_field = plist::Dictionary::new();
        bool_field.insert(
            "pfm_name".to_string(),
            plist::Value::String("AutoJoin".to_string()),
        );
        bool_field.insert(
            "pfm_type".to_string(),
            plist::Value::String("boolean".to_string()),
        );
        bool_field.insert("pfm_default".to_string(), plist::Value::Boolean(true));

        dict.insert(
            "pfm_subkeys".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(bool_field)]),
        );

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &plist::Value::Dictionary(dict)).unwrap();

        let manifest = parse_plist_manifest(&buffer).unwrap();
        let field = manifest.fields.get("AutoJoin").unwrap();
        assert_eq!(field.default, Some("true".to_string()));
    }

    // ========== Platform Parsing Tests ==========

    #[test]
    fn test_parse_platforms_from_array() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "pfm_platforms".to_string(),
            plist::Value::Array(vec![
                plist::Value::String("macOS".to_string()),
                plist::Value::String("iOS".to_string()),
            ]),
        );

        let platforms = parse_platforms(&dict);
        assert!(platforms.macos);
        assert!(platforms.ios);
        assert!(!platforms.tvos);
    }

    #[test]
    fn test_parse_platforms_from_min_version() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "pfm_macos_min".to_string(),
            plist::Value::String("10.15".to_string()),
        );

        let platforms = parse_platforms(&dict);
        assert!(platforms.macos);
    }

    #[test]
    fn test_parse_platforms_defaults_to_macos() {
        let dict = plist::Dictionary::new();
        let platforms = parse_platforms(&dict);
        assert!(platforms.macos);
    }

    #[test]
    fn test_parse_platforms_osx_variant() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "pfm_platforms".to_string(),
            plist::Value::Array(vec![plist::Value::String("OSX".to_string())]),
        );

        let platforms = parse_platforms(&dict);
        assert!(platforms.macos);
    }
}
