use anyhow::{Context, Result};
use std::collections::HashMap;

use super::types::{FieldDefinition, FieldFlags, FieldType, PayloadManifest, Platform, Platforms};

/// Parse ultra-compact format into PayloadManifest structs
///
/// Format:
/// - M|domain|title|description|platforms|min_versions|category
/// - K|name|type|flags|title|description|default|allowed|platform|version
/// - K>|... (first nested level)
/// - K>>|... (second nested level)
pub fn parse_ultra_compact(content: &str) -> Result<Vec<PayloadManifest>> {
    let mut manifests = Vec::new();
    let mut current_manifest: Option<PayloadManifest> = None;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("M|") {
            // Save previous manifest if any
            if let Some(manifest) = current_manifest.take() {
                manifests.push(manifest);
            }

            // Parse new manifest
            current_manifest =
                Some(parse_manifest_line(line).with_context(|| {
                    format!("Failed to parse manifest at line {}", line_num + 1)
                })?);
        } else if line.starts_with('K') {
            // Parse key definition
            if let Some(ref mut manifest) = current_manifest {
                let field = parse_key_line(line)
                    .with_context(|| format!("Failed to parse key at line {}", line_num + 1))?;

                manifest.field_order.push(field.name.clone());
                manifest.fields.insert(field.name.clone(), field);
            }
        }
    }

    // Don't forget the last manifest
    if let Some(manifest) = current_manifest {
        manifests.push(manifest);
    }

    Ok(manifests)
}

/// Parse DDM ultra-compact format into PayloadManifest structs
///
/// Format:
/// - D|declarationType|title|description|platforms|category|apply
/// - K|name|type|flags|title|description
pub fn parse_ddm_ultra_compact(content: &str) -> Result<Vec<PayloadManifest>> {
    let mut manifests = Vec::new();
    let mut current_manifest: Option<PayloadManifest> = None;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("D|") {
            // Save previous manifest if any
            if let Some(manifest) = current_manifest.take() {
                manifests.push(manifest);
            }

            // Parse new DDM declaration
            current_manifest = Some(parse_ddm_declaration_line(line).with_context(|| {
                format!("Failed to parse DDM declaration at line {}", line_num + 1)
            })?);
        } else if line.starts_with('K') {
            // Parse key definition (same format as profile manifests)
            if let Some(ref mut manifest) = current_manifest {
                let field = parse_ddm_key_line(line)
                    .with_context(|| format!("Failed to parse key at line {}", line_num + 1))?;

                manifest.field_order.push(field.name.clone());
                manifest.fields.insert(field.name.clone(), field);
            }
        }
    }

    // Don't forget the last manifest
    if let Some(manifest) = current_manifest {
        manifests.push(manifest);
    }

    Ok(manifests)
}

/// Parse a DDM declaration line: D|declarationType|title|description|platforms|category|apply
fn parse_ddm_declaration_line(line: &str) -> Result<PayloadManifest> {
    let parts: Vec<&str> = line.splitn(7, '|').collect();

    if parts.len() < 6 {
        anyhow::bail!(
            "Invalid DDM declaration line: expected at least 6 fields, got {}",
            parts.len()
        );
    }

    let payload_type = parts[1].to_string();
    let title = parts[2].to_string();
    let description = parts[3].to_string();
    let platforms = parse_ddm_platforms(parts[4]);
    let category = format!("ddm-{}", parts[5]); // Prefix with ddm- for categorization

    Ok(PayloadManifest {
        payload_type,
        title,
        description,
        platforms,
        min_versions: std::collections::HashMap::new(),
        category,
        fields: std::collections::HashMap::new(),
        field_order: Vec::new(),
        segments: vec![],
    })
}

/// Parse DDM platforms string like "iOS,macOS,tvOS"
fn parse_ddm_platforms(s: &str) -> Platforms {
    let mut platforms = Platforms::default();

    for part in s.split(',') {
        match part.trim() {
            "macOS" => platforms.macos = true,
            "iOS" => platforms.ios = true,
            "tvOS" => platforms.tvos = true,
            "watchOS" => platforms.watchos = true,
            "visionOS" => platforms.visionos = true,
            _ => {}
        }
    }

    platforms
}

/// Parse a DDM key line: K|name|type|flags|title|description
fn parse_ddm_key_line(line: &str) -> Result<FieldDefinition> {
    let content = &line[2..]; // Remove "K|" prefix
    let parts: Vec<&str> = content.splitn(6, '|').collect();

    if parts.len() < 5 {
        anyhow::bail!(
            "Invalid DDM key line: expected at least 5 fields, got {}",
            parts.len()
        );
    }

    let name = parts[0].to_string();
    let type_char = parts[1].chars().next().unwrap_or('s');
    let field_type = FieldType::from_char(type_char).unwrap_or(FieldType::String);
    let flags = FieldFlags::parse(parts[2]);
    let title = parts[3].to_string();
    let description = parts[4].to_string();

    Ok(FieldDefinition {
        name,
        field_type,
        flags,
        title,
        description,
        default: None,
        allowed_values: Vec::new(),
        depth: 0,
        parent_key: None,
        platforms: Vec::new(),
        min_version: None,
    })
}

/// Parse a manifest line: M|domain|title|description|platforms|min_versions|category
fn parse_manifest_line(line: &str) -> Result<PayloadManifest> {
    let parts: Vec<&str> = line.splitn(7, '|').collect();

    if parts.len() < 7 {
        anyhow::bail!(
            "Invalid manifest line: expected 7 fields, got {}",
            parts.len()
        );
    }

    let payload_type = parts[1].to_string();
    let title = parts[2].to_string();
    let description = parts[3].to_string();
    let platforms = Platforms::parse(parts[4]);
    let min_versions = parse_min_versions(parts[5]);
    let category = parts[6].to_string();

    Ok(PayloadManifest {
        payload_type,
        title,
        description,
        platforms,
        min_versions,
        category,
        fields: HashMap::new(),
        field_order: Vec::new(),
        segments: vec![],
    })
}

/// Parse minimum versions string like "m:10.7,i:4.0,t:9.0"
fn parse_min_versions(s: &str) -> HashMap<Platform, String> {
    let mut versions = HashMap::new();

    if s.is_empty() {
        return versions;
    }

    for part in s.split(',') {
        let kv: Vec<&str> = part.split(':').collect();
        if kv.len() == 2
            && let Some(platform) = Platform::from_char(kv[0].chars().next().unwrap_or(' '))
        {
            versions.insert(platform, kv[1].to_string());
        }
    }

    versions
}

/// Parse a key line: K|name|type|flags|title|description|default|allowed|platform|version
/// or K>|... for nested, K>>|... for double nested
fn parse_key_line(line: &str) -> Result<FieldDefinition> {
    // Determine depth from prefix
    let depth = if line.starts_with("K>>|") {
        2
    } else {
        u8::from(line.starts_with("K>|"))
    };

    // Remove prefix
    let content = if depth == 2 {
        &line[4..]
    } else if depth == 1 {
        &line[3..]
    } else {
        &line[2..]
    };

    // Split into parts (at least 5 fields required: name|type|flags|title|description)
    let parts: Vec<&str> = content.splitn(9, '|').collect();

    if parts.len() < 5 {
        anyhow::bail!(
            "Invalid key line: expected at least 5 fields, got {}",
            parts.len()
        );
    }

    let name = parts[0].to_string();

    // Parse type (single char)
    let type_char = parts[1].chars().next().unwrap_or('s');
    let field_type = FieldType::from_char(type_char).unwrap_or(FieldType::String);

    let flags = FieldFlags::parse(parts[2]);
    let title = parts[3].to_string();

    // Description may be truncated with ... - preserve as-is
    let description = parts[4].to_string();

    // Optional fields with safe access
    let default = parts.get(5).and_then(|s| {
        let s = s.trim();
        if s.is_empty() {
            None
        } else {
            // Remove quotes if present
            Some(s.trim_matches('"').to_string())
        }
    });

    let allowed_values: Vec<String> = parts
        .get(6)
        .map(|s| {
            s.split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // Platform-specific field
    let platforms: Vec<Platform> = parts
        .get(7)
        .map(|s| s.chars().filter_map(Platform::from_char).collect())
        .unwrap_or_default();

    // Version requirement (e.g., "m:10.8+")
    let min_version = parts.get(8).and_then(|s| {
        let s = s.trim();
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    });

    Ok(FieldDefinition {
        name,
        field_type,
        flags,
        title,
        description,
        default,
        allowed_values,
        depth,
        parent_key: None,
        platforms,
        min_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Manifest Line Tests ==========

    #[test]
    fn test_parse_manifest_line() {
        let line = "M|com.apple.wifi.managed|WiFi|Configure WiFi networks|m,i,t|m:10.7,i:4.0|apple";
        let manifest = parse_manifest_line(line).unwrap();

        assert_eq!(manifest.payload_type, "com.apple.wifi.managed");
        assert_eq!(manifest.title, "WiFi");
        assert!(manifest.platforms.macos);
        assert!(manifest.platforms.ios);
        assert!(manifest.platforms.tvos);
        assert!(!manifest.platforms.watchos);
        assert_eq!(manifest.category, "apple");
    }

    #[test]
    fn test_parse_manifest_line_all_platforms() {
        let line = "M|com.example.test|Test|Test desc|*||prefs";
        let manifest = parse_manifest_line(line).unwrap();

        assert!(manifest.platforms.macos);
        assert!(manifest.platforms.ios);
        assert!(manifest.platforms.tvos);
        assert!(manifest.platforms.watchos);
        assert!(manifest.platforms.visionos);
    }

    #[test]
    fn test_parse_manifest_line_empty_description() {
        let line = "M|com.example.test|Test||m||apple";
        let manifest = parse_manifest_line(line).unwrap();

        assert_eq!(manifest.description, "");
    }

    #[test]
    fn test_parse_manifest_line_invalid_too_few_fields() {
        let line = "M|com.example|Test|Desc";
        let result = parse_manifest_line(line);
        assert!(result.is_err());
    }

    // ========== Key Line Tests ==========

    #[test]
    fn test_parse_key_line_simple() {
        let line = "K|SSID_STR|s|R|Network Name|The name of the wireless network||||";
        let field = parse_key_line(line).unwrap();

        assert_eq!(field.name, "SSID_STR");
        assert_eq!(field.field_type, FieldType::String);
        assert!(field.flags.required);
        assert_eq!(field.depth, 0);
    }

    #[test]
    fn test_parse_key_line_with_defaults() {
        let line = "K|AutoJoin|b|-|Auto Join|Automatically join network|true|||";
        let field = parse_key_line(line).unwrap();

        assert_eq!(field.name, "AutoJoin");
        assert_eq!(field.field_type, FieldType::Boolean);
        assert!(!field.flags.required);
        assert_eq!(field.default, Some("true".to_string()));
    }

    #[test]
    fn test_parse_key_line_with_allowed_values() {
        let line = "K|EncryptionType|s|R|Security Type|The encryption type||None,WEP,WPA,WPA2||";
        let field = parse_key_line(line).unwrap();

        assert_eq!(field.allowed_values, vec!["None", "WEP", "WPA", "WPA2"]);
    }

    #[test]
    fn test_parse_key_line_nested() {
        let line = "K>|EAPUsername|s|-|Username|EAP username||||";
        let field = parse_key_line(line).unwrap();

        assert_eq!(field.name, "EAPUsername");
        assert_eq!(field.depth, 1);
    }

    #[test]
    fn test_parse_key_line_double_nested() {
        let line = "K>>|NestedField|i|-|Nested|Doubly nested field||||";
        let field = parse_key_line(line).unwrap();

        assert_eq!(field.name, "NestedField");
        assert_eq!(field.depth, 2);
        assert_eq!(field.field_type, FieldType::Integer);
    }

    #[test]
    fn test_parse_key_line_all_field_types() {
        let types = [
            ("s", FieldType::String),
            ("i", FieldType::Integer),
            ("b", FieldType::Boolean),
            ("a", FieldType::Array),
            ("d", FieldType::Dictionary),
            ("x", FieldType::Data),
            ("t", FieldType::Date),
            ("r", FieldType::Real),
        ];

        for (char, expected_type) in types {
            let line = format!("K|TestField|{}|-|Test|Description||||", char);
            let field = parse_key_line(&line).unwrap();
            assert_eq!(
                field.field_type, expected_type,
                "Failed for type char '{}'",
                char
            );
        }
    }

    #[test]
    fn test_parse_key_line_with_platform() {
        let line = "K|MacOnlyField|s|-|Mac Only|Mac only field|||m|";
        let field = parse_key_line(line).unwrap();

        assert_eq!(field.platforms.len(), 1);
        assert_eq!(field.platforms[0], Platform::MacOS);
    }

    #[test]
    fn test_parse_key_line_with_multiple_platforms() {
        let line = "K|MultiPlatformField|s|-|Multi|Multi platform|||mi|";
        let field = parse_key_line(line).unwrap();

        assert_eq!(field.platforms.len(), 2);
        assert!(field.platforms.contains(&Platform::MacOS));
        assert!(field.platforms.contains(&Platform::Ios));
    }

    #[test]
    fn test_parse_key_line_with_min_version() {
        let line = "K|NewField|s|-|New|New field||||m:10.13+";
        let field = parse_key_line(line).unwrap();

        assert_eq!(field.min_version, Some("m:10.13+".to_string()));
    }

    #[test]
    fn test_parse_key_line_all_flags() {
        let line = "K|SecureField|s|RSX|Secure|Sensitive required supervised field||||";
        let field = parse_key_line(line).unwrap();

        assert!(field.flags.required);
        assert!(field.flags.supervised);
        assert!(field.flags.sensitive);
    }

    #[test]
    fn test_parse_key_line_quoted_default() {
        let line = "K|StringField|s|-|String|With quotes|\"quoted value\"|||";
        let field = parse_key_line(line).unwrap();

        assert_eq!(field.default, Some("quoted value".to_string()));
    }

    #[test]
    fn test_parse_key_line_invalid_too_few_fields() {
        let line = "K|Name|s|R";
        let result = parse_key_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_key_line_unknown_type_defaults_to_string() {
        let line = "K|Unknown|z|-|Unknown|Unknown type||||";
        let field = parse_key_line(line).unwrap();
        assert_eq!(field.field_type, FieldType::String);
    }

    // ========== Min Versions Tests ==========

    #[test]
    fn test_parse_min_versions() {
        let versions = parse_min_versions("m:10.7,i:4.0,t:9.0");

        assert_eq!(versions.get(&Platform::MacOS), Some(&"10.7".to_string()));
        assert_eq!(versions.get(&Platform::Ios), Some(&"4.0".to_string()));
        assert_eq!(versions.get(&Platform::TvOS), Some(&"9.0".to_string()));
    }

    #[test]
    fn test_parse_min_versions_empty() {
        let versions = parse_min_versions("");
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_min_versions_single_platform() {
        let versions = parse_min_versions("m:14.0");
        assert_eq!(versions.len(), 1);
        assert_eq!(versions.get(&Platform::MacOS), Some(&"14.0".to_string()));
    }

    #[test]
    fn test_parse_min_versions_all_platforms() {
        let versions = parse_min_versions("m:14.0,i:17.0,t:17.0,w:10.0,v:1.0");
        assert_eq!(versions.len(), 5);
        assert!(versions.contains_key(&Platform::MacOS));
        assert!(versions.contains_key(&Platform::Ios));
        assert!(versions.contains_key(&Platform::TvOS));
        assert!(versions.contains_key(&Platform::WatchOS));
        assert!(versions.contains_key(&Platform::VisionOS));
    }

    // ========== Ultra Compact Format Tests ==========

    #[test]
    fn test_parse_ultra_compact() {
        let content = r"
# Test manifest
M|com.apple.test|Test|Test payload|m,i|m:10.7|apple
K|Field1|s|R|Field One|First field||||
K|Field2|i|-|Field Two|Second field|42|||
";
        let manifests = parse_ultra_compact(content).unwrap();

        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].payload_type, "com.apple.test");
        assert_eq!(manifests[0].fields.len(), 2);
        assert_eq!(manifests[0].field_order, vec!["Field1", "Field2"]);
    }

    #[test]
    fn test_parse_ultra_compact_multiple_manifests() {
        let content = r"
M|com.apple.first|First|First payload|m||apple
K|FieldA|s|-|A|First field||||

M|com.apple.second|Second|Second payload|i||apple
K|FieldB|i|-|B|Second field||||
K|FieldC|b|-|C|Third field||||
";
        let manifests = parse_ultra_compact(content).unwrap();

        assert_eq!(manifests.len(), 2);
        assert_eq!(manifests[0].payload_type, "com.apple.first");
        assert_eq!(manifests[0].fields.len(), 1);
        assert_eq!(manifests[1].payload_type, "com.apple.second");
        assert_eq!(manifests[1].fields.len(), 2);
    }

    #[test]
    fn test_parse_ultra_compact_empty_content() {
        let content = "";
        let manifests = parse_ultra_compact(content).unwrap();
        assert!(manifests.is_empty());
    }

    #[test]
    fn test_parse_ultra_compact_only_comments() {
        let content = r"
# This is a comment
# Another comment

";
        let manifests = parse_ultra_compact(content).unwrap();
        assert!(manifests.is_empty());
    }

    #[test]
    fn test_parse_ultra_compact_manifest_without_fields() {
        let content = "M|com.apple.empty|Empty|No fields|m||apple";
        let manifests = parse_ultra_compact(content).unwrap();

        assert_eq!(manifests.len(), 1);
        assert!(manifests[0].fields.is_empty());
    }

    #[test]
    fn test_parse_ultra_compact_with_nested_fields() {
        let content = r"
M|com.apple.test|Test|Test with nesting|m||apple
K|TopLevel|d|-|Top|Top level dict||||
K>|Nested|s|-|Nested|Nested field||||
K>>|DeepNested|i|-|Deep|Deep nested||||
";
        let manifests = parse_ultra_compact(content).unwrap();

        assert_eq!(manifests[0].fields.len(), 3);
        assert_eq!(manifests[0].fields.get("TopLevel").unwrap().depth, 0);
        assert_eq!(manifests[0].fields.get("Nested").unwrap().depth, 1);
        assert_eq!(manifests[0].fields.get("DeepNested").unwrap().depth, 2);
    }

    #[test]
    fn test_parse_ultra_compact_preserves_field_order() {
        let content = r"
M|com.apple.test|Test|Test|m||apple
K|Zebra|s|-|Zebra|Z field||||
K|Alpha|s|-|Alpha|A field||||
K|Middle|s|-|Middle|M field||||
";
        let manifests = parse_ultra_compact(content).unwrap();

        assert_eq!(manifests[0].field_order, vec!["Zebra", "Alpha", "Middle"]);
    }
}
