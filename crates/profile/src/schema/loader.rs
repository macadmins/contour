use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

use super::parser::parse_ultra_compact;
use super::plist_parser;
use super::types::{FieldDefinition, FieldFlags, FieldType, PayloadManifest, Platform, Platforms};
use super::yaml_parser;

/// Schema format detection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SchemaFormat {
    /// Ultra-compact .ultra.txt format
    UltraCompact,
    /// ProfileManifests .plist format
    ProfileManifests,
    /// Apple device-management .yaml format
    AppleYaml,
}

/// Load embedded manifests from mdm-schema's Parquet data (profiles + capabilities).
pub fn load_embedded() -> Result<Vec<PayloadManifest>> {
    let profile_manifests = mdm_schema::profiles::read(mdm_schema::embedded_profile_manifests())
        .context("Failed to read embedded profile manifests from Parquet")?;

    let mut manifests: Vec<PayloadManifest> = profile_manifests
        .into_iter()
        .map(|pm| {
            let mut fields = HashMap::new();
            let mut field_order = Vec::new();

            for f in &pm.fields {
                field_order.push(f.name.clone());
                fields.insert(
                    f.name.clone(),
                    FieldDefinition {
                        name: f.name.clone(),
                        field_type: match f.field_type.as_str() {
                            "String" => FieldType::String,
                            "Integer" => FieldType::Integer,
                            "Boolean" => FieldType::Boolean,
                            "Array" => FieldType::Array,
                            "Dictionary" => FieldType::Dictionary,
                            "Data" => FieldType::Data,
                            "Date" => FieldType::Date,
                            "Real" => FieldType::Real,
                            _ => FieldType::String,
                        },
                        flags: FieldFlags {
                            required: f.required,
                            supervised: f.supervised,
                            sensitive: f.sensitive,
                        },
                        title: f.title.clone(),
                        description: f.description.clone(),
                        default: f.default_value.clone(),
                        allowed_values: f
                            .allowed_values
                            .as_ref()
                            .map(|v| {
                                v.split(',')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect()
                            })
                            .unwrap_or_default(),
                        depth: f.depth,
                        parent_key: None,
                        platforms: f
                            .platforms
                            .as_ref()
                            .map(|s| s.chars().filter_map(Platform::from_char).collect())
                            .unwrap_or_default(),
                        min_version: f.min_version.clone(),
                    },
                );
            }

            let mut min_versions = HashMap::new();
            if let Some(v) = &pm.min_versions.macos {
                min_versions.insert(Platform::MacOS, v.clone());
            }
            if let Some(v) = &pm.min_versions.ios {
                min_versions.insert(Platform::Ios, v.clone());
            }
            if let Some(v) = &pm.min_versions.tvos {
                min_versions.insert(Platform::TvOS, v.clone());
            }
            if let Some(v) = &pm.min_versions.watchos {
                min_versions.insert(Platform::WatchOS, v.clone());
            }
            if let Some(v) = &pm.min_versions.visionos {
                min_versions.insert(Platform::VisionOS, v.clone());
            }

            PayloadManifest {
                payload_type: pm.payload_type,
                title: pm.title,
                description: pm.description,
                platforms: Platforms {
                    macos: pm.platforms.macos,
                    ios: pm.platforms.ios,
                    tvos: pm.platforms.tvos,
                    watchos: pm.platforms.watchos,
                    visionos: pm.platforms.visionos,
                },
                min_versions,
                category: pm.category,
                fields,
                field_order,
                segments: vec![],
            }
        })
        .collect();

    // Append Apple's native schemas from capabilities.parquet.
    // MDM profiles override ProfileCreator where both exist (Apple is authoritative).
    // DDM declarations are added alongside (no overlap with ProfileCreator).
    let capabilities = mdm_schema::capabilities::read(mdm_schema::embedded_capabilities())
        .context("Failed to read embedded capabilities from Parquet")?;

    // Collect existing payload_types so we can merge, not duplicate
    let mut existing_types: std::collections::HashSet<String> =
        manifests.iter().map(|m| m.payload_type.clone()).collect();

    // MDM profiles from Apple's device-management repo (authoritative)
    for cap in capabilities
        .iter()
        .filter(|c| c.kind == mdm_schema::PayloadKind::MdmProfile)
    {
        if existing_types.contains(&cap.payload_type) {
            // Merge Apple keys into existing ProfileCreator manifest.
            // Apple keys take precedence where both define the same key,
            // but ProfileCreator-only keys (legacy) are preserved.
            if let Some(existing) = manifests
                .iter_mut()
                .find(|m| m.payload_type == cap.payload_type)
            {
                let apple = capability_to_manifest(cap);
                // Merge fields: Apple overrides, ProfileCreator fills gaps
                for (key, field) in apple.fields {
                    existing.fields.insert(key.clone(), field);
                    if !existing.field_order.contains(&key) {
                        existing.field_order.push(key);
                    }
                }
                existing.platforms = apple.platforms;
                if !apple.description.is_empty() {
                    existing.description = apple.description;
                }
            }
        } else {
            existing_types.insert(cap.payload_type.clone());
            manifests.push(capability_to_manifest(cap));
        }
    }

    // DDM declarations (no overlap with ProfileCreator)
    for cap in capabilities
        .iter()
        .filter(|c| c.kind == mdm_schema::PayloadKind::DdmDeclaration)
    {
        if !existing_types.contains(&cap.payload_type) {
            existing_types.insert(cap.payload_type.clone());
            manifests.push(capability_to_manifest(cap));
        }
    }

    // Append supplemental preference domains used by mSCP but not yet in any upstream source.
    manifests.extend(supplemental_prefs_manifests());

    Ok(manifests)
}

/// Preference domains commonly managed via profiles (mSCP, CIS benchmarks) but
/// missing from the upstream ProfileManifests/ProfileCreator repo.
fn supplemental_prefs_manifests() -> Vec<PayloadManifest> {
    let make = |payload_type: &str, title: &str, desc: &str, keys: &[(&str, FieldType, &str)]| {
        let mut fields = HashMap::new();
        let mut field_order = Vec::new();
        for (name, ft, fdesc) in keys {
            field_order.push(name.to_string());
            fields.insert(
                name.to_string(),
                FieldDefinition {
                    name: name.to_string(),
                    field_type: ft.clone(),
                    flags: FieldFlags::default(),
                    title: name.to_string(),
                    description: fdesc.to_string(),
                    default: None,
                    allowed_values: Vec::new(),
                    depth: 0,
                    parent_key: None,
                    platforms: vec![Platform::MacOS],
                    min_version: None,
                },
            );
        }
        PayloadManifest {
            payload_type: payload_type.to_string(),
            title: title.to_string(),
            description: desc.to_string(),
            platforms: Platforms {
                macos: true,
                ..Default::default()
            },
            min_versions: HashMap::new(),
            category: "prefs".to_string(),
            fields,
            field_order,
            segments: vec![],
        }
    };

    vec![
        make(
            "com.apple.Accessibility",
            "Accessibility",
            "Accessibility preference domain for macOS.",
            &[
                (
                    "ReduceTransparencyEnabled",
                    FieldType::Boolean,
                    "Reduce transparency in the UI",
                ),
                (
                    "IncreaseContrastEnabled",
                    FieldType::Boolean,
                    "Increase contrast in the UI",
                ),
                (
                    "ReduceMotionEnabled",
                    FieldType::Boolean,
                    "Reduce motion effects",
                ),
                (
                    "DifferentiateWithoutColor",
                    FieldType::Boolean,
                    "Differentiate without color",
                ),
                (
                    "EnhancedBackgroundContrastEnabled",
                    FieldType::Boolean,
                    "Increase contrast between app content and the background",
                ),
                ("KeyRepeatEnabled", FieldType::Boolean, "Enable key repeat"),
                (
                    "KeyRepeatDelay",
                    FieldType::Real,
                    "Delay before key repeat starts",
                ),
                (
                    "KeyRepeatInterval",
                    FieldType::Real,
                    "Interval between key repeats",
                ),
            ],
        ),
        make(
            "com.apple.Terminal",
            "Terminal",
            "Terminal.app preference domain for macOS.",
            &[(
                "SecureKeyboardEntry",
                FieldType::Boolean,
                "Enable Secure Keyboard Entry to prevent other apps from intercepting keystrokes",
            )],
        ),
    ]
}

/// Convert an Apple `Capability` (MDM profile or DDM declaration) to a contour `PayloadManifest`.
fn capability_to_manifest(cap: &mdm_schema::Capability) -> PayloadManifest {
    let mut fields = std::collections::HashMap::new();
    let mut field_order = Vec::new();

    for key in &cap.keys {
        // Deduplicate across platforms but include all depths
        if fields.contains_key(&key.name) {
            continue;
        }
        let field_type = match key.data_type.as_str() {
            "boolean" => FieldType::Boolean,
            "integer" => FieldType::Integer,
            "real" => FieldType::Real,
            "data" => FieldType::Data,
            "date" => FieldType::Date,
            "array" => FieldType::Array,
            "dictionary" => FieldType::Dictionary,
            _ => FieldType::String,
        };
        let fd = FieldDefinition {
            name: key.name.clone(),
            field_type,
            flags: FieldFlags {
                required: key.presence == "required",
                supervised: false,
                sensitive: false,
            },
            title: key.key_title.clone().unwrap_or_default(),
            description: key.key_description.clone().unwrap_or_default(),
            default: key.default_value.as_ref().map(|v| v.to_string()),
            allowed_values: key.range_list.clone().unwrap_or_default(),
            depth: key.depth as u8,
            parent_key: key.parent_key.clone(),
            platforms: Vec::new(),
            min_version: None,
        };
        field_order.push(key.name.clone());
        fields.insert(key.name.clone(), fd);
    }

    // Derive platform flags from supported_os
    let mut platforms = Platforms::default();
    for os in &cap.supported_os {
        match os.platform {
            mdm_schema::Platform::MacOS => platforms.macos = true,
            mdm_schema::Platform::IOS => platforms.ios = true,
            mdm_schema::Platform::TvOS => platforms.tvos = true,
            mdm_schema::Platform::WatchOS => platforms.watchos = true,
            mdm_schema::Platform::VisionOS => platforms.visionos = true,
        }
    }

    // Map kind + DDM category to contour's category system
    let category = match cap.kind {
        mdm_schema::PayloadKind::MdmProfile => "apple".to_string(),
        mdm_schema::PayloadKind::DdmDeclaration => cap
            .ddm_category
            .as_ref()
            .map(|c| format!("ddm-{}", c.as_str()))
            .unwrap_or_else(|| "ddm-configuration".to_string()),
        mdm_schema::PayloadKind::MdmCommand | mdm_schema::PayloadKind::MdmCheckin => {
            "apple".to_string()
        }
    };

    // Derive min_versions from the earliest `introduced` per platform
    let mut min_versions = std::collections::HashMap::new();
    for os in &cap.supported_os {
        if let Some(ref v) = os.introduced {
            let platform = match os.platform {
                mdm_schema::Platform::MacOS => Platform::MacOS,
                mdm_schema::Platform::IOS => Platform::Ios,
                mdm_schema::Platform::TvOS => Platform::TvOS,
                mdm_schema::Platform::WatchOS => Platform::WatchOS,
                mdm_schema::Platform::VisionOS => Platform::VisionOS,
            };
            min_versions.entry(platform).or_insert_with(|| v.clone());
        }
    }

    PayloadManifest {
        payload_type: cap.payload_type.clone(),
        title: cap.title.clone(),
        description: cap.description.clone(),
        platforms,
        min_versions,
        category,
        fields,
        field_order,
        segments: vec![],
    }
}

/// Load manifests from an external directory, auto-detecting format
pub fn load_from_directory(dir: &Path) -> Result<Vec<PayloadManifest>> {
    let format = detect_directory_format(dir)?;
    load_from_directory_with_format(dir, format)
}

/// Load manifests from directory with explicit format
pub fn load_from_directory_with_format(
    dir: &Path,
    format: SchemaFormat,
) -> Result<Vec<PayloadManifest>> {
    match format {
        SchemaFormat::UltraCompact => load_ultra_compact_directory(dir),
        SchemaFormat::ProfileManifests => plist_parser::load_from_profile_manifests_dir(dir),
        SchemaFormat::AppleYaml => yaml_parser::load_from_apple_dm_dir(dir),
    }
}

/// Detect the schema format from directory contents
pub fn detect_directory_format(dir: &Path) -> Result<SchemaFormat> {
    // Check for ProfileManifests structure (has ManifestsApple/ or ManagedPreferences* subdirs)
    let manifests_apple = dir.join("ManifestsApple");
    let managed_prefs_apple = dir.join("ManagedPreferencesApple");
    let managed_prefs_apps = dir.join("ManagedPreferencesApplications");

    if manifests_apple.exists() || managed_prefs_apple.exists() || managed_prefs_apps.exists() {
        return Ok(SchemaFormat::ProfileManifests);
    }

    // Check for Manifests/ parent (pointing to repo root)
    let manifests_dir = dir.join("Manifests");
    if manifests_dir.exists() {
        return Ok(SchemaFormat::ProfileManifests);
    }

    // Check for Apple device-management structure (has mdm/profiles/ subdirectory)
    let mdm_profiles = dir.join("mdm").join("profiles");
    if mdm_profiles.exists() {
        return Ok(SchemaFormat::AppleYaml);
    }

    // Check for profiles subdirectory (if pointing to mdm/)
    let profiles_dir = dir.join("profiles");
    if profiles_dir.exists() {
        // Check if any .yaml files exist in profiles/
        if let Ok(entries) = std::fs::read_dir(&profiles_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|s| s.to_str());
                if ext == Some("yaml") || ext == Some("yml") {
                    return Ok(SchemaFormat::AppleYaml);
                }
            }
        }
    }

    // Check file extensions in directory and subdirectories
    let mut has_plist = false;
    let mut has_yaml = false;
    let mut has_ultra = false;

    // Check current directory
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();

            // Recurse one level into subdirs for detection
            if path.is_dir() {
                if let Ok(sub_entries) = std::fs::read_dir(&path) {
                    for sub_entry in sub_entries.flatten() {
                        check_file_extension(
                            &sub_entry.path(),
                            &mut has_plist,
                            &mut has_yaml,
                            &mut has_ultra,
                        );
                    }
                }
            } else {
                check_file_extension(&path, &mut has_plist, &mut has_yaml, &mut has_ultra);
            }
        }
    }

    if has_ultra {
        Ok(SchemaFormat::UltraCompact)
    } else if has_plist {
        Ok(SchemaFormat::ProfileManifests)
    } else if has_yaml {
        Ok(SchemaFormat::AppleYaml)
    } else {
        // Default to ultra-compact
        Ok(SchemaFormat::UltraCompact)
    }
}

/// Helper to check file extension
fn check_file_extension(
    path: &Path,
    has_plist: &mut bool,
    has_yaml: &mut bool,
    has_ultra: &mut bool,
) {
    let ext = path.extension().and_then(|s| s.to_str());
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

    match ext {
        Some("plist") => *has_plist = true,
        Some("yaml" | "yml") => *has_yaml = true,
        Some("txt") if name.ends_with(".ultra.txt") => *has_ultra = true,
        _ => {}
    }
}

/// Load ultra-compact format from directory
fn load_ultra_compact_directory(dir: &Path) -> Result<Vec<PayloadManifest>> {
    let mut all_manifests = Vec::new();

    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("txt")
            && path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.ends_with(".ultra.txt"))
        {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read: {}", path.display()))?;

            let manifests = parse_ultra_compact(&content)
                .with_context(|| format!("Failed to parse: {}", path.display()))?;

            all_manifests.extend(manifests);
        }
    }

    Ok(all_manifests)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ========== Embedded Manifests Tests ==========

    #[test]
    fn test_load_embedded() {
        let manifests = load_embedded().expect("Failed to load embedded manifests");

        // ProfileCreator (~200) + Apple MDM profiles (~260) + DDM declarations (~42)
        // + supplemental prefs, minus overlaps
        assert!(
            manifests.len() >= 300,
            "Expected 300+ manifests (ProfileCreator + Apple native), got {}",
            manifests.len()
        );

        // Verify we can find specific known manifests
        let wifi = manifests
            .iter()
            .find(|m| m.payload_type == "com.apple.wifi.managed");
        assert!(wifi.is_some(), "Should have WiFi manifest");

        // Verify FileVault exists
        let filevault = manifests
            .iter()
            .find(|m| m.payload_type == "com.apple.MCX.FileVault2");
        assert!(filevault.is_some(), "Should have FileVault manifest");

        // Verify Apple-native MDM profiles are present (not just ProfileCreator)
        let screensaver = manifests
            .iter()
            .find(|m| m.payload_type == "com.apple.screensaver");
        assert!(
            screensaver.is_some(),
            "Should have Apple-native screensaver manifest"
        );

        // Verify DDM declarations are present
        let passcode_ddm = manifests
            .iter()
            .find(|m| m.payload_type == "com.apple.configuration.passcode.settings");
        assert!(
            passcode_ddm.is_some(),
            "Should have DDM passcode declaration"
        );
    }

    #[test]
    fn test_manifest_has_fields() {
        let manifests = load_embedded().unwrap();

        // Find WiFi manifest and verify it has expected fields
        let wifi = manifests
            .iter()
            .find(|m| m.payload_type == "com.apple.wifi.managed")
            .expect("WiFi manifest not found");

        assert!(!wifi.fields.is_empty(), "WiFi manifest should have fields");

        // Should have SSID_STR field
        assert!(
            wifi.fields.contains_key("SSID_STR") || wifi.fields.contains_key("SSID"),
            "WiFi should have SSID field"
        );
    }

    #[test]
    fn test_embedded_manifests_have_categories() {
        let manifests = load_embedded().unwrap();

        let has_apple = manifests.iter().any(|m| m.category == "apple");
        let has_apps = manifests.iter().any(|m| m.category == "apps");
        let has_prefs = manifests.iter().any(|m| m.category == "prefs");

        assert!(has_apple, "Should have apple category manifests");
        assert!(has_apps, "Should have apps category manifests");
        assert!(has_prefs, "Should have prefs category manifests");
    }

    // ========== Schema Format Tests ==========

    #[test]
    fn test_schema_format_equality() {
        assert_eq!(SchemaFormat::UltraCompact, SchemaFormat::UltraCompact);
        assert_eq!(
            SchemaFormat::ProfileManifests,
            SchemaFormat::ProfileManifests
        );
        assert_eq!(SchemaFormat::AppleYaml, SchemaFormat::AppleYaml);
        assert_ne!(SchemaFormat::UltraCompact, SchemaFormat::ProfileManifests);
    }

    // ========== Directory Format Detection Tests ==========

    #[test]
    fn test_detect_format_ultra_compact() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.ultra.txt");
        fs::write(&file_path, "# Ultra compact").unwrap();

        let format = detect_directory_format(temp_dir.path()).unwrap();
        assert_eq!(format, SchemaFormat::UltraCompact);
    }

    #[test]
    fn test_detect_format_profile_manifests_apple() {
        let temp_dir = TempDir::new().unwrap();
        let manifests_dir = temp_dir.path().join("ManifestsApple");
        fs::create_dir(&manifests_dir).unwrap();

        let format = detect_directory_format(temp_dir.path()).unwrap();
        assert_eq!(format, SchemaFormat::ProfileManifests);
    }

    #[test]
    fn test_detect_format_profile_manifests_prefs_apple() {
        let temp_dir = TempDir::new().unwrap();
        let prefs_dir = temp_dir.path().join("ManagedPreferencesApple");
        fs::create_dir(&prefs_dir).unwrap();

        let format = detect_directory_format(temp_dir.path()).unwrap();
        assert_eq!(format, SchemaFormat::ProfileManifests);
    }

    #[test]
    fn test_detect_format_profile_manifests_prefs_apps() {
        let temp_dir = TempDir::new().unwrap();
        let prefs_dir = temp_dir.path().join("ManagedPreferencesApplications");
        fs::create_dir(&prefs_dir).unwrap();

        let format = detect_directory_format(temp_dir.path()).unwrap();
        assert_eq!(format, SchemaFormat::ProfileManifests);
    }

    #[test]
    fn test_detect_format_profile_manifests_root() {
        let temp_dir = TempDir::new().unwrap();
        let manifests_dir = temp_dir.path().join("Manifests");
        fs::create_dir(&manifests_dir).unwrap();

        let format = detect_directory_format(temp_dir.path()).unwrap();
        assert_eq!(format, SchemaFormat::ProfileManifests);
    }

    #[test]
    fn test_detect_format_apple_yaml_mdm_profiles() {
        let temp_dir = TempDir::new().unwrap();
        let mdm_dir = temp_dir.path().join("mdm");
        let profiles_dir = mdm_dir.join("profiles");
        fs::create_dir_all(&profiles_dir).unwrap();

        let format = detect_directory_format(temp_dir.path()).unwrap();
        assert_eq!(format, SchemaFormat::AppleYaml);
    }

    #[test]
    fn test_detect_format_apple_yaml_profiles_with_yaml_files() {
        let temp_dir = TempDir::new().unwrap();
        let profiles_dir = temp_dir.path().join("profiles");
        fs::create_dir(&profiles_dir).unwrap();
        fs::write(profiles_dir.join("test.yaml"), "title: Test").unwrap();

        let format = detect_directory_format(temp_dir.path()).unwrap();
        assert_eq!(format, SchemaFormat::AppleYaml);
    }

    #[test]
    fn test_detect_format_plist_files() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("test.plist"), "<?xml").unwrap();

        let format = detect_directory_format(temp_dir.path()).unwrap();
        assert_eq!(format, SchemaFormat::ProfileManifests);
    }

    #[test]
    fn test_detect_format_yaml_files() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("test.yml"), "title: Test").unwrap();

        let format = detect_directory_format(temp_dir.path()).unwrap();
        assert_eq!(format, SchemaFormat::AppleYaml);
    }

    #[test]
    fn test_detect_format_empty_directory_defaults_to_ultra() {
        let temp_dir = TempDir::new().unwrap();

        let format = detect_directory_format(temp_dir.path()).unwrap();
        assert_eq!(format, SchemaFormat::UltraCompact);
    }

    // ========== Ultra Compact Loading Tests ==========

    #[test]
    fn test_load_ultra_compact_directory() {
        let temp_dir = TempDir::new().unwrap();

        let content = r"
M|com.test.one|Test One|Description|m||prefs
K|Field1|s|-|Field|Description||||

M|com.test.two|Test Two|Description|i||prefs
K|Field2|b|-|Field|Description||||
";
        fs::write(temp_dir.path().join("test.ultra.txt"), content).unwrap();

        let manifests = load_ultra_compact_directory(temp_dir.path()).unwrap();
        assert_eq!(manifests.len(), 2);
    }

    #[test]
    fn test_load_ultra_compact_directory_multiple_files() {
        let temp_dir = TempDir::new().unwrap();

        let content1 = "M|com.test.file1|File 1|Description|m||prefs\n";
        let content2 = "M|com.test.file2|File 2|Description|m||prefs\n";

        fs::write(temp_dir.path().join("file1.ultra.txt"), content1).unwrap();
        fs::write(temp_dir.path().join("file2.ultra.txt"), content2).unwrap();
        fs::write(temp_dir.path().join("other.txt"), "ignored").unwrap(); // Should be ignored

        let manifests = load_ultra_compact_directory(temp_dir.path()).unwrap();
        assert_eq!(manifests.len(), 2);
    }

    #[test]
    fn test_load_ultra_compact_directory_empty() {
        let temp_dir = TempDir::new().unwrap();

        let manifests = load_ultra_compact_directory(temp_dir.path()).unwrap();
        assert!(manifests.is_empty());
    }

    // ========== Check File Extension Tests ==========

    #[test]
    fn test_check_file_extension_plist() {
        let mut has_plist = false;
        let mut has_yaml = false;
        let mut has_ultra = false;

        check_file_extension(
            Path::new("test.plist"),
            &mut has_plist,
            &mut has_yaml,
            &mut has_ultra,
        );

        assert!(has_plist);
        assert!(!has_yaml);
        assert!(!has_ultra);
    }

    #[test]
    fn test_check_file_extension_yaml() {
        let mut has_plist = false;
        let mut has_yaml = false;
        let mut has_ultra = false;

        check_file_extension(
            Path::new("test.yaml"),
            &mut has_plist,
            &mut has_yaml,
            &mut has_ultra,
        );

        assert!(!has_plist);
        assert!(has_yaml);
        assert!(!has_ultra);
    }

    #[test]
    fn test_check_file_extension_yml() {
        let mut has_plist = false;
        let mut has_yaml = false;
        let mut has_ultra = false;

        check_file_extension(
            Path::new("test.yml"),
            &mut has_plist,
            &mut has_yaml,
            &mut has_ultra,
        );

        assert!(!has_plist);
        assert!(has_yaml);
        assert!(!has_ultra);
    }

    #[test]
    fn test_check_file_extension_ultra() {
        let mut has_plist = false;
        let mut has_yaml = false;
        let mut has_ultra = false;

        check_file_extension(
            Path::new("test.ultra.txt"),
            &mut has_plist,
            &mut has_yaml,
            &mut has_ultra,
        );

        assert!(!has_plist);
        assert!(!has_yaml);
        assert!(has_ultra);
    }

    #[test]
    fn test_check_file_extension_regular_txt_not_ultra() {
        let mut has_plist = false;
        let mut has_yaml = false;
        let mut has_ultra = false;

        check_file_extension(
            Path::new("test.txt"),
            &mut has_plist,
            &mut has_yaml,
            &mut has_ultra,
        );

        assert!(!has_plist);
        assert!(!has_yaml);
        assert!(!has_ultra);
    }

    #[test]
    fn test_check_file_extension_unknown() {
        let mut has_plist = false;
        let mut has_yaml = false;
        let mut has_ultra = false;

        check_file_extension(
            Path::new("test.json"),
            &mut has_plist,
            &mut has_yaml,
            &mut has_ultra,
        );

        assert!(!has_plist);
        assert!(!has_yaml);
        assert!(!has_ultra);
    }
}
