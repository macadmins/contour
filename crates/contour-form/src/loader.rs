use anyhow::{Context, Result};
use std::collections::HashMap;
#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use super::parser::parse_ultra_compact;
#[cfg(feature = "native")]
use super::plist_parser;
use super::types::{
    FieldDefinition, FieldFlags, FieldType, OsSupportDetail, PayloadManifest, Platform, Platforms,
};
#[cfg(feature = "native")]
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
    load_embedded_from(mdm_schema::embedded_capabilities())
}

/// Load embedded manifests using the **beta seed** capabilities dataset.
///
/// Identical to [`load_embedded`] but sources Apple capabilities from
/// `embedded_capabilities_beta`, so pre-release (seed) declarations and keys —
/// e.g. `com.apple.configuration.app.settings` and `package`'s
/// `UninstallBehavior` — appear in the registry. ProfileCreator manifests and
/// supplemental prefs are shared with the stable path.
pub fn load_embedded_beta() -> Result<Vec<PayloadManifest>> {
    load_embedded_from(mdm_schema::embedded_capabilities_beta())
}

/// Load the embedded **Windows CSP** dataset as manifests.
///
/// Standalone by design — Windows CSP nodes (kinds `CspSetting`/`AdmxPolicy`,
/// categories `windows-csp`/`windows-admx`) are never merged into the Apple
/// registry; `--windows` on `profile search`/`info` opts into this set.
/// No ProfileCreator overlay applies.
pub fn load_embedded_windows() -> Result<Vec<PayloadManifest>> {
    let capabilities = mdm_schema::capabilities::read(mdm_schema::embedded_windows_capabilities())
        .context("Failed to read embedded Windows capabilities from Parquet")?;
    Ok(capabilities.iter().map(capability_to_manifest).collect())
}

/// Shared body for [`load_embedded`] / [`load_embedded_beta`].
fn load_embedded_from(capabilities_bytes: &[u8]) -> Result<Vec<PayloadManifest>> {
    load_from_parquet(capabilities_bytes)
}

/// Build manifests from `capabilities.parquet` as bytes — the entry point
/// for a host that ships the dataset as a separate asset instead of baking
/// it into the binary (the wasm module does; refreshing the schema then
/// needs no rebuild).
///
/// Third-party domains are App Schema documents built from their vendors'
/// own sources, which arrive in `capabilities.parquet` like everything
/// else.
pub fn load_from_parquet(capabilities_bytes: &[u8]) -> Result<Vec<PayloadManifest>> {
    let mut manifests: Vec<PayloadManifest> = Vec::new();

    // Append Apple's native schemas from capabilities.parquet.
    // MDM profiles override ProfileCreator where both exist (Apple is authoritative).
    // DDM declarations are added alongside (no overlap with ProfileCreator).
    let capabilities = mdm_schema::capabilities::read(capabilities_bytes)
        .context("Failed to read embedded capabilities from Parquet")?;

    // Collect existing payload_types so we can merge, not duplicate
    let mut existing_types: std::collections::HashSet<String> =
        manifests.iter().map(|m| m.payload_type.clone()).collect();

    // MDM profiles from Apple's device-management repo (authoritative)
    // Preference domains ride along with profiles here: before the
    // ManagedPreference kind existed they were read as MdmProfile, and
    // this is the branch that merged them.
    for cap in capabilities.iter().filter(|c| {
        matches!(
            c.kind,
            mdm_schema::PayloadKind::MdmProfile | mdm_schema::PayloadKind::ManagedPreference
        )
    }) {
        if existing_types.contains(&cap.payload_type) {
            // Merge Apple keys into existing ProfileCreator manifest.
            // Apple keys take precedence where both define the same key,
            // but ProfileCreator-only keys (legacy) are preserved.
            if let Some(existing) = manifests
                .iter_mut()
                .find(|m| m.payload_type == cap.payload_type)
            {
                let apple = capability_to_manifest(cap);
                // What arrives here is a second VARIANT of one payload type: com.apple.extensiblesso and its (kerberos) surface,
                // or the six com.apple.MCX files. A variant's requirements
                // hold for that variant alone — Realm and TeamIdentifier are
                // required of the Kerberos extension, not of every SSO
                // extension — and one manifest cannot say which variant a
                // payload is. So a merged key stays required only where every
                // variant that shares the type requires it; letting the last
                // variant win would reject every Okta and Entra SSO profile.
                for (key, field) in existing.fields.iter_mut() {
                    if !apple.fields.contains_key(key) {
                        field.flags.required = false;
                    }
                }
                for (key, mut field) in apple.fields {
                    match existing.fields.get(&key) {
                        Some(prior) => field.flags.required &= prior.flags.required,
                        None => field.flags.required = false,
                    }
                    existing.fields.insert(key.clone(), field);
                    if !existing.field_order.contains(&key) {
                        existing.field_order.push(key);
                    }
                }
                existing.platforms = apple.platforms;
                // Apple contributed these paths, so they — and only they —
                // have a source that records availability.
                existing.fields_recording_availability = apple.fields_recording_availability;
                // Apple is authoritative for per-OS metadata too —
                // ProfileCreator never carried `os_support`, so this
                // doesn't lose any pre-existing data.
                existing.os_support = apple.os_support;
                // Apple's apply_mode wins when present; otherwise keep
                // the ProfileCreator value already on `existing`.
                if apple.apply_mode.is_some() {
                    existing.apply_mode = apple.apply_mode;
                }
                if existing.min_versions.is_empty() {
                    existing.min_versions = apple.min_versions;
                }
                if !apple.description.is_empty() {
                    existing.description = apple.description;
                }
            }
        } else {
            existing_types.insert(cap.payload_type.clone());
            manifests.push(capability_to_manifest(cap));
        }
    }

    // DDM declarations — always add/override (ProfileCreator may have stale entries)
    for cap in capabilities
        .iter()
        .filter(|c| c.kind == mdm_schema::PayloadKind::DdmDeclaration)
    {
        if existing_types.contains(&cap.payload_type) {
            // Override existing ProfileCreator entry with Apple's DDM schema
            if let Some(existing) = manifests
                .iter_mut()
                .find(|m| m.payload_type == cap.payload_type)
            {
                let apple = capability_to_manifest(cap);
                existing.fields = apple.fields;
                existing.field_order = apple.field_order;
                existing.platforms = apple.platforms;
                // Apple is authoritative for per-OS metadata, exactly as in
                // the non-DDM branch above. Without this a DDM type that also
                // had a ProfileCreator entry kept the backfilled os_support,
                // whose `allowed_scopes` is None by construction — so every
                // DDM declaration read as having no scope restriction at all,
                // including the 13 macOS user-only payloads.
                existing.os_support = apple.os_support;
                existing.fields_recording_availability = apple.fields_recording_availability;
                if existing.min_versions.is_empty() {
                    existing.min_versions = apple.min_versions;
                }
                existing.category = apple.category; // ensure ddm-* category
                if !apple.description.is_empty() {
                    existing.description = apple.description;
                }
            }
        } else {
            existing_types.insert(cap.payload_type.clone());
            manifests.push(capability_to_manifest(cap));
        }
    }

    // Everything else Apple describes: commands, check-ins, and the shared
    // structures from `other/`.
    //
    // These are not authorable — `PayloadKind::not_authorable_reason` refuses
    // them by kind — but they have to be IN the registry for that refusal to
    // happen. Absent, they are "unknown payload type", which is what invites
    // an agent to invent keys for them.
    for cap in capabilities.iter().filter(|c| {
        matches!(
            c.kind,
            mdm_schema::PayloadKind::MdmCommand
                | mdm_schema::PayloadKind::MdmCheckin
                | mdm_schema::PayloadKind::SharedStructure
        )
    }) {
        if existing_types.insert(cap.payload_type.clone()) {
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
            // Flat: the name is the path.
            field_order.push(name.to_string());
            fields.insert(
                name.to_string(),
                FieldDefinition {
                    name: name.to_string(),
                    // Supplemental prefs are flat: the name is the path.
                    path: name.to_string(),
                    field_type: ft.clone(),
                    flags: FieldFlags::default(),
                    title: name.to_string(),
                    description: fdesc.to_string(),
                    default: None,
                    allowed_values: Vec::new(),
                    range_min: None,
                    range_max: None,
                    subtype: None,
                    format: None,
                    asset_types: Vec::new(),
                    allowed_scopes: std::collections::HashMap::new(),
                    depth: 0,
                    parent_key: None,
                    platforms: vec![Platform::MacOS],
                    min_version: None,
                    deprecated_in: None,
                    introduced_by_platform: HashMap::new(),
                    deprecated_by_platform: HashMap::new(),
                    removed_by_platform: HashMap::new(),
                    combinetype: None,
                },
            );
        }
        PayloadManifest {
            // A local directory states no provenance.
            manifest_source: None,
            // Synthesized from a preferences domain; nothing states
            // availability.
            fields_recording_availability: Default::default(),
            payload_type: payload_type.to_string(),
            // A preference domain, as its category says. Left None, these
            // were the only authorable schemas with no kind, and anything
            // filtering by kind — `profile search --json`, an agent — skipped
            // them.
            kind: Some(mdm_schema::PayloadKind::ManagedPreference),
            title: title.to_string(),
            description: desc.to_string(),
            platforms: Platforms {
                macos: true,
                ..Default::default()
            },
            min_versions: HashMap::new(),
            os_support: HashMap::new(),
            apply_mode: None,
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

/// Translate mdm_schema's per-platform map to contour's `Platform` enum.
/// Both enums are 5-variant; this is a 1:1 isomorphism.
/// The same platform mapping for a map whose values are scope arrays.
fn convert_platform_scopes(
    src: &std::collections::HashMap<mdm_schema::Platform, Vec<String>>,
) -> std::collections::HashMap<Platform, Vec<String>> {
    src.iter()
        .map(|(p, v)| (map_platform(*p), v.clone()))
        .collect()
}

fn map_platform(p: mdm_schema::Platform) -> Platform {
    match p {
        mdm_schema::Platform::MacOS => Platform::MacOS,
        mdm_schema::Platform::IOS => Platform::Ios,
        mdm_schema::Platform::TvOS => Platform::TvOS,
        mdm_schema::Platform::WatchOS => Platform::WatchOS,
        mdm_schema::Platform::VisionOS => Platform::VisionOS,
        mdm_schema::Platform::Windows => Platform::Windows,
    }
}

fn convert_platform_map(
    src: &std::collections::HashMap<mdm_schema::Platform, String>,
) -> std::collections::HashMap<Platform, String> {
    src.iter()
        .map(|(p, v)| {
            let mapped = match p {
                mdm_schema::Platform::MacOS => Platform::MacOS,
                mdm_schema::Platform::IOS => Platform::Ios,
                mdm_schema::Platform::TvOS => Platform::TvOS,
                mdm_schema::Platform::WatchOS => Platform::WatchOS,
                mdm_schema::Platform::VisionOS => Platform::VisionOS,
                mdm_schema::Platform::Windows => Platform::Windows,
            };
            (mapped, v.clone())
        })
        .collect()
}

/// Convert an Apple `Capability` (MDM profile or DDM declaration) to a contour `PayloadManifest`.
fn capability_to_manifest(cap: &mdm_schema::Capability) -> PayloadManifest {
    let mut fields = std::collections::HashMap::new();
    let mut field_order = Vec::new();

    for key in &cap.keys {
        // Deduplicate across platforms but include all depths.
        //
        // Keyed on the PATH, not the leaf name. A leaf name is not unique
        // within a payload: account.mail carries Port under both
        // IncomingServer and OutgoingServer, and keying on the name dropped
        // 61 keys across 14 declaration types -- OutgoingServer.HostName and
        // .Port did not appear in output at all.
        let key_path = key
            .key_path
            .clone()
            .unwrap_or_else(|| FieldDefinition::compose_path(key.parent_key.as_deref(), &key.name));
        if fields.contains_key(&key_path) {
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
            // Identity. Prefer the schema's own key_path: it escapes dots
            // inside a segment, and Apple ships key names containing dots
            // (com.apple.EnergySaver.desktop.ACPower is one key). Composing
            // from parent_key cannot express that, so it is the fallback for
            // datasets predating the column.
            path: key.key_path.clone().unwrap_or_else(|| {
                FieldDefinition::compose_path(key.parent_key.as_deref(), &key.name)
            }),
            field_type,
            flags: FieldFlags {
                required: key.presence == "required",
                // Supervised-gated if the key's own supportedOS marks it
                // supervised on any platform it supports.
                supervised: key.supervised.values().any(|&s| s),
                sensitive: false,
            },
            title: key.key_title.clone().unwrap_or_default(),
            description: key.key_description.clone().unwrap_or_default(),
            // Unwrap a JSON string default to its raw text — `Value::to_string()`
            // JSON-encodes it (`"Flurry"` -> `"\"Flurry\""`), baking embedded
            // quotes into the rendered plist. Non-string scalars keep their
            // faithful text form.
            default: key.default_value.as_ref().map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            }),
            allowed_values: key.range_list.clone().unwrap_or_default(),
            // Present in the schema and previously dropped here: the emitter
            // could not show a bound, a validator hint or an asset picker
            // because FieldDefinition had nowhere to put them.
            range_min: key.range_min,
            range_max: key.range_max,
            subtype: key.subtype.clone(),
            format: key.format.clone(),
            asset_types: key.asset_types.clone().unwrap_or_default(),
            allowed_scopes: convert_platform_scopes(&key.allowed_scopes),
            depth: key.depth as u8,
            parent_key: key.parent_key.clone(),
            // Empty = inherits the payload. Non-empty only when Apple
            // excluded the key somewhere (`introduced: n/a`): the payload's
            // platforms minus those, so `Allowed.DeniedApps` (`macOS: n/a`)
            // lists every platform of app.settings except macOS.
            platforms: {
                let excluded = key.unavailable_on();
                if excluded.is_empty() {
                    Vec::new()
                } else {
                    cap.supported_os
                        .iter()
                        .map(|o| o.platform)
                        .filter(|p| !excluded.contains(p))
                        .map(|p| match p {
                            mdm_schema::Platform::MacOS => Platform::MacOS,
                            mdm_schema::Platform::IOS => Platform::Ios,
                            mdm_schema::Platform::TvOS => Platform::TvOS,
                            mdm_schema::Platform::WatchOS => Platform::WatchOS,
                            mdm_schema::Platform::VisionOS => Platform::VisionOS,
                            mdm_schema::Platform::Windows => Platform::Windows,
                        })
                        .collect()
                }
            },
            // Single-value summaries: lexicographic min across the
            // per-platform map. Backwards-compat for callers that don't
            // care which OS the value came from.
            min_version: key.earliest_introduced(),
            deprecated_in: key.deprecated.values().min().cloned(),
            // Versions only: Apple's `n/a` is an exclusion, carried in
            // `platforms` above, not a version a consumer could compare.
            introduced_by_platform: convert_platform_map(
                &key.introduced
                    .iter()
                    .filter(|(_, v)| !mdm_schema::PayloadKey::is_unavailable_marker(v))
                    .map(|(p, v)| (*p, v.clone()))
                    .collect(),
            ),
            deprecated_by_platform: convert_platform_map(&key.deprecated),
            removed_by_platform: convert_platform_map(&key.removed),
            combinetype: key.combinetype.clone(),
        };
        field_order.push(key_path.clone());
        fields.insert(key_path, fd);
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
            mdm_schema::Platform::Windows => platforms.windows = true,
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
        mdm_schema::PayloadKind::CspSetting => "windows-csp".to_string(),
        mdm_schema::PayloadKind::AdmxPolicy => "windows-admx".to_string(),
        mdm_schema::PayloadKind::ManagedPreference => "apps".to_string(),
        mdm_schema::PayloadKind::MdmCommand | mdm_schema::PayloadKind::MdmCheckin => {
            "apple".to_string()
        }
        // Apple's `other/` shapes: catalogued, never authorable.
        mdm_schema::PayloadKind::SharedStructure => "apple-shared".to_string(),
    };

    // Derive min_versions from the earliest `introduced` per platform,
    // and build the rich per-OS support map used by `info --os <NAME>`
    // and downstream agents.
    let mut min_versions = std::collections::HashMap::new();
    let mut os_support = std::collections::HashMap::new();
    for os in &cap.supported_os {
        let platform = match os.platform {
            mdm_schema::Platform::MacOS => Platform::MacOS,
            mdm_schema::Platform::IOS => Platform::Ios,
            mdm_schema::Platform::TvOS => Platform::TvOS,
            mdm_schema::Platform::WatchOS => Platform::WatchOS,
            mdm_schema::Platform::VisionOS => Platform::VisionOS,
            mdm_schema::Platform::Windows => Platform::Windows,
        };
        if let Some(ref v) = os.introduced {
            min_versions.entry(platform).or_insert_with(|| v.clone());
        }
        os_support.insert(
            platform,
            OsSupportDetail {
                introduced: os.introduced.clone(),
                deprecated: os.deprecated.clone(),
                removed: os.removed.clone(),
                allowed_enrollments: os.allowed_enrollments.clone(),
                allowed_scopes: os.allowed_scopes.clone(),
                supervised: os.supervised,
                requires_dep: os.requires_dep,
                user_approved_mdm: os.user_approved_mdm,
                allow_manual_install: os.allow_manual_install,
                device_channel: os.device_channel,
                user_channel: os.user_channel,
                multiple: os.multiple,
                beta: os.beta,
                shared_ipad_mode: os.shared_ipad_mode.clone(),
                user_enrollment_mode: os.user_enrollment_mode.clone(),
            },
        );
    }

    // Apple's schema states introduced/deprecated/removed; the community
    // manifests state nothing, and both arrive here as the same nulls.
    // Only the source tells them apart.
    let records_availability = match cap.manifest_source.as_deref() {
        Some("device-management") | Some("both") => true,
        Some(_) => false,
        // Datasets predating the column: Apple is the source for
        // everything except ManagedPreference.
        None => cap.kind != mdm_schema::PayloadKind::ManagedPreference,
    };

    PayloadManifest {
        manifest_source: cap.manifest_source.clone(),
        // Apple's schema states introduced/deprecated/removed; the
        // community manifests state nothing, and both arrive here as the
        // same nulls. Only the source tells them apart.
        fields_recording_availability: if records_availability {
            fields.keys().cloned().collect()
        } else {
            Default::default()
        },
        payload_type: cap.payload_type.clone(),
        kind: Some(cap.kind),
        title: cap.title.clone(),
        description: cap.description.clone(),
        platforms,
        min_versions,
        os_support,
        apply_mode: cap.apply_mode.map(|m| m.as_str().to_string()),
        category,
        fields,
        field_order,
        segments: vec![],
    }
}

/// Load manifests from an external directory, auto-detecting format
#[cfg(feature = "native")]
pub fn load_from_directory(dir: &Path) -> Result<Vec<PayloadManifest>> {
    let format = detect_directory_format(dir)?;
    load_from_directory_with_format(dir, format)
}

/// Load manifests from directory with explicit format
#[cfg(feature = "native")]
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
#[cfg(feature = "native")]
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
#[cfg(feature = "native")]
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
#[cfg(feature = "native")]
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

    /// Every authorable schema states what it is.
    #[test]
    fn every_authorable_manifest_has_a_kind() {
        let manifests = load_embedded().expect("load embedded manifests");
        let kindless: Vec<&str> = manifests
            .iter()
            .filter(|m| m.is_authorable() && m.kind.is_none())
            .map(|m| m.payload_type.as_str())
            .collect();
        assert!(kindless.is_empty(), "authorable with no kind: {kindless:?}");
    }

    /// The Support App declares StatusBarIconAllowsColor `Bool`
    /// (root3nl/SupportApp@5f9cae1, Preferences.swift:86). A debug log line
    /// reads it through `defaults.string(forKey:)`, which must not decide its
    /// type — or every profile the support tool writes fails validation.
    #[test]
    fn the_support_app_colour_flag_is_a_boolean() {
        let manifests = load_embedded().expect("load embedded manifests");
        let support = manifests
            .iter()
            .find(|m| m.payload_type == "nl.root3.support")
            .expect("nl.root3.support is described");
        let field = support
            .fields
            .get("StatusBarIconAllowsColor")
            .expect("StatusBarIconAllowsColor is described");
        assert_eq!(field.field_type, FieldType::Boolean);
    }

    /// Apple ships com.apple.extensiblesso twice: the base schema and the
    /// `(kerberos)` variant, which alone requires Realm and TeamIdentifier.
    /// Merging them let the variant's requirements apply to every SSO
    /// payload, so each Okta and Entra redirect profile failed validation.
    #[test]
    fn a_variant_does_not_impose_its_requirements_on_the_base_type() {
        let manifests = load_embedded().expect("load embedded manifests");
        let sso = manifests
            .iter()
            .find(|m| m.payload_type == "com.apple.extensiblesso")
            .expect("extensiblesso is described");
        let required = |k: &str| sso.fields.get(k).map(|f| f.flags.required);

        // Required by both variants: still required.
        assert_eq!(required("ExtensionIdentifier"), Some(true));
        assert_eq!(required("Type"), Some(true));
        // Required by (kerberos) only: known, but not required of every SSO payload.
        assert_eq!(required("Realm"), Some(false));
        assert_eq!(required("TeamIdentifier"), Some(false));
        // And it is one field, not one per variant.
        assert_eq!(sso.field_order.iter().filter(|k| *k == "Realm").count(), 1);
    }

    #[test]
    fn test_load_embedded() {
        let manifests = load_embedded().expect("Failed to load embedded manifests");

        // Apple's profiles and declarations, the non-authorable kinds
        // (commands, check-ins, shared structures), the App Schema documents
        // and the supplemental preference domains. A smoke threshold, not a
        // census — `contour census` reports the real figures.
        assert!(
            manifests.len() >= 250,
            "Expected 250+ manifests, got {}",
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
    fn test_load_embedded_beta_is_superset_of_stable() {
        // The beta registry is a superset of stable for every OS. It strictly
        // exceeded it whenever a seed was pinned (historically app.settings and
        // package.UninstallBehavior for OS 27) — that half is suspended while
        // beta is mapped to stable; see the assertion below.
        use std::collections::BTreeSet;
        let stable: BTreeSet<String> = load_embedded()
            .expect("stable manifests")
            .into_iter()
            .map(|m| m.payload_type)
            .collect();
        let beta: BTreeSet<String> = load_embedded_beta()
            .expect("beta manifests")
            .into_iter()
            .map(|m| m.payload_type)
            .collect();
        assert!(
            beta.is_superset(&stable),
            "beta registry must be a superset of stable; missing from beta: {:?}",
            stable.difference(&beta).collect::<Vec<_>>()
        );

        // The strict-growth half of this invariant is suspended while the beta
        // channel is mapped to stable (see the banner on mdm-schema's
        // `*_beta` accessors).
        // Equality is now the correct expectation, and asserting it keeps the
        // test honest instead of vacuous: if someone re-points the accessors
        // at seed data without restoring the growth assertion below, this
        // fails and says so.
        assert_eq!(
            beta, stable,
            "while beta is mapped to stable the two registries must be identical; \
             if the beta build is back, restore the pinned-seed growth assertion"
        );
    }

    #[test]
    fn test_capability_key_os_support_is_per_key_not_payload_level() {
        // Regression: per-key `introduced` / `supervised` must come from the
        // key's own `supportedOS`, not the payload's. Verified against
        // apple/device-management `com.apple.applicationaccess.yaml`:
        // `allowListedAppBundleIDs` is iOS 15.0 (supervised), tvOS 15.0
        // (supervised), and n/a on macOS / watchOS / visionOS.
        let manifests = load_embedded().expect("Failed to load embedded manifests");
        let aa = manifests
            .iter()
            .find(|m| m.payload_type == "com.apple.applicationaccess")
            .expect("applicationaccess manifest");
        let f = aa
            .fields
            .get("allowListedAppBundleIDs")
            .expect("allowListedAppBundleIDs field");

        assert_eq!(
            f.introduced_by_platform
                .get(&Platform::Ios)
                .map(String::as_str),
            Some("15.0"),
            "iOS introduced must be the key's own 15.0, not the payload's 4.0"
        );
        assert_eq!(
            f.introduced_by_platform
                .get(&Platform::TvOS)
                .map(String::as_str),
            Some("15.0"),
        );
        assert!(
            !f.introduced_by_platform.contains_key(&Platform::MacOS),
            "macOS is n/a for this key — it must not inherit the payload's 10.7"
        );
        assert!(
            !f.introduced_by_platform.contains_key(&Platform::WatchOS),
            "watchOS is n/a for this key"
        );
        assert!(
            f.flags.supervised,
            "allowListedAppBundleIDs is supervised-only — must not report false"
        );

        // Deprecated alias: per-key `deprecated` must surface too.
        let w = aa
            .fields
            .get("whitelistedAppBundleIDs")
            .expect("whitelistedAppBundleIDs field");
        assert_eq!(
            w.deprecated_in.as_deref(),
            Some("15.0"),
            "whitelistedAppBundleIDs was deprecated in iOS/tvOS 15.0"
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
