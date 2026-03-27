//! PPPC (Privacy Preferences Policy Control) profile types and utilities.
//!
//! Provides models for TCC/PPPC services and generating mobileconfig profiles
//! that grant privacy permissions to applications.

use anyhow::Result;
use clap::ValueEnum;
use contour_profiles::ProfileBuilder;
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// TCC/PPPC services that can be configured via MDM profiles.
///
/// These represent the common privacy permissions that macOS applications
/// may request access to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum, Serialize, Deserialize)]
pub enum PppcService {
    /// Full Disk Access (SystemPolicyAllFiles)
    #[value(name = "fda", alias = "full-disk-access")]
    #[serde(rename = "fda")]
    SystemPolicyAllFiles,

    /// Camera access
    #[value(name = "camera")]
    #[serde(rename = "camera")]
    Camera,

    /// Microphone access
    #[value(name = "microphone", alias = "mic")]
    #[serde(rename = "microphone")]
    Microphone,

    /// Screen recording/capture
    #[value(name = "screen-capture", alias = "screen")]
    #[serde(rename = "screen-capture")]
    ScreenCapture,

    /// Accessibility API access
    #[value(name = "accessibility")]
    #[serde(rename = "accessibility")]
    Accessibility,

    /// Contacts/Address Book access
    #[value(name = "contacts", alias = "addressbook")]
    #[serde(rename = "contacts")]
    AddressBook,

    /// Calendar access
    #[value(name = "calendar")]
    #[serde(rename = "calendar")]
    Calendar,

    /// Photos library access
    #[value(name = "photos")]
    #[serde(rename = "photos")]
    Photos,

    /// Documents folder access (SystemPolicyDocumentsFolder)
    #[value(name = "documents", alias = "docs")]
    #[serde(rename = "documents")]
    SystemPolicyDocumentsFolder,

    /// Desktop folder access (SystemPolicyDesktopFolder)
    #[value(name = "desktop")]
    #[serde(rename = "desktop")]
    SystemPolicyDesktopFolder,

    /// Downloads folder access (SystemPolicyDownloadsFolder)
    #[value(name = "downloads")]
    #[serde(rename = "downloads")]
    SystemPolicyDownloadsFolder,

    /// Network volumes access (SystemPolicyNetworkVolumes)
    #[value(name = "network-volumes")]
    #[serde(rename = "network-volumes")]
    SystemPolicyNetworkVolumes,

    /// Removable volumes access (SystemPolicyRemovableVolumes)
    #[value(name = "removable-volumes")]
    #[serde(rename = "removable-volumes")]
    SystemPolicyRemovableVolumes,

    /// System administration files (SystemPolicySysAdminFiles)
    #[value(name = "sysadmin-files")]
    #[serde(rename = "sysadmin-files")]
    SystemPolicySysAdminFiles,

    /// App management / update other apps (SystemPolicyAppBundles, macOS 13+)
    #[value(name = "app-management", alias = "app-bundles")]
    #[serde(rename = "app-management")]
    SystemPolicyAppBundles,

    /// Access other apps' data (SystemPolicyAppData, macOS 14+)
    #[value(name = "app-data")]
    #[serde(rename = "app-data")]
    SystemPolicyAppData,

    /// AppleEvents / Automation
    #[value(name = "apple-events", alias = "automation")]
    #[serde(rename = "apple-events")]
    AppleEvents,

    /// CoreGraphics event posting (PostEvent)
    #[value(name = "post-event")]
    #[serde(rename = "post-event")]
    PostEvent,

    /// CoreGraphics/HID event listening (ListenEvent, deny only)
    #[value(name = "listen-event")]
    #[serde(rename = "listen-event")]
    ListenEvent,

    /// Speech recognition
    #[value(name = "speech-recognition")]
    #[serde(rename = "speech-recognition")]
    SpeechRecognition,

    /// Apple Music / media library (MediaLibrary)
    #[value(name = "media-library")]
    #[serde(rename = "media-library")]
    MediaLibrary,

    /// File Provider user activity (FileProviderPresence)
    #[value(name = "file-provider")]
    #[serde(rename = "file-provider")]
    FileProviderPresence,

    /// Bluetooth device access (BluetoothAlways, macOS 11+)
    #[value(name = "bluetooth")]
    #[serde(rename = "bluetooth")]
    BluetoothAlways,

    /// Reminders access
    #[value(name = "reminders")]
    #[serde(rename = "reminders")]
    Reminders,
}

impl PppcService {
    /// Get the Apple TCC key for this service.
    ///
    /// This is the key used in the Services dictionary of a
    /// `com.apple.TCC.configuration-profile-policy` payload.
    pub fn key(&self) -> &'static str {
        match self {
            Self::SystemPolicyAllFiles => "SystemPolicyAllFiles",
            Self::Camera => "Camera",
            Self::Microphone => "Microphone",
            Self::ScreenCapture => "ScreenCapture",
            Self::Accessibility => "Accessibility",
            Self::AddressBook => "AddressBook",
            Self::Calendar => "Calendar",
            Self::Photos => "Photos",
            Self::SystemPolicyDocumentsFolder => "SystemPolicyDocumentsFolder",
            Self::SystemPolicyDesktopFolder => "SystemPolicyDesktopFolder",
            Self::SystemPolicyDownloadsFolder => "SystemPolicyDownloadsFolder",
            Self::SystemPolicyNetworkVolumes => "SystemPolicyNetworkVolumes",
            Self::SystemPolicyRemovableVolumes => "SystemPolicyRemovableVolumes",
            Self::SystemPolicySysAdminFiles => "SystemPolicySysAdminFiles",
            Self::SystemPolicyAppBundles => "SystemPolicyAppBundles",
            Self::SystemPolicyAppData => "SystemPolicyAppData",
            Self::AppleEvents => "AppleEvents",
            Self::PostEvent => "PostEvent",
            Self::ListenEvent => "ListenEvent",
            Self::SpeechRecognition => "SpeechRecognition",
            Self::MediaLibrary => "MediaLibrary",
            Self::FileProviderPresence => "FileProviderPresence",
            Self::BluetoothAlways => "BluetoothAlways",
            Self::Reminders => "Reminders",
        }
    }

    /// Human-readable display name for this service.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::SystemPolicyAllFiles => "Full Disk Access",
            Self::Camera => "Camera",
            Self::Microphone => "Microphone",
            Self::ScreenCapture => "Screen Recording",
            Self::Accessibility => "Accessibility",
            Self::AddressBook => "Contacts",
            Self::Calendar => "Calendar",
            Self::Photos => "Photos",
            Self::SystemPolicyDocumentsFolder => "Documents Folder",
            Self::SystemPolicyDesktopFolder => "Desktop Folder",
            Self::SystemPolicyDownloadsFolder => "Downloads Folder",
            Self::SystemPolicyNetworkVolumes => "Network Volumes",
            Self::SystemPolicyRemovableVolumes => "Removable Volumes",
            Self::SystemPolicySysAdminFiles => "SysAdmin Files",
            Self::SystemPolicyAppBundles => "App Management",
            Self::SystemPolicyAppData => "App Data Access",
            Self::AppleEvents => "Apple Events",
            Self::PostEvent => "Post Event",
            Self::ListenEvent => "Listen Event",
            Self::SpeechRecognition => "Speech Recognition",
            Self::MediaLibrary => "Media Library",
            Self::FileProviderPresence => "File Provider",
            Self::BluetoothAlways => "Bluetooth",
            Self::Reminders => "Reminders",
        }
    }

    /// Returns the correct TCC Authorization value per Apple's spec.
    ///
    /// - Camera, Microphone: deny-only (profile cannot grant access)
    /// - ScreenCapture, ListenEvent: standard-user-settable
    /// - All others: Allow
    pub fn authorization_default(&self) -> contour_profiles::TccAuthorization {
        use contour_profiles::TccAuthorization;
        match self {
            Self::Camera | Self::Microphone => TccAuthorization::Deny,
            Self::ScreenCapture | Self::ListenEvent => {
                TccAuthorization::AllowStandardUserToSetSystemService
            }
            _ => TccAuthorization::Allow,
        }
    }

    /// Returns true if this service is deny-only per Apple's TCC spec.
    ///
    /// Camera and Microphone access cannot be granted via profile;
    /// the profile can only deny access.
    pub fn is_deny_only(&self) -> bool {
        matches!(self, Self::Camera | Self::Microphone)
    }

    /// Returns true if this service supports standard-user toggling.
    ///
    /// ScreenCapture and ListenEvent can use
    /// `AllowStandardUserToSetSystemService` to let non-admin users
    /// toggle the permission.
    pub fn supports_standard_user_set(&self) -> bool {
        matches!(self, Self::ScreenCapture | Self::ListenEvent)
    }

    /// Get all available services.
    pub fn all() -> &'static [PppcService] {
        &[
            Self::SystemPolicyAllFiles,
            Self::SystemPolicyDocumentsFolder,
            Self::SystemPolicyDesktopFolder,
            Self::SystemPolicyDownloadsFolder,
            Self::SystemPolicyNetworkVolumes,
            Self::SystemPolicyRemovableVolumes,
            Self::SystemPolicySysAdminFiles,
            Self::SystemPolicyAppBundles,
            Self::SystemPolicyAppData,
            Self::Camera,
            Self::Microphone,
            Self::ScreenCapture,
            Self::Accessibility,
            Self::AddressBook,
            Self::Calendar,
            Self::Photos,
            Self::Reminders,
            Self::AppleEvents,
            Self::PostEvent,
            Self::ListenEvent,
            Self::SpeechRecognition,
            Self::MediaLibrary,
            Self::FileProviderPresence,
            Self::BluetoothAlways,
        ]
    }
}

impl std::fmt::Display for PppcService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Information about an application for PPPC profile generation.
#[derive(Debug, Clone)]
pub struct AppInfo {
    /// Application display name
    pub name: String,
    /// Bundle identifier (e.g., "com.apple.Safari") or binary path
    pub bundle_id: String,
    /// Code requirement string from codesign
    pub code_requirement: String,
    /// Identifier type: "bundleID" or "path"
    pub identifier_type: String,
    /// Path to the application bundle
    pub path: PathBuf,
}

/// A PPPC policy mapping an app to its required permissions.
#[derive(Debug, Clone)]
pub struct PppcPolicy {
    /// Application information
    pub app: AppInfo,
    /// Services to grant to this application
    pub services: Vec<PppcService>,
}

/// PPPC policy configuration file (pppc.toml).
///
/// This is the format used for the GitOps workflow where users can
/// scan apps to generate a .toml file, edit it, then generate profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PppcConfig {
    /// Configuration metadata
    pub config: PppcConfigMeta,
    /// Application entries
    #[serde(default)]
    pub apps: Vec<PppcAppEntry>,
}

/// Metadata for a PPPC configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PppcConfigMeta {
    /// Organization identifier (e.g., "com.example")
    pub org: String,
    /// Optional display name for the profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// An application entry in a PPPC configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PppcAppEntry {
    /// Application display name
    pub name: String,
    /// Bundle identifier (e.g., "com.apple.Safari") or binary path (e.g., "/usr/local/munki/managedsoftwareupdate")
    pub bundle_id: String,
    /// Code requirement string from codesign
    pub code_requirement: String,
    /// Identifier type: "bundleID" (default) or "path" for non-bundled binaries
    #[serde(
        default = "default_identifier_type",
        skip_serializing_if = "is_bundle_id"
    )]
    pub identifier_type: String,
    /// Path to the application bundle (optional, for reference)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// TCC/PPPC services to grant to this application
    #[serde(default)]
    pub services: Vec<PppcService>,
}

fn default_identifier_type() -> String {
    "bundleID".to_string()
}

fn is_bundle_id(s: &str) -> bool {
    s == "bundleID"
}

impl PppcConfig {
    /// Load a PPPC configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))?;
        toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse TOML from {}: {}", path.display(), e))
    }

    /// Save the configuration to a TOML file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize configuration to TOML: {e}"))?;

        // Add a header comment
        let with_header = format!(
            "# PPPC Policy Definitions\n\
             # Generated by: contour pppc scan\n\
             # Edit manually or re-run scan to update\n\n\
             {content}"
        );

        std::fs::write(path, with_header)
            .map_err(|e| anyhow::anyhow!("Failed to write {}: {}", path.display(), e))
    }

    /// Convert to PppcPolicy list for profile generation.
    pub fn to_policies(&self) -> Vec<PppcPolicy> {
        self.apps
            .iter()
            .filter(|app| !app.services.is_empty())
            .map(|app| PppcPolicy {
                app: AppInfo {
                    name: app.name.clone(),
                    bundle_id: app.bundle_id.clone(),
                    code_requirement: app.code_requirement.clone(),
                    identifier_type: app.identifier_type.clone(),
                    path: app
                        .path
                        .as_ref()
                        .map_or_else(|| PathBuf::from(""), PathBuf::from),
                },
                services: app.services.clone(),
            })
            .collect()
    }
}

impl PppcAppEntry {
    /// Returns true if this app has any TCC services configured.
    pub fn is_configured(&self) -> bool {
        !self.services.is_empty()
    }
}

impl From<&AppInfo> for PppcAppEntry {
    fn from(info: &AppInfo) -> Self {
        Self {
            name: info.name.clone(),
            bundle_id: info.bundle_id.clone(),
            code_requirement: info.code_requirement.clone(),
            identifier_type: "bundleID".to_string(),
            path: Some(info.path.display().to_string()),
            services: Vec::new(),
        }
    }
}

/// Extract the Team ID from a code requirement string.
///
/// Delegates to `contour_core::extract_team_id`.
pub fn extract_team_id(code_requirement: &str) -> Option<String> {
    contour_core::extract_team_id(code_requirement)
}

/// Sanitize a bundle ID for use in a profile identifier.
pub fn sanitize_id(bundle_id: &str) -> String {
    bundle_id.replace(['.', '-'], "_")
}

/// Generate a PPPC mobileconfig profile from policies.
///
/// When `identifier_suffix` is provided, it is appended to the profile identifier
/// to produce unique identifiers for per-app profiles. When `None`, the profile
/// uses the base `{org}.pppc` identifier (combined mode).
pub fn generate_pppc_profile(
    policies: &[PppcPolicy],
    org: &str,
    display_name: Option<&str>,
    identifier_suffix: Option<&str>,
) -> Result<Vec<u8>> {
    use std::collections::HashMap;

    let profile_id = match identifier_suffix {
        Some(suffix) => format!("{org}.pppc.{suffix}"),
        None => format!("{org}.pppc"),
    };

    // Group entries by service
    let mut services_map: HashMap<&str, Vec<Value>> = HashMap::new();

    for policy in policies {
        let id_type = if policy.app.identifier_type == "path" {
            contour_profiles::IdentifierType::Path
        } else {
            contour_profiles::IdentifierType::BundleID
        };

        for service in &policy.services {
            let entry = contour_profiles::build_tcc_entry_with_authorization(
                &policy.app.bundle_id,
                &policy.app.code_requirement,
                service.authorization_default(),
                id_type,
            );
            services_map.entry(service.key()).or_default().push(entry);
        }
    }

    // Build Services dictionary
    let mut services_dict = Dictionary::new();
    // Sort keys for deterministic output
    let mut keys: Vec<_> = services_map.keys().collect();
    keys.sort();
    for key in keys {
        if let Some(entries) = services_map.get(key) {
            services_dict.insert(key.to_string(), Value::Array(entries.clone()));
        }
    }

    let mut payload_content = Dictionary::new();
    payload_content.insert("Services".to_string(), Value::Dictionary(services_dict));

    let profile_display_name = display_name.unwrap_or("PPPC Profile");

    ProfileBuilder::new(org, &profile_id)
        .display_name(profile_display_name)
        .description("Privacy preferences for managed applications")
        .removal_disallowed(true)
        .build(
            "com.apple.TCC.configuration-profile-policy",
            payload_content,
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_key() {
        assert_eq!(
            PppcService::SystemPolicyAllFiles.key(),
            "SystemPolicyAllFiles"
        );
        assert_eq!(PppcService::Camera.key(), "Camera");
        assert_eq!(PppcService::ScreenCapture.key(), "ScreenCapture");
    }

    #[test]
    fn test_service_display_name() {
        assert_eq!(
            PppcService::SystemPolicyAllFiles.display_name(),
            "Full Disk Access"
        );
        assert_eq!(
            PppcService::ScreenCapture.display_name(),
            "Screen Recording"
        );
        assert_eq!(PppcService::AddressBook.display_name(), "Contacts");
    }

    #[test]
    fn test_all_services() {
        let all = PppcService::all();
        assert_eq!(all.len(), 24);
    }

    #[test]
    fn test_generate_profile() {
        let policies = vec![PppcPolicy {
            app: AppInfo {
                name: "Test App".to_string(),
                bundle_id: "com.example.test".to_string(),
                code_requirement: r#"identifier "com.example.test" and anchor apple generic"#
                    .to_string(),
                identifier_type: "bundleID".to_string(),
                path: PathBuf::from("/Applications/Test.app"),
            },
            services: vec![
                PppcService::SystemPolicyAllFiles,
                PppcService::Camera,
                PppcService::ScreenCapture,
            ],
        }];

        let result = generate_pppc_profile(&policies, "com.example", None, None);
        assert!(result.is_ok());

        let content = String::from_utf8(result.unwrap()).unwrap();
        assert!(content.contains("com.apple.TCC.configuration-profile-policy"));
        assert!(content.contains("SystemPolicyAllFiles"));
        assert!(content.contains("Camera"));
        assert!(content.contains("ScreenCapture"));
        assert!(content.contains("com.example.test"));
        // Uses Authorization key, not legacy Allowed
        assert!(content.contains("Authorization"));
        assert!(!content.contains("<key>Allowed</key>"));
        // FDA gets Allow, Camera gets Deny, ScreenCapture gets AllowStandardUserToSetSystemService
        assert!(content.contains("Allow"));
        assert!(content.contains("Deny"));
        assert!(content.contains("AllowStandardUserToSetSystemService"));
    }

    #[test]
    fn test_pppc_config_roundtrip() {
        let config = PppcConfig {
            config: PppcConfigMeta {
                org: "com.example".to_string(),
                display_name: Some("Test Profile".to_string()),
            },
            apps: vec![PppcAppEntry {
                name: "Zoom".to_string(),
                bundle_id: "us.zoom.xos".to_string(),
                code_requirement: r#"identifier "us.zoom.xos" and anchor apple generic"#
                    .to_string(),
                identifier_type: "bundleID".to_string(),
                path: Some("/Applications/zoom.us.app".to_string()),
                services: vec![PppcService::Camera, PppcService::Microphone],
            }],
        };

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: PppcConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(parsed.config.org, "com.example");
        assert_eq!(parsed.config.display_name, Some("Test Profile".to_string()));
        assert_eq!(parsed.apps.len(), 1);
        assert_eq!(parsed.apps[0].bundle_id, "us.zoom.xos");
        assert_eq!(parsed.apps[0].services.len(), 2);
    }

    #[test]
    fn test_pppc_config_to_policies() {
        let config = PppcConfig {
            config: PppcConfigMeta {
                org: "com.example".to_string(),
                display_name: None,
            },
            apps: vec![
                PppcAppEntry {
                    name: "App1".to_string(),
                    bundle_id: "com.example.app1".to_string(),
                    code_requirement: "identifier \"com.example.app1\"".to_string(),
                    identifier_type: "bundleID".to_string(),
                    path: None,
                    services: vec![PppcService::SystemPolicyAllFiles],
                },
                PppcAppEntry {
                    name: "App2".to_string(),
                    bundle_id: "com.example.app2".to_string(),
                    code_requirement: "identifier \"com.example.app2\"".to_string(),
                    identifier_type: "bundleID".to_string(),
                    path: None,
                    services: vec![], // No services = should be filtered out
                },
            ],
        };

        let policies = config.to_policies();
        assert_eq!(policies.len(), 1); // Only App1 has services
        assert_eq!(policies[0].app.bundle_id, "com.example.app1");
    }

    #[test]
    fn test_service_serde() {
        // Test that services serialize/deserialize correctly in TOML
        let app = PppcAppEntry {
            name: "Test".to_string(),
            bundle_id: "com.test".to_string(),
            code_requirement: "test".to_string(),
            identifier_type: "bundleID".to_string(),
            path: None,
            services: vec![
                PppcService::SystemPolicyAllFiles,
                PppcService::ScreenCapture,
            ],
        };

        let toml_str = toml::to_string(&app).unwrap();
        assert!(toml_str.contains("fda"));
        assert!(toml_str.contains("screen-capture"));

        let parsed: PppcAppEntry = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.services.len(), 2);
    }

    #[test]
    fn test_extract_team_id() {
        // Quoted format
        let req = r#"identifier "us.zoom.xos" and anchor apple generic and certificate leaf[subject.OU] = "BJ4HAAB9B3""#;
        assert_eq!(extract_team_id(req), Some("BJ4HAAB9B3".to_string()));

        // Unquoted format
        let req2 = r#"identifier "com.1password" and certificate leaf[subject.OU] = ABCD1234EF"#;
        assert_eq!(extract_team_id(req2), Some("ABCD1234EF".to_string()));

        // No team ID
        let req3 = r#"identifier "com.example" and anchor apple"#;
        assert_eq!(extract_team_id(req3), None);
    }

    #[test]
    fn test_authorization_default() {
        use contour_profiles::TccAuthorization;

        // Normal services get Allow
        assert_eq!(
            PppcService::SystemPolicyAllFiles.authorization_default(),
            TccAuthorization::Allow
        );
        assert_eq!(
            PppcService::Accessibility.authorization_default(),
            TccAuthorization::Allow
        );
        assert_eq!(
            PppcService::AddressBook.authorization_default(),
            TccAuthorization::Allow
        );

        // Deny-only
        assert_eq!(
            PppcService::Camera.authorization_default(),
            TccAuthorization::Deny
        );
        assert_eq!(
            PppcService::Microphone.authorization_default(),
            TccAuthorization::Deny
        );

        // Standard-user-settable
        assert_eq!(
            PppcService::ScreenCapture.authorization_default(),
            TccAuthorization::AllowStandardUserToSetSystemService
        );
        assert_eq!(
            PppcService::ListenEvent.authorization_default(),
            TccAuthorization::AllowStandardUserToSetSystemService
        );
    }

    #[test]
    fn test_is_deny_only() {
        assert!(PppcService::Camera.is_deny_only());
        assert!(PppcService::Microphone.is_deny_only());
        assert!(!PppcService::ScreenCapture.is_deny_only());
        assert!(!PppcService::SystemPolicyAllFiles.is_deny_only());
    }

    #[test]
    fn test_supports_standard_user_set() {
        assert!(PppcService::ScreenCapture.supports_standard_user_set());
        assert!(PppcService::ListenEvent.supports_standard_user_set());
        assert!(!PppcService::Camera.supports_standard_user_set());
        assert!(!PppcService::SystemPolicyAllFiles.supports_standard_user_set());
    }
}
