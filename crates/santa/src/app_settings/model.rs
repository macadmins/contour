//! Schema-faithful types for `com.apple.configuration.app.settings`.
//!
//! These mirror Apple's OS 27 `app.settings` declaration: binary execution
//! control (`AllowedBinaries`/`DeniedBinaries` via code-signing identifiers),
//! app allow/deny lists (`AllowedApps`/`DeniedApps`), and app privacy
//! permission defaults (`Privacy.PermissionDefaults`). Field names use Apple's
//! exact casing (`CDHash`, `SigningID`, `TeamID`), so renames are explicit.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Which list a binary or app belongs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryPolicy {
    /// Goes into `AllowedBinaries` / `AllowedApps`.
    Allow,
    /// Goes into `DeniedBinaries` / `DeniedApps`. Under Endpoint Security this
    /// also terminates already-running processes of the matched binary.
    Deny,
}

/// The `SigningState` code-signing match value (schema rangelist).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningState {
    All,
    TestFlight,
    #[serde(rename = "DeveloperID")]
    DeveloperId,
    Enterprise,
    AppStore,
    Apple,
}

impl SigningState {
    /// All valid values (for validation and `--help`).
    pub const ALL: [SigningState; 6] = [
        SigningState::All,
        SigningState::TestFlight,
        SigningState::DeveloperId,
        SigningState::Enterprise,
        SigningState::AppStore,
        SigningState::Apple,
    ];

    /// The on-the-wire string used in the declaration.
    pub fn as_str(self) -> &'static str {
        match self {
            SigningState::All => "All",
            SigningState::TestFlight => "TestFlight",
            SigningState::DeveloperId => "DeveloperID",
            SigningState::Enterprise => "Enterprise",
            SigningState::AppStore => "AppStore",
            SigningState::Apple => "Apple",
        }
    }
}

/// A `BinaryIdentifier` — one entry of `AllowedBinaries`/`DeniedBinaries`.
///
/// A binary matches only when ALL present identifiers match. The schema's
/// `notes` require, per list:
/// - `AllowedBinaries`: `CDHash` or `TeamID` must be present.
/// - `DeniedBinaries`: `CDHash`, `TeamID`, or `SigningID` must be present.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIdentifier {
    #[serde(rename = "CDHash", skip_serializing_if = "Option::is_none")]
    pub cdhash: Option<String>,
    #[serde(rename = "SigningID", skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    #[serde(rename = "TeamID", skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(rename = "PathPrefix", skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(rename = "SigningState", skip_serializing_if = "Option::is_none")]
    pub signing_state: Option<SigningState>,
}

impl BinaryIdentifier {
    /// True when no identifying field is set (an empty, useless matcher).
    pub fn is_empty(&self) -> bool {
        self.cdhash.is_none()
            && self.signing_id.is_none()
            && self.team_id.is_none()
            && self.path_prefix.is_none()
    }
}

/// An app bundle-ID entry of `AllowedApps`/`DeniedApps` (iOS/tvOS/visionOS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppIdentifier {
    #[serde(rename = "AppIdentifier")]
    pub app_identifier: String,
}

/// A macOS Privacy "composed identifier": `Bundle-ID`, `Bundle-ID (Team-ID)`,
/// or `Bundle-ID {Designated-Requirement}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposedIdentifier {
    pub bundle_id: String,
    pub team_id: Option<String>,
    pub designated_requirement: Option<String>,
}

impl ComposedIdentifier {
    /// Render the composed identifier string per the schema's format. A
    /// designated requirement (most specific) wins over a team ID.
    pub fn render(&self) -> String {
        if let Some(dr) = &self.designated_requirement {
            format!("{} {{{dr}}}", self.bundle_id)
        } else if let Some(team) = &self.team_id {
            format!("{} ({team})", self.bundle_id)
        } else {
            self.bundle_id.clone()
        }
    }
}

/// An app privacy permission key (`Privacy.PermissionDefaults.<app>.<key>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    Accessibility,
    Bluetooth,
    Camera,
    Dictation,
    LocalNetwork,
    Location,
    LocationAccuracy,
    Microphone,
}

impl Permission {
    /// The declaration key for this permission (matches the schema verbatim).
    pub fn key(self) -> &'static str {
        match self {
            Permission::Accessibility => "Accessibility",
            Permission::Bluetooth => "Bluetooth",
            Permission::Camera => "Camera",
            Permission::Dictation => "Dictation",
            Permission::LocalNetwork => "LocalNetwork",
            Permission::Location => "Location",
            Permission::LocationAccuracy => "LocationAccuracy",
            Permission::Microphone => "Microphone",
        }
    }

    /// Valid values for this permission (schema rangelist). Most are
    /// `None`/`Allow`; `Location` and `LocationAccuracy` are richer.
    pub fn allowed_values(self) -> &'static [&'static str] {
        match self {
            Permission::Location => &["None", "WhileUsing", "Always"],
            Permission::LocationAccuracy => &["None", "Approximate", "Precise"],
            _ => &["None", "Allow"],
        }
    }

    /// Resolve a permission from its declaration key.
    pub fn from_key(key: &str) -> Option<Permission> {
        [
            Permission::Accessibility,
            Permission::Bluetooth,
            Permission::Camera,
            Permission::Dictation,
            Permission::LocalNetwork,
            Permission::Location,
            Permission::LocationAccuracy,
            Permission::Microphone,
        ]
        .into_iter()
        .find(|p| p.key() == key)
    }
}

/// Privacy permission defaults for a single app, keyed by composed/bundle ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDefault {
    /// Composed identifier (macOS) or bundle ID (iOS).
    pub app_identifier: String,
    /// Required text shown in the consent prompt explaining the request.
    pub organization_justification: String,
    /// Permission → value (value validated against [`Permission::allowed_values`]).
    pub permissions: BTreeMap<Permission, String>,
}

impl PermissionDefault {
    /// Serialize to the per-app dictionary the declaration expects:
    /// `{ "OrganizationJustification": "...", "Camera": "Allow", ... }`.
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "OrganizationJustification".to_string(),
            serde_json::Value::String(self.organization_justification.clone()),
        );
        for (perm, value) in &self.permissions {
            map.insert(
                perm.key().to_string(),
                serde_json::Value::String(value.clone()),
            );
        }
        serde_json::Value::Object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_identifier_omits_none_and_uses_apple_casing() {
        let bi = BinaryIdentifier {
            team_id: Some("ABCDE12345".to_string()),
            signing_state: Some(SigningState::DeveloperId),
            ..Default::default()
        };
        let json = serde_json::to_string(&bi).unwrap();
        assert!(json.contains("\"TeamID\":\"ABCDE12345\""), "{json}");
        assert!(json.contains("\"SigningState\":\"DeveloperID\""), "{json}");
        // None fields are omitted entirely.
        assert!(!json.contains("CDHash"), "{json}");
        assert!(!json.contains("PathPrefix"), "{json}");
    }

    #[test]
    fn signing_state_round_trips_developer_id() {
        let s = serde_json::to_string(&SigningState::DeveloperId).unwrap();
        assert_eq!(s, "\"DeveloperID\"");
        let back: SigningState = serde_json::from_str("\"DeveloperID\"").unwrap();
        assert_eq!(back, SigningState::DeveloperId);
    }

    #[test]
    fn composed_identifier_renders_all_three_forms() {
        let bundle = ComposedIdentifier {
            bundle_id: "com.example.app".to_string(),
            team_id: None,
            designated_requirement: None,
        };
        assert_eq!(bundle.render(), "com.example.app");

        let with_team = ComposedIdentifier {
            team_id: Some("ABCDE12345".to_string()),
            ..bundle.clone()
        };
        assert_eq!(with_team.render(), "com.example.app (ABCDE12345)");

        let with_dr = ComposedIdentifier {
            designated_requirement: Some("anchor apple generic".to_string()),
            ..with_team.clone()
        };
        // Designated requirement wins over team ID.
        assert_eq!(with_dr.render(), "com.example.app {anchor apple generic}");
    }

    #[test]
    fn binary_identifier_is_empty_ignores_signing_state() {
        // SigningState alone is not an identifier — such an entry is empty.
        let bi = BinaryIdentifier {
            signing_state: Some(SigningState::All),
            ..Default::default()
        };
        assert!(bi.is_empty());
    }

    #[test]
    fn permission_rangelists_match_schema() {
        assert_eq!(Permission::Camera.allowed_values(), &["None", "Allow"]);
        assert_eq!(
            Permission::Location.allowed_values(),
            &["None", "WhileUsing", "Always"]
        );
        assert_eq!(
            Permission::LocationAccuracy.allowed_values(),
            &["None", "Approximate", "Precise"]
        );
        assert_eq!(
            Permission::from_key("Microphone"),
            Some(Permission::Microphone)
        );
        assert_eq!(Permission::from_key("Nonexistent"), None);
    }

    #[test]
    fn permission_default_serializes_justification_and_values() {
        let mut permissions = BTreeMap::new();
        permissions.insert(Permission::Camera, "Allow".to_string());
        let pd = PermissionDefault {
            app_identifier: "com.example.app (ABCDE12345)".to_string(),
            organization_justification: "Required for video calls".to_string(),
            permissions,
        };
        let json = pd.to_json();
        assert_eq!(
            json["OrganizationJustification"],
            "Required for video calls"
        );
        assert_eq!(json["Camera"], "Allow");
    }
}
