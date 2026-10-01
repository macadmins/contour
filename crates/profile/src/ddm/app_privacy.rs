//! App privacy defaults — `com.apple.configuration.app.settings`'s `Privacy`
//! block.
//!
//! macOS 27 lets an MDM pre-answer the privacy prompts an app would otherwise
//! raise one at a time, by shipping a `Privacy.PermissionDefaults` map keyed by
//! app. This module builds that map.
//!
//! ## The key is the whole problem
//!
//! Each entry is keyed by the app's bundle identifier followed by its
//! **designated requirement** in braces:
//!
//! ```text
//! us.zoom.xos {identifier "us.zoom.xos" and anchor apple generic and certificate …}
//! ```
//!
//! The designated requirement is a codesign expression nobody should type by
//! hand — it is long, quoted, and a single wrong character produces a
//! declaration that validates cleanly and manages nothing. [`permission_key`]
//! builds it from what `codesign -d -r-` reports, which is why `scan` refuses
//! an app whose requirement cannot be read rather than emitting a placeholder.
//!
//! ## Three things the public write-ups get wrong
//!
//! 1. **There is no `Deny`.** Apple's allowed values are `None` and `Allow`
//!    (plus `WhileUsing`/`Always` for [`Permission::Location`] and
//!    `Approximate`/`Precise` for [`Permission::LocationAccuracy`]).
//!    [`Permission::parse_value`] refuses `Deny` by name, because a dropped
//!    "Deny" reads as "unmanaged" on device — the opposite of the intent.
//! 2. **Omitting a permission is not denying it.** An absent key leaves the
//!    app unmanaged for that permission and the user is still prompted.
//! 3. **The fifth permission is `Dictation`**, not "Speech Recognition", and
//!    `Bluetooth`, `Location` and `LocationAccuracy` exist too.
//!
//! Verified against contour's embedded schema:
//! `contour profile ddm info com.apple.configuration.app.settings --full`.

use std::collections::BTreeMap;
use std::fmt;

/// The DDM configuration type this module targets.
pub const APP_SETTINGS_TYPE: &str = "com.apple.configuration.app.settings";

/// One privacy permission Apple lets a declaration pre-answer.
///
/// The variants and their legal values mirror
/// `Privacy.PermissionDefaults.ANY` in Apple's schema exactly; adding one here
/// without the schema agreeing produces a declaration the device rejects.
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
    /// Every permission, in the order they appear in a generated TOML.
    pub const ALL: &'static [Permission] = &[
        Permission::Accessibility,
        Permission::Bluetooth,
        Permission::Camera,
        Permission::Dictation,
        Permission::LocalNetwork,
        Permission::Location,
        Permission::LocationAccuracy,
        Permission::Microphone,
    ];

    /// The Apple key name, used verbatim in the declaration payload.
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

    /// The snake_case name accepted in `app-privacy.toml`.
    pub fn toml_key(self) -> &'static str {
        match self {
            Permission::Accessibility => "accessibility",
            Permission::Bluetooth => "bluetooth",
            Permission::Camera => "camera",
            Permission::Dictation => "dictation",
            Permission::LocalNetwork => "local_network",
            Permission::Location => "location",
            Permission::LocationAccuracy => "location_accuracy",
            Permission::Microphone => "microphone",
        }
    }

    /// Parse a TOML key back to a permission.
    pub fn from_toml_key(s: &str) -> Option<Permission> {
        Permission::ALL
            .iter()
            .copied()
            .find(|p| p.toml_key() == s || p.key() == s)
    }

    /// Values Apple accepts for this permission.
    pub fn allowed_values(self) -> &'static [&'static str] {
        match self {
            Permission::Location => &["None", "WhileUsing", "Always"],
            Permission::LocationAccuracy => &["None", "Approximate", "Precise"],
            _ => &["None", "Allow"],
        }
    }

    /// Validate one value for this permission, normalising case.
    ///
    /// `Deny` is called out by name rather than folded into the generic
    /// "not allowed" message: it is the single most likely thing an operator
    /// writes, it comes straight from PPPC habits and from published examples,
    /// and silently treating it as invalid would leave the app unmanaged.
    pub fn parse_value(self, raw: &str) -> Result<&'static str, AppPrivacyError> {
        let want = raw.trim();
        if let Some(v) = self
            .allowed_values()
            .iter()
            .find(|v| v.eq_ignore_ascii_case(want))
        {
            return Ok(v);
        }

        if want.eq_ignore_ascii_case("Deny") || want.eq_ignore_ascii_case("Denied") {
            return Err(AppPrivacyError::DenyNotSupported {
                permission: self.key(),
            });
        }

        Err(AppPrivacyError::BadValue {
            permission: self.key(),
            value: want.to_string(),
            allowed: self.allowed_values().join(", "),
        })
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

/// Everything that can go wrong building a privacy payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppPrivacyError {
    /// `Deny` was requested; Apple has no such value.
    DenyNotSupported { permission: &'static str },
    /// A value outside the permission's allowed set.
    BadValue {
        permission: &'static str,
        value: String,
        allowed: String,
    },
    /// An unrecognised permission name in the TOML.
    UnknownPermission { name: String },
    /// `OrganizationJustification` missing or blank.
    MissingJustification { bundle_id: String },
    /// The app's designated requirement could not be read.
    NoDesignatedRequirement { path: String, reason: String },
    /// An app entry with no permissions set at all.
    NoPermissions { bundle_id: String },
}

impl fmt::Display for AppPrivacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppPrivacyError::DenyNotSupported { permission } => write!(
                f,
                "{permission}: Apple has no 'Deny' value — use \"None\" to leave the \
                 permission unmanaged (the user is still prompted), or \"Allow\" to grant it"
            ),
            AppPrivacyError::BadValue {
                permission,
                value,
                allowed,
            } => write!(
                f,
                "{permission}: '{value}' is not allowed; expected one of {allowed}"
            ),
            AppPrivacyError::UnknownPermission { name } => write!(
                f,
                "'{name}' is not a privacy permission; known: {}",
                Permission::ALL
                    .iter()
                    .map(|p| p.toml_key())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            AppPrivacyError::MissingJustification { bundle_id } => write!(
                f,
                "{bundle_id}: OrganizationJustification is required and is shown to the \
                 user — set a real reason, e.g. \"Used for video conferencing\""
            ),
            AppPrivacyError::NoDesignatedRequirement { path, reason } => write!(
                f,
                "{path}: cannot read a designated requirement ({reason}). A declaration \
                 keyed on a missing or wrong requirement validates cleanly and manages \
                 nothing, so this app is refused rather than guessed at."
            ),
            AppPrivacyError::NoPermissions { bundle_id } => write!(
                f,
                "{bundle_id}: no permissions set — an entry with only a justification \
                 manages nothing"
            ),
        }
    }
}

impl std::error::Error for AppPrivacyError {}

/// One app's privacy defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEntry {
    /// Bundle identifier, e.g. `us.zoom.xos`.
    pub bundle_id: String,
    /// The full designated requirement, without surrounding braces.
    pub designated_requirement: String,
    /// User-visible reason. Required by Apple's schema.
    pub justification: String,
    /// Permission → already-validated value.
    pub permissions: BTreeMap<Permission, String>,
}

impl AppEntry {
    /// The `PermissionDefaults` key for this app: `<bundle id> {<requirement>}`.
    ///
    /// Apple matches on this whole string, so the requirement must be exactly
    /// what `codesign -d -r-` printed — no re-wrapping, no whitespace fixups.
    pub fn permission_key(&self) -> String {
        permission_key(&self.bundle_id, &self.designated_requirement)
    }
}

/// Build the `PermissionDefaults` key from a bundle id and a designated
/// requirement.
pub fn permission_key(bundle_id: &str, designated_requirement: &str) -> String {
    format!("{bundle_id} {{{designated_requirement}}}")
}

/// Build the `Privacy` payload object for a set of apps.
///
/// Returns the value that belongs under `[configuration.payload]` as
/// `Privacy`, ready to hand to `ddm compose`.
pub fn build_privacy_payload(
    apps: &[AppEntry],
) -> Result<serde_json::Map<String, serde_json::Value>, AppPrivacyError> {
    let mut defaults = serde_json::Map::new();

    for app in apps {
        if app.justification.trim().is_empty() {
            return Err(AppPrivacyError::MissingJustification {
                bundle_id: app.bundle_id.clone(),
            });
        }
        if app.permissions.is_empty() {
            return Err(AppPrivacyError::NoPermissions {
                bundle_id: app.bundle_id.clone(),
            });
        }

        let mut entry = serde_json::Map::new();
        // Justification first so the generated JSON reads the way an operator
        // would explain the entry out loud.
        entry.insert(
            "OrganizationJustification".to_string(),
            serde_json::Value::String(app.justification.trim().to_string()),
        );
        for (permission, value) in &app.permissions {
            entry.insert(
                permission.key().to_string(),
                serde_json::Value::String(value.clone()),
            );
        }

        defaults.insert(app.permission_key(), serde_json::Value::Object(entry));
    }

    let mut privacy = serde_json::Map::new();
    privacy.insert(
        "PermissionDefaults".to_string(),
        serde_json::Value::Object(defaults),
    );
    Ok(privacy)
}

/// PPPC services that have an `app.settings` equivalent.
///
/// PPPC is a much larger surface — 24 services including `fda`,
/// `apple-events`, `screen-capture` and the folder policies — while
/// `app.settings` carries permissions PPPC never had (`LocalNetwork`,
/// `Location`, `LocationAccuracy`). Only these five carry over; everything
/// else is reported as unmapped rather than silently dropped, because an
/// operator converting a PPPC policy needs to know which grants did not
/// survive the trip.
pub fn pppc_service_mapping(service: &str) -> Option<Permission> {
    // The names are pppc.toml's serialised forms (kebab-case), not the Rust
    // variant names — the importer reads the TOML generically rather than
    // depending on the pppc crate.
    match service {
        "camera" => Some(Permission::Camera),
        "microphone" => Some(Permission::Microphone),
        "accessibility" => Some(Permission::Accessibility),
        // PPPC's SpeechRecognition is app.settings' Dictation. Same permission,
        // different name — this is the one rename in the overlap.
        "speech-recognition" => Some(Permission::Dictation),
        // PPPC's BluetoothAlways.
        "bluetooth" => Some(Permission::Bluetooth),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zoom() -> AppEntry {
        let mut permissions = BTreeMap::new();
        permissions.insert(Permission::Camera, "Allow".to_string());
        permissions.insert(Permission::Microphone, "Allow".to_string());
        AppEntry {
            bundle_id: "us.zoom.xos".to_string(),
            designated_requirement:
                "identifier \"us.zoom.xos\" and anchor apple generic and certificate \
                 leaf[subject.OU] = BJ4HAAB9B3"
                    .to_string(),
            justification: "Used for video conferencing".to_string(),
            permissions,
        }
    }

    #[test]
    fn permission_key_wraps_the_requirement_in_braces() {
        let key = zoom().permission_key();
        assert!(
            key.starts_with("us.zoom.xos {identifier \"us.zoom.xos\""),
            "key must be '<bundle id> {{<requirement>}}', got: {key}"
        );
        assert!(key.ends_with('}'), "key must close the brace: {key}");
        // The requirement's own quotes survive — Apple matches the whole string.
        assert!(key.contains("\"us.zoom.xos\""));
    }

    #[test]
    fn deny_is_refused_by_name() {
        // The single most likely operator mistake: PPPC habits and published
        // examples both suggest Deny, which Apple does not have.
        let err = Permission::Camera.parse_value("Deny").unwrap_err();
        assert_eq!(
            err,
            AppPrivacyError::DenyNotSupported {
                permission: "Camera"
            }
        );
        assert!(
            err.to_string().contains("no 'Deny' value"),
            "message must name the problem: {err}"
        );
    }

    #[test]
    fn values_are_case_insensitive_but_normalised() {
        assert_eq!(Permission::Camera.parse_value("allow").unwrap(), "Allow");
        assert_eq!(Permission::Camera.parse_value(" NONE ").unwrap(), "None");
    }

    #[test]
    fn location_has_its_own_value_set() {
        assert_eq!(
            Permission::Location.parse_value("WhileUsing").unwrap(),
            "WhileUsing"
        );
        // "Allow" is legal for Camera but not for Location.
        Permission::Location.parse_value("Allow").unwrap_err();
        assert_eq!(
            Permission::LocationAccuracy.parse_value("Precise").unwrap(),
            "Precise"
        );
        Permission::LocationAccuracy
            .parse_value("Allow")
            .unwrap_err();
    }

    #[test]
    fn payload_shape_matches_apples_schema() {
        let privacy = build_privacy_payload(&[zoom()]).unwrap();
        let defaults = privacy["PermissionDefaults"].as_object().unwrap();
        assert_eq!(defaults.len(), 1);

        let (key, entry) = defaults.iter().next().unwrap();
        assert!(key.starts_with("us.zoom.xos {"));
        assert_eq!(
            entry["OrganizationJustification"],
            "Used for video conferencing"
        );
        assert_eq!(entry["Camera"], "Allow");
        assert_eq!(entry["Microphone"], "Allow");
    }

    #[test]
    fn blank_justification_is_refused() {
        let mut app = zoom();
        app.justification = "   ".to_string();
        assert_eq!(
            build_privacy_payload(&[app]).unwrap_err(),
            AppPrivacyError::MissingJustification {
                bundle_id: "us.zoom.xos".to_string()
            }
        );
    }

    #[test]
    fn an_entry_with_no_permissions_is_refused() {
        let mut app = zoom();
        app.permissions.clear();
        assert_eq!(
            build_privacy_payload(&[app]).unwrap_err(),
            AppPrivacyError::NoPermissions {
                bundle_id: "us.zoom.xos".to_string()
            }
        );
    }

    #[test]
    fn every_permission_round_trips_through_its_toml_key() {
        for p in Permission::ALL {
            assert_eq!(Permission::from_toml_key(p.toml_key()), Some(*p));
            // The Apple key is accepted too, so a TOML copied from a
            // declaration still loads.
            assert_eq!(Permission::from_toml_key(p.key()), Some(*p));
        }
        assert_eq!(Permission::from_toml_key("speech_recognition"), None);
    }

    #[test]
    fn pppc_mapping_covers_only_the_overlap() {
        // pppc.toml's serialised names, not the Rust variant names.
        assert_eq!(pppc_service_mapping("camera"), Some(Permission::Camera));
        assert_eq!(
            pppc_service_mapping("bluetooth"),
            Some(Permission::Bluetooth)
        );
        // The one rename in the overlap.
        assert_eq!(
            pppc_service_mapping("speech-recognition"),
            Some(Permission::Dictation)
        );
        // PPPC-only services must report as unmapped, never silently drop.
        for only_pppc in [
            "fda",
            "apple-events",
            "screen-capture",
            "documents",
            "photos",
        ] {
            assert_eq!(pppc_service_mapping(only_pppc), None, "{only_pppc}");
        }
        // PascalCase variant names are NOT accepted — that would be reading
        // the wrong field and quietly mapping nothing.
        assert_eq!(pppc_service_mapping("Camera"), None);
    }
}
