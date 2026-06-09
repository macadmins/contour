//! Privacy permission-default inputs.
//!
//! `Privacy.PermissionDefaults` can't come from a scan — *which* permissions to
//! pre-grant and the required `OrganizationJustification` are operator
//! decisions. This module reads an authored policy file and can emit an
//! editable skeleton (`--scaffold`) from a scan's app inventory.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use crate::cli::scan::ScannedApp;

use super::map::composed_from_scanned;
use super::model::{Permission, PermissionDefault};
use super::validate::permission_macos_na;

/// On-disk Privacy policy (`--permissions`). TOML, e.g.:
/// ```toml
/// [[app]]
/// identifier = "com.example.app (ABCDE12345)"
/// justification = "Required for video conferencing"
/// [app.permissions]
/// Camera = "Allow"
/// Microphone = "Allow"
/// Location = "WhileUsing"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionPolicyFile {
    #[serde(default)]
    pub app: Vec<PermissionPolicyEntry>,
}

/// One app's privacy policy entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionPolicyEntry {
    /// Composed identifier (macOS) or bundle ID (iOS).
    pub identifier: String,
    /// Text shown in the consent prompt (becomes `OrganizationJustification`).
    pub justification: String,
    /// Permission key → value (validated later against the rangelists).
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
}

impl PermissionPolicyFile {
    /// Serialize back to TOML (used by `--scaffold`).
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serializing permission policy")
    }

    /// Convert to validated model entries. Unknown permission keys are an error.
    pub fn into_defaults(self) -> Result<Vec<PermissionDefault>> {
        let mut out = Vec::with_capacity(self.app.len());
        for entry in self.app {
            let mut permissions = BTreeMap::new();
            for (key, value) in entry.permissions {
                let perm = Permission::from_key(&key).with_context(|| {
                    format!("unknown permission '{key}' for {}", entry.identifier)
                })?;
                permissions.insert(perm, value);
            }
            out.push(PermissionDefault {
                app_identifier: entry.identifier,
                organization_justification: entry.justification,
                permissions,
            });
        }
        Ok(out)
    }
}

/// Read a Privacy policy file (TOML) into validated permission defaults.
pub fn from_permission_policy(path: &Path) -> Result<Vec<PermissionDefault>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading permission policy {}", path.display()))?;
    let file: PermissionPolicyFile = toml::from_str(&text)
        .with_context(|| format!("parsing permission policy {}", path.display()))?;
    file.into_defaults()
}

/// Build an editable Privacy policy skeleton from a scan: one entry per app
/// (composed identifier), placeholder justification, every macOS-supported
/// permission defaulted to `None` for the operator to flip to `Allow`.
pub fn scaffold_policy(apps: &[ScannedApp]) -> PermissionPolicyFile {
    const PLACEHOLDER: &str = "TODO: explain why the organization requires these permissions";

    // macOS-supported permissions (LocationAccuracy is macOS `n/a`).
    let macos_permissions: Vec<Permission> = [
        Permission::Accessibility,
        Permission::Bluetooth,
        Permission::Camera,
        Permission::Dictation,
        Permission::LocalNetwork,
        Permission::Location,
        Permission::Microphone,
    ]
    .into_iter()
    .filter(|p| !permission_macos_na(*p))
    .collect();

    let app = apps
        .iter()
        .filter_map(|app| {
            let composed = composed_from_scanned(app)?;
            let permissions = macos_permissions
                .iter()
                .map(|p| (p.key().to_string(), "None".to_string()))
                .collect();
            Some(PermissionPolicyEntry {
                identifier: composed.render(),
                justification: PLACEHOLDER.to_string(),
                permissions,
            })
        })
        .collect();

    PermissionPolicyFile { app }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(bundle: &str, team: Option<&str>) -> ScannedApp {
        ScannedApp {
            name: "X".into(),
            path: "/Applications/X.app".into(),
            version: None,
            team_id: team.map(str::to_string),
            signing_id: None,
            sha256: None,
            cdhash: None,
            bundle_id: Some(bundle.into()),
        }
    }

    #[test]
    fn policy_file_round_trips_and_converts() {
        let toml_src = r#"
[[app]]
identifier = "com.example.app (ABCDE12345)"
justification = "Video calls"
[app.permissions]
Camera = "Allow"
Microphone = "Allow"
"#;
        let file: PermissionPolicyFile = toml::from_str(toml_src).unwrap();
        let defaults = file.into_defaults().unwrap();
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0].organization_justification, "Video calls");
        assert_eq!(
            defaults[0]
                .permissions
                .get(&Permission::Camera)
                .map(String::as_str),
            Some("Allow")
        );
    }

    #[test]
    fn unknown_permission_key_is_an_error() {
        let toml_src = r#"
[[app]]
identifier = "com.x"
justification = "j"
[app.permissions]
Telepathy = "Allow"
"#;
        let file: PermissionPolicyFile = toml::from_str(toml_src).unwrap();
        file.into_defaults().unwrap_err();
    }

    #[test]
    fn scaffold_emits_one_entry_per_app_with_none_defaults() {
        let apps = vec![
            app("com.example.app", Some("ABCDE12345")),
            app("com.other.tool", None),
        ];
        let policy = scaffold_policy(&apps);
        assert_eq!(policy.app.len(), 2);
        assert_eq!(policy.app[0].identifier, "com.example.app (ABCDE12345)");
        // All scaffolded values are None for the operator to edit.
        assert!(policy.app[0].permissions.values().all(|v| v == "None"));
        // macOS-only scaffold excludes LocationAccuracy.
        assert!(!policy.app[0].permissions.contains_key("LocationAccuracy"));
        // ...but includes Accessibility (macOS-supported).
        assert!(policy.app[0].permissions.contains_key("Accessibility"));
        // Round-trips to TOML.
        assert!(policy.to_toml().unwrap().contains("com.example.app"));
    }
}
