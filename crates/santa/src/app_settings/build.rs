//! Assemble a `com.apple.configuration.app.settings` declaration.
//!
//! Groups validated entries into the `Allowed` and `Privacy` dictionaries and
//! wraps them in the `Type`/`Identifier`/`Payload` envelope (`apply: combined`).
//! Built as `serde_json::Value` directly — same approach as `btm::generate`.

use serde_json::{Map, Value, json};

use super::model::{AppIdentifier, BinaryIdentifier, BinaryPolicy, PermissionDefault};

/// The Apple DDM configuration type emitted by this module.
pub const APP_SETTINGS_TYPE: &str = "com.apple.configuration.app.settings";

/// Inputs for one assembled declaration.
#[derive(Debug, Default)]
pub struct AppSettings {
    pub binaries: Vec<(BinaryIdentifier, BinaryPolicy)>,
    pub apps: Vec<(AppIdentifier, BinaryPolicy)>,
    pub privacy: Vec<PermissionDefault>,
    pub always_allow_managed: bool,
}

impl AppSettings {
    /// True when nothing would be emitted (caller can error before writing).
    pub fn is_empty(&self) -> bool {
        self.binaries.is_empty()
            && self.apps.is_empty()
            && self.privacy.is_empty()
            && !self.always_allow_managed
    }

    /// Build the `Allowed` dictionary, or `None` when it would be empty.
    fn allowed_dict(&self) -> Option<Value> {
        let mut allowed_binaries = Vec::new();
        let mut denied_binaries = Vec::new();
        for (bi, policy) in &self.binaries {
            match policy {
                BinaryPolicy::Allow => allowed_binaries.push(bi),
                BinaryPolicy::Deny => denied_binaries.push(bi),
            }
        }
        let mut allowed_apps = Vec::new();
        let mut denied_apps = Vec::new();
        for (app, policy) in &self.apps {
            match policy {
                BinaryPolicy::Allow => allowed_apps.push(app),
                BinaryPolicy::Deny => denied_apps.push(app),
            }
        }

        let mut allowed = Map::new();
        if !allowed_apps.is_empty() {
            allowed.insert("AllowedApps".into(), json!(allowed_apps));
        }
        if !denied_apps.is_empty() {
            allowed.insert("DeniedApps".into(), json!(denied_apps));
        }
        if !allowed_binaries.is_empty() {
            allowed.insert("AllowedBinaries".into(), json!(allowed_binaries));
        }
        if !denied_binaries.is_empty() {
            allowed.insert("DeniedBinaries".into(), json!(denied_binaries));
        }
        if self.always_allow_managed {
            allowed.insert("AlwaysAllowManagedApps".into(), Value::Bool(true));
        }

        (!allowed.is_empty()).then_some(Value::Object(allowed))
    }

    /// Build the `Privacy` dictionary, or `None` when there are no defaults.
    fn privacy_dict(&self) -> Option<Value> {
        if self.privacy.is_empty() {
            return None;
        }
        let mut defaults = Map::new();
        for pd in &self.privacy {
            defaults.insert(pd.app_identifier.clone(), pd.to_json());
        }
        Some(json!({ "PermissionDefaults": Value::Object(defaults) }))
    }

    /// Build the full declaration JSON.
    pub fn to_declaration(&self, org: &str, identifier_suffix: &str) -> Value {
        let mut payload = Map::new();
        if let Some(allowed) = self.allowed_dict() {
            payload.insert("Allowed".into(), allowed);
        }
        if let Some(privacy) = self.privacy_dict() {
            payload.insert("Privacy".into(), privacy);
        }

        json!({
            "Type": APP_SETTINGS_TYPE,
            "Identifier": format!("{org}.app-settings.{}", sanitize_id(identifier_suffix)),
            "Payload": Value::Object(payload),
        })
    }
}

/// Lower-case and replace any non `[a-z0-9.]` run with a single `-`.
fn sanitize_id(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::super::model::SigningState;
    use super::*;

    fn team(id: &str) -> BinaryIdentifier {
        BinaryIdentifier {
            team_id: Some(id.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn groups_allow_and_deny_into_correct_lists() {
        let settings = AppSettings {
            binaries: vec![
                (team("ABCDE12345"), BinaryPolicy::Allow),
                (team("FFFFF99999"), BinaryPolicy::Deny),
            ],
            always_allow_managed: true,
            ..Default::default()
        };
        let decl = settings.to_declaration("com.acme", "fleet");
        let allowed = &decl["Payload"]["Allowed"];
        assert_eq!(allowed["AllowedBinaries"][0]["TeamID"], "ABCDE12345");
        assert_eq!(allowed["DeniedBinaries"][0]["TeamID"], "FFFFF99999");
        assert_eq!(allowed["AlwaysAllowManagedApps"], true);
        assert_eq!(decl["Type"], APP_SETTINGS_TYPE);
        assert_eq!(decl["Identifier"], "com.acme.app-settings.fleet");
    }

    #[test]
    fn groups_apps_into_allowed_and_denied() {
        let app = |id: &str| AppIdentifier {
            app_identifier: id.to_string(),
        };
        let settings = AppSettings {
            apps: vec![
                (app("com.allow.app"), BinaryPolicy::Allow),
                (app("com.deny.app"), BinaryPolicy::Deny),
            ],
            ..Default::default()
        };
        let decl = settings.to_declaration("com.acme", "x");
        let allowed = &decl["Payload"]["Allowed"];
        assert_eq!(allowed["AllowedApps"][0]["AppIdentifier"], "com.allow.app");
        assert_eq!(allowed["DeniedApps"][0]["AppIdentifier"], "com.deny.app");
    }

    #[test]
    fn signing_state_serializes_in_binary_entry() {
        let bi = BinaryIdentifier {
            team_id: Some("ABCDE12345".to_string()),
            signing_state: Some(SigningState::DeveloperId),
            ..Default::default()
        };
        let settings = AppSettings {
            binaries: vec![(bi, BinaryPolicy::Allow)],
            ..Default::default()
        };
        let decl = settings.to_declaration("com.acme", "x");
        assert_eq!(
            decl["Payload"]["Allowed"]["AllowedBinaries"][0]["SigningState"],
            "DeveloperID"
        );
    }

    #[test]
    fn empty_settings_emits_empty_payload() {
        let settings = AppSettings::default();
        assert!(settings.is_empty());
        let decl = settings.to_declaration("com.acme", "x");
        assert!(decl["Payload"].as_object().unwrap().is_empty());
    }

    #[test]
    fn sanitize_id_normalizes() {
        assert_eq!(sanitize_id("My Fleet!"), "my-fleet");
        assert_eq!(sanitize_id("com.example.app"), "com.example.app");
    }
}
