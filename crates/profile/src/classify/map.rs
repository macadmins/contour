//! The editable naming reference map: payload type → friendly Kind/Subject.
//!
//! Loaded from an embedded default (`reference/naming.yaml`), overridable at
//! runtime via an explicit path or a repo-local `.contour/naming.yaml`.

use std::path::Path;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;

/// The canonical default map, compiled into the binary.
const EMBEDDED_DEFAULT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../reference/naming.yaml"
));

/// A parsed naming reference map.
#[derive(Debug, Clone, Deserialize)]
pub struct NamingMap {
    /// Template for system-scope profiles. Placeholders `{scope} {kind}
    /// {subject}`; the `({subject})` parens are dropped when the subject is empty.
    pub system_format: String,
    /// Template for app-scope profiles (an app name is derivable). Placeholders
    /// `{subject} {kind}` — the app name leads, the payload kind is the
    /// parenthetical aspect.
    pub app_format: String,
    /// Scope detection / labelling.
    #[serde(default)]
    pub scope: ScopeConfig,
    /// Separator joining multiple distinct kinds.
    #[serde(default = "default_join")]
    pub multi_kind_join: String,
    /// Payload type → friendly Kind label (insertion order preserved).
    #[serde(default)]
    pub kinds: IndexMap<String, String>,
    /// Payload type → subject extraction rule (insertion order preserved).
    #[serde(default)]
    pub subjects: IndexMap<String, SubjectRule>,
    /// Bundle id / preference domain → friendly app name.
    #[serde(default)]
    pub apps: IndexMap<String, String>,
    /// Leading tokens stripped by every `from_existing` rule, in addition to
    /// each rule's own `strip_leading`. The place to declare org-wide scope and
    /// cluster/tenant words (`System`, `App`, your tenant codes, …) once.
    #[serde(default)]
    pub strip_leading_default: Vec<String>,
    /// Tokens removed from recovered detail wherever they appear (whole-word),
    /// not just at the start. For cluster/tenant tags that show up trailing or
    /// mid-name (e.g. a code appended as a suffix), with separator cleanup.
    #[serde(default)]
    pub strip_tokens_default: Vec<String>,
    /// Codes preserved and re-appended as a trailing ` - {code}` suffix (e.g.
    /// site codes), rather than stripped. Whole-word, case-insensitive.
    #[serde(default)]
    pub keep_trailing: Vec<String>,
    /// Codes preserved and re-prepended as a leading `{code} - ` prefix (e.g.
    /// a tenant/cluster code that should lead the name), rather than stripped.
    /// Whole-word, case-insensitive.
    #[serde(default)]
    pub keep_leading: Vec<String>,
}

/// Scope detection and labelling.
///
/// A profile is classified into one of three scopes (checked in this order):
/// **App** (every kind-contributing payload is an `app_payload_types` entry and an
/// app name is derivable), **User** (envelope `PayloadScope == "User"`), else
/// **System**. Each scope renders with its own label substituted for `{scope}`.
#[derive(Debug, Clone, Deserialize)]
pub struct ScopeConfig {
    /// Label used for system-scope profiles (e.g. `System`).
    #[serde(default = "default_system_label")]
    pub system_label: String,
    /// Label used for app-scope profiles (e.g. `App`).
    #[serde(default = "default_app_label")]
    pub app_label: String,
    /// Label used for user-scope profiles — envelope `PayloadScope == "User"`
    /// (e.g. `User`).
    #[serde(default = "default_user_label")]
    pub user_label: String,
    /// Payload types that mark a profile as app-scope. A profile is app-scope
    /// when every payload that contributes a kind is one of these.
    #[serde(default)]
    pub app_payload_types: Vec<String>,
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            system_label: default_system_label(),
            app_label: default_app_label(),
            user_label: default_user_label(),
            app_payload_types: Vec::new(),
        }
    }
}

fn default_system_label() -> String {
    "System".to_string()
}

fn default_app_label() -> String {
    "App".to_string()
}

fn default_user_label() -> String {
    "User".to_string()
}

/// How to derive the `{subject}` for a payload type.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SubjectRule {
    /// Read a string field of this name from the payload.
    #[serde(default)]
    pub field: Option<String>,
    /// Parse the cert in `PayloadContent` and use its subject common name.
    #[serde(default)]
    pub cert_subject_cn: bool,
    /// Resolve the payload's app bundle id and map it via `apps`.
    #[serde(default)]
    pub app_name: bool,
    /// Recover a subject from the profile's existing display name. For payloads
    /// with no identity field of their own (fonts, restrictions, notifications),
    /// where the distinguishing detail lives only in the name being replaced.
    #[serde(default)]
    pub from_existing: Option<FromExisting>,
}

/// Recover the subject from the existing display name: prefer the first `(...)`
/// group, else strip the rendered `{scope} - {kind}` lead and leading
/// scope/cluster tokens. Keeps renaming idempotent — `Scope - Kind (detail)`
/// recovers `detail` on a second pass.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FromExisting {
    /// Extra leading tokens (case-insensitive, whole words) to strip for this
    /// payload type, on top of the map-wide `strip_leading_default`.
    #[serde(default)]
    pub strip_leading: Vec<String>,
}

fn default_join() -> String {
    " + ".to_string()
}

impl NamingMap {
    /// Parse a map from YAML text.
    ///
    /// # Errors
    /// Returns an error if the YAML is malformed or missing required fields.
    pub fn from_yaml(text: &str) -> Result<Self> {
        yaml_serde::from_str(text).context("Failed to parse naming map YAML")
    }

    /// Parse a map from TOML text (the `name.toml` override format).
    ///
    /// # Errors
    /// Returns an error if the TOML is malformed or missing required fields.
    pub fn from_toml(text: &str) -> Result<Self> {
        toml::from_str(text).context("Failed to parse naming map TOML")
    }

    /// Load a map from a file, picking the parser by extension: `.toml` → TOML,
    /// anything else → YAML.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read naming map: {}", path.display()))?;
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("toml"))
        {
            Self::from_toml(&text)
        } else {
            Self::from_yaml(&text)
        }
    }

    /// The embedded default map — contour's built-in naming schema.
    pub fn embedded() -> Result<Self> {
        Self::from_yaml(EMBEDDED_DEFAULT)
    }

    /// Resolve the map to use. Contour's embedded schema is the default; callers
    /// override it with `--map`, or a repo-local `.contour/name.toml` (TOML) or
    /// `.contour/naming.yaml` (YAML), checked in that order.
    ///
    /// # Errors
    /// Returns an error if an explicitly requested file cannot be read or parsed.
    pub fn resolve(explicit: Option<&Path>) -> Result<Self> {
        if let Some(p) = explicit {
            return Self::from_file(p);
        }
        for candidate in [".contour/name.toml", ".contour/naming.yaml"] {
            let local = Path::new(candidate);
            if local.is_file() {
                return Self::from_file(local);
            }
        }
        Self::embedded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_default_parses() {
        let map = NamingMap::embedded().expect("embedded map parses");
        assert_eq!(map.system_format, "{scope} - {kind} ({subject})");
        assert_eq!(map.app_format, "{scope} - {subject} ({kind})");
        assert_eq!(map.scope.app_label, "App");
        assert_eq!(map.scope.user_label, "User");
        assert_eq!(map.multi_kind_join, " + ");
        assert_eq!(
            map.kinds.get("com.apple.wifi.managed").map(String::as_str),
            Some("Wi-Fi")
        );
        assert_eq!(
            map.kinds
                .get("com.apple.security.pkcs12")
                .map(String::as_str),
            Some("Identity")
        );
    }

    #[test]
    fn kinds_preserve_yaml_order() {
        let map = NamingMap::embedded().unwrap();
        let first = map.kinds.keys().next().map(String::as_str);
        assert_eq!(first, Some("com.apple.wifi.managed"));
    }

    #[test]
    fn subject_rule_variants_parse() {
        let map = NamingMap::embedded().unwrap();
        assert_eq!(
            map.subjects
                .get("com.apple.wifi.managed")
                .unwrap()
                .field
                .as_deref(),
            Some("SSID_STR")
        );
        assert!(
            map.subjects
                .get("com.apple.security.root")
                .unwrap()
                .cert_subject_cn
        );
        assert!(
            map.subjects
                .get("com.apple.ManagedClient.preferences")
                .unwrap()
                .app_name
        );
    }
}
