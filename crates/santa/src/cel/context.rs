//! CEL context building for app records.
//!
//! Converts AppRecord structs into CEL evaluation contexts.

use cel_interpreter::{Context, Value, objects::Key};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An application record from Fleet CSV data.
///
/// This represents a normalized view of an application that can be
/// evaluated against CEL bundle expressions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppRecord {
    /// Application name (e.g., "Google Chrome")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,

    /// Code signing ID (e.g., "EQHXZ8M8AV:com.google.Chrome")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,

    /// Apple Team ID (e.g., "EQHXZ8M8AV")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,

    /// SHA-256 hash of the binary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// Application version string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Bundle identifier (e.g., "com.google.Chrome")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,

    /// Vendor/publisher name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,

    /// File path on the device
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Number of devices this app was seen on
    #[serde(default)]
    pub device_count: usize,

    /// Device names this app was seen on (for debugging)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
}

impl AppRecord {
    /// Create a new empty app record.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set app name.
    #[must_use]
    pub fn with_app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = Some(name.into());
        self
    }

    /// Builder: set signing ID.
    #[must_use]
    pub fn with_signing_id(mut self, id: impl Into<String>) -> Self {
        self.signing_id = Some(id.into());
        self
    }

    /// Builder: set team ID.
    #[must_use]
    pub fn with_team_id(mut self, id: impl Into<String>) -> Self {
        self.team_id = Some(id.into());
        self
    }

    /// Builder: set SHA-256 hash.
    #[must_use]
    pub fn with_sha256(mut self, hash: impl Into<String>) -> Self {
        self.sha256 = Some(hash.into());
        self
    }

    /// Builder: set version.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Builder: set bundle ID.
    #[must_use]
    pub fn with_bundle_id(mut self, id: impl Into<String>) -> Self {
        self.bundle_id = Some(id.into());
        self
    }

    /// Builder: set vendor.
    #[must_use]
    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Builder: set path.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Builder: set device count.
    #[must_use]
    pub fn with_device_count(mut self, count: usize) -> Self {
        self.device_count = count;
        self
    }

    /// Builder: add a device.
    #[must_use]
    pub fn with_device(mut self, device: impl Into<String>) -> Self {
        self.devices.push(device.into());
        self.device_count = self.devices.len();
        self
    }

    /// Get a display name for the app.
    pub fn display_name(&self) -> String {
        self.app_name
            .as_ref()
            .or(self.bundle_id.as_ref())
            .or(self.signing_id.as_ref())
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string())
    }

    /// Get the best available identifier for Santa rules.
    ///
    /// Prefers TeamID > SigningID > SHA256.
    pub fn best_identifier(&self) -> Option<(&'static str, &str)> {
        if let Some(team_id) = &self.team_id {
            if is_valid_team_id(team_id) {
                return Some(("TEAMID", team_id));
            }
        }
        if let Some(signing_id) = &self.signing_id {
            if is_valid_signing_id(signing_id) {
                return Some(("SIGNINGID", signing_id));
            }
        }
        if let Some(sha256) = &self.sha256 {
            if is_valid_sha256(sha256) {
                return Some(("BINARY", sha256));
            }
        }
        None
    }

    /// Check if this app has valid code signing information.
    pub fn is_signed(&self) -> bool {
        self.team_id.as_ref().is_some_and(|t| is_valid_team_id(t))
            || self
                .signing_id
                .as_ref()
                .is_some_and(|s| is_valid_signing_id(s))
    }

    /// Convert to a CEL evaluation context.
    pub fn to_cel_context(&self) -> Context<'_> {
        let mut ctx = Context::default();

        // Build the "app" map
        let mut app_map: HashMap<Key, Value> = HashMap::new();

        if let Some(name) = &self.app_name {
            app_map.insert(Key::from("app_name"), Value::String(name.clone().into()));
        }
        if let Some(id) = &self.signing_id {
            app_map.insert(Key::from("signing_id"), Value::String(id.clone().into()));
        }
        if let Some(id) = &self.team_id {
            app_map.insert(Key::from("team_id"), Value::String(id.clone().into()));
        }
        if let Some(hash) = &self.sha256 {
            app_map.insert(Key::from("sha256"), Value::String(hash.clone().into()));
        }
        if let Some(ver) = &self.version {
            app_map.insert(Key::from("version"), Value::String(ver.clone().into()));
        }
        if let Some(id) = &self.bundle_id {
            app_map.insert(Key::from("bundle_id"), Value::String(id.clone().into()));
        }
        if let Some(vendor) = &self.vendor {
            app_map.insert(Key::from("vendor"), Value::String(vendor.clone().into()));
        }
        if let Some(path) = &self.path {
            app_map.insert(Key::from("path"), Value::String(path.clone().into()));
        }
        app_map.insert(
            Key::from("device_count"),
            Value::UInt(self.device_count as u64),
        );

        ctx.add_variable("app", Value::Map(app_map.into())).unwrap();
        ctx
    }

    /// Create an app record from Fleet CSV row data.
    pub fn from_csv_row(row: &HashMap<String, String>) -> Self {
        let get = |keys: &[&str]| -> Option<String> {
            for key in keys {
                if let Some(val) = row.get(*key) {
                    let val = val.trim();
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
            None
        };

        Self {
            app_name: get(&["name", "app_name", "software_name", "software_title"]),
            signing_id: get(&["signing_id", "signingid"]),
            team_id: get(&["team_id", "team_identifier", "teamid", "developer_id"]),
            sha256: get(&["sha256", "hash"]),
            version: get(&["version", "software_version"]),
            bundle_id: get(&["bundle_identifier", "bundle_id", "bundleid"]),
            vendor: get(&["vendor", "publisher", "developer", "authority"]),
            path: get(&["path", "source", "install_path"]),
            device_count: 1,
            devices: row
                .get("device_name")
                .or_else(|| row.get("hostname"))
                .map(|s| vec![s.clone()])
                .unwrap_or_default(),
        }
    }
}

/// Check if a string is a valid Apple TeamID (10 alphanumeric characters).
pub fn is_valid_team_id(s: &str) -> bool {
    s.len() == 10 && s.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Check if a string is a valid SigningID (TeamID:BundleID format).
pub fn is_valid_signing_id(s: &str) -> bool {
    if let Some((team_part, bundle_part)) = s.split_once(':') {
        // platform: prefix is also valid
        (is_valid_team_id(team_part) || team_part == "platform") && !bundle_part.is_empty()
    } else {
        false
    }
}

/// Check if a string is a valid SHA-256 hash (64 hex characters).
pub fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// A collection of app records with deduplication support.
#[derive(Debug, Clone, Default)]
pub struct AppRecordSet {
    apps: Vec<AppRecord>,
}

impl AppRecordSet {
    /// Create an empty set.
    pub fn new() -> Self {
        Self { apps: Vec::new() }
    }

    /// Add an app record to the set.
    pub fn add(&mut self, app: AppRecord) {
        self.apps.push(app);
    }

    /// Get all apps.
    pub fn apps(&self) -> &[AppRecord] {
        &self.apps
    }

    /// Number of apps.
    pub fn len(&self) -> usize {
        self.apps.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }

    /// Iterate over apps.
    pub fn iter(&self) -> std::slice::Iter<'_, AppRecord> {
        self.apps.iter()
    }

    /// Deduplicate by signing ID, merging device information.
    pub fn dedup_by_signing_id(&mut self) {
        self.dedup_by_key(|app| app.signing_id.clone());
    }

    /// Deduplicate by team ID, merging device information.
    pub fn dedup_by_team_id(&mut self) {
        self.dedup_by_key(|app| app.team_id.clone());
    }

    /// Deduplicate by SHA-256, merging device information.
    pub fn dedup_by_sha256(&mut self) {
        self.dedup_by_key(|app| app.sha256.clone());
    }

    /// Generic deduplication by key, merging device counts.
    fn dedup_by_key<F>(&mut self, key_fn: F)
    where
        F: Fn(&AppRecord) -> Option<String>,
    {
        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut result: Vec<AppRecord> = Vec::new();

        for app in std::mem::take(&mut self.apps) {
            if let Some(key) = key_fn(&app) {
                if let Some(&idx) = seen.get(&key) {
                    // Merge with existing
                    result[idx].device_count += app.device_count;
                    result[idx].devices.extend(app.devices);
                } else {
                    seen.insert(key, result.len());
                    result.push(app);
                }
            } else {
                // No key, keep as-is
                result.push(app);
            }
        }

        self.apps = result;
    }

    /// Sort apps by device count (descending).
    pub fn sort_by_device_count(&mut self) {
        self.apps
            .sort_by(|a, b| b.device_count.cmp(&a.device_count));
    }

    /// Sort apps by app name.
    pub fn sort_by_name(&mut self) {
        self.apps.sort_by(|a, b| {
            a.display_name()
                .to_lowercase()
                .cmp(&b.display_name().to_lowercase())
        });
    }

    /// Consume and return the inner apps.
    pub fn into_apps(self) -> Vec<AppRecord> {
        self.apps
    }
}

impl IntoIterator for AppRecordSet {
    type Item = AppRecord;
    type IntoIter = std::vec::IntoIter<AppRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.apps.into_iter()
    }
}

impl<'a> IntoIterator for &'a AppRecordSet {
    type Item = &'a AppRecord;
    type IntoIter = std::slice::Iter<'a, AppRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.apps.iter()
    }
}

impl Extend<AppRecord> for AppRecordSet {
    fn extend<T: IntoIterator<Item = AppRecord>>(&mut self, iter: T) {
        self.apps.extend(iter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_record_builder() {
        let app = AppRecord::new()
            .with_app_name("Chrome")
            .with_team_id("EQHXZ8M8AV")
            .with_signing_id("EQHXZ8M8AV:com.google.Chrome")
            .with_device_count(100);

        assert_eq!(app.app_name, Some("Chrome".to_string()));
        assert_eq!(app.device_count, 100);
    }

    #[test]
    fn test_is_valid_team_id() {
        assert!(is_valid_team_id("EQHXZ8M8AV"));
        assert!(is_valid_team_id("UBF8T346G9"));
        assert!(!is_valid_team_id("short"));
        assert!(!is_valid_team_id("toolongstring"));
        assert!(!is_valid_team_id("has spaces"));
    }

    #[test]
    fn test_is_valid_signing_id() {
        assert!(is_valid_signing_id("EQHXZ8M8AV:com.google.Chrome"));
        assert!(is_valid_signing_id("platform:com.apple.Safari"));
        assert!(!is_valid_signing_id("nocolon"));
        assert!(!is_valid_signing_id(":nobundle"));
        assert!(!is_valid_signing_id("short:com.test"));
    }

    #[test]
    fn test_is_valid_sha256() {
        let valid = "a".repeat(64);
        assert!(is_valid_sha256(&valid));

        let invalid_short = "a".repeat(32);
        assert!(!is_valid_sha256(&invalid_short));

        let invalid_chars = "g".repeat(64); // 'g' is not hex
        assert!(!is_valid_sha256(&invalid_chars));
    }

    #[test]
    fn test_best_identifier() {
        let app_full = AppRecord::new()
            .with_team_id("EQHXZ8M8AV")
            .with_signing_id("EQHXZ8M8AV:com.google.Chrome")
            .with_sha256("a".repeat(64));

        // Should prefer TeamID
        assert_eq!(app_full.best_identifier(), Some(("TEAMID", "EQHXZ8M8AV")));

        // Without TeamID, should use SigningID
        let app_signing = AppRecord::new()
            .with_signing_id("EQHXZ8M8AV:com.google.Chrome")
            .with_sha256("a".repeat(64));
        assert_eq!(
            app_signing.best_identifier(),
            Some(("SIGNINGID", "EQHXZ8M8AV:com.google.Chrome"))
        );
    }

    #[test]
    fn test_dedup_by_team_id() {
        let mut set = AppRecordSet::new();
        set.add(
            AppRecord::new()
                .with_team_id("EQHXZ8M8AV")
                .with_app_name("Chrome")
                .with_device_count(10),
        );
        set.add(
            AppRecord::new()
                .with_team_id("EQHXZ8M8AV")
                .with_app_name("Chrome Beta")
                .with_device_count(5),
        );
        set.add(
            AppRecord::new()
                .with_team_id("UBF8T346G9")
                .with_app_name("Word")
                .with_device_count(20),
        );

        set.dedup_by_team_id();

        assert_eq!(set.len(), 2);
        let google = set
            .apps()
            .iter()
            .find(|a| a.team_id.as_deref() == Some("EQHXZ8M8AV"))
            .unwrap();
        assert_eq!(google.device_count, 15); // Merged
    }

    #[test]
    fn test_cel_context() {
        let app = AppRecord::new()
            .with_team_id("EQHXZ8M8AV")
            .with_app_name("Chrome");

        let _ctx = app.to_cel_context();
        // Context is created without panicking
    }
}
