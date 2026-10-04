//! Notification configuration types — notifications.toml format.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Type alias — notification settings use the shared config settings from core.
pub type NotificationSettings = contour_core::ConfigSettings;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub settings: NotificationSettings,
    #[serde(default)]
    pub apps: Vec<NotificationAppEntry>,
}

/// `GroupingType` — how notifications from this app are grouped.
///
/// Accepts the integers Apple documents or the readable names, so a TOML
/// author need not memorise the numbering:
///
/// | value | name | Apple's description |
/// |---|---|---|
/// | 0 | `automatic` | group into app-specified groups |
/// | 1 | `by_app` | group into one group |
/// | 2 | `off` | don't group |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GroupingType {
    Number(u8),
    Name(GroupingName),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupingName {
    Automatic,
    ByApp,
    Off,
}

impl GroupingType {
    /// The integer Apple expects, or `None` when a number is out of range.
    pub fn to_apple(self) -> Option<i64> {
        match self {
            GroupingType::Number(n @ 0..=2) => Some(i64::from(n)),
            GroupingType::Number(_) => None,
            GroupingType::Name(GroupingName::Automatic) => Some(0),
            GroupingType::Name(GroupingName::ByApp) => Some(1),
            GroupingType::Name(GroupingName::Off) => Some(2),
        }
    }
}

/// `PreviewType` — when notification previews are shown.
///
/// Overrides Settings > Notifications > Show Previews. The names are the
/// ones `--sop notifications` already documented.
///
/// | value | name | Apple's description |
/// |---|---|---|
/// | 0 | `always` | previews when locked and unlocked |
/// | 1 | `when_unlocked` | previews only when unlocked |
/// | 2 | `never` | never show previews |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PreviewType {
    Number(u8),
    Name(PreviewName),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewName {
    Always,
    WhenUnlocked,
    Never,
}

impl PreviewType {
    /// The integer Apple expects, or `None` when a number is out of range.
    pub fn to_apple(self) -> Option<i64> {
        match self {
            PreviewType::Number(n @ 0..=2) => Some(i64::from(n)),
            PreviewType::Number(_) => None,
            PreviewType::Name(PreviewName::Always) => Some(0),
            PreviewType::Name(PreviewName::WhenUnlocked) => Some(1),
            PreviewType::Name(PreviewName::Never) => Some(2),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Per-app notification settings.
pub struct NotificationAppEntry {
    pub name: String,
    pub bundle_id: String,
    #[serde(default = "default_true")]
    pub alerts_enabled: bool,
    /// 0 = None, 1 = Temporary Banner, 2 = Persistent Banner
    #[serde(default = "default_alert_type")]
    pub alert_type: u8,
    #[serde(default = "default_true")]
    pub badges_enabled: bool,
    #[serde(default = "default_true")]
    pub critical_alerts: bool,
    #[serde(default = "default_true")]
    pub lock_screen: bool,
    #[serde(default = "default_true")]
    pub notification_center: bool,
    #[serde(default)]
    pub sounds_enabled: bool,

    /// `GroupingType`. Omitted from the profile when unset: emitting
    /// Apple's default (0, Automatic) would override an app's own grouping
    /// on every profile contour generates, which is not what an operator
    /// who never mentioned grouping asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grouping_type: Option<GroupingType>,

    /// `PreviewType`. Omitted when unset, for the same reason — it
    /// overrides a system-wide user setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_type: Option<PreviewType>,

    /// `ShowInCarPlay`. Omitted when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_in_car_play: Option<bool>,
}

fn default_true() -> bool {
    true
}
fn default_alert_type() -> u8 {
    1
}

impl NotificationConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {e}", path.display()))?;
        toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse notifications.toml: {e}"))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize notifications.toml: {e}"))?;
        let with_header = format!(
            "# Notification Settings Definitions\n\
             # Generated by: contour notifications\n\
             # Edit manually or re-run scan to update\n\n\
             {content}"
        );
        std::fs::write(path, with_header)
            .map_err(|e| anyhow::anyhow!("Failed to write {}: {e}", path.display()))
    }
}

impl NotificationAppEntry {
    /// Create a new entry with all notifications enabled (sensible defaults).
    pub fn new(name: String, bundle_id: String) -> Self {
        Self {
            name,
            bundle_id,
            alerts_enabled: true,
            alert_type: 1,
            badges_enabled: true,
            critical_alerts: true,
            lock_screen: true,
            notification_center: true,
            sounds_enabled: false,
            // Unset by default: these override user-visible system settings,
            // so `scan` should not take them over without being asked.
            grouping_type: None,
            preview_type: None,
            show_in_car_play: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_config_roundtrip() {
        let config = NotificationConfig {
            settings: NotificationSettings {
                org: "com.example".to_string(),
                display_name: Some("Test".to_string()),
            },
            apps: vec![NotificationAppEntry {
                name: "Slack".to_string(),
                bundle_id: "com.tinyspeck.slackmacgap".to_string(),
                alerts_enabled: true,
                alert_type: 2,
                badges_enabled: true,
                critical_alerts: false,
                lock_screen: true,
                notification_center: true,
                sounds_enabled: true,
                grouping_type: None,
                preview_type: None,
                show_in_car_play: None,
            }],
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: NotificationConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.settings.org, "com.example");
        assert_eq!(parsed.apps.len(), 1);
        assert_eq!(parsed.apps[0].alert_type, 2);
        assert!(parsed.apps[0].sounds_enabled);
        assert!(!parsed.apps[0].critical_alerts);
    }

    #[test]
    fn test_notification_app_entry_defaults() {
        let entry = NotificationAppEntry::new("Test".to_string(), "com.test".to_string());
        assert!(entry.alerts_enabled);
        assert_eq!(entry.alert_type, 1);
        assert!(entry.badges_enabled);
        assert!(entry.critical_alerts);
        assert!(entry.lock_screen);
        assert!(entry.notification_center);
        assert!(!entry.sounds_enabled);
    }
}
