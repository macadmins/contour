//! Notification profile generation.

use crate::config::NotificationAppEntry;
use anyhow::Result;
use contour_profiles::ProfileBuilder;
use plist::{Dictionary, Value};

fn sanitize_id(s: &str) -> String {
    s.replace(['.', '-'], "_")
}

/// Build a notification settings plist entry from per-app settings.
pub fn build_notification_entry_from_config(app: &NotificationAppEntry) -> Dictionary {
    // Key order follows Apple's device-management spec:
    // github.com/apple/device-management → mdm/profiles/com.apple.notificationsettings.yaml
    let mut entry = Dictionary::new();
    entry.insert(
        "BundleIdentifier".to_string(),
        Value::String(app.bundle_id.clone()),
    );
    entry.insert(
        "NotificationsEnabled".to_string(),
        Value::Boolean(app.alerts_enabled),
    );
    entry.insert(
        "ShowInNotificationCenter".to_string(),
        Value::Boolean(app.notification_center),
    );
    entry.insert(
        "ShowInLockScreen".to_string(),
        Value::Boolean(app.lock_screen),
    );
    entry.insert(
        "AlertType".to_string(),
        Value::Integer(app.alert_type.into()),
    );
    entry.insert(
        "BadgesEnabled".to_string(),
        Value::Boolean(app.badges_enabled),
    );
    entry.insert(
        "SoundsEnabled".to_string(),
        Value::Boolean(app.sounds_enabled),
    );
    entry.insert(
        "CriticalAlertEnabled".to_string(),
        Value::Boolean(app.critical_alerts),
    );
    entry
}

/// Generate a notification settings mobileconfig for a single app.
pub fn generate_notification_profile(app: &NotificationAppEntry, org: &str) -> Result<Vec<u8>> {
    let profile_id = format!("{}.notifications.{}", org, sanitize_id(&app.bundle_id));
    let notification = build_notification_entry_from_config(app);

    let mut payload_content = Dictionary::new();
    payload_content.insert(
        "NotificationSettings".to_string(),
        Value::Array(vec![Value::Dictionary(notification)]),
    );

    ProfileBuilder::new(org, &profile_id)
        .display_name(&format!("{} Notifications", app.name))
        .description(&format!("Notification settings for {}", app.name))
        .removal_disallowed(true)
        .build("com.apple.notificationsettings", payload_content)
}

/// Generate a combined notification settings mobileconfig for multiple apps.
pub fn generate_combined_notification_profile(
    apps: &[NotificationAppEntry],
    org: &str,
    display_name: Option<&str>,
) -> Result<Vec<u8>> {
    let profile_id = format!("{org}.notifications");

    let entries: Vec<Value> = apps
        .iter()
        .map(|app| Value::Dictionary(build_notification_entry_from_config(app)))
        .collect();

    let mut payload_content = Dictionary::new();
    payload_content.insert("NotificationSettings".to_string(), Value::Array(entries));

    let name = display_name.unwrap_or("Notification Settings");
    ProfileBuilder::new(org, &profile_id)
        .display_name(name)
        .description("Managed notification settings")
        .removal_disallowed(true)
        .build("com.apple.notificationsettings", payload_content)
}

// Re-export shared utilities so existing `crate::generate::sanitize_filename` paths keep working.
pub use contour_core::{resolve_output_dir, sanitize_filename};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NotificationAppEntry;

    #[test]
    fn test_single_notification_profile() {
        let app = NotificationAppEntry {
            name: "Slack".to_string(),
            bundle_id: "com.tinyspeck.slackmacgap".to_string(),
            alerts_enabled: true,
            alert_type: 2,
            badges_enabled: true,
            critical_alerts: false,
            lock_screen: true,
            notification_center: true,
            sounds_enabled: true,
        };
        let result = generate_notification_profile(&app, "com.example");
        assert!(result.is_ok());
        let content = String::from_utf8(result.unwrap()).unwrap();
        assert!(content.contains("com.apple.notificationsettings"));
        assert!(content.contains("com.tinyspeck.slackmacgap"));
        assert!(content.contains("NotificationsEnabled"));
        assert!(content.contains("BadgesEnabled"));
        assert!(content.contains("CriticalAlertEnabled"));
        assert!(content.contains("SoundsEnabled"));
    }

    #[test]
    fn test_combined_notification_profile() {
        let apps = vec![
            NotificationAppEntry::new("Slack".to_string(), "com.slack".to_string()),
            NotificationAppEntry::new("Zoom".to_string(), "us.zoom.xos".to_string()),
        ];
        let result = generate_combined_notification_profile(&apps, "com.example", None);
        assert!(result.is_ok());
        let content = String::from_utf8(result.unwrap()).unwrap();
        assert!(content.contains("com.slack"));
        assert!(content.contains("us.zoom.xos"));
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("Zoom Workplace"), "zoom-workplace");
        assert_eq!(sanitize_filename("1Password 8"), "1password-8");
    }
}
