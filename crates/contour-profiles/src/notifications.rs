use plist::{Dictionary, Value};

/// Build a notification settings entry for a single application.
///
/// Creates the dictionary structure expected inside the `NotificationSettings`
/// array of a `com.apple.notificationsettings` payload.
pub fn build_notification_entry(bundle_id: &str) -> Dictionary {
    // Key order follows Apple's device-management spec:
    // github.com/apple/device-management → mdm/profiles/com.apple.notificationsettings.yaml
    let mut notification = Dictionary::new();
    notification.insert(
        "BundleIdentifier".to_string(),
        Value::String(bundle_id.to_string()),
    );
    notification.insert("NotificationsEnabled".to_string(), Value::Boolean(true));
    notification.insert("ShowInNotificationCenter".to_string(), Value::Boolean(true));
    notification.insert("ShowInLockScreen".to_string(), Value::Boolean(true));
    notification.insert(
        "AlertType".to_string(),
        Value::Integer(1.into()), // 1 = Temporary Banner
    );
    notification.insert("BadgesEnabled".to_string(), Value::Boolean(true));
    notification.insert("SoundsEnabled".to_string(), Value::Boolean(false));
    notification.insert("CriticalAlertEnabled".to_string(), Value::Boolean(true));
    notification
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_notification_entry() {
        let entry = build_notification_entry("com.example.app");
        assert_eq!(
            entry.get("BundleIdentifier").unwrap().as_string().unwrap(),
            "com.example.app"
        );
        assert!(
            entry
                .get("NotificationsEnabled")
                .unwrap()
                .as_boolean()
                .unwrap()
        );
        assert_eq!(
            entry.get("AlertType").unwrap().as_signed_integer().unwrap(),
            1
        );
    }
}
