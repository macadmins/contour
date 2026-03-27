//! Notifications configure command — interactively configure per-app notification settings.

use crate::cli::{print_info, print_success};
use crate::config::NotificationConfig;
use anyhow::Result;
use std::path::Path;

/// Run the notifications configure command.
///
/// Walks through each app in the config and lets the user toggle
/// notification settings field by field.
pub fn run(input: &Path) -> Result<()> {
    let mut config = NotificationConfig::load(input)?;

    if config.apps.is_empty() {
        anyhow::bail!(
            "No apps in {}. Run 'notifications scan' first.",
            input.display()
        );
    }

    print_info(&format!(
        "Configuring notification settings for {} app(s)...",
        config.apps.len()
    ));
    println!();

    for app in &mut config.apps {
        println!("--- {} ({}) ---", app.name, app.bundle_id);

        app.alerts_enabled = inquire::Confirm::new("  Alerts enabled?")
            .with_default(app.alerts_enabled)
            .prompt()?;

        let alert_type_options = vec!["None (0)", "Temporary Banner (1)", "Persistent Banner (2)"];
        let default_idx = usize::from(app.alert_type).min(2);
        let alert_type_selection =
            inquire::Select::new("  Alert type:", alert_type_options.clone())
                .with_starting_cursor(default_idx)
                .prompt()?;
        app.alert_type = alert_type_options
            .iter()
            .position(|o| *o == alert_type_selection)
            .unwrap_or(1) as u8;

        app.badges_enabled = inquire::Confirm::new("  Badges enabled?")
            .with_default(app.badges_enabled)
            .prompt()?;

        app.critical_alerts = inquire::Confirm::new("  Critical alerts?")
            .with_default(app.critical_alerts)
            .prompt()?;

        app.lock_screen = inquire::Confirm::new("  Show on lock screen?")
            .with_default(app.lock_screen)
            .prompt()?;

        app.notification_center = inquire::Confirm::new("  Show in notification center?")
            .with_default(app.notification_center)
            .prompt()?;

        app.sounds_enabled = inquire::Confirm::new("  Sounds enabled?")
            .with_default(app.sounds_enabled)
            .prompt()?;

        println!();
    }

    config.save(input)?;
    print_success(&format!(
        "Saved notification settings to {}",
        input.display()
    ));

    Ok(())
}
