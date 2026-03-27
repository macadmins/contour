//! Notifications init command — create a blank notifications.toml.

use crate::cli::{OutputMode, print_json, print_success};
use crate::config::{NotificationConfig, NotificationSettings};
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

/// JSON output for the init command.
#[derive(Serialize)]
struct InitResult {
    path: String,
    created: bool,
}

/// Run the notifications init command.
///
/// Creates a notifications.toml pre-configured for notification settings work.
pub fn run(
    output: &Path,
    org: Option<&str>,
    name: Option<&str>,
    force: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "File already exists: {}. Use --force to overwrite.",
            output.display()
        );
    }

    let org = org.unwrap_or("com.example");

    let config = NotificationConfig {
        settings: NotificationSettings {
            org: org.to_string(),
            display_name: name.map(String::from),
        },
        apps: vec![],
    };

    config.save(output)?;

    if output_mode == OutputMode::Json {
        print_json(&InitResult {
            path: output.display().to_string(),
            created: true,
        })?;
    }

    if output_mode == OutputMode::Human {
        print_success(&format!(
            "Created notification settings file: {}",
            output.display()
        ));
        println!();
        println!("Next steps:");
        println!(
            "  1. Scan apps: contour notifications scan --org {} -o {}",
            org,
            output.display()
        );
        println!(
            "  2. Configure: contour notifications configure {}",
            output.display()
        );
        println!(
            "  3. Generate profiles: contour notifications generate {}",
            output.display()
        );
    }

    Ok(())
}
