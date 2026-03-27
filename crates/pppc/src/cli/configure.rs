//! Interactive configuration of an existing pppc.toml policy file.
//!
//! Walks through each app entry and lets the user toggle TCC services.

use crate::pppc::{PppcConfig, PppcService};
use anyhow::{Context, Result};
use colored::Colorize;
use inquire::{Confirm, InquireError, MultiSelect};
use std::path::Path;

/// Catch Esc / Ctrl+C from inquire prompts and break the labelled loop
/// instead of propagating the error.
macro_rules! prompt_or_break {
    ($expr:expr, $label:lifetime) => {
        match $expr {
            Ok(val) => val,
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
                break $label;
            }
            Err(e) => return Err(e.into()),
        }
    };
}

/// Run the interactive configure walkthrough on an existing pppc.toml.
pub fn run(input: &Path, skip_configured: bool) -> Result<()> {
    let mut config =
        PppcConfig::load(input).with_context(|| format!("Failed to load {}", input.display()))?;

    if config.apps.is_empty() {
        println!("{} No apps in {}", "!".yellow(), input.display());
        return Ok(());
    }

    println!();
    println!("{}", "PPPC Policy Configuration".bold().cyan());
    println!("{}", "=".repeat(50));
    println!();
    println!(
        "Walking through {} app(s) in {}",
        config.apps.len(),
        input.display()
    );
    println!("For each app, toggle TCC services.");
    println!("Press Enter to keep current values, or change them.");
    if skip_configured {
        println!(
            "{} Skipping already-configured apps (--skip-configured)",
            "→".dimmed()
        );
    }
    println!("Press Esc to stop and save progress so far.");
    println!();

    let all_services = PppcService::all();
    let mut service_options: Vec<String> = Vec::with_capacity(all_services.len() + 1);
    service_options.push(super::ALL_SERVICES_LABEL.to_string());
    service_options.extend(all_services.iter().map(|s| {
        let suffix = if s.is_deny_only() {
            " [deny only]"
        } else if s.supports_standard_user_set() {
            " [standard user settable]"
        } else {
            ""
        };
        format!("{} ({}){}", s.display_name(), s.key(), suffix)
    }));

    let mut changed = false;
    let app_count = config.apps.len();
    let mut last_index = 0;

    'apps: for i in 0..app_count {
        last_index = i;

        // Skip already-configured apps when --skip-configured is set
        if skip_configured && config.apps[i].is_configured() {
            println!(
                "{} {} [{}/{}] {}",
                "→".dimmed(),
                config.apps[i].name.cyan(),
                i + 1,
                app_count,
                "(already configured, skipping)".dimmed()
            );
            continue;
        }

        println!(
            "{} {} [{}/{}]",
            "App:".bold(),
            config.apps[i].name.cyan(),
            i + 1,
            app_count
        );
        println!("  Bundle ID: {}", config.apps[i].bundle_id.dimmed());

        // Show current state
        if config.apps[i].services.is_empty() {
            println!("  Services: {}", "none".dimmed());
        } else {
            let svc_names: Vec<&str> = config.apps[i]
                .services
                .iter()
                .map(super::super::pppc::PppcService::display_name)
                .collect();
            println!("  Services: {}", svc_names.join(", "));
        }
        println!();

        // Ask if they want to configure this app
        let configure = prompt_or_break!(
            Confirm::new(&format!("Configure {}?", config.apps[i].name))
                .with_default(false)
                .with_help_message("No = keep current settings, Yes = change")
                .prompt(),
            'apps
        );

        if !configure {
            println!("  {} Keeping current settings", "→".dimmed());
            println!();
            continue;
        }

        // TCC services — pre-select current ones (offset by 1 for the sentinel)
        let mut defaults: Vec<usize> = config.apps[i]
            .services
            .iter()
            .filter_map(|s| all_services.iter().position(|a| a == s).map(|idx| idx + 1))
            .collect();
        // If all services are already selected, also check the sentinel
        if defaults.len() == all_services.len() {
            defaults.insert(0, 0);
        }

        let selected = prompt_or_break!(
            MultiSelect::new(
                &format!("TCC services for {}:", config.apps[i].name),
                service_options.clone(),
            )
            .with_default(&defaults)
            .with_page_size(12)
            .with_help_message("Space to toggle, Enter to confirm (first item selects all)")
            .prompt(),
            'apps
        );

        let new_services: Vec<PppcService> = if selected
            .iter()
            .any(|name| name == super::ALL_SERVICES_LABEL)
        {
            all_services.to_vec()
        } else {
            selected
                .iter()
                .filter_map(|name| {
                    all_services
                        .iter()
                        .enumerate()
                        .find(|(idx, _)| &service_options[idx + 1] == name)
                        .map(|(_, s)| *s)
                })
                .collect()
        };

        // Warn about deny-only services
        let deny_only: Vec<_> = new_services.iter().filter(|s| s.is_deny_only()).collect();
        if !deny_only.is_empty() {
            let names: Vec<_> = deny_only.iter().map(|s| s.display_name()).collect();
            println!(
                "  {} {}: profile will deny (not grant) access per Apple spec",
                "!".yellow(),
                names.join(", ")
            );
        }

        // Apply changes
        let app = &mut config.apps[i];
        if new_services != app.services {
            app.services = new_services;
            changed = true;
            println!("  {} Updated", "✓".green());
        } else {
            println!("  {} No changes", "→".dimmed());
        }

        // Save after each app so progress is never lost
        if changed {
            config.save(input)?;
        }

        println!();
    }

    // Adaptive summary message
    let completed_all = last_index + 1 == app_count;
    if changed {
        if completed_all {
            println!("{} All changes saved to {}", "✓".green(), input.display());
        } else {
            println!();
            println!(
                "{} Saved progress ({}/{} apps visited). Re-run with {} to continue.",
                "✓".green(),
                last_index + 1,
                app_count,
                "--skip-configured".bold()
            );
        }
    } else if !completed_all {
        println!();
        println!("{} Stopped early — no changes made.", "→".dimmed());
    } else {
        println!("{}", "No changes made.".dimmed());
    }

    Ok(())
}
