//! Interactive wizard for generating Support App mobileconfig profiles.
//!
//! Guides the user through a Q&A flow and produces a working mobileconfig
//! directly — no intermediate TOML file needed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use contour_core::{OutputMode, print_info, print_success};

use crate::config::{BrandEntry, ButtonItemDef, CommonSettings, RowDef, SupportConfig};
use crate::generator;

/// Run the interactive Support App wizard.
pub fn run_wizard(
    output: Option<&Path>,
    org: Option<&str>,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    println!(
        "\n{}\n{}",
        "Support App Wizard".bold(),
        "════════════════════".dimmed()
    );
    println!(
        "{}\n",
        "Generate a Support App mobileconfig profile interactively.".dimmed()
    );

    // ── 1. Organization ──────────────────────────────────────────────
    let org_default = org
        .map(String::from)
        .or_else(|| contour_core::ContourConfig::load_nearest().map(|c| c.organization.domain))
        .unwrap_or_default();

    let org_value = inquire::Text::new("Organization identifier:")
        .with_default(&org_default)
        .with_help_message("Reverse-domain org, e.g. com.example")
        .prompt()
        .context("Cancelled")?;

    // ── 2. Profile display name ──────────────────────────────────────
    let display_name = inquire::Text::new("Profile display name:")
        .with_default("Support App Configuration")
        .prompt()
        .context("Cancelled")?;

    // ── 3. Title ─────────────────────────────────────────────────────
    let title = inquire::Text::new("App title:")
        .with_default("IT Support")
        .prompt()
        .context("Cancelled")?;

    // ── 4. Asset base path ───────────────────────────────────────────
    let default_base = format!("/Library/Application Support/{}/", org_value);
    let base_path = inquire::Text::new("Asset base path:")
        .with_default(&default_base)
        .with_help_message("Directory containing logo, logo_darkmode, and menubar icon")
        .prompt()
        .context("Cancelled")?;

    let base = PathBuf::from(&base_path);
    let logo = base.join("logo.png");
    let logo_darkmode = base.join("logo_darkmode.png");
    let menubar_icon = base.join("support-app-menubar-icon.png");

    println!(
        "  {} logo = {}",
        "→".dimmed(),
        logo.display().to_string().dimmed()
    );
    println!(
        "  {} logo_darkmode = {}",
        "→".dimmed(),
        logo_darkmode.display().to_string().dimmed()
    );
    println!(
        "  {} menubar_icon = {}\n",
        "→".dimmed(),
        menubar_icon.display().to_string().dimmed()
    );

    // ── 5. Custom colors ─────────────────────────────────────────────
    let custom_color = inquire::Text::new("Custom color (hex, e.g. #05164D):")
        .with_help_message("Press Enter to skip")
        .with_default("")
        .prompt()
        .context("Cancelled")?;
    let custom_color = if custom_color.is_empty() {
        None
    } else {
        Some(custom_color)
    };

    let custom_color_darkmode = if custom_color.is_some() {
        let c = inquire::Text::new("Custom color dark mode (hex):")
            .with_help_message("Press Enter to use same as light mode")
            .with_default("")
            .prompt()
            .context("Cancelled")?;
        if c.is_empty() { None } else { Some(c) }
    } else {
        None
    };

    // ── 6. Info items ────────────────────────────────────────────────
    let info_options = vec![
        "ComputerName",
        "MacOSVersion",
        "Uptime",
        "Storage",
        "Network",
        "Password",
    ];
    let default_info = vec![0, 1, 2, 3]; // ComputerName, MacOSVersion, Uptime, Storage

    let selected_info = inquire::MultiSelect::new("Info items to display:", info_options.clone())
        .with_default(&default_info)
        .with_vim_mode(true)
        .prompt()
        .context("Cancelled")?;

    let info_items: Vec<String> = selected_info.iter().map(|s| s.to_string()).collect();
    let has_uptime = info_items.iter().any(|s| s == "Uptime");

    // ── 7. Uptime limit ──────────────────────────────────────────────
    let uptime_days_limit = if has_uptime {
        let limit = inquire::Text::new("Uptime warning threshold (days):")
            .with_default("21")
            .with_help_message("Show warning when uptime exceeds this many days")
            .prompt()
            .context("Cancelled")?;
        Some(limit.parse::<u32>().unwrap_or(21))
    } else {
        None
    };

    // ── 8. Footer text ───────────────────────────────────────────────
    let default_footer = format!("Managed by {}", org_value);
    let footer_text = inquire::Text::new("Footer text:")
        .with_default(&default_footer)
        .prompt()
        .context("Cancelled")?;

    // ── 9. Buttons ───────────────────────────────────────────────────
    let button_presets = vec!["Help Desk", "Knowledge Base", "IT Settings", "Report Issue"];
    let default_buttons = vec![0, 1]; // Help Desk + Knowledge Base

    let selected_buttons =
        inquire::MultiSelect::new("Button presets to include:", button_presets.clone())
            .with_default(&default_buttons)
            .with_vim_mode(true)
            .prompt()
            .context("Cancelled")?;

    let mut button_items: Vec<ButtonItemDef> = Vec::new();
    for preset in &selected_buttons {
        let (default_title, default_subtitle, symbol) = match *preset {
            "Help Desk" => ("Help Desk", "Contact IT support", "phone.fill"),
            "Knowledge Base" => ("Knowledge Base", "Browse articles", "book.fill"),
            "IT Settings" => ("IT Settings", "Open preferences", "gear"),
            "Report Issue" => (
                "Report Issue",
                "Submit a ticket",
                "exclamationmark.bubble.fill",
            ),
            _ => continue,
        };

        let url = inquire::Text::new(&format!("URL for '{}':", preset))
            .with_help_message("e.g. https://support.example.com")
            .prompt()
            .context("Cancelled")?;

        button_items.push(ButtonItemDef {
            title: default_title.to_string(),
            subtitle: default_subtitle.to_string(),
            symbol: symbol.to_string(),
            item_type: "URL".to_string(),
            link: if url.is_empty() { None } else { Some(url) },
        });
    }

    let rows = if button_items.is_empty() {
        vec![]
    } else {
        vec![RowDef {
            items: button_items,
        }]
    };

    // ── 10. Feature toggles ──────────────────────────────────────────
    let toggle_options = vec![
        "Show welcome screen",
        "Open at login",
        "Notification badge",
        "Color menu bar icon",
    ];
    let default_toggles = vec![0, 2]; // welcome screen + notification badge

    let selected_toggles = inquire::MultiSelect::new("Feature toggles:", toggle_options.clone())
        .with_default(&default_toggles)
        .with_vim_mode(true)
        .prompt()
        .context("Cancelled")?;

    let show_welcome_screen = selected_toggles.contains(&"Show welcome screen");
    let open_at_login = selected_toggles.contains(&"Open at login");
    let notifier_enabled = selected_toggles.contains(&"Notification badge");
    let color_icon = selected_toggles.contains(&"Color menu bar icon");

    // ── 11. Output path ──────────────────────────────────────────────
    let default_output = output
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "support.mobileconfig".to_string());

    let output_path = inquire::Text::new("Output file:")
        .with_default(&default_output)
        .prompt()
        .context("Cancelled")?;
    let output_path = PathBuf::from(output_path);

    // ── Summary ──────────────────────────────────────────────────────
    println!("\n{}", "Summary".bold());
    println!("{}", "───────────────────".dimmed());
    println!("  {} {}: {}", "✓".green(), "Org".dimmed(), org_value);
    println!("  {} {}: {}", "✓".green(), "Title".dimmed(), title);
    println!(
        "  {} {}: {}",
        "✓".green(),
        "Info items".dimmed(),
        info_items.join(", ")
    );
    if let Some(ref c) = custom_color {
        println!("  {} {}: {}", "✓".green(), "Color".dimmed(), c);
    }
    if !rows.is_empty() {
        let names: Vec<&str> = rows[0].items.iter().map(|b| b.title.as_str()).collect();
        println!(
            "  {} {}: {}",
            "✓".green(),
            "Buttons".dimmed(),
            names.join(", ")
        );
    }
    println!(
        "  {} {}: {}",
        "✓".green(),
        "Output".dimmed(),
        output_path.display()
    );

    // ── Build config and generate ────────────────────────────────────
    let config = SupportConfig {
        common: CommonSettings {
            org: org_value,
            payload_display_name: display_name,
            error_message: "Please contact IT support".to_string(),
            footer_text,
            password_type: "Apple".to_string(),
            storage_limit: 90,
            show_welcome_screen,
            open_at_login,
            disable_configurator_mode: false,
            disable_privileged_helper_tool: false,
            status_bar_icon_allows_color: color_icon,
            status_bar_icon_notifier_enabled: notifier_enabled,
            title,
            custom_color,
            custom_color_darkmode,
            info_items: if info_items.is_empty() {
                None
            } else {
                Some(info_items)
            },
            uptime_days_limit,
            rows,
        },
        brands: vec![BrandEntry {
            name: "Default".to_string(),
            folder: base.clone(),
            logo,
            logo_darkmode,
            menubar_icon,
            title: None,
            footer_text: None,
            error_message: None,
            password_type: None,
            storage_limit: None,
            show_welcome_screen: None,
            open_at_login: None,
            disable_configurator_mode: None,
            disable_privileged_helper_tool: None,
            status_bar_icon_allows_color: None,
            status_bar_icon_notifier_enabled: None,
            custom_color: None,
            custom_color_darkmode: None,
            info_items: None,
            uptime_days_limit: None,
            rows: None,
        }],
    };

    let results = generator::generate_all(&config, None)?;

    if dry_run {
        if output_mode == OutputMode::Json {
            contour_core::print_json(&serde_json::json!({
                "output": output_path.display().to_string(),
                "dry_run": true,
            }))?;
        } else {
            println!();
            print_info(&format!("Dry run — would write: {}", output_path.display()));
        }
        return Ok(());
    }

    // Write the discover profile (the primary output for single-brand wizard)
    if let Some(result) = results.first() {
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(&output_path, &result.discover_profile)?;
        if output_mode == OutputMode::Human {
            println!();
            print_success(&format!("Written to {}", output_path.display()));
        }
    }

    Ok(())
}
