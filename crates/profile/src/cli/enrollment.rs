//! DEP/ADE enrollment profile generation from embedded skip_keys data.
//!
//! Provides `list` and `generate` subcommands for working with Setup Assistant
//! skip keys across Apple platforms.

use crate::output::OutputMode;
use anyhow::{Context, Result};
use colored::Colorize;
use mdm_schema::SkipKey;
use serde_json::json;
use std::io::Write;

/// Common defaults that are typically skipped in enterprise deployments.
const DEFAULT_SKIP_KEYS: &[&str] = &[
    "AppleID",
    "AppStore",
    "Diagnostics",
    "Biometric",
    "iCloudDiagnostics",
    "iCloudStorage",
    "Privacy",
    "SIMSetup",
    "Siri",
    "TOS",
    "ScreenTime",
    "Appearance",
    "Welcome",
];

/// Load and filter skip keys for a given platform and optional OS version.
fn load_skip_keys(platform: &str, os_version: Option<&str>) -> Result<Vec<SkipKey>> {
    let all = mdm_schema::skip_keys::read(mdm_schema::embedded_skip_keys())
        .context("Failed to read embedded skip_keys")?;

    let filtered = all
        .into_iter()
        .filter(|k| k.platform.eq_ignore_ascii_case(platform))
        .filter(|k| {
            if let Some(ver) = os_version {
                let introduced_ok = k.introduced.as_deref().is_none_or(|intro| intro <= ver);
                let not_removed = k.removed.as_deref().is_none_or(|rem| rem > ver);
                introduced_ok && not_removed
            } else {
                true
            }
        })
        .collect();

    Ok(filtered)
}

/// Handle the `enrollment list` subcommand.
pub fn handle_enrollment_list(
    platform: &str,
    os_version: Option<&str>,
    mode: OutputMode,
) -> Result<()> {
    let keys = load_skip_keys(platform, os_version)?;

    if keys.is_empty() {
        if mode == OutputMode::Json {
            println!("[]");
        } else {
            println!(
                "No skip keys found for platform '{platform}'{}",
                os_version.map_or(String::new(), |v| format!(" at version {v}"))
            );
        }
        return Ok(());
    }

    match mode {
        OutputMode::Json => {
            let json_keys: Vec<serde_json::Value> = keys
                .iter()
                .map(|k| {
                    json!({
                        "key": k.key,
                        "title": k.title,
                        "description": k.description,
                        "platform": k.platform,
                        "introduced": k.introduced,
                        "deprecated": k.deprecated,
                        "removed": k.removed,
                        "always_skippable": k.always_skippable,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_keys)?);
        }
        OutputMode::Human => {
            println!(
                "\n{} skip keys for {} {}",
                keys.len().to_string().bold(),
                platform.bold(),
                os_version.map_or(String::new(), |v| format!("(>= {v})"))
            );
            println!(
                "{:<25} {:<30} {:<12} {:<12}",
                "Key".bold(),
                "Title".bold(),
                "Introduced".bold(),
                "Deprecated".bold()
            );
            println!("{}", "-".repeat(79));
            for k in &keys {
                println!(
                    "{:<25} {:<30} {:<12} {:<12}",
                    k.key,
                    truncate(&k.title, 28),
                    k.introduced.as_deref().unwrap_or("-"),
                    k.deprecated.as_deref().unwrap_or("-"),
                );
            }
        }
    }

    Ok(())
}

/// Handle the `enrollment generate` subcommand.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler mirrors the many flags available"
)]
pub fn handle_enrollment_generate(
    platform: &str,
    os_version: Option<&str>,
    skip_all: bool,
    skip: &[String],
    output: Option<&str>,
    profile_name: &str,
    interactive: bool,
    mode: OutputMode,
) -> Result<()> {
    let available_keys = load_skip_keys(platform, os_version)?;

    if available_keys.is_empty() {
        anyhow::bail!(
            "No skip keys found for platform '{platform}'{}",
            os_version.map_or(String::new(), |v| format!(" at version {v}"))
        );
    }

    let selected_keys: Vec<String> = if interactive {
        select_keys_interactive(&available_keys)?
    } else if skip_all {
        available_keys.iter().map(|k| k.key.clone()).collect()
    } else if !skip.is_empty() {
        // Validate that all requested keys exist
        for requested in skip {
            if !available_keys.iter().any(|k| k.key == *requested) {
                anyhow::bail!(
                    "Unknown skip key '{requested}' for platform '{platform}'. \
                     Use 'enrollment list --platform {platform}' to see available keys."
                );
            }
        }
        skip.to_vec()
    } else {
        anyhow::bail!(
            "Specify --skip-all, --skip KEY1,KEY2, or --interactive to select skip keys."
        );
    };

    let profile = build_enrollment_profile(profile_name, &selected_keys);

    let json_output = serde_json::to_string_pretty(&profile)?;

    if let Some(path) = output {
        let mut file = std::fs::File::create(path)
            .with_context(|| format!("Failed to create output file: {path}"))?;
        file.write_all(json_output.as_bytes())?;
        file.write_all(b"\n")?;

        if mode == OutputMode::Human {
            println!(
                "{} Wrote enrollment profile to {}",
                "OK".green().bold(),
                path.bold()
            );
            println!(
                "   {} skip keys selected for {}",
                selected_keys.len().to_string().bold(),
                platform.bold()
            );
        }
    } else if mode == OutputMode::Human {
        println!("{json_output}");
    }

    if mode == OutputMode::Json {
        let result = json!({
            "success": true,
            "profile_name": profile_name,
            "platform": platform,
            "os_version": os_version,
            "skip_setup_items": selected_keys,
            "skip_count": selected_keys.len(),
            "available_count": available_keys.len(),
            "output_file": output,
            "profile": profile,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Interactive skip key selection using inquire.
fn select_keys_interactive(available: &[SkipKey]) -> Result<Vec<String>> {
    let options: Vec<String> = available
        .iter()
        .map(|k| {
            let desc = k
                .description
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(50)
                .collect::<String>();
            format!("{} - {}", k.key, desc)
        })
        .collect();

    // Pre-select common defaults
    let defaults: Vec<usize> = available
        .iter()
        .enumerate()
        .filter(|(_, k)| DEFAULT_SKIP_KEYS.contains(&k.key.as_str()))
        .map(|(i, _)| i)
        .collect();

    let selected =
        inquire::MultiSelect::new("Select skip keys for enrollment profile:", options.clone())
            .with_default(&defaults)
            .with_page_size(20)
            .prompt()
            .context("Interactive selection cancelled")?;

    // Map selected display strings back to key names
    let result: Vec<String> = selected
        .iter()
        .filter_map(|sel| {
            let idx = options.iter().position(|o| o == sel)?;
            Some(available[idx].key.clone())
        })
        .collect();

    Ok(result)
}

/// Build the DEP enrollment profile JSON structure.
fn build_enrollment_profile(profile_name: &str, skip_keys: &[String]) -> serde_json::Value {
    json!({
        "profile_name": profile_name,
        "allow_pairing": true,
        "is_supervised": true,
        "is_mdm_removable": false,
        "org_magic": "1",
        "language": "en",
        "region": "US",
        "skip_setup_items": skip_keys,
    })
}

/// Truncate a string to a given width, adding ellipsis if needed.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}
