//! DEP/ADE enrollment profile generation from embedded skip_keys data.
//!
//! Provides `list` and `generate` subcommands for working with Setup Assistant
//! skip keys across Apple platforms.

use crate::output::OutputMode;
use anyhow::{Context, Result};
use colored::Colorize;
use mdm_schema::SkipKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Write;
use std::path::Path;

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

/// Skip keys that must never be present in a generated enrollment profile.
///
/// FileVault: skipping bypasses the user-led recovery-key flow.
/// SoftwareUpdate: skipping leaves devices on shipping-time OS during onboarding.
/// Documented in sop-enrollment.md; this constant enforces the SOP at PRECONDITIONS time.
pub const NEVER_SKIP: &[&str] = &["FileVault", "SoftwareUpdate"];

/// Reusable enrollment skip-list file format (TOML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkipListFile {
    /// Schema version; reserved for forward compatibility.
    #[serde(default = "default_skip_list_version")]
    pub version: u8,
    /// Platform override (e.g. "macOS", "iOS"). When set, takes precedence
    /// over the `--platform` default; an explicit `--platform` CLI flag
    /// overrides this in turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// OS version override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Profile name override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    /// Skip keys to apply.
    #[serde(default)]
    pub skip: Vec<String>,
}

fn default_skip_list_version() -> u8 {
    1
}

/// Read and parse a skip-list TOML file from disk.
pub fn parse_skip_list_file(path: &Path) -> Result<SkipListFile> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read skip-list file: {}", path.display()))?;
    let file: SkipListFile = toml::from_str(&content)
        .with_context(|| format!("Failed to parse skip-list TOML: {}", path.display()))?;
    Ok(file)
}

/// Load and filter skip keys for a given platform and optional OS version.
///
/// `beta` selects the pre-release OS seed dataset (e.g. OS 27.0 keys like
/// `AccessibilityAppearance` / `LiquidGlass`); the stable set is the default.
fn load_skip_keys(platform: &str, os_version: Option<&str>, beta: bool) -> Result<Vec<SkipKey>> {
    let raw = if beta {
        mdm_schema::embedded_skip_keys_beta()
    } else {
        mdm_schema::embedded_skip_keys()
    };
    let all = mdm_schema::skip_keys::read(raw).context("Failed to read embedded skip_keys")?;

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
    beta: bool,
    mode: OutputMode,
) -> Result<()> {
    let keys = load_skip_keys(platform, os_version, beta)?;

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
    skip_list_path: Option<&Path>,
    output: Option<&str>,
    profile_name: &str,
    interactive: bool,
    beta: bool,
    mode: OutputMode,
) -> Result<()> {
    // Load skip-list file first so its fields can supply defaults.
    let skip_list = skip_list_path.map(parse_skip_list_file).transpose()?;

    // Resolve scalars: CLI > file > caller-passed default.
    let platform_owned: String;
    let resolved_platform: &str = match skip_list.as_ref().and_then(|s| s.platform.as_deref()) {
        Some(p) if platform == "macOS" => {
            // platform CLI flag has a clap default of "macOS"; treat that as
            // "not explicitly set" so the file can override it.
            platform_owned = p.to_string();
            &platform_owned
        }
        _ => platform,
    };
    let os_version_owned: Option<String>;
    let resolved_os_version: Option<&str> = if os_version.is_some() {
        os_version
    } else {
        os_version_owned = skip_list.as_ref().and_then(|s| s.os_version.clone());
        os_version_owned.as_deref()
    };
    let profile_name_owned: String;
    let resolved_profile_name: &str =
        if profile_name == "Automatic enrollment profile" && skip_list.is_some() {
            // CLI default; let the file override if it set one.
            match skip_list.as_ref().and_then(|s| s.profile_name.clone()) {
                Some(n) => {
                    profile_name_owned = n;
                    &profile_name_owned
                }
                None => profile_name,
            }
        } else {
            profile_name
        };

    let available_keys = load_skip_keys(resolved_platform, resolved_os_version, beta)?;

    if available_keys.is_empty() {
        anyhow::bail!(
            "No skip keys found for platform '{resolved_platform}'{}",
            resolved_os_version.map_or(String::new(), |v| format!(" at version {v}"))
        );
    }

    let mut selected_keys: Vec<String> = if interactive {
        select_keys_interactive(&available_keys)?
    } else if skip_all {
        available_keys.iter().map(|k| k.key.clone()).collect()
    } else if skip_list.is_some() || !skip.is_empty() {
        // Union of file's `skip` and `--skip` CLI args. Dedup preserves first-seen order.
        let mut combined: Vec<String> = skip_list
            .as_ref()
            .map(|s| s.skip.clone())
            .unwrap_or_default();
        for k in skip {
            if !combined.contains(k) {
                combined.push(k.clone());
            }
        }
        // Validate every key against the available set for the platform/OS.
        for requested in &combined {
            if !available_keys.iter().any(|k| k.key == *requested) {
                anyhow::bail!(
                    "Unknown skip key '{requested}' for platform '{resolved_platform}'. \
                     Use 'enrollment list --platform {resolved_platform}' to see available keys."
                );
            }
        }
        combined
    } else {
        anyhow::bail!(
            "Specify --skip-all, --skip KEY1,KEY2, --skip-list <PATH>, or --interactive to select skip keys."
        );
    };

    // NEVER_SKIP guardrail — refuse to emit FileVault or SoftwareUpdate.
    // Applied to the final, post-merge selection regardless of source.
    let forbidden: Vec<&String> = selected_keys
        .iter()
        .filter(|k| NEVER_SKIP.contains(&k.as_str()))
        .collect();
    if !forbidden.is_empty() {
        let names: Vec<&str> = forbidden.iter().map(|s| s.as_str()).collect();
        anyhow::bail!(
            "Refusing to generate enrollment profile: {} must not appear in skip_setup_items \
             (NEVER_SKIP guardrail). Remove these from your skip list or --skip flag.",
            names.join(", ")
        );
    }

    // Dedup any user-supplied dupes while preserving order. Cheap and harmless.
    let mut seen = std::collections::HashSet::new();
    selected_keys.retain(|k| seen.insert(k.clone()));

    let profile = build_enrollment_profile(resolved_profile_name, &selected_keys);

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
                resolved_platform.bold()
            );
        }
    } else if mode == OutputMode::Human {
        println!("{json_output}");
    }

    if mode == OutputMode::Json {
        let result = json!({
            "success": true,
            "profile_name": resolved_profile_name,
            "platform": resolved_platform,
            "os_version": resolved_os_version,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skip_list_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("skip-list.toml");
        std::fs::write(
            &path,
            r#"
version = 1
platform = "iOS"
os_version = "18.0"
profile_name = "Acme Onboarding"
skip = ["Appearance", "Siri", "Diagnostics"]
"#,
        )
        .unwrap();

        let file = parse_skip_list_file(&path).unwrap();
        assert_eq!(file.version, 1);
        assert_eq!(file.platform.as_deref(), Some("iOS"));
        assert_eq!(file.os_version.as_deref(), Some("18.0"));
        assert_eq!(file.profile_name.as_deref(), Some("Acme Onboarding"));
        assert_eq!(file.skip, vec!["Appearance", "Siri", "Diagnostics"]);
    }

    #[test]
    fn parse_skip_list_minimal_defaults_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("skip-list.toml");
        std::fs::write(&path, r#"skip = ["Siri"]"#).unwrap();

        let file = parse_skip_list_file(&path).unwrap();
        assert_eq!(file.version, 1);
        assert!(file.platform.is_none());
        assert!(file.os_version.is_none());
        assert!(file.profile_name.is_none());
        assert_eq!(file.skip, vec!["Siri"]);
    }

    #[test]
    fn never_skip_constant_covers_filevault_and_softwareupdate() {
        assert!(NEVER_SKIP.contains(&"FileVault"));
        assert!(NEVER_SKIP.contains(&"SoftwareUpdate"));
    }

    #[test]
    fn never_skip_rejected_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(
            &path,
            r#"
platform = "macOS"
skip = ["Siri", "FileVault"]
"#,
        )
        .unwrap();

        let err = handle_enrollment_generate(
            "macOS",
            None,
            false,
            &[],
            Some(&path),
            None,
            "Automatic enrollment profile",
            false,
            false,
            OutputMode::Json,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("FileVault") && msg.contains("NEVER_SKIP"),
            "expected NEVER_SKIP rejection mentioning FileVault, got: {msg}"
        );
    }

    #[test]
    fn never_skip_rejected_from_cli_skip_flag() {
        let err = handle_enrollment_generate(
            "macOS",
            None,
            false,
            &["SoftwareUpdate".to_string()],
            None,
            None,
            "Automatic enrollment profile",
            false,
            false,
            OutputMode::Json,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("SoftwareUpdate") && msg.contains("NEVER_SKIP"));
    }
}
