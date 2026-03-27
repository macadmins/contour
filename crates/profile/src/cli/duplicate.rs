//! Handler for the `profile duplicate` command.
//!
//! Safely duplicates a .mobileconfig profile with unique identity values
//! (PayloadDisplayName, PayloadIdentifier, and all UUIDs) to avoid MDM
//! conflicts when deploying variants of the same profile to different teams.

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::output::OutputMode;
use crate::profile::parser;
use crate::uuid as profile_uuid;

/// Handle the `duplicate` command.
pub fn handle_duplicate(
    source: &str,
    name: Option<&str>,
    output: Option<&str>,
    org: Option<&str>,
    predictable: bool,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    // 1. Parse source profile (auto-unsign if needed)
    let mut profile = parser::parse_profile_auto_unsign(source)
        .with_context(|| format!("Failed to parse source profile: {source}"))?;

    let old_display_name = profile.payload_display_name.clone();
    let old_identifier = profile.payload_identifier.clone();
    let old_uuid = profile.payload_uuid.clone();

    // 2. Determine new display name
    let new_display_name = match name {
        Some(n) => n.to_string(),
        None => {
            let default = format!("{old_display_name} (Copy)");

            inquire::Text::new("New PayloadDisplayName:")
                .with_default(&default)
                .prompt()
                .with_context(|| "Prompt cancelled")?
        }
    };

    // 3. Derive new identifier
    let slug = slugify(&new_display_name);
    let new_identifier = if let Some(org_domain) = org {
        format!("{org_domain}.{slug}")
    } else {
        // Replace last segment of existing identifier
        let parts: Vec<&str> = old_identifier.rsplitn(2, '.').collect();
        if parts.len() == 2 {
            format!("{}.{slug}", parts[1])
        } else {
            format!("{old_identifier}.{slug}")
        }
    };

    // 4. UUID config
    let uuid_config = profile_uuid::UuidConfig {
        org_domain: org.map(String::from),
        predictable,
    };

    // 5. Regenerate profile-level UUID
    let new_uuid =
        profile_uuid::regenerate_uuid(&profile.payload_uuid, &uuid_config, &new_identifier)?;

    // 6. Update profile fields
    profile.payload_display_name = new_display_name.clone();
    profile.payload_identifier = new_identifier.clone();
    profile.payload_uuid = new_uuid.clone();

    // 7. Regenerate payload-level UUIDs and identifiers
    let mut payload_changes = Vec::new();
    for payload in &mut profile.payload_content {
        let old_pi = payload.payload_identifier.clone();
        let old_pu = payload.payload_uuid.clone();

        // Derive new payload identifier: replace prefix matching old profile identifier
        let new_pi = if old_pi.starts_with(&old_identifier) {
            old_pi.replacen(&old_identifier, &new_identifier, 1)
        } else {
            // Fallback: use new profile identifier + last segment of old payload identifier
            let suffix = old_pi.rsplit('.').next().unwrap_or(&old_pi);
            format!("{new_identifier}.{suffix}")
        };

        let new_pu = profile_uuid::regenerate_uuid(&old_pu, &uuid_config, &new_pi)?;

        payload.payload_identifier = new_pi.clone();
        payload.payload_uuid = new_pu.clone();

        payload_changes.push((old_pi, new_pi, old_pu, new_pu));
    }

    // 8. Determine output path
    let output_path = match output {
        Some(p) => PathBuf::from(p),
        None => {
            let source_dir = Path::new(source).parent().unwrap_or_else(|| Path::new("."));
            let filename = format!("{}.mobileconfig", sanitize_filename(&new_display_name));
            source_dir.join(filename)
        }
    };

    // 9. Output
    if output_mode == OutputMode::Json {
        output_json(
            source,
            &old_display_name,
            &new_display_name,
            &old_identifier,
            &new_identifier,
            &old_uuid,
            &new_uuid,
            &payload_changes,
            &output_path,
            dry_run,
        )?;
    } else {
        output_human(
            source,
            &old_display_name,
            &new_display_name,
            &old_identifier,
            &new_identifier,
            &old_uuid,
            &new_uuid,
            &payload_changes,
            &output_path,
            dry_run,
        );
    }

    // 10. Write (unless dry-run)
    if !dry_run {
        parser::write_profile(&profile, &output_path)?;
    }

    Ok(())
}

/// Slugify a display name for use in identifiers.
/// "Santa Configuration Kiosk" -> "santa-configuration-kiosk"
fn slugify(name: &str) -> String {
    let lowered = name.to_lowercase();
    let slug: String = lowered
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    // Collapse consecutive hyphens and trim
    let mut result = String::new();
    let mut prev_hyphen = false;
    for c in slug.chars() {
        if c == '-' {
            if !prev_hyphen && !result.is_empty() {
                result.push('-');
            }
            prev_hyphen = true;
        } else {
            result.push(c);
            prev_hyphen = false;
        }
    }
    result.trim_end_matches('-').to_string()
}

/// Sanitize a name for use as a filename (no extension).
/// "Santa Configuration Kiosk" -> "santa-configuration-kiosk"
fn sanitize_filename(name: &str) -> String {
    let with_hyphens = name.replace(' ', "-");
    let sanitized: String = with_hyphens
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    // Collapse hyphens and trim
    let mut result = String::new();
    let mut prev_hyphen = false;
    for c in sanitized.chars() {
        if c == '-' {
            if !prev_hyphen && !result.is_empty() {
                result.push('-');
            }
            prev_hyphen = true;
        } else {
            result.push(c);
            prev_hyphen = false;
        }
    }
    result.trim_matches('-').to_string()
}

fn output_human(
    source: &str,
    old_name: &str,
    new_name: &str,
    old_id: &str,
    new_id: &str,
    old_uuid: &str,
    new_uuid: &str,
    payload_changes: &[(String, String, String, String)],
    output_path: &Path,
    dry_run: bool,
) {
    let prefix = if dry_run {
        "[dry-run] ".yellow().to_string()
    } else {
        String::new()
    };

    println!("\n  {}Duplicating profile...", prefix);
    println!("  Source: {}\n", source.dimmed());

    println!(
        "  PayloadDisplayName: {} {} {}",
        old_name.dimmed(),
        "->".dimmed(),
        new_name.green()
    );
    println!(
        "  PayloadIdentifier:  {} {} {}",
        old_id.dimmed(),
        "->".dimmed(),
        new_id.green()
    );
    println!(
        "  PayloadUUID:        {} {} {}",
        truncate_uuid(old_uuid).dimmed(),
        "->".dimmed(),
        truncate_uuid(new_uuid).green()
    );

    for (i, (old_pi, new_pi, old_pu, new_pu)) in payload_changes.iter().enumerate() {
        println!("\n  Payload [{}]:", i);
        println!(
            "    Identifier: {} {} {}",
            old_pi.dimmed(),
            "->".dimmed(),
            new_pi.green()
        );
        println!(
            "    UUID:       {} {} {}",
            truncate_uuid(old_pu).dimmed(),
            "->".dimmed(),
            truncate_uuid(new_pu).green()
        );
    }

    if dry_run {
        println!(
            "\n  {} Would write: {}",
            "[dry-run]".yellow(),
            output_path.display()
        );
    } else {
        println!("\n  {} Duplicated: {}", "✓".green(), output_path.display());
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
fn output_json(
    source: &str,
    old_name: &str,
    new_name: &str,
    old_id: &str,
    new_id: &str,
    old_uuid: &str,
    new_uuid: &str,
    payload_changes: &[(String, String, String, String)],
    output_path: &Path,
    dry_run: bool,
) -> Result<()> {
    let payloads: Vec<serde_json::Value> = payload_changes
        .iter()
        .enumerate()
        .map(|(i, (old_pi, new_pi, old_pu, new_pu))| {
            serde_json::json!({
                "index": i,
                "old_identifier": old_pi,
                "new_identifier": new_pi,
                "old_uuid": old_pu,
                "new_uuid": new_pu,
            })
        })
        .collect();

    let result = serde_json::json!({
        "command": "duplicate",
        "success": true,
        "dry_run": dry_run,
        "source": source,
        "output": output_path.display().to_string(),
        "old_display_name": old_name,
        "new_display_name": new_name,
        "old_identifier": old_id,
        "new_identifier": new_id,
        "old_uuid": old_uuid,
        "new_uuid": new_uuid,
        "payloads": payloads,
    });

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn truncate_uuid(uuid: &str) -> String {
    if uuid.len() > 13 {
        format!("{}...", &uuid[..13])
    } else {
        uuid.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{ConfigurationProfile, PayloadContent};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn create_test_profile() -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.example.santa-configuration".to_string(),
            payload_uuid: "0FEE6FAB-1234-5678-9ABC-DEF012345678".to_string(),
            payload_display_name: "Santa Configuration".to_string(),
            payload_content: vec![PayloadContent {
                payload_type: "com.google.santa".to_string(),
                payload_version: 1,
                payload_identifier: "com.example.santa-configuration.santa".to_string(),
                payload_uuid: "E08BF479-AAAA-BBBB-CCCC-DDDDEEEEEEEE".to_string(),
                content: HashMap::new(),
            }],
            additional_fields: HashMap::new(),
        }
    }

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("Santa Configuration"), "santa-configuration");
        assert_eq!(
            slugify("Santa Configuration Kiosk"),
            "santa-configuration-kiosk"
        );
        assert_eq!(slugify("Hello  World"), "hello-world");
        assert_eq!(slugify("test!@#name"), "test-name");
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(
            sanitize_filename("Santa Configuration Kiosk"),
            "Santa-Configuration-Kiosk"
        );
        assert_eq!(sanitize_filename("Test (Copy)"), "Test-Copy");
        assert_eq!(sanitize_filename("a  b"), "a-b");
    }

    #[test]
    fn test_duplicate_with_name_flag() {
        let tmp = TempDir::new().unwrap();
        let source_path = tmp.path().join("source.mobileconfig");

        // Write test profile
        let profile = create_test_profile();
        parser::write_profile(&profile, &source_path).unwrap();

        let output_path = tmp.path().join("output.mobileconfig");

        // Run duplicate
        handle_duplicate(
            source_path.to_str().unwrap(),
            Some("Santa Configuration Kiosk"),
            Some(output_path.to_str().unwrap()),
            None,
            false,
            false,
            OutputMode::Human,
        )
        .unwrap();

        // Read back and verify
        let dup = parser::parse_profile(output_path.to_str().unwrap()).unwrap();

        assert_eq!(dup.payload_display_name, "Santa Configuration Kiosk");
        assert_eq!(
            dup.payload_identifier,
            "com.example.santa-configuration-kiosk"
        );
        assert_ne!(dup.payload_uuid, profile.payload_uuid);
        assert_ne!(
            dup.payload_content[0].payload_uuid,
            profile.payload_content[0].payload_uuid
        );
        assert!(
            dup.payload_content[0]
                .payload_identifier
                .contains("santa-configuration-kiosk")
        );
    }

    #[test]
    fn test_duplicate_with_org_flag() {
        let tmp = TempDir::new().unwrap();
        let source_path = tmp.path().join("source.mobileconfig");

        let profile = create_test_profile();
        parser::write_profile(&profile, &source_path).unwrap();

        let output_path = tmp.path().join("output.mobileconfig");

        handle_duplicate(
            source_path.to_str().unwrap(),
            Some("Kiosk Santa"),
            Some(output_path.to_str().unwrap()),
            Some("com.acme"),
            false,
            false,
            OutputMode::Human,
        )
        .unwrap();

        let dup = parser::parse_profile(output_path.to_str().unwrap()).unwrap();

        assert_eq!(dup.payload_identifier, "com.acme.kiosk-santa");
    }

    #[test]
    fn test_duplicate_predictable_uuids() {
        let tmp = TempDir::new().unwrap();
        let source_path = tmp.path().join("source.mobileconfig");

        let profile = create_test_profile();
        parser::write_profile(&profile, &source_path).unwrap();

        let out1 = tmp.path().join("out1.mobileconfig");
        let out2 = tmp.path().join("out2.mobileconfig");

        // Run twice with predictable
        handle_duplicate(
            source_path.to_str().unwrap(),
            Some("Kiosk"),
            Some(out1.to_str().unwrap()),
            Some("com.example"),
            true,
            false,
            OutputMode::Human,
        )
        .unwrap();

        handle_duplicate(
            source_path.to_str().unwrap(),
            Some("Kiosk"),
            Some(out2.to_str().unwrap()),
            Some("com.example"),
            true,
            false,
            OutputMode::Human,
        )
        .unwrap();

        let dup1 = parser::parse_profile(out1.to_str().unwrap()).unwrap();
        let dup2 = parser::parse_profile(out2.to_str().unwrap()).unwrap();

        assert_eq!(dup1.payload_uuid, dup2.payload_uuid);
        assert_eq!(
            dup1.payload_content[0].payload_uuid,
            dup2.payload_content[0].payload_uuid
        );
    }

    #[test]
    fn test_duplicate_dry_run_does_not_write() {
        let tmp = TempDir::new().unwrap();
        let source_path = tmp.path().join("source.mobileconfig");

        let profile = create_test_profile();
        parser::write_profile(&profile, &source_path).unwrap();

        let output_path = tmp.path().join("should-not-exist.mobileconfig");

        handle_duplicate(
            source_path.to_str().unwrap(),
            Some("Dry Run Test"),
            Some(output_path.to_str().unwrap()),
            None,
            false,
            true, // dry_run
            OutputMode::Human,
        )
        .unwrap();

        assert!(!output_path.exists());
    }

    #[test]
    fn test_duplicate_default_output_path() {
        let tmp = TempDir::new().unwrap();
        let source_path = tmp.path().join("santa-config.mobileconfig");

        let profile = create_test_profile();
        parser::write_profile(&profile, &source_path).unwrap();

        // No --output flag: should write to same directory with derived filename
        handle_duplicate(
            source_path.to_str().unwrap(),
            Some("Santa Kiosk"),
            None,
            None,
            false,
            false,
            OutputMode::Human,
        )
        .unwrap();

        let expected = tmp.path().join("Santa-Kiosk.mobileconfig");
        assert!(expected.exists());
    }
}
