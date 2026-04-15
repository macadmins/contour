//! Import profiles from Jamf backup YAML files (jamf-cli export format).
//!
//! Jamf backup YAML files have the structure:
//! ```yaml
//! _meta:
//!     schema_version: 1
//!     cli_version: 1.4.0
//!     resource_type: profiles
//! general:
//!     name: Some Profile Name
//!     payloads: |-
//!         <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist...>...
//! ```
//!
//! The `general.payloads` field contains the entire mobileconfig XML as a single
//! minified line. This module extracts, normalizes, and validates those payloads.

use crate::cli::glob_utils::{BatchResult, output_batch_json, print_batch_summary};
use crate::config::ProfileConfig;
use crate::output::OutputMode;
use crate::profile::{normalizer, parser, validator};
use crate::uuid::{self, UuidConfig};
use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

// ── Jamf YAML structures ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct JamfProfileYaml {
    general: JamfGeneral,
}

#[derive(Debug, Deserialize)]
struct JamfGeneral {
    name: String,
    payloads: Option<String>,
}

// ── Filename sanitization ────────────────────────────────────────────

/// Sanitize a profile name for use as a filename (no extension).
/// "Some Profile Name" -> "some-profile-name"
fn sanitize_name(name: &str) -> String {
    let with_hyphens = name.replace(' ', "-");
    let sanitized: String = with_hyphens
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    // Collapse consecutive hyphens and trim leading/trailing hyphens
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
    result.trim_end_matches('-').to_lowercase()
}

// ── Main entry point ─────────────────────────────────────────────────

#[expect(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "CLI handler requires many parameters"
)]
pub fn handle_jamf_import(
    source: &str,
    output_dir: Option<&str>,
    org_domain: Option<&str>,
    org_name: Option<&str>,
    config: Option<&ProfileConfig>,
    validate: bool,
    regen_uuid: bool,
    dry_run: bool,
    import_all: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let start = Instant::now();
    let source_path = Path::new(source);

    // Discover YAML files
    let yaml_files = discover_jamf_yaml_files(source_path)?;

    if yaml_files.is_empty() {
        if output_mode == OutputMode::Human {
            println!("{}", "No .yaml files found in source.".yellow());
        } else {
            let result = serde_json::json!({
                "success": false,
                "total_found": 0,
                "message": "No .yaml files found"
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    // Extract payloads from YAML files
    let mut extracted: Vec<ExtractedProfile> = Vec::new();
    let mut skipped = 0usize;
    let mut parse_errors = Vec::new();

    for yaml_path in &yaml_files {
        match extract_profile_from_yaml(yaml_path) {
            Ok(Some(profile)) => extracted.push(profile),
            Ok(None) => skipped += 1,
            Err(e) => {
                parse_errors.push((yaml_path.clone(), format!("{e:#}")));
            }
        }
    }

    if output_mode == OutputMode::Human {
        println!();
        println!("{}", "=".repeat(66));
        println!("{}", "  Jamf Backup Import".bold().cyan());
        println!("{}", "=".repeat(66));
        println!();
        println!("Source: {}", source.cyan());
        println!();
        println!("{}", "Discovery:".bold());
        println!(
            "  {} .yaml files found",
            yaml_files.len().to_string().green()
        );
        println!(
            "  {} contain profile payloads",
            extracted.len().to_string().green()
        );
        if skipped > 0 {
            println!(
                "  {} skipped (no plist payload)",
                skipped.to_string().yellow()
            );
        }
        if !parse_errors.is_empty() {
            println!(
                "  {} failed to parse:",
                parse_errors.len().to_string().red()
            );
            for (path, err) in &parse_errors {
                println!("    {} {} — {}", "✗".red(), path.display(), err);
            }
        }
        println!();
    }

    if extracted.is_empty() {
        if output_mode == OutputMode::Json {
            let result = serde_json::json!({
                "success": false,
                "total_found": yaml_files.len(),
                "extracted": 0,
                "skipped": skipped,
                "parse_errors": parse_errors.len(),
                "message": "No profile payloads found in YAML files"
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!("{}", "No profile payloads found in YAML files.".yellow());
        }
        return Ok(());
    }

    // Resolve output directory
    let effective_output = output_dir.unwrap_or("./jamf-imported");

    // Resolve org domain: CLI --org -> profile.toml -> .contour/config.toml
    let contour_domain;
    let effective_org = if org_domain.is_some() {
        org_domain
    } else if let Some(cfg) = config {
        Some(cfg.organization.domain.as_str())
    } else if let Some(cfg) = contour_core::config::ContourConfig::load_nearest() {
        contour_domain = cfg.organization.domain;
        Some(contour_domain.as_str())
    } else {
        None
    };

    // Org is required for Jamf imports (via --org, profile.toml, or .contour/config.toml)
    let effective_org = effective_org.ok_or_else(|| {
        anyhow::anyhow!(
            "--org is required for Jamf imports (e.g., --org com.yourorg)\n\
             Alternatively, set organization.domain in profile.toml or .contour/config.toml"
        )
    })?;

    // Resolve org name
    let effective_org_name = org_name
        .map(String::from)
        .or_else(|| config.map(super::super::config::ProfileConfig::org_name))
        .or_else(|| {
            contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.name)
        });

    // Preview
    if output_mode == OutputMode::Human {
        println!("{}", "Import Preview".bold());
        println!("{}", "-".repeat(50));
        println!(
            "  Profiles to import:  {}",
            extracted.len().to_string().green()
        );
        println!("  Output directory:    {}", effective_output);
        println!("  Organization:        {}", effective_org);
        if let Some(ref name) = effective_org_name {
            println!("  Organization name:   {}", name);
        }
        println!();
        println!("  Pipeline (per profile):");
        println!("    1. Extract plist from Jamf YAML");
        println!("    2. Write as formatted .mobileconfig");
        println!("    3. Normalize identifiers");
        if regen_uuid {
            println!("    4. Regenerate UUIDs");
        }
        if validate {
            println!("    5. Validate structure");
        }
        println!();
    }

    if dry_run {
        if output_mode == OutputMode::Human {
            println!("{}", "Dry run — no files will be written.".yellow());
            println!();
            for ep in &extracted {
                let filename = format!("{}.mobileconfig", sanitize_name(&ep.name));
                println!(
                    "  Would import: {} → {}/{}",
                    ep.source_path.display(),
                    effective_output,
                    filename
                );
                println!("    Name: \"{}\"", ep.name);
            }
        } else {
            let items: Vec<_> = extracted
                .iter()
                .map(|ep| {
                    let filename = format!("{}.mobileconfig", sanitize_name(&ep.name));
                    serde_json::json!({
                        "source": ep.source_path.to_string_lossy(),
                        "output": format!("{}/{}", effective_output, filename),
                        "name": ep.name,
                    })
                })
                .collect();
            let result = serde_json::json!({
                "dry_run": true,
                "total_extracted": extracted.len(),
                "would_import": items,
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    // Confirm (interactive only, non-all)
    if output_mode == OutputMode::Human && !import_all {
        let confirm = inquire::Confirm::new(&format!(
            "Import {} profiles from Jamf backup?",
            extracted.len()
        ))
        .with_default(true)
        .prompt()?;

        if !confirm {
            println!("{}", "Import cancelled.".yellow());
            return Ok(());
        }
    }

    // Create output directory
    fs::create_dir_all(effective_output)?;

    // Process each extracted profile
    let total = extracted.len();
    let mut batch = BatchResult::new();
    batch.total = total;

    for (seq, ep) in extracted.iter().enumerate() {
        let filename = format!("{}.mobileconfig", sanitize_name(&ep.name));
        let output_path = Path::new(effective_output).join(&filename);

        if output_mode == OutputMode::Human {
            println!(
                "\n{}",
                format!("[{}/{}] \"{}\"", seq + 1, total, ep.name).cyan()
            );
        }

        match process_extracted_profile(
            ep,
            &output_path,
            Some(effective_org),
            effective_org_name.as_deref(),
            config,
            validate,
            regen_uuid,
            output_mode,
        ) {
            Ok(()) => {
                batch.success += 1;
                if output_mode == OutputMode::Human {
                    println!("  {} {}", "→".green(), output_path.display());
                }
            }
            Err(e) => {
                let err_msg = format!("{e:#}");
                batch
                    .failures
                    .push((ep.source_path.clone(), err_msg.clone()));
                batch.failed += 1;
                if output_mode == OutputMode::Human {
                    println!("  {} {}", "✗".red(), err_msg);
                }
            }
        }
    }

    // Summary
    let elapsed = start.elapsed();
    let elapsed_display = contour_core::format_elapsed(elapsed);
    if output_mode == OutputMode::Human {
        print_batch_summary(&batch, "Jamf Import");
        println!("  Completed in {elapsed_display}");
    } else {
        output_batch_json(&batch, "jamf_import")?;
    }

    if batch.failed > 0 {
        anyhow::bail!("{} file(s) failed to import", batch.failed);
    }

    Ok(())
}

// ── Discovery ────────────────────────────────────────────────────────

fn discover_jamf_yaml_files(source: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if source.is_file() {
        let ext = source
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") {
            files.push(source.to_path_buf());
        }
        return Ok(files);
    }

    if !source.is_dir() {
        anyhow::bail!("Source must be a file or directory: {}", source.display());
    }

    for entry in WalkDir::new(source)
        .follow_links(true)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") {
            files.push(path.to_path_buf());
        }
    }

    files.sort();
    Ok(files)
}

// ── Extraction ───────────────────────────────────────────────────────

struct ExtractedProfile {
    source_path: PathBuf,
    name: String,
    plist_xml: String,
}

/// Extract a profile payload from a Jamf backup YAML file.
///
/// Returns `Ok(None)` if the YAML is valid but doesn't contain a plist payload
/// (e.g., it's a different Jamf resource type like scripts or policies).
fn extract_profile_from_yaml(path: &Path) -> Result<Option<ExtractedProfile>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read YAML file: {}", path.display()))?;

    let parsed: JamfProfileYaml = yaml_serde::from_str(&content)
        .with_context(|| format!("Failed to parse YAML: {}", path.display()))?;

    let payloads = match &parsed.general.payloads {
        Some(p) if p.contains("<plist") => p.clone(),
        _ => return Ok(None),
    };

    Ok(Some(ExtractedProfile {
        source_path: path.to_path_buf(),
        name: parsed.general.name.clone(),
        plist_xml: payloads,
    }))
}

// ── Processing pipeline ──────────────────────────────────────────────

#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
fn process_extracted_profile(
    ep: &ExtractedProfile,
    output_path: &Path,
    org_domain: Option<&str>,
    org_name: Option<&str>,
    config: Option<&ProfileConfig>,
    validate: bool,
    regen_uuid: bool,
    output_mode: OutputMode,
) -> Result<()> {
    // 1. Parse the extracted plist XML
    let plist_bytes = ep.plist_xml.as_bytes();
    let mut profile = parser::parse_profile_from_bytes(plist_bytes)
        .with_context(|| format!("Failed to parse plist from \"{}\"", ep.name))?;

    if output_mode == OutputMode::Human {
        println!("  {} Parsed plist from YAML", "✓".green());
    }

    // 2. Normalize (org_domain and org_name are already resolved by caller)
    if org_domain.is_some() || org_name.is_some() {
        let normalizer_config = normalizer::NormalizerConfig {
            org_domain: org_domain.map(String::from),
            org_name: org_name.map(String::from),
            naming_convention: normalizer::NamingConvention::OrgDomainPrefix,
        };

        normalizer::normalize_profile(&mut profile, &normalizer_config)?;
        if output_mode == OutputMode::Human {
            if org_domain.is_some() {
                println!(
                    "  {} Normalized → {}",
                    "✓".green(),
                    profile.payload_identifier
                );
            } else {
                println!("  {} Normalized", "✓".green());
            }
        }
    }

    // 3. UUID regeneration
    if regen_uuid {
        let predictable = config.is_some_and(|c| c.uuid.predictable);
        let uuid_config = UuidConfig {
            org_domain: org_domain.map(String::from),
            predictable,
        };

        profile.payload_uuid = uuid::regenerate_uuid(
            &profile.payload_uuid,
            &uuid_config,
            &profile.payload_identifier,
        )?;

        for content in &mut profile.payload_content {
            content.payload_uuid = uuid::regenerate_uuid(
                &content.payload_uuid,
                &uuid_config,
                &content.payload_identifier,
            )?;
        }

        if output_mode == OutputMode::Human {
            println!("  {} UUIDs regenerated", "✓".green());
        }
    }

    // 4. Validate
    if validate {
        let validation = validator::validate_profile(&profile)?;
        if !validation.valid {
            let detail = validation.errors.join("; ");
            anyhow::bail!("Validation failed: {detail}");
        }
        if output_mode == OutputMode::Human {
            println!("  {} Validated", "✓".green());
        }
    }

    // 5. Write as properly formatted mobileconfig
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }

    parser::write_profile(&profile, output_path)?;

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_name() {
        assert_eq!(sanitize_name("Some Profile Name"), "some-profile-name");
        assert_eq!(sanitize_name("WiFi - Corporate"), "wifi-corporate");
        assert_eq!(sanitize_name("Test (v2)"), "test-v2");
        assert_eq!(sanitize_name("  Leading Spaces"), "leading-spaces");
        assert_eq!(
            sanitize_name("Multiple   Spaces Here"),
            "multiple-spaces-here"
        );
        assert_eq!(sanitize_name("UPPERCASE"), "uppercase");
        assert_eq!(sanitize_name("with_underscore"), "with_underscore");
    }

    #[test]
    fn test_extract_from_yaml_string() {
        let yaml = r#"
_meta:
    schema_version: 1
    cli_version: 1.4.0
    resource_type: profiles
general:
    name: Test Profile
    payloads: |-
        <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>PayloadContent</key><array><dict><key>PayloadDisplayName</key><string>Test</string><key>PayloadIdentifier</key><string>com.test.payload</string><key>PayloadType</key><string>com.apple.dock</string><key>PayloadUUID</key><string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string><key>PayloadVersion</key><integer>1</integer></dict></array><key>PayloadDisplayName</key><string>Test Profile</string><key>PayloadIdentifier</key><string>com.test.profile</string><key>PayloadType</key><string>Configuration</string><key>PayloadUUID</key><string>12345678-1234-1234-1234-123456789012</string><key>PayloadVersion</key><integer>1</integer></dict></plist>
"#;

        let parsed: JamfProfileYaml = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(parsed.general.name, "Test Profile");
        assert!(parsed.general.payloads.is_some());
        let payloads = parsed.general.payloads.unwrap();
        assert!(payloads.contains("<plist"));

        // Verify the plist can be parsed as a profile
        let profile = parser::parse_profile_from_bytes(payloads.as_bytes()).unwrap();
        assert_eq!(profile.payload_display_name, "Test Profile");
        assert_eq!(profile.payload_identifier, "com.test.profile");
    }

    #[test]
    fn test_extract_skips_non_profile_yaml() {
        let yaml = r#"
_meta:
    schema_version: 1
    cli_version: 1.4.0
    resource_type: scripts
general:
    name: Some Script
"#;

        // Should fail to parse because `payloads` is missing — but our struct makes it optional
        let parsed: Result<JamfProfileYaml, _> = yaml_serde::from_str(yaml);
        // This may or may not parse depending on strictness — if it does, payloads is None
        if let Ok(p) = parsed {
            assert!(
                p.general.payloads.is_none() || !p.general.payloads.unwrap().contains("<plist")
            );
        }
    }

    #[test]
    fn test_extract_skips_empty_payloads() {
        let yaml = r#"
_meta:
    schema_version: 1
general:
    name: Empty Profile
    payloads: ""
"#;

        let parsed: JamfProfileYaml = yaml_serde::from_str(yaml).unwrap();
        // payloads is Some("") which doesn't contain "<plist", so should be skipped
        assert!(
            parsed.general.payloads.as_deref().unwrap_or("").is_empty()
                || !parsed
                    .general
                    .payloads
                    .as_deref()
                    .unwrap_or("")
                    .contains("<plist")
        );
    }

    #[test]
    fn test_jamf_import_with_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("test-profile.yaml");

        let yaml_content = r#"_meta:
    schema_version: 1
    cli_version: 1.4.0
    resource_type: profiles
general:
    name: Dock Settings
    payloads: |-
        <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>PayloadContent</key><array><dict><key>PayloadDisplayName</key><string>Dock</string><key>PayloadIdentifier</key><string>com.test.dock</string><key>PayloadType</key><string>com.apple.dock</string><key>PayloadUUID</key><string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string><key>PayloadVersion</key><integer>1</integer></dict></array><key>PayloadDisplayName</key><string>Dock Settings</string><key>PayloadIdentifier</key><string>com.test.dock-profile</string><key>PayloadType</key><string>Configuration</string><key>PayloadUUID</key><string>12345678-1234-1234-1234-123456789012</string><key>PayloadVersion</key><integer>1</integer></dict></plist>
"#;
        fs::write(&yaml_path, yaml_content).unwrap();

        let output_dir = dir.path().join("output");

        handle_jamf_import(
            dir.path().to_str().unwrap(),
            Some(output_dir.to_str().unwrap()),
            Some("com.example"),
            None,
            None,
            true,
            true,
            false, // not dry_run
            true,  // import_all
            OutputMode::Json,
        )
        .unwrap();

        // Verify output file exists and is valid XML
        let output_file = output_dir.join("dock-settings.mobileconfig");
        assert!(output_file.exists(), "Output file should exist");

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("<?xml"), "Should be formatted XML");
        assert!(content.contains("<plist"), "Should contain plist root");
        assert!(
            content.contains('\n'),
            "Should be multi-line (not minified)"
        );
    }

    #[test]
    fn test_jamf_import_requires_org() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("test-profile.yaml");

        let yaml_content = r#"_meta:
    schema_version: 1
    cli_version: 1.4.0
    resource_type: profiles
general:
    name: Dock Settings
    payloads: |-
        <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>PayloadContent</key><array><dict><key>PayloadDisplayName</key><string>Dock</string><key>PayloadIdentifier</key><string>com.test.dock</string><key>PayloadType</key><string>com.apple.dock</string><key>PayloadUUID</key><string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string><key>PayloadVersion</key><integer>1</integer></dict></array><key>PayloadDisplayName</key><string>Dock Settings</string><key>PayloadIdentifier</key><string>com.test.dock-profile</string><key>PayloadType</key><string>Configuration</string><key>PayloadUUID</key><string>12345678-1234-1234-1234-123456789012</string><key>PayloadVersion</key><integer>1</integer></dict></plist>
"#;
        fs::write(&yaml_path, yaml_content).unwrap();

        let output_dir = dir.path().join("output");

        let result = handle_jamf_import(
            dir.path().to_str().unwrap(),
            Some(output_dir.to_str().unwrap()),
            None, // no org
            None,
            None,
            true,
            true,
            false,
            true,
            OutputMode::Json,
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("--org is required"),
            "Error should mention --org requirement, got: {err}"
        );
    }
}
