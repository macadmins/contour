//! Handler for the `profile info` command.
//!
//! Displays CLI version, configuration status, and schema statistics.

use anyhow::Result;
use colored::Colorize;

use crate::config::ProfileConfig;
use crate::output::OutputMode;
use crate::schema::SchemaRegistry;

/// Handle the `info` command
pub fn handle_info(config: Option<&ProfileConfig>, output_mode: OutputMode) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let build_timestamp = env!("BUILD_TIMESTAMP");

    // Load schema registry to get statistics
    let registry = SchemaRegistry::embedded()?;
    let stats = registry.stats();

    if output_mode == OutputMode::Json {
        output_json(config, version, build_timestamp, stats)?;
    } else {
        output_human(config, version, build_timestamp, stats);
    }

    Ok(())
}

fn output_json(
    config: Option<&ProfileConfig>,
    version: &str,
    build_timestamp: &str,
    stats: &crate::schema::RegistryStats,
) -> Result<()> {
    let config_json = config.map(|c| {
        serde_json::json!({
            "domain": c.organization.domain,
            "name": c.organization.name,
            "renaming_scheme": c.renaming.scheme,
            "predictable_uuids": c.uuid.predictable,
            "fleet_enabled": c.fleet.is_some(),
        })
    });

    let sv = mdm_schema::schema_versions();
    let result = serde_json::json!({
        "version": version,
        "build": build_timestamp,
        "config": config_json,
        "schemas": {
            "total": stats.total,
            "apple": stats.apple_count,
            "apps": stats.apps_count,
            "prefs": stats.prefs_count,
            "ddm": stats.ddm_count,
            "sources": {
                "apple_device_management": {
                    "commit": sv.apple_device_management_commit,
                    "date": sv.apple_device_management_date,
                },
                "profile_manifests": {
                    "commit": sv.profile_manifests_commit,
                    "date": sv.profile_manifests_date,
                },
                "generation_date": sv.generation_date,
            }
        }
    });

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn output_human(
    config: Option<&ProfileConfig>,
    version: &str,
    build_timestamp: &str,
    stats: &crate::schema::RegistryStats,
) {
    // Version section
    println!("{}", "Profile CLI".bold());
    println!("  Version: {}", version.cyan());
    println!("  Build:   {}", build_timestamp.dimmed());
    println!();

    // Configuration section
    println!("{}", "Configuration".bold());
    if let Some(c) = config {
        println!("  Domain:            {}", c.organization.domain.green());
        println!(
            "  Name:              {}",
            c.organization
                .name
                .as_deref()
                .unwrap_or("-")
                .to_string()
                .green()
        );
        println!("  Renaming scheme:   {}", c.renaming.scheme);
        println!(
            "  Predictable UUIDs: {}",
            if c.uuid.predictable { "true" } else { "false" }
        );
        println!(
            "  Fleet:             {}",
            if c.fleet.is_some() {
                "enabled".green()
            } else {
                "disabled".dimmed()
            }
        );
    } else {
        println!("  {}", "No profile.toml found".dimmed());
    }
    println!();

    // Schema statistics section
    println!("{}", "Embedded Schemas".bold());
    println!("  Total: {} payload types", stats.total.to_string().cyan());
    println!("    • Apple: {}", stats.apple_count);
    println!("    • Apps:  {}", stats.apps_count);
    println!("    • Prefs: {}", stats.prefs_count);
    println!("    • DDM:   {}", stats.ddm_count);
    println!();

    // Schema version pinning
    let sv = mdm_schema::schema_versions();
    println!("{}", "Schema Sources".bold());
    let apple_sha = if sv.apple_device_management_commit.is_empty() {
        "unknown".dimmed().to_string()
    } else {
        sv.apple_device_management_commit[..7.min(sv.apple_device_management_commit.len())]
            .to_string()
    };
    let pm_sha = if sv.profile_manifests_commit.is_empty() {
        "unknown".dimmed().to_string()
    } else {
        sv.profile_manifests_commit[..7.min(sv.profile_manifests_commit.len())].to_string()
    };
    println!(
        "  Apple device-management: {} ({})",
        apple_sha, sv.apple_device_management_date
    );
    println!(
        "  ProfileManifests:        {} ({})",
        pm_sha, sv.profile_manifests_date
    );
    println!("  Generated:               {}", sv.generation_date);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_info_no_config() {
        // Should not panic with no config
        let result = handle_info(None, OutputMode::Json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_info_with_config() {
        use crate::config::{OrganizationConfig, OutputConfig, RenamingConfig, UuidConfig};

        let config = ProfileConfig {
            organization: OrganizationConfig {
                domain: "com.example".to_string(),
                name: Some("Example".to_string()),
            },
            renaming: RenamingConfig::default(),
            uuid: UuidConfig::default(),
            output: OutputConfig::default(),
            processing: None,
            fleet: None,
        };

        let result = handle_info(Some(&config), OutputMode::Json);
        assert!(result.is_ok());
    }
}
