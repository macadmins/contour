//! Handler for the `profile info` command.
//!
//! Two modes:
//! - No argument: displays CLI version, configuration status, and schema statistics.
//! - `<payload_type>`: displays the full schema for that payload type — title,
//!   description, platforms, every field's name + type + plist tag + required
//!   flag + default + allowed values. Mirrors the `ddm info` JSON shape so
//!   agents can route schema questions through one consistent surface.

use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::config::ProfileConfig;
use crate::output::OutputMode;
use crate::schema::{FieldType, PayloadManifest, SchemaRegistry};

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

/// Handle the `info <payload_type>` command — schema lookup for a single
/// payload type.
///
/// Mirrors `profile ddm info <name>`: returns title, description, platforms,
/// and every field with its type, plist tag (`<real>`, `<integer>`, …),
/// required flag, default, and allowed values. Designed so an agent can
/// answer "what type does Apple expect for `<key>` in `<payload>`?" with
/// one CLI call and a single jq filter.
pub fn handle_payload_info(
    payload_type: &str,
    schema_path: Option<&str>,
    full: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = if let Some(p) = schema_path {
        SchemaRegistry::from_auto_detect(Path::new(p))?
    } else {
        SchemaRegistry::embedded()?
    };

    let manifest = registry.get(payload_type).ok_or_else(|| {
        let suggestions = registry.search(payload_type);
        let hint = if suggestions.is_empty() {
            "Use 'contour profile docs list' to see available types.".to_string()
        } else {
            let names: Vec<&str> = suggestions
                .iter()
                .take(3)
                .map(|m| m.payload_type.as_str())
                .collect();
            format!("Did you mean one of: {}?", names.join(", "))
        };
        anyhow::anyhow!("Payload type '{payload_type}' not found.\n{hint}")
    })?;

    if output_mode == OutputMode::Json {
        emit_payload_info_json(manifest, full)?;
    } else {
        emit_payload_info_human(manifest, full);
    }
    Ok(())
}

/// Map a `FieldType` to the plist XML tag agents see in `.mobileconfig`
/// files. Authors verify mobileconfig contents against this exact tag —
/// it's the answer to "what should `<key>` look like in the file?".
pub fn plist_tag_for(t: &FieldType) -> &'static str {
    match t {
        FieldType::String => "string",
        FieldType::Integer => "integer",
        FieldType::Boolean => "boolean",
        FieldType::Array => "array",
        FieldType::Dictionary => "dict",
        FieldType::Data => "data",
        FieldType::Date => "date",
        FieldType::Real => "real",
    }
}

fn emit_payload_info_json(manifest: &PayloadManifest, full: bool) -> Result<()> {
    let mut platforms = Vec::new();
    if manifest.platforms.macos {
        platforms.push("macOS");
    }
    if manifest.platforms.ios {
        platforms.push("iOS");
    }
    if manifest.platforms.tvos {
        platforms.push("tvOS");
    }
    if manifest.platforms.watchos {
        platforms.push("watchOS");
    }
    if manifest.platforms.visionos {
        platforms.push("visionOS");
    }

    let fields: Vec<_> = manifest
        .field_order
        .iter()
        .filter_map(|name| manifest.fields.get(name))
        .filter(|f| full || f.flags.required || f.depth == 0)
        .map(|f| {
            serde_json::json!({
                "name": f.name,
                "type": f.field_type.as_str(),
                "plist_tag": plist_tag_for(&f.field_type),
                "required": f.flags.required,
                "supervised": f.flags.supervised,
                "sensitive": f.flags.sensitive,
                "default": f.default,
                "allowed_values": f.allowed_values,
                "min_version": f.min_version,
                "depth": f.depth,
                "parent_key": f.parent_key,
                "title": f.title,
                "description": f.description,
            })
        })
        .collect();

    let info = serde_json::json!({
        "payload_type": manifest.payload_type,
        "title": manifest.title,
        "description": manifest.description,
        "category": manifest.category,
        "platforms": platforms,
        "field_count": manifest.fields.len(),
        "fields_returned": fields.len(),
        "fields": fields,
    });
    println!("{}", serde_json::to_string_pretty(&info)?);
    Ok(())
}

fn emit_payload_info_human(manifest: &PayloadManifest, full: bool) {
    println!("{}\n", manifest.title.bold());
    println!("{}: {}", "Payload Type".cyan(), manifest.payload_type);
    println!("{}: {}", "Category".cyan(), manifest.category.magenta());

    let mut platforms = Vec::new();
    if manifest.platforms.macos {
        platforms.push("macOS");
    }
    if manifest.platforms.ios {
        platforms.push("iOS");
    }
    if manifest.platforms.tvos {
        platforms.push("tvOS");
    }
    if manifest.platforms.watchos {
        platforms.push("watchOS");
    }
    if manifest.platforms.visionos {
        platforms.push("visionOS");
    }
    println!("{}: {}", "Platforms".cyan(), platforms.join(", "));

    if !manifest.description.is_empty() {
        println!("\n{}", "Description:".cyan());
        println!("  {}", manifest.description);
    }

    let fields: Vec<_> = manifest
        .field_order
        .iter()
        .filter_map(|name| manifest.fields.get(name))
        .filter(|f| full || f.flags.required || f.depth == 0)
        .collect();

    if fields.is_empty() {
        println!("\n{}", "(no top-level fields documented)".dimmed());
        return;
    }

    println!(
        "\n{} ({} of {}):",
        "Fields".cyan().bold(),
        fields.len(),
        manifest.fields.len()
    );
    for f in &fields {
        let mut markers = Vec::new();
        if f.flags.required {
            markers.push("required".red().to_string());
        }
        if f.flags.supervised {
            markers.push("supervised".yellow().to_string());
        }
        if f.flags.sensitive {
            markers.push("sensitive".red().to_string());
        }
        let marker_str = if markers.is_empty() {
            String::new()
        } else {
            format!(" [{}]", markers.join(", "))
        };
        let indent = "  ".repeat(usize::from(f.depth) + 1);
        println!(
            "{}{} : <{}>{}",
            indent,
            f.name.green(),
            plist_tag_for(&f.field_type).cyan(),
            marker_str
        );
        if !f.allowed_values.is_empty() {
            println!(
                "{}  values: {}",
                indent,
                f.allowed_values.join(", ").dimmed()
            );
        }
        if let Some(d) = &f.default {
            println!("{}  default: {}", indent, d.dimmed());
        }
    }

    if !full {
        let hidden = manifest.fields.len() - fields.len();
        if hidden > 0 {
            println!(
                "\n  {} {hidden} additional fields hidden (use --full to show)",
                "ℹ".blue()
            );
        }
    }
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
