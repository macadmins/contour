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
use crate::schema::{FieldType, OsSupportDetail, PayloadManifest, Platform, SchemaRegistry};

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
/// per-OS support detail (introduced/deprecated/removed/allowed_enrollments/
/// scopes/supervised/requires_dep/user_approved_mdm/device_channel/
/// user_channel/multiple/beta), and every field with its type, plist tag
/// (`<real>`, `<integer>`, …), required flag, default, and allowed values.
///
/// `os_filter` (the `--os <NAME>` flag) restricts output to fields supported
/// on that platform — fails fast if the payload itself isn't supported there.
pub fn handle_payload_info(
    payload_type: &str,
    schema_path: Option<&str>,
    full: bool,
    os_filter: Option<&str>,
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

    // Resolve --os flag against the payload's supported platforms.
    // Errors fast on unsupported OS so an agent can't accidentally
    // generate a profile that won't install on the target.
    let os = match os_filter {
        Some(s) => {
            let p = Platform::from_cli_str(s).ok_or_else(|| {
                anyhow::anyhow!("Unknown --os '{s}'. Valid: macOS, iOS, tvOS, watchOS, visionOS")
            })?;
            if !manifest_supports_platform(manifest, p) {
                anyhow::bail!(
                    "Payload '{}' is not supported on {} — supported platforms: {}",
                    manifest.payload_type,
                    p.as_str(),
                    supported_platform_list(manifest)
                );
            }
            Some(p)
        }
        None => None,
    };

    if output_mode == OutputMode::Json {
        emit_payload_info_json(manifest, full, os)?;
    } else {
        emit_payload_info_human(manifest, full, os);
    }
    Ok(())
}

fn manifest_supports_platform(m: &PayloadManifest, p: Platform) -> bool {
    match p {
        Platform::MacOS => m.platforms.macos,
        Platform::Ios => m.platforms.ios,
        Platform::TvOS => m.platforms.tvos,
        Platform::WatchOS => m.platforms.watchos,
        Platform::VisionOS => m.platforms.visionos,
    }
}

fn supported_platform_list(m: &PayloadManifest) -> String {
    let mut p = Vec::new();
    if m.platforms.macos {
        p.push("macOS");
    }
    if m.platforms.ios {
        p.push("iOS");
    }
    if m.platforms.tvos {
        p.push("tvOS");
    }
    if m.platforms.watchos {
        p.push("watchOS");
    }
    if m.platforms.visionos {
        p.push("visionOS");
    }
    if p.is_empty() {
        "(none)".into()
    } else {
        p.join(", ")
    }
}

/// Serialize an `OsSupportDetail` to a JSON object — same shape across
/// every consumer (`info`, future search, etc.).
fn os_support_to_json(detail: &OsSupportDetail) -> serde_json::Value {
    serde_json::json!({
        "introduced": detail.introduced,
        "deprecated": detail.deprecated,
        "removed": detail.removed,
        "allowed_enrollments": detail.allowed_enrollments,
        "allowed_scopes": detail.allowed_scopes,
        "supervised": detail.supervised,
        "requires_dep": detail.requires_dep,
        "user_approved_mdm": detail.user_approved_mdm,
        "allow_manual_install": detail.allow_manual_install,
        "device_channel": detail.device_channel,
        "user_channel": detail.user_channel,
        "multiple": detail.multiple,
        "beta": detail.beta,
        "shared_ipad_mode": detail.shared_ipad_mode,
        "user_enrollment_mode": detail.user_enrollment_mode,
    })
}

/// Serialize a per-OS map for JSON output, scoping when `--os` is set.
///
/// - `os = None` → emit the full map keyed by platform name as the
///   value of the field. Empty maps serialize to `{}`.
/// - `os = Some(p)` → emit just that platform's value as a JSON string,
///   or `null` if the map has no entry for `p`. This collapses the jq
///   path so `--os iOS` callers can use
///   `.fields[].introduced_by_platform` directly without a nested
///   key access.
fn serialize_per_os_field(
    map: &std::collections::HashMap<Platform, String>,
    os: Option<Platform>,
) -> serde_json::Value {
    if let Some(p) = os {
        return match map.get(&p) {
            Some(v) => serde_json::Value::String(v.clone()),
            None => serde_json::Value::Null,
        };
    }
    let mut out = serde_json::Map::new();
    for p in [
        Platform::MacOS,
        Platform::Ios,
        Platform::TvOS,
        Platform::WatchOS,
        Platform::VisionOS,
    ] {
        if let Some(v) = map.get(&p) {
            out.insert(p.as_str().to_string(), serde_json::Value::String(v.clone()));
        }
    }
    serde_json::Value::Object(out)
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

fn emit_payload_info_json(
    manifest: &PayloadManifest,
    full: bool,
    os: Option<Platform>,
) -> Result<()> {
    let platforms = supported_platform_vec(manifest, os);

    let fields: Vec<_> = manifest
        .field_order
        .iter()
        .filter_map(|name| manifest.fields.get(name))
        .filter(|f| full || f.flags.required || f.depth == 0)
        .map(|f| {
            // Scope per-OS maps when --os is set:
            //   none → emit the full map (`{macOS: ..., iOS: ...}`)
            //   some → emit a flat string (just that OS's value), so
            //          `jq '.fields[].introduced_by_platform'` reads a
            //          string instead of forcing the agent to drill
            //          another level.
            let intro_by_os = serialize_per_os_field(&f.introduced_by_platform, os);
            let dep_by_os = serialize_per_os_field(&f.deprecated_by_platform, os);
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
                "deprecated_in": f.deprecated_in,
                "introduced_by_platform": intro_by_os,
                "deprecated_by_platform": dep_by_os,
                "combinetype": f.combinetype,
                "depth": f.depth,
                "parent_key": f.parent_key,
                "title": f.title,
                "description": f.description,
            })
        })
        .collect();

    // Emit the os_support map keyed by platform name. When `--os` is
    // set, scope to that single platform so jq filters stay simple.
    let mut os_support = serde_json::Map::new();
    let entries: Vec<(Platform, &OsSupportDetail)> = match os {
        Some(p) => manifest
            .os_support
            .get(&p)
            .map(|d| vec![(p, d)])
            .unwrap_or_default(),
        None => {
            // Stable order: macOS, iOS, tvOS, watchOS, visionOS.
            let mut v = Vec::new();
            for p in [
                Platform::MacOS,
                Platform::Ios,
                Platform::TvOS,
                Platform::WatchOS,
                Platform::VisionOS,
            ] {
                if let Some(d) = manifest.os_support.get(&p) {
                    v.push((p, d));
                }
            }
            v
        }
    };
    for (p, d) in entries {
        os_support.insert(p.as_str().to_string(), os_support_to_json(d));
    }

    let info = serde_json::json!({
        "payload_type": manifest.payload_type,
        "title": manifest.title,
        "description": manifest.description,
        "category": manifest.category,
        "apply_mode": manifest.apply_mode,
        "platforms": platforms,
        "os_filter": os.map(|p| p.as_str()),
        "os_support": os_support,
        "field_count": manifest.fields.len(),
        "fields_returned": fields.len(),
        "fields": fields,
    });
    println!("{}", serde_json::to_string_pretty(&info)?);
    Ok(())
}

fn supported_platform_vec(m: &PayloadManifest, os: Option<Platform>) -> Vec<&'static str> {
    if let Some(p) = os {
        return vec![p.as_str()];
    }
    let mut v = Vec::new();
    if m.platforms.macos {
        v.push("macOS");
    }
    if m.platforms.ios {
        v.push("iOS");
    }
    if m.platforms.tvos {
        v.push("tvOS");
    }
    if m.platforms.watchos {
        v.push("watchOS");
    }
    if m.platforms.visionos {
        v.push("visionOS");
    }
    v
}

fn emit_payload_info_human(manifest: &PayloadManifest, full: bool, os: Option<Platform>) {
    println!("{}\n", manifest.title.bold());
    println!("{}: {}", "Payload Type".cyan(), manifest.payload_type);
    println!("{}: {}", "Category".cyan(), manifest.category.magenta());

    let platforms = supported_platform_vec(manifest, os);
    println!("{}: {}", "Platforms".cyan(), platforms.join(", "));

    // Per-OS support detail — show only if requested OS or if any platform has data.
    let to_show: Vec<(Platform, &OsSupportDetail)> = match os {
        Some(p) => manifest
            .os_support
            .get(&p)
            .map(|d| vec![(p, d)])
            .unwrap_or_default(),
        None => {
            let mut v = Vec::new();
            for p in [
                Platform::MacOS,
                Platform::Ios,
                Platform::TvOS,
                Platform::WatchOS,
                Platform::VisionOS,
            ] {
                if let Some(d) = manifest.os_support.get(&p) {
                    v.push((p, d));
                }
            }
            v
        }
    };
    if !to_show.is_empty() {
        println!("\n{}", "OS Support:".cyan().bold());
        for (p, d) in &to_show {
            let mut bits: Vec<String> = Vec::new();
            if let Some(v) = &d.introduced {
                bits.push(format!("introduced {v}"));
            }
            if let Some(v) = &d.deprecated {
                bits.push(format!("deprecated {v}").yellow().to_string());
            }
            if let Some(v) = &d.removed {
                bits.push(format!("removed {v}").red().to_string());
            }
            if d.supervised == Some(true) {
                bits.push("supervised".yellow().to_string());
            }
            if d.requires_dep == Some(true) {
                bits.push("requires DEP".yellow().to_string());
            }
            if d.user_approved_mdm == Some(true) {
                bits.push("UAMDM".yellow().to_string());
            }
            if d.device_channel == Some(true) {
                bits.push("device-channel".to_string());
            }
            if d.user_channel == Some(true) {
                bits.push("user-channel".to_string());
            }
            if d.multiple == Some(true) {
                bits.push("multiple-allowed".to_string());
            }
            if d.beta == Some(true) {
                bits.push("beta".magenta().to_string());
            }
            if let Some(e) = &d.allowed_enrollments
                && !e.is_empty()
            {
                bits.push(format!("enrollments=[{}]", e.join(",")));
            }
            if let Some(s) = &d.allowed_scopes
                && !s.is_empty()
            {
                bits.push(format!("scopes=[{}]", s.join(",")));
            }
            let summary = if bits.is_empty() {
                "(no per-OS detail)".dimmed().to_string()
            } else {
                bits.join("  ")
            };
            println!("  {}: {summary}", p.as_str().green());
        }
    }

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
