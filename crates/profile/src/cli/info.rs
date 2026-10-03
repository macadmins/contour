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
        "next": next_steps(config),
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
                "apple_device_management_seed": {
                    "commit": sv.apple_device_management_seed_commit,
                    "date": sv.apple_device_management_seed_date,
                    "release": sv.apple_device_management_seed_release,
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
    println!(
        "  Apple device-management: {} ({})",
        apple_sha, sv.apple_device_management_date
    );
    if !sv.apple_device_management_seed_commit.is_empty() {
        let seed_sha = sv.apple_device_management_seed_commit
            [..7.min(sv.apple_device_management_seed_commit.len())]
            .to_string();
        println!(
            "  Apple seed (--beta):     {} ({}, {})",
            seed_sha, sv.apple_device_management_seed_release, sv.apple_device_management_seed_date
        );
    }
    // Printed only when the dataset records it. This was an unconditional
    // line, so after the ProfileCreator corpus was removed it reported
    // "ProfileManifests: unknown ()" — a source that is not merely at an
    // unknown revision but is not used at all. A provenance display that
    // names a source the dataset does not carry is worse than one that says
    // nothing.
    if !sv.profile_manifests_commit.is_empty() {
        println!(
            "  ProfileManifests:        {} ({})",
            &sv.profile_manifests_commit[..7.min(sv.profile_manifests_commit.len())],
            sv.profile_manifests_date
        );
    }
    println!("  Generated:               {}", sv.generation_date);
    contour_core::output::print_next_steps(&next_steps(config));
}

/// What to do after reading the summary: set the org if there is none,
/// then find a key or start from a preset.
fn next_steps(config: Option<&ProfileConfig>) -> Vec<contour_core::output::NextStep> {
    use contour_core::output::NextStep;
    let mut steps = Vec::new();
    let org = match config {
        Some(c) => c.organization.domain.clone(),
        None => {
            steps.push(NextStep::new(
                "No profile.toml — set your org once",
                "contour init --domain <your.domain> --yes",
            ));
            "<your.domain>".to_string()
        }
    };
    steps.push(NextStep::new(
        "Find the payload or key for a setting",
        "contour profile search <keyword> --json",
    ));
    steps.push(NextStep::new(
        "Start from a DDM preset",
        format!("contour profile ddm compose --list-presets   # then --preset <name> --org {org} -o <dir>"),
    ));
    steps
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
/// `os_filter` (the `--os <NAME>` flag) scopes the platform list and the
/// per-OS support detail to that platform — fails fast if the payload itself
/// isn't supported there. The field list is not filtered by OS.
pub fn handle_payload_info(
    payload_type: &str,
    schema_path: Option<&str>,
    full: bool,
    os_filter: Option<&str>,
    channel: crate::schema::Channel,
    windows: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = if windows {
        SchemaRegistry::embedded_windows()?
    } else if let Some(p) = schema_path {
        SchemaRegistry::from_auto_detect(Path::new(p))?
    } else {
        if channel.is_beta() {
            crate::cli::ddm::note_if_beta_is_retired();
        }
        SchemaRegistry::embedded_channel(channel)?
    };

    let manifest = registry.get(payload_type).ok_or_else(|| {
        // A payload contour withheld on purpose is not "not found". Saying so
        // is the difference between an agent asking for the community corpus
        // and an agent deciding the domain does not exist and inventing keys
        // for it — which is what happened before this branch existed.
        if let Some(why) = registry.why_withheld(payload_type) {
            return anyhow::anyhow!("{why}");
        }
        // Cross-channel hint first — the most actionable on a seed-only type.
        if let Some(hint) = crate::schema::suggest_other_channel(payload_type, channel, false) {
            return anyhow::anyhow!("Payload type '{payload_type}' not found.\n{hint}");
        }
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
        Platform::Windows => m.platforms.windows,
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
    if m.platforms.windows {
        p.push("Windows");
    }
    if p.is_empty() {
        "(none)".into()
    } else {
        p.join(", ")
    }
}

/// The dynamic-keys facts for one field, as `profile info` and `ddm info`
/// both emit them. Three keys, always present: `placeholder` says this entry
/// is itself a marker (`ANY`, `{{key}}`, `{{value}}`) and not a key an
/// operator writes; `dynamic_keys` says this dictionary's keys are supplied
/// by the operator; `value_shape` then describes each value.
pub(crate) fn dynamic_keys_json(
    manifest: &PayloadManifest,
    f: &crate::schema::FieldDefinition,
) -> serde_json::Map<String, serde_json::Value> {
    let shape = manifest.dynamic_value_shape(f);
    let mut m = serde_json::Map::new();
    m.insert("placeholder".into(), serde_json::json!(f.is_placeholder()));
    m.insert("dynamic_keys".into(), serde_json::json!(shape.is_some()));
    m.insert(
        "value_shape".into(),
        match shape {
            Some(v) => serde_json::json!({
                "type": v.field_type.as_str(),
                "plist_tag": plist_tag_for(&v.field_type),
                "fields": manifest.child_names(v),
            }),
            None => serde_json::Value::Null,
        },
    );
    m
}

/// Manifest-level dynamic-keys facts: `dynamic_keys` when the payload's own
/// top-level keys are operator-named, with the `value_shape` each takes.
pub(crate) fn root_dynamic_keys_json(
    manifest: &PayloadManifest,
) -> serde_json::Map<String, serde_json::Value> {
    let shape = manifest.root_dynamic_value_shape();
    let mut m = serde_json::Map::new();
    m.insert("dynamic_keys".into(), serde_json::json!(shape.is_some()));
    m.insert(
        "value_shape".into(),
        match shape {
            Some(v) => serde_json::json!({
                "type": v.field_type.as_str(),
                "plist_tag": plist_tag_for(&v.field_type),
                "fields": manifest.child_names(v),
            }),
            None => serde_json::Value::Null,
        },
    );
    m
}

/// Serialize an `OsSupportDetail` to a JSON object — same shape across
/// every consumer (`info`, future search, etc.).
pub(crate) fn os_support_to_json(detail: &OsSupportDetail) -> serde_json::Value {
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

/// The `os_support` JSON map keyed by platform name, in Apple's canonical
/// order. With `os` set, only that platform — so jq filters stay simple.
pub(crate) fn os_support_json_map(
    manifest: &PayloadManifest,
    os: Option<Platform>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    let entries: Vec<(Platform, &OsSupportDetail)> = match os {
        Some(p) => manifest
            .os_support
            .get(&p)
            .map(|d| vec![(p, d)])
            .unwrap_or_default(),
        None => [
            Platform::MacOS,
            Platform::Ios,
            Platform::TvOS,
            Platform::WatchOS,
            Platform::VisionOS,
        ]
        .into_iter()
        .filter_map(|p| manifest.os_support.get(&p).map(|d| (p, d)))
        .collect(),
    };
    for (p, d) in entries {
        out.insert(p.as_str().to_string(), os_support_to_json(d));
    }
    out
}

/// Print the per-platform support block, or nothing when no platform has
/// detail. Shared by `profile info` and `ddm info` so the two surfaces cannot
/// drift: Apple states scopes, enrollments and versions per platform, and the
/// platforms disagree on most declaration types, so this is never unioned.
pub(crate) fn print_os_support(manifest: &PayloadManifest, os: Option<Platform>) {
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
            let mut entry = serde_json::json!({
                "name": f.name,
                "type": f.field_type.as_str(),
                "plist_tag": plist_tag_for(&f.field_type),
                "required": f.flags.required,
                "supervised": f.flags.supervised,
                "sensitive": f.flags.sensitive,
                "default": f.default,
                "allowed_values": f.allowed_values,
                // The DDF's word, for a Windows node: what each value means,
                // what it depends on, where it applies, and whether it must
                // travel inside <Atomic>. `null` for Apple keys.
                "value_meanings": node_details()
                    .get(&(manifest.payload_type.clone(), f.path.clone()))
                    .map(|d| d.value_descriptions.iter().map(|v| serde_json::json!({"value": v.value, "description": v.description})).collect::<Vec<_>>()),
                "dependencies": node_details()
                    .get(&(manifest.payload_type.clone(), f.path.clone()))
                    .map(|d| d.dependencies.iter().map(|x| serde_json::json!({"kind": x.kind, "uri": x.uri, "values": x.values})).collect::<Vec<_>>()),
                "editions": node_details()
                    .get(&(manifest.payload_type.clone(), f.path.clone()))
                    .and_then(|d| d.editions.clone()),
                "atomic_required": node_details()
                    .get(&(manifest.payload_type.clone(), f.path.clone()))
                    .map(|d| d.atomic_required),
                // Empty: the key is on every platform the payload is.
                // Otherwise only these — Apple marked the rest n/a.
                "platforms": f.platforms.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                "min_version": f.min_version,
                "deprecated_in": f.deprecated_in,
                "introduced_by_platform": intro_by_os,
                "deprecated_by_platform": dep_by_os,
                "combinetype": f.combinetype,
                "depth": f.depth,
                "parent_key": f.parent_key,
                "title": f.title,
                "description": f.description,
            });
            entry
                .as_object_mut()
                .expect("json! object")
                .extend(dynamic_keys_json(manifest, f));
            entry
        })
        .collect();

    let os_support = os_support_json_map(manifest, os);

    let mut info = serde_json::json!({
        "payload_type": manifest.payload_type,
        "title": manifest.title,
        "description": manifest.description,
        "category": manifest.category,
        "kind": manifest.kind.map(|k| k.as_str()),
        "authorable": manifest.is_authorable(),
        // The default envelope for a .mobileconfig of this type — Direct or
        // McxWrapped — or null for a declaration. A default, not a rule: a
        // preference domain is also valid delivered directly.
        "nesting": crate::schema::form::default_nesting(crate::schema::form::kind_of(manifest)),
        "apply_mode": manifest.apply_mode,
        "platforms": platforms,
        "os_filter": os.map(|p| p.as_str()),
        "os_support": os_support,
        "field_count": manifest.fields.len(),
        "fields_returned": fields.len(),
        "fields": fields,
    });
    info.as_object_mut()
        .expect("json! object")
        .extend(root_dynamic_keys_json(manifest));
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
    if m.platforms.windows {
        v.push("Windows");
    }
    v
}

fn emit_payload_info_human(manifest: &PayloadManifest, full: bool, os: Option<Platform>) {
    println!("{}\n", manifest.title.bold());
    println!("{}: {}", "Payload Type".cyan(), manifest.payload_type);
    println!("{}: {}", "Category".cyan(), manifest.category.magenta());
    if let Some(k) = manifest.kind {
        println!("{}: {}", "Kind".cyan(), k.as_str());
    }
    if let Some(n) = crate::schema::form::default_nesting(crate::schema::form::kind_of(manifest)) {
        let note = match n {
            crate::schema::formspec::Nesting::McxWrapped => {
                " (default — direct delivery is also valid; `form emit --direct`)"
            }
            crate::schema::formspec::Nesting::Direct => "",
        };
        println!("{}: {:?}{}", "Nesting".cyan(), n, note.dimmed());
    }
    if !manifest.is_authorable() {
        let because = manifest
            .kind
            .and_then(mdm_schema::PayloadKind::not_authorable_reason)
            .unwrap_or("not a document an operator authors");
        println!(
            "{} {}",
            "!".yellow(),
            format!(
                "Not authorable: this is {because}. `profile generate` refuses it; see \
                 `contour profile command`."
            )
            .yellow()
        );
    }

    let platforms = supported_platform_vec(manifest, os);
    println!("{}: {}", "Platforms".cyan(), platforms.join(", "));

    print_os_support(manifest, os);

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
        emit_app_schema_facts(&manifest.payload_type);
        emit_admx_payloads(&manifest.payload_type, full);
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
        // The DDF's word, where the dataset carries it: value meanings beside
        // the bare numbers, dependencies, editions, Atomic.
        if let Some(d) = node_details().get(&(manifest.payload_type.clone(), f.path.clone())) {
            for v in &d.value_descriptions {
                println!(
                    "{}    {} — {}",
                    indent,
                    v.value.cyan(),
                    v.description.dimmed()
                );
            }
            for dep in &d.dependencies {
                println!(
                    "{}  depends on: {} {} {}",
                    indent,
                    dep.uri.dimmed(),
                    if dep.kind == "Not" { "≠" } else { "=" },
                    dep.values.join(" | ").dimmed()
                );
            }
            if let Some(e) = &d.editions {
                println!("{}  editions: {}", indent, e.dimmed());
            }
            if d.atomic_required {
                println!(
                    "{}  atomic: {}",
                    indent,
                    "must be delivered inside <Atomic> with its siblings".yellow()
                );
            }
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

    emit_app_schema_facts(&manifest.payload_type);
    emit_admx_payloads(&manifest.payload_type, full);
}

/// App Schema facts for a domain, read once per process.
fn app_schema_facts() -> &'static (
    Vec<mdm_schema::AppSchemaKey>,
    Vec<mdm_schema::AppSchemaRule>,
) {
    static FACTS: std::sync::OnceLock<(
        Vec<mdm_schema::AppSchemaKey>,
        Vec<mdm_schema::AppSchemaRule>,
    )> = std::sync::OnceLock::new();
    FACTS.get_or_init(|| {
        let keys = mdm_schema::app_schema::keys::read(mdm_schema::embedded_app_schema_keys())
            .unwrap_or_default();
        let rules = mdm_schema::app_schema::rules::read(mdm_schema::embedded_app_schema_rules())
            .unwrap_or_default();
        (keys, rules)
    })
}

/// What the DDF says about a Windows CSP node beyond its type, read once per
/// process and indexed by `(payload_type, key_path)`. Empty for Apple types
/// and on a dataset without the table.
fn node_details() -> &'static std::collections::HashMap<(String, String), windows_schema::NodeDetail>
{
    static DETAILS: std::sync::OnceLock<
        std::collections::HashMap<(String, String), windows_schema::NodeDetail>,
    > = std::sync::OnceLock::new();
    DETAILS.get_or_init(|| {
        windows_schema::node_details::read(windows_schema::embedded_windows_node_details())
            .unwrap_or_default()
            .into_iter()
            .map(|d| ((d.payload_type.clone(), d.key_path.clone()), d))
            .collect()
    })
}

/// ADMX policies for ADMX-backed Windows CSP nodes, read once per process.
fn admx_policies() -> &'static Vec<windows_schema::AdmxPolicy> {
    static POLICIES: std::sync::OnceLock<Vec<windows_schema::AdmxPolicy>> =
        std::sync::OnceLock::new();
    POLICIES.get_or_init(|| {
        windows_schema::admx_policies::read(windows_schema::embedded_windows_admx_policies())
            .unwrap_or_default()
    })
}

/// Print what a profile must not set for this domain, and its rules.
///
/// Only domains described from an App Schema document have these:
/// ProfileManifests cannot say that a key is written by the app, replaced,
/// or read from another payload.
fn emit_app_schema_facts(payload_type: &str) {
    let (keys, rules) = app_schema_facts();
    let mine: Vec<&mdm_schema::AppSchemaKey> =
        keys.iter().filter(|k| k.domain == payload_type).collect();
    let my_rules: Vec<&mdm_schema::AppSchemaRule> =
        rules.iter().filter(|r| r.domain == payload_type).collect();
    if mine.is_empty() && my_rules.is_empty() {
        return;
    }

    let mistakes: Vec<&&mdm_schema::AppSchemaKey> =
        mine.iter().filter(|k| k.is_profile_mistake()).collect();
    if !mistakes.is_empty() {
        println!(
            "
{}:",
            "Do not set in a profile".red().bold()
        );
        for key in &mistakes {
            let why = match key.kind.as_str() {
                "runtime" => "written by the app",
                "dynamic" => "written by a script",
                _ => "no longer read",
            };
            let replacement = key
                .replacement_key
                .as_ref()
                .map(|r| format!(" — use {r}"))
                .unwrap_or_default();
            println!("  {} ({why}){}", key.key.yellow(), replacement.dimmed());
        }
    }

    let external: Vec<&&mdm_schema::AppSchemaKey> =
        mine.iter().filter(|k| k.kind == "external").collect();
    if !external.is_empty() {
        println!(
            "
{}:",
            "Read from another payload".cyan().bold()
        );
        for key in &external {
            let domain = key.replacement_domain.as_deref().unwrap_or("?");
            println!("  {} in {}", key.key.green(), domain.dimmed());
        }
    }

    let deprecated: Vec<&&mdm_schema::AppSchemaKey> =
        mine.iter().filter(|k| k.kind == "deprecated").collect();
    if !deprecated.is_empty() {
        println!(
            "
{}:",
            "Deprecated".yellow().bold()
        );
        for key in &deprecated {
            let replacement = key
                .replacement_key
                .as_ref()
                .map(|r| format!(" — use {r}"))
                .unwrap_or_default();
            println!("  {}{}", key.key.yellow(), replacement.dimmed());
        }
    }

    if !my_rules.is_empty() {
        println!(
            "
{} ({}):",
            "Rules".cyan().bold(),
            my_rules.len()
        );
        for rule in &my_rules {
            let severity = match rule.severity.as_str() {
                "error" => rule.severity.red(),
                "warning" => rule.severity.yellow(),
                _ => rule.severity.blue(),
            };
            println!("  [{severity}] {}", rule.message);
        }
    }
}

/// Print the payload each ADMX-backed node needs, with its elements.
///
/// A DDF node says only that a setting is ADMX-backed; this is the element
/// schema that makes it settable.
fn emit_admx_payloads(payload_type: &str, full: bool) {
    let mine: Vec<&windows_schema::AdmxPolicy> = admx_policies()
        .iter()
        .filter(|p| p.payload_type == payload_type)
        .collect();
    if mine.is_empty() {
        return;
    }
    let shown = if full { mine.len() } else { mine.len().min(5) };
    println!(
        "
{} ({} of {}):",
        "ADMX payloads".cyan().bold(),
        shown,
        mine.len()
    );
    for policy in mine.iter().take(shown) {
        println!("  {} [{}]", policy.key_name.green(), policy.class.dimmed());
        println!("    {}", policy.payload(None).dimmed());
        for element in &policy.elements {
            let choices = if element.items.is_empty() {
                String::new()
            } else {
                format!(
                    "  values: {}",
                    element
                        .items
                        .iter()
                        .map(|i| i.value.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            println!(
                "    {} <{}>{}",
                element.id,
                element.kind.cyan(),
                choices.dimmed()
            );
        }
    }
    if shown < mine.len() {
        println!(
            "
  {} {} more ADMX payloads hidden (use --full to show)",
            "ℹ".blue(),
            mine.len() - shown
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_info_no_config() {
        // Should not panic with no config
        let result = handle_info(None, OutputMode::Json);
        result.unwrap();
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
        result.unwrap();
    }
}

#[cfg(test)]
mod os_support_tests {
    use super::*;

    fn manifest() -> PayloadManifest {
        let mut m = PayloadManifest {
            manifest_source: None,
            fields_recording_availability: Default::default(),
            payload_type: "com.test.configuration.scopes".to_string(),
            kind: None,
            title: String::new(),
            description: String::new(),
            platforms: crate::schema::types::Platforms::default(),
            min_versions: std::collections::HashMap::new(),
            os_support: std::collections::HashMap::new(),
            apply_mode: None,
            category: "ddm-configuration".to_string(),
            fields: std::collections::HashMap::new(),
            field_order: vec![],
            segments: vec![],
        };
        m.os_support.insert(
            Platform::MacOS,
            OsSupportDetail {
                introduced: Some("26.0".into()),
                allowed_scopes: Some(vec!["user".into()]),
                ..Default::default()
            },
        );
        m.os_support.insert(
            Platform::Ios,
            OsSupportDetail {
                introduced: Some("26.0".into()),
                allowed_scopes: Some(vec!["system".into()]),
                ..Default::default()
            },
        );
        m
    }

    /// The map is per platform and only for platforms with detail. A tvOS
    /// entry Apple marked n/a has no row upstream and must not appear here
    /// either — and nothing may union macOS `user` with iOS `system`.
    #[test]
    fn os_support_map_is_per_platform_and_omits_absent_platforms() {
        let m = manifest();
        let map = os_support_json_map(&m, None);
        assert_eq!(map.keys().collect::<Vec<_>>(), vec!["macOS", "iOS"]);
        assert_eq!(map["macOS"]["allowed_scopes"], serde_json::json!(["user"]));
        assert_eq!(map["iOS"]["allowed_scopes"], serde_json::json!(["system"]));
        assert!(!map.contains_key("tvOS"));

        let only = os_support_json_map(&m, Some(Platform::Ios));
        assert_eq!(only.keys().collect::<Vec<_>>(), vec!["iOS"]);
        assert!(os_support_json_map(&m, Some(Platform::TvOS)).is_empty());
    }
}
