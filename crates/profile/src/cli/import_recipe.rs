//! `profile library import` — convert an existing `.mobileconfig`
//! into a TOML recipe inside a library directory.
//!
//! The inverse of `synthesize`: synthesize takes bare managed-pref
//! plists and produces `.mobileconfig`; this command takes a complete
//! `.mobileconfig` and produces a `recipe.toml` plus a `.meaning.md`
//! sidecar. Faithful pass-through — no payload-type-specific
//! unwrapping. MCX-style profiles produce deeply-nested `[profile.fields.*]`
//! sub-tables; the structure round-trips exactly.

use crate::cli::generate::load_registry;
use crate::cli::info::plist_tag_for;
use crate::output::OutputMode;
use crate::profile::parser::parse_profile_auto_unsign;
use crate::recipe::{ProfileSpec, Recipe, RecipeMeta};
use crate::schema::{PayloadManifest, Platform, SchemaRegistry};
use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Envelope keys that live on every payload — these are profile
/// metadata, not user-authored content. Mirror of
/// `synthesize::MANAGEMENT_KEYS` plus the Display/Description ones
/// that we hoist into `display_name` / `description` separately.
const MANAGEMENT_KEYS: &[&str] = &[
    "PayloadUUID",
    "PayloadIdentifier",
    "PayloadType",
    "PayloadVersion",
    "PayloadDisplayName",
    "PayloadDescription",
    "PayloadOrganization",
    "PayloadScope",
    "PayloadRemovalDisallowed",
    "PayloadEnabled",
];

/// Options for `library import`.
#[derive(Debug)]
pub struct LibraryImportOptions<'a> {
    pub input: &'a Path,
    pub into: &'a Path,
    pub name: Option<&'a str>,
    pub force: bool,
}

pub fn handle_library_import(
    opts: LibraryImportOptions<'_>,
    output_mode: OutputMode,
) -> Result<()> {
    if !opts.input.is_file() {
        anyhow::bail!("Input file not found: {}", opts.input.display());
    }

    // 1. Parse the mobileconfig (auto-unsigns if needed).
    let path_str = opts
        .input
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Input path is not valid UTF-8"))?;
    let profile = parse_profile_auto_unsign(path_str).with_context(|| {
        format!(
            "Failed to parse {} as a configuration profile",
            opts.input.display()
        )
    })?;

    // 2. Derive the recipe name (override > snake-cased file stem).
    let recipe_name = opts.name.map(str::to_string).unwrap_or_else(|| {
        recipe_name_from_path(opts.input).unwrap_or_else(|| "imported".to_string())
    });

    // 3. Compute output paths and refuse to overwrite without --force.
    let recipes_dir = opts.into.join("recipes");
    std::fs::create_dir_all(&recipes_dir)
        .with_context(|| format!("Failed to create {}", recipes_dir.display()))?;
    let recipe_path = recipes_dir.join(format!("{recipe_name}.toml"));
    let meaning_path = recipes_dir.join(format!("{recipe_name}.meaning.md"));
    if recipe_path.exists() && !opts.force {
        anyhow::bail!(
            "{} already exists. Re-run with --force to overwrite, or pass --name <NAME> to write a different file.",
            recipe_path.display()
        );
    }

    // 4. Build the Recipe struct from the parsed profile.
    let description = if profile.payload_display_name.trim().is_empty() {
        profile.payload_description().unwrap_or_default()
    } else {
        profile.payload_display_name.clone()
    };
    let vendor = profile.payload_organization();

    let mut profiles: Vec<ProfileSpec> = Vec::with_capacity(profile.payload_content.len());
    let mut seen_filenames: HashSet<String> = HashSet::new();
    let mut payload_types: Vec<String> = Vec::new();
    for inner in &profile.payload_content {
        let display_name = inner
            .payload_display_name()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| payload_type_tail(&inner.payload_type).to_string());
        let filename = unique_filename(&inner.payload_type, &mut seen_filenames);

        let mut fields: BTreeMap<String, toml::Value> = BTreeMap::new();
        for (k, v) in &inner.content {
            if MANAGEMENT_KEYS.contains(&k.as_str()) {
                continue;
            }
            match plist_value_to_toml(v) {
                Ok(tv) => {
                    fields.insert(k.clone(), tv);
                }
                Err(e) => {
                    anyhow::bail!(
                        "Cannot convert key '{}' on payload '{}': {}",
                        k,
                        inner.payload_type,
                        e
                    );
                }
            }
        }

        payload_types.push(inner.payload_type.clone());
        profiles.push(ProfileSpec {
            filename,
            payload_type: inner.payload_type.clone(),
            display_name,
            description: String::new(),
            removal_disallowed: false,
            fields,
            extra_fields: BTreeMap::new(),
        });
    }

    let recipe = Recipe {
        recipe: RecipeMeta {
            name: recipe_name.clone(),
            description,
            vendor,
            variables: None,
            secrets: None,
        },
        profiles,
        ddm: Vec::new(),
    };

    // 5. Serialize and write the TOML + sidecar.
    let toml_body =
        toml::to_string(&recipe).with_context(|| "Failed to serialize imported recipe to TOML")?;
    std::fs::write(&recipe_path, &toml_body)
        .with_context(|| format!("Failed to write {}", recipe_path.display()))?;

    // Schema-enrich the sidecar: pull title/description/platforms/OS
    // support from the embedded schema for each payload, plus per-field
    // docs for the keys this recipe sets. Best-effort — payloads not in
    // the schema (custom prefs, unknown vendor keys) get a "no schema
    // match" note rather than an empty section.
    let registry = load_registry(None).ok();
    let sidecar_body = build_meaning_md(&recipe, opts.input, registry.as_ref());
    std::fs::write(&meaning_path, sidecar_body)
        .with_context(|| format!("Failed to write {}", meaning_path.display()))?;

    // 6. Emit report.
    match output_mode {
        OutputMode::Json => {
            let payload = serde_json::json!({
                "success": true,
                "recipe_path": recipe_path.display().to_string(),
                "meaning_path": meaning_path.display().to_string(),
                "payload_count": payload_types.len(),
                "payload_types": payload_types,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputMode::Human => {
            println!(
                "{} Imported {} payload(s) into {}",
                "✓".green(),
                payload_types.len(),
                recipe_name.bold()
            );
            println!("  {} {}", "→".green(), recipe_path.display());
            println!("  {} {}", "→".green(), meaning_path.display());
            for pt in &payload_types {
                println!("    {} {}", "•".dimmed(), pt.dimmed());
            }
            println!();
            println!(
                "Next: contour profile generate --recipe-path {} --recipe {} --org com.acme -o ./out",
                opts.into.join("recipes").display(),
                recipe_name
            );
        }
    }

    Ok(())
}

/// Inverse of `cli::generate::toml_to_plist`. `plist::Value::Data` is
/// rejected explicitly (round-tripping binary blobs through TOML
/// needs a sentinel scheme — out of scope for the MVP).
pub fn plist_value_to_toml(v: &plist::Value) -> Result<toml::Value> {
    Ok(match v {
        plist::Value::String(s) => toml::Value::String(s.clone()),
        plist::Value::Boolean(b) => toml::Value::Boolean(*b),
        plist::Value::Integer(i) => i
            .as_signed()
            .map(toml::Value::Integer)
            .or_else(|| {
                i.as_unsigned()
                    .and_then(|u| i64::try_from(u).ok().map(toml::Value::Integer))
            })
            .ok_or_else(|| anyhow::anyhow!("integer out of i64 range"))?,
        plist::Value::Real(f) => toml::Value::Float(*f),
        plist::Value::Date(d) => {
            // Apple plist dates serialize as RFC 3339 — TOML datetimes
            // accept the same shape.
            let text: String = d.to_xml_format();
            text.parse::<toml::value::Datetime>()
                .map(toml::Value::Datetime)
                .map_err(|e| {
                    anyhow::anyhow!("plist date '{text}' not a valid TOML datetime: {e}")
                })?
        }
        plist::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(plist_value_to_toml(item)?);
            }
            toml::Value::Array(out)
        }
        plist::Value::Dictionary(dict) => {
            let mut tbl = toml::map::Map::new();
            for (k, v) in dict {
                tbl.insert(k.clone(), plist_value_to_toml(v)?);
            }
            toml::Value::Table(tbl)
        }
        plist::Value::Data(_) => {
            anyhow::bail!(
                "<data> binary value not supported on import yet — strip the binary key from the source profile, or open an issue if you need this."
            );
        }
        // Future-proofing: plist::Value is non-exhaustive.
        _ => anyhow::bail!("unsupported plist value variant"),
    })
}

/// Snake-case the file stem so `Privileges.mobileconfig` →
/// `privileges`, `My Org-Wifi.mobileconfig` → `my_org_wifi`.
fn recipe_name_from_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    let mut out = String::with_capacity(stem.len());
    let mut prev_alnum = false;
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() {
            out.extend(ch.to_lowercase());
            prev_alnum = true;
        } else if prev_alnum {
            out.push('-');
            prev_alnum = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() { None } else { Some(out) }
}

/// `com.apple.security.firewall` → `firewall`.
fn payload_type_tail(payload_type: &str) -> &str {
    payload_type.rsplit('.').next().unwrap_or(payload_type)
}

/// Produce a `<tail>.mobileconfig` filename per profile, suffixing
/// `-2`, `-3`, … on collisions so two payloads of the same type don't
/// land on the same filename.
fn unique_filename(payload_type: &str, seen: &mut HashSet<String>) -> String {
    let tail = payload_type_tail(payload_type);
    let base = format!("{tail}.mobileconfig");
    if seen.insert(base.clone()) {
        return base;
    }
    let mut n = 2;
    loop {
        let candidate = format!("{tail}-{n}.mobileconfig");
        if seen.insert(candidate.clone()) {
            return candidate;
        }
        n += 1;
    }
}

/// Build the schema-enriched `.meaning.md` sidecar.
///
/// Each `[[profile]]` in the recipe gets its own `### <title>` section
/// pulled from the registry — Apple's title/description/platforms/OS
/// support, plus per-field docs for the keys this recipe configures.
/// Payloads not in the schema (custom prefs, vendor envelopes whose
/// inner keys aren't documented) get a "no schema match" note so the
/// reader knows where docs stop being authoritative.
fn build_meaning_md(recipe: &Recipe, source: &Path, registry: Option<&SchemaRegistry>) -> String {
    let name = &recipe.recipe.name;
    let description = &recipe.recipe.description;
    let intent = if description.is_empty() {
        format!(
            "Imported from `{}`. Document what this profile does.",
            source.display()
        )
    } else {
        description.clone()
    };

    let mut out = String::new();
    let _ = writeln!(out, "# {name}\n");
    let _ = writeln!(
        out,
        "Imported from `{}` via `contour profile library import`. The",
        source.display()
    );
    let _ = writeln!(
        out,
        "listing description is taken from the profile's PayloadDisplayName"
    );
    let _ = writeln!(
        out,
        "/ PayloadDescription envelope. Sections under **Payloads** below"
    );
    let _ = writeln!(
        out,
        "are auto-populated from the embedded contour schema; everything"
    );
    let _ = writeln!(out, "else is yours to fill in.\n");

    let _ = writeln!(out, "## Intent\n");
    let _ = writeln!(out, "{intent}\n");

    let _ = writeln!(out, "## Source\n");
    let _ = writeln!(out, "- Original profile: `{}`", source.display());
    if let Some(vendor) = &recipe.recipe.vendor {
        let _ = writeln!(out, "- PayloadOrganization: `{vendor}`");
    }
    let _ = writeln!(out);

    // ── Schema-enriched payload sections ──────────────────────────────
    let _ = writeln!(out, "## Payloads\n");
    for spec in &recipe.profiles {
        append_payload_section(&mut out, spec, registry);
    }

    let _ = writeln!(out, "## References\n");
    let _ = writeln!(
        out,
        "- Apple device-management spec: <https://developer.apple.com/documentation/devicemanagement>"
    );
    let _ = writeln!(
        out,
        "- contour schema lookup: `contour profile info <payload_type> --full`"
    );
    let _ = writeln!(
        out,
        "- ProfileCreator manifests: <https://github.com/ProfileCreator/ProfileManifests>"
    );

    out
}

/// Render one `### <Title>` block per `[[profile]]`, pulling docs from
/// the schema when the payload is recognized.
fn append_payload_section(out: &mut String, spec: &ProfileSpec, registry: Option<&SchemaRegistry>) {
    let manifest = registry.and_then(|r| r.get_by_name(&spec.payload_type));

    let heading = match manifest {
        Some(m) if !m.title.is_empty() => format!("{} (`{}`)", m.title, spec.payload_type),
        _ => format!("`{}`", spec.payload_type),
    };
    let _ = writeln!(out, "### {heading}\n");

    match manifest {
        Some(m) => append_known_payload(out, spec, m),
        None => {
            let _ = writeln!(
                out,
                "_No schema match — likely a vendor-specific or custom payload."
            );
            let _ = writeln!(
                out,
                "Document the keys configured by this profile manually._\n"
            );
            append_recipe_keys_only(out, spec);
        }
    }
}

fn append_known_payload(out: &mut String, spec: &ProfileSpec, manifest: &PayloadManifest) {
    if !manifest.description.trim().is_empty() {
        let _ = writeln!(out, "{}\n", manifest.description.trim());
    }

    // Platforms with per-OS introduced versions. Iterate the platform
    // flags in a fixed order so the rendering is deterministic; fold in
    // os_support per-OS detail when present.
    let plats: Vec<(Platform, &'static str, bool)> = vec![
        (Platform::MacOS, "macOS", manifest.platforms.macos),
        (Platform::Ios, "iOS", manifest.platforms.ios),
        (Platform::TvOS, "tvOS", manifest.platforms.tvos),
        (Platform::WatchOS, "watchOS", manifest.platforms.watchos),
        (Platform::VisionOS, "visionOS", manifest.platforms.visionos),
    ];
    let parts: Vec<String> = plats
        .iter()
        .filter(|(_, _, supported)| *supported)
        .map(|(p, label, _)| {
            if let Some(detail) = manifest.os_support.get(p)
                && let Some(intro) = &detail.introduced
            {
                format!("{label} (introduced {intro})")
            } else {
                (*label).to_string()
            }
        })
        .collect();
    if !parts.is_empty() {
        let _ = writeln!(out, "**Platforms:** {}\n", parts.join(", "));
    }

    if !manifest.category.is_empty() {
        let _ = writeln!(out, "**Source:** {} schema\n", manifest.category);
    }

    let _ = writeln!(out, "**Fields configured by this recipe:**\n");
    let mut documented = 0usize;
    let mut undocumented: Vec<&String> = Vec::new();
    for key in spec.fields.keys() {
        match manifest.fields.get(key) {
            Some(field) => {
                let tag = plist_tag_for(&field.field_type);
                let plist_tag = if tag.is_empty() {
                    String::new()
                } else {
                    format!(" *(`<{tag}>`)*")
                };
                let required = if field.flags.required {
                    ", required"
                } else {
                    ""
                };
                let mut line = format!("- **`{}`**{plist_tag}{required}", field.name);
                if !field.description.trim().is_empty() {
                    let _ = write!(line, " — {}", first_sentence(&field.description));
                }
                if !field.allowed_values.is_empty() {
                    let _ = write!(line, " (allowed: {})", field.allowed_values.join(", "));
                }
                if let Some(default) = &field.default {
                    let _ = write!(line, " (default: `{default}`)");
                }
                if let Some(dep) = &field.deprecated_in {
                    let _ = write!(line, " *(deprecated in {dep})*");
                }
                let _ = writeln!(out, "{line}");
                documented += 1;
            }
            None => undocumented.push(key),
        }
    }
    if documented == 0 {
        let _ = writeln!(
            out,
            "- _(no top-level recipe fields matched documented schema keys — likely a vendor envelope wrapping nested settings)_"
        );
    }
    if !undocumented.is_empty() {
        let _ = writeln!(
            out,
            "\n**Keys not in the schema (vendor-specific or typo?):**\n"
        );
        for key in undocumented {
            let _ = writeln!(out, "- `{key}`");
        }
    }
    let _ = writeln!(out);
}

fn append_recipe_keys_only(out: &mut String, spec: &ProfileSpec) {
    if spec.fields.is_empty() {
        return;
    }
    let _ = writeln!(out, "**Top-level keys configured by this recipe:**\n");
    for key in spec.fields.keys() {
        let _ = writeln!(out, "- `{key}`");
    }
    let _ = writeln!(out);
}

/// Schema descriptions are full sentences/paragraphs. Trim to the first
/// sentence so the bullet list stays scannable.
fn first_sentence(s: &str) -> String {
    let trimmed = s.trim();
    if let Some(end) = trimmed.find(". ") {
        trimmed[..=end].trim().to_string()
    } else if let Some(stripped) = trimmed.strip_suffix('.') {
        format!("{stripped}.")
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipe_name_snake_cases_filename() {
        assert_eq!(
            recipe_name_from_path(Path::new("/tmp/Privileges.mobileconfig")).as_deref(),
            Some("privileges")
        );
        assert_eq!(
            recipe_name_from_path(Path::new("My Org-Wifi.mobileconfig")).as_deref(),
            Some("my-org-wifi")
        );
        // file_stem strips only the last extension, so internal dots
        // turn into separators per the snake-case rule.
        assert_eq!(
            recipe_name_from_path(Path::new("foo.bar.mobileconfig")).as_deref(),
            Some("foo-bar")
        );
    }

    #[test]
    fn payload_tail_strips_reverse_dns() {
        assert_eq!(payload_type_tail("com.apple.security.firewall"), "firewall");
        assert_eq!(payload_type_tail("custom"), "custom");
    }

    #[test]
    fn unique_filename_disambiguates_collisions() {
        let mut seen = HashSet::new();
        assert_eq!(
            unique_filename("com.apple.security.firewall", &mut seen),
            "firewall.mobileconfig"
        );
        assert_eq!(
            unique_filename("com.apple.security.firewall", &mut seen),
            "firewall-2.mobileconfig"
        );
        assert_eq!(
            unique_filename("com.apple.security.firewall", &mut seen),
            "firewall-3.mobileconfig"
        );
    }

    #[test]
    fn plist_to_toml_round_trips_primitives() {
        // String, bool, int, float, array, nested dict.
        let mut dict = plist::Dictionary::new();
        dict.insert("s".into(), plist::Value::String("x".into()));
        dict.insert("b".into(), plist::Value::Boolean(true));
        dict.insert("i".into(), plist::Value::Integer(42i64.into()));
        dict.insert("f".into(), plist::Value::Real(1.5));
        dict.insert(
            "arr".into(),
            plist::Value::Array(vec![
                plist::Value::Integer(1i64.into()),
                plist::Value::Integer(2i64.into()),
            ]),
        );
        let mut nested = plist::Dictionary::new();
        nested.insert("inner".into(), plist::Value::String("y".into()));
        dict.insert("d".into(), plist::Value::Dictionary(nested));

        let toml_value = plist_value_to_toml(&plist::Value::Dictionary(dict)).unwrap();
        let tbl = toml_value.as_table().unwrap();
        assert_eq!(tbl["s"].as_str(), Some("x"));
        assert_eq!(tbl["b"].as_bool(), Some(true));
        assert_eq!(tbl["i"].as_integer(), Some(42));
        assert_eq!(tbl["f"].as_float(), Some(1.5));
        assert_eq!(tbl["arr"].as_array().unwrap().len(), 2);
        assert_eq!(tbl["d"]["inner"].as_str(), Some("y"));
    }

    #[test]
    fn plist_to_toml_rejects_data_blobs() {
        let v = plist::Value::Data(vec![1, 2, 3]);
        let err = plist_value_to_toml(&v).unwrap_err();
        assert!(
            err.to_string().contains("<data>"),
            "error must mention <data>; got: {err}"
        );
    }
}
