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
use crate::profile::parser::{XmlComment, parse_profile_lenient};
use crate::recipe::{ProfileSpec, Recipe, RecipeMeta};
use crate::schema::{PayloadManifest, Platform, SchemaRegistry};
use anyhow::{Context, Result};
use base64::Engine;
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
    // Directory mode: walk the tree, import each .mobileconfig with
    // `--name` derived from the filename (the `--name` override is
    // only meaningful for single-file imports). Failures don't abort
    // the run — they're collected and reported.
    if opts.input.is_dir() {
        if opts.name.is_some() {
            anyhow::bail!(
                "--name cannot be combined with a directory input — names are derived from each file's stem in bulk mode."
            );
        }
        return handle_directory_import(opts, output_mode);
    }
    if !opts.input.is_file() {
        anyhow::bail!("Input not found: {}", opts.input.display());
    }
    let report = import_any_file(opts.input, opts.into, opts.name, opts.force)?;
    emit_single_report(&report, output_mode);
    Ok(())
}

/// Dispatch a single file to the right importer based on extension.
/// `.mobileconfig` → MDM recipe; `.json` → DDM bundle.
fn import_any_file(
    input: &Path,
    into: &Path,
    name_override: Option<&str>,
    force: bool,
) -> Result<SingleImportReport> {
    match input.extension().and_then(|s| s.to_str()) {
        Some("mobileconfig") => import_one(input, into, name_override, force),
        Some("json") => import_ddm_json(input, into, name_override, force),
        Some(other) => {
            anyhow::bail!("unsupported extension '.{other}' — expected .mobileconfig or .json")
        }
        None => anyhow::bail!("input file has no extension; expected .mobileconfig or .json"),
    }
}

/// Walk `<INPUT>` recursively for `*.mobileconfig` and `*.json`
/// (DDM declarations) and import each.
fn handle_directory_import(opts: LibraryImportOptions<'_>, output_mode: OutputMode) -> Result<()> {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_importable_files(opts.input, &mut files)?;
    files.sort();

    let mut succeeded: Vec<SingleImportReport> = Vec::new();
    let mut failed: Vec<(PathBuf, String)> = Vec::new();
    // Track names claimed in *this* run so two source files with the
    // same stem (e.g. `ios/lock-screen-message.mobileconfig` and
    // `ipados/lock-screen-message.mobileconfig`) get disambiguated by
    // their parent directory name rather than colliding.
    let mut claimed: HashSet<String> = HashSet::new();

    for file in &files {
        let name = bulk_recipe_name(file, &claimed);
        claimed.insert(name.clone());
        match import_any_file(file, opts.into, Some(&name), opts.force) {
            Ok(report) => succeeded.push(report),
            Err(e) => failed.push((file.clone(), format!("{e:#}"))),
        }
    }

    match output_mode {
        OutputMode::Json => {
            let payload = serde_json::json!({
                "success": failed.is_empty(),
                "scanned": files.len(),
                "imported": succeeded.len(),
                "failed": failed.len(),
                "imports": succeeded.iter().map(|r| serde_json::json!({
                    "input": r.input.display().to_string(),
                    "recipe_path": r.recipe_path.display().to_string(),
                    "meaning_path": r.meaning_path.display().to_string(),
                    "payload_count": r.payload_types.len(),
                    "payload_types": r.payload_types,
                })).collect::<Vec<_>>(),
                "failures": failed.iter().map(|(p, e)| serde_json::json!({
                    "input": p.display().to_string(),
                    "error": e,
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputMode::Human => {
            println!(
                "{} Bulk import: {} succeeded, {} failed (of {} scanned)",
                if failed.is_empty() {
                    "✓".green()
                } else {
                    "!".yellow()
                },
                succeeded.len(),
                failed.len(),
                files.len(),
            );
            for r in &succeeded {
                println!(
                    "  {} {} → {}",
                    "→".green(),
                    r.input.display(),
                    r.recipe_path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default()
                );
            }
            for (p, err) in &failed {
                println!("  {} {}: {}", "✗".red(), p.display(), err);
            }
        }
    }

    if !failed.is_empty() {
        // Non-fatal exit for bulk imports — partial success is the
        // common case. JSON consumers gate on `success` / `failed`.
        anyhow::bail!("{} of {} imports failed", failed.len(), files.len());
    }
    Ok(())
}

#[derive(Debug, Default, Clone, Copy)]
struct CommentInjectionStats {
    total: usize,
    anchored: usize,
    dropped: usize,
}

#[derive(Debug)]
struct SingleImportReport {
    input: PathBuf,
    recipe_path: PathBuf,
    meaning_path: PathBuf,
    payload_types: Vec<String>,
    comment_stats: CommentInjectionStats,
}

fn import_one(
    input: &Path,
    into: &Path,
    name_override: Option<&str>,
    force: bool,
) -> Result<SingleImportReport> {
    // 1. Lenient parse — handles signed/unsigned + MDM placeholder
    //    sentinels. The placeholder mapping flows through to the value
    //    converter so `<data>$VAR</data>` round-trips back to the
    //    original placeholder string in TOML.
    let path_str = input
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Input path is not valid UTF-8"))?;
    let fixup = parse_profile_lenient(path_str).with_context(|| {
        format!(
            "Failed to parse {} as a configuration profile",
            input.display()
        )
    })?;
    let profile = fixup.profile;
    let placeholder_mapping = fixup.placeholder_mapping;
    let xml_comments = fixup.comments;

    // 2. Recipe name.
    let recipe_name = name_override
        .map(str::to_string)
        .unwrap_or_else(|| recipe_name_from_path(input).unwrap_or_else(|| "imported".to_string()));

    // 3. Output paths.
    let recipes_dir = into.join("recipes");
    std::fs::create_dir_all(&recipes_dir)
        .with_context(|| format!("Failed to create {}", recipes_dir.display()))?;
    let recipe_path = recipes_dir.join(format!("{recipe_name}.toml"));
    let meaning_path = recipes_dir.join(format!("{recipe_name}.meaning.md"));
    if recipe_path.exists() && !force {
        anyhow::bail!(
            "{} already exists. Re-run with --force to overwrite, or pass --name <NAME> to write a different file.",
            recipe_path.display()
        );
    }

    // 4. Build the Recipe.
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
            let tv = plist_value_to_toml(v, &placeholder_mapping).with_context(|| {
                format!("converting key '{k}' on payload '{}'", inner.payload_type)
            })?;
            fields.insert(k.clone(), tv);
        }

        // Inner payloads can carry their own `PayloadRemovalDisallowed`
        // (rare — usually only the top-level envelope sets it), but the
        // top-level envelope is the authoritative source for whether
        // an end user can rip the profile back off. Surface it on
        // every `[[profile]]` so a regenerate-from-recipe round-trip
        // matches the source's intent.
        let removal_disallowed = inner
            .content
            .get("PayloadRemovalDisallowed")
            .and_then(|v| v.as_boolean())
            .unwrap_or_else(|| {
                profile
                    .additional_fields
                    .get("PayloadRemovalDisallowed")
                    .and_then(|v| v.as_boolean())
                    .unwrap_or(false)
            });

        // MCX auto-unwrap: profiles of type
        // `com.apple.ManagedClient.preferences` carry settings deeply
        // nested under PayloadContent.<domain>.Forced[0].mcx_preference_settings.
        // Detect and flatten so the recipe TOML reads naturally;
        // `mcx_domain` is set so `generate --recipe` re-wraps on the
        // way out. When the structure doesn't match the canonical
        // shape (e.g. multiple Forced entries, multiple domains), we
        // fall back to faithful pass-through.
        let (mcx_domain, fields) = unwrap_mcx_if_canonical(&inner.payload_type, fields);

        payload_types.push(inner.payload_type.clone());
        profiles.push(ProfileSpec {
            filename,
            payload_type: inner.payload_type.clone(),
            display_name,
            description: String::new(),
            removal_disallowed,
            mcx_domain,
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

    // 5. Write TOML + enriched sidecar.
    let raw_toml =
        toml::to_string(&recipe).with_context(|| "Failed to serialize imported recipe to TOML")?;
    // Inject XML comments captured from the source as TOML `#` lines
    // above the matching `key = value` pair. The plist crate strips
    // `<!-- … -->` on parse; the lenient parser kept them aside via
    // `extract_comments`, anchored to the next non-empty XML line.
    let (toml_body, comment_stats) = inject_xml_comments(&raw_toml, &xml_comments);
    std::fs::write(&recipe_path, &toml_body)
        .with_context(|| format!("Failed to write {}", recipe_path.display()))?;
    let registry = load_registry(None).ok();
    let sidecar_body = build_meaning_md(&recipe, input, registry.as_ref());
    std::fs::write(&meaning_path, sidecar_body)
        .with_context(|| format!("Failed to write {}", meaning_path.display()))?;

    Ok(SingleImportReport {
        input: input.to_path_buf(),
        recipe_path,
        meaning_path,
        payload_types,
        comment_stats,
    })
}

fn emit_single_report(report: &SingleImportReport, output_mode: OutputMode) {
    match output_mode {
        OutputMode::Json => {
            let payload = serde_json::json!({
                "success": true,
                "recipe_path": report.recipe_path.display().to_string(),
                "meaning_path": report.meaning_path.display().to_string(),
                "payload_count": report.payload_types.len(),
                "payload_types": report.payload_types,
                "comments": {
                    "total": report.comment_stats.total,
                    "anchored": report.comment_stats.anchored,
                    "dropped": report.comment_stats.dropped,
                },
            });
            if let Ok(s) = serde_json::to_string_pretty(&payload) {
                println!("{s}");
            }
        }
        OutputMode::Human => {
            let recipe_name = report
                .recipe_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("imported");
            println!(
                "{} Imported {} payload(s) into {}",
                "✓".green(),
                report.payload_types.len(),
                recipe_name.bold()
            );
            println!("  {} {}", "→".green(), report.recipe_path.display());
            println!("  {} {}", "→".green(), report.meaning_path.display());
            for pt in &report.payload_types {
                println!("    {} {}", "•".dimmed(), pt.dimmed());
            }
            // Surface comment-injection results when comments existed.
            // Anchored count is the headline; dropped count is the
            // honesty signal so reviewers know docs were lost.
            if report.comment_stats.total > 0 {
                let stats = &report.comment_stats;
                let mut line = format!(
                    "  {} {} XML comment(s) preserved",
                    "•".dimmed(),
                    stats.anchored,
                );
                if stats.dropped > 0 {
                    let _ = write!(
                        line,
                        ", {} dropped (non-key anchors — see docs)",
                        stats.dropped
                    );
                }
                println!("{}", line.dimmed());
            }
        }
    }
}

/// Pick a recipe name for a bulk-mode file, disambiguating collisions
/// with names already claimed in the same run by prefixing the parent
/// directory (e.g. `ios-lock-screen-message`).
fn bulk_recipe_name(file: &Path, claimed: &HashSet<String>) -> String {
    let base = recipe_name_from_path(file).unwrap_or_else(|| "imported".to_string());
    if !claimed.contains(&base) {
        return base;
    }
    // First disambiguator: parent directory name (snake-cased).
    if let Some(parent) = file
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        && let Some(parent_slug) = snake_case_slug(parent)
    {
        let prefixed = format!("{parent_slug}-{base}");
        if !claimed.contains(&prefixed) {
            return prefixed;
        }
    }
    // Last resort: numeric suffix.
    let mut n = 2;
    loop {
        let candidate = format!("{base}-{n}");
        if !claimed.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// Snake-case a path component so it's safe as a recipe name prefix.
fn snake_case_slug(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut prev_alnum = false;
    for ch in s.chars() {
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

/// Recursively collect every importable file under `root` —
/// `*.mobileconfig` (MDM profiles) and `*.json` (DDM declarations).
fn collect_importable_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in
        std::fs::read_dir(root).with_context(|| format!("Failed to read {}", root.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_importable_files(&path, out)?;
            continue;
        }
        let ext = path.extension().and_then(|s| s.to_str());
        if matches!(ext, Some("mobileconfig") | Some("json")) {
            out.push(path);
        }
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// DDM declaration import — `.json` → `<lib>/ddm/<name>.toml` Bundle.
// ────────────────────────────────────────────────────────────────────

/// Import a single DDM declaration JSON into the library's `ddm/`
/// directory as a Bundle TOML. Only `com.apple.configuration.*`
/// declarations are accepted as bundle roots — activations, assets,
/// and subscriptions live alongside their configuration and don't
/// import standalone.
fn import_ddm_json(
    input: &Path,
    into: &Path,
    name_override: Option<&str>,
    force: bool,
) -> Result<SingleImportReport> {
    let body = std::fs::read_to_string(input)
        .with_context(|| format!("Failed to read {}", input.display()))?;
    let decl: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("Failed to parse {} as JSON", input.display()))?;

    let decl_obj = decl
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("DDM declaration must be a JSON object"))?;

    let decl_type = decl_obj
        .get("Type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("DDM declaration missing required `Type` field"))?
        .to_string();

    if !decl_type.starts_with("com.apple.configuration.") {
        anyhow::bail!(
            "only `com.apple.configuration.*` declarations import as bundles; got `{decl_type}`. Activations, assets, and status-subscriptions are referenced from the configuration's bundle — import the configuration JSON instead."
        );
    }

    // Pull the (optional) Identifier so we can record it in a comment
    // header. The bundle's `intent_name` drives the regenerated
    // identifier under `--org`, so we don't preserve the raw value.
    let original_identifier = decl_obj
        .get("Identifier")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let payload_obj = decl_obj
        .get("Payload")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::anyhow!("DDM declaration missing required `Payload` object"))?;

    // intent_name precedence:
    //   1. Explicit --name override
    //   2. Tail of the source Identifier when shaped
    //      `<reverse-dns>.config.<intent>` — the canonical pattern
    //      `compose` itself emits, so round-tripping recovers the
    //      original tail.
    //   3. Snake-cased filename stem (last resort).
    let intent_name = name_override
        .map(str::to_string)
        .or_else(|| identifier_intent_tail(&original_identifier))
        .unwrap_or_else(|| recipe_name_from_path(input).unwrap_or_else(|| "imported".to_string()));

    // Output path under the library's `ddm/` subdir.
    let ddm_dir = into.join("ddm");
    std::fs::create_dir_all(&ddm_dir)
        .with_context(|| format!("Failed to create {}", ddm_dir.display()))?;
    let bundle_path = ddm_dir.join(format!("{intent_name}.toml"));
    let meaning_path = ddm_dir.join(format!("{intent_name}.meaning.md"));
    if bundle_path.exists() && !force {
        anyhow::bail!(
            "{} already exists. Re-run with --force to overwrite, or pass --name <NAME> to write a different file.",
            bundle_path.display()
        );
    }

    // Convert JSON payload → TOML table.
    let mut payload_table = toml::map::Map::new();
    for (k, v) in payload_obj {
        payload_table.insert(k.clone(), serde_json_to_toml(v)?);
    }

    // Hand-emit the bundle TOML so we can lead with a comment header
    // documenting the source. The Bundle struct serializes cleanly,
    // but `toml::to_string(&bundle)` doesn't preserve a leading
    // comment — so we render manually.
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# DDM bundle imported from {} via `contour profile library import`.",
        input.display()
    );
    if !original_identifier.is_empty() {
        let _ = writeln!(out, "# Original Identifier: {original_identifier}");
    }
    let _ = writeln!(
        out,
        "# Compose with: contour profile ddm compose --preset-path <DIR> --preset {intent_name} --org <YOUR_ORG> -o ./out"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "intent_name = \"{intent_name}\"");
    let _ = writeln!(out);
    let _ = writeln!(out, "[configuration]");
    let _ = writeln!(out, "type = \"{decl_type}\"");
    let _ = writeln!(out);
    let _ = writeln!(out, "[configuration.payload]");
    // Emit payload via the toml serializer to handle nested tables /
    // arrays / strings correctly. We feed a one-key wrapper and strip
    // the wrapper header.
    let payload_value = toml::Value::Table(payload_table.clone());
    let payload_only = toml::Value::Table({
        let mut m = toml::map::Map::new();
        m.insert("__payload__".to_string(), payload_value);
        m
    });
    let serialized = toml::to_string(&payload_only)?;
    // Re-anchor under [configuration.payload] by rewriting the
    // section path on every header that came out of the wrapper.
    for line in serialized.lines() {
        let rewritten = if let Some(rest) = line.strip_prefix("[__payload__") {
            // [__payload__]                  -> (skip — already wrote [configuration.payload])
            // [__payload__.<sub>]            -> [configuration.payload.<sub>]
            // [[__payload__.<sub>]]          -> [[configuration.payload.<sub>]]
            if rest == "]" {
                continue;
            }
            format!("[configuration.payload{rest}")
        } else if let Some(rest) = line.strip_prefix("[[__payload__") {
            format!("[[configuration.payload{rest}")
        } else {
            line.to_string()
        };
        let _ = writeln!(out, "{rewritten}");
    }
    let _ = writeln!(out);
    // Default activation — operators can edit if they need a predicate
    // or a referenced asset.
    let _ = writeln!(out, "[activation]");
    let _ = writeln!(out, "type = \"com.apple.activation.simple\"");

    std::fs::write(&bundle_path, &out)
        .with_context(|| format!("Failed to write {}", bundle_path.display()))?;

    // Write a stub `.meaning.md` mirroring the recipe-side pattern.
    let registry = load_registry(None).ok();
    let manifest = registry.as_ref().and_then(|r| r.get_by_name(&decl_type));
    let mut meaning = String::new();
    let _ = writeln!(&mut meaning, "# {intent_name}\n");
    let _ = writeln!(
        &mut meaning,
        "DDM bundle imported from `{}` via `contour profile library import`.\n",
        input.display()
    );
    if !original_identifier.is_empty() {
        let _ = writeln!(&mut meaning, "## Source\n");
        let _ = writeln!(
            &mut meaning,
            "- Original Identifier: `{original_identifier}`\n"
        );
    }
    let _ = writeln!(&mut meaning, "## Configuration\n");
    if let Some(m) = manifest {
        if !m.title.is_empty() {
            let _ = writeln!(&mut meaning, "**{}** — `{decl_type}`\n", m.title);
        } else {
            let _ = writeln!(&mut meaning, "`{decl_type}`\n");
        }
        if !m.description.trim().is_empty() {
            let _ = writeln!(&mut meaning, "{}\n", m.description.trim());
        }
    } else {
        let _ = writeln!(&mut meaning, "`{decl_type}` _(not in embedded schema)_\n");
    }
    let _ = writeln!(&mut meaning, "## References\n");
    let _ = writeln!(
        &mut meaning,
        "- Apple device-management spec: <https://developer.apple.com/documentation/devicemanagement>"
    );
    let _ = writeln!(
        &mut meaning,
        "- contour schema lookup: `contour profile ddm info {decl_type}`"
    );
    std::fs::write(&meaning_path, meaning)
        .with_context(|| format!("Failed to write {}", meaning_path.display()))?;

    Ok(SingleImportReport {
        input: input.to_path_buf(),
        recipe_path: bundle_path,
        meaning_path,
        payload_types: vec![decl_type],
        // DDM JSON has no XML comments to inject — the field stays at default zero.
        comment_stats: CommentInjectionStats::default(),
    })
}

/// JSON → TOML value converter. Null is rejected because TOML has no
/// null type — operators should drop unset keys before importing.
fn serde_json_to_toml(v: &serde_json::Value) -> Result<toml::Value> {
    Ok(match v {
        serde_json::Value::Null => {
            anyhow::bail!("DDM payload contains a null value — TOML has no null type")
        }
        serde_json::Value::Bool(b) => toml::Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                toml::Value::Float(f)
            } else {
                anyhow::bail!("number {n} not representable as TOML i64/f64")
            }
        }
        serde_json::Value::String(s) => toml::Value::String(s.clone()),
        serde_json::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(serde_json_to_toml(item)?);
            }
            toml::Value::Array(out)
        }
        serde_json::Value::Object(obj) => {
            let mut tbl = toml::map::Map::new();
            for (k, v) in obj {
                tbl.insert(k.clone(), serde_json_to_toml(v)?);
            }
            toml::Value::Table(tbl)
        }
    })
}

/// Inverse of `cli::generate::toml_to_plist_resolved`.
///
/// `placeholder_mapping` is the (sentinel, original) list produced
/// by `parse_profile_lenient` — when a `<string>` value contains a
/// sentinel, swap it back to the original placeholder. When a
/// `<data>` payload's bytes UTF-8-decode to a `CONTOUR_DATA_PH_*`
/// sentinel, swap to the original placeholder string. Real `<data>`
/// blobs are encoded as `base64:<b64>` strings — matching the
/// `toml_to_plist_resolved` round-trip path used at recipe-generation
/// time.
pub fn plist_value_to_toml(
    v: &plist::Value,
    placeholder_mapping: &[(String, String)],
) -> Result<toml::Value> {
    Ok(match v {
        plist::Value::String(s) => {
            toml::Value::String(restore_string_placeholders(s, placeholder_mapping))
        }
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
                out.push(plist_value_to_toml(item, placeholder_mapping)?);
            }
            toml::Value::Array(out)
        }
        plist::Value::Dictionary(dict) => {
            let mut tbl = toml::map::Map::new();
            for (k, v) in dict {
                tbl.insert(k.clone(), plist_value_to_toml(v, placeholder_mapping)?);
            }
            toml::Value::Table(tbl)
        }
        plist::Value::Data(bytes) => {
            // <data>$VAR</data> was rewritten by the lenient parser
            // into a base64-of-sentinel; the parsed bytes are the
            // *decoded* sentinel string. If we can match it, swap
            // back to the original placeholder.
            if let Ok(s) = std::str::from_utf8(bytes)
                && let Some(original) = lookup_data_sentinel(s, placeholder_mapping)
            {
                toml::Value::String(original)
            } else {
                let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
                toml::Value::String(format!("base64:{b64}"))
            }
        }
        // Future-proofing: plist::Value is non-exhaustive.
        _ => anyhow::bail!("unsupported plist value variant"),
    })
}

/// Replace every sentinel substring in `s` with its original
/// placeholder. Operates in mapping order so a later sentinel can't
/// alias an earlier one.
fn restore_string_placeholders(s: &str, mapping: &[(String, String)]) -> String {
    if mapping.is_empty() || !s.contains("CONTOUR_") {
        return s.to_string();
    }
    let mut out = s.to_string();
    for (sentinel, original) in mapping {
        if sentinel.starts_with("CONTOUR_PH_") && out.contains(sentinel) {
            out = out.replace(sentinel.as_str(), original.as_str());
        }
    }
    out
}

/// Resolve a `<data>` payload's decoded bytes to the original
/// placeholder string when they came from a `CONTOUR_DATA_PH_*`
/// sentinel. The mapping stores `(b64-of-sentinel, original)` for
/// data-channel placeholders, so we re-encode and look it up.
fn lookup_data_sentinel(decoded: &str, mapping: &[(String, String)]) -> Option<String> {
    if !decoded.starts_with("CONTOUR_DATA_PH_") {
        return None;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(decoded);
    mapping
        .iter()
        .find(|(s, _)| s == &b64)
        .map(|(_, original)| original.clone())
}

/// Snake-case the file stem so `Privileges.mobileconfig` →
/// `privileges`, `My Org-Wifi.mobileconfig` → `my_org_wifi`.
/// MCX (Managed Client for X) preferences ship the actual settings
/// deeply nested under
/// `PayloadContent.<domain>.Forced[0].mcx_preference_settings`. When
/// the source profile follows that *exact* canonical shape (one
/// domain, one `Forced` entry, only the `mcx_preference_settings`
/// key inside), we flatten the nested settings to top-level
/// `[profile.fields]` and record the domain in `mcx_domain` so
/// `generate --recipe` can re-wrap on the way out.
///
/// Anything non-canonical (multiple domains, multiple Forced entries,
/// extra peer keys) falls back to faithful pass-through — better an
/// ugly recipe that round-trips than silent data loss.
/// Inject XML comments captured from the source mobileconfig as TOML
/// `#` lines above the matching `key = value` pair.
///
/// The plist crate strips `<!-- … -->` on parse, but
/// `parse_profile_lenient` keeps each comment with its `anchor_line`
/// (the next non-empty XML line). When the anchor is shaped
/// `<key>X</key>`, we pull `X` and look for `X = …` lines in the
/// emitted TOML. Each match gets the comment text re-emitted as
/// `# …` lines just above it.
///
/// Comments whose anchor isn't a `<key>X</key>` are silently dropped —
/// they could land on the wrong line, which is worse than losing them.
fn inject_xml_comments(
    toml_body: &str,
    comments: &[XmlComment],
) -> (String, CommentInjectionStats) {
    let mut stats = CommentInjectionStats {
        total: comments.len(),
        anchored: 0,
        dropped: 0,
    };
    if comments.is_empty() {
        return (toml_body.to_string(), stats);
    }

    // Build {key_name → joined `#` comment block}. Multiple comments
    // anchored to the same key concatenate (rare but possible).
    let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for c in comments {
        let Some(key) = anchor_key_name(&c.anchor_line) else {
            stats.dropped += 1;
            continue;
        };
        let block = comment_to_toml_lines(&c.text);
        if block.is_empty() {
            stats.dropped += 1;
            continue;
        }
        stats.anchored += 1;
        map.entry(key).or_default().push_str(&block);
    }

    if map.is_empty() {
        return (toml_body.to_string(), stats);
    }

    // Walk the TOML output. Inject when a non-section line starts with
    // `<KEY> = …` and we have a comment block keyed by `<KEY>`.
    let mut out = String::with_capacity(toml_body.len());
    for line in toml_body.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('[') && !trimmed.starts_with('#') && !trimmed.is_empty() {
            if let Some(eq) = trimmed.find('=') {
                let key = trimmed[..eq].trim().trim_matches('"');
                if let Some(block) = map.get(key) {
                    out.push_str(block);
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    (out, stats)
}

/// Pull the key name out of an XML `<key>NAME</key>` anchor line.
/// Returns `None` for any other shape — we won't risk attaching a
/// comment to a non-key element.
fn anchor_key_name(anchor: &str) -> Option<String> {
    let trimmed = anchor.trim();
    let rest = trimmed.strip_prefix("<key>")?;
    let inner = rest.strip_suffix("</key>")?;
    let name = inner.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Turn a raw `<!-- … -->` block into TOML `#` lines, preserving
/// internal line structure. Always ends with a trailing newline so
/// callers can prepend it to a target line directly.
fn comment_to_toml_lines(raw: &str) -> String {
    let inner = raw
        .trim()
        .strip_prefix("<!--")
        .unwrap_or(raw)
        .strip_suffix("-->")
        .unwrap_or(raw)
        .trim_matches(|c: char| c == '\n' || c == '\r');

    let mut out = String::new();
    for line in inner.lines() {
        let cleaned = line.trim_end();
        // Skip leading whitespace from the source's indentation —
        // re-emit each comment line at column 0 so it stays readable
        // regardless of nesting depth.
        let body = cleaned.trim_start();
        if body.is_empty() {
            out.push_str("#\n");
        } else {
            out.push_str("# ");
            out.push_str(body);
            out.push('\n');
        }
    }
    out
}

fn unwrap_mcx_if_canonical(
    payload_type: &str,
    fields: BTreeMap<String, toml::Value>,
) -> (Option<String>, BTreeMap<String, toml::Value>) {
    if payload_type != "com.apple.ManagedClient.preferences" {
        return (None, fields);
    }
    // Shape check 1: only `PayloadContent` at top level.
    if fields.len() != 1 {
        return (None, fields);
    }
    let Some(payload_content) = fields
        .get("PayloadContent")
        .and_then(|v| v.as_table())
        .cloned()
    else {
        return (None, fields);
    };
    // Shape check 2: exactly one preference domain.
    if payload_content.len() != 1 {
        return (None, fields);
    }
    let (domain, domain_value) = payload_content
        .into_iter()
        .next()
        .expect("len 1 verified above");
    let Some(domain_table) = domain_value.as_table() else {
        return (None, fields);
    };
    // Shape check 3: domain dict has at least a `Forced` array.
    let Some(forced) = domain_table.get("Forced").and_then(|v| v.as_array()) else {
        return (None, fields);
    };
    if forced.len() != 1 {
        return (None, fields);
    }
    let Some(forced_entry) = forced[0].as_table() else {
        return (None, fields);
    };
    // Shape check 4: forced entry's only key is `mcx_preference_settings`.
    if forced_entry.len() != 1 {
        return (None, fields);
    }
    let Some(settings) = forced_entry
        .get("mcx_preference_settings")
        .and_then(|v| v.as_table())
        .cloned()
    else {
        return (None, fields);
    };

    // Materialize as BTreeMap so the recipe stays byte-stable.
    let flat: BTreeMap<String, toml::Value> = settings.into_iter().collect();
    (Some(domain), flat)
}

/// Extract the intent tail from a DDM declaration `Identifier` when
/// it follows the canonical shape `<reverse-dns>.{config,activation}.<intent>`.
///
/// `compose()` emits identifiers as `{org}.{config|activation}.{intent_name}`,
/// so round-tripping a previously-composed JSON recovers the
/// original tail. Returns `None` when the identifier is empty or
/// doesn't fit the shape — caller falls back to the filename stem.
fn identifier_intent_tail(identifier: &str) -> Option<String> {
    if identifier.is_empty() {
        return None;
    }
    let segments: Vec<&str> = identifier.split('.').collect();
    if segments.len() < 4 {
        return None;
    }
    // The penultimate segment must be `config` or `activation` for the
    // identifier to match contour's compose-time shape.
    let kind = segments[segments.len() - 2];
    if kind != "config" && kind != "activation" {
        return None;
    }
    let tail = segments.last().copied()?;
    if tail.is_empty() {
        None
    } else {
        Some(tail.to_string())
    }
}

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
pub fn build_meaning_md(
    recipe: &Recipe,
    source: &Path,
    registry: Option<&SchemaRegistry>,
) -> String {
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
    if !recipe.profiles.is_empty() {
        let _ = writeln!(out, "## Payloads\n");
        for spec in &recipe.profiles {
            append_payload_section(&mut out, spec, registry);
        }
    }

    // DDM bundles in the recipe (parallel to mobileconfig payloads —
    // hardening-macos-baseline ships both). Same enrichment shape:
    // schema title from the configuration type, platforms/OS support,
    // and a one-line summary of activation/asset/subscriptions.
    if !recipe.ddm.is_empty() {
        let _ = writeln!(out, "## DDM declarations\n");
        for bundle in &recipe.ddm {
            append_ddm_section(&mut out, bundle, registry);
        }
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

/// Render one `### <intent_name>` block per `[[ddm]]` bundle, pulling
/// schema docs for the configuration type when known. Mirror of
/// `append_payload_section` — same shape, DDM-flavoured fields.
fn append_ddm_section(
    out: &mut String,
    bundle: &crate::ddm::compose::Bundle,
    registry: Option<&SchemaRegistry>,
) {
    let cfg_type = &bundle.configuration.type_name;
    let manifest = registry.and_then(|r| r.get_by_name(cfg_type));

    let heading = match manifest {
        Some(m) if !m.title.is_empty() => {
            format!("{} — `{}` (`{}`)", m.title, bundle.intent_name, cfg_type)
        }
        _ => format!("`{}` (`{}`)", bundle.intent_name, cfg_type),
    };
    let _ = writeln!(out, "### {heading}\n");

    if let Some(m) = manifest
        && !m.description.trim().is_empty()
    {
        let _ = writeln!(out, "{}\n", m.description.trim());
    }

    // Platforms + OS support (DDM types live in the same registry as
    // mobileconfig payloads, so reuse the same lookup).
    if let Some(m) = manifest {
        let plats: Vec<(Platform, &'static str, bool)> = vec![
            (Platform::MacOS, "macOS", m.platforms.macos),
            (Platform::Ios, "iOS", m.platforms.ios),
            (Platform::TvOS, "tvOS", m.platforms.tvos),
            (Platform::WatchOS, "watchOS", m.platforms.watchos),
            (Platform::VisionOS, "visionOS", m.platforms.visionos),
        ];
        let parts: Vec<String> = plats
            .iter()
            .filter(|(_, _, supported)| *supported)
            .map(|(p, label, _)| {
                if let Some(detail) = m.os_support.get(p)
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
    }

    // Bundle-shape summary: activation type, asset, subscriptions.
    let mut shape: Vec<String> = Vec::new();
    if let Some(activation) = &bundle.activation {
        let act_type = activation
            .type_name
            .as_deref()
            .unwrap_or("com.apple.activation.simple");
        if let Some(predicate) = &activation.predicate {
            shape.push(format!(
                "activation: `{act_type}` (predicate: `{predicate}`)"
            ));
        } else {
            shape.push(format!("activation: `{act_type}`"));
        }
    }
    if let Some(asset) = &bundle.asset {
        shape.push(format!("asset: `{}`", asset.type_name));
    }
    if let Some(subs) = &bundle.subscriptions {
        shape.push(format!(
            "status subscriptions: {}",
            subs.keys
                .iter()
                .map(|k| format!("`{k}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !shape.is_empty() {
        let _ = writeln!(out, "**Bundle shape:**\n");
        for line in shape {
            let _ = writeln!(out, "- {line}");
        }
        let _ = writeln!(out);
    }

    // Configured payload keys — same per-key documentation as the
    // mobileconfig path (DDM uses the same FieldDefinition shape).
    let configured_keys: Vec<&String> = bundle.configuration.payload.keys().collect();
    if !configured_keys.is_empty() {
        let _ = writeln!(out, "**Configuration payload keys:**\n");
        if let Some(m) = manifest {
            for key in &configured_keys {
                match m.fields.get(*key) {
                    Some(field) => {
                        let mut line = format!("- **`{}`**", field.name);
                        if !field.description.trim().is_empty() {
                            let _ = write!(line, " — {}", first_sentence(&field.description));
                        }
                        let _ = writeln!(out, "{line}");
                    }
                    None => {
                        let _ = writeln!(out, "- `{key}` _(nested or vendor-specific)_");
                    }
                }
            }
        } else {
            for key in &configured_keys {
                let _ = writeln!(out, "- `{key}`");
            }
        }
        let _ = writeln!(out);
    }
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

        let toml_value = plist_value_to_toml(&plist::Value::Dictionary(dict), &[]).unwrap();
        let tbl = toml_value.as_table().unwrap();
        assert_eq!(tbl["s"].as_str(), Some("x"));
        assert_eq!(tbl["b"].as_bool(), Some(true));
        assert_eq!(tbl["i"].as_integer(), Some(42));
        assert_eq!(tbl["f"].as_float(), Some(1.5));
        assert_eq!(tbl["arr"].as_array().unwrap().len(), 2);
        assert_eq!(tbl["d"]["inner"].as_str(), Some("y"));
    }

    #[test]
    fn plist_to_toml_encodes_data_as_base64_string() {
        // Real <data> payload (no sentinel match) → `base64:<>` string.
        let v = plist::Value::Data(vec![1, 2, 3]);
        let result = plist_value_to_toml(&v, &[]).unwrap();
        let s = result.as_str().expect("string");
        assert!(
            s.starts_with("base64:"),
            "data must be encoded with the base64: sentinel; got {s}"
        );
        // Round-trip via the `toml_to_plist_resolved` decoder shape:
        // strip prefix and base64-decode → original bytes.
        let b64 = s.strip_prefix("base64:").unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn plist_to_toml_swaps_data_sentinel_to_original_placeholder() {
        // Simulate what `parse_profile_lenient` produces for
        // `<data>$DOGFOOD_OKTA_CA_CERTIFICATE</data>`: the bytes are
        // the decoded sentinel string; the mapping stores
        // (b64-of-sentinel, original).
        let sentinel = "CONTOUR_DATA_PH_0";
        let b64_of_sentinel = base64::engine::general_purpose::STANDARD.encode(sentinel);
        let mapping = vec![(b64_of_sentinel, "$DOGFOOD_OKTA_CA_CERTIFICATE".to_string())];
        let v = plist::Value::Data(sentinel.as_bytes().to_vec());

        let result = plist_value_to_toml(&v, &mapping).unwrap();
        assert_eq!(
            result.as_str(),
            Some("$DOGFOOD_OKTA_CA_CERTIFICATE"),
            "data sentinel must round-trip to the original MDM placeholder"
        );
    }

    #[test]
    fn plist_to_toml_swaps_string_sentinel_back_to_placeholder() {
        let mapping = vec![("CONTOUR_PH_0".to_string(), "$DOMAIN".to_string())];
        let v = plist::Value::String("auth.CONTOUR_PH_0/sso".into());
        let result = plist_value_to_toml(&v, &mapping).unwrap();
        assert_eq!(result.as_str(), Some("auth.$DOMAIN/sso"));
    }
}
