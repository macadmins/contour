//! `profile generate --fragment`: a Fleet GitOps fragment, in Fleet's layout.
//!
//! The profiles and declarations come from the ordinary generators, written
//! straight into the layout `fleetctl new` creates; this places each file by
//! what it is, refuses what Fleet would refuse at upload, and writes the fleet
//! YAML and `fragment.toml` that reference them.
//!
//! The fleet YAML uses `controls.apple_settings.configuration_profiles` — the
//! form Fleet's own templates and docs use since v4.83.0; `macos_settings` and
//! `custom_settings` are deprecated aliases in Fleet's GitOps schema.
//!
//! Placement, from Fleet's templates (cmd/fleetctl/fleetctl/templates/new):
//!   `.mobileconfig`                  → platforms/macos/configuration-profiles/
//!   configuration declarations       → platforms/macos/declaration-profiles/
//! and, for the two kinds the template has no folder for, the folder names
//! Fleet's docs use, under the same `platforms/macos/` root — kept out of
//! `declaration-profiles/` because the template globs that folder
//! (`paths: ../platforms/macos/declaration-profiles/*.json`) and would upload
//! them as declarations:
//!   activations                      → platforms/macos/activations/
//!   asset declarations               → platforms/macos/assets/

use anyhow::{Context, Result, bail};
use colored::Colorize;
use contour_core::fleet_layout::FleetLayout;
use contour_core::fleet_rules::{screen_declaration, screen_mobileconfig};
use contour_core::fragment::{
    DefaultYmlEntries, FleetEntries, FragmentManifest, FragmentMeta, LibFiles, ProfileEntry,
    ScriptEntries, SimpleEntry,
};
use contour_core::output::OutputMode;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Where an activation, and the assets, go: not in Fleet's template, so the
/// folder names Fleet's docs use (`lib/macos/activations`, `…/assets`).
const ACTIVATIONS_SUBDIR: &str = "platforms/macos/activations";
const ASSETS_SUBDIR: &str = "platforms/macos/assets";

/// What `profile generate` is asked to render into the fragment.
#[derive(Debug)]
pub enum Source<'a> {
    /// One payload type → one `.mobileconfig`.
    Payload(&'a str),
    /// One or more recipes → profiles and DDM bundles.
    Recipes(&'a [String]),
}

/// Everything the generators need, passed through unchanged.
#[derive(Debug)]
pub struct Generate<'a> {
    pub org: Option<&'a str>,
    pub full: bool,
    pub sanitize: bool,
    pub schema_path: Option<&'a str>,
    pub recipe_path: Option<&'a str>,
    pub config: Option<&'a crate::config::ProfileConfig>,
    pub vars: &'a [String],
    pub format: &'a str,
    pub combined: Option<bool>,
    pub channel: crate::schema::Channel,
    pub allow_placeholders: bool,
}

#[derive(Debug, Serialize)]
struct Placed {
    kind: &'static str,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    activation: Option<String>,
}

/// Fleet YAML for the fragment's reference fleet.
#[derive(Serialize)]
struct FleetYaml<'a> {
    name: &'a str,
    controls: Controls<'a>,
}
#[derive(Serialize)]
struct Controls<'a> {
    apple_settings: AppleSettings<'a>,
}
#[derive(Serialize)]
struct AppleSettings<'a> {
    configuration_profiles: &'a [ProfileEntry],
    #[serde(skip_serializing_if = "<[SimpleEntry]>::is_empty")]
    assets: &'a [SimpleEntry],
}

/// Generate into a fragment directory and report it.
pub fn handle_generate_fragment(
    source: Source<'_>,
    output: Option<&str>,
    g: &Generate<'_>,
    output_mode: OutputMode,
) -> Result<()> {
    if g.format != "mobileconfig" {
        bail!(
            "--fragment writes .mobileconfig files for Fleet; --format {} is a raw payload \
             Fleet cannot upload",
            g.format
        );
    }
    let out = PathBuf::from(output.unwrap_or("profile-fragment"));
    // A fragment is a set: a file left from an earlier run would sit in a
    // folder Fleet's templates glob, and be uploaded though the YAML here no
    // longer names it.
    if out.exists() && std::fs::read_dir(&out)?.next().is_some() {
        bail!(
            "{} is not empty. A fragment is written to a new or empty directory, so no \
             file from an earlier run is merged by mistake.",
            out.display()
        );
    }
    let layout = FleetLayout::default();
    let profiles_dir = out.join(layout.macos_profiles_subdir);
    std::fs::create_dir_all(&profiles_dir)?;

    // 1. Render, silently, straight into the profiles folder.
    let mut unfilled = Vec::new();
    match source {
        Source::Payload(pt) => {
            let file = profiles_dir.join(format!("{}.mobileconfig", slug(pt)));
            super::generate::handle_generate(
                pt,
                Some(&file.to_string_lossy()),
                g.org,
                g.full,
                g.schema_path,
                g.config,
                output_mode,
                g.format,
                g.channel,
                false,
            )?;
        }
        Source::Recipes(recipes) => {
            let mut renders = Vec::new();
            for selector in recipes {
                renders.push(super::generate::handle_generate_recipe(
                    selector,
                    g.recipe_path,
                    Some(&profiles_dir.to_string_lossy()),
                    g.org,
                    g.full,
                    g.sanitize,
                    g.schema_path,
                    g.config,
                    g.vars,
                    output_mode,
                    g.format,
                    g.combined,
                    false,
                )?);
            }
            super::generate::judge_recipe_renders(
                &renders,
                g.vars,
                g.allow_placeholders || g.sanitize,
            )?;
            for r in &renders {
                unfilled.extend(r.unfilled.iter().cloned());
            }
        }
    }

    // 2. Place every file by what it is, and refuse what Fleet would refuse.
    let mut placed = Vec::new();
    let mut profiles = Vec::new();
    let mut assets = Vec::new();
    let mut refusals = Vec::new();
    let mut dropped_activations = Vec::new();
    let mut custom_activations = Vec::new();

    let mut mobileconfigs: Vec<PathBuf> = std::fs::read_dir(&profiles_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "mobileconfig"))
        .collect();
    mobileconfigs.sort();
    for p in &mobileconfigs {
        let name = file_name(p);
        for r in screen_mobileconfig(&std::fs::read(p)?)
            .with_context(|| format!("reading {}", p.display()))?
        {
            refusals.push(format!("{name}: {r}"));
        }
        let rel = format!("{}/{name}", layout.macos_profiles_subdir);
        profiles.push(entry(&rel, None));
        placed.push(Placed {
            kind: "configuration-profile",
            path: rel,
            activation: None,
        });
    }

    let mut bundles: Vec<PathBuf> = std::fs::read_dir(&profiles_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    bundles.sort();
    for bundle in &bundles {
        let intent = file_name(bundle);
        let mut configs = Vec::new(); // (identifier, type, file)
        let mut activation = None; // (declaration JSON, file)
        let mut files: Vec<PathBuf> = std::fs::read_dir(bundle)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        files.sort();
        for f in &files {
            let decl: serde_json::Value = serde_json::from_slice(&std::fs::read(f)?)
                .with_context(|| format!("{} is not a JSON declaration", f.display()))?;
            let ty = decl
                .get("Type")
                .and_then(|t| t.as_str())
                .unwrap_or_default()
                .to_string();
            let id = decl
                .get("Identifier")
                .and_then(|t| t.as_str())
                .unwrap_or_default()
                .to_string();
            if ty.starts_with("com.apple.activation.") {
                activation = Some((decl, f.clone()));
            } else if ty.starts_with("com.apple.asset.") {
                let rel = format!("{ASSETS_SUBDIR}/{intent}.json");
                move_into(f, &out.join(&rel))?;
                assets.push(SimpleEntry {
                    path: format!("../{rel}"),
                });
                placed.push(Placed {
                    kind: "asset",
                    path: rel,
                    activation: None,
                });
            } else {
                for r in screen_declaration(&ty, &id) {
                    refusals.push(format!("{intent}/{}: {r}", file_name(f)));
                }
                configs.push((id, ty, f.clone()));
            }
        }
        // One file per configuration: the bundle's main one takes the intent's
        // name, any other its own file stem.
        let mut config_rels = Vec::new();
        for (i, (id, _, f)) in configs.iter().enumerate() {
            let stem = if i == 0 {
                intent.clone()
            } else {
                format!("{intent}.{}", file_stem(f))
            };
            let rel = format!("{}/{stem}.json", layout.macos_declarations_subdir);
            move_into(f, &out.join(&rel))?;
            config_rels.push((id.clone(), rel));
        }
        // An activation that adds nothing to the one Fleet makes is left to
        // Fleet; one with a predicate is linked, and needs the server opt-in.
        let mut linked = None;
        if let Some((decl, f)) = activation {
            let payload = decl.get("Payload");
            let refs: Vec<String> = payload
                .and_then(|p| p.get("StandardConfigurations"))
                .and_then(|r| r.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let has_predicate = payload.and_then(|p| p.get("Predicate")).is_some();
            let subscribed = configs
                .iter()
                .any(|(_, ty, _)| ty == "com.apple.configuration.management.status-subscriptions");
            if has_predicate && subscribed {
                refusals.push(format!(
                    "{intent}: the activation's predicate reads status items, which needs the \
                     bundle's status-subscriptions declaration, and Fleet refuses that \
                     declaration — so Fleet cannot deliver this predicate. Drop the status \
                     keys from the predicate, or deploy this bundle through another MDM"
                ));
            }
            if refs.len() > 1 {
                refusals.push(format!(
                    "{intent}/{}: the activation names {} configurations; Fleet attaches an \
                     activation to exactly one declaration",
                    file_name(&f),
                    refs.len()
                ));
            } else if !has_predicate {
                dropped_activations.push(intent.clone());
                std::fs::remove_file(&f)?;
            } else {
                let rel = format!("{ACTIVATIONS_SUBDIR}/{intent}.json");
                move_into(&f, &out.join(&rel))?;
                custom_activations.push(intent.clone());
                linked = Some(format!("../{rel}"));
            }
        }
        for (i, (_, rel)) in config_rels.iter().enumerate() {
            let act = if i == 0 { linked.clone() } else { None };
            profiles.push(entry(rel, act.clone()));
            placed.push(Placed {
                kind: "declaration",
                path: rel.clone(),
                activation: act.map(|a| a.trim_start_matches("../").to_string()),
            });
        }
        if refusals.is_empty() {
            std::fs::remove_dir(bundle).with_context(|| {
                format!("{} still holds files no rule placed", bundle.display())
            })?;
        }
    }

    if !refusals.is_empty() {
        let _ = std::fs::remove_dir_all(&out); // best effort: the refusal is the result
        bail!(
            "Fleet would refuse this fragment, so it was not written:\n  {}",
            refusals.join("\n  ")
        );
    }
    if profiles.is_empty() && assets.is_empty() {
        let _ = std::fs::remove_dir_all(&out); // best effort: the refusal is the result
        bail!("nothing was generated, so there is no fragment to write");
    }

    // 3. The reference fleet and the manifest.
    let fleets_dir = out.join(layout.fleets_dir);
    std::fs::create_dir_all(&fleets_dir)?;
    let yaml = yaml_serde::to_string(&FleetYaml {
        name: "profile-reference",
        controls: Controls {
            apple_settings: AppleSettings {
                configuration_profiles: &profiles,
                assets: &assets,
            },
        },
    })?;
    std::fs::write(
        fleets_dir.join("reference-fleet.yml"),
        format!(
            "# Fleet GitOps — reference fleet for a contour profile fragment.\n\
             # Merge these entries into your own fleet file; paths are relative to fleets/.\n\
             {yaml}"
        ),
    )?;
    let lib_files: Vec<String> = placed
        .iter()
        .map(|p| p.path.clone())
        .chain(placed.iter().filter_map(|p| p.activation.clone()))
        .collect();
    FragmentManifest {
        fragment: FragmentMeta {
            name: "profile".to_string(),
            version: "1.0.0".to_string(),
            description: format!(
                "{} configuration profile(s) and declaration(s)",
                profiles.len() + assets.len()
            ),
            generator: "contour-profile".to_string(),
        },
        default_yml: DefaultYmlEntries::default(),
        fleet_entries: FleetEntries {
            profiles: profiles.clone(),
            reports: Vec::new(),
            policies: Vec::new(),
            software: Vec::new(),
            assets: assets.clone(),
        },
        lib_files: LibFiles { copy: lib_files },
        scripts: ScriptEntries::default(),
    }
    .save(&out.join("fragment.toml"))?;

    // 4. Report, once, with the paths the files now have.
    if output_mode == OutputMode::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "fragment": out.display().to_string(),
                "fleet_file": format!("{}/reference-fleet.yml", layout.fleets_dir),
                "files": placed,
                "activations_left_to_fleet": dropped_activations,
                "custom_activations": custom_activations,
                "placeholders": unfilled,
            }))?
        );
    } else {
        println!(
            "{} Fleet GitOps fragment: {}",
            "✓".green(),
            out.display().to_string().cyan()
        );
        for p in &placed {
            println!("  {} {}", "→".green(), p.path);
            if let Some(a) = &p.activation {
                println!("    {} {a}", "activation:".dimmed());
            }
        }
        println!(
            "  {} {}/reference-fleet.yml, fragment.toml",
            "→".green(),
            layout.fleets_dir
        );
        if !dropped_activations.is_empty() {
            println!(
                "\n  {} Fleet makes the activation for {}: contour's added nothing to it.",
                "ℹ".blue(),
                dropped_activations.join(", ")
            );
        }
        if !custom_activations.is_empty() {
            println!(
                "\n  {} {} carries a predicate, so its activation is kept. Fleet accepts a \
                 custom activation only with Fleet Premium and FLEET_MDM_ALLOW_CUSTOM_ACTIVATIONS \
                 set on the server.",
                "!".yellow(),
                custom_activations.join(", ")
            );
        }
        if !unfilled.is_empty() {
            println!(
                "\n  {} Replace these placeholders before deploying:",
                "!".yellow()
            );
            for p in &unfilled {
                println!("    {} {{{{{p}}}}}", "•".yellow());
            }
        }
    }
    Ok(())
}

fn entry(rel: &str, activation: Option<String>) -> ProfileEntry {
    ProfileEntry {
        path: format!("../{rel}"),
        labels_include_any: None,
        labels_include_all: None,
        labels_exclude_any: None,
        activation,
    }
}

fn move_into(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(from, to)
        .with_context(|| format!("moving {} to {}", from.display(), to.display()))
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn file_stem(p: &Path) -> String {
    p.file_stem()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// A payload type as a file name: `com.apple.dock` → `com.apple.dock`.
fn slug(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect()
}
