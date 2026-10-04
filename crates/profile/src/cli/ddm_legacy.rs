//! `profile ddm legacy` — wrap classic profiles in legacy declarations, and
//! keep the wrapping honest as they change.
//!
//! The core decisions live in [`crate::ddm::legacy`] as pure functions; this
//! module is the I/O shell around them: walk inputs, call `compose`, write
//! files, maintain the index.
//!
//! Declarations are built through [`crate::ddm::compose::compose`] rather than
//! assembled here, so identifier derivation, the org-domain check and the
//! never-author-`ServerToken` invariant are inherited instead of duplicated.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Map;

use crate::cli::ddm::{load_registry_opts, resolve_ddm_org_domain};
use crate::config::ProfileConfig;
use crate::ddm::compose::{
    Bundle, BundleActivation, BundleConfiguration, BundleSubscriptions, ComposeOptions, compose,
};
use crate::ddm::legacy::{
    LEGACY_TYPE, LegacyEntry, LegacyIndex, RefreshOutcome, TemplateContext, expand_template,
    legacy_payload, plan_refresh, reject_duplicate_basenames, sha256_hex,
};
use crate::ddm::predicate::extract_predicate_keys;
use crate::output::OutputMode;

/// Collect `.mobileconfig` inputs from files and/or directories.
fn collect_profiles(paths: &[String], recursive: bool) -> Result<(Vec<PathBuf>, Option<PathBuf>)> {
    let mut out = Vec::new();
    // The root is used for `{path}` expansion. With a single directory input it
    // is that directory; otherwise relative paths would be meaningless and
    // `{path}` degrades to the full path.
    let mut root = None;

    for raw in paths {
        let p = Path::new(raw);
        if p.is_dir() {
            if paths.len() == 1 {
                root = Some(p.to_path_buf());
            }
            let walker = walkdir::WalkDir::new(p).max_depth(if recursive { usize::MAX } else { 1 });
            for entry in walker.into_iter().filter_map(Result::ok) {
                let ep = entry.path();
                if ep.is_file() && ep.extension().is_some_and(|e| e == "mobileconfig") {
                    out.push(ep.to_path_buf());
                }
            }
        } else if p.is_file() {
            out.push(p.to_path_buf());
        } else {
            bail!("no such file or directory: {raw}");
        }
    }

    out.sort();
    out.dedup();
    if out.is_empty() {
        bail!("no .mobileconfig files found");
    }
    Ok((out, root))
}

/// Derive the intent name used in computed identifiers.
///
/// `compose` builds `{org}.{kind}.{intent}`, so this becomes the tail of every
/// identifier for the profile — it must be stable across runs or a re-convert
/// would silently mint new identifiers and orphan what is deployed.
fn intent_name(profile: &Path) -> String {
    profile
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// How emitted files are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Naming {
    /// `nudge-preferences.configuration.json` — sorts together, unambiguous.
    Contour,
    /// `Nudge preferences settings.json` — matches Fleet's
    /// declaration-profiles convention, which uses human-readable names with
    /// spaces (`Software Update settings.json`).
    Fleet,
}

impl Naming {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "contour" => Ok(Self::Contour),
            "fleet" => Ok(Self::Fleet),
            other => bail!("unknown --naming `{other}` (expected: contour, fleet)"),
        }
    }
}

/// Turn a file stem into a human title: `nudge-preferences` → `Nudge preferences`.
fn humanize(stem: &str) -> String {
    let spaced = stem.replace(['-', '_'], " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => spaced,
    }
}

/// Output file name for a declaration.
///
/// Fleet's kind words differ from contour's: its declarations are named
/// `… settings.json`, not `… configuration.json`, so a converted profile drops
/// into `lib/macos/declaration-profiles/` looking like the ones already there.
fn file_name(stem: &str, kind: &str, naming: Naming) -> String {
    match naming {
        Naming::Contour => format!("{stem}.{kind}.json"),
        Naming::Fleet => {
            let word = if kind == "configuration" {
                "settings"
            } else {
                kind
            };
            format!("{} {word}.json", humanize(stem))
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler mirrors the flag surface; grouping into a struct would \
              only move the arity to the call site"
)]
pub fn handle_legacy_convert(
    paths: &[String],
    url_template: &str,
    sha: Option<&str>,
    predicate: Option<&str>,
    no_subscriptions: bool,
    org_flag: Option<&str>,
    output: Option<&str>,
    recursive: bool,
    naming: &str,
    gitops: bool,
    write: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    let naming = Naming::parse(naming)?;
    let (profiles, root) = collect_profiles(paths, recursive)?;

    // `{name}` is the common template token, so two inputs sharing a file name
    // would expand to one URL and the second declaration would point at the
    // first one's content. Refuse before writing anything.
    reject_duplicate_basenames(&profiles)?;

    let registry = load_registry_opts(None, false)?;
    let Some(domain) = resolve_ddm_org_domain(org_flag, config) else {
        bail!(
            "organization domain is required\n  \
             • --org <domain>\n  \
             • CONTOUR_ORG\n  \
             • organization.domain in profile.toml or .contour/config.toml"
        );
    };

    // Status keys the predicate references. Apple does not auto-subscribe from
    // predicate parsing, and compose documents Error.UnableToEvaluatePredicate
    // on device for an unsubscribed key — so subscriptions are emitted unless
    // explicitly declined.
    let status_keys = predicate
        .map(|p| extract_predicate_keys(p).status)
        .unwrap_or_default();

    let out_dir = PathBuf::from(output.unwrap_or("."));
    let index_path = out_dir.join(LegacyIndex::FILE_NAME);
    let mut index: LegacyIndex = std::fs::read_to_string(&index_path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default();

    let mut planned: Vec<(PathBuf, String, String)> = Vec::new();

    for profile in &profiles {
        let bytes =
            std::fs::read(profile).with_context(|| format!("reading {}", profile.display()))?;
        let hash = sha256_hex(&bytes);

        let ctx = TemplateContext::for_profile(profile, root.as_deref(), sha);
        let url = expand_template(url_template, &ctx)?;
        let intent = intent_name(profile);

        let bundle = Bundle {
            intent_name: intent.clone(),
            platforms: Vec::new(),
            asset: None,
            configuration: BundleConfiguration {
                type_name: LEGACY_TYPE.to_string(),
                identifier: None,
                asset_ref_field: None,
                payload: legacy_payload(&url),
            },
            activation: predicate.map(|p| BundleActivation {
                type_name: None,
                identifier: None,
                predicate: Some(p.to_string()),
                references: None,
            }),
            subscriptions: (!no_subscriptions && !status_keys.is_empty()).then(|| {
                BundleSubscriptions {
                    keys: status_keys.clone(),
                    identifier: None,
                }
            }),
        };

        let composed = compose(&bundle, &domain, &registry, &ComposeOptions::default())
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let stem = ctx.stem.clone();
        // Each file is reported under its OWN identifier. Labelling all three
        // with the configuration's made the activation and subscriptions look
        // like duplicates of it in the output.
        let mut writes: Vec<(PathBuf, String, String)> = vec![(
            out_dir.join(file_name(&stem, "configuration", naming)),
            serde_json::to_string_pretty(&composed.configuration)?,
            composed.configuration.identifier.clone(),
        )];
        if let Some(act) = &composed.activation {
            writes.push((
                out_dir.join(file_name(&stem, "activation", naming)),
                serde_json::to_string_pretty(act)?,
                act.identifier.clone(),
            ));
        }
        if let Some(subs) = &composed.subscriptions {
            writes.push((
                out_dir.join(file_name(&stem, "subscriptions", naming)),
                serde_json::to_string_pretty(subs)?,
                subs.identifier.clone(),
            ));
        }

        index.upsert(LegacyEntry {
            identifier: composed.configuration.identifier.clone(),
            // The path relative to the input root — the same value `{path}`
            // expands to. An absolute path here would be committed beside the
            // declarations and break on every other machine.
            profile: ctx.path.clone(),
            sha256: hash,
            url: url.clone(),
            url_template: url_template.to_string(),
            sha: ctx.sha.clone(),
        });

        planned.extend(writes);
    }

    if write {
        std::fs::create_dir_all(&out_dir)?;
        for (path, body, _) in &planned {
            std::fs::write(path, format!("{body}\n"))
                .with_context(|| format!("writing {}", path.display()))?;
        }
        std::fs::write(&index_path, toml::to_string_pretty(&index)?)
            .with_context(|| format!("writing {}", index_path.display()))?;
    }

    report_convert(
        &planned,
        &profiles,
        sha,
        &status_keys,
        no_subscriptions,
        gitops,
        write,
        output_mode,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "reporting mirrors the flag surface it describes"
)]
fn report_convert(
    planned: &[(PathBuf, String, String)],
    profiles: &[PathBuf],
    sha: Option<&str>,
    status_keys: &[String],
    no_subscriptions: bool,
    gitops: bool,
    write: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Json {
        let files: Vec<_> = planned
            .iter()
            .map(
                |(p, _, id)| serde_json::json!({"path": p.display().to_string(), "identifier": id}),
            )
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "dry_run": !write,
                "profiles": profiles.len(),
                "files": files,
                "sha_pinned": sha.is_some(),
            }))?
        );
        return Ok(());
    }

    for (path, _, id) in planned {
        println!("  ✓ {}  {id}", path.display());
    }
    println!();

    // A placeholder SHA is a URL that must never reach a device. Say so every
    // time rather than only in --help.
    if sha.is_none() {
        println!("  ⚠ no --sha given: URLs carry a REPLACE-WITH-COMMIT-SHA placeholder");
    }
    if !status_keys.is_empty() && no_subscriptions {
        println!(
            "  ⚠ --no-subscriptions with @status keys ({}): an unsubscribed key can fail \
             on device with Error.UnableToEvaluatePredicate",
            status_keys.join(", ")
        );
    }
    if gitops {
        print_gitops_entries(planned);
    }
    if !write {
        println!("Dry run — no files written (pass --write to apply)");
    }
    println!("{} profile(s), {} file(s)", profiles.len(), planned.len());
    Ok(())
}

/// Print the Fleet GitOps entries for the emitted declarations.
///
/// In Fleet's `configuration_profiles:` list the activation is a **sibling key**
/// of `path:`, not its own entry — so a converted profile is one list item with
/// two paths, and pasting them as separate entries would deliver the activation
/// as if it were a configuration.
///
/// The subscriptions declaration, when present, IS its own entry: nothing
/// references it, the device just needs it applied.
///
/// Paths print relative to the working directory when they are under it. A
/// GitOps file stores repo-relative paths, so echoing back an absolute one
/// would produce an entry that resolves only on the machine that ran convert.
fn print_gitops_entries(planned: &[(PathBuf, String, String)]) {
    let find = |kind: &str| -> Option<&PathBuf> {
        planned
            .iter()
            .find(|(_, _, id)| id.contains(&format!(".{kind}.")))
            .map(|(p, _, _)| p)
    };

    println!("GitOps entries for controls.apple_settings.configuration_profiles:");
    if let Some(config) = find("config") {
        println!("      - path: {}", for_gitops(config));
        if let Some(act) = find("activation") {
            println!("        activation: {}", for_gitops(act));
        }
    }
    if let Some(subs) = find("subscriptions") {
        // Applied on its own; the activation's predicate cannot evaluate until
        // the device has the subscription.
        println!("      - path: {}", for_gitops(subs));
    }
    println!();
}

/// Render a path for pasting into a GitOps YAML: relative to the working
/// directory when it lives under it, otherwise as given.
fn for_gitops(path: &Path) -> String {
    std::env::current_dir()
        .ok()
        .and_then(|cwd| path.strip_prefix(&cwd).ok())
        .unwrap_or(path)
        .display()
        .to_string()
}

pub fn handle_legacy_refresh(
    declarations: &str,
    against: &str,
    sha: &str,
    write: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let decl_dir = Path::new(declarations);
    let index_path = decl_dir.join(LegacyIndex::FILE_NAME);
    let text = std::fs::read_to_string(&index_path).with_context(|| {
        format!(
            "no index at {} — run `ddm legacy convert` first",
            index_path.display()
        )
    })?;
    let mut index: LegacyIndex = toml::from_str(&text)?;

    let mut outcomes = Vec::new();
    for entry in &index.entries.clone() {
        // The index records the path relative to the root `convert` walked,
        // so joining it onto --against reproduces the original layout and
        // keeps nested trees distinct. Two fallbacks, in order: the bare file
        // name (for an --against pointing straight at a flattened directory),
        // then the recorded path as given (for an index written before paths
        // were relative, or one pointing outside --against).
        let recorded = Path::new(&entry.profile);
        let candidates = [
            Path::new(against).join(recorded),
            recorded
                .file_name()
                .map(|n| Path::new(against).join(n))
                .unwrap_or_else(|| recorded.to_path_buf()),
            recorded.to_path_buf(),
        ];
        let profile_path = candidates
            .iter()
            .find(|c| c.exists())
            .cloned()
            .unwrap_or_else(|| candidates[0].clone());

        let bytes = std::fs::read(&profile_path).with_context(|| {
            format!(
                "`{}` wraps `{}`, which could not be read",
                entry.identifier,
                profile_path.display()
            )
        })?;

        let outcome = plan_refresh(entry, &bytes, sha).map_err(|e| anyhow::anyhow!("{e}"))?;
        if let RefreshOutcome::Repointed { new_url, .. } = &outcome {
            let mut updated = entry.clone();
            updated.url = new_url.clone();
            updated.sha = sha.to_string();
            updated.sha256 = sha256_hex(&bytes);
            index.upsert(updated);
        }
        outcomes.push(outcome);
    }

    if write {
        for outcome in &outcomes {
            let RefreshOutcome::Repointed { identifier, .. } = outcome else {
                continue;
            };
            let Some(entry) = index.get(identifier) else {
                continue;
            };
            rewrite_profile_url(decl_dir, identifier, &entry.url)?;
        }
        std::fs::write(&index_path, toml::to_string_pretty(&index)?)?;
    }

    report_refresh(&outcomes, write, output_mode)
}

/// Rewrite `Payload.ProfileURL` in the declaration carrying `identifier`.
///
/// Reads and rewrites the specific file rather than regenerating it, so any
/// hand-added keys in the declaration survive a refresh.
fn rewrite_profile_url(dir: &Path, identifier: &str, url: &str) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        if value.get("Identifier").and_then(|v| v.as_str()) != Some(identifier) {
            continue;
        }
        let payload = value
            .get_mut("Payload")
            .and_then(|p| p.as_object_mut())
            .map_or_else(Map::new, std::mem::take);
        let mut payload = payload;
        payload.insert(
            "ProfileURL".to_string(),
            serde_json::Value::String(url.to_string()),
        );
        value["Payload"] = serde_json::Value::Object(payload);
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&value)?),
        )?;
        return Ok(());
    }
    bail!(
        "no declaration file in {} carries Identifier `{identifier}`",
        dir.display()
    )
}

fn report_refresh(outcomes: &[RefreshOutcome], write: bool, output_mode: OutputMode) -> Result<()> {
    let changed = outcomes.iter().filter(|o| o.changed()).count();

    if output_mode == OutputMode::Json {
        let items: Vec<_> = outcomes
            .iter()
            .map(|o| match o {
                RefreshOutcome::Unchanged { identifier } => serde_json::json!({
                    "identifier": identifier, "status": "unchanged"
                }),
                RefreshOutcome::Repointed {
                    identifier,
                    old_url,
                    new_url,
                } => serde_json::json!({
                    "identifier": identifier, "status": "repointed",
                    "old_url": old_url, "new_url": new_url
                }),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "dry_run": !write,
                "repointed": changed,
                "unchanged": outcomes.len() - changed,
                "declarations": items,
            }))?
        );
        return Ok(());
    }

    for o in outcomes {
        match o {
            RefreshOutcome::Unchanged { identifier } => {
                println!("  • {identifier}  unchanged");
            }
            RefreshOutcome::Repointed { identifier, .. } => {
                println!("  ✓ {identifier}  hash changed → URL re-pointed");
            }
        }
    }
    println!();
    if !write {
        println!("Dry run — no files written (pass --write to apply)");
    }
    println!(
        "{changed} re-pointed, {} unchanged",
        outcomes.len() - changed
    );
    Ok(())
}
