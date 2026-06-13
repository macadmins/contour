//! `contour profile plan` subcommand.
//!
//! Compare a baseline profile (or directory of profiles) against a
//! proposed one and classify every payload-level delta into a tier.
//! See `crates/contour-core/skills/contour/references/sop-profile-changes.md`
//! for the operational doctrine.

use crate::plan::{ChangeTier, PayloadChange, Plan};
use crate::profile::{ConfigurationProfile, normalizer, parser};
use anyhow::{Context, Result, bail};
use colored::Colorize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// CLI flags routed from `cli::Commands::Plan`. Mirrors the contract
/// documented in sop-profile-changes.md::PROCEDURE plan_profile_changes.
#[derive(Debug, Default, Clone)]
pub struct PlanOptions {
    pub recursive: bool,
    pub predictable: bool,
    pub org: Option<String>,
    pub org_name: Option<String>,
    pub format: OutputFormat,
    pub accept_replace: bool,
    pub accept_scope_change: bool,
    /// Optional fleet size — when set, blast-radius narrative is multiplied.
    pub fleet_size: Option<usize>,
    /// Optional path for a markdown report, written alongside the primary output.
    pub md_report: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    /// SARIF 2.1.0 — GitHub Code Scanning's standard format.
    /// Emit this in CI to get inline PR annotations on every blocker.
    Sarif,
}

/// One file pair plus its plan. The reporter walks a `Vec<FilePlan>`
/// for both directory and single-file modes.
struct FilePlan {
    /// Display path used in output. For directory mode this is the
    /// path *relative to the proposed directory*; for single-file mode
    /// it's the proposed file path as the user typed it.
    label: String,
    plan: Plan,
}

pub fn handle_plan(baseline: &str, proposed: &str, opts: &PlanOptions) -> Result<()> {
    let baseline_path = Path::new(baseline);
    let proposed_path = Path::new(proposed);

    let pairs = if opts.recursive || baseline_path.is_dir() || proposed_path.is_dir() {
        collect_directory_pairs(baseline_path, proposed_path)?
    } else {
        vec![FilePair {
            label: proposed.to_string(),
            baseline_file: Some(baseline_path.to_path_buf()),
            proposed_file: Some(proposed_path.to_path_buf()),
        }]
    };

    let mut file_plans = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let plan = plan_pair(&pair, opts)?;
        file_plans.push(FilePlan {
            label: pair.label,
            plan,
        });
    }

    let exit_blocked = decide_exit(&file_plans, opts);

    match opts.format {
        OutputFormat::Text => render_text(&file_plans, opts),
        OutputFormat::Json => render_json(&file_plans, exit_blocked, opts)?,
        OutputFormat::Sarif => render_sarif(&file_plans)?,
    }

    if let Some(path) = &opts.md_report {
        std::fs::write(path, render_markdown(&file_plans, exit_blocked))
            .with_context(|| format!("writing {path}"))?;
        if opts.format == OutputFormat::Text {
            println!("{}", format!("Report written to {path}").green());
        }
    }

    if exit_blocked {
        bail!("plan reports blocking changes");
    }
    Ok(())
}

/// One pairing across baseline/proposed. Either side may be `None` —
/// `proposed_file = None` means a file was removed; `baseline_file =
/// None` means a file was added.
struct FilePair {
    label: String,
    baseline_file: Option<PathBuf>,
    proposed_file: Option<PathBuf>,
}

fn collect_directory_pairs(baseline: &Path, proposed: &Path) -> Result<Vec<FilePair>> {
    let baseline_files = list_mobileconfigs(baseline)?;
    let proposed_files = list_mobileconfigs(proposed)?;

    let mut by_name: BTreeMap<String, FilePair> = BTreeMap::new();
    for f in &baseline_files {
        let key = relative_label(f, baseline);
        by_name.entry(key.clone()).or_insert_with(|| FilePair {
            label: key,
            baseline_file: None,
            proposed_file: None,
        });
        by_name
            .get_mut(&relative_label(f, baseline))
            .unwrap()
            .baseline_file = Some(f.clone());
    }
    for f in &proposed_files {
        let key = relative_label(f, proposed);
        by_name.entry(key.clone()).or_insert_with(|| FilePair {
            label: key,
            baseline_file: None,
            proposed_file: None,
        });
        by_name
            .get_mut(&relative_label(f, proposed))
            .unwrap()
            .proposed_file = Some(f.clone());
    }
    Ok(by_name.into_values().collect())
}

fn list_mobileconfigs(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        bail!("path does not exist: {}", root.display());
    }
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
    {
        let p = entry.path();
        if p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("mobileconfig") {
            out.push(p.to_path_buf());
        }
    }
    out.sort();
    Ok(out)
}

fn relative_label(path: &Path, root: &Path) -> String {
    if root.is_file() {
        return path.display().to_string();
    }
    path.strip_prefix(root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

fn plan_pair(pair: &FilePair, opts: &PlanOptions) -> Result<Plan> {
    // File added on proposed side only → every payload is an Add.
    let baseline_profile = match &pair.baseline_file {
        Some(p) => Some(load_and_normalize(p, opts)?),
        None => None,
    };
    let proposed_profile = match &pair.proposed_file {
        Some(p) => Some(load_and_normalize(p, opts)?),
        None => None,
    };

    // Cross-tier orchestrator: gather changes from each detector, then
    // hand the merged Vec to Plan::from_changes so the summary tallies
    // reflect every tier in one place.
    let mut all_changes = Vec::new();
    let label_path = std::path::PathBuf::from(&pair.label);

    match (baseline_profile.as_ref(), proposed_profile.as_ref()) {
        (Some(b), Some(p)) => {
            all_changes.extend(crate::plan::plan_profiles(b, p).changes);
            // REF_BROKEN runs against the proposed profile only — it
            // catches dangling cross-references the classifier can't see.
            all_changes.extend(crate::plan::check_proposed_refs(p, &label_path));
            // SCOPE_BROADENED needs both sides — it's about widening,
            // which is only meaningful relative to a baseline.
            all_changes.extend(crate::plan::check_scope_broadening(b, p));
            // TYPE_INVALID is a property of the proposed profile alone;
            // a value that fails its schema fails regardless of what
            // baseline looked like.
            all_changes.extend(crate::plan::check_type_validity(p));
            // DEPRECATED only fires when the proposed profile newly
            // introduces a deprecated payload type (vs already having one).
            all_changes.extend(crate::plan::check_new_deprecations(Some(b), p));
        }
        (None, Some(p)) => {
            for (idx, content) in p.payload_content.iter().enumerate() {
                all_changes.push(PayloadChange {
                    tier: ChangeTier::Add,
                    payload_type: content.payload_type.clone(),
                    payload_identifier: content.payload_identifier.clone(),
                    payload_index: idx,
                    baseline_uuid: None,
                    proposed_uuid: Some(content.payload_uuid.clone()),
                    fields_changed: vec![],
                    evidence: format!(
                        "new file {} introduces payload {} ({})",
                        pair.label, content.payload_identifier, content.payload_type
                    ),
                });
            }
            // A new file's cross-refs still need to resolve internally.
            all_changes.extend(crate::plan::check_proposed_refs(p, &label_path));
            // Adding a new file with a deprecated PayloadType should
            // also surface as DEPRECATED.
            all_changes.extend(crate::plan::check_new_deprecations(None, p));
            // Type validity applies to any new file too.
            all_changes.extend(crate::plan::check_type_validity(p));
        }
        (Some(b), None) => {
            for (idx, content) in b.payload_content.iter().enumerate() {
                all_changes.push(PayloadChange {
                    tier: ChangeTier::Remove,
                    payload_type: content.payload_type.clone(),
                    payload_identifier: content.payload_identifier.clone(),
                    payload_index: idx,
                    baseline_uuid: Some(content.payload_uuid.clone()),
                    proposed_uuid: None,
                    fields_changed: vec![],
                    evidence: format!(
                        "file {} removed; payload {} ({}) will be uninstalled",
                        pair.label, content.payload_identifier, content.payload_type
                    ),
                });
            }
        }
        (None, None) => {}
    }

    Ok(Plan::from_changes(all_changes))
}

fn load_and_normalize(path: &Path, opts: &PlanOptions) -> Result<ConfigurationProfile> {
    let mut profile =
        parser::parse_profile_auto_unsign(path.to_str().context("path is not valid UTF-8")?)?;
    if opts.org.is_some() || opts.org_name.is_some() {
        let cfg = normalizer::NormalizerConfig {
            org_domain: opts.org.clone(),
            org_name: opts.org_name.clone(),
            naming_convention: normalizer::NamingConvention::OrgDomainPrefix,
        };
        normalizer::normalize_profile(&mut profile, &cfg)?;
    }
    if opts.predictable {
        regenerate_predictable_uuids(&mut profile, opts.org.as_deref())?;
    }
    Ok(profile)
}

/// Regenerate every PayloadUUID using v5 from `(org, payload_identifier)`
/// so that two normalized profiles converge on the same UUID for the
/// same logical payload. This is the crux of "honest plans": real
/// content changes appear as IN_PLACE_UPDATE instead of REPLACE.
fn regenerate_predictable_uuids(
    profile: &mut ConfigurationProfile,
    org: Option<&str>,
) -> Result<()> {
    use crate::uuid::{UuidConfig, regenerate_uuid};
    let cfg = UuidConfig {
        org_domain: org.map(str::to_string),
        predictable: true,
    };
    profile.payload_uuid =
        regenerate_uuid(&profile.payload_uuid, &cfg, &profile.payload_identifier)?;
    for content in &mut profile.payload_content {
        content.payload_uuid =
            regenerate_uuid(&content.payload_uuid, &cfg, &content.payload_identifier)?;
    }
    Ok(())
}

fn decide_exit(file_plans: &[FilePlan], opts: &PlanOptions) -> bool {
    for fp in file_plans {
        for change in &fp.plan.changes {
            match change.tier {
                ChangeTier::Replace if !opts.accept_replace => return true,
                ChangeTier::ScopeBroadened if !opts.accept_scope_change => return true,
                ChangeTier::RefBroken | ChangeTier::TypeInvalid | ChangeTier::Deprecated => {
                    return true;
                }
                _ => {}
            }
        }
    }
    false
}

fn render_text(file_plans: &[FilePlan], opts: &PlanOptions) {
    let mut total = SummaryTotals::default();
    for fp in file_plans {
        if fp.plan.summary.noop > 0
            && fp.plan.summary.in_place_update == 0
            && fp.plan.summary.add == 0
            && fp.plan.summary.remove == 0
            && fp.plan.summary.replace == 0
            && fp.plan.summary.ref_broken == 0
            && fp.plan.summary.scope_broadened == 0
            && fp.plan.summary.type_invalid == 0
            && fp.plan.summary.deprecated == 0
        {
            // pure NOOP — keep output quiet by default
            total.add(&fp.plan.summary);
            continue;
        }
        total.add(&fp.plan.summary);

        let header_marker = if fp.plan.summary.has_default_blocker() {
            "!".red()
        } else {
            "~".yellow()
        };
        println!("  {} {}", header_marker, fp.label.bold());
        for change in &fp.plan.changes {
            // NOOP entries are noise once at least one tier is firing
            // for this file. The summary line still counts them.
            if change.tier == ChangeTier::Noop {
                continue;
            }
            let (marker, tier_label) = tier_marker(change.tier);
            println!(
                "      {} payload[{}] {:32}  {}",
                marker, change.payload_index, change.payload_type, tier_label,
            );
            if !change.evidence.is_empty() {
                println!("        {}", change.evidence.dimmed());
            }
            if change.tier == ChangeTier::Replace
                && let Some(fleet_size) = opts.fleet_size
            {
                println!(
                    "        {}",
                    format!(
                        "↳ blast-radius: {} endpoints will remove + reinstall this payload",
                        fleet_size
                    )
                    .red()
                );
            }
            if !change.fields_changed.is_empty() {
                println!(
                    "        fields: {}",
                    change.fields_changed.join(", ").cyan()
                );
            }
        }
        println!();
    }

    println!(
        "Summary: {} NOOP   {} IN_PLACE_UPDATE   {} ADD   {} REMOVE",
        total.noop, total.in_place_update, total.add, total.remove,
    );
    println!(
        "         {} REPLACE   {} REF_BROKEN   {} SCOPE_BROADENED   {} TYPE_INVALID   {} DEPRECATED",
        total.replace,
        total.ref_broken,
        total.scope_broadened,
        total.type_invalid,
        total.deprecated,
    );

    let still_blocking = (total.replace > 0 && !opts.accept_replace)
        || (total.scope_broadened > 0 && !opts.accept_scope_change)
        || total.ref_broken > 0
        || total.type_invalid > 0
        || total.deprecated > 0;

    println!();
    if still_blocking {
        println!(
            "{}",
            "Plan exits non-zero: blocking changes detected. \
             Override with --accept-replace or --accept-scope-change \
             where appropriate; REF_BROKEN, TYPE_INVALID, and \
             DEPRECATED have no accept flag — fix the change."
                .red()
        );
    } else if total.replace > 0 || total.scope_broadened > 0 {
        println!(
            "{}",
            "Plan exits 0: blocking changes were explicitly accepted via flags.".yellow()
        );
    } else {
        println!("{}", "Plan exits 0: no blocking changes.".green());
    }
}

fn tier_marker(tier: ChangeTier) -> (colored::ColoredString, &'static str) {
    match tier {
        ChangeTier::Noop => ("=".dimmed(), "NOOP"),
        ChangeTier::InPlaceUpdate => ("~".yellow(), "IN_PLACE_UPDATE"),
        ChangeTier::Add => ("+".green(), "ADD"),
        ChangeTier::Remove => ("-".red(), "REMOVE"),
        ChangeTier::Replace => ("!".red(), "REPLACE"),
        ChangeTier::RefBroken => ("!".red(), "REF_BROKEN"),
        ChangeTier::ScopeBroadened => ("!".red(), "SCOPE_BROADENED"),
        ChangeTier::TypeInvalid => ("!".red(), "TYPE_INVALID"),
        ChangeTier::Deprecated => ("!".red(), "DEPRECATED"),
    }
}

#[derive(Serialize)]
struct JsonOutput<'a> {
    success: bool,
    exit_policy: &'static str,
    summary: SummaryTotals,
    files: Vec<JsonFile<'a>>,
}

#[derive(Serialize)]
struct JsonFile<'a> {
    file: &'a str,
    summary: &'a crate::plan::PlanSummary,
    changes: &'a [PayloadChange],
}

#[derive(Default, Serialize)]
struct SummaryTotals {
    noop: usize,
    in_place_update: usize,
    add: usize,
    remove: usize,
    replace: usize,
    ref_broken: usize,
    scope_broadened: usize,
    type_invalid: usize,
    deprecated: usize,
}

impl SummaryTotals {
    fn add(&mut self, s: &crate::plan::PlanSummary) {
        self.noop += s.noop;
        self.in_place_update += s.in_place_update;
        self.add += s.add;
        self.remove += s.remove;
        self.replace += s.replace;
        self.ref_broken += s.ref_broken;
        self.scope_broadened += s.scope_broadened;
        self.type_invalid += s.type_invalid;
        self.deprecated += s.deprecated;
    }
}

/// Emit SARIF 2.1.0. The result `level` maps to the tier's blast
/// radius: blockers → "error", non-blockers → "note". GitHub Code
/// Scanning renders "error" results as inline PR annotations.
fn render_sarif(file_plans: &[FilePlan]) -> Result<()> {
    let mut results = Vec::new();
    for fp in file_plans {
        for change in &fp.plan.changes {
            if change.tier == ChangeTier::Noop {
                continue;
            }
            let level = if change.tier.is_default_blocker() {
                "error"
            } else {
                "note"
            };
            let rule_id = match change.tier {
                ChangeTier::Noop => "noop",
                ChangeTier::InPlaceUpdate => "in_place_update",
                ChangeTier::Add => "add",
                ChangeTier::Remove => "remove",
                ChangeTier::Replace => "replace",
                ChangeTier::RefBroken => "ref_broken",
                ChangeTier::ScopeBroadened => "scope_broadened",
                ChangeTier::TypeInvalid => "type_invalid",
                ChangeTier::Deprecated => "deprecated",
            };
            results.push(serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": change.evidence },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": fp.label },
                        "region": { "startLine": 1 }
                    },
                    "logicalLocations": [{
                        "name": change.payload_identifier,
                        "kind": "object",
                        "fullyQualifiedName": format!(
                            "{}#payload[{}]",
                            change.payload_type, change.payload_index
                        )
                    }]
                }]
            }));
        }
    }
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "contour",
                    "informationUri": "https://github.com/macadmins/contour",
                    "rules": [
                        {"id": "replace", "name": "REPLACE", "shortDescription": {"text": "PayloadUUID change forces remove + reinstall"}},
                        {"id": "ref_broken", "name": "REF_BROKEN", "shortDescription": {"text": "Cross-reference points at no payload"}},
                        {"id": "scope_broadened", "name": "SCOPE_BROADENED", "shortDescription": {"text": "Access surface widened"}},
                        {"id": "type_invalid", "name": "TYPE_INVALID", "shortDescription": {"text": "Plist value type doesn't match schema"}},
                        {"id": "deprecated", "name": "DEPRECATED", "shortDescription": {"text": "Newly introduces a deprecated PayloadType"}},
                    ]
                }
            },
            "results": results,
        }],
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

fn render_json(file_plans: &[FilePlan], exit_blocked: bool, _opts: &PlanOptions) -> Result<()> {
    let mut totals = SummaryTotals::default();
    let mut files = Vec::with_capacity(file_plans.len());
    for fp in file_plans {
        totals.add(&fp.plan.summary);
        files.push(JsonFile {
            file: &fp.label,
            summary: &fp.plan.summary,
            changes: &fp.plan.changes,
        });
    }
    let out = JsonOutput {
        success: !exit_blocked,
        exit_policy: if exit_blocked { "blocked" } else { "ok" },
        summary: totals,
        files,
    };
    let s = serde_json::to_string_pretty(&out)?;
    println!("{s}");
    Ok(())
}

/// Snake-case tier label shared by SARIF/markdown reporters.
fn tier_label(tier: ChangeTier) -> &'static str {
    match tier {
        ChangeTier::Noop => "noop",
        ChangeTier::InPlaceUpdate => "in_place_update",
        ChangeTier::Add => "add",
        ChangeTier::Remove => "remove",
        ChangeTier::Replace => "replace",
        ChangeTier::RefBroken => "ref_broken",
        ChangeTier::ScopeBroadened => "scope_broadened",
        ChangeTier::TypeInvalid => "type_invalid",
        ChangeTier::Deprecated => "deprecated",
    }
}

/// Render the plan as a markdown report — summary table plus a per-file
/// change matrix. Mirrors the text/JSON reporters over `Vec<FilePlan>`.
fn render_markdown(file_plans: &[FilePlan], exit_blocked: bool) -> String {
    use std::fmt::Write as _;
    let mut md = String::with_capacity(4096);
    let mut totals = SummaryTotals::default();
    for fp in file_plans {
        totals.add(&fp.plan.summary);
    }

    writeln!(md, "# Profile Plan Report\n").unwrap();
    writeln!(
        md,
        "**Status:** {}\n",
        if exit_blocked {
            "BLOCKED — blocking changes detected"
        } else {
            "OK — no blocking changes"
        }
    )
    .unwrap();
    writeln!(
        md,
        "| Files | Noop | In-place | Add | Remove | Replace | Ref-broken | Scope | Type-invalid | Deprecated |\n|---|---|---|---|---|---|---|---|---|---|"
    )
    .unwrap();
    writeln!(
        md,
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
        file_plans.len(),
        totals.noop,
        totals.in_place_update,
        totals.add,
        totals.remove,
        totals.replace,
        totals.ref_broken,
        totals.scope_broadened,
        totals.type_invalid,
        totals.deprecated
    )
    .unwrap();

    for fp in file_plans {
        let changed: Vec<&PayloadChange> = fp
            .plan
            .changes
            .iter()
            .filter(|c| c.tier != ChangeTier::Noop)
            .collect();
        if changed.is_empty() {
            continue;
        }
        writeln!(md, "## `{}`\n", fp.label).unwrap();
        writeln!(
            md,
            "| Tier | Payload type | Identifier | Fields | Evidence |\n|---|---|---|---|---|"
        )
        .unwrap();
        for c in changed {
            let fields = if c.fields_changed.is_empty() {
                String::new()
            } else {
                format!("`{}`", c.fields_changed.join("`, `"))
            };
            writeln!(
                md,
                "| {} | `{}` | `{}` | {} | {} |",
                tier_label(c.tier),
                c.payload_type,
                c.payload_identifier,
                fields,
                c.evidence.replace('|', "\\|")
            )
            .unwrap();
        }
        writeln!(md).unwrap();
    }

    if file_plans
        .iter()
        .all(|fp| fp.plan.changes.iter().all(|c| c.tier == ChangeTier::Noop))
    {
        writeln!(md, "_No payload-level changes._").unwrap();
    }
    md
}
