//! Reidentify command — make PayloadIdentifiers consistent with UUIDs.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use rayon::prelude::*;

use crate::cli::glob_utils::{collect_profile_files_multi_with_depth, should_batch_process_multi};
use crate::output::OutputMode;
use crate::profile::parser::parse_profile_auto_unsign;
use crate::reidentify::{ReidentifyConfig, ReidentifyReport, Scheme, reidentify_profile};
use crate::signing;

/// One file's reidentify outcome.
#[derive(serde::Serialize)]
struct ReidentifyResult {
    path: String,
    #[serde(flatten)]
    report: ReidentifyReport,
}

/// Handle `profile reidentify`.
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_reidentify(
    paths: &[String],
    org: &str,
    scheme: &Scheme,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    write: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let files: Vec<PathBuf> = if should_batch_process_multi(paths) {
        collect_profile_files_multi_with_depth(paths, recursive, max_depth)?
    } else {
        let p = Path::new(&paths[0]);
        if !p.exists() {
            anyhow::bail!("Path not found: {}", paths[0]);
        }
        vec![p.to_path_buf()]
    };

    // Regenerating UUIDs rewrites references only WITHIN each profile. If a
    // reference crosses files (a Wi-Fi profile naming a certificate that lives
    // in another file), a per-file remap would leave the referrer pointing at
    // a UUID nothing owns — installs clean, never authenticates. Refuse, and
    // name the tool that does handle cross-file references.
    if matches!(
        scheme,
        Scheme::Pattern {
            regenerate_uuid: true,
            ..
        }
    ) && files.len() > 1
    {
        let parsed: Vec<(PathBuf, crate::profile::ConfigurationProfile)> = files
            .iter()
            .filter_map(|f| {
                parse_profile_auto_unsign(&f.to_string_lossy())
                    .ok()
                    .map(|p| (f.clone(), p))
            })
            .collect();
        let analysis = crate::link::analyze::analyze_links(&parsed);
        let cross_file: Vec<&crate::link::analyze::ResolvedLink> = analysis
            .links
            .iter()
            .filter(|l| l.to_file.as_ref().is_some_and(|to| *to != l.from_file))
            .collect();
        if !cross_file.is_empty() {
            anyhow::bail!(
                "--regenerate-uuid would break {} cross-file reference(s): {}\n\
                 Per-file UUID remapping cannot follow a reference into another file. \
                 Either drop --regenerate-uuid (identifiers still get rewritten, UUIDs \
                 kept), or use `contour profile link` which synchronises UUIDs across \
                 the whole set.",
                cross_file.len(),
                cross_file
                    .iter()
                    .map(|l| format!(
                        "{} → {}",
                        l.from_file,
                        l.to_file.clone().unwrap_or_default()
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    let run = |path: &PathBuf| -> Result<ReidentifyResult, (String, String)> {
        reidentify_one(path, org, scheme, write)
            .map_err(|e| (path.display().to_string(), e.to_string()))
    };
    let outcomes: Vec<_> = if parallel {
        files.par_iter().map(run).collect()
    } else {
        files.iter().map(run).collect()
    };

    let mut results = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(r) => results.push(r),
            Err((p, e)) => eprintln!("{} {}: {}", "Warning:".yellow(), p, e),
        }
    }

    match output_mode {
        OutputMode::Json => print_json(&results, write),
        OutputMode::Human => print_human(&results, write),
    }
    Ok(())
}

fn reidentify_one(
    path: &Path,
    org: &str,
    scheme: &Scheme,
    write: bool,
) -> Result<ReidentifyResult> {
    if signing::is_signed_profile(path).unwrap_or(false) {
        anyhow::bail!("signed — skipping (reidentify would break the signature)");
    }
    let mut profile = parse_profile_auto_unsign(&path.to_string_lossy())
        .with_context(|| format!("parse {}", path.display()))?;
    let config = ReidentifyConfig {
        org_domain: org.to_string(),
        scheme: scheme.clone(),
    };
    let report = reidentify_profile(&mut profile, &config)?;

    if write && report.changed {
        let value = profile.to_plist_value();
        let mut cursor = std::io::Cursor::new(Vec::new());
        plist::to_writer_xml(&mut cursor, &value).context("serialize profile")?;
        std::fs::write(path, cursor.into_inner())
            .with_context(|| format!("write {}", path.display()))?;
    }

    Ok(ReidentifyResult {
        path: path.display().to_string(),
        report,
    })
}

fn print_human(results: &[ReidentifyResult], write: bool) {
    let verb = if write {
        "Reidentified"
    } else {
        "Would reidentify"
    };
    for r in results.iter().filter(|r| r.report.changed) {
        println!("{}", r.path.bold());
        println!(
            "  {} {} {} {}",
            "envelope:".cyan(),
            r.report.envelope.identifier.old.dimmed(),
            "→".green(),
            r.report.envelope.identifier.new
        );
        for o in &r.report.orphan_refs {
            println!(
                "  {} {} {} (not a payload in this profile)",
                "orphan ref:".yellow(),
                o.field,
                o.uuid.dimmed()
            );
        }
    }
    let changed = results.iter().filter(|r| r.report.changed).count();
    let orphans: usize = results.iter().map(|r| r.report.orphan_refs.len()).sum();
    println!();
    println!("{}", "Summary".white().bold());
    println!("  {} {}", format!("{verb}:").cyan(), changed);
    println!("  {} {}", "Unchanged:".cyan(), results.len() - changed);
    println!("  {} {}", "Orphan refs:".cyan(), orphans);
}

fn print_json(results: &[ReidentifyResult], write: bool) {
    let out = serde_json::json!({
        "applied": write,
        "total": results.len(),
        "changed": results.iter().filter(|r| r.report.changed).count(),
        "orphan_refs": results.iter().map(|r| r.report.orphan_refs.len()).sum::<usize>(),
        "profiles": results,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
}

/// Resolve the scheme from CLI flags: `--from-prefix/--to-prefix` selects the
/// pattern scheme (UUIDs preserved unless `regenerate_uuid`); otherwise the
/// `--scheme` name applies.
///
/// # Errors
/// Returns an error for an unknown scheme name.
pub fn resolve_scheme(
    scheme: &str,
    from_prefix: Option<&str>,
    to_prefix: Option<&str>,
    regenerate_uuid: bool,
) -> Result<Scheme> {
    match (from_prefix, to_prefix) {
        (Some(from), Some(to)) => Ok(Scheme::Pattern {
            from: from.to_string(),
            to: to.to_string(),
            regenerate_uuid,
        }),
        _ => parse_scheme(scheme),
    }
}

/// Parse the `--scheme` value.
///
/// # Errors
/// Returns an error for an unknown scheme name.
pub fn parse_scheme(s: &str) -> Result<Scheme> {
    match s.to_ascii_lowercase().as_str() {
        "uuid" => Ok(Scheme::Uuid),
        "name" => Ok(Scheme::Name),
        other => anyhow::bail!("unknown --scheme '{other}' (expected: uuid | name)"),
    }
}
