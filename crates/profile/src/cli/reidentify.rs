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
    scheme: Scheme,
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

fn reidentify_one(path: &Path, org: &str, scheme: Scheme, write: bool) -> Result<ReidentifyResult> {
    if signing::is_signed_profile(path).unwrap_or(false) {
        anyhow::bail!("signed — skipping (reidentify would break the signature)");
    }
    let mut profile = parse_profile_auto_unsign(&path.to_string_lossy())
        .with_context(|| format!("parse {}", path.display()))?;
    let config = ReidentifyConfig {
        org_domain: org.to_string(),
        scheme,
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
