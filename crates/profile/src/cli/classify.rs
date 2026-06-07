//! Classify command — rewrite PayloadDisplayName into a friendly Kind: Subject name.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use rayon::prelude::*;

use crate::classify::collision::{self, NameItem};
use crate::classify::map::NamingMap;
use crate::classify::{Status, classify_profile};
use crate::cli::glob_utils::{collect_profile_files_multi_with_depth, should_batch_process_multi};
use crate::output::OutputMode;
use crate::profile::parser::parse_profile_auto_unsign;
use crate::signing;

/// One profile's classify result for output.
#[derive(serde::Serialize)]
struct ClassifyResult {
    path: String,
    old_name: String,
    new_name: Option<String>,
    status: Status,
    changed: bool,
}

/// Handle `profile classify`.
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_classify(
    paths: &[String],
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    map_path: Option<&str>,
    write: bool,
    sync_identity: bool,
    scheme: crate::reidentify::Scheme,
    org: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    if sync_identity && org.is_none() {
        anyhow::bail!("--sync-identity requires --org (e.g. --org com.yourorg)");
    }
    let map = NamingMap::resolve(map_path.map(Path::new))?;

    let files: Vec<PathBuf> = if should_batch_process_multi(paths) {
        collect_profile_files_multi_with_depth(paths, recursive, max_depth)?
    } else {
        let p = Path::new(&paths[0]);
        if !p.exists() {
            anyhow::bail!("Path not found: {}", paths[0]);
        }
        vec![p.to_path_buf()]
    };

    // Phase 1: classify every profile (no writes), in parallel.
    let process = |path: &PathBuf| -> Result<Classified, (String, String)> {
        classify_only(path, &map).map_err(|e| (path.display().to_string(), e.to_string()))
    };
    let outcomes: Vec<_> = if parallel {
        files.par_iter().map(process).collect()
    } else {
        files.iter().map(process).collect()
    };
    let mut classified = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(c) => classified.push(c),
            Err((p, e)) => eprintln!("{} {}: {}", "Warning:".yellow(), p, e),
        }
    }

    // Phase 2: resolve display-name collisions across the whole batch.
    let items: Vec<NameItem> = classified
        .iter()
        .map(|c| NameItem {
            sort_key: c.path.to_string_lossy().into_owned(),
            proposed: c.base_new_name.clone(),
            existing: c.old_name.clone(),
        })
        .collect();
    let final_names = collision::resolve_collisions(&items);

    // Phase 3: decide changes and write.
    let mut results = Vec::new();
    for (c, final_name) in classified.into_iter().zip(final_names) {
        let is_classified = c.base_new_name.is_some();
        let changed = is_classified && final_name != c.old_name;

        let sync = if sync_identity {
            org.map(|o| (o, scheme))
        } else {
            None
        };
        if write && changed && !c.signed {
            if let Err(e) = write_name(&c.path, &final_name, sync) {
                eprintln!("{} {}: {}", "Warning:".yellow(), c.path.display(), e);
            }
        }
        if c.signed && changed {
            eprintln!(
                "{} {}: signed — skipping rename (would break signature)",
                "Warning:".yellow(),
                c.path.display()
            );
        }

        results.push(ClassifyResult {
            path: c.path.display().to_string(),
            old_name: c.old_name,
            new_name: is_classified.then_some(final_name),
            status: c.status,
            changed: changed && !c.signed,
        });
    }

    match output_mode {
        OutputMode::Json => print_json(&results, write),
        OutputMode::Human => print_human(&results, write),
    }
    Ok(())
}

/// A profile classified in phase 1, before collision resolution and writing.
struct Classified {
    path: PathBuf,
    old_name: String,
    /// The classified name before collision suffixing (`None` = unclassified).
    base_new_name: Option<String>,
    status: Status,
    signed: bool,
}

/// Classify one file without writing.
fn classify_only(path: &Path, map: &NamingMap) -> Result<Classified> {
    let signed = signing::is_signed_profile(path).unwrap_or(false);
    let profile = parse_profile_auto_unsign(&path.to_string_lossy())
        .with_context(|| format!("parse {}", path.display()))?;
    let old_name = profile.payload_display_name.clone();
    let classification = classify_profile(&profile, map);
    Ok(Classified {
        path: path.to_path_buf(),
        old_name,
        base_new_name: classification.new_name,
        status: classification.status,
        signed,
    })
}

/// Rewrite a profile's `PayloadDisplayName` (and optionally its identity).
fn write_name(
    path: &Path,
    new_name: &str,
    sync: Option<(&str, crate::reidentify::Scheme)>,
) -> Result<()> {
    let mut profile = parse_profile_auto_unsign(&path.to_string_lossy())
        .with_context(|| format!("parse {}", path.display()))?;
    profile.payload_display_name = new_name.to_string();
    if let Some((org, scheme)) = sync {
        let cfg = crate::reidentify::ReidentifyConfig {
            org_domain: org.to_string(),
            scheme,
        };
        crate::reidentify::reidentify_profile(&mut profile, &cfg)?;
    }
    let value = profile.to_plist_value();
    let mut cursor = std::io::Cursor::new(Vec::new());
    plist::to_writer_xml(&mut cursor, &value).context("serialize profile")?;
    std::fs::write(path, cursor.into_inner())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn print_human(results: &[ClassifyResult], write: bool) {
    let verb = if write { "Renamed" } else { "Would rename" };
    for r in results.iter().filter(|r| r.changed) {
        if let Some(n) = &r.new_name {
            println!("{}", r.path.bold());
            println!("  {} {}", "old:".dimmed(), r.old_name);
            println!("  {} {}", "new:".green(), n);
        }
    }
    let changed = results.iter().filter(|r| r.changed).count();
    let unclassified = results
        .iter()
        .filter(|r| r.status == Status::Unclassified)
        .count();
    let unmapped = results
        .iter()
        .filter(|r| r.status == Status::AppUnmapped)
        .count();
    println!();
    println!("{}", "Summary".white().bold());
    println!("  {} {}", format!("{verb}:").cyan(), changed);
    println!("  {} {}", "Unchanged:".cyan(), results.len() - changed);
    println!("  {} {}", "Unclassified:".cyan(), unclassified);
    println!("  {} {}", "App-unmapped:".cyan(), unmapped);
}

fn print_json(results: &[ClassifyResult], write: bool) {
    let out = serde_json::json!({
        "applied": write,
        "total": results.len(),
        "changed": results.iter().filter(|r| r.changed).count(),
        "profiles": results,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
}
