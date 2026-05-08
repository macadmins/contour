//! `contour profile rollback` subcommand — cherry-pick UUID restore.
//!
//! See `crates/contour-core/skills/contour/references/sop-profile-changes.md`
//! for the operational doctrine.

use crate::profile::parser;
use crate::rollback::{RollbackFilter, RollbackOptions, restore_uuids};
use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct RollbackCliOptions {
    pub recursive: bool,
    pub uuids_only: bool,
    pub payload_types: Vec<String>,
    pub refs_only: bool,
    pub no_rewrite_refs: bool,
    pub dry_run: bool,
    /// Output directory (None = in-place rewrite of CURRENT files).
    pub output_dir: Option<PathBuf>,
}

pub fn handle_rollback(baseline: &str, current: &str, opts: &RollbackCliOptions) -> Result<()> {
    let baseline_path = Path::new(baseline);
    let current_path = Path::new(current);

    let pairs = if opts.recursive || baseline_path.is_dir() || current_path.is_dir() {
        collect_pairs(baseline_path, current_path)?
    } else {
        vec![FilePair {
            label: current.to_string(),
            baseline_file: baseline_path.to_path_buf(),
            current_file: current_path.to_path_buf(),
        }]
    };

    let mut total_uuids = 0usize;
    let mut total_refs = 0usize;
    let mut written = 0usize;

    let rollback_opts = RollbackOptions {
        filter: RollbackFilter {
            uuids_only: opts.uuids_only,
            payload_types: opts.payload_types.clone(),
            refs_only: opts.refs_only,
        },
        rewrite_refs: !opts.no_rewrite_refs,
    };

    for pair in pairs {
        let baseline_profile = parser::parse_profile_auto_unsign(
            pair.baseline_file
                .to_str()
                .context("baseline path is not valid UTF-8")?,
        )?;
        let mut current_profile = parser::parse_profile_auto_unsign(
            pair.current_file
                .to_str()
                .context("current path is not valid UTF-8")?,
        )?;

        let result = match restore_uuids(&baseline_profile, &mut current_profile, &rollback_opts) {
            Ok(r) => r,
            Err(e) => {
                // Fail-closed: never write a partial rollback.
                bail!("{}: rollback aborted before write — {e}", pair.label);
            }
        };

        total_uuids += result.uuids_restored;
        total_refs += result.refs_rewritten;

        if result.uuids_restored == 0 {
            println!(
                "{} {}: nothing to restore (UUIDs already match baseline)",
                "=".dimmed(),
                pair.label.dimmed()
            );
            continue;
        }
        println!(
            "{} {}: restored {} UUID(s), rewrote {} cross-reference(s)",
            "~".yellow(),
            pair.label.bold(),
            result.uuids_restored,
            result.refs_rewritten,
        );

        if !opts.dry_run {
            let output_path = match &opts.output_dir {
                Some(dir) => dir.join(&pair.label),
                None => pair.current_file.clone(),
            };
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }
            parser::write_profile(&current_profile, &output_path)?;
            written += 1;
        }
    }

    println!();
    if opts.dry_run {
        println!(
            "{}",
            format!(
                "Dry run: would restore {} UUID(s), rewrite {} cross-reference(s) across {} file(s).",
                total_uuids,
                total_refs,
                written, // 0 in dry-run mode
            )
            .yellow()
        );
        println!("{}", "Re-run without --dry-run to apply.".dimmed());
    } else {
        println!(
            "{}",
            format!(
                "Rollback applied: {} UUID(s) restored, {} cross-reference(s) rewritten, {} file(s) written.",
                total_uuids, total_refs, written
            )
            .green()
        );
    }
    Ok(())
}

struct FilePair {
    label: String,
    baseline_file: PathBuf,
    current_file: PathBuf,
}

fn collect_pairs(baseline: &Path, current: &Path) -> Result<Vec<FilePair>> {
    let baseline_files = list_mobileconfigs(baseline)?;
    let current_files = list_mobileconfigs(current)?;

    let mut by_name: std::collections::BTreeMap<String, FilePair> =
        std::collections::BTreeMap::new();
    for f in &current_files {
        let label = relative_label(f, current);
        if let Some(b) = baseline_files
            .iter()
            .find(|bf| relative_label(bf, baseline) == label)
        {
            by_name.insert(
                label.clone(),
                FilePair {
                    label,
                    baseline_file: b.clone(),
                    current_file: f.clone(),
                },
            );
        }
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
