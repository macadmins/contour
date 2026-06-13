//! `profile collisions` — detect cross-profile payload-domain collisions.
//!
//! Recursively scans `.mobileconfig` profiles and DDM `.json` declarations, groups
//! every managed payload by `(scope, domain)` where the scope is the file's parent
//! directory (or the whole tree with `--flat`), and reports any domain managed by
//! 2+ files — with a per-key verdict (conflict / redundant / complementary).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::collisions::{
    CollisionReport, Format, KeyVerdict, PayloadRecord, canonical_json, canonical_plist,
    index_collisions,
};
use crate::ddm::parser::{is_ddm_file, parse_declaration_file};
use crate::output::OutputMode;
use crate::profile::parser::parse_profile_lenient;

/// Classify a path as a scannable config file, by extension (+ content for DDM).
fn config_format(p: &Path) -> Option<Format> {
    match p
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("mobileconfig") => Some(Format::Mobileconfig),
        Some("json") if is_ddm_file(p) => Some(Format::Ddm),
        _ => None,
    }
}

/// Collect `.mobileconfig` + DDM `.json` files from the given paths.
fn collect_config_files(
    paths: &[String],
    recursive: bool,
    max_depth: Option<usize>,
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in paths {
        let p = Path::new(path);
        if p.is_file() {
            if config_format(p).is_some() {
                files.push(p.to_path_buf());
            }
        } else if p.is_dir() {
            let mut walker = WalkDir::new(p).follow_links(true);
            if !recursive {
                walker = walker.max_depth(1);
            } else if let Some(d) = max_depth {
                walker = walker.max_depth(d);
            }
            for entry in walker.into_iter().filter_map(std::result::Result::ok) {
                let ep = entry.path();
                if ep.is_file() && config_format(ep).is_some() {
                    files.push(ep.to_path_buf());
                }
            }
        } else {
            anyhow::bail!("Path does not exist: {path}");
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

/// Parse one file into its managed-payload records (best-effort: unparseable files
/// yield no records rather than failing the whole scan).
fn parse_file(path: &Path, flat: bool) -> Vec<PayloadRecord> {
    let scope = if flat {
        "<flat>".to_string()
    } else {
        path.parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    };
    let file = path.display().to_string();

    if is_ddm_file(path) {
        return match parse_declaration_file(path) {
            Ok(decl) => vec![PayloadRecord {
                scope,
                domain: decl.declaration_type,
                source_file: file,
                format: Format::Ddm,
                keys: decl
                    .payload
                    .iter()
                    .map(|(k, v)| (k.clone(), canonical_json(v)))
                    .collect(),
            }],
            Err(_) => vec![],
        };
    }

    match parse_profile_lenient(path.to_str().unwrap_or_default()) {
        Ok(fr) => fr
            .profile
            .payload_content
            .iter()
            .map(|payload| PayloadRecord {
                scope: scope.clone(),
                domain: payload.payload_type.clone(),
                source_file: file.clone(),
                format: Format::Mobileconfig,
                // Exclude only the standard envelope metadata keys; keep real config
                // keys — incl. `PayloadContent` for com.apple.ManagedClient.preferences.
                keys: payload
                    .content
                    .iter()
                    .filter(|(k, _)| !crate::collisions::is_envelope_key(k))
                    .map(|(k, v)| (k.clone(), canonical_plist(v)))
                    .collect(),
            })
            .collect(),
        Err(_) => vec![],
    }
}

/// Handle `profile collisions`.
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_collisions(
    paths: &[String],
    recursive: bool,
    max_depth: Option<usize>,
    flat: bool,
    fail_on_conflict: bool,
    fail_on_split: bool,
    parallel: bool,
    md_report: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let files = collect_config_files(paths, recursive, max_depth)?;

    let records: Vec<PayloadRecord> = if parallel {
        files.par_iter().flat_map(|f| parse_file(f, flat)).collect()
    } else {
        files.iter().flat_map(|f| parse_file(f, flat)).collect()
    };

    let report = CollisionReport {
        collisions: index_collisions(&records),
        files_scanned: files.len(),
        payloads_scanned: records.len(),
    };

    match output_mode {
        OutputMode::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputMode::Human => render_human(&report),
    }

    if let Some(path) = md_report {
        fs::write(path, render_markdown(&report)).with_context(|| format!("writing {path}"))?;
        if output_mode == OutputMode::Human {
            println!("{}", format!("Report written to {path}").green());
        }
    }

    if fail_on_conflict && report.conflict_count() > 0 {
        anyhow::bail!(
            "{} domain(s) have value conflicts across co-applied profiles",
            report.conflict_count()
        );
    }
    if fail_on_split && !report.is_empty() {
        anyhow::bail!(
            "{} domain(s) are split across 2+ profiles (--fail-on-split)",
            report.collisions.len()
        );
    }
    Ok(())
}

fn verdict_label(v: KeyVerdict) -> colored::ColoredString {
    match v {
        KeyVerdict::Conflict => "CONFLICT".red().bold(),
        KeyVerdict::Redundant => "redundant".dimmed(),
        KeyVerdict::Complementary => "complementary".yellow(),
    }
}

fn render_human(report: &CollisionReport) {
    if report.is_empty() {
        println!(
            "{} No payload-domain collisions across {} file(s).",
            "✓".green(),
            report.files_scanned
        );
        return;
    }

    for c in &report.collisions {
        let fmt = match c.format {
            Format::Mobileconfig => "mobileconfig",
            Format::Ddm => "DDM",
        };
        println!(
            "\n{}  {} {}",
            "▌".red(),
            c.domain.bold(),
            format!("[{fmt}] scope: {}]", c.scope).dimmed()
        );
        println!("  managed by {} files:", c.files.len());
        for f in &c.files {
            println!("    • {f}");
        }
        for k in &c.keys {
            let detail = if k.verdict == KeyVerdict::Conflict {
                let vals: Vec<String> = k
                    .values
                    .iter()
                    .map(|(f, v)| format!("{}={v}", short(f)))
                    .collect();
                format!("  ({})", vals.join("  vs  "))
            } else if k.verdict == KeyVerdict::Complementary {
                let only = k.values.keys().next().map(|f| short(f)).unwrap_or_default();
                format!("  (only in {only})")
            } else {
                String::new()
            };
            println!(
                "    {:<14} {}{}",
                verdict_label(k.verdict),
                k.key,
                detail.dimmed()
            );
        }
    }

    println!(
        "\n{} {} colliding domain(s), {} with value conflicts (across {} files).",
        if report.conflict_count() > 0 {
            "✗".red()
        } else {
            "!".yellow()
        },
        report.collisions.len(),
        report.conflict_count(),
        report.files_scanned
    );
}

/// Last two path components, for compact human output.
fn short(path: &str) -> String {
    let parts: Vec<&str> = path.rsplit('/').take(2).collect();
    parts.into_iter().rev().collect::<Vec<_>>().join("/")
}

fn render_markdown(report: &CollisionReport) -> String {
    use std::fmt::Write as _;
    let mut md = String::with_capacity(4096);
    writeln!(md, "# Profile Collision Report\n").unwrap();
    writeln!(
        md,
        "| Files scanned | Payloads | Colliding domains | With conflicts |\n|---|---|---|---|\n| {} | {} | {} | {} |\n",
        report.files_scanned,
        report.payloads_scanned,
        report.collisions.len(),
        report.conflict_count()
    )
    .unwrap();

    for c in &report.collisions {
        let fmt = match c.format {
            Format::Mobileconfig => "mobileconfig",
            Format::Ddm => "DDM",
        };
        writeln!(md, "## `{}` — {} ({fmt})\n", c.domain, c.scope).unwrap();
        writeln!(md, "Managed by:").unwrap();
        for f in &c.files {
            writeln!(md, "- `{f}`").unwrap();
        }
        writeln!(md, "\n| Key | Verdict | Values |\n|---|---|---|").unwrap();
        for k in &c.keys {
            let verdict = match k.verdict {
                KeyVerdict::Conflict => "**conflict**",
                KeyVerdict::Redundant => "redundant",
                KeyVerdict::Complementary => "complementary",
            };
            let values = k
                .values
                .iter()
                .map(|(f, v)| format!("`{}`=`{v}`", short(f)))
                .collect::<Vec<_>>()
                .join(" · ");
            writeln!(md, "| `{}` | {verdict} | {values} |", k.key).unwrap();
        }
        writeln!(md).unwrap();
    }
    md
}
