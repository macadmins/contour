//! `santa parity` — where a Santa ruleset and an `app.settings` declaration
//! disagree. The comparison itself lives in [`crate::app_settings::parity`].

use crate::app_settings::parity::{self, DeclaredBinaries, Entry, ParityReport};
use crate::config::ClientMode;
use crate::output::{CommandResult, OutputMode, print_info, print_json, print_success};
use crate::parser::parse_files;
use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};

pub fn run(
    rules: &[PathBuf],
    declaration: &Path,
    santa_mode: ClientMode,
    mode: OutputMode,
) -> Result<()> {
    let ruleset = parse_files(rules)?;
    let text = std::fs::read_to_string(declaration)
        .with_context(|| format!("reading {}", declaration.display()))?;
    let decl: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("parsing {}", declaration.display()))?;
    let declared = DeclaredBinaries::from_declaration(&decl)
        .with_context(|| declaration.display().to_string())?;

    let report = parity::compare(&ruleset, &declared, santa_mode);

    if mode == OutputMode::Human {
        print_human(&report, ruleset.len());
    } else {
        print_json(&CommandResult::success(&report))?;
    }

    // A non-zero exit on drift, so this can gate a deploy.
    if report.has_drift() {
        anyhow::bail!("Santa and app.settings disagree about which binaries may run");
    }
    Ok(())
}

/// One entry, as an operator would recognise it.
fn describe(entry: &Entry) -> String {
    let id = &entry.identifier;
    let parts: Vec<String> = [
        id.team_id.as_ref().map(|v| format!("TeamID {v}")),
        id.signing_id.as_ref().map(|v| format!("SigningID {v}")),
        id.cdhash.as_ref().map(|v| format!("CDHash {v}")),
        id.path_prefix.as_ref().map(|v| format!("PathPrefix {v}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    match &entry.label {
        Some(label) => format!("{label} — {}", parts.join(", ")),
        None => parts.join(", "),
    }
}

fn print_human(report: &ParityReport, rule_count: usize) {
    print_info(&format!(
        "Santa: {rule_count} rule(s), {}",
        if report.santa_blocks_unknown {
            "blocks binaries no rule allows"
        } else {
            "monitor mode — blocks nothing"
        }
    ));
    print_info(&format!(
        "app.settings: {}",
        if report.app_settings_is_allowlist {
            "AllowedBinaries present — an allowlist"
        } else {
            "no AllowedBinaries — not an allowlist"
        }
    ));
    if report.santa_blocks_unknown && report.app_settings_is_allowlist {
        println!(
            "  {} two allowlists: every app must be admitted by both gates",
            "!".yellow().bold()
        );
    }

    let section = |title: &str, lines: Vec<String>| {
        if lines.is_empty() {
            return;
        }
        println!("\n{} ({})", title.bold(), lines.len());
        for line in lines {
            println!("  {} {line}", "✗".red());
        }
    };

    section(
        "Allowed by Santa, blocked by app.settings",
        report
            .blocked_by_app_settings
            .iter()
            .map(describe)
            .collect(),
    );
    section(
        "Allowed by app.settings, blocked by Santa",
        report.blocked_by_santa.iter().map(describe).collect(),
    );
    section(
        "Allowed on one gate, cancelled by a deny on the other",
        report
            .nullified
            .iter()
            .map(|n| {
                format!(
                    "{} (allowed by {}) — denied by {}",
                    describe(&n.allow),
                    n.allowed_by,
                    describe(&n.deny)
                )
            })
            .collect(),
    );
    section(
        "Santa rules app.settings cannot express, and so blocks",
        report
            .no_equivalent
            .iter()
            .filter(|u| u.blocks)
            .map(|u| format!("{} — {}", u.rule, u.reason))
            .collect(),
    );

    // Unmapped rules that block nothing still deserve a mention: they are the
    // part of the Santa policy app.settings is not carrying.
    let quiet: Vec<_> = report.no_equivalent.iter().filter(|u| !u.blocks).collect();
    if !quiet.is_empty() {
        println!(
            "\n{} {} Santa rule(s) have no app.settings form; Santa alone enforces them",
            "ℹ".blue(),
            quiet.len()
        );
    }

    if report.apple_via_platform_binaries {
        println!(
            "\n{} TeamID *APPLE*: Santa allows Apple's platform binaries without a rule. \
             Apple apps outside the OS (Xcode, Keynote) carry their own Team ID and \
             need a Santa rule for it",
            "ℹ".blue()
        );
    }

    if report.always_allow_managed && !report.blocked_by_app_settings.is_empty() {
        println!(
            "\n{} AlwaysAllowManagedApps is on: any of these installed as a managed app \
             still runs, which rules alone cannot show",
            "ℹ".blue()
        );
    }

    println!();
    if !report.has_drift() {
        print_success("No drift: every app one gate allows, the other admits too");
    }
}
