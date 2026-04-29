//! Interactive builder for the `[gitops_glob]` section of a baseline in `mscp.toml`.
//!
//! Invoked by `mscp process --interactive` / `mscp generate --interactive` to
//! let the user collapse long sections (profiles, scripts) into a single
//! `paths:` glob, while keeping a small set of items as literal `path:`
//! exceptions (optionally moved into subfolders so the flat glob does not
//! match them on disk).
//!
//! Flow per (baseline × section):
//!   1. Discover items.
//!   2. For profiles only: ask "drop labels?" — Fleet disallows labels on
//!      `paths:` entries, so globbing profiles requires the user to
//!      consciously accept that the globbed subset will run without the
//!      baseline label.
//!   3. Ask "Customize exceptions?" (default no).
//!   4. MultiSelect items to keep as literal `path:`.
//!   5. For each selected exception: Text prompts for subfolder + labels.
//!   6. Preview YAML snippet; confirm.
//!
//! Mutates the passed-in `Config` in place; the caller persists to `mscp.toml`.

use crate::config::{BaselineConfig, Config, GlobException, GlobSection};
use crate::managers::constraints::Constraints;
use anyhow::Result;
use colored::Colorize;
use inquire::{Confirm, MultiSelect, Text};
use std::path::Path;

/// Entry point: walks every enabled baseline in `config`, running the
/// interactive glob flow for each.
pub fn run_glob_interactive(config: &mut Config, mscp_repo: &Path) -> Result<()> {
    println!(
        "\n{}",
        "Fleet GitOps glob configuration (interactive)"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "Collapse long sections into a single `paths:` glob and keep \
         specific items as `path:` exceptions.\n"
            .dimmed()
    );

    for baseline in config.baselines.iter_mut().filter(|b| b.enabled) {
        configure_baseline(baseline, mscp_repo)?;
    }

    Ok(())
}

fn configure_baseline(baseline: &mut BaselineConfig, mscp_repo: &Path) -> Result<()> {
    println!(
        "\n{} {}",
        "Baseline:".bold(),
        baseline.name.as_str().cyan().bold()
    );

    // --- Profiles section ---
    let profiles = Constraints::discover_profiles(mscp_repo, Some(&baseline.name))
        .unwrap_or_default()
        .into_iter()
        .map(|p| p.filename)
        .collect::<Vec<_>>();
    baseline.gitops_glob.profiles =
        configure_profiles_section(&baseline.name, &profiles)?;

    // --- Scripts section ---
    // `discover_scripts` returns rule IDs; audit/remediate filenames are
    // derived downstream. For the interactive UX we treat the rule ID as
    // the user-facing identifier; subfolder placement is applied to the
    // generated audit/remediate pair if their filenames contain the rule ID.
    let scripts = Constraints::discover_scripts(mscp_repo, Some(&baseline.name))
        .unwrap_or_default()
        .into_iter()
        .map(|s| format!("{}.sh", s.rule_id))
        .collect::<Vec<_>>();
    baseline.gitops_glob.scripts = configure_scripts_section(&baseline.name, &scripts)?;

    Ok(())
}

fn configure_profiles_section(
    baseline_name: &str,
    items: &[String],
) -> Result<Option<GlobSection>> {
    if items.len() < 2 {
        println!(
            "  {} {}",
            "profiles:".bold(),
            format!("{} item(s) — glob has no benefit, skipping", items.len()).dimmed()
        );
        return Ok(None);
    }

    println!(
        "  {} {} items in `{baseline_name}`",
        "profiles:".bold(),
        items.len()
    );
    println!(
        "  {}",
        "(profiles carry the `mscp-<baseline>` label by default — a `paths:` \
         glob cannot, so enabling this drops the label on globbed items.)"
            .dimmed()
    );

    let enable = Confirm::new(&format!(
        "Enable profiles glob for `{baseline_name}`? (drops labels on globbed items)"
    ))
    .with_default(false)
    .prompt_skippable()
    .unwrap_or(Some(false))
    .unwrap_or(false);

    if !enable {
        return Ok(None);
    }

    let exceptions = prompt_exceptions(items, /* labels_allowed = */ true)?;
    let section = GlobSection {
        enabled: true,
        drop_labels: true,
        exceptions,
    };

    print_preview_profiles(baseline_name, &section);
    let looks_good = Confirm::new("Looks good?")
        .with_default(true)
        .prompt_skippable()
        .unwrap_or(Some(true))
        .unwrap_or(true);

    if !looks_good {
        println!("  {}", "Restarting profiles section...".yellow());
        return configure_profiles_section(baseline_name, items);
    }

    Ok(Some(section))
}

fn configure_scripts_section(
    baseline_name: &str,
    items: &[String],
) -> Result<Option<GlobSection>> {
    if items.len() < 2 {
        println!(
            "  {} {}",
            "scripts:".bold(),
            format!("{} item(s) — glob has no benefit, skipping", items.len()).dimmed()
        );
        return Ok(None);
    }

    println!(
        "  {} {} items in `{baseline_name}`",
        "scripts:".bold(),
        items.len()
    );

    let enable = Confirm::new(&format!(
        "Enable scripts glob for `{baseline_name}`?"
    ))
    .with_default(true)
    .prompt_skippable()
    .unwrap_or(Some(false))
    .unwrap_or(false);

    if !enable {
        return Ok(None);
    }

    let exceptions = prompt_exceptions(items, /* labels_allowed = */ false)?;
    let section = GlobSection {
        enabled: true,
        drop_labels: false, // scripts carry no labels in Fleet; field is irrelevant
        exceptions,
    };

    print_preview_scripts(baseline_name, &section);
    let looks_good = Confirm::new("Looks good?")
        .with_default(true)
        .prompt_skippable()
        .unwrap_or(Some(true))
        .unwrap_or(true);

    if !looks_good {
        println!("  {}", "Restarting scripts section...".yellow());
        return configure_scripts_section(baseline_name, items);
    }

    Ok(Some(section))
}

/// Prompt the user to pick a subset of `items` as exceptions, then collect
/// subfolder (and optionally labels) for each picked item.
fn prompt_exceptions(items: &[String], labels_allowed: bool) -> Result<Vec<GlobException>> {
    let customize = Confirm::new("Any exceptions to keep as literal path:?")
        .with_default(false)
        .prompt_skippable()
        .unwrap_or(Some(false))
        .unwrap_or(false);

    if !customize {
        return Ok(Vec::new());
    }

    let selected = MultiSelect::new(
        "Pick items to keep as literal `path:` (space to toggle, enter to confirm):",
        items.to_vec(),
    )
    .with_vim_mode(true)
    .with_page_size(15)
    .prompt_skippable()
    .unwrap_or(Some(Vec::new()))
    .unwrap_or_default();

    let mut exceptions = Vec::with_capacity(selected.len());
    for filename in selected {
        println!("  {} {}", "•".cyan(), filename.as_str().green());

        let subfolder = Text::new("Subfolder (empty = flat, glob may still match):")
            .with_help_message("Moving into a subfolder hides the file from a flat glob")
            .prompt_skippable()
            .unwrap_or(Some(String::new()))
            .unwrap_or_default();
        let subfolder = if subfolder.trim().is_empty() {
            None
        } else {
            Some(subfolder.trim().to_string())
        };

        let (labels_include_all, labels_include_any, labels_exclude_any) = if labels_allowed {
            (
                read_csv_labels("labels_include_all (comma-separated)")?,
                read_csv_labels("labels_include_any (comma-separated)")?,
                read_csv_labels("labels_exclude_any (comma-separated)")?,
            )
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        exceptions.push(GlobException {
            filename,
            subfolder,
            labels_include_all,
            labels_include_any,
            labels_exclude_any,
        });
    }

    Ok(exceptions)
}

fn read_csv_labels(prompt: &str) -> Result<Vec<String>> {
    let raw = Text::new(prompt)
        .prompt_skippable()
        .unwrap_or(Some(String::new()))
        .unwrap_or_default();
    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

fn print_preview_profiles(baseline_name: &str, section: &GlobSection) {
    println!("\n  {} preview:", "Profiles".bold());
    println!(
        "    - paths: ../platforms/mscp/{baseline_name}/profiles/*.mobileconfig"
    );
    for exc in &section.exceptions {
        let sub = exc
            .subfolder
            .as_deref()
            .map(|s| format!("/{s}"))
            .unwrap_or_default();
        println!(
            "    - path: ../platforms/mscp/{baseline_name}/profiles{sub}/{}",
            exc.filename
        );
        if !exc.labels_include_all.is_empty() {
            println!(
                "      labels_include_all: [{}]",
                exc.labels_include_all.join(", ")
            );
        }
        if !exc.labels_include_any.is_empty() {
            println!(
                "      labels_include_any: [{}]",
                exc.labels_include_any.join(", ")
            );
        }
        if !exc.labels_exclude_any.is_empty() {
            println!(
                "      labels_exclude_any: [{}]",
                exc.labels_exclude_any.join(", ")
            );
        }
    }
    println!();
}

fn print_preview_scripts(baseline_name: &str, section: &GlobSection) {
    println!("\n  {} preview:", "Scripts".bold());
    println!(
        "    - paths: ../platforms/mscp/{baseline_name}/scripts/*.sh"
    );
    for exc in &section.exceptions {
        let sub = exc
            .subfolder
            .as_deref()
            .map(|s| format!("/{s}"))
            .unwrap_or_default();
        println!(
            "    - path: ../platforms/mscp/{baseline_name}/scripts{sub}/{}",
            exc.filename
        );
    }
    println!();
}
