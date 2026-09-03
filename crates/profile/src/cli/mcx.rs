//! `profile mcx` — inspect and surgically rename managed-preference domains.
//!
//! Two verbs, deliberately separate: `list` shows where a domain is in scope
//! (analysis, never writes), `rename` performs the edit. Rename defaults to a
//! dry run so the scope is always reviewed before any file changes.

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::mcx::{DomainRewrite, McxDomainRef, find_domains, rename_domains};
use crate::output::OutputMode;
use crate::profile::parser::parse_profile_auto_unsign;

/// Collect `.mobileconfig` files from paths.
fn collect(paths: &[String], recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in paths {
        let p = Path::new(path);
        if p.is_file() {
            files.push(p.to_path_buf());
        } else if p.is_dir() {
            let walker = if recursive {
                walkdir::WalkDir::new(p)
            } else {
                walkdir::WalkDir::new(p).max_depth(1)
            };
            for entry in walker.into_iter().filter_map(std::result::Result::ok) {
                let ep = entry.path();
                if ep.is_file() && ep.extension().is_some_and(|e| e == "mobileconfig") {
                    files.push(ep.to_path_buf());
                }
            }
        } else {
            anyhow::bail!("path does not exist: {path}");
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

/// Every managed-preference domain across the file set, with its files.
fn survey(files: &[PathBuf]) -> BTreeMap<String, Vec<(PathBuf, McxDomainRef)>> {
    let mut by_domain: BTreeMap<String, Vec<(PathBuf, McxDomainRef)>> = BTreeMap::new();
    for file in files {
        let Ok(profile) = parse_profile_auto_unsign(&file.to_string_lossy()) else {
            continue;
        };
        for d in find_domains(&profile) {
            by_domain
                .entry(d.domain.clone())
                .or_default()
                .push((file.clone(), d));
        }
    }
    by_domain
}

/// Handle `profile mcx list` — where each managed-preference domain is in scope.
pub fn handle_list(paths: &[String], recursive: bool, output_mode: OutputMode) -> Result<()> {
    let files = collect(paths, recursive)?;
    let by_domain = survey(&files);

    if output_mode == OutputMode::Json {
        let items: Vec<serde_json::Value> = by_domain
            .iter()
            .map(|(domain, hits)| {
                serde_json::json!({
                    "domain": domain,
                    "occurrences": hits.len(),
                    "files": hits.iter().map(|(f, d)| serde_json::json!({
                        "file": f.display().to_string(),
                        "payload_index": d.payload_index,
                        "payload_identifier": d.payload_identifier,
                        "setting_keys": d.setting_keys,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "files_scanned": files.len(),
                "domains": items,
            }))?
        );
        return Ok(());
    }

    if by_domain.is_empty() {
        println!("No managed-preference domains in {} file(s).", files.len());
        return Ok(());
    }

    println!(
        "{} managed-preference domain(s) across {} file(s):\n",
        by_domain.len(),
        files.len()
    );
    for (domain, hits) in &by_domain {
        println!(
            "  {}  {}",
            format!("{:3}x", hits.len()).dimmed(),
            domain.bold()
        );
        for (file, d) in hits {
            let keys = if d.setting_keys.is_empty() {
                String::new()
            } else {
                format!("  [{}]", d.setting_keys.join(", "))
            };
            println!(
                "        {}  payload {}{}",
                file.display().to_string().dimmed(),
                d.payload_index,
                keys.dimmed()
            );
        }
    }
    Ok(())
}

/// Handle `profile mcx rename`.
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_rename(
    paths: &[String],
    from: Option<&str>,
    to: Option<&str>,
    from_prefix: Option<&str>,
    to_prefix: Option<&str>,
    interactive: bool,
    recursive: bool,
    write: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let files = collect(paths, recursive)?;
    let by_domain = survey(&files);
    if by_domain.is_empty() {
        anyhow::bail!(
            "no managed-preference domains found in {} file(s)",
            files.len()
        );
    }

    // Interactive: pick the domain to rename from what is actually present,
    // then supply the replacement — search and replace against reality rather
    // than a remembered string.
    let (rewrite_from, rewrite_to, is_prefix) = if interactive {
        let labels: Vec<String> = by_domain
            .iter()
            .map(|(d, hits)| format!("{d}   ({} occurrence(s))", hits.len()))
            .collect();
        let picked = inquire::Select::new("Domain to rename:", labels.clone())
            .with_help_message("shown with occurrence counts from the scanned files")
            .prompt()
            .context("selection cancelled")?;
        let idx = labels.iter().position(|l| *l == picked).unwrap_or(0);
        let domain = by_domain.keys().nth(idx).cloned().unwrap_or_default();

        let replacement = inquire::Text::new("Replace with:")
            .with_initial_value(&domain)
            .with_help_message("edit to the new domain; siblings are handled by prefix mode")
            .prompt()
            .context("entry cancelled")?;
        let as_prefix = inquire::Confirm::new("Also rename sibling domains sharing this prefix?")
            .with_default(true)
            .prompt()
            .unwrap_or(false);
        (domain, replacement.trim().to_string(), as_prefix)
    } else {
        match (from, to, from_prefix, to_prefix) {
            (Some(f), Some(t), None, None) => (f.to_string(), t.to_string(), false),
            (None, None, Some(f), Some(t)) => (f.to_string(), t.to_string(), true),
            _ => anyhow::bail!(
                "pass --from/--to (one domain), --from-prefix/--to-prefix (a namespace), \
                 or --interactive"
            ),
        }
    };

    if rewrite_from == rewrite_to {
        anyhow::bail!("the replacement is identical to the original — nothing to do");
    }

    let rewrite = if is_prefix {
        DomainRewrite::Prefix {
            from: &rewrite_from,
            to: &rewrite_to,
        }
    } else {
        DomainRewrite::Exact {
            from: &rewrite_from,
            to: &rewrite_to,
        }
    };

    let mut changed = 0usize;
    let mut refusals = Vec::new();
    let mut report: Vec<serde_json::Value> = Vec::new();

    for file in &files {
        let text =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let Ok(profile) = parse_profile_auto_unsign(&file.to_string_lossy()) else {
            continue;
        };
        match rename_domains(&text, &profile, &rewrite) {
            Ok((new_text, applied)) => {
                changed += 1;
                if write {
                    std::fs::write(file, &new_text)
                        .with_context(|| format!("writing {}", file.display()))?;
                }
                report.push(serde_json::json!({
                    "file": file.display().to_string(),
                    "renamed": applied.iter().map(|(o, n)| serde_json::json!({"from": o, "to": n}))
                        .collect::<Vec<_>>(),
                }));
                if output_mode == OutputMode::Human {
                    println!("{} {}", "✓".green(), file.display());
                    for (old, new) in &applied {
                        println!("      {old}  →  {new}");
                    }
                }
            }
            // Nothing matching in this file is normal in a mixed directory.
            Err(crate::mcx::RenameRefusal::DomainNotPresent) => {}
            Err(e) => {
                refusals.push((file.clone(), e.to_string()));
                if output_mode == OutputMode::Human {
                    println!("{} {}: {e}", "✗".red(), file.display());
                }
            }
        }
    }

    if output_mode == OutputMode::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": refusals.is_empty(),
                "dry_run": !write,
                "files_scanned": files.len(),
                "files_changed": changed,
                "changes": report,
                "refusals": refusals.iter()
                    .map(|(f, e)| serde_json::json!({"file": f.display().to_string(), "reason": e}))
                    .collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!();
        if !write {
            println!(
                "{}",
                "Dry run — no files written (pass --write to apply)".yellow()
            );
        }
        println!("{changed} file(s) affected, {} refused", refusals.len());
    }

    if changed == 0 && refusals.is_empty() {
        anyhow::bail!("no file declared a matching domain — check the name against `mcx list`");
    }
    if !refusals.is_empty() {
        anyhow::bail!(
            "{} file(s) refused; nothing partial was written",
            refusals.len()
        );
    }
    Ok(())
}
