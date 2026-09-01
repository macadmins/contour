//! `profile ddm reidentify` — rewrite declaration Identifiers in place.
//!
//! Two shapes: replace one exact Identifier, or rewrite a prefix across a
//! whole directory so every declaration reads `com.acme.*`. Either way the
//! rewrite is bundle-aware — an activation's `StandardConfigurations` (and
//! any other reference to a renamed Identifier) follows the rename, so the
//! bundle never dangles.

use anyhow::Result;
use colored::Colorize;
use std::path::PathBuf;

use crate::ddm::rename::{IdentifierRewrite, set_ddm_identifier};
use crate::output::OutputMode;

/// Collect `.json` declaration files from the given paths.
fn collect_json(paths: &[String], recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in paths {
        let p = std::path::Path::new(path);
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
                if ep.is_file() && ep.extension().is_some_and(|e| e == "json") {
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

/// Handle `profile ddm reidentify`.
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_ddm_reidentify(
    paths: &[String],
    from: Option<&str>,
    to: Option<&str>,
    from_prefix: Option<&str>,
    to_prefix: Option<&str>,
    recursive: bool,
    write: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let rewrite = match (from, to, from_prefix, to_prefix) {
        (Some(from), Some(to), None, None) => IdentifierRewrite::Exact { from, to },
        (None, None, Some(from), Some(to)) => IdentifierRewrite::Prefix { from, to },
        _ => anyhow::bail!(
            "pass either --from/--to (exact Identifier) or --from-prefix/--to-prefix (batch)"
        ),
    };

    let files = collect_json(paths, recursive)?;
    if files.is_empty() {
        anyhow::bail!("no .json declaration files found");
    }

    // Dry run unless --write; in-place means no suffix and no output dir.
    let result = set_ddm_identifier(&files, &rewrite, None, "", !write);

    let renamed: Vec<_> = result
        .files
        .iter()
        .filter(|f| f.identifier.is_some() || f.reference_updates > 0)
        .collect();

    if output_mode == OutputMode::Json {
        let items: Vec<serde_json::Value> = renamed
            .iter()
            .map(|f| {
                serde_json::json!({
                    "file": f.input.display().to_string(),
                    "identifier": f.identifier.as_ref().map(|(old, new)| {
                        serde_json::json!({"from": old, "to": new})
                    }),
                    "reference_updates": f.reference_updates,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "success": result.failures.is_empty(),
                "dry_run": !write,
                "matched": result.matched(),
                "files": items,
                "failures": result.failures.iter()
                    .map(|(p, e)| serde_json::json!({"file": p.display().to_string(), "error": e}))
                    .collect::<Vec<_>>(),
            })
        );
    } else {
        if !write {
            println!("{}", "Dry run — no files written (pass --write)".yellow());
        }
        for f in &renamed {
            if let Some((old, new)) = &f.identifier {
                println!("{} {}", "✓".green(), f.input.display());
                println!("    {old}  →  {new}");
            }
            if f.reference_updates > 0 {
                println!(
                    "    {} {} cross-reference(s) updated",
                    "↳".cyan(),
                    f.reference_updates
                );
            }
        }
        for (path, err) in &result.failures {
            println!("{} {}: {err}", "✗".red(), path.display());
        }
        println!();
        println!(
            "{} declaration(s) renamed across {} file(s)",
            result.matched(),
            files.len()
        );
    }

    // A rewrite that matched nothing is an operator error — the pattern was
    // wrong. Failing loudly beats reporting a successful no-op.
    if result.matched() == 0 {
        anyhow::bail!(
            "no declaration matched the rewrite — check --from/--from-prefix against the \
             Identifiers actually present"
        );
    }
    if !result.failures.is_empty() {
        anyhow::bail!("{} file(s) failed", result.failures.len());
    }
    Ok(())
}
