//! `contour app …` — clap surface and handlers.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;

use crate::{PARQUET_THRESHOLD, scan, write_parquet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// JSON, or Parquet when above the row threshold and --output is given.
    Auto,
    Json,
    Parquet,
}

#[derive(Debug, Subcommand)]
pub enum AppAction {
    #[command(
        about = "Read installed apps' code identities into a manifest other tools can consume",
        long_about = "Scans .app bundles and records, for each, what codesign and Info.plist say: \
                      bundle id, signing id, team id, signing state, every slice's CDHash and the \
                      designated requirement byte for byte. Nothing is reconstructed from a \
                      template — a synthesised requirement produces a declaration that reports \
                      Verified and manages nothing.\n\n\
                      One unreadable bundle is one entry in failed[]; the scan still succeeds.\n\n\
                      Output is JSON with both tables nested, or a Parquet pair \
                      (<stem>.identity.parquet, <stem>.builds.parquet) — automatically above \
                      2,000 apps when --output is given, or with --format parquet."
    )]
    Manifest {
        #[arg(help = "App bundles or directories to scan (default: /Applications)")]
        paths: Vec<String>,

        #[arg(
            short,
            long,
            help = "Output file (JSON) or stem (Parquet). Omit to print JSON"
        )]
        output: Option<String>,

        #[arg(long, value_enum, default_value_t = Format::Auto, help = "Output format")]
        format: Format,
    },
}

pub fn handle(action: AppAction, json: bool) -> Result<()> {
    match action {
        AppAction::Manifest {
            paths,
            output,
            format,
        } => handle_manifest(&paths, output.as_deref(), format, json),
    }
}

fn handle_manifest(
    paths: &[String],
    output: Option<&str>,
    format: Format,
    json: bool,
) -> Result<()> {
    let sources: Vec<PathBuf> = if paths.is_empty() {
        vec![PathBuf::from("/Applications")]
    } else {
        paths.iter().map(PathBuf::from).collect()
    };
    let m = scan(&sources, chrono::Utc::now().to_rfc3339())?;

    let format = match format {
        Format::Auto if m.apps.len() > PARQUET_THRESHOLD && output.is_some() => Format::Parquet,
        Format::Auto => Format::Json,
        f => f,
    };

    match (format, output) {
        (Format::Parquet, Some(stem)) => {
            let (a, b) = write_parquet(&m, Path::new(stem))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "identity": a.display().to_string(),
                        "builds": b.display().to_string(),
                        "counts": m.counts,
                        "failed": m.failed,
                    }))?
                );
            } else {
                summary(&m);
                println!("{} {}", "✓".green(), a.display());
                println!("{} {}", "✓".green(), b.display());
            }
        }
        (Format::Parquet, None) => {
            anyhow::bail!("--format parquet needs --output <stem>");
        }
        (_, Some(file)) => {
            let text = serde_json::to_string_pretty(&m)?;
            std::fs::write(file, &text).with_context(|| format!("writing {file}"))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "file": file, "counts": m.counts, "failed": m.failed
                    }))?
                );
            } else {
                summary(&m);
                println!("{} {}", "✓".green(), file);
            }
        }
        (_, None) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&m)?);
            } else {
                summary(&m);
                for a in &m.apps {
                    println!(
                        "  {:<40} {:<12} {:<12} {}",
                        a.bundle_id,
                        a.team_id.as_deref().unwrap_or("-"),
                        a.signing_state,
                        a.version.as_deref().unwrap_or("").dimmed()
                    );
                }
                println!(
                    "\n{}",
                    "Pass -o FILE to save the full manifest (requirements, CDHashes).".dimmed()
                );
            }
        }
    }
    Ok(())
}

fn summary(m: &crate::Manifest) {
    for f in &m.failed {
        println!("  {} skipping {}: {}", "!".yellow(), f.path, f.reason);
    }
    println!(
        "{} {} app(s), {} slice(s){}",
        "✓".green(),
        m.counts.apps,
        m.counts.slices,
        if m.counts.failed > 0 {
            format!(", {} skipped", m.counts.failed)
                .yellow()
                .to_string()
        } else {
            String::new()
        }
    );
}
