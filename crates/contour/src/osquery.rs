//! Handlers for the `contour osquery` subcommand.
//!
//! Provides search, table detail, and statistics against the embedded
//! osquery schema (283 tables, 2 581 columns).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;

/// Actions available under `contour osquery`.
#[derive(Debug, Subcommand)]
pub enum OsqueryAction {
    /// Search osquery tables and columns by keyword
    Search {
        /// Search term (matches table names, column names, descriptions)
        query: String,
        /// Filter by platform (darwin, linux, windows)
        #[arg(long)]
        platform: Option<String>,
    },
    /// Show full schema for a specific table
    Table {
        /// Table name (e.g., preferences, alf, disk_encryption)
        table_name: String,
    },
    /// Show embedded schema statistics
    Stats,
    /// Validate osquery SQL in Fleet GitOps YAML against the embedded schema (offline)
    Validate {
        /// GitOps repo, directory, or single YAML file
        path: PathBuf,
        /// Recurse into directories
        #[arg(short, long)]
        recursive: bool,
    },
    /// Emit osqueryi + orbit commands for generated queries (*.policies.yml / *.reports.yml)
    Verify {
        /// GitOps repo, directory, or single query file to verify
        path: PathBuf,
        /// Write the commands to this Markdown file (default: print to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

/// Dispatch an `OsqueryAction`.
pub fn handle(action: OsqueryAction, json: bool) -> Result<()> {
    let mut out = std::io::stdout();
    match action {
        OsqueryAction::Search { query, platform } => {
            handle_search(&query, platform.as_deref(), json, &mut out)
        }
        OsqueryAction::Table { table_name } => handle_table(&table_name, json, &mut out),
        OsqueryAction::Stats => handle_stats(json, &mut out),
        OsqueryAction::Validate { path, recursive } => {
            handle_validate(&path, recursive, json, &mut out)
        }
        OsqueryAction::Verify { path, output } => handle_verify(&path, output.as_deref(), &mut out),
    }
}

/// Render every generated query under `path` as a Markdown reference with both
/// the `osqueryi` (dev/CI) and `sudo orbit shell` (Fleet-managed host) command
/// per query (never executed). With `--output`, write the doc to a `.md` file;
/// otherwise print it.
fn handle_verify(path: &Path, output: Option<&Path>, out: &mut impl Write) -> Result<()> {
    use mscp::osquery::verify;

    let queries = verify::collect_queries(path)?;
    if queries.is_empty() {
        writeln!(
            out,
            "No *.policies.yml / *.reports.yml queries found under {}",
            path.display()
        )?;
        return Ok(());
    }

    match output {
        Some(file) => {
            verify::write_markdown(file, &queries)?;
            writeln!(
                out,
                "Wrote {} query commands (osqueryi + orbit forms) → {}",
                queries.len(),
                file.display()
            )?;
        }
        None => write!(out, "{}", verify::render_markdown(&queries))?,
    }
    Ok(())
}

/// Load all entries from the embedded Parquet data.
fn load_entries() -> Result<Vec<osquery_schema::OsqueryEntry>> {
    osquery_schema::osquery::read(osquery_schema::embedded())
}

// ── Search ───────────────────────────────────────────────────────────

fn handle_search(
    query: &str,
    platform: Option<&str>,
    json: bool,
    out: &mut impl Write,
) -> Result<()> {
    let entries = load_entries()?;
    let q = query.to_lowercase();

    let matches: Vec<_> = entries
        .iter()
        .filter(|e| {
            let hit = e.table_name.to_lowercase().contains(&q)
                || e.column_name.to_lowercase().contains(&q)
                || e.table_description
                    .as_deref()
                    .unwrap_or_default()
                    .to_lowercase()
                    .contains(&q)
                || e.column_description
                    .as_deref()
                    .unwrap_or_default()
                    .to_lowercase()
                    .contains(&q);
            if !hit {
                return false;
            }
            if let Some(p) = platform {
                e.platforms.contains(p)
            } else {
                true
            }
        })
        .collect();

    if json {
        serde_json::to_writer_pretty(&mut *out, &matches)?;
        writeln!(out)?;
        return Ok(());
    }

    if matches.is_empty() {
        writeln!(out, "No matches for '{query}'.")?;
        return Ok(());
    }

    // Group by table name (preserving insertion order via BTreeMap).
    let mut grouped: BTreeMap<&str, Vec<&osquery_schema::OsqueryEntry>> = BTreeMap::new();
    for entry in &matches {
        grouped.entry(&entry.table_name).or_default().push(entry);
    }

    for (table, cols) in &grouped {
        let first = cols[0];
        let desc = first.table_description.as_deref().unwrap_or("-");
        let platforms = &first.platforms;
        writeln!(out, "{} ({platforms})", table.bold())?;
        writeln!(out, "  {desc}")?;
        for col in cols {
            let cdesc = col.column_description.as_deref().unwrap_or("");
            writeln!(
                out,
                "  {:30} {:10} {cdesc}",
                col.column_name.green().to_string(),
                col.column_type
            )?;
        }
        writeln!(out)?;
    }

    writeln!(
        out,
        "{} matching columns across {} tables.",
        matches.len(),
        grouped.len()
    )?;

    Ok(())
}

// ── Table detail ─────────────────────────────────────────────────────

fn handle_table(table_name: &str, json: bool, out: &mut impl Write) -> Result<()> {
    let entries = load_entries()?;

    let table_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.table_name == table_name)
        .collect();

    if table_entries.is_empty() {
        anyhow::bail!("Table '{table_name}' not found in embedded osquery schema.");
    }

    if json {
        // Build a structured table object.
        let first = table_entries[0];
        let obj = serde_json::json!({
            "table_name": first.table_name,
            "table_description": first.table_description,
            "platforms": first.platforms,
            "evented": first.evented,
            "columns": table_entries.iter().map(|e| serde_json::json!({
                "column_name": e.column_name,
                "column_description": e.column_description,
                "column_type": e.column_type,
                "required": e.required,
                "hidden": e.hidden,
            })).collect::<Vec<_>>(),
        });
        serde_json::to_writer_pretty(&mut *out, &obj)?;
        writeln!(out)?;
        return Ok(());
    }

    let first = table_entries[0];
    let desc = first.table_description.as_deref().unwrap_or("-");
    writeln!(out, "{}", first.table_name.bold())?;
    writeln!(out, "  Description: {desc}")?;
    writeln!(out, "  Platforms:   {}", first.platforms)?;
    writeln!(out, "  Evented:     {}", first.evented)?;
    writeln!(out)?;
    writeln!(
        out,
        "  {:<30} {:<10} {:<8} {:<6} Description",
        "Column", "Type", "Required", "Hidden"
    )?;
    writeln!(out, "  {}", "-".repeat(90))?;

    for col in &table_entries {
        let cdesc = col.column_description.as_deref().unwrap_or("");
        writeln!(
            out,
            "  {:<30} {:<10} {:<8} {:<6} {cdesc}",
            col.column_name, col.column_type, col.required, col.hidden,
        )?;
    }

    Ok(())
}

// ── Stats ────────────────────────────────────────────────────────────

fn handle_stats(json: bool, out: &mut impl Write) -> Result<()> {
    let entries = load_entries()?;

    let mut tables: BTreeSet<&str> = BTreeSet::new();
    let mut darwin_tables: BTreeSet<&str> = BTreeSet::new();
    let mut linux_tables: BTreeSet<&str> = BTreeSet::new();
    let mut windows_tables: BTreeSet<&str> = BTreeSet::new();

    for e in &entries {
        tables.insert(&e.table_name);
        if e.platforms.contains("darwin") {
            darwin_tables.insert(&e.table_name);
        }
        if e.platforms.contains("linux") {
            linux_tables.insert(&e.table_name);
        }
        if e.platforms.contains("windows") {
            windows_tables.insert(&e.table_name);
        }
    }

    let total_columns = entries.len();

    if json {
        let obj = serde_json::json!({
            "total_tables": tables.len(),
            "total_columns": total_columns,
            "darwin_tables": darwin_tables.len(),
            "linux_tables": linux_tables.len(),
            "windows_tables": windows_tables.len(),
        });
        serde_json::to_writer_pretty(&mut *out, &obj)?;
        writeln!(out)?;
        return Ok(());
    }

    writeln!(out, "{}", "osquery embedded schema statistics".bold())?;
    writeln!(out)?;
    writeln!(out, "  Total tables:    {}", tables.len())?;
    writeln!(out, "  Total columns:   {total_columns}")?;
    writeln!(out)?;
    writeln!(out, "  darwin tables:   {}", darwin_tables.len())?;
    writeln!(out, "  linux tables:    {}", linux_tables.len())?;
    writeln!(out, "  windows tables:  {}", windows_tables.len())?;

    Ok(())
}

/// Handle `osquery validate` — static, offline table-level checking of every
/// query found in Fleet GitOps YAML under `path`.
///
/// Tier 1 by design: a typo'd table is the failure that hides, because the
/// query returns no rows and a Fleet policy reads no rows as compliant.
fn handle_validate(path: &Path, recursive: bool, json: bool, out: &mut impl Write) -> Result<()> {
    use contour_core::osquery_validate::{extract_fleet_queries, validate_query};

    let known: std::collections::BTreeSet<String> = load_entries()?
        .iter()
        .map(|e| e.table_name.to_lowercase())
        .collect();

    let files = collect_yaml_files(path, recursive)?;
    if files.is_empty() {
        anyhow::bail!("no .yml/.yaml files found under {}", path.display());
    }

    let mut findings: Vec<serde_json::Value> = Vec::new();
    let mut checked = 0usize;

    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for query in extract_fleet_queries(&text) {
            checked += 1;
            let Some(finding) = validate_query(&query, &known) else {
                continue;
            };
            for unknown in &finding.unknown_tables {
                findings.push(serde_json::json!({
                    "file": file.display().to_string(),
                    "kind": finding.kind,
                    "index": finding.index,
                    "name": finding.name,
                    "unknown_table": unknown.name,
                    "suggestions": unknown.suggestions,
                }));
            }
        }
    }

    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": findings.is_empty(),
                "files_scanned": files.len(),
                "queries_checked": checked,
                "findings": findings,
            }))?
        )?;
    } else if findings.is_empty() {
        writeln!(
            out,
            "{} {checked} query(s) across {} file(s): every table exists in the embedded schema",
            "\u{2713}".green(),
            files.len()
        )?;
    } else {
        for f in &findings {
            let name = f["name"].as_str().unwrap_or("(unnamed)");
            writeln!(
                out,
                "{} {}:{}[{}] {name}",
                "\u{2717}".red(),
                f["file"].as_str().unwrap_or_default(),
                f["kind"].as_str().unwrap_or_default(),
                f["index"]
            )?;
            let suggestions = f["suggestions"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let hint = if suggestions.is_empty() {
                String::new()
            } else {
                format!(" \u{2014} did you mean: {suggestions}?")
            };
            writeln!(
                out,
                "    unknown table '{}'{hint}",
                f["unknown_table"].as_str().unwrap_or_default()
            )?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "{} unknown table reference(s) in {checked} query(s)",
            findings.len()
        )?;
    }

    if !findings.is_empty() {
        anyhow::bail!("{} query(s) reference unknown tables", findings.len());
    }
    Ok(())
}

/// Collect `.yml` / `.yaml` files from a path.
fn collect_yaml_files(path: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        let walker = if recursive {
            walkdir::WalkDir::new(path)
        } else {
            walkdir::WalkDir::new(path).max_depth(1)
        };
        for entry in walker.into_iter().filter_map(std::result::Result::ok) {
            let p = entry.path();
            if p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == "yml" || e == "yaml")
            {
                files.push(p.to_path_buf());
            }
        }
    } else {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    files.sort();
    Ok(files)
}
