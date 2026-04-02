//! Handlers for the `contour osquery` subcommand.
//!
//! Provides search, table detail, and statistics against the embedded
//! osquery schema (283 tables, 2 581 columns).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

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
    }
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
