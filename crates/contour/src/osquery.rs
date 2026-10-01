//! Handlers for the `contour osquery` subcommand.
//!
//! Provides search, table detail, and statistics against the embedded
//! osquery schema (286 tables, 2,624 columns).

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

/// Which schema describes a table.
///
/// The two sources agree on 286 tables today and Fleet adds 91, but that is
/// a snapshot, not a guarantee: Fleet tracks osquery's main branch and can
/// lag it, and its own agent ships tables upstream will never have. So the
/// two are never merged into one list — a table carries where it came from,
/// and a reader can act on the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableSource {
    /// In both schemas — the ordinary case.
    Both,
    /// Upstream osquery only. Either Fleet has not synced yet, or it
    /// deliberately omits the table.
    OsqueryOnly,
    /// Fleet only: an agent extension (`ai_tools`, `cis_audit`,
    /// `app_sso_platform`, …). Plain `osqueryi` cannot answer it.
    FleetOnly,
}

impl TableSource {
    fn label(self) -> &'static str {
        match self {
            TableSource::Both => "",
            TableSource::OsqueryOnly => "osquery only — not in Fleet's schema",
            TableSource::FleetOnly => {
                "Fleet extension — requires Fleet's agent, not in upstream osquery"
            }
        }
    }
}

/// Every table either schema knows, with its provenance.
///
/// Computed once per process: it decodes both embedded datasets, and callers
/// reach it from per-row filters, where a fresh decode would take seconds.
fn table_sources() -> &'static BTreeMap<String, TableSource> {
    static SOURCES: std::sync::OnceLock<BTreeMap<String, TableSource>> = std::sync::OnceLock::new();
    SOURCES.get_or_init(compute_table_sources)
}

fn compute_table_sources() -> BTreeMap<String, TableSource> {
    let upstream: BTreeSet<String> = load_entries()
        .map(|v| v.into_iter().map(|e| e.table_name).collect())
        .unwrap_or_default();
    let fleet: BTreeSet<String> = osquery_schema::fleet::read(osquery_schema::embedded_fleet())
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.table_name)
        .collect();
    let mut out = BTreeMap::new();
    for t in upstream.union(&fleet) {
        let src = match (upstream.contains(t), fleet.contains(t)) {
            (true, true) => TableSource::Both,
            (true, false) => TableSource::OsqueryOnly,
            _ => TableSource::FleetOnly,
        };
        out.insert(t.clone(), src);
    }
    out
}

/// Fleet's schema for one table: the authoring facts upstream osquery has
/// no column for — worked examples, notes, a documentation link — and the
/// 91 tables it does not list at all. Empty on a dataset without the file.
fn fleet_for(table: &str) -> Vec<osquery_schema::fleet::FleetEntry> {
    osquery_schema::fleet::read(osquery_schema::embedded_fleet())
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.table_name == table)
        .collect()
}

/// Load all entries from the embedded Parquet data.
fn load_entries() -> Result<Vec<osquery_schema::OsqueryEntry>> {
    osquery_schema::osquery::read(osquery_schema::embedded())
}

// ── Search ───────────────────────────────────────────────────────────

/// Every column row of a Fleet-only table matching `q`.
///
/// `handle_search` also keeps a table-deduplicated view for the human
/// listing; the JSON array needs the column rows so its shape matches the
/// upstream entries beside them.
fn fleet_columns(q: &str) -> Vec<osquery_schema::fleet::FleetEntry> {
    let sources = table_sources();
    osquery_schema::fleet::read(osquery_schema::embedded_fleet())
        .unwrap_or_default()
        .into_iter()
        .filter(|e| {
            sources.get(&e.table_name) == Some(&TableSource::FleetOnly)
                && (e.table_name.to_lowercase().contains(q)
                    || e.column_name
                        .as_deref()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(q)
                    || e.table_description
                        .as_deref()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(q))
        })
        .collect()
}

fn handle_search(
    query: &str,
    platform: Option<&str>,
    json: bool,
    out: &mut impl Write,
) -> Result<()> {
    let entries = load_entries()?;
    let q = query.to_lowercase();
    let sources = table_sources();
    // Fleet-only tables are real and queryable under Fleet's agent, so a
    // search that hides them answers the wrong question. They are listed
    // after the upstream hits and labelled, never mixed in silently.
    let fleet_hits: BTreeMap<String, osquery_schema::fleet::FleetEntry> =
        osquery_schema::fleet::read(osquery_schema::embedded_fleet())
            .unwrap_or_default()
            .into_iter()
            .filter(|e| {
                sources.get(&e.table_name) == Some(&TableSource::FleetOnly)
                    && (e.table_name.to_lowercase().contains(&q)
                        || e.table_description
                            .as_deref()
                            .unwrap_or_default()
                            .to_lowercase()
                            .contains(&q))
            })
            .fold(BTreeMap::new(), |mut m, e| {
                m.entry(e.table_name.clone()).or_insert(e);
                m
            });

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
        // The contract is a flat, column-level array — agents index it
        // directly and `sop_traps_osquery` guards both properties. Wrapping
        // it in an object to make room for Fleet was a breaking change
        // dressed up as an addition.
        //
        // Provenance rides on each entry instead, as `source`. That is
        // strictly better than a sibling list: a caller that ignores the
        // field still gets every hit, and one that reads it can tell an
        // upstream table from one that needs Fleet's agent — without
        // knowing the envelope changed.
        let mut arr: Vec<serde_json::Value> = Vec::with_capacity(matches.len());
        for e in &matches {
            let mut v = serde_json::to_value(e)?;
            if let Some(o) = v.as_object_mut() {
                o.insert("source".into(), serde_json::json!("osquery"));
            }
            arr.push(v);
        }
        // Fleet-only rows are column-level too, so they keep the array
        // uniform: every entry has a table_name and a column_name.
        for e in fleet_columns(&q) {
            arr.push(serde_json::json!({
                "table_name": e.table_name,
                "table_description": e.table_description,
                "platforms": e.platforms,
                "evented": e.evented.unwrap_or(false),
                "column_name": e.column_name.clone().unwrap_or_default(),
                "column_description": e.column_description,
                "column_type": e.column_type.clone().unwrap_or_default(),
                "required": e.required.unwrap_or(false),
                "hidden": e.hidden.unwrap_or(false),
                "source": "fleet",
            }));
        }
        serde_json::to_writer_pretty(&mut *out, &arr)?;
        writeln!(out)?;
        return Ok(());
    }

    if matches.is_empty() && fleet_hits.is_empty() {
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

    if !fleet_hits.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "  {} {}",
            format!("{} Fleet-only table(s):", fleet_hits.len()).yellow(),
            "require Fleet's agent — not in upstream osquery".dimmed()
        )?;
        for e in fleet_hits.values() {
            writeln!(
                out,
                "    {:<28} {}",
                e.table_name,
                e.table_description
                    .as_deref()
                    .unwrap_or("")
                    .lines()
                    .next()
                    .unwrap_or("")
            )?;
        }
    }

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
        // Not upstream — but Fleet may still describe it, and saying so is
        // more useful than "not found" for a table that genuinely exists.
        let fleet = fleet_for(table_name);
        if !fleet.is_empty() {
            return handle_fleet_only_table(table_name, &fleet, json, out);
        }
        anyhow::bail!(
            "Table '{table_name}' not found: it is in neither the upstream osquery \
             schema nor Fleet's. \
             Try `contour osquery search {table_name}`."
        );
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
        let mut obj = obj;
        // Fleet's half: present only when the dataset carries it, so a
        // consumer can tell "no examples documented" from "no Fleet data".
        if let Some(f) = fleet_for(table_name).first()
            && let Some(o) = obj.as_object_mut()
        {
            o.insert(
                "fleet".into(),
                serde_json::json!({
                    "examples": f.examples,
                    "notes": f.notes,
                    "url": f.url,
                    "cacheable": f.cacheable,
                }),
            );
        }
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
    let fleet = fleet_for(table_name);
    if let Some(f) = fleet.first() {
        if let Some(u) = &f.url {
            writeln!(out, "  Docs:        {u}")?;
        }
        if let Some(n) = &f.notes {
            writeln!(out, "  Notes:       {}", n.lines().next().unwrap_or(n))?;
        }
        if let Some(ex) = &f.examples {
            writeln!(out)?;
            writeln!(out, "  {}", "Example:".cyan())?;
            for line in ex.lines() {
                writeln!(out, "    {line}")?;
            }
        }
    }
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

/// A table only Fleet describes. Rendered with the same shape as an
/// upstream table, and labelled: the query will not run under plain
/// `osqueryi`.
fn handle_fleet_only_table(
    table_name: &str,
    fleet: &[osquery_schema::fleet::FleetEntry],
    json: bool,
    out: &mut impl Write,
) -> Result<()> {
    let first = &fleet[0];
    if json {
        let obj = serde_json::json!({
            "table_name": table_name,
            "table_description": first.table_description,
            "platforms": first.platforms,
            "source": "fleet",
            "note": TableSource::FleetOnly.label(),
            "columns": fleet.iter().filter(|e| e.column_name.is_some()).map(|e| serde_json::json!({
                "column_name": e.column_name,
                "column_description": e.column_description,
                "column_type": e.column_type,
                "required": e.required,
            })).collect::<Vec<_>>(),
            "fleet": { "examples": first.examples, "notes": first.notes, "url": first.url },
        });
        serde_json::to_writer_pretty(&mut *out, &obj)?;
        writeln!(out)?;
        return Ok(());
    }

    writeln!(out, "{}", table_name.bold())?;
    writeln!(out, "  {}", TableSource::FleetOnly.label().yellow())?;
    if let Some(d) = &first.table_description {
        writeln!(out, "  Description: {d}")?;
    }
    if let Some(p) = &first.platforms {
        writeln!(out, "  Platforms:   {p}")?;
    }
    if let Some(u) = &first.url {
        writeln!(out, "  Docs:        {u}")?;
    }
    writeln!(out)?;
    writeln!(out, "  {:<30} {:<12} Description", "Column", "Type")?;
    writeln!(out, "  {}", "-".repeat(80))?;
    for e in fleet.iter().filter(|e| e.column_name.is_some()) {
        writeln!(
            out,
            "  {:<30} {:<12} {}",
            e.column_name.as_deref().unwrap_or(""),
            e.column_type.as_deref().unwrap_or(""),
            e.column_description.as_deref().unwrap_or("")
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
        let sources = table_sources();
        let only = |w: TableSource| -> Vec<&str> {
            sources
                .iter()
                .filter(|(_, s)| **s == w)
                .map(|(t, _)| t.as_str())
                .collect()
        };
        let obj = serde_json::json!({
            "total_tables": tables.len(),
            "total_columns": total_columns,
            "darwin_tables": darwin_tables.len(),
            "linux_tables": linux_tables.len(),
            "windows_tables": windows_tables.len(),
            // The two sources are never merged; this is the difference
            // between them, so a drift either way is a fact you can read
            // rather than something you discover from a failed query.
            "sources": {
                "osquery": tables.len(),
                "fleet": sources.values().filter(|s| **s != TableSource::OsqueryOnly).count(),
                "both": only(TableSource::Both).len(),
                "fleet_only": only(TableSource::FleetOnly),
                "osquery_only": only(TableSource::OsqueryOnly),
            },
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

    // Two sources, never merged. Fleet tracks osquery's main and can lag it;
    // its agent also ships tables upstream will never have. Both directions
    // are reported, because each means something different to a reader.
    let sources = table_sources();
    let count = |w: TableSource| sources.values().filter(|s| **s == w).count();
    let fleet_only = count(TableSource::FleetOnly);
    let osquery_only = count(TableSource::OsqueryOnly);
    if fleet_only + osquery_only > 0 {
        writeln!(out, "  {}", "Sources".bold())?;
        writeln!(out, "    in both:            {}", count(TableSource::Both))?;
        if fleet_only > 0 {
            writeln!(
                out,
                "    Fleet only:         {fleet_only}  {}",
                "(agent extensions — plain osqueryi cannot answer these)".dimmed()
            )?;
        }
        if osquery_only > 0 {
            writeln!(
                out,
                "    {} {osquery_only}  {}",
                "osquery only:      ".yellow(),
                "(Fleet has not synced these — its schema is behind)".dimmed()
            )?;
            for t in sources
                .iter()
                .filter(|(_, s)| **s == TableSource::OsqueryOnly)
                .take(8)
            {
                writeln!(out, "      {}", t.0)?;
            }
        }
        writeln!(out)?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `table_sources` decodes both embedded datasets. Callers reach it from
    /// per-row filters, so it must be computed once, not once per call.
    #[test]
    fn table_sources_is_computed_once() {
        assert!(std::ptr::eq(table_sources(), table_sources()));
        assert!(!table_sources().is_empty());
    }
}
