//! Handlers for the `contour osquery` subcommand.
//!
//! Provides search, table detail, statistics and validation against the
//! embedded schemas: 286 upstream osquery tables plus 91 Fleet-only agent
//! tables (377), with Fleet's examples and notes where it has them.

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
        OsqueryAction::Verify { path, output } => {
            handle_verify(&path, output.as_deref(), json, &mut out)
        }
    }
}

/// Render every generated query under `path` as a Markdown reference with both
/// the `osqueryi` (dev/CI) and `sudo orbit shell` (Fleet-managed host) command
/// per query (never executed). With `--output`, write the doc to a `.md` file;
/// otherwise print it. With `--json`, emit the same commands as an object.
fn handle_verify(path: &Path, output: Option<&Path>, json: bool, out: &mut impl Write) -> Result<()> {
    use mscp::osquery::verify;

    let queries = verify::collect_queries(path)?;
    if json {
        let osq = verify::osqueryi_or_conventional();
        let orbit = verify::orbit_or_conventional();
        let items: Vec<serde_json::Value> = queries
            .iter()
            .map(|q| {
                serde_json::json!({
                    "name": q.name,
                    "source": q.source,
                    "query": q.query,
                    "osqueryi_cmd": osq.suggest(&q.query),
                    "orbit_cmd": orbit.suggest(&q.query),
                })
            })
            .collect();
        let mut obj = serde_json::json!({
            "count": items.len(),
            "osqueryi": osq.label(),
            "orbit": orbit.label(),
            "queries": items,
        });
        if let Some(file) = output {
            verify::write_markdown(file, &queries)?;
            obj["wrote"] = serde_json::json!(file.display().to_string());
        }
        writeln!(out, "{}", serde_json::to_string_pretty(&obj)?)?;
        return Ok(());
    }
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

use osquery_schema::{TableSource, fleet_for, osquery_entries, table_sources};

// ── Search ───────────────────────────────────────────────────────────

/// Every column row of a Fleet-only table matching `q`, on `platform` when
/// one is given — the same filter the upstream rows get.
///
/// `handle_search` dedupes this by table for the human listing; the JSON
/// array needs the column rows so its shape matches the upstream entries.
fn fleet_columns(q: &str, platform: Option<&str>) -> Vec<&'static osquery_schema::fleet::FleetEntry> {
    let sources = table_sources();
    osquery_schema::fleet_entries()
        .iter()
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
                && platform.is_none_or(|p| e.platforms.as_deref().is_some_and(|s| s.contains(p)))
        })
        .collect()
}

fn handle_search(
    query: &str,
    platform: Option<&str>,
    json: bool,
    out: &mut impl Write,
) -> Result<()> {
    let entries = osquery_entries();
    let q = query.to_lowercase();
    // Fleet-only tables are real and queryable under Fleet's agent, so a
    // search that hides them answers the wrong question. They are listed
    // after the upstream hits and labelled, never mixed in silently.
    let fleet_rows = fleet_columns(&q, platform);
    let fleet_hits: BTreeMap<&str, &osquery_schema::fleet::FleetEntry> =
        fleet_rows.iter().fold(BTreeMap::new(), |mut m, e| {
            m.entry(e.table_name.as_str()).or_insert(*e);
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
        for e in &fleet_rows {
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
    let entries = osquery_entries();

    let table_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.table_name == table_name)
        .collect();

    if table_entries.is_empty() {
        // Not upstream — but Fleet may still describe it, and saying so is
        // more useful than "not found" for a table that genuinely exists.
        let fleet: Vec<_> = fleet_for(table_name).cloned().collect();
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
        if let Some(f) = fleet_for(table_name).next()
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
    if let Some(f) = fleet_for(table_name).next() {
        write_fleet_facts(f, out)?;
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

/// Fleet's authoring facts for a table: docs link, the full notes, the
/// worked example.
fn write_fleet_facts(f: &osquery_schema::fleet::FleetEntry, out: &mut impl Write) -> Result<()> {
    if let Some(u) = &f.url {
        writeln!(out, "  Docs:        {u}")?;
    }
    if let Some(n) = &f.notes {
        let mut lines = n.lines();
        if let Some(first) = lines.next() {
            writeln!(out, "  Notes:       {first}")?;
        }
        for line in lines {
            writeln!(out, "               {line}")?;
        }
    }
    if let Some(ex) = &f.examples {
        writeln!(out)?;
        writeln!(out, "  {}", "Example:".cyan())?;
        for line in ex.lines() {
            writeln!(out, "    {line}")?;
        }
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
            "note": TableSource::FleetOnly.note(),
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
    writeln!(out, "  {}", TableSource::FleetOnly.note().unwrap_or_default().yellow())?;
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
    let entries = osquery_entries();

    let mut tables: BTreeSet<&str> = BTreeSet::new();
    let mut darwin_tables: BTreeSet<&str> = BTreeSet::new();
    let mut linux_tables: BTreeSet<&str> = BTreeSet::new();
    let mut windows_tables: BTreeSet<&str> = BTreeSet::new();

    for e in entries {
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
    use contour_core::osquery_validate::{Severity, check_query, extract_fleet_queries};

    // Both schemas: a Fleet-only table is real under Fleet's agent, so it is
    // not "unknown" — but plain osqueryd cannot answer it, so it is a warning.
    let index = osquery_schema::index();

    let files = collect_yaml_files(path, recursive)?;
    if files.is_empty() {
        anyhow::bail!("no .yml/.yaml files found under {}", path.display());
    }

    let mut findings: Vec<serde_json::Value> = Vec::new();
    let mut warnings: Vec<serde_json::Value> = Vec::new();
    let mut unreadable: Vec<serde_json::Value> = Vec::new();
    let mut checked = 0usize;

    for file in &files {
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(e) => {
                unreadable.push(serde_json::json!({
                    "file": file.display().to_string(),
                    "error": e.to_string(),
                }));
                continue;
            }
        };
        for query in extract_fleet_queries(&text) {
            checked += 1;
            let platform = query.platform.as_deref().unwrap_or("");
            for problem in check_query(&query.sql, platform, index) {
                let entry = serde_json::json!({
                    "file": file.display().to_string(),
                    "kind": query.kind,
                    "index": query.index,
                    "name": query.name,
                    "problem": problem.to_string(),
                });
                match problem.severity() {
                    Severity::Error => findings.push(entry),
                    Severity::Warning => warnings.push(entry),
                }
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
                "warnings": warnings,
                "unreadable": unreadable,
            }))?
        )?;
    } else {
        let locate = |v: &serde_json::Value| {
            format!(
                "{}:{}[{}] {}",
                v["file"].as_str().unwrap_or_default(),
                v["kind"].as_str().unwrap_or_default(),
                v["index"],
                v["name"].as_str().unwrap_or("(unnamed)")
            )
        };
        for u in &unreadable {
            writeln!(
                out,
                "{} {}: {}",
                "\u{26a0}".yellow(),
                u["file"].as_str().unwrap_or_default(),
                u["error"].as_str().unwrap_or_default()
            )?;
        }
        for w in &warnings {
            writeln!(
                out,
                "{} {} — {}",
                "\u{26a0}".yellow(),
                locate(w),
                w["problem"].as_str().unwrap_or_default()
            )?;
        }
        for f in &findings {
            writeln!(out, "{} {}", "\u{2717}".red(), locate(f))?;
            writeln!(out, "    {}", f["problem"].as_str().unwrap_or_default())?;
        }
        if findings.is_empty() {
            writeln!(
                out,
                "{} {checked} query(s) across {} file(s): every table, column and platform checks out against the embedded osquery and Fleet schemas",
                "\u{2713}".green(),
                files.len()
            )?;
        } else {
            writeln!(out)?;
            writeln!(
                out,
                "{} problem(s) in {checked} query(s)",
                findings.len()
            )?;
        }
    }

    if !findings.is_empty() {
        anyhow::bail!("{} query(s) fail the osquery schema check", findings.len());
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
    use contour_core::osquery_validate::{EXTENSION_TABLES, Severity, check_query, extract_tables};
    use contour_core::trainer::queries as q;

    /// Every SQL string the trainer prints must name real tables and columns.
    /// Queries over an extension table are skipped, and the test holds that
    /// such a table is still absent from the index — when a dataset carries
    /// it, the allowlist entry comes off and the query gets checked.
    #[test]
    fn trainer_queries_pass_the_schema_check() {
        let index = osquery_schema::index();
        let all: &[(&str, &str)] = &[
            ("santa::DISCOVER_APPS", q::santa::DISCOVER_APPS),
            ("santa::APP_COVERAGE", q::santa::APP_COVERAGE),
            ("santa::APPS_BY_TEAMID", q::santa::APPS_BY_TEAMID),
            ("santa::SANTA_RULES", q::santa::SANTA_RULES),
            ("pppc::DISCOVER_APPS", q::pppc::DISCOVER_APPS),
            ("pppc::APP_SIGNATURES", q::pppc::APP_SIGNATURES),
            ("mscp::SECURITY_SETTINGS", q::mscp::SECURITY_SETTINGS),
            ("mscp::FILEVAULT_STATUS", q::mscp::FILEVAULT_STATUS),
            ("mscp::GATEKEEPER_STATUS", q::mscp::GATEKEEPER_STATUS),
            ("mscp::SIP_STATUS", q::mscp::SIP_STATUS),
            ("fleet::PROFILE_STATUS", q::fleet::PROFILE_STATUS),
            ("fleet::PROFILE_ISSUES", q::fleet::PROFILE_ISSUES),
        ];
        for (name, sql) in all {
            let tables = extract_tables(sql);
            if tables.iter().any(|t| EXTENSION_TABLES.contains(&t.as_str())) {
                for t in &tables {
                    assert!(!index.contains_key(t), "`{t}` is now in the dataset — remove it from EXTENSION_TABLES");
                }
                continue;
            }
            let errors: Vec<String> = check_query(sql, "darwin", index)
                .into_iter()
                .filter(|p| p.severity() == Severity::Error)
                .map(|p| p.to_string())
                .collect();
            assert!(errors.is_empty(), "{name}: {errors:?}");
        }
    }

}
