//! `fleet_osquery_schema.parquet` — Fleet's osquery schema.
//!
//! The same tables as [`crate::osquery`] plus what an author actually wants:
//! worked `examples`, `notes`, a documentation `url`, per-column platforms
//! and notes — and 91 tables upstream osquery does not list.
//!
//! A separate reader rather than more columns on [`crate::OsqueryEntry`]:
//! the upstream table is the authority on what osquery ships, this one is
//! the authority on how to use it, and a consumer should be able to say
//! which it read.

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use serde::{Deserialize, Serialize};

/// One (table, column) row of Fleet's schema.
///
/// Field types follow the Parquet schema exactly — the booleans are
/// `bool`, not strings. Optional throughout: Fleet leaves a column null
/// rather than guessing, and so does this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetEntry {
    pub table_name: String,
    pub table_description: Option<String>,
    pub platforms: Option<String>,
    pub evented: Option<bool>,
    pub cacheable: Option<bool>,
    pub table_hidden: Option<bool>,
    /// Worked SQL, as Fleet documents it.
    pub examples: Option<String>,
    pub notes: Option<String>,
    /// Documentation link.
    pub url: Option<String>,
    pub fleet_repo_url: Option<String>,
    pub osquery_repo_url: Option<String>,
    pub column_name: Option<String>,
    pub column_description: Option<String>,
    pub column_type: Option<String>,
    pub required: Option<bool>,
    pub hidden: Option<bool>,
    /// Platforms this *column* exists on, where they differ from the table's.
    pub column_platforms: Option<String>,
    pub column_notes: Option<String>,
    pub column_index: Option<bool>,
}

/// Read the table. Empty bytes read as an empty table. The build does not
/// write a placeholder for this file (a dataset without it fails to build);
/// the tolerance is for callers handing in bytes from elsewhere.
pub fn read(bytes: &[u8]) -> Result<Vec<FleetEntry>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))?
        .build()
        .context("building fleet_osquery_schema Parquet reader")?;

    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let text = |n: &str, row: usize| -> Option<String> {
            let a = batch.column_by_name(n)?.as_string::<i32>();
            (!a.is_null(row)).then(|| a.value(row).to_string())
        };
        let flag = |n: &str, row: usize| -> Option<bool> {
            let a = batch.column_by_name(n)?.as_boolean();
            (!a.is_null(row)).then(|| a.value(row))
        };
        for row in 0..batch.num_rows() {
            let Some(table_name) = text("table_name", row) else {
                continue;
            };
            out.push(FleetEntry {
                table_name,
                table_description: text("table_description", row),
                platforms: text("platforms", row),
                evented: flag("evented", row),
                cacheable: flag("cacheable", row),
                table_hidden: flag("table_hidden", row),
                examples: text("examples", row),
                notes: text("notes", row),
                url: text("url", row),
                fleet_repo_url: text("fleet_repo_url", row),
                osquery_repo_url: text("osquery_repo_url", row),
                column_name: text("column_name", row),
                column_description: text("column_description", row),
                column_type: text("column_type", row),
                required: flag("required", row),
                hidden: flag("hidden", row),
                column_platforms: text("column_platforms", row),
                column_notes: text("column_notes", row),
                column_index: flag("column_index", row),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_read_as_no_rows() {
        assert!(read(&[]).unwrap().is_empty());
    }

    /// Fleet lists tables upstream osquery does not, and carries the
    /// authoring facts upstream has no column for.
    #[test]
    fn fleet_adds_tables_and_authoring_detail() {
        let fleet = read(crate::embedded_fleet()).expect("read fleet schema");
        assert!(
            !fleet.is_empty(),
            "fleet_osquery_schema has no rows — the dataset did not carry it; do not skip"
        );
        let upstream: std::collections::BTreeSet<String> = crate::osquery::read(crate::embedded())
            .expect("read upstream")
            .into_iter()
            .map(|e| e.table_name)
            .collect();
        let theirs: std::collections::BTreeSet<&str> =
            fleet.iter().map(|e| e.table_name.as_str()).collect();
        let extra = theirs.len() - theirs.iter().filter(|t| upstream.contains(**t)).count();
        assert!(
            extra > 50,
            "expected dozens of Fleet-only tables, saw {extra}"
        );
        assert!(
            fleet.iter().any(|e| e.examples.is_some()),
            "Fleet's value is the worked examples"
        );
        assert!(fleet.iter().any(|e| e.url.is_some()));
    }
}
