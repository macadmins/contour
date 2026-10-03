//! Embedded osquery table/column schema from osquery 5.22.1.
//!
//! 286 tables, 2,624 columns across darwin, linux, and windows.

pub mod fleet;
pub mod osquery;
pub mod types;

pub use types::*;

/// Embedded osquery schema Parquet data.
pub fn embedded() -> &'static [u8] {
    include_bytes!("../data/osquery_schema.parquet")
}

/// Fleet's osquery schema: the same tables plus what an author actually
/// wants — worked `examples`, `notes`, a documentation `url`, per-column
/// platforms — and tables upstream osquery does not list. Required by the
/// build: a dataset without it does not compile.
pub fn embedded_fleet() -> &'static [u8] {
    include_bytes!("../data/fleet_osquery_schema.parquet")
}

// ── Shared, decoded once per process ────────────────────────────────
//
// Decoding a parquet takes seconds; every CLI and MCP handler reaches these
// from per-row filters, so each dataset is decoded once and shared.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

pub use contour_core::osquery_validate::{SchemaIndex, TableInfo};

/// Every upstream row.
pub fn osquery_entries() -> &'static [OsqueryEntry] {
    static CACHE: OnceLock<Vec<OsqueryEntry>> = OnceLock::new();
    CACHE.get_or_init(|| osquery::read(embedded()).unwrap_or_default())
}

/// Every Fleet row.
pub fn fleet_entries() -> &'static [fleet::FleetEntry] {
    static CACHE: OnceLock<Vec<fleet::FleetEntry>> = OnceLock::new();
    CACHE.get_or_init(|| fleet::read(embedded_fleet()).unwrap_or_default())
}

/// Which schema describes a table.
///
/// The two sources agree on the upstream tables and Fleet adds its own, but
/// that is a snapshot, not a guarantee: Fleet tracks osquery's main branch and
/// can lag it, and its agent ships tables upstream will never have. So the two
/// are never merged into one list — a table carries where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableSource {
    /// In both schemas — the ordinary case.
    Both,
    /// Upstream osquery only. Either Fleet has not synced yet, or it
    /// deliberately omits the table.
    OsqueryOnly,
    /// Fleet only: an agent extension (`ai_tools`, `cis_audit`,
    /// `app_sso_platform`, …). Plain `osqueryd` cannot answer it.
    FleetOnly,
}

impl TableSource {
    /// Stable machine tag.
    pub fn as_str(self) -> &'static str {
        match self {
            TableSource::Both => "both",
            TableSource::OsqueryOnly => "osquery",
            TableSource::FleetOnly => "fleet",
        }
    }

    /// One-line caveat, or `None` when the table is in both schemas.
    pub fn note(self) -> Option<&'static str> {
        match self {
            TableSource::Both => None,
            TableSource::OsqueryOnly => Some("osquery only — not in Fleet's schema"),
            TableSource::FleetOnly => {
                Some("Fleet extension — requires Fleet's agent, not in upstream osquery")
            }
        }
    }
}

/// Every table either schema knows, with its provenance.
pub fn table_sources() -> &'static BTreeMap<String, TableSource> {
    static CACHE: OnceLock<BTreeMap<String, TableSource>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let upstream: BTreeSet<&str> = osquery_entries().iter().map(|e| e.table_name.as_str()).collect();
        let fleet: BTreeSet<&str> = fleet_entries().iter().map(|e| e.table_name.as_str()).collect();
        upstream
            .union(&fleet)
            .map(|t| {
                let src = match (upstream.contains(t), fleet.contains(t)) {
                    (true, true) => TableSource::Both,
                    (true, false) => TableSource::OsqueryOnly,
                    _ => TableSource::FleetOnly,
                };
                ((*t).to_string(), src)
            })
            .collect()
    })
}

/// Fleet's rows for one table: table-level facts on every row, column facts
/// where `column_name` is set.
pub fn fleet_for(table: &str) -> impl Iterator<Item = &'static fleet::FleetEntry> {
    fleet_entries().iter().filter(move |e| e.table_name == table)
}

/// Both schemas folded into one index for
/// [`contour_core::osquery_validate::check_query`].
pub fn index() -> &'static SchemaIndex {
    static CACHE: OnceLock<SchemaIndex> = OnceLock::new();
    CACHE.get_or_init(|| {
        use contour_core::osquery_validate::normalise_platforms;
        let mut idx = SchemaIndex::new();
        for e in osquery_entries() {
            let t = idx.entry(e.table_name.to_lowercase()).or_default();
            t.in_osquery = true;
            t.platforms.extend(normalise_platforms(&e.platforms));
            t.columns.insert(e.column_name.to_lowercase());
            if e.required {
                t.required.insert(e.column_name.to_lowercase());
            }
        }
        for e in fleet_entries() {
            let t = idx.entry(e.table_name.to_lowercase()).or_default();
            t.in_fleet = true;
            // Upstream is the authority on platforms where it lists the table.
            if !t.in_osquery && let Some(p) = &e.platforms {
                t.platforms.extend(normalise_platforms(p));
            }
            if let Some(c) = &e.column_name {
                t.columns.insert(c.to_lowercase());
                if !t.in_osquery && e.required == Some(true) {
                    t.required.insert(c.to_lowercase());
                }
            }
        }
        idx
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_embedded() {
        let entries = osquery::read(embedded()).expect("Failed to read embedded osquery schema");
        assert!(
            entries.len() >= 2000,
            "Expected 2000+ entries, got {}",
            entries.len()
        );
    }

    #[test]
    fn test_tables_have_platforms() {
        let entries = osquery::read(embedded()).expect("Failed to read embedded osquery schema");

        let has_darwin = entries.iter().any(|e| e.platforms.contains("darwin"));
        let has_linux = entries.iter().any(|e| e.platforms.contains("linux"));
        let has_windows = entries.iter().any(|e| e.platforms.contains("windows"));

        assert!(has_darwin, "Expected at least one darwin table");
        assert!(has_linux, "Expected at least one linux table");
        assert!(has_windows, "Expected at least one windows table");
    }

    /// The caches decode both embedded datasets. Callers reach them from
    /// per-row filters, so each must be computed once, not once per call.
    #[test]
    fn caches_are_computed_once() {
        assert!(std::ptr::eq(table_sources(), table_sources()));
        assert!(std::ptr::eq(index(), index()));
        assert!(!table_sources().is_empty());
    }

    /// The index is what every generate-time check reads; its shape must hold.
    #[test]
    fn index_folds_both_schemas_and_keeps_required_columns() {
        let idx = index();
        assert!(idx.len() > 300, "expected upstream + Fleet-only tables, got {}", idx.len());
        let plist = &idx["plist"];
        assert!(plist.in_osquery && plist.in_fleet);
        assert_eq!(plist.required, ["path".to_string()].into_iter().collect());
        assert!(plist.platforms.contains("darwin"));
        let fleet_only = idx.values().filter(|t| t.in_fleet && !t.in_osquery).count();
        assert!(fleet_only > 50, "expected dozens of Fleet-only tables, got {fleet_only}");
        // Extension tables stay off the index until a dataset carries them;
        // when one does, drop it from EXTENSION_TABLES.
        for t in contour_core::osquery_validate::EXTENSION_TABLES {
            assert!(!idx.contains_key(*t), "`{t}` is now in the dataset — remove it from EXTENSION_TABLES");
        }
    }

    #[test]
    fn test_preferences_table_exists() {
        let entries = osquery::read(embedded()).expect("Failed to read embedded osquery schema");

        let preferences: Vec<_> = entries
            .iter()
            .filter(|e| e.table_name == "preferences")
            .collect();

        assert!(
            !preferences.is_empty(),
            "Expected to find 'preferences' table"
        );
        assert!(
            preferences.iter().any(|e| e.column_name == "domain"),
            "Expected 'preferences' table to have a 'domain' column"
        );
    }
}
