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
