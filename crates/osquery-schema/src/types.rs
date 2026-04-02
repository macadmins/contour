use serde::{Deserialize, Serialize};

/// A single osquery table+column entry.
///
/// Each row represents one column within one table.
/// Group by `table_name` to reconstruct full table definitions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsqueryEntry {
    pub table_name: String,
    pub table_description: Option<String>,
    pub platforms: String,
    pub evented: bool,
    pub column_name: String,
    pub column_description: Option<String>,
    pub column_type: String,
    pub required: bool,
    pub hidden: bool,
}
