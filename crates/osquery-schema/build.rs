use std::path::Path;

fn main() {
    resolve_dataset(&DatasetSpec {
        archive: "osquery-schema",
        url_var: "CONTOUR_OSQUERY_SCHEMA_URL",
        files: LOCAL_SCHEMA_FILES,
        optional: &[],
    });
}

/// Parquet files this crate embeds, in the order the dataset release lists
/// them for this archive.
const LOCAL_SCHEMA_FILES: &[&str] = &[
    "osquery_schema.parquet",
    // Fleet's own schema, embedded by `include_bytes!` in lib.rs and asserted
    // non-empty by fleet.rs. Listed here because CONTOUR_SCHEMA_SRC copies
    // this list file by file and emits rerun-if-changed from it; a file
    // missing from the list would stay stale on a local build.
    "fleet_osquery_schema.parquet",
];

// Shared with every schema crate: the stamp, the pinned-archive download,
// CONTOUR_SCHEMA_SRC and the data repository. See the file.
include!("../../build-support/schema_data.rs");
