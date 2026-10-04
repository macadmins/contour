use std::path::Path;

fn main() {
    resolve_dataset(&DatasetSpec {
        archive: "mdm-schema",
        url_var: "CONTOUR_MDM_SCHEMA_URL",
        files: LOCAL_SCHEMA_FILES,
        optional: OPTIONAL_FILES,
    });
    // Whatever the dataset carries, a table it predates becomes a
    // zero-length placeholder; see the function.
    ensure_optional_placeholders(Path::new("data"));
}

/// Parquet files this crate embeds, in the order the dataset release lists
/// them for this archive.
const LOCAL_SCHEMA_FILES: &[&str] = &[
    "capabilities.parquet",
    "skip_keys.parquet",
    "examples.parquet",
    "app_schema_keys.parquet",
    "app_schema_rules.parquet",
    "windows_capabilities.parquet",
    "source_versions.parquet",
    // The other half of DDM: what a device reports back, and Apple's
    // documented error codes.
    "status_items.parquet",
    "mdm_errors.parquet",
    // Generated from the same rows as source_versions.parquet.
    "schema-versions.toml",
];

/// Tables added after a dataset was published get a zero-length placeholder
/// so `include_bytes!` resolves and the reader sees an empty table. Only
/// for files whose readers are documented to accept empty input.
const OPTIONAL_FILES: &[&str] = &[
    "source_versions.parquet",
    "status_items.parquet",
    "mdm_errors.parquet",
];

fn ensure_optional_placeholders(data_dir: &Path) {
    for f in OPTIONAL_FILES {
        let p = data_dir.join(f);
        if !p.exists() {
            println!(
                "cargo:warning=mdm-schema: {} not in this dataset — source.upstream_ref will be null until the schema is republished",
                f
            );
            std::fs::create_dir_all(data_dir).expect("Failed to create data directory");
            std::fs::write(&p, []).expect("Failed to write placeholder");
        }
    }
}

// Shared with every schema crate: the stamp, the pinned-archive download,
// CONTOUR_SCHEMA_SRC and the data repository. See the file.
include!("../../build-support/schema_data.rs");
