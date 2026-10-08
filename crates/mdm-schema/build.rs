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

    // The OS seed's Apple schema, when the pin carries one. lib.rs embeds
    // `data-beta/` under this cfg and serves stable's bytes without it.
    println!("cargo::rustc-check-cfg=cfg(seed_dataset)");
    if resolve_seed_dataset(&DatasetSpec {
        archive: "mdm-schema-beta",
        url_var: "CONTOUR_MDM_SCHEMA_BETA_URL",
        files: SEED_SCHEMA_FILES,
        optional: &[],
    }) {
        println!("cargo:rustc-cfg=seed_dataset");
    }
}

/// The tables the seed archive carries: the Apple schema itself, and the
/// provenance row naming the seed commit.
const SEED_SCHEMA_FILES: &[&str] = &[
    "capabilities.parquet",
    "examples.parquet",
    "skip_keys.parquet",
    "status_items.parquet",
    "source_versions.parquet",
];

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
