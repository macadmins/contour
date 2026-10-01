use std::path::Path;

fn main() {
    resolve_dataset(&DatasetSpec {
        archive: "mscp-schema",
        url_var: "CONTOUR_MSCP_SCHEMA_URL",
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
    "baseline_meta.parquet",
    "sections.parquet",
    "control_tiers.parquet",
    "rule_meta.parquet",
    "baseline_edges.parquet",
    "rules_versioned.parquet",
    "rule_payloads.parquet",
    "envelope_patterns.parquet",
    "envelope_meta_keys.parquet",
    "rule_capability_links.parquet",
    // rule → framework → control_id, and what the corpus addresses.
    "rule_control_edges.parquet",
    "supported_payloads.parquet",
    // Fleet's GitOps JSON Schema, sha256-pinned by the dataset: what
    // `mscp validate` checks fleets/*.yml against when no --schemas is given.
    "fleet-gitops-schema.json",
];

/// Tables added after a dataset was published get a zero-length placeholder
/// so `include_bytes!` resolves and the reader sees an empty table. Only
/// for files whose readers are documented to accept empty input.
const OPTIONAL_FILES: &[&str] = &[
    "rule_capability_links.parquet",
    "rule_control_edges.parquet",
    "supported_payloads.parquet",
    // An older dataset without it gets an empty placeholder, which
    // `embedded_fleet_gitops_schema` reports as None.
    "fleet-gitops-schema.json",
];

fn ensure_optional_placeholders(data_dir: &Path) {
    for f in OPTIONAL_FILES {
        let p = data_dir.join(f);
        if !p.exists() {
            println!(
                "cargo:warning=mscp-schema: {} not in this dataset — annotations will be empty until the schema is republished",
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
