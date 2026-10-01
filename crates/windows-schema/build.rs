use std::path::Path;

fn main() {
    resolve_dataset(&DatasetSpec {
        archive: "windows-schema",
        url_var: "CONTOUR_WINDOWS_SCHEMA_URL",
        files: LOCAL_SCHEMA_FILES,
        optional: OPTIONAL_FILES,
    });
    // Whatever the dataset carries, a table it predates becomes a
    // zero-length placeholder; see the function.
    ensure_optional_placeholders(Path::new("data"));

    // The dataset stamp (`release <pin> sha256 <hex>`, or `local <path>`),
    // for generated SyncML to name the data it was checked against.
    // `resolve_dataset` already declares the file as a rerun input.
    let pin = std::fs::read_to_string("data/.dataset-pin")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unstamped".to_string());
    println!("cargo:rustc-env=CONTOUR_WINDOWS_DATASET_PIN={pin}");
}

/// Parquet files this crate embeds, in the order the dataset release lists
/// them for this archive.
const LOCAL_SCHEMA_FILES: &[&str] = &[
    "windows_rules.parquet",
    "windows_baseline_edges.parquet",
    "stig_registry_checks.parquet",
    "fleet_stigs.parquet",
    "windows_admx_policies.parquet",
    "windows_rule_capability_links.parquet",
    "windows_node_details.parquet",
    "windows_app_policies.parquet",
];

/// Tables added after a dataset was published get a zero-length placeholder
/// so a checkout pinned to an older archive still compiles. The placeholder
/// reads as no rows — and `no_embedded_table_is_an_empty_placeholder` in
/// contour's tests fails on it, so an old dataset is loud, not silent.
const OPTIONAL_FILES: &[&str] = &["windows_rule_capability_links.parquet"];

fn ensure_optional_placeholders(data_dir: &Path) {
    for f in OPTIONAL_FILES {
        let p = data_dir.join(f);
        if !p.exists() {
            println!(
                "cargo:warning=windows-schema: {f} not in this dataset — the surface it feeds \
                 (rule annotations, third-party app policies, node details) is empty until the \
                 schema is republished"
            );
            std::fs::create_dir_all(data_dir).expect("Failed to create data directory");
            std::fs::write(&p, []).expect("Failed to write placeholder");
        }
    }
}

// Shared with every schema crate: the stamp, the pinned-archive download,
// CONTOUR_SCHEMA_SRC and the data repository. See the file.
include!("../../build-support/schema_data.rs");
