use std::path::Path;

fn main() {
    resolve_dataset(&DatasetSpec {
        archive: "app-policy-schema",
        url_var: "CONTOUR_APP_POLICY_SCHEMA_URL",
        files: LOCAL_SCHEMA_FILES,
        optional: &[],
    });
}

/// Parquet files this crate embeds, in the order the dataset release lists
/// them for this archive.
const LOCAL_SCHEMA_FILES: &[&str] = &["app_policies.parquet"];

// Shared with every schema crate: the stamp, the pinned-archive download,
// CONTOUR_SCHEMA_SRC and the data repository. See the file.
include!("../../build-support/schema_data.rs");
