use std::path::Path;
use std::process::Command;

fn main() {
    let data_dir = Path::new("data");

    // Re-run only when the sentinel file changes (or is created/deleted).
    println!("cargo:rerun-if-changed=data/osquery_schema.parquet");

    // Allow skipping downloads entirely for offline / CI-cached builds.
    if std::env::var("CONTOUR_SCHEMA_SKIP_DOWNLOAD").is_ok() {
        return;
    }

    // If the sentinel file already exists, nothing to do.
    if data_dir.join("osquery_schema.parquet").exists() {
        return;
    }

    let url = std::env::var("CONTOUR_OSQUERY_SCHEMA_URL").unwrap_or_else(|_| {
        panic!(
            "CONTOUR_OSQUERY_SCHEMA_URL is not set and data/osquery_schema.parquet is missing.\n\
             Set CONTOUR_OSQUERY_SCHEMA_URL to the URL of osquery-schema.zip,\n\
             or copy parquet files into crates/osquery-schema/data/ manually."
        )
    });

    download_and_extract(&url, data_dir, "osquery-schema/data");
}

/// Download a zip archive from `url`, extract it, and move files from the
/// nested `inner_prefix` directory into `data_dir`.
///
/// The upstream zips contain the full crate layout (e.g. `osquery-schema/data/*.parquet`),
/// so we extract into a temporary directory and then relocate just the data files.
fn download_and_extract(url: &str, data_dir: &Path, inner_prefix: &str) {
    println!("cargo:warning=Downloading schema data from {url}");

    std::fs::create_dir_all(data_dir).expect("Failed to create data directory");

    let zip_path = data_dir.join("_schema.zip");
    let tmp_dir = data_dir.join("_tmp");

    // Download with curl.
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&zip_path)
        .arg(url)
        .status()
        .expect("Failed to run curl — is curl installed?");

    if !status.success() {
        panic!("Failed to download schema data from {url}");
    }

    // Extract into a temporary directory.
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).expect("Failed to create temp directory");

    let status = Command::new("unzip")
        .args(["-o", "-q"])
        .arg(&zip_path)
        .arg("-d")
        .arg(&tmp_dir)
        .status()
        .expect("Failed to run unzip — is unzip installed?");

    if !status.success() {
        let _ = std::fs::remove_file(&zip_path);
        let _ = std::fs::remove_dir_all(&tmp_dir);
        panic!("Failed to extract schema data");
    }

    // Move data files from the nested directory into the final location.
    let nested_dir = tmp_dir.join(inner_prefix);
    if nested_dir.is_dir() {
        for entry in std::fs::read_dir(&nested_dir).expect("Failed to read nested data dir") {
            let entry = entry.expect("Failed to read directory entry");
            let dest = data_dir.join(entry.file_name());
            let _ = std::fs::remove_file(&dest);
            std::fs::rename(entry.path(), &dest).unwrap_or_else(|e| {
                // rename can fail across mount points; fall back to copy+delete.
                std::fs::copy(entry.path(), &dest)
                    .unwrap_or_else(|_| panic!("Failed to copy {}: {e}", entry.path().display()));
                let _ = std::fs::remove_file(entry.path());
            });
        }
    } else {
        // Fallback: maybe the zip is flat — move everything from tmp_dir directly.
        for entry in std::fs::read_dir(&tmp_dir).expect("Failed to read temp dir") {
            let entry = entry.expect("Failed to read directory entry");
            if entry.path().is_file() {
                let dest = data_dir.join(entry.file_name());
                let _ = std::fs::remove_file(&dest);
                let _ = std::fs::rename(entry.path(), &dest);
            }
        }
    }

    // Clean up.
    let _ = std::fs::remove_file(&zip_path);
    let _ = std::fs::remove_dir_all(&tmp_dir);

    println!(
        "cargo:warning=Schema data downloaded and extracted to {}",
        data_dir.display()
    );
}
