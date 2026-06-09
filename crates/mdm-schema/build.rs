use std::path::Path;
use std::process::Command;

fn main() {
    // Re-run when either embedded snapshot changes (or is created/deleted).
    println!("cargo:rerun-if-changed=data/capabilities.parquet");
    // The beta seed snapshot (embedded via `embedded_capabilities_beta`) ships
    // inside the regular mdm-schema.zip under `mdm-schema/data/beta/`, so the
    // stable download below extracts it alongside the top-level parquet — no
    // separate download. Rebuild when it is refreshed.
    println!("cargo:rerun-if-changed=data/beta/capabilities.parquet");

    // Allow skipping downloads entirely for offline / CI-cached builds.
    if std::env::var("CONTOUR_SCHEMA_SKIP_DOWNLOAD").is_ok() {
        return;
    }

    // Stable channel — embedded via `embedded_capabilities`. The same archive
    // carries `data/beta/` (embedded via `embedded_capabilities_beta`);
    // `download_and_extract` relocates the `beta/` subdir wholesale.
    ensure_dataset(
        Path::new("data"),
        "mdm-schema/data",
        "CONTOUR_MDM_SCHEMA_URL",
        "mdm-schema.zip",
    );
}

/// Ensure `data_dir/capabilities.parquet` exists, downloading and extracting
/// the schema zip named by the `url_var` environment variable when it's
/// missing. `inner_prefix` is the zip's nested data path; `zip_name` appears
/// only in the missing-URL error message.
fn ensure_dataset(data_dir: &Path, inner_prefix: &str, url_var: &str, zip_name: &str) {
    // The capabilities parquet is the sentinel file for each channel.
    if data_dir.join("capabilities.parquet").exists() {
        return;
    }

    let url = std::env::var(url_var).unwrap_or_else(|_| {
        panic!(
            "{url_var} is not set and {}/capabilities.parquet is missing.\n\
             Set {url_var} to the URL of {zip_name},\n\
             or copy parquet files into crates/mdm-schema/{} manually.",
            data_dir.display(),
            data_dir.display(),
        )
    });

    download_and_extract(&url, data_dir, inner_prefix);
}

/// Download a zip archive from `url`, extract it, and move files from the
/// nested `inner_prefix` directory into `data_dir`.
///
/// The upstream zips contain the full crate layout (e.g. `mdm-schema/data/*.parquet`),
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
