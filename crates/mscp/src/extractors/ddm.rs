use crate::models::{DdmArtifact, DdmDeclarationType};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Extract DDM artifacts from mSCP build directory
pub fn extract_ddm_artifacts<P: AsRef<Path>>(build_path: P) -> Result<Vec<DdmArtifact>> {
    let build_path = build_path.as_ref();
    let declarative_dir = build_path.join("declarative");

    if !declarative_dir.exists() {
        tracing::info!("No declarative/ directory found - DDM not generated");
        return Ok(Vec::new());
    }

    tracing::info!("Found declarative/ directory - extracting DDM artifacts");

    let mut artifacts = Vec::new();

    // Extract configurations
    artifacts.extend(extract_ddm_type(
        &declarative_dir,
        DdmDeclarationType::Configuration,
    )?);

    // Extract assets (JSON + ZIP pairs)
    artifacts.extend(extract_ddm_type(
        &declarative_dir,
        DdmDeclarationType::Asset,
    )?);

    // Extract activations
    artifacts.extend(extract_ddm_type(
        &declarative_dir,
        DdmDeclarationType::Activation,
    )?);

    tracing::info!("Found {} DDM artifacts", artifacts.len());
    Ok(artifacts)
}

/// Extract DDM artifacts of a specific type
fn extract_ddm_type(
    declarative_dir: &Path,
    declaration_type: DdmDeclarationType,
) -> Result<Vec<DdmArtifact>> {
    let type_dir = declarative_dir.join(declaration_type.subdirectory());

    if !type_dir.exists() {
        tracing::debug!("No {} directory found", declaration_type.subdirectory());
        return Ok(Vec::new());
    }

    let mut artifacts = Vec::new();

    for entry in WalkDir::new(&type_dir)
        .max_depth(1)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();

        // Only process JSON files
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        // Parse identifier from filename
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        let identifier = extract_identifier(filename);

        // Calculate hash
        let content = fs::read(path).context("Failed to read DDM JSON file")?;
        let hash_bytes = Sha256::digest(&content);
        use std::fmt::Write as _;
        let hash = hash_bytes
            .iter()
            .fold(String::with_capacity(64), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            });
        let size = content.len() as u64;

        // For assets, find corresponding ZIP file
        let asset_path = if declaration_type == DdmDeclarationType::Asset {
            find_asset_zip(&type_dir, &identifier)
        } else {
            None
        };

        artifacts.push(DdmArtifact {
            declaration_type: declaration_type.clone(),
            identifier: identifier.clone(),
            json_path: path.to_path_buf(),
            asset_path,
            hash,
            size,
        });
    }

    tracing::info!(
        "Found {} {} declarations",
        artifacts.len(),
        declaration_type.subdirectory()
    );

    Ok(artifacts)
}

/// Extract service identifier from DDM filename
/// Example: "`org.mscp.cis_lvl1.config.pam.json`" -> "pam"
fn extract_identifier(filename: &str) -> String {
    // Format: org.mscp.{baseline}.{type}.{identifier}.json
    let parts: Vec<&str> = filename.split('.').collect();

    if parts.len() >= 5 {
        // Get the part before ".json"
        parts[parts.len() - 2].to_string()
    } else {
        filename.trim_end_matches(".json").to_string()
    }
}

/// Find associated ZIP file for an asset declaration
fn find_asset_zip(assets_dir: &Path, identifier: &str) -> Option<PathBuf> {
    // Look for {service}.zip in the same directory
    let zip_path = assets_dir.join(format!("{identifier}.zip"));

    if zip_path.exists() {
        tracing::debug!("Found asset ZIP: {}", zip_path.display());
        Some(zip_path)
    } else {
        // Try alternate naming: com.apple.{service}.zip
        let alt_zip_path = assets_dir.join(format!("com.apple.{identifier}.zip"));
        if alt_zip_path.exists() {
            tracing::debug!("Found asset ZIP (alternate): {}", alt_zip_path.display());
            Some(alt_zip_path)
        } else {
            tracing::warn!("No ZIP file found for asset: {}", identifier);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_identifier() {
        assert_eq!(
            extract_identifier("org.mscp.cis_lvl1.config.pam.json"),
            "pam"
        );
        assert_eq!(
            extract_identifier("org.mscp.800-53r5_high.asset.sshd.json"),
            "sshd"
        );
        assert_eq!(
            extract_identifier("org.mscp.baseline.activation.sudo.json"),
            "sudo"
        );
    }

    #[test]
    fn test_extract_identifier_fallback() {
        assert_eq!(extract_identifier("simple.json"), "simple");
    }
}
