//! Lookup support for known third-party identifiers from ProfileManifests.
//!
//! Scans a local ProfileManifests checkout to build a set of known
//! reverse-DNS identifiers. This allows the validator to suppress
//! false-positive "invalid value" warnings for fields like
//! `ExtensionIdentifier` where the upstream schema has a limited
//! `allowed_values` list but `pfm_range_list_allow_custom_value: true`.

use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::path::Path;

/// Build a `HashSet` of known identifiers from a ProfileManifests checkout.
///
/// Scans both `Manifests/ManagedPreferencesApplications/*.plist` and
/// `Manifests/ManifestsApple/*.plist`, stripping the `.plist` extension
/// to produce reverse-DNS identifiers (e.g. `com.okta.mobile.auth-service-extension`).
///
/// No plist parsing is needed — the filenames ARE the identifiers.
pub fn load_known_identifiers(manifests_path: &Path) -> Result<HashSet<String>> {
    if !manifests_path.is_dir() {
        bail!(
            "ProfileManifests path does not exist: {}",
            manifests_path.display()
        );
    }

    let mut identifiers = HashSet::new();

    let subdirs = [
        "Manifests/ManagedPreferencesApplications",
        "Manifests/ManifestsApple",
    ];

    for subdir in &subdirs {
        let dir = manifests_path.join(subdir);
        if !dir.is_dir() {
            continue;
        }

        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("Failed to read directory: {}", dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("plist") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    identifiers.insert(stem.to_string());
                }
            }
        }
    }

    Ok(identifiers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_load_known_identifiers() {
        let tmp = TempDir::new().unwrap();
        let apps_dir = tmp.path().join("Manifests/ManagedPreferencesApplications");
        let apple_dir = tmp.path().join("Manifests/ManifestsApple");
        fs::create_dir_all(&apps_dir).unwrap();
        fs::create_dir_all(&apple_dir).unwrap();

        // Create some fake plist files
        fs::write(
            apps_dir.join("com.okta.mobile.auth-service-extension.plist"),
            "",
        )
        .unwrap();
        fs::write(apps_dir.join("com.google.Chrome.plist"), "").unwrap();
        fs::write(apple_dir.join("com.apple.wifi.managed.plist"), "").unwrap();
        // Non-plist file should be ignored
        fs::write(apps_dir.join("README.md"), "").unwrap();

        let ids = load_known_identifiers(tmp.path()).unwrap();
        assert!(ids.contains("com.okta.mobile.auth-service-extension"));
        assert!(ids.contains("com.google.Chrome"));
        assert!(ids.contains("com.apple.wifi.managed"));
        assert!(!ids.contains("README"));
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn test_load_known_identifiers_missing_path() {
        let result = load_known_identifiers(Path::new("/nonexistent/path"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_load_known_identifiers_missing_subdirs() {
        let tmp = TempDir::new().unwrap();
        // No subdirs created — should return empty set, not error
        let ids = load_known_identifiers(tmp.path()).unwrap();
        assert!(ids.is_empty());
    }
}
