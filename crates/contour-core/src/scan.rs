//! Shared app discovery and scanning for contour domain crates.
//!
//! Provides a common `AppInfo` struct and `discover_apps()` function
//! used by PPPC, notifications, and BTM crates.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::app_discovery::{extract_team_id, find_apps_recursive};
use crate::codesign::{get_app_name, get_bundle_id, get_code_requirement};

/// Metadata about a discovered macOS application bundle.
///
/// Shared across PPPC, notifications, and BTM crates as the common
/// unit of app discovery. Domain crates wrap or extend this with
/// domain-specific fields (TCC services, notification settings, BTM rules).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppInfo {
    /// Human-readable application name (from CFBundleDisplayName or CFBundleName).
    pub name: String,

    /// Bundle identifier (e.g., "com.tinyspeck.slackmacgap").
    pub bundle_id: String,

    /// Apple Team ID extracted from the code signature, if available.
    pub team_id: Option<String>,

    /// Path to the .app bundle on disk.
    pub path: PathBuf,

    /// Path to the main executable inside the bundle, if found.
    pub executable: Option<PathBuf>,

    /// Code signing designated requirement string, if available.
    pub code_requirement: Option<String>,
}

impl std::fmt::Display for AppInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.bundle_id)
    }
}

/// Discover all .app bundles in the given paths and extract their metadata.
///
/// For each path:
/// - If it ends in `.app`, treats it as a single app bundle.
/// - If it's a directory, recursively finds `.app` bundles inside it.
///
/// Apps that fail to yield a bundle ID are silently skipped.
/// Results are sorted by app name.
pub fn discover_apps(paths: &[PathBuf]) -> Result<Vec<AppInfo>> {
    let mut app_paths = Vec::new();
    for path in paths {
        if path.extension().is_some_and(|e| e == "app") {
            app_paths.push(path.clone());
        } else if path.is_dir() {
            find_apps_recursive(path, &mut app_paths)
                .with_context(|| format!("scanning {}", path.display()))?;
        }
    }

    let mut results = Vec::new();
    for app_path in &app_paths {
        if let Some(info) = discover_single_app(app_path) {
            results.push(info);
        }
    }

    results.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(results)
}

/// Extract metadata from a single .app bundle.
///
/// Returns `None` if the bundle ID cannot be read (invalid bundle).
fn discover_single_app(app_path: &Path) -> Option<AppInfo> {
    let bundle_id = get_bundle_id(app_path).ok()?;
    let name = get_app_name(app_path);

    let code_requirement = get_code_requirement(app_path).ok();
    let team_id = code_requirement.as_deref().and_then(extract_team_id);

    let executable = crate::codesign::find_main_executable(app_path).ok();

    Some(AppInfo {
        name,
        bundle_id,
        team_id,
        path: app_path.to_path_buf(),
        executable,
        code_requirement,
    })
}

/// Interactively select from a list using a multi-select picker.
///
/// Works with any type that implements `Display` and `Clone`.
/// Returns the selected items directly.
///
/// Returns an empty vec if `items` is empty.
pub fn multi_select<T: std::fmt::Display + Clone>(items: &[T], prompt: &str) -> Result<Vec<T>> {
    if items.is_empty() {
        return Ok(Vec::new());
    }

    let options: Vec<String> = items.iter().map(ToString::to_string).collect();

    let selected = inquire::MultiSelect::new(prompt, options.clone())
        .with_page_size(15)
        .with_help_message("Space to select, Enter to confirm")
        .prompt()?;

    let results: Vec<T> = selected
        .iter()
        .filter_map(|sel| {
            options
                .iter()
                .position(|o| o == sel)
                .map(|i| items[i].clone())
        })
        .collect();

    Ok(results)
}

/// Interactively select apps from a list using a multi-select picker.
///
/// Convenience wrapper around [`multi_select`] for `AppInfo` slices.
pub fn select_apps(apps: &[AppInfo], prompt: &str) -> Result<Vec<usize>> {
    if apps.is_empty() {
        return Ok(Vec::new());
    }

    let selected = multi_select(apps, prompt)?;

    let indices: Vec<usize> = selected
        .iter()
        .filter_map(|sel| apps.iter().position(|a| a.bundle_id == sel.bundle_id))
        .collect();

    Ok(indices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_apps_empty_paths() {
        let result = discover_apps(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_discover_apps_nonexistent_path() {
        let result = discover_apps(&[PathBuf::from("/nonexistent/path")]);
        // Non-existent non-app path is just skipped (not a dir, not .app)
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_app_info_display() {
        let info = AppInfo {
            name: "Slack".into(),
            bundle_id: "com.tinyspeck.slackmacgap".into(),
            team_id: Some("BQR82RBBHL".into()),
            path: PathBuf::from("/Applications/Slack.app"),
            executable: None,
            code_requirement: None,
        };
        assert_eq!(info.to_string(), "Slack (com.tinyspeck.slackmacgap)");
    }
}
