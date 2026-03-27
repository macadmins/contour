//! App discovery for notification profile generation.

use anyhow::Result;
use std::path::PathBuf;

/// A discovered application with its notification-relevant info.
#[derive(Debug, Clone)]
pub struct NotificationScanResult {
    pub name: String,
    pub bundle_id: String,
    pub path: PathBuf,
}

impl std::fmt::Display for NotificationScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.bundle_id)
    }
}

impl From<contour_core::AppInfo> for NotificationScanResult {
    fn from(info: contour_core::AppInfo) -> Self {
        Self {
            name: info.name,
            bundle_id: info.bundle_id,
            path: info.path,
        }
    }
}

/// Scan directories for .app bundles and extract bundle IDs.
pub fn scan_apps(paths: &[PathBuf]) -> Result<Vec<NotificationScanResult>> {
    let scan_paths = if paths.is_empty() {
        vec![PathBuf::from("/Applications")]
    } else {
        paths.to_vec()
    };

    let apps = contour_core::discover_apps(&scan_paths)?;
    Ok(apps.into_iter().map(NotificationScanResult::from).collect())
}

/// Interactive selection of scan results.
pub fn interactive_selection(
    results: &[NotificationScanResult],
) -> Result<Vec<NotificationScanResult>> {
    contour_core::multi_select(results, "Select apps for notification profiles:")
}
