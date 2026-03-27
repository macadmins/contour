use std::path::{Path, PathBuf};

use colored::Colorize;

/// A discovered brand folder with its asset paths.
#[derive(Debug)]
pub struct DiscoveredBrand {
    pub name: String,
    pub folder: PathBuf,
    pub logo: PathBuf,
    pub logo_darkmode: PathBuf,
    pub menubar_icon: PathBuf,
}

/// Scan a parent directory for brand subfolders containing Support App assets.
///
/// Each subdirectory is checked for `logo.png`, `logo_darkmode.png`, and
/// `support-app-menubar-icon.png`. Folders missing assets are warned about
/// but not included in the results.
pub fn scan_brands(parent: &Path) -> anyhow::Result<Vec<DiscoveredBrand>> {
    if !parent.is_dir() {
        anyhow::bail!("Not a directory: {}", parent.display());
    }

    let mut brands = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(parent)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name_str = name.to_string_lossy();
            e.path().is_dir() && !name_str.starts_with('.')
        })
        .collect();

    // Sort by folder name for deterministic output
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let folder = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        let logo = folder.join("logo.png");
        let logo_darkmode = folder.join("logo_darkmode.png");
        let menubar_icon = folder.join("support-app-menubar-icon.png");

        let mut missing = Vec::new();
        if !logo.exists() {
            missing.push("logo.png");
        }
        if !logo_darkmode.exists() {
            missing.push("logo_darkmode.png");
        }
        if !menubar_icon.exists() {
            missing.push("support-app-menubar-icon.png");
        }

        if !missing.is_empty() {
            eprintln!(
                "{} Skipping {}: missing {}",
                "warning:".yellow().bold(),
                name,
                missing.join(", ")
            );
            continue;
        }

        brands.push(DiscoveredBrand {
            name,
            folder: std::fs::canonicalize(&folder)?,
            logo: std::fs::canonicalize(&logo)?,
            logo_darkmode: std::fs::canonicalize(&logo_darkmode)?,
            menubar_icon: std::fs::canonicalize(&menubar_icon)?,
        });
    }

    Ok(brands)
}
