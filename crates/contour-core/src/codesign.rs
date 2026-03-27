//! Code signing utilities for extracting code requirements.
//!
//! Uses the `codesign` command to extract code requirements from macOS
//! application bundles, which are needed for PPPC profile generation.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Extract the designated code requirement from an application bundle.
///
/// This runs `codesign -d -r - <path>` and parses the output to extract
/// the designated requirement string.
///
/// # Example output from codesign:
/// ```text
/// Executable=/Applications/Example.app/Contents/MacOS/Example
/// designated => identifier "com.example.app" and anchor apple generic and ...
/// ```
pub fn get_code_requirement(path: &Path) -> Result<String> {
    if cfg!(not(target_os = "macos")) {
        anyhow::bail!("Code requirement extraction requires macOS (uses `codesign` command)");
    }
    let output = Command::new("codesign")
        .args(["-d", "-r", "-"])
        .arg(path)
        .output()
        .context("Failed to run codesign command")?;

    // codesign outputs the requirement to stdout (designated => ...)
    // and info messages to stderr (Executable=...)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Look for "designated => " line in stdout
    for line in stdout.lines() {
        if let Some(requirement) = line.strip_prefix("designated => ") {
            return Ok(requirement.trim().to_string());
        }
    }

    // If no designated requirement found, check if unsigned
    if stderr.contains("code object is not signed at all") {
        anyhow::bail!("Application is not signed");
    }

    anyhow::bail!(
        "Could not extract code requirement from codesign output.\nstdout: {stdout}\nstderr: {stderr}"
    )
}

/// Get the bundle identifier from an application's Info.plist.
pub fn get_bundle_id(app_path: &Path) -> Result<String> {
    let info_plist = app_path.join("Contents/Info.plist");

    if !info_plist.exists() {
        anyhow::bail!("Info.plist not found at {}", info_plist.display());
    }

    let content = std::fs::read(&info_plist)
        .with_context(|| format!("Failed to read {}", info_plist.display()))?;

    let plist: plist::Value = plist::from_bytes(&content)
        .with_context(|| format!("Failed to parse {}", info_plist.display()))?;

    if let Some(dict) = plist.as_dictionary()
        && let Some(bundle_id) = dict.get("CFBundleIdentifier")
        && let Some(id) = bundle_id.as_string()
    {
        return Ok(id.to_string());
    }

    anyhow::bail!("CFBundleIdentifier not found in Info.plist")
}

/// Get the application name from Info.plist or fallback to directory name.
pub fn get_app_name(app_path: &Path) -> String {
    // Try to get from Info.plist
    let info_plist = app_path.join("Contents/Info.plist");
    if info_plist.exists()
        && let Ok(content) = std::fs::read(&info_plist)
        && let Ok(plist) = plist::from_bytes::<plist::Value>(&content)
        && let Some(dict) = plist.as_dictionary()
    {
        // Try CFBundleDisplayName first, then CFBundleName
        for key in &["CFBundleDisplayName", "CFBundleName"] {
            if let Some(name) = dict.get(key)
                && let Some(s) = name.as_string()
                && !s.is_empty()
            {
                return s.to_string();
            }
        }
    }

    // Fallback to directory name without .app extension
    app_path.file_stem().map_or_else(
        || "Unknown".to_string(),
        |s| s.to_string_lossy().to_string(),
    )
}

/// Find the main executable path within an app bundle.
pub fn find_main_executable(app_path: &Path) -> Result<std::path::PathBuf> {
    let contents = app_path.join("Contents");
    let macos = contents.join("MacOS");
    let info_plist = contents.join("Info.plist");

    // Try to read Info.plist to get the executable name
    if info_plist.exists()
        && let Ok(content) = std::fs::read(&info_plist)
        && let Ok(plist) = plist::from_bytes::<plist::Value>(&content)
        && let Some(dict) = plist.as_dictionary()
        && let Some(exec) = dict.get("CFBundleExecutable")
        && let Some(exec_name) = exec.as_string()
    {
        let exec_path = macos.join(exec_name);
        if exec_path.exists() {
            return Ok(exec_path);
        }
    }

    // Fallback: use the app name as executable name
    if let Some(app_name) = app_path.file_stem() {
        let exec_path = macos.join(app_name);
        if exec_path.exists() {
            return Ok(exec_path);
        }
    }

    // Last resort: find any executable in MacOS folder
    if macos.exists() {
        for entry in std::fs::read_dir(&macos)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                return Ok(path);
            }
        }
    }

    anyhow::bail!("No executable found in {}", app_path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_app_name_fallback() {
        let path = Path::new("/Applications/Test.app");
        // Should fall back to directory name
        let name = get_app_name(path);
        assert_eq!(name, "Test");
    }
}
