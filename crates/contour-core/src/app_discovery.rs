//! App discovery and code signature utilities shared across BTM, PPPC, and notifications.

use anyhow::Result;
use std::path::{Path, PathBuf};

/// Bundle extensions that follow the standard `Contents/Info.plist` layout.
///
/// `.app` is the dominant case; the others are common Apple bundle types
/// that PPPC/TCC profiles need to target (XPC services, app extensions,
/// system extensions, generic loadable bundles, plug-ins). All have a
/// `Contents/Info.plist` with `CFBundleIdentifier` and a `Contents/MacOS/`
/// executable.
///
/// `.framework` is intentionally NOT in this list — frameworks use a
/// different versioned layout (`Versions/<v>/Resources/Info.plist`) and
/// aren't typical PPPC targets. Their nested XPC services ARE typical
/// targets, and those are caught by recursing into the framework dir.
pub const BUNDLE_EXTENSIONS: &[&str] =
    &["app", "xpc", "appex", "systemextension", "bundle", "plugin"];

/// Find all bundle directories recursively under `path`.
///
/// When the walker encounters a directory whose extension matches
/// [`BUNDLE_EXTENSIONS`], it adds the bundle and stops recursing into
/// it (the bundle's children are part of the bundle, not separate
/// targets — except for nested XPC services in frameworks, which are
/// surfaced by recursing into the framework directory itself rather
/// than treating it as a leaf).
///
/// Non-bundle directories are descended into.
pub fn find_apps_recursive(path: &Path, apps: &mut Vec<PathBuf>) -> Result<()> {
    if !path.is_dir() {
        return Ok(());
    }
    if is_bundle_dir(path) {
        apps.push(path.to_path_buf());
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            find_apps_recursive(&entry_path, apps)?;
        }
    }
    Ok(())
}

/// True if `path` is a directory whose extension is one of [`BUNDLE_EXTENSIONS`].
pub fn is_bundle_dir(path: &Path) -> bool {
    path.is_dir()
        && path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| BUNDLE_EXTENSIONS.contains(&e))
}

/// Extract the Team ID from a code requirement string.
///
/// Looks for patterns like `certificate leaf[subject.OU] = "ABCD1234"` or
/// `certificate leaf[subject.OU] = ABCD1234` (with or without quotes).
pub fn extract_team_id(code_requirement: &str) -> Option<String> {
    let patterns = [
        r#"certificate leaf\[subject\.OU\] = "([A-Z0-9]+)""#,
        r"certificate leaf\[subject\.OU\] = ([A-Z0-9]+)",
    ];
    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern)
            && let Some(caps) = re.captures(code_requirement)
            && let Some(m) = caps.get(1)
        {
            return Some(m.as_str().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_team_id_quoted() {
        let req = r#"identifier "us.zoom.xos" and anchor apple generic and certificate leaf[subject.OU] = "BJ4HAAB9B3""#;
        assert_eq!(extract_team_id(req), Some("BJ4HAAB9B3".to_string()));
    }

    #[test]
    fn test_extract_team_id_unquoted() {
        let req = r#"identifier "com.1password" and certificate leaf[subject.OU] = ABCD1234EF"#;
        assert_eq!(extract_team_id(req), Some("ABCD1234EF".to_string()));
    }

    #[test]
    fn test_extract_team_id_none() {
        let req = r#"identifier "com.example" and anchor apple"#;
        assert_eq!(extract_team_id(req), None);
    }
}
