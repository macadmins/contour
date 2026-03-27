//! App discovery and code signature utilities shared across BTM, PPPC, and notifications.

use anyhow::Result;
use std::path::{Path, PathBuf};

/// Find all .app bundles recursively in a directory.
///
/// When encountering a `.app` directory, adds it and stops recursing into it.
/// For non-app directories, recurses into subdirectories.
pub fn find_apps_recursive(path: &Path, apps: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        if path.extension().is_some_and(|e| e == "app") {
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
    }
    Ok(())
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
