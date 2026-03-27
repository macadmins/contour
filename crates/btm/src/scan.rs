//! BTM (Background Task Management) scanning for LaunchDaemons, LaunchAgents, and login items.
//!
//! Provides filesystem scanning to discover launchd plists and build
//! service management rules for the `com.apple.servicemanagement` MDM payload.

use crate::config::BtmRule;
use anyhow::{Context, Result};
use contour_core::{extract_team_id, get_code_requirement};
use std::path::{Path, PathBuf};

/// Result of scanning a single launchd plist.
#[derive(Debug, Clone)]
pub struct BtmScanResult {
    /// The launchd label from the plist
    pub label: String,
    /// Path to the executable (from Program or ProgramArguments)
    pub executable: Option<PathBuf>,
    /// Team ID extracted from the executable's code signature
    pub team_id: Option<String>,
    /// Bundle identifiers associated with this launch item
    pub bundle_ids: Vec<String>,
    /// Suggested BTM rules for this launch item
    pub suggested_rules: Vec<BtmRule>,
    /// Path to the source plist file
    pub source_plist: PathBuf,
}

impl std::fmt::Display for BtmScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.label, self.source_plist.display())
    }
}

/// Parse a launchd plist and extract label, executable path, and associated bundle IDs.
fn parse_launch_plist(path: &Path) -> Result<(String, Option<PathBuf>, Vec<String>)> {
    let content =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;

    let plist: plist::Value = plist::from_bytes(&content)
        .with_context(|| format!("Failed to parse plist {}", path.display()))?;

    let dict = plist
        .as_dictionary()
        .ok_or_else(|| anyhow::anyhow!("Plist is not a dictionary: {}", path.display()))?;

    // Extract Label (required)
    let label = dict
        .get("Label")
        .and_then(|v| v.as_string())
        .ok_or_else(|| anyhow::anyhow!("No Label in plist: {}", path.display()))?
        .to_string();

    // Extract executable path from Program or ProgramArguments[0]
    let executable = dict
        .get("Program")
        .and_then(|v| v.as_string())
        .map(PathBuf::from)
        .or_else(|| {
            dict.get("ProgramArguments")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_string())
                .map(PathBuf::from)
        });

    // Extract AssociatedBundleIdentifiers
    let bundle_ids = dict
        .get("AssociatedBundleIdentifiers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_string().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok((label, executable, bundle_ids))
}

/// Build suggested BTM rules from scan data.
fn build_suggested_rules(
    label: &str,
    team_id: Option<&str>,
    bundle_ids: &[String],
) -> Vec<BtmRule> {
    let mut rules = Vec::new();

    // Always add a Label rule
    rules.push(BtmRule {
        rule_type: "Label".to_string(),
        rule_value: label.to_string(),
        comment: Some(format!("launchd label: {label}")),
    });

    // Add TeamIdentifier if signed
    if let Some(tid) = team_id {
        rules.push(BtmRule {
            rule_type: "TeamIdentifier".to_string(),
            rule_value: tid.to_string(),
            comment: Some(format!("Team ID for {label}")),
        });
    }

    // Add BundleIdentifier for each associated bundle ID
    for bid in bundle_ids {
        rules.push(BtmRule {
            rule_type: "BundleIdentifier".to_string(),
            rule_value: bid.clone(),
            comment: Some(format!("Associated bundle for {label}")),
        });
    }

    rules
}

/// Resolve team ID from an executable path by running codesign.
fn resolve_team_id(executable: &Path) -> Option<String> {
    if !executable.exists() {
        return None;
    }
    get_code_requirement(executable)
        .ok()
        .and_then(|req| extract_team_id(&req))
}

/// Scan system LaunchDaemons and LaunchAgents directories.
///
/// Scans `/Library/LaunchDaemons/` and `/Library/LaunchAgents/` by default,
/// or custom paths if provided.
pub fn scan_launch_items(paths: &[PathBuf]) -> Result<Vec<BtmScanResult>> {
    let dirs: Vec<PathBuf> = if paths.is_empty() {
        vec![
            PathBuf::from("/Library/LaunchDaemons"),
            PathBuf::from("/Library/LaunchAgents"),
        ]
    } else {
        paths.to_vec()
    };

    let mut results = Vec::new();

    for dir in &dirs {
        if !dir.exists() {
            continue;
        }

        let entries =
            std::fs::read_dir(dir).with_context(|| format!("Failed to read {}", dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|e| e == "plist")
                && let Ok((label, executable, bundle_ids)) = parse_launch_plist(&path)
            {
                let team_id = executable.as_ref().and_then(|exe| resolve_team_id(exe));

                let suggested_rules =
                    build_suggested_rules(&label, team_id.as_deref(), &bundle_ids);

                results.push(BtmScanResult {
                    label,
                    executable,
                    team_id,
                    bundle_ids,
                    suggested_rules,
                    source_plist: path,
                });
            }
        }
    }

    // Sort by label for deterministic output
    results.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(results)
}

/// Scan app bundles for embedded LaunchDaemons and LaunchAgents.
///
/// For each `.app` bundle, looks inside:
/// - `Contents/Library/LaunchDaemons/`
/// - `Contents/Library/LaunchAgents/`
pub fn scan_app_bundles(paths: &[PathBuf]) -> Result<Vec<BtmScanResult>> {
    let scan_paths = if paths.is_empty() {
        vec![PathBuf::from("/Applications")]
    } else {
        paths.to_vec()
    };

    let apps = contour_core::discover_apps(&scan_paths)?;
    let mut results = Vec::new();

    for app_info in &apps {
        let contents = app_info.path.join("Contents");
        if !contents.is_dir() {
            continue;
        }

        let search_dirs = [
            contents.join("Library/LaunchDaemons"),
            contents.join("Library/LaunchAgents"),
        ];

        for dir in &search_dirs {
            if !dir.is_dir() {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    continue;
                };
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "plist") {
                    if let Ok((label, executable, bundle_ids)) = parse_launch_plist(&path) {
                        // Prefer executable's own team ID, fall back to the app's team ID
                        let team_id = executable
                            .as_ref()
                            .and_then(|exe| resolve_team_id(exe))
                            .or_else(|| app_info.team_id.clone());

                        let suggested_rules =
                            build_suggested_rules(&label, team_id.as_deref(), &bundle_ids);

                        results.push(BtmScanResult {
                            label,
                            executable,
                            team_id,
                            bundle_ids,
                            suggested_rules,
                            source_plist: path,
                        });
                    }
                }
            }
        }
    }

    results.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(results)
}

/// Interactive selection of BTM scan results.
///
/// Presents a multi-select picker showing each discovered launch item.
pub fn interactive_btm_selection(results: &[BtmScanResult]) -> Result<Vec<BtmScanResult>> {
    contour_core::multi_select(results, "Select launch items to include:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_test_plist(dir: &Path, filename: &str, label: &str, program: &str) -> PathBuf {
        let path = dir.join(filename);
        let content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>Program</key>
    <string>{program}</string>
</dict>
</plist>"#
        );
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_parse_launch_plist() {
        let dir = tempfile::tempdir().unwrap();
        create_test_plist(
            dir.path(),
            "com.example.daemon.plist",
            "com.example.daemon",
            "/usr/local/bin/example",
        );

        let (label, executable, bundle_ids) =
            parse_launch_plist(&dir.path().join("com.example.daemon.plist")).unwrap();

        assert_eq!(label, "com.example.daemon");
        assert_eq!(executable, Some(PathBuf::from("/usr/local/bin/example")));
        assert!(bundle_ids.is_empty());
    }

    #[test]
    fn test_parse_launch_plist_with_program_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.plist");
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/agent</string>
        <string>--daemon</string>
    </array>
</dict>
</plist>"#;
        std::fs::write(&path, content).unwrap();

        let (label, executable, _) = parse_launch_plist(&path).unwrap();
        assert_eq!(label, "com.example.agent");
        assert_eq!(executable, Some(PathBuf::from("/usr/local/bin/agent")));
    }

    #[test]
    fn test_build_suggested_rules_with_team_id() {
        let rules = build_suggested_rules(
            "com.example.daemon",
            Some("ABC123"),
            &["com.example.app".to_string()],
        );

        assert_eq!(rules.len(), 3); // Label + TeamIdentifier + BundleIdentifier
        assert_eq!(rules[0].rule_type, "Label");
        assert_eq!(rules[0].rule_value, "com.example.daemon");
        assert_eq!(rules[1].rule_type, "TeamIdentifier");
        assert_eq!(rules[1].rule_value, "ABC123");
        assert_eq!(rules[2].rule_type, "BundleIdentifier");
        assert_eq!(rules[2].rule_value, "com.example.app");
    }

    #[test]
    fn test_build_suggested_rules_without_team_id() {
        let rules = build_suggested_rules("com.example.daemon", None, &[]);

        assert_eq!(rules.len(), 1); // Just Label
        assert_eq!(rules[0].rule_type, "Label");
    }

    #[test]
    fn test_scan_launch_items_from_directory() {
        let dir = tempfile::tempdir().unwrap();
        create_test_plist(
            dir.path(),
            "com.example.daemon.plist",
            "com.example.daemon",
            "/nonexistent/bin/example",
        );
        create_test_plist(
            dir.path(),
            "com.example.agent.plist",
            "com.example.agent",
            "/nonexistent/bin/agent",
        );

        let results = scan_launch_items(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(results.len(), 2);

        // Should be sorted by label
        assert_eq!(results[0].label, "com.example.agent");
        assert_eq!(results[1].label, "com.example.daemon");
    }

    #[test]
    fn test_scan_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let results = scan_launch_items(&[dir.path().to_path_buf()]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_nonexistent_directory() {
        let results = scan_launch_items(&[PathBuf::from("/nonexistent/path")]).unwrap();
        assert!(results.is_empty());
    }
}
