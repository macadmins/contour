use crate::versioning::manifest::{BaselineEntry, ProfileInfo};
use std::collections::{HashMap, HashSet};

/// Diff engine for comparing versions
#[derive(Debug)]
pub struct DiffEngine;

impl DiffEngine {
    /// Compare two baseline entries and generate a diff report
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn diff_baselines(old: &BaselineEntry, new: &BaselineEntry) -> BaselineDiff {
        let mut changes = Vec::new();

        // Compare git hashes
        if old.mscp_git_hash != new.mscp_git_hash {
            changes.push(format!(
                "mSCP Git hash changed: {} -> {}",
                &old.mscp_git_hash[..7],
                &new.mscp_git_hash[..7]
            ));
        }

        // Compare git tags
        if old.mscp_git_tag != new.mscp_git_tag {
            let old_tag = old.mscp_git_tag.as_deref().unwrap_or("none");
            let new_tag = new.mscp_git_tag.as_deref().unwrap_or("none");
            changes.push(format!("mSCP tag changed: {old_tag} -> {new_tag}"));
        }

        // Compare profile counts
        if old.profile_count != new.profile_count {
            changes.push(format!(
                "Profile count changed: {} -> {}",
                old.profile_count, new.profile_count
            ));
        }

        // Compare individual profiles
        let profile_changes = Self::diff_profiles(&old.profiles, &new.profiles);
        changes.extend(profile_changes);

        BaselineDiff {
            baseline_name: new.name.clone(),
            old_version_id: old.version_id.clone(),
            new_version_id: new.version_id.clone(),
            changes,
        }
    }

    /// Compare profile lists
    #[allow(dead_code, reason = "reserved for future use")]
    fn diff_profiles(old: &[ProfileInfo], new: &[ProfileInfo]) -> Vec<String> {
        let mut changes = Vec::new();

        let old_map: HashMap<&str, &ProfileInfo> =
            old.iter().map(|p| (p.filename.as_str(), p)).collect();
        let new_map: HashMap<&str, &ProfileInfo> =
            new.iter().map(|p| (p.filename.as_str(), p)).collect();

        let old_files: HashSet<&str> = old_map.keys().copied().collect();
        let new_files: HashSet<&str> = new_map.keys().copied().collect();

        // Find added profiles
        for added in new_files.difference(&old_files) {
            changes.push(format!("Added profile: {added}"));
        }

        // Find removed profiles
        for removed in old_files.difference(&new_files) {
            changes.push(format!("Removed profile: {removed}"));
        }

        // Find modified profiles
        for common in old_files.intersection(&new_files) {
            let old_profile = old_map.get(common).unwrap();
            let new_profile = new_map.get(common).unwrap();

            if old_profile.hash != new_profile.hash {
                changes.push(format!("Modified profile: {common}"));
            }
        }

        changes
    }

    /// Generate a markdown diff report
    pub fn generate_markdown_report(diffs: &[BaselineDiff]) -> String {
        let mut report = String::new();
        report.push_str("# mSCP FleetDM GitOps Diff Report\n\n");
        report.push_str(&format!(
            "Generated at: {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        for diff in diffs {
            report.push_str(&format!("## Baseline: {}\n\n", diff.baseline_name));
            report.push_str(&format!(
                "**Version:** `{}` → `{}`\n\n",
                diff.old_version_id, diff.new_version_id
            ));

            if diff.changes.is_empty() {
                report.push_str("*No changes detected*\n\n");
            } else {
                report.push_str("### Changes:\n\n");
                for change in &diff.changes {
                    report.push_str(&format!("- {change}\n"));
                }
                report.push('\n');
            }
        }

        report
    }
}

/// Represents a diff between two baseline versions
#[derive(Debug, Clone)]
pub struct BaselineDiff {
    pub baseline_name: String,
    pub old_version_id: String,
    pub new_version_id: String,
    pub changes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_profiles() {
        let old = vec![ProfileInfo {
            filename: "test.mobileconfig".to_string(),
            payload_identifier: Some("com.test".to_string()),
            hash: "abc123".to_string(),
        }];

        let new = vec![
            ProfileInfo {
                filename: "test.mobileconfig".to_string(),
                payload_identifier: Some("com.test".to_string()),
                hash: "def456".to_string(), // Changed hash
            },
            ProfileInfo {
                filename: "new.mobileconfig".to_string(),
                payload_identifier: Some("com.new".to_string()),
                hash: "xyz789".to_string(),
            },
        ];

        let changes = DiffEngine::diff_profiles(&old, &new);
        assert!(changes.len() >= 2); // Modified + Added
    }
}
