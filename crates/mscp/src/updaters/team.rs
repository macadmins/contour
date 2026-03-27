use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use contour_core::yaml_edit;

/// Updates Fleet team YAML files to include baseline profiles and scripts.
///
/// Uses line-based YAML editing (via `yaml_edit`) to preserve comments
/// and formatting, rather than serde round-trips.
#[derive(Debug)]
pub struct TeamUpdater {
    output_base: PathBuf,
    baseline_name: String,
}

impl TeamUpdater {
    pub fn new<P: AsRef<Path>>(output_base: P, baseline_name: String) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
            baseline_name,
        }
    }

    /// Validate that all team names resolve to existing team files.
    /// Bails with a clear error listing available teams if any are missing.
    pub fn validate_teams(&self, team_names: &[String]) -> Result<()> {
        let mut missing = Vec::new();
        for team_name in team_names {
            let team_file = self
                .output_base
                .join("fleets")
                .join(format!("{team_name}.yml"));
            if !team_file.exists() {
                missing.push(team_name.clone());
            }
        }

        if !missing.is_empty() {
            let available = self.list_available_teams()?;
            anyhow::bail!(
                "Team files not found: {}\nAvailable teams: {}",
                missing.join(", "),
                if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                }
            );
        }

        Ok(())
    }

    /// Add baseline to specified teams using comment-preserving editing.
    pub fn add_to_teams(&self, team_names: &[String]) -> Result<()> {
        for team_name in team_names {
            let team_file = self
                .output_base
                .join("fleets")
                .join(format!("{team_name}.yml"));

            if !team_file.exists() {
                let available = self.list_available_teams()?;
                anyhow::bail!(
                    "Team file not found: {}\nAvailable teams: {}",
                    team_file.display(),
                    if available.is_empty() {
                        "(none)".to_string()
                    } else {
                        available.join(", ")
                    }
                );
            }

            tracing::info!(
                "Adding baseline '{}' to team '{}'",
                self.baseline_name,
                team_name
            );

            let content = std::fs::read_to_string(&team_file)
                .with_context(|| format!("Failed to read team file: {}", team_file.display()))?;

            let mut modified = content.clone();
            let mut changes_made = false;

            // Append profiles to controls.macos_settings.custom_settings
            if let Some(new_content) = self.append_profiles(&modified)? {
                modified = new_content;
                changes_made = true;
            }

            // Append scripts to controls.scripts
            if let Some(new_content) = self.append_scripts(&modified)? {
                modified = new_content;
                changes_made = true;
            }

            if changes_made {
                std::fs::write(&team_file, &modified).with_context(|| {
                    format!("Failed to write team file: {}", team_file.display())
                })?;

                tracing::info!("✓ Updated team: {}", team_name);
            } else {
                tracing::info!(
                    "  Team '{}' already has baseline '{}' - no changes needed",
                    team_name,
                    self.baseline_name
                );
            }
        }

        Ok(())
    }

    /// Update default.yml with labels using comment-preserving editing.
    pub fn add_labels_to_default(&self) -> Result<()> {
        let default_file = self.output_base.join("default.yml");

        if !default_file.exists() {
            tracing::warn!("default.yml not found at: {}", default_file.display());
            return Ok(());
        }

        tracing::info!(
            "Adding labels for baseline '{}' to default.yml",
            self.baseline_name
        );

        let content =
            std::fs::read_to_string(&default_file).context("Failed to read default.yml")?;

        let label_path_value = format!("./lib/all/labels/mscp-{}.labels.yml", self.baseline_name);

        // Check if already present (simple text search)
        if content.contains(&label_path_value) {
            tracing::info!("  Labels already present in default.yml");
            return Ok(());
        }

        // Use append_to_section to add the label path entry
        let entry = yaml_edit::format_path_entry(&label_path_value, 2);
        let modified = yaml_edit::append_to_section(&content, "labels", &[entry]);

        std::fs::write(&default_file, &modified).context("Failed to write default.yml")?;

        tracing::info!("✓ Updated default.yml with labels");

        Ok(())
    }

    /// Append baseline profiles using line-based editing.
    /// Returns `Some(modified)` if changes were made, `None` if all already present.
    fn append_profiles(&self, content: &str) -> Result<Option<String>> {
        let baseline_profiles = self.get_baseline_profiles()?;

        if baseline_profiles.is_empty() {
            tracing::warn!("No profiles found in baseline '{}'", self.baseline_name);
            return Ok(None);
        }

        // Filter out profiles already present
        let label_name = format!("mscp-{}", self.baseline_name);
        let mut entries: Vec<Vec<String>> = Vec::new();

        for profile_path in &baseline_profiles {
            if !content.contains(profile_path) {
                entries.push(yaml_edit::format_profile_entry(
                    profile_path,
                    None,
                    Some(std::slice::from_ref(&label_name)),
                    None,
                    6, // standard indent for custom_settings entries
                ));
            }
        }

        if entries.is_empty() {
            return Ok(None);
        }

        tracing::info!("  Adding {} profiles", entries.len());
        Ok(Some(yaml_edit::append_custom_settings(content, &entries)))
    }

    /// Append baseline scripts using line-based editing.
    /// Returns `Some(modified)` if changes were made, `None` if all already present.
    fn append_scripts(&self, content: &str) -> Result<Option<String>> {
        let baseline_scripts = self.get_baseline_scripts()?;

        if baseline_scripts.is_empty() {
            tracing::warn!("No scripts found in baseline '{}'", self.baseline_name);
            return Ok(None);
        }

        // Filter out scripts already present
        let mut new_entries: Vec<(String, String)> = Vec::new();
        for (script_path, label) in &baseline_scripts {
            if !content.contains(script_path) {
                new_entries.push((script_path.clone(), label.clone()));
            }
        }

        if new_entries.is_empty() {
            return Ok(None);
        }

        tracing::info!("  Adding {} scripts", new_entries.len());

        let lines: Vec<&str> = content.lines().collect();

        // Format script entries with labels_include_all
        let formatted: Vec<Vec<String>> = new_entries
            .iter()
            .map(|(path, label)| {
                yaml_edit::format_profile_entry(
                    path,
                    None,
                    Some(std::slice::from_ref(label)),
                    None,
                    4, // standard indent for controls.scripts entries
                )
            })
            .collect();

        let flat: Vec<String> = formatted.into_iter().flatten().collect();

        // Try to find existing controls.scripts section
        if let Some(insert) =
            yaml_edit::find_nested_section_insert_point(&lines, &["controls", "scripts"])
        {
            return Ok(Some(yaml_edit::insert_lines_at(content, &insert, &flat)));
        }

        // controls.scripts doesn't exist — check if controls: exists
        let controls_exists = lines
            .iter()
            .any(|l| l.trim() == "controls:" || l.trim().starts_with("controls: "));

        if controls_exists {
            // Find end of controls section and insert scripts: block
            let controls_idx = lines
                .iter()
                .position(|l| l.trim() == "controls:" || l.trim().starts_with("controls: "))
                .unwrap();
            let controls_indent =
                lines[controls_idx].len() - lines[controls_idx].trim_start().len();
            let mut insert_at = controls_idx + 1;
            for (i, line) in lines.iter().enumerate().skip(controls_idx + 1) {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    insert_at = i + 1;
                    continue;
                }
                let indent = line.len() - line.trim_start().len();
                if indent <= controls_indent {
                    break;
                }
                insert_at = i + 1;
            }

            let pad = " ".repeat(controls_indent + 2);
            let mut new_lines = vec![format!("{pad}scripts:")];
            new_lines.extend(flat);

            let insert = yaml_edit::InsertPoint {
                line: insert_at,
                indent: controls_indent + 4,
                section_exists: false,
            };
            return Ok(Some(yaml_edit::insert_lines_at(
                content, &insert, &new_lines,
            )));
        }

        // No controls section at all — append
        let mut result = content.to_string();
        if !result.ends_with('\n') {
            result.push('\n');
        }
        result.push_str("\ncontrols:\n  scripts:\n");
        for line in &flat {
            result.push_str(line);
            result.push('\n');
        }
        Ok(Some(result))
    }

    /// Read baseline.toml and extract profile paths
    fn get_baseline_profiles(&self) -> Result<Vec<String>> {
        let baseline_file = self
            .output_base
            .join("lib/mscp")
            .join(&self.baseline_name)
            .join("baseline.toml");

        if !baseline_file.exists() {
            return Ok(vec![]);
        }

        let content = std::fs::read_to_string(&baseline_file)?;
        let baseline: crate::models::BaselineReference = toml::from_str(&content)?;

        let mut profiles = Vec::new();

        for profile in baseline.profiles {
            // Convert relative path to team-relative path
            let team_relative = format!(
                "../lib/mscp/{}/{}",
                self.baseline_name,
                profile.path.trim_start_matches("./")
            );
            profiles.push(team_relative);
        }

        Ok(profiles)
    }

    /// Read baseline.toml and extract script paths with labels
    fn get_baseline_scripts(&self) -> Result<Vec<(String, String)>> {
        let baseline_file = self
            .output_base
            .join("lib/mscp")
            .join(&self.baseline_name)
            .join("baseline.toml");

        if !baseline_file.exists() {
            return Ok(vec![]);
        }

        let content = std::fs::read_to_string(&baseline_file)?;
        let baseline: crate::models::BaselineReference = toml::from_str(&content)?;

        let mut scripts = Vec::new();

        for script in baseline.scripts {
            // Get label from labels_include_all (first label)
            let label = script
                .labels_include_all
                .first()
                .cloned()
                .unwrap_or_else(|| format!("mscp-{}", self.baseline_name));

            // Convert relative path to team-relative path
            let team_relative = format!(
                "../lib/mscp/{}/{}",
                self.baseline_name,
                script.path.trim_start_matches("./")
            );
            scripts.push((team_relative, label));
        }

        Ok(scripts)
    }

    /// List available team files
    fn list_available_teams(&self) -> Result<Vec<String>> {
        let teams_dir = self.output_base.join("fleets");

        if !teams_dir.exists() {
            return Ok(vec![]);
        }

        let mut teams = Vec::new();

        for entry in std::fs::read_dir(&teams_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("yml")
                && let Some(name) = path.file_stem().and_then(|s| s.to_str())
            {
                // Skip example teams
                if !path.to_string_lossy().contains("example") {
                    teams.push(name.to_string());
                }
            }
        }

        teams.sort();
        Ok(teams)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_profile_path_conversion() {
        let updater = TeamUpdater::new("/tmp/test", "800-53r5_high".to_string());

        // Test relative path conversion
        let baseline_path = "./profiles/com.apple.security.firewall.mobileconfig";
        let expected =
            "../lib/mscp/800-53r5_high/profiles/com.apple.security.firewall.mobileconfig";

        let result = format!(
            "../lib/mscp/{}/{}",
            updater.baseline_name,
            baseline_path.trim_start_matches("./")
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn test_validate_teams_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let teams_dir = tmp.path().join("fleets");
        fs::create_dir_all(&teams_dir).unwrap();
        fs::write(teams_dir.join("alpha.yml"), "name: alpha\n").unwrap();

        let updater = TeamUpdater::new(tmp.path(), "cis_lvl2".to_string());
        let result = updater.validate_teams(&["alpha".to_string(), "nonexistent".to_string()]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonexistent"));
        assert!(err.contains("alpha"));
    }

    #[test]
    fn test_validate_teams_all_present() {
        let tmp = tempfile::TempDir::new().unwrap();
        let teams_dir = tmp.path().join("fleets");
        fs::create_dir_all(&teams_dir).unwrap();
        fs::write(teams_dir.join("alpha.yml"), "name: alpha\n").unwrap();
        fs::write(teams_dir.join("beta.yml"), "name: beta\n").unwrap();

        let updater = TeamUpdater::new(tmp.path(), "cis_lvl2".to_string());
        assert!(
            updater
                .validate_teams(&["alpha".to_string(), "beta".to_string()])
                .is_ok()
        );
    }

    #[test]
    fn test_add_labels_to_default_preserves_comments() {
        let tmp = tempfile::TempDir::new().unwrap();
        let default_file = tmp.path().join("default.yml");
        fs::write(
            &default_file,
            "# Fleet GitOps default configuration\norg_settings:\n  org_name: Test\n\n# Labels for scoping\nlabels:\n  - path: ./lib/all/labels/existing.yml\n",
        ).unwrap();

        let updater = TeamUpdater::new(tmp.path(), "cis_lvl2".to_string());
        updater.add_labels_to_default().unwrap();

        let content = fs::read_to_string(&default_file).unwrap();
        // Comment should be preserved
        assert!(content.contains("# Fleet GitOps default configuration"));
        assert!(content.contains("# Labels for scoping"));
        // New label should be added
        assert!(content.contains("./lib/all/labels/mscp-cis_lvl2.labels.yml"));
        // Existing label still there
        assert!(content.contains("./lib/all/labels/existing.yml"));
    }

    #[test]
    fn test_add_labels_to_default_idempotent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let default_file = tmp.path().join("default.yml");
        fs::write(
            &default_file,
            "labels:\n  - path: ./lib/all/labels/mscp-cis_lvl2.labels.yml\n",
        )
        .unwrap();

        let updater = TeamUpdater::new(tmp.path(), "cis_lvl2".to_string());
        updater.add_labels_to_default().unwrap();

        let content = fs::read_to_string(&default_file).unwrap();
        // Should not duplicate
        assert_eq!(content.matches("mscp-cis_lvl2").count(), 1);
    }

    #[test]
    fn test_append_profiles_preserves_comments() {
        let content = "# Team: Blue\nname: fleet-air-blue\n\n# Controls section\ncontrols:\n  macos_settings:\n    custom_settings:\n      - path: ../lib/macos/configuration-profiles/existing.mobileconfig\n";

        let updater = TeamUpdater::new("/tmp/test", "cis_lvl2".to_string());
        // append_profiles reads from baseline.toml which doesn't exist — returns None
        let result = updater.append_profiles(content).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_append_scripts_preserves_comments() {
        let content = "# Team: Blue\nname: fleet-air-blue\n\n# Controls section\ncontrols:\n  scripts:\n    - path: ../lib/macos/scripts/existing.sh\n";

        let updater = TeamUpdater::new("/tmp/test", "cis_lvl2".to_string());
        let result = updater.append_scripts(content).unwrap();
        assert!(result.is_none());
    }
}
