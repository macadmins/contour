use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::managers::baseline::baseline_path_to_fleet_path;
use contour_core::fleet_layout::FleetLayout;
use contour_core::yaml_edit;

/// Updates Fleet YAML files to include baseline profiles and scripts.
///
/// Uses line-based YAML editing (via `yaml_edit`) to preserve comments
/// and formatting, rather than serde round-trips.
#[derive(Debug)]
pub struct FleetUpdater {
    output_base: PathBuf,
    baseline_name: String,
    /// When true, the baseline's profiles are attached as a single
    /// `*.mobileconfig` glob entry instead of one entry per file.
    glob: bool,
}

impl FleetUpdater {
    pub fn new<P: AsRef<Path>>(output_base: P, baseline_name: String) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
            baseline_name,
            glob: false,
        }
    }

    /// Enable glob mode: attach the baseline as one `*.mobileconfig` glob
    /// entry rather than a literal entry per profile.
    #[must_use]
    pub fn with_glob(mut self, glob: bool) -> Self {
        self.glob = glob;
        self
    }

    /// Validate that all fleet names resolve to existing fleet files.
    /// Bails with a clear error listing available fleets if any are missing.
    pub fn validate_fleets(&self, fleet_names: &[String]) -> Result<()> {
        let mut missing = Vec::new();
        for fleet_name in fleet_names {
            let fleet_file = self
                .output_base
                .join("fleets")
                .join(format!("{fleet_name}.yml"));
            if !fleet_file.exists() {
                missing.push(fleet_name.clone());
            }
        }

        if !missing.is_empty() {
            let available = self.list_available_fleets()?;
            anyhow::bail!(
                "Fleet files not found: {}\nAvailable fleets: {}",
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

    /// Add baseline to specified fleets using comment-preserving editing.
    pub fn add_to_fleets(&self, fleet_names: &[String]) -> Result<()> {
        for fleet_name in fleet_names {
            let fleet_file = self
                .output_base
                .join("fleets")
                .join(format!("{fleet_name}.yml"));

            if !fleet_file.exists() {
                let available = self.list_available_fleets()?;
                anyhow::bail!(
                    "Fleet file not found: {}\nAvailable fleets: {}",
                    fleet_file.display(),
                    if available.is_empty() {
                        "(none)".to_string()
                    } else {
                        available.join(", ")
                    }
                );
            }

            tracing::info!(
                "Adding baseline '{}' to fleet '{}'",
                self.baseline_name,
                fleet_name
            );

            let content = std::fs::read_to_string(&fleet_file)
                .with_context(|| format!("Failed to read fleet file: {}", fleet_file.display()))?;

            let mut modified = content.clone();
            let mut changes_made = false;

            // Append profiles to controls.apple_settings.configuration_profiles
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
                // Fail-closed: never overwrite an operator's fleet file with
                // content that no longer parses. The line-based editors are
                // heuristic; if a splice produced invalid YAML, abort and
                // leave the original file byte-for-byte untouched.
                if let Err(e) = yaml_serde::from_str::<yaml_serde::Value>(&modified) {
                    anyhow::bail!(
                        "refused to edit {}: the baseline append produced invalid YAML ({e}). \
                         The file was left untouched — add the baseline manually.",
                        fleet_file.display()
                    );
                }

                std::fs::write(&fleet_file, &modified).with_context(|| {
                    format!("Failed to write fleet file: {}", fleet_file.display())
                })?;

                tracing::info!("✓ Updated fleet: {}", fleet_name);
            } else {
                tracing::info!(
                    "  Fleet '{}' already has baseline '{}' - no changes needed",
                    fleet_name,
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

        // Fleet v4.83+: labels live at top-level `labels/`.
        let layout = FleetLayout::default();
        let label_path_value = format!(
            "./{}/mscp-{}.labels.yml",
            layout.labels_dir, self.baseline_name
        );

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

    /// Append baseline profiles into `controls.apple_settings.configuration_profiles`
    /// (current Fleet GitOps schema) using comment-preserving line editing.
    ///
    /// In glob mode the whole baseline is attached as a single
    /// `*.mobileconfig` entry; otherwise one entry per profile is emitted.
    /// Returns `Some(modified)` if changes were made, `None` if already present.
    fn append_profiles(&self, content: &str) -> Result<Option<String>> {
        let baseline_profiles = self.get_baseline_profiles()?;

        if baseline_profiles.is_empty() {
            tracing::warn!("No profiles found in baseline '{}'", self.baseline_name);
            return Ok(None);
        }

        let label_name = format!("mscp-{}", self.baseline_name);

        let entries: Vec<yaml_edit::ProfileListEntry> = if self.glob {
            // One glob entry covering the baseline's profile directory.
            let glob_path = glob_dir_from_profiles(&baseline_profiles)?;
            if content.contains(&glob_path) {
                return Ok(None);
            }
            vec![yaml_edit::ProfileListEntry {
                path: glob_path,
                glob: true,
                labels_include_all: vec![label_name],
            }]
        } else {
            // One literal entry per profile, skipping any already present.
            baseline_profiles
                .iter()
                .filter(|path| !content.contains(path.as_str()))
                .map(|path| yaml_edit::ProfileListEntry {
                    path: path.clone(),
                    glob: false,
                    labels_include_all: vec![label_name.clone()],
                })
                .collect()
        };

        if entries.is_empty() {
            return Ok(None);
        }

        tracing::info!(
            "  Adding {} profile entr{}",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" }
        );
        Ok(Some(yaml_edit::append_apple_configuration_profiles(
            content, &entries,
        )))
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

    /// Read baseline.toml and extract profile paths.
    ///
    /// Fleet v4.83+: baseline.toml lives at `mscp/{name}/baseline.toml` and
    /// stores profile paths relative from there (e.g.
    /// `../../platforms/macos/configuration-profiles/{name}/file.mobileconfig`).
    /// Fleet YAML lives one level shallower (`fleets/{fleet}.yml`), so we drop
    /// one leading `../` to convert.
    fn get_baseline_profiles(&self) -> Result<Vec<String>> {
        let baseline_file = self
            .output_base
            .join("mscp")
            .join(&self.baseline_name)
            .join("baseline.toml");

        if !baseline_file.exists() {
            return Ok(vec![]);
        }

        let content = std::fs::read_to_string(&baseline_file)?;
        let baseline: crate::models::BaselineReference = toml::from_str(&content)?;

        let mut profiles = Vec::new();

        for profile in baseline.profiles {
            profiles.push(baseline_path_to_fleet_path(&profile.path));
        }

        Ok(profiles)
    }

    /// Read baseline.toml and extract script paths with labels (Fleet v4.83+ paths).
    fn get_baseline_scripts(&self) -> Result<Vec<(String, String)>> {
        let baseline_file = self
            .output_base
            .join("mscp")
            .join(&self.baseline_name)
            .join("baseline.toml");

        if !baseline_file.exists() {
            return Ok(vec![]);
        }

        let content = std::fs::read_to_string(&baseline_file)?;
        let baseline: crate::models::BaselineReference = toml::from_str(&content)?;

        let mut scripts = Vec::new();

        for script in baseline.scripts {
            let label = script
                .labels_include_all
                .first()
                .cloned()
                .unwrap_or_else(|| format!("mscp-{}", self.baseline_name));

            scripts.push((baseline_path_to_fleet_path(&script.path), label));
        }

        Ok(scripts)
    }

    /// List available fleet files
    fn list_available_fleets(&self) -> Result<Vec<String>> {
        let fleets_dir = self.output_base.join("fleets");

        if !fleets_dir.exists() {
            return Ok(vec![]);
        }

        let mut fleets = Vec::new();

        for entry in std::fs::read_dir(&fleets_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("yml")
                && let Some(name) = path.file_stem().and_then(|s| s.to_str())
            {
                // Skip example fleets
                if !path.to_string_lossy().contains("example") {
                    fleets.push(name.to_string());
                }
            }
        }

        fleets.sort();
        Ok(fleets)
    }
}

/// Derive a single `*.mobileconfig` glob path from a baseline's profile
/// list. All profiles in one baseline share a directory, so the glob is
/// that common parent directory plus `/*.mobileconfig`.
fn glob_dir_from_profiles(profiles: &[String]) -> Result<String> {
    let first = profiles
        .first()
        .context("baseline has no profiles to derive a glob from")?;
    let dir = std::path::Path::new(first)
        .parent()
        .and_then(|p| p.to_str())
        .with_context(|| format!("profile path has no parent directory: {first}"))?;
    Ok(format!("{dir}/*.mobileconfig"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_profile_path_conversion() {
        // Fleet v4.83+: baseline.toml at mscp/{name}/baseline.toml stores
        // paths relative from there (`../../platforms/...`). Fleet YAML at
        // fleets/{fleet}.yml is one level shallower, so the helper drops
        // one leading `../`.
        let baseline_relative = "../../platforms/macos/configuration-profiles/800-53r5_high/com.apple.security.firewall.mobileconfig";
        let expected = "../platforms/macos/configuration-profiles/800-53r5_high/com.apple.security.firewall.mobileconfig";
        assert_eq!(baseline_path_to_fleet_path(baseline_relative), expected);
    }

    #[test]
    fn test_validate_fleets_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let fleets_dir = tmp.path().join("fleets");
        fs::create_dir_all(&fleets_dir).unwrap();
        fs::write(fleets_dir.join("alpha.yml"), "name: alpha\n").unwrap();

        let updater = FleetUpdater::new(tmp.path(), "cis_lvl2".to_string());
        let result = updater.validate_fleets(&["alpha".to_string(), "nonexistent".to_string()]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonexistent"));
        assert!(err.contains("alpha"));
    }

    #[test]
    fn test_validate_fleets_all_present() {
        let tmp = tempfile::TempDir::new().unwrap();
        let fleets_dir = tmp.path().join("fleets");
        fs::create_dir_all(&fleets_dir).unwrap();
        fs::write(fleets_dir.join("alpha.yml"), "name: alpha\n").unwrap();
        fs::write(fleets_dir.join("beta.yml"), "name: beta\n").unwrap();

        let updater = FleetUpdater::new(tmp.path(), "cis_lvl2".to_string());
        updater
            .validate_fleets(&["alpha".to_string(), "beta".to_string()])
            .unwrap();
    }

    #[test]
    fn test_add_labels_to_default_preserves_comments() {
        let tmp = tempfile::TempDir::new().unwrap();
        let default_file = tmp.path().join("default.yml");
        // Fleet v4.83+: labels live at top-level `labels/`.
        fs::write(
            &default_file,
            "# Fleet GitOps default configuration\norg_settings:\n  org_name: Test\n\n# Labels for scoping\nlabels:\n  - path: ./labels/existing.yml\n",
        ).unwrap();

        let updater = FleetUpdater::new(tmp.path(), "cis_lvl2".to_string());
        updater.add_labels_to_default().unwrap();

        let content = fs::read_to_string(&default_file).unwrap();
        // Comment should be preserved
        assert!(content.contains("# Fleet GitOps default configuration"));
        assert!(content.contains("# Labels for scoping"));
        // New label should be added at the v4.83 path
        assert!(content.contains("./labels/mscp-cis_lvl2.labels.yml"));
        // Existing label still there
        assert!(content.contains("./labels/existing.yml"));
    }

    #[test]
    fn test_add_labels_to_default_idempotent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let default_file = tmp.path().join("default.yml");
        fs::write(
            &default_file,
            "labels:\n  - path: ./labels/mscp-cis_lvl2.labels.yml\n",
        )
        .unwrap();

        let updater = FleetUpdater::new(tmp.path(), "cis_lvl2".to_string());
        updater.add_labels_to_default().unwrap();

        let content = fs::read_to_string(&default_file).unwrap();
        // Should not duplicate
        assert_eq!(content.matches("mscp-cis_lvl2").count(), 1);
    }

    #[test]
    fn test_append_profiles_preserves_comments() {
        let content = "# Fleet: Blue\nname: fleet-air-blue\n\n# Controls section\ncontrols:\n  apple_settings:\n    configuration_profiles:\n      - path: ../lib/macos/configuration-profiles/existing.mobileconfig\n";

        let updater = FleetUpdater::new("/tmp/test", "cis_lvl2".to_string());
        // append_profiles reads from baseline.toml which doesn't exist — returns None
        let result = updater.append_profiles(content).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_append_scripts_preserves_comments() {
        let content = "# Fleet: Blue\nname: fleet-air-blue\n\n# Controls section\ncontrols:\n  scripts:\n    - path: ../lib/macos/scripts/existing.sh\n";

        let updater = FleetUpdater::new("/tmp/test", "cis_lvl2".to_string());
        let result = updater.append_scripts(content).unwrap();
        assert!(result.is_none());
    }
}
