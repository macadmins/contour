use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::models::baseline_reference::BaselineReference;

/// Information about a baseline discovered in the output directory
#[derive(Debug, Clone, Serialize)]
pub struct BaselineInfo {
    pub name: String,
    pub platform: String,
    #[allow(dead_code, reason = "reserved for future use")]
    pub path: PathBuf,
    pub generated_at: Option<DateTime<Utc>>,
    pub profile_count: usize,
    pub script_count: usize,
    pub referenced_by: Vec<PathBuf>,
}

/// Indexes and discovers available baselines.
#[derive(Debug)]
pub struct BaselineIndex {
    output_base: PathBuf,
}

impl BaselineIndex {
    pub fn new(output_base: PathBuf) -> Self {
        Self { output_base }
    }

    /// List all baselines in the output directory
    pub fn list_baselines(&self) -> Result<Vec<BaselineInfo>> {
        let mscp_dir = self.output_base.join("lib/mscp");
        if !mscp_dir.exists() {
            return Ok(vec![]);
        }

        let mut baselines = Vec::new();

        for entry in std::fs::read_dir(&mscp_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            // Skip special directories
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if dir_name.starts_with('.') || dir_name == "versions" {
                continue;
            }

            // Look for baseline.toml or baseline.yml
            if let Some(info) = self.parse_baseline_info(&path)? {
                baselines.push(info);
            }
        }

        Ok(baselines)
    }

    /// Parse baseline information from a baseline directory
    fn parse_baseline_info(&self, baseline_path: &Path) -> Result<Option<BaselineInfo>> {
        let baseline_name = baseline_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Try TOML first, then YAML
        let toml_path = baseline_path.join("baseline.toml");
        let yaml_path = baseline_path.join("baseline.yml");

        let (_manifest_path, baseline_ref) = if toml_path.exists() {
            let content = std::fs::read_to_string(&toml_path)?;
            let baseline: BaselineReference =
                toml::from_str(&content).context("Failed to parse baseline.toml")?;
            (toml_path, Some(baseline))
        } else if yaml_path.exists() {
            // For old YAML format, we don't parse it - just count files manually
            (yaml_path, None)
        } else {
            return Ok(None);
        };

        let (platform, generated_at, profile_count, script_count) =
            if let Some(ref baseline) = baseline_ref {
                (
                    baseline.baseline.platform.clone(),
                    Some(baseline.baseline.generated_at),
                    baseline.profiles.len(),
                    baseline.scripts.len(),
                )
            } else {
                // Count manually for YAML format
                let profile_count =
                    self.count_files(&baseline_path.join("profiles"), "mobileconfig")?;
                let script_count = self.count_files(&baseline_path.join("scripts"), "sh")?;
                ("unknown".to_string(), None, profile_count, script_count)
            };

        // Find team files that reference this baseline
        let referenced_by = self.find_team_references(&baseline_name)?;

        Ok(Some(BaselineInfo {
            name: baseline_name,
            platform,
            path: baseline_path.to_path_buf(),
            generated_at,
            profile_count,
            script_count,
            referenced_by,
        }))
    }

    /// Count files with a specific extension in a directory
    fn count_files(&self, dir: &Path, extension: &str) -> Result<usize> {
        if !dir.exists() {
            return Ok(0);
        }

        let count = std::fs::read_dir(dir)?
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext == extension)
            })
            .count();

        Ok(count)
    }

    /// Find team files that reference a specific baseline
    fn find_team_references(&self, baseline_name: &str) -> Result<Vec<PathBuf>> {
        let fleets_dir = self.output_base.join("fleets");
        if !fleets_dir.exists() {
            return Ok(vec![]);
        }

        let mut references = Vec::new();
        let search_pattern = format!("lib/mscp/{baseline_name}/");

        for entry in std::fs::read_dir(&fleets_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some("yml") {
                continue;
            }

            // Skip example directory
            if path.to_str().unwrap_or("").contains("/examples/") {
                continue;
            }

            // Read file and check if it contains baseline reference
            if let Ok(content) = std::fs::read_to_string(&path)
                && content.contains(&search_pattern)
            {
                references.push(path);
            }
        }

        Ok(references)
    }

    /// Clean (remove) a baseline and all associated files
    pub fn clean_baseline(&self, baseline_name: &str, force: bool) -> Result<CleanReport> {
        let baseline_path = self.output_base.join("lib/mscp").join(baseline_name);

        if !baseline_path.exists() {
            anyhow::bail!(
                "Baseline '{baseline_name}' not found at {}",
                baseline_path.display()
            );
        }

        // Check for team file references
        let team_refs = self.find_team_references(baseline_name)?;
        if !team_refs.is_empty() && !force {
            anyhow::bail!(
                "Baseline '{}' is referenced by {} team file(s). Use --force to remove anyway.\nReferenced by:\n{}",
                baseline_name,
                team_refs.len(),
                team_refs
                    .iter()
                    .map(|p| format!("  - {}", p.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }

        let mut report = CleanReport {
            baseline_name: baseline_name.to_string(),
            removed_files: Vec::new(),
            warnings: Vec::new(),
        };

        // Remove baseline directory
        if baseline_path.exists() {
            std::fs::remove_dir_all(&baseline_path)
                .context("Failed to remove baseline directory")?;
            report.removed_files.push(baseline_path);
        }

        // Remove label file
        let label_file = self
            .output_base
            .join("lib/all/labels")
            .join(format!("mscp-{baseline_name}.labels.yml"));

        if label_file.exists() {
            std::fs::remove_file(&label_file).context("Failed to remove label file")?;
            report.removed_files.push(label_file);
        }

        // Remove example team file
        let example_file = self
            .output_base
            .join("fleets/examples")
            .join(format!("mscp-{baseline_name}-example.yml"));

        if example_file.exists() {
            std::fs::remove_file(&example_file).context("Failed to remove example team file")?;
            report.removed_files.push(example_file);
        }

        // Add warnings about team file references
        for team_ref in team_refs {
            report.warnings.push(format!(
                "Team file {} still references this baseline and may be broken",
                team_ref.display()
            ));
        }

        Ok(report)
    }

    /// Migrate team files from one baseline to another
    ///
    /// This function removes all mSCP-managed sections from the old baseline
    /// and inserts the new baseline's profiles and scripts from baseline.toml
    pub fn migrate_team_file(
        &self,
        team_file: &Path,
        from_baseline: &str,
        to_baseline: &str,
        create_backup: bool,
    ) -> Result<MigrationReport> {
        if !team_file.exists() {
            anyhow::bail!("Team file not found: {}", team_file.display());
        }

        let content = std::fs::read_to_string(team_file)?;

        // Check if file actually references the old baseline
        let old_pattern = format!("lib/mscp/{from_baseline}/");
        if !content.contains(&old_pattern) {
            anyhow::bail!("Team file does not reference baseline '{from_baseline}'");
        }

        // Load the new baseline manifest
        let new_baseline_path = self
            .output_base
            .join("lib/mscp")
            .join(to_baseline)
            .join("baseline.toml");

        if !new_baseline_path.exists() {
            anyhow::bail!(
                "New baseline manifest not found: {}. Generate the baseline first.",
                new_baseline_path.display()
            );
        }

        let new_baseline_content = std::fs::read_to_string(&new_baseline_path)?;
        let new_baseline: BaselineReference =
            toml::from_str(&new_baseline_content).context("Failed to parse new baseline.toml")?;

        // Create backup if requested
        if create_backup {
            let backup_path = team_file.with_extension("yml.bak");
            std::fs::copy(team_file, &backup_path)?;
        }

        // Parse the team YAML
        let mut team_yaml: yaml_serde::Value =
            yaml_serde::from_str(&content).context("Failed to parse team file as YAML")?;

        let mut path_replacements = 0;

        // Remove old mSCP profiles and scripts
        if let Some(controls) = team_yaml.get_mut("controls") {
            if let Some(macos_settings) = controls.get_mut("macos_settings")
                && let Some(custom_settings) = macos_settings.get_mut("custom_settings")
                && let Some(settings_array) = custom_settings.as_sequence_mut()
            {
                settings_array.retain(|item| {
                    if let Some(path) = item.get("path").and_then(|p| p.as_str()) {
                        let should_remove = path.contains(&old_pattern);
                        if should_remove {
                            path_replacements += 1;
                        }
                        !should_remove
                    } else {
                        true
                    }
                });

                // Add new baseline profiles
                for profile in &new_baseline.profiles {
                    let team_relative_path = format!(
                        "../lib/mscp/{}/{}",
                        to_baseline,
                        profile.path.trim_start_matches("./")
                    );

                    let mut profile_entry = yaml_serde::Mapping::new();
                    profile_entry.insert(
                        yaml_serde::Value::String("path".to_string()),
                        yaml_serde::Value::String(team_relative_path),
                    );

                    if !profile.labels_include_all.is_empty() {
                        let labels: Vec<yaml_serde::Value> = profile
                            .labels_include_all
                            .iter()
                            .map(|l| yaml_serde::Value::String(l.clone()))
                            .collect();
                        profile_entry.insert(
                            yaml_serde::Value::String("labels_include_all".to_string()),
                            yaml_serde::Value::Sequence(labels),
                        );
                    }

                    settings_array.push(yaml_serde::Value::Mapping(profile_entry));
                }
            }

            // Handle scripts
            if let Some(scripts) = controls.get_mut("scripts")
                && let Some(scripts_array) = scripts.as_sequence_mut()
            {
                scripts_array.retain(|item| {
                    if let Some(path) = item.get("path").and_then(|p| p.as_str()) {
                        let should_remove = path.contains(&old_pattern);
                        if should_remove {
                            path_replacements += 1;
                        }
                        !should_remove
                    } else {
                        true
                    }
                });

                // Add new baseline scripts
                for script in &new_baseline.scripts {
                    let team_relative_path = format!(
                        "../lib/mscp/{}/{}",
                        to_baseline,
                        script.path.trim_start_matches("./")
                    );

                    let mut script_entry = yaml_serde::Mapping::new();
                    script_entry.insert(
                        yaml_serde::Value::String("path".to_string()),
                        yaml_serde::Value::String(team_relative_path),
                    );

                    if !script.labels_include_all.is_empty() {
                        let labels: Vec<yaml_serde::Value> = script
                            .labels_include_all
                            .iter()
                            .map(|l| yaml_serde::Value::String(l.clone()))
                            .collect();
                        script_entry.insert(
                            yaml_serde::Value::String("labels_include_all".to_string()),
                            yaml_serde::Value::Sequence(labels),
                        );
                    }

                    scripts_array.push(yaml_serde::Value::Mapping(script_entry));
                }
            }
        }

        // Also update any remaining label references in comments or other places
        let yaml_output = yaml_serde::to_string(&team_yaml)?;
        let old_label_pattern = format!("mscp-{from_baseline}");
        let new_label_pattern = format!("mscp-{to_baseline}");
        let label_replacements = yaml_output.matches(&old_label_pattern).count();
        let final_output = yaml_output.replace(&old_label_pattern, &new_label_pattern);

        // Write new content
        std::fs::write(team_file, &final_output)?;

        Ok(MigrationReport {
            team_file: team_file.to_path_buf(),
            from_baseline: from_baseline.to_string(),
            to_baseline: to_baseline.to_string(),
            path_replacements,
            label_replacements,
        })
    }

    /// Verify `GitOps` repository integrity - check for orphaned references
    pub fn verify_references(&self) -> Result<VerificationReport> {
        let mut report = VerificationReport {
            orphaned_label_references: Vec::new(),
            orphaned_baseline_references: Vec::new(),
            missing_baselines: Vec::new(),
            valid: true,
        };

        // Get list of actual baselines
        let baselines = self.list_baselines()?;
        let baseline_names: Vec<String> = baselines.iter().map(|b| b.name.clone()).collect();

        // Check default.yml for orphaned label references
        let default_file = self.output_base.join("default.yml");
        if default_file.exists()
            && let Ok(content) = std::fs::read_to_string(&default_file)
            && let Ok(yaml) = yaml_serde::from_str::<yaml_serde::Value>(&content)
            && let Some(labels) = yaml.get("labels").and_then(|l| l.as_sequence())
        {
            for label_entry in labels {
                if let Some(path) = label_entry.get("path").and_then(|p| p.as_str()) {
                    let full_path = self.output_base.join(path.trim_start_matches("./"));
                    if !full_path.exists() {
                        report.orphaned_label_references.push(OrphanedReference {
                            file: default_file.clone(),
                            reference: path.to_string(),
                            reason: "Label file does not exist".to_string(),
                        });
                        report.valid = false;
                    }

                    // Check if label references a baseline that doesn't exist
                    if path.contains("mscp-") {
                        let baseline_name = path
                            .trim_start_matches("./lib/all/labels/mscp-")
                            .trim_end_matches(".labels.yml");

                        if !baseline_names.contains(&baseline_name.to_string()) {
                            report.orphaned_label_references.push(OrphanedReference {
                                file: default_file.clone(),
                                reference: path.to_string(),
                                reason: format!(
                                    "References non-existent baseline '{baseline_name}'"
                                ),
                            });
                            report.valid = false;
                        }
                    }
                }
            }
        }

        // Check team files for orphaned baseline references
        let fleets_dir = self.output_base.join("fleets");
        if fleets_dir.exists() {
            for entry in std::fs::read_dir(&fleets_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.extension().and_then(|e| e.to_str()) != Some("yml") {
                    continue;
                }

                // Skip example directory
                if path.to_str().unwrap_or("").contains("/examples/") {
                    continue;
                }

                if let Ok(content) = std::fs::read_to_string(&path) {
                    // Check for references to baselines that don't exist
                    if content.contains("lib/mscp/") {
                        for line in content.lines() {
                            if line.contains("lib/mscp/") && !line.trim().starts_with('#') {
                                // Extract baseline name from path
                                if let Some(start) = line.find("lib/mscp/") {
                                    let after_mscp = &line[start + 9..];
                                    if let Some(end) = after_mscp.find('/') {
                                        let referenced_baseline = &after_mscp[..end];

                                        if !baseline_names
                                            .contains(&referenced_baseline.to_string())
                                        {
                                            report.orphaned_baseline_references.push(
                                                OrphanedReference {
                                                    file: path.clone(),
                                                    reference: referenced_baseline.to_string(),
                                                    reason: "Baseline directory does not exist"
                                                        .to_string(),
                                                },
                                            );
                                            report.valid = false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(report)
    }
}

/// Report of files removed during baseline cleanup
#[derive(Debug)]
pub struct CleanReport {
    pub baseline_name: String,
    pub removed_files: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

/// Report of changes made during team file migration
#[derive(Debug)]
pub struct MigrationReport {
    #[allow(dead_code, reason = "reserved for future use")]
    pub team_file: PathBuf,
    #[allow(dead_code, reason = "reserved for future use")]
    pub from_baseline: String,
    #[allow(dead_code, reason = "reserved for future use")]
    pub to_baseline: String,
    pub path_replacements: usize,
    pub label_replacements: usize,
}

/// Report of orphaned references found during verification
#[derive(Debug)]
pub struct VerificationReport {
    pub orphaned_label_references: Vec<OrphanedReference>,
    pub orphaned_baseline_references: Vec<OrphanedReference>,
    #[allow(dead_code, reason = "reserved for future use")]
    pub missing_baselines: Vec<String>,
    pub valid: bool,
}

/// An orphaned reference in a `GitOps` file
#[derive(Debug, Clone)]
pub struct OrphanedReference {
    pub file: PathBuf,
    pub reference: String,
    pub reason: String,
}
