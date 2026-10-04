use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use contour_core::fleet_layout::FleetLayout;
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::models::baseline_reference::BaselineReference;

/// Information about a baseline discovered in the output directory
#[derive(Debug, Clone, Serialize)]
pub struct BaselineInfo {
    pub name: String,
    pub platform: String,
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

    /// List all baselines in the output directory.
    ///
    /// Fleet v4.83+: each baseline has a `mscp/{name}/baseline.toml` manifest.
    /// We list immediate children of `mscp/`, skipping the `versions/` subdir
    /// which holds the version manifest, not a baseline.
    pub fn list_baselines(&self) -> Result<Vec<BaselineInfo>> {
        let mscp_dir = self.output_base.join("mscp");
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

        // Find fleet files that reference this baseline
        let referenced_by = self.find_fleet_references(&baseline_name)?;

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

    /// Find fleet files that reference a specific baseline.
    ///
    /// Fleet v4.83+ fleet YAMLs reference baselines in two ways:
    ///   - profile/script/policy paths under `../platforms/macos/.../{baseline}/`
    ///   - the baseline component manifest at `../mscp/{baseline}/`
    ///
    /// We detect either (see `baseline_reference_patterns`); the unique
    /// combination of `{baseline}/` after a v4.83 prefix is what makes this
    /// baseline-specific. The `mscp-{baseline}` label is not matched.
    fn find_fleet_references(&self, baseline_name: &str) -> Result<Vec<PathBuf>> {
        let fleets_dir = self.output_base.join("fleets");
        if !fleets_dir.exists() {
            return Ok(vec![]);
        }

        let layout = FleetLayout::default();
        let patterns = baseline_reference_patterns(&layout, baseline_name);

        let mut references = Vec::new();

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

            if let Ok(content) = std::fs::read_to_string(&path)
                && patterns.iter().any(|p| content.contains(p))
            {
                references.push(path);
            }
        }

        Ok(references)
    }

    /// Clean (remove) a baseline and all associated files.
    ///
    /// Fleet v4.83+: removes `mscp/{name}/` (baseline component dir),
    /// `labels/mscp-{name}.labels.yml`, and `fleets/examples/mscp-{name}-example.yml`.
    /// Artifacts under `platforms/macos/{kind}/{name}/` are left in place.
    pub fn clean_baseline(&self, baseline_name: &str, force: bool) -> Result<CleanReport> {
        let baseline_path = self.output_base.join("mscp").join(baseline_name);

        if !baseline_path.exists() {
            anyhow::bail!(
                "Baseline '{baseline_name}' not found at {}",
                baseline_path.display()
            );
        }

        // Check for fleet file references
        let fleet_refs = self.find_fleet_references(baseline_name)?;
        if !fleet_refs.is_empty() && !force {
            anyhow::bail!(
                "Baseline '{}' is referenced by {} fleet file(s). Use --force to remove anyway.\nReferenced by:\n{}",
                baseline_name,
                fleet_refs.len(),
                fleet_refs
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

        // Remove label file (Fleet v4.83+: top-level `labels/`, was `lib/all/labels/`)
        let layout = FleetLayout::default();
        let label_file = self
            .output_base
            .join(layout.labels_dir)
            .join(format!("mscp-{baseline_name}.labels.yml"));

        if label_file.exists() {
            std::fs::remove_file(&label_file).context("Failed to remove label file")?;
            report.removed_files.push(label_file);
        }

        // Remove example fleet file
        let example_file = self
            .output_base
            .join("fleets/examples")
            .join(format!("mscp-{baseline_name}-example.yml"));

        if example_file.exists() {
            std::fs::remove_file(&example_file).context("Failed to remove example fleet file")?;
            report.removed_files.push(example_file);
        }

        // Add warnings about fleet file references
        for fleet_ref in fleet_refs {
            report.warnings.push(format!(
                "Fleet file {} still references this baseline and may be broken",
                fleet_ref.display()
            ));
        }

        Ok(report)
    }

    /// Migrate fleet files from one baseline to another
    ///
    /// This function removes all mSCP-managed sections from the old baseline
    /// and inserts the new baseline's profiles and scripts from baseline.toml;
    /// `policies:` entries the fleet already took are re-pointed at
    /// `platforms/macos/policies/{to}/`.
    pub fn migrate_fleet_file(
        &self,
        fleet_file: &Path,
        from_baseline: &str,
        to_baseline: &str,
        create_backup: bool,
    ) -> Result<MigrationReport> {
        if !fleet_file.exists() {
            anyhow::bail!("Fleet file not found: {}", fleet_file.display());
        }

        let content = std::fs::read_to_string(fleet_file)?;

        // Check if file references the old baseline. Fleet v4.83 fleet YAMLs may
        // reference a baseline via several v4.83 path prefixes — match any of
        // them. (Pre-v4.83 outputs use `lib/mscp/{baseline}/`; that pattern is
        // detected separately via the legacy substring as a courtesy fallback,
        // since users may be migrating older repos.)
        let layout = FleetLayout::default();
        let from_patterns = baseline_reference_patterns(&layout, from_baseline);
        let legacy_pattern = format!("lib/mscp/{from_baseline}/");
        if !from_patterns.iter().any(|p| content.contains(p)) && !content.contains(&legacy_pattern)
        {
            anyhow::bail!("Fleet file does not reference baseline '{from_baseline}'");
        }

        // Load the new baseline manifest. Fleet v4.83+: at `mscp/{name}/baseline.toml`.
        let new_baseline_path = self
            .output_base
            .join("mscp")
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

        // Which entries belong to the old baseline is read from a parse, so
        // the match is on real `path` values — not on text that happens to
        // contain the baseline name, like a comment or the enroll secret.
        // The EDIT, though, is done on the text: parsing, modifying the tree
        // and serialising it back would drop every comment — the generated
        // header, its "Required environment variables" line, and anything an
        // operator had written in their own GitOps repo.
        let parsed: yaml_serde::Value =
            yaml_serde::from_str(&content).context("Failed to parse fleet file as YAML")?;
        let path_matches_old_baseline = |path: &str| -> bool {
            from_patterns.iter().any(|p| path.contains(p)) || path.contains(&legacy_pattern)
        };

        // The three places a baseline shows up in a fleet file. Leaving
        // `policies:` on the old baseline would deploy the new baseline's
        // profiles while reporting compliance against the old one's policies.
        //
        // The profile list is read and written under the spelling this file
        // already uses (contour_core::fleet_keys): a new key beside the old one
        // is the file Fleet rejects.
        let (settings_key, list_key) =
            contour_core::fleet_keys::spelling_in(&content.lines().collect::<Vec<_>>());
        let profiles_path: &[&str] = &["controls", settings_key, list_key];
        const SCRIPTS: &[&str] = &["controls", "scripts"];
        const POLICIES: &[&str] = &["policies"];
        let entries = |path: &[&str]| -> Vec<yaml_serde::Value> {
            let mut node = Some(&parsed);
            for key in path {
                node = node.and_then(|n| n.get(*key));
            }
            node.and_then(|n| n.as_sequence())
                .cloned()
                .unwrap_or_default()
        };
        let old_paths = |path: &[&str]| -> Vec<String> {
            entries(path)
                .iter()
                .filter_map(|e| e.get("path").and_then(|p| p.as_str()))
                .filter(|p| path_matches_old_baseline(p))
                .map(str::to_string)
                .collect()
        };

        // Glob entries (`paths:`) are not handled, so refuse rather than
        // leave a stale reference to the old baseline behind.
        let globs: Vec<String> = [profiles_path, SCRIPTS, POLICIES]
            .iter()
            .flat_map(|s| entries(s))
            .filter_map(|e| e.get("paths").and_then(|p| p.as_str()).map(str::to_string))
            .filter(|p| path_matches_old_baseline(p))
            .collect();
        if !globs.is_empty() {
            anyhow::bail!(
                "{} references baseline '{from_baseline}' through a glob ({}). migrate edits \
                 literal `path:` entries only and would leave the glob in place — replace it by \
                 hand, or regenerate the fleet file with --fleets.",
                fleet_file.display(),
                globs.join(", ")
            );
        }

        let old_profiles = old_paths(profiles_path);
        let old_scripts = old_paths(SCRIPTS);
        let old_policies = old_paths(POLICIES);

        // The indent the old entries sat at, so the new ones sit there too.
        // A section emptied by the removal has nothing left to copy it from,
        // and the default is a level deeper than contour's own generator
        // writes — valid YAML, and a needless diff in someone's GitOps repo.
        let indent_of = |paths: &[String]| -> Option<usize> {
            let first = paths.first()?;
            content.lines().find_map(|l| {
                let t = l.trim_start();
                (t.strip_prefix("- path: ").map(str::trim) == Some(first.as_str()))
                    .then(|| l.len() - t.len())
            })
        };
        let (profile_indent, script_indent, policy_indent) = (
            indent_of(&old_profiles),
            indent_of(&old_scripts),
            indent_of(&old_policies),
        );

        // Create backup if requested
        if create_backup {
            let backup_path = fleet_file.with_extension("yml.bak");
            std::fs::copy(fleet_file, &backup_path)?;
        }

        let to_remove: Vec<String> = old_profiles
            .iter()
            .chain(&old_scripts)
            .chain(&old_policies)
            .cloned()
            .collect();
        let (mut text, path_replacements) =
            contour_core::yaml_edit::remove_path_entries(&content, &to_remove);

        // What replaces them. Profiles and scripts come from the new
        // baseline's manifest; policies from the new baseline's policies
        // directory, since baseline.toml does not list them.
        let profile_lines: Vec<(String, Vec<String>)> = new_baseline
            .profiles
            .iter()
            .map(|p| {
                (
                    baseline_path_to_fleet_path(&p.path),
                    p.labels_include_all.clone(),
                )
            })
            .collect();
        // No labels on scripts, whatever baseline.toml records for them. Fleet's
        // GitOps schema has no label fields on `controls.scripts` entries, and
        // copying them across made every migrated fleet file one that
        // `fleetctl gitops` rejects. The generator never wrote them; migrate did.
        let script_lines: Vec<(String, Vec<String>)> = new_baseline
            .scripts
            .iter()
            .map(|s| (baseline_path_to_fleet_path(&s.path), Vec::new()))
            .collect();
        let policy_lines: Vec<(String, Vec<String>)> = if old_policies.is_empty() {
            // The fleet did not take this baseline's policies; do not start.
            Vec::new()
        } else {
            let dir = self
                .output_base
                .join(layout.macos_policies_subdir)
                .join(to_baseline);
            let mut files: Vec<String> = std::fs::read_dir(&dir)
                .with_context(|| {
                    format!(
                        "the fleet takes '{from_baseline}' policies, and '{to_baseline}' has no \
                         policies directory at {} — generate '{to_baseline}' first",
                        dir.display()
                    )
                })?
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
                .collect();
            files.sort();
            if files.is_empty() {
                anyhow::bail!(
                    "the fleet takes '{from_baseline}' policies, and {} holds none for \
                     '{to_baseline}' — generate it first, or the fleet would lose its \
                     compliance policies",
                    dir.display()
                );
            }
            files
                .into_iter()
                .map(|f| {
                    (
                        format!("../{}/{to_baseline}/{f}", layout.macos_policies_subdir),
                        Vec::new(),
                    )
                })
                .collect()
        };

        for (section, new_entries, indent) in [
            (profiles_path, &profile_lines, profile_indent),
            (SCRIPTS, &script_lines, script_indent),
            (POLICIES, &policy_lines, policy_indent),
        ] {
            if new_entries.is_empty() {
                continue;
            }
            text = insert_section_entries(&text, section, new_entries, indent);
        }

        // Generated header lines that name the baseline. The enroll-secret
        // line names the FLEET and is left alone, like `name:`.
        let text = text
            .lines()
            .map(|l| {
                let is_baseline_line = ["# mSCP Baseline:", "# Profiles:", "# Scripts:"]
                    .iter()
                    .any(|p| l.starts_with(p));
                if is_baseline_line {
                    l.replace(&format!("/{from_baseline}/"), &format!("/{to_baseline}/"))
                        .replace(
                            &format!("mSCP Baseline: {from_baseline}"),
                            &format!("mSCP Baseline: {to_baseline}"),
                        )
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + if content.ends_with('\n') { "\n" } else { "" };

        // Label references elsewhere — entries the operator added that target
        // the baseline's label, and comments that mention it.
        let old_label_pattern = format!("mscp-{from_baseline}");
        let new_label_pattern = format!("mscp-{to_baseline}");
        let label_replacements = text.matches(&old_label_pattern).count();
        let final_output = text.replace(&old_label_pattern, &new_label_pattern);

        // Never write a file that is not YAML, or that still points at the old
        // baseline. A line edit can go wrong in ways a tree edit cannot; this is
        // the price of keeping comments, and it is checked rather than hoped.
        let check: yaml_serde::Value = yaml_serde::from_str(&final_output).with_context(|| {
            format!(
                "migrating {} produced invalid YAML — nothing was written",
                fleet_file.display()
            )
        })?;
        let leftover: Vec<String> = [profiles_path, SCRIPTS, POLICIES]
            .iter()
            .flat_map(|s| {
                let mut node = Some(&check);
                for key in *s {
                    node = node.and_then(|n| n.get(*key));
                }
                node.and_then(|n| n.as_sequence())
                    .cloned()
                    .unwrap_or_default()
            })
            .filter_map(|e| e.get("path").and_then(|p| p.as_str()).map(str::to_string))
            .filter(|p| path_matches_old_baseline(p))
            .collect();
        if !leftover.is_empty() {
            anyhow::bail!(
                "migrating {} would leave {} reference(s) to '{from_baseline}' — nothing was \
                 written:\n  {}",
                fleet_file.display(),
                leftover.len(),
                leftover.join("\n  ")
            );
        }

        std::fs::write(fleet_file, &final_output)?;

        Ok(MigrationReport {
            fleet_file: fleet_file.to_path_buf(),
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

                    // Check if label references a baseline that doesn't exist.
                    // Fleet v4.83+: labels live at top-level `labels/`.
                    if path.contains("mscp-") {
                        let baseline_name = path
                            .trim_start_matches("./labels/mscp-")
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

        // Check fleet files for orphaned baseline references
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
                    // Check for references to baselines that don't exist.
                    // Fleet v4.83+ fleet YAMLs reference baselines via four prefixes:
                    //   ../platforms/macos/configuration-profiles/{name}/...
                    //   ../platforms/macos/scripts/{name}/...
                    //   ../platforms/macos/policies/{name}/...
                    //   ../mscp/{name}/...
                    // Extract the {name} segment after each prefix and check whether
                    // it matches a known baseline directory.
                    let layout = FleetLayout::default();
                    let v483_prefixes = [
                        format!("../{}/", layout.macos_profiles_subdir),
                        format!("../{}/", layout.macos_scripts_subdir),
                        format!("../{}/", layout.macos_policies_subdir),
                        "../mscp/".to_string(),
                    ];
                    for line in content.lines() {
                        if line.trim().starts_with('#') {
                            continue;
                        }
                        for prefix in &v483_prefixes {
                            if let Some(start) = line.find(prefix.as_str()) {
                                let after_prefix = &line[start + prefix.len()..];
                                if let Some(end) = after_prefix.find('/') {
                                    let referenced_baseline = &after_prefix[..end];
                                    // Skip the special `versions/` subdir of `mscp/`
                                    if referenced_baseline == "versions" {
                                        continue;
                                    }
                                    if !baseline_names.contains(&referenced_baseline.to_string()) {
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

/// Report of changes made during fleet file migration
#[derive(Debug)]
pub struct MigrationReport {
    #[allow(dead_code, reason = "reserved for future use")]
    pub fleet_file: PathBuf,
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

/// Insert `(path, labels_include_all)` entries at the end of a section's list,
/// as text, keeping every other line — comments included — as it was.
///
/// Entries are written the way contour's generator writes them — keys two
/// columns in from the dash, label items level with their key, plain scalars
/// — at `indent` when the caller knows the column the old entries used.
/// `format_profile_entry` in yaml_edit nests and quotes differently, which
/// would turn every migrated line of a generated file into a diff.
///
/// A section written as an empty flow list (`scripts: []`) is opened into a
/// block first; inserting `- path:` beneath `key: []` would not be YAML.
fn insert_section_entries(
    text: &str,
    section: &[&str],
    entries: &[(String, Vec<String>)],
    indent: Option<usize>,
) -> String {
    use contour_core::yaml_edit::{
        find_nested_section_insert_point, find_section_insert_point, insert_lines_at,
    };
    let last = *section.last().expect("section path is not empty");
    let opened: String = text
        .lines()
        .map(|l| {
            if l.trim() == format!("{last}: []") {
                l.replacen(": []", ":", 1)
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if text.ends_with('\n') { "\n" } else { "" };
    let lines: Vec<&str> = opened.lines().collect();
    let point = if section.len() == 1 {
        find_section_insert_point(&lines, last)
    } else {
        find_nested_section_insert_point(&lines, section)
    };
    let Some(point) = point.filter(|p| p.section_exists) else {
        return opened;
    };
    let pad = " ".repeat(indent.unwrap_or(point.indent));
    let scalar = |v: &str| -> String {
        // Quoted only when YAML needs it, decided by the serialiser rather
        // than by a hand-kept list of special characters.
        yaml_serde::to_string(v)
            .map(|s| s.trim_end().to_string())
            .unwrap_or_else(|_| format!("{v:?}"))
    };
    let new_lines: Vec<String> = entries
        .iter()
        .flat_map(|(path, labels)| {
            let mut out = vec![format!("{pad}- path: {}", scalar(path))];
            if !labels.is_empty() {
                out.push(format!("{pad}  labels_include_all:"));
                out.extend(labels.iter().map(|l| format!("{pad}  - {}", scalar(l))));
            }
            out
        })
        .collect();
    insert_lines_at(&opened, &point, &new_lines)
}

/// Build the set of substring patterns that uniquely identify references to a
/// given baseline in a Fleet v4.83+ fleet YAML.
///
/// A fleet YAML references a baseline through any of:
///   1. profile/script/policy paths under `../platforms/macos/.../{name}/`
///   2. the baseline component manifest at `../mscp/{name}/`
pub(crate) fn baseline_reference_patterns(
    layout: &FleetLayout,
    baseline_name: &str,
) -> Vec<String> {
    vec![
        format!("../{}/{baseline_name}/", layout.macos_profiles_subdir),
        format!("../{}/{baseline_name}/", layout.macos_scripts_subdir),
        format!("../{}/{baseline_name}/", layout.macos_policies_subdir),
        format!("../mscp/{baseline_name}/"),
    ]
}

/// Convert a baseline.toml-relative path to a fleet-yaml-relative path.
///
/// Fleet v4.83+: baseline.toml lives at `mscp/{name}/baseline.toml` and stores
/// artifact paths relative from there (e.g.
/// `../../platforms/macos/configuration-profiles/{name}/file.mobileconfig`).
/// Fleet YAML lives at `fleets/{fleet}.yml`, one level shallower, so the fleet-
/// relative path drops one leading `../`.
pub(crate) fn baseline_path_to_fleet_path(baseline_relative: &str) -> String {
    baseline_relative
        .strip_prefix("../")
        .unwrap_or(baseline_relative)
        .to_string()
}

#[cfg(test)]
mod migrate_tests {
    use super::*;

    /// A fleet file the way `mscp generate` writes one, plus what an operator
    /// adds in their own GitOps repo: a comment of their own, and a profile of
    /// their own that is nothing to do with mSCP.
    const FLEET: &str = "\
# Fleet GitOps - Fleet Configuration: eng (Fleet v4.82+)
#
# mSCP Baseline: cis_lvl1
# Profiles: platforms/macos/configuration-profiles/cis_lvl1/
# Scripts:  platforms/macos/scripts/cis_lvl1/
#
# Required environment variables:
#   - $FLEET_ENG_ENROLL_SECRET

name: eng
controls:
  macos_settings:
    custom_settings:
    # ours: keep the Wi-Fi profile outside the baseline
    - path: ../lib/macos/wifi.mobileconfig
    - path: ../platforms/macos/configuration-profiles/cis_lvl1/com.apple.dock.mobileconfig
      labels_include_all:
      - mscp-cis_lvl1
  scripts:
  - path: ../platforms/macos/scripts/cis_lvl1/cis_lvl1_os_audit.sh
policies:
- path: ../platforms/macos/policies/cis_lvl1/cis_lvl1.policies.yml
reports: []
settings:
  secrets:
  - secret: $FLEET_ENG_ENROLL_SECRET
";

    /// A tree holding `fleets/eng.yml` and a generated 800-171 to migrate to.
    fn tree(fleet: &str, with_policies: bool) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("fleets")).unwrap();
        std::fs::create_dir_all(root.join("mscp/800-171")).unwrap();
        std::fs::write(
            root.join("mscp/800-171/baseline.toml"),
            r#"[baseline]
name = "800-171"
platform = "macOS"
generated_at = "2026-09-27T00:00:00Z"

[[profiles]]
path = "../../platforms/macos/configuration-profiles/800-171/com.apple.dock.mobileconfig"
labels_include_all = ["mscp-800-171"]

[[scripts]]
path = "../../platforms/macos/scripts/800-171/800-171_os_audit.sh"
labels_include_all = ["mscp-800-171"]
"#,
        )
        .unwrap();
        if with_policies {
            let p = root.join("platforms/macos/policies/800-171");
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("800-171.policies.yml"), "[]\n").unwrap();
        }
        let file = root.join("fleets/eng.yml");
        std::fs::write(&file, fleet).unwrap();
        (dir, file)
    }

    fn migrate(file: &Path, root: &Path) -> Result<MigrationReport> {
        BaselineIndex::new(root.to_path_buf())
            .migrate_fleet_file(file, "cis_lvl1", "800-171", false)
    }

    fn out(file: &Path) -> (String, yaml_serde::Value) {
        let text = std::fs::read_to_string(file).unwrap();
        let yaml = yaml_serde::from_str(&text).expect("migrate wrote YAML");
        (text, yaml)
    }

    /// `policies:` moves with the baseline.
    ///
    /// A migrated fleet must not deploy the new baseline's profiles while
    /// reporting compliance against the old baseline's policies.
    #[test]
    fn policies_move_with_the_baseline() {
        let (dir, file) = tree(FLEET, true);
        migrate(&file, dir.path()).expect("migrates");
        let (_, y) = out(&file);
        let policies: Vec<&str> = y["policies"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|p| p["path"].as_str())
            .collect();
        assert_eq!(
            policies,
            vec!["../platforms/macos/policies/800-171/800-171.policies.yml"]
        );
    }

    /// The bug: every comment went.
    ///
    /// migrate parsed the file, edited the tree and serialised it back, which
    /// keeps no comments — the generated header with its "Required environment
    /// variables" line, and whatever the operator wrote in their own repo.
    #[test]
    fn comments_survive_and_the_header_follows_the_baseline() {
        let (dir, file) = tree(FLEET, true);
        migrate(&file, dir.path()).expect("migrates");
        let (text, _) = out(&file);
        assert!(
            text.contains("# ours: keep the Wi-Fi profile outside the baseline"),
            "an operator's comment was dropped:\n{text}"
        );
        assert!(text.contains("# Required environment variables:"));
        assert!(
            text.contains("#   - $FLEET_ENG_ENROLL_SECRET"),
            "the secret names the FLEET, and must not change"
        );
        assert!(text.contains("# mSCP Baseline: 800-171"), "{text}");
        assert!(text.contains("# Profiles: platforms/macos/configuration-profiles/800-171/"));
        assert!(
            !text.contains("cis_lvl1"),
            "a reference to the old baseline survived:\n{text}"
        );
    }

    /// Entries that are not the baseline's are left exactly where they were.
    #[test]
    fn an_operators_own_entry_is_untouched() {
        let (dir, file) = tree(FLEET, true);
        migrate(&file, dir.path()).expect("migrates");
        let (text, y) = out(&file);
        let paths: Vec<&str> = y["controls"]["macos_settings"]["custom_settings"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|p| p["path"].as_str())
            .collect();
        assert_eq!(
            paths[0], "../lib/macos/wifi.mobileconfig",
            "their entry kept its place"
        );
        assert!(paths.contains(
            &"../platforms/macos/configuration-profiles/800-171/com.apple.dock.mobileconfig"
        ));
        assert_eq!(
            y["name"].as_str(),
            Some("eng"),
            "migrating a baseline does not rename the fleet"
        );
        assert!(text.contains("- secret: $FLEET_ENG_ENROLL_SECRET"));
    }

    /// Scripts carry no labels — Fleet's schema has no label fields on them.
    ///
    /// baseline.toml records labels on its script entries, and migrate copied
    /// them across, so every migrated fleet file was one `fleetctl gitops`
    /// rejects. The generator never wrote them.
    #[test]
    fn scripts_are_written_without_labels_and_the_file_is_valid_fleet_gitops() {
        let (dir, file) = tree(FLEET, true);
        migrate(&file, dir.path()).expect("migrates");
        let (_, y) = out(&file);
        for s in y["controls"]["scripts"].as_sequence().unwrap() {
            assert!(
                s.get("labels_include_all").is_none(),
                "a script got labels: {s:?}"
            );
        }
        let schema: serde_json::Value = serde_json::from_slice(
            mscp_schema::embedded_fleet_gitops_schema().expect("this build embeds Fleet's schema"),
        )
        .unwrap();
        let v = jsonschema::validator_for(&schema).unwrap();
        let json = serde_json::to_value(&y).unwrap();
        let errs: Vec<String> = v
            .iter_errors(&json)
            .map(|e| format!("{} {e}", e.instance_path()))
            .collect();
        assert!(
            errs.is_empty(),
            "the migrated fleet file is not valid Fleet GitOps:\n{}",
            errs.join("\n")
        );
    }

    /// New entries sit where the old ones did, in the generator's style.
    ///
    /// Emptying a section leaves nothing to copy the indent from; a fallback a
    /// level deeper would be valid YAML, and a needless diff on every line of
    /// a generated file.
    #[test]
    fn new_entries_keep_the_old_indentation() {
        let (dir, file) = tree(FLEET, true);
        migrate(&file, dir.path()).expect("migrates");
        let (text, _) = out(&file);
        for line in [
            "    - path: ../platforms/macos/configuration-profiles/800-171/com.apple.dock.mobileconfig",
            "      labels_include_all:",
            "      - mscp-800-171",
            "  - path: ../platforms/macos/scripts/800-171/800-171_os_audit.sh",
            "- path: ../platforms/macos/policies/800-171/800-171.policies.yml",
        ] {
            assert!(
                text.lines().any(|l| l == line),
                "missing, or at another indent: {line:?}\n{text}"
            );
        }
    }

    /// A file indented by hand keeps its own indentation.
    #[test]
    fn a_hand_indented_file_keeps_its_style() {
        let indented = FLEET.replace(
            "  scripts:\n  - path: ../platforms/macos/scripts/cis_lvl1/cis_lvl1_os_audit.sh\n",
            "  scripts:\n    - path: ../platforms/macos/scripts/cis_lvl1/cis_lvl1_os_audit.sh\n",
        );
        let (dir, file) = tree(&indented, true);
        migrate(&file, dir.path()).expect("migrates");
        let (text, _) = out(&file);
        assert!(
            text.contains("\n    - path: ../platforms/macos/scripts/800-171/800-171_os_audit.sh\n"),
            "{text}"
        );
    }

    /// The fleet took the old baseline's policies and the new one has none:
    /// refuse, and leave the file as it was.
    #[test]
    fn missing_new_policies_refuses_and_writes_nothing() {
        let (dir, file) = tree(FLEET, false);
        let err = migrate(&file, dir.path()).expect_err("no 800-171 policies to move to");
        assert!(err.to_string().contains("policies"), "{err}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            FLEET,
            "the file was touched"
        );
    }

    /// Glob entries are refused rather than silently left behind.
    #[test]
    fn a_glob_reference_is_refused() {
        let glob = FLEET.replace(
            "    - path: ../platforms/macos/configuration-profiles/cis_lvl1/com.apple.dock.mobileconfig\n      labels_include_all:\n      - mscp-cis_lvl1\n",
            "    - paths: ../platforms/macos/configuration-profiles/cis_lvl1/*.mobileconfig\n",
        );
        let (dir, file) = tree(&glob, true);
        let err = migrate(&file, dir.path()).expect_err("globs are not migrated");
        assert!(err.to_string().contains("glob"), "{err}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), glob);
    }

    /// An empty flow list is opened into a block before anything is added.
    #[test]
    fn an_empty_scripts_list_is_opened_before_inserting() {
        let empty = FLEET.replace(
            "  scripts:\n  - path: ../platforms/macos/scripts/cis_lvl1/cis_lvl1_os_audit.sh\n",
            "  scripts: []\n",
        );
        let (dir, file) = tree(&empty, true);
        migrate(&file, dir.path()).expect("migrates");
        let (_, y) = out(&file);
        let scripts = y["controls"]["scripts"]
            .as_sequence()
            .expect("scripts is a list");
        assert_eq!(scripts.len(), 1);
    }
}
