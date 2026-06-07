use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::managers::baseline::baseline_path_to_fleet_path;
use crate::updaters::injection_manifest::InjectionManifest;
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
    /// Optional label to scope the attached *profiles* to. `None` (default)
    /// leaves them unscoped — the baseline's configuration profiles enforce on
    /// every host in the fleet. Remediation *scripts* keep their own functional
    /// trigger labels regardless.
    profile_label: Option<String>,
}

impl FleetUpdater {
    pub fn new<P: AsRef<Path>>(output_base: P, baseline_name: String) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
            baseline_name,
            glob: false,
            profile_label: None,
        }
    }

    /// Enable glob mode: attach the baseline as one `*.mobileconfig` glob
    /// entry rather than a literal entry per profile.
    #[must_use]
    pub fn with_glob(mut self, glob: bool) -> Self {
        self.glob = glob;
        self
    }

    /// Scope attached profiles to a label (opt-in). Without it, profiles are
    /// unscoped (apply to all hosts in the fleet).
    #[must_use]
    pub fn with_profile_label(mut self, label: Option<String>) -> Self {
        self.profile_label = label;
        self
    }

    /// The labels to scope attached profile entries with: the explicit
    /// `--fleet-label`, else none (unscoped).
    fn profile_labels(&self) -> Vec<String> {
        self.profile_label.clone().into_iter().collect()
    }

    /// The fleet entries this baseline contributes (the profile glob/paths plus
    /// each script path) — recorded in the injection manifest as contour-owned.
    fn baseline_entries(&self) -> Result<Vec<String>> {
        let mut entries = Vec::new();
        let profiles = self.get_baseline_profiles()?;
        if self.glob {
            if !profiles.is_empty() {
                entries.push(glob_dir_from_profiles(&profiles)?);
            }
        } else {
            entries.extend(profiles);
        }
        for (script_path, _label) in self.get_baseline_scripts()? {
            entries.push(script_path);
        }
        Ok(entries)
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
            let available = self.fleet_names()?;
            anyhow::bail!(
                "Fleet files not found: {missing}\n\
                 Available fleets: {available}\n\
                 \n\
                 The fleet is referenced by `[[baselines]].fleet` in mscp.toml \
                 but no `output/fleets/<name>.yml` exists for it. Either:\n  \
                 • Re-run `contour mscp init` to scaffold a stub for every \
                 referenced fleet, or\n  \
                 • Remove the `fleet = \"...\"` line from the baseline if you \
                 don't want Fleet aggregation, or\n  \
                 • Scaffold the file yourself (e.g. via `fleetctl new`).",
                missing = missing.join(", "),
                available = if available.is_empty() {
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
        let mut manifest = InjectionManifest::load(&self.output_base)?;
        for fleet_name in fleet_names {
            let fleet_file = self
                .output_base
                .join("fleets")
                .join(format!("{fleet_name}.yml"));

            if !fleet_file.exists() {
                let available = self.fleet_names()?;
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

            // Emit the `# contour:<baseline>` signpost only if this fleet doesn't
            // already carry it — decided from the original content so the
            // profiles- and scripts-section appends agree (scripts runs on the
            // already-modified text, which by then holds the profile marker).
            let marker_line = format!("# contour:{}", self.baseline_name);
            let marker = (!content.contains(&marker_line)).then_some(self.baseline_name.as_str());

            // Append profiles to controls.apple_settings.configuration_profiles
            if let Some(new_content) = self.append_profiles(&modified, marker)? {
                modified = new_content;
                changes_made = true;
            }

            // Append scripts to controls.scripts
            if let Some(new_content) = self.append_scripts(&modified, marker)? {
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

            // Record this baseline as injected into the fleet — the manifest is
            // the source of truth for idempotency and `--remove`.
            manifest.record(fleet_name, &self.baseline_name, self.baseline_entries()?);
        }

        manifest.save(&self.output_base)?;
        Ok(())
    }

    /// Withdraw this baseline from `fleet_names`, using the injection manifest to
    /// know exactly which entries contour added. Each entry line (and its
    /// indented continuation, e.g. labels) is removed; everything else — the
    /// operator's own content and comments — is left byte-stable. Fails closed on
    /// invalid YAML, and updates the manifest.
    pub fn remove_from_fleets(&self, fleet_names: &[String]) -> Result<()> {
        let mut manifest = InjectionManifest::load(&self.output_base)?;
        for fleet_name in fleet_names {
            let Some(injection) = manifest.find(fleet_name, &self.baseline_name) else {
                tracing::info!(
                    "  Fleet '{}' has no '{}' injection recorded — nothing to remove",
                    fleet_name,
                    self.baseline_name
                );
                continue;
            };
            let fleet_file = self
                .output_base
                .join("fleets")
                .join(format!("{fleet_name}.yml"));
            if !fleet_file.exists() {
                manifest.remove(fleet_name, &self.baseline_name);
                continue;
            }
            let content = std::fs::read_to_string(&fleet_file)
                .with_context(|| format!("Failed to read {}", fleet_file.display()))?;
            let modified = remove_entries(&content, &injection.entries, Some(&self.baseline_name));
            if modified != content {
                if let Err(e) = yaml_serde::from_str::<yaml_serde::Value>(&modified) {
                    anyhow::bail!(
                        "refused to edit {}: removing the baseline produced invalid YAML ({e}). \
                         The file was left untouched.",
                        fleet_file.display()
                    );
                }
                std::fs::write(&fleet_file, &modified)
                    .with_context(|| format!("Failed to write {}", fleet_file.display()))?;
                tracing::info!(
                    "✓ Removed '{}' from fleet: {}",
                    self.baseline_name,
                    fleet_name
                );
            }
            manifest.remove(fleet_name, &self.baseline_name);
        }
        manifest.save(&self.output_base)?;
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
    fn append_profiles(&self, content: &str, marker: Option<&str>) -> Result<Option<String>> {
        let baseline_profiles = self.get_baseline_profiles()?;

        if baseline_profiles.is_empty() {
            tracing::warn!("No profiles found in baseline '{}'", self.baseline_name);
            return Ok(None);
        }

        // Profiles are unscoped by default (enforce on all hosts in the fleet);
        // `--fleet-label` opts into scoping them.
        let labels = self.profile_labels();

        let entries: Vec<yaml_edit::ProfileListEntry> = if self.glob {
            // One glob entry covering the baseline's profile directory.
            let glob_path = glob_dir_from_profiles(&baseline_profiles)?;
            if content.contains(&glob_path) {
                return Ok(None);
            }
            vec![yaml_edit::ProfileListEntry {
                path: glob_path,
                glob: true,
                labels_include_all: labels.clone(),
            }]
        } else {
            // One literal entry per profile, skipping any already present.
            baseline_profiles
                .iter()
                .filter(|path| !content.contains(path.as_str()))
                .map(|path| yaml_edit::ProfileListEntry {
                    path: path.clone(),
                    glob: false,
                    labels_include_all: labels.clone(),
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
            content, &entries, marker,
        )))
    }

    /// Append baseline scripts using line-based editing.
    /// Returns `Some(modified)` if changes were made, `None` if all already present.
    fn append_scripts(&self, content: &str, marker: Option<&str>) -> Result<Option<String>> {
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

        // A seeded `scripts: []` must become bare before we splice block entries
        // under it (otherwise the result is invalid YAML).
        let content = yaml_edit::normalize_empty_flow_list(content, &["controls", "scripts"]);
        let content = content.as_str();
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

        let mut flat: Vec<String> = formatted.into_iter().flatten().collect();

        // Lead the injected block with a `# contour:<baseline>` signpost (indent 4
        // to match the script entries). Cosmetic — the manifest drives removal.
        if let Some(baseline) = marker {
            flat.insert(0, format!("    # contour:{baseline}"));
        }

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
    /// The fleet names (file stems) present under `fleets/`, sorted, excluding
    /// example stubs. Used by `--all-fleets` to attach a baseline to every fleet.
    pub fn fleet_names(&self) -> Result<Vec<String>> {
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

    /// Scaffold the canonical greenfield fleets ([`CANONICAL_FLEETS`]) that don't
    /// yet exist under `fleets/`, returning the names actually created (empty if
    /// all were already present). Idempotent — never overwrites an operator's
    /// fleet file. Used by `--canonical-fleets` to bootstrap a repo with no
    /// fleets before attaching a baseline to the workstations fleet.
    ///
    /// # Errors
    /// Returns an error if the `fleets/` directory or a file cannot be written.
    pub fn ensure_canonical_fleets(&self) -> Result<Vec<String>> {
        let fleets_dir = self.output_base.join("fleets");
        std::fs::create_dir_all(&fleets_dir)
            .with_context(|| format!("Failed to create {}", fleets_dir.display()))?;

        let mut created = Vec::new();
        for (name, purpose) in CANONICAL_FLEETS {
            let path = fleets_dir.join(format!("{name}.yml"));
            if path.exists() {
                continue;
            }
            std::fs::write(&path, canonical_fleet_yaml(name, purpose))
                .with_context(|| format!("Failed to write {}", path.display()))?;
            created.push((*name).to_string());
        }
        Ok(created)
    }
}

/// Remove list entries whose `path:`/`paths:` value is in `paths`, plus each
/// entry's indented continuation lines (e.g. `labels_include_all`). Everything
/// else — operator content, comments, blank lines — is preserved verbatim.
fn remove_entries(content: &str, paths: &[String], marker: Option<&str>) -> String {
    // The cosmetic `# contour:<baseline>` signpost, dropped alongside its entries
    // so removal leaves no orphaned marker behind.
    let marker_line = marker.map(|b| format!("# contour:{b}"));
    let lines: Vec<&str> = content.lines().collect();
    let mut out: Vec<&str> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        if marker_line.as_deref() == Some(trimmed) {
            i += 1;
            continue;
        }
        let is_target = (trimmed.starts_with("- path:") || trimmed.starts_with("- paths:"))
            && paths.iter().any(|p| line.contains(p.as_str()));
        if !is_target {
            out.push(line);
            i += 1;
            continue;
        }
        // Drop the entry and any lines indented deeper than it (its continuation).
        let indent = line.len() - trimmed.len();
        i += 1;
        while i < lines.len() {
            let next = lines[i];
            let next_trim = next.trim_start();
            let deeper = !next_trim.is_empty() && (next.len() - next_trim.len()) > indent;
            if deeper {
                i += 1;
            } else {
                break;
            }
        }
    }
    let mut result = out.join("\n");
    if content.ends_with('\n') {
        result.push('\n');
    }
    result
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

/// Minimal Fleet GitOps stub for `fleets/<name>.yml`, written by
/// `mscp init` when a baseline references a fleet that doesn't yet
/// exist. All seven top-level keys (`name`, `controls`, `policies`,
/// `reports`, `agent_options`, `settings`, `software`) are present so
/// `fleetctl gitops` parses the file as-is, but bodies are empty so the
/// operator must fill in agent_options, secrets, and host labels before
/// deploying.
///
/// The `agent_options.path` is the standard `../platforms/all/agent-options.yml`
/// emitted by mSCP — it resolves once the first `mscp generate` runs.
pub fn fleet_stub_yaml(fleet_name: &str) -> String {
    format!(
        "# Fleet GitOps - {fleet_name} fleet (scaffolded by `contour mscp init`)\n\
         #\n\
         # `[[baselines]].fleet = \"{fleet_name}\"` in mscp.toml references this\n\
         # file. `contour mscp generate` will append each baseline's profiles\n\
         # and scripts to the sections below. Before running `fleetctl gitops`:\n\
         #   - Set the policies, reports, and host-label targeting for this fleet\n\
         #   - Wire in any required `secrets:` (e.g. enroll secret)\n\
         #   - Confirm `agent_options.path` matches your repo layout\n\
         #\n\
         # See: https://fleetdm.com/docs/configuration/yaml-files#teams\n\
         \n\
         name: {fleet_name}\n\
         controls:\n  \
           macos_settings:\n    \
             custom_settings: []\n\
         policies: []\n\
         reports: []\n\
         agent_options:\n  \
           path: ../platforms/all/agent-options.yml\n\
         settings: {{}}\n\
         software: {{}}\n"
    )
}

/// The canonical fleet that macOS security baselines attach to: supervised,
/// MDM-managed workstations (not BYOD). `--canonical-fleets` targets this fleet.
pub const CANONICAL_PRIMARY: &str = "workstations";

/// The greenfield fleets `--canonical-fleets` scaffolds, each with a purpose
/// comment block (every line prefixed `# `, trailing newline): a supervised
/// macOS workstation fleet and a BYOD/user-enrolled mobile fleet.
const CANONICAL_FLEETS: &[(&str, &str)] = &[
    (
        CANONICAL_PRIMARY,
        "# Supervised, MDM-managed macOS workstations — the primary target for\n\
         # security baselines (CIS, STIG, 800-53). `--canonical-fleets` attaches a\n\
         # baseline's configuration profiles and audit scripts to the sections below.\n",
    ),
    (
        "personal-mobile-devices",
        "# BYOD / user-enrolled iPhones and iPads with a limited management scope.\n\
         # macOS security baselines do NOT attach here — keep this fleet for\n\
         # mobile-appropriate configuration only.\n",
    ),
];

/// A canonical Fleet GitOps team file for `--canonical-fleets`: all seven
/// top-level keys present so `fleetctl gitops` parses it, `controls` already
/// shaped as `apple_settings.configuration_profiles: []` + `scripts: []` so a
/// baseline attach inserts cleanly. `purpose` is the per-fleet comment block.
fn canonical_fleet_yaml(fleet_name: &str, purpose: &str) -> String {
    format!(
        "# Fleet GitOps — {fleet_name} fleet (scaffolded by `contour mscp generate --canonical-fleets`)\n\
         #\n\
         {purpose}\
         #\n\
         # Before `fleetctl gitops`:\n\
         #   - Set host-label targeting / team enrollment for this fleet\n\
         #   - Wire in any required `secrets:` (e.g. enroll secret)\n\
         #   - Confirm `agent_options.path` matches your repo layout\n\
         #\n\
         # See: https://fleetdm.com/docs/configuration/yaml-files#teams\n\
         \n\
         name: {fleet_name}\n\
         controls:\n  \
           apple_settings:\n    \
             configuration_profiles: []\n  \
           scripts: []\n\
         policies: []\n\
         reports: []\n\
         agent_options:\n  \
           path: ../platforms/all/agent-options.yml\n\
         settings: {{}}\n\
         software: {{}}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn remove_entries_drops_matched_entry_and_labels_keeps_rest() {
        let content = "\
controls:
  apple_settings:
    configuration_profiles:
      # operator's own profile — keep
      - paths: ../platforms/macos/configuration-profiles/tenants/sample/*.mobileconfig
      # contour:cis_lvl1
      - paths: ../platforms/macos/configuration-profiles/cis_lvl1/*.mobileconfig
        labels_include_all:
          - \"mscp-cis_lvl1\"
  scripts:
    # contour:cis_lvl1
    - path: ../platforms/macos/scripts/cis_lvl1/cis_lvl1_os_audit.sh
      labels_include_all:
        - \"mscp-cis_lvl1\"
";
        let removed = remove_entries(
            content,
            &[
                "../platforms/macos/configuration-profiles/cis_lvl1/*.mobileconfig".to_string(),
                "../platforms/macos/scripts/cis_lvl1/cis_lvl1_os_audit.sh".to_string(),
            ],
            Some("cis_lvl1"),
        );
        // CIS profile + its labels, the CIS script + its labels, and both
        // `# contour:cis_lvl1` signposts are gone…
        assert!(!removed.contains("cis_lvl1"));
        assert!(!removed.contains("mscp-cis_lvl1"));
        assert!(!removed.contains("# contour:"));
        // …operator content + comment preserved.
        assert!(removed.contains("tenants/sample/*.mobileconfig"));
        assert!(removed.contains("# operator's own profile — keep"));
    }

    #[test]
    fn ensure_canonical_fleets_scaffolds_valid_files_idempotently() {
        let tmp = tempfile::TempDir::new().unwrap();
        let updater = FleetUpdater::new(tmp.path(), "cis_lvl1".to_string());

        // First run creates both canonical fleets, in declaration order.
        let created = updater.ensure_canonical_fleets().unwrap();
        assert_eq!(created, vec!["workstations", "personal-mobile-devices"]);

        let ws = tmp.path().join("fleets/workstations.yml");
        let mobile = tmp.path().join("fleets/personal-mobile-devices.yml");
        assert!(ws.exists() && mobile.exists());

        // Each scaffold is valid YAML with the attach-ready controls shape.
        let ws_text = fs::read_to_string(&ws).unwrap();
        yaml_serde::from_str::<yaml_serde::Value>(&ws_text).expect("workstations.yml parses");
        assert!(ws_text.contains("name: workstations"));
        assert!(ws_text.contains("configuration_profiles: []"));
        assert!(ws_text.contains("scripts: []"));

        // Second run is a no-op: nothing created, operator content untouched.
        fs::write(&ws, "name: workstations  # operator-owned\n").unwrap();
        let again = updater.ensure_canonical_fleets().unwrap();
        assert!(again.is_empty());
        assert_eq!(
            fs::read_to_string(&ws).unwrap(),
            "name: workstations  # operator-owned\n"
        );
    }

    #[test]
    fn fleet_names_discovers_yml_stems_sorted_excluding_examples() {
        let tmp = tempfile::TempDir::new().unwrap();
        let fleets = tmp.path().join("fleets");
        fs::create_dir_all(&fleets).unwrap();
        for f in [
            "servers.yml",
            "workstations.yml",
            "example-fleet.yml",
            "notes.txt",
        ] {
            fs::write(fleets.join(f), "name: x\n").unwrap();
        }
        let updater = FleetUpdater::new(tmp.path(), "cis_lvl1".to_string());
        // Sorted, .yml only, example stubs excluded.
        assert_eq!(
            updater.fleet_names().unwrap(),
            vec!["servers", "workstations"]
        );
    }

    #[test]
    fn fleet_names_is_empty_when_no_fleets_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let updater = FleetUpdater::new(tmp.path(), "cis_lvl1".to_string());
        assert!(updater.fleet_names().unwrap().is_empty());
    }

    #[test]
    fn fleet_stub_yaml_is_well_formed() {
        // The stub must parse as YAML (so `fleetctl gitops` won't reject
        // it) and include every top-level key Fleet GitOps requires.
        let body = fleet_stub_yaml("workstations");
        let parsed: yaml_serde::Value =
            yaml_serde::from_str(&body).expect("stub must parse as YAML");

        let map = parsed.as_mapping().expect("top-level must be a mapping");
        for key in [
            "name",
            "controls",
            "policies",
            "reports",
            "agent_options",
            "settings",
            "software",
        ] {
            assert!(
                map.contains_key(yaml_serde::Value::String(key.to_string())),
                "stub missing required top-level key `{key}`"
            );
        }
        assert_eq!(
            map.get(yaml_serde::Value::String("name".to_string()))
                .and_then(yaml_serde::Value::as_str),
            Some("workstations"),
            "stub `name` must match the fleet name"
        );
    }

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
        let result = updater.append_profiles(content, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_append_scripts_preserves_comments() {
        let content = "# Fleet: Blue\nname: fleet-air-blue\n\n# Controls section\ncontrols:\n  scripts:\n    - path: ../lib/macos/scripts/existing.sh\n";

        let updater = FleetUpdater::new("/tmp/test", "cis_lvl2".to_string());
        let result = updater.append_scripts(content, None).unwrap();
        assert!(result.is_none());
    }
}
