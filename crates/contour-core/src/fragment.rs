//! Fragment manifest (`fragment.toml`) parsing and serialization.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level fragment manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentManifest {
    pub fragment: FragmentMeta,
    #[serde(default)]
    pub default_yml: DefaultYmlEntries,
    #[serde(default)]
    pub fleet_entries: FleetEntries,
    #[serde(default)]
    pub lib_files: LibFiles,
    #[serde(default)]
    pub scripts: ScriptEntries,
}

/// Fragment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentMeta {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_generator")]
    pub generator: String,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

fn default_generator() -> String {
    "manual".to_string()
}

/// Entries to append to target default.yml.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[allow(
    clippy::struct_field_names,
    reason = "field names match domain terminology"
)]
pub struct DefaultYmlEntries {
    #[serde(default)]
    pub label_paths: Vec<String>,
    #[serde(default)]
    pub report_paths: Vec<String>,
    #[serde(default)]
    pub policy_paths: Vec<String>,
}

/// Entries to add to target fleet files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetEntries {
    #[serde(default)]
    pub profiles: Vec<ProfileEntry>,
    #[serde(default)]
    pub reports: Vec<SimpleEntry>,
    #[serde(default)]
    pub policies: Vec<SimpleEntry>,
    #[serde(default)]
    pub software: Vec<SoftwareEntry>,
}

/// A configuration profile entry for a fleet file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileEntry {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_include_any: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_include_all: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_exclude_any: Option<Vec<String>>,
}

/// A simple path-only entry (reports, policies).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleEntry {
    pub path: String,
}

/// A software package entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareEntry {
    pub path: String,
    #[serde(default)]
    pub self_service: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_include_any: Option<Vec<String>>,
}

/// Library files to copy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LibFiles {
    #[serde(default)]
    pub copy: Vec<String>,
}

/// Script entries for the fragment.
///
/// Scripts are organized by type and can be added to fleet files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScriptEntries {
    /// Check scripts (executed to verify compliance).
    #[serde(default)]
    pub check: Vec<ScriptEntry>,
    /// Remediation/fix scripts (executed to fix non-compliance).
    #[serde(default)]
    pub remediation: Vec<ScriptEntry>,
}

/// A script entry in the fragment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptEntry {
    /// Relative path to the script file (from fragment root).
    pub path: String,
    /// Optional display name for the script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional description of what the script does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Labels to target specific hosts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_include_any: Option<Vec<String>>,
}

impl FragmentManifest {
    /// Load a manifest from a `fragment.toml` file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let manifest: Self = toml::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        Ok(manifest)
    }

    /// Save the manifest to a `fragment.toml` file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let content =
            toml::to_string_pretty(self).context("Failed to serialize fragment manifest")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        Ok(())
    }

    /// Summary counts for display.
    pub fn summary(&self) -> FragmentSummary {
        FragmentSummary {
            name: self.fragment.name.clone(),
            version: self.fragment.version.clone(),
            description: self.fragment.description.clone(),
            label_count: self.default_yml.label_paths.len(),
            report_count: self.default_yml.report_paths.len(),
            policy_count: self.default_yml.policy_paths.len(),
            profile_count: self.fleet_entries.profiles.len(),
            fleet_report_count: self.fleet_entries.reports.len(),
            fleet_policy_count: self.fleet_entries.policies.len(),
            software_count: self.fleet_entries.software.len(),
            lib_file_count: self.lib_files.copy.len(),
            check_script_count: self.scripts.check.len(),
            remediation_script_count: self.scripts.remediation.len(),
        }
    }
}

/// Summary of fragment contents for display.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FragmentSummary {
    pub name: String,
    pub version: String,
    pub description: String,
    pub label_count: usize,
    pub report_count: usize,
    pub policy_count: usize,
    pub profile_count: usize,
    pub fleet_report_count: usize,
    pub fleet_policy_count: usize,
    pub software_count: usize,
    pub lib_file_count: usize,
    pub check_script_count: usize,
    pub remediation_script_count: usize,
}
