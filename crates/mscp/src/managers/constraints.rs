//! Constraints manager for interactively managing profile and script exclusion constraints.
//!
//! Supports Fleet, Jamf, and Munki constraint files with a unified interface.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::extractors::RuleExtractor;
use crate::managers::category_resolver::CategoryExclusionPlan;

/// Result of merging category exclusions into constraints
#[derive(Debug, Clone, Default)]
pub struct MergeResult {
    /// Number of profile exclusions added
    pub profiles_added: usize,
    /// Number of script exclusions added
    pub scripts_added: usize,
    /// Number of profile exclusions skipped (already existed)
    pub profiles_skipped: usize,
    /// Number of script exclusions skipped (already existed)
    pub scripts_skipped: usize,
}

/// Constraint type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ConstraintType {
    Fleet,
    Jamf,
    Munki,
}

impl ConstraintType {
    /// Get the default filename for this constraint type
    #[must_use]
    pub fn default_filename(&self) -> &'static str {
        match self {
            Self::Fleet => "fleet-constraints.yml",
            Self::Jamf => "jamf-constraints.yml",
            Self::Munki => "munki-constraints.yml",
        }
    }
}

impl fmt::Display for ConstraintType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fleet => write!(f, "Fleet"),
            Self::Jamf => write!(f, "Jamf"),
            Self::Munki => write!(f, "Munki"),
        }
    }
}

/// Profile information discovered from mSCP repository
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub filename: String,
    /// Full path to the profile file (retained for future use)
    #[allow(dead_code, reason = "reserved for future use")]
    pub path: PathBuf,
}

impl fmt::Display for ProfileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.filename)
    }
}

/// Script information discovered from mSCP rules
#[derive(Debug, Clone)]
pub struct ScriptInfo {
    pub rule_id: String,
    pub title: String,
    #[allow(dead_code, reason = "reserved for future use")]
    pub category: String,
}

impl fmt::Display for ScriptInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.rule_id, self.title)
    }
}

/// Excluded profile entry in constraints file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludedProfile {
    pub filename: String,
    pub reason: String,
    #[serde(default)]
    pub fleet_alternative: String,
    #[serde(default)]
    pub exclude_munki_scripts: bool,
    #[serde(default)]
    pub affected_rules: Vec<String>,
}

/// Payload key exclusion entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadKeyExclusion {
    pub payload_type: String,
    pub keys_to_remove: Vec<String>,
    pub reason: String,
    #[serde(default)]
    pub fleet_alternative: String,
}

/// Excluded script entry in constraints file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludedScript {
    pub rule_id: String,
    pub reason: String,
    #[serde(default)]
    pub alternative: String,
}

/// Fleet/Jamf/Munki constraints structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConstraintData {
    #[serde(default)]
    pub excluded_profiles: Vec<ExcludedProfile>,
    #[serde(default)]
    pub payload_key_exclusions: Vec<PayloadKeyExclusion>,
    #[serde(default)]
    pub excluded_scripts: Vec<ExcludedScript>,
    /// Additional fields preserved during round-trip
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, yaml_serde::Value>,
}

/// Loads, queries, and persists profile and script exclusion constraints.
#[derive(Debug)]
pub struct Constraints {
    constraint_type: ConstraintType,
    constraints_path: PathBuf,
    constraints: ConstraintData,
}

impl Constraints {
    /// Load constraints from file
    pub fn load(constraint_type: ConstraintType, path: Option<PathBuf>) -> Result<Self> {
        let constraints_path =
            path.unwrap_or_else(|| PathBuf::from(constraint_type.default_filename()));

        let constraints = if constraints_path.exists() {
            let content = std::fs::read_to_string(&constraints_path).with_context(|| {
                format!("Failed to read constraints: {}", constraints_path.display())
            })?;

            yaml_serde::from_str(&content).with_context(|| {
                format!(
                    "Failed to parse constraints: {}",
                    constraints_path.display()
                )
            })?
        } else {
            ConstraintData::default()
        };

        Ok(Self {
            constraint_type,
            constraints_path,
            constraints,
        })
    }

    /// Save constraints to file
    pub fn save(&self) -> Result<()> {
        let content =
            yaml_serde::to_string(&self.constraints).context("Failed to serialize constraints")?;

        // Add header comment based on constraint type
        let header = match self.constraint_type {
            ConstraintType::Fleet => {
                r"# Fleet Constraint Definitions
# Profiles and payload keys that conflict with Fleet native capabilities
#
# When --fleet-mode is enabled, these profiles will be:
# - Excluded entirely (if listed in excluded_profiles)
# - Have specific keys stripped (if listed in payload_key_exclusions)

"
            }
            ConstraintType::Jamf => {
                r"# Jamf Constraint Definitions
# Profiles that conflict with Jamf Pro native capabilities
#
# When --jamf-exclude-conflicts is enabled, these profiles will be:
# - Excluded entirely (if listed in excluded_profiles)
# - Have specific keys stripped (if listed in payload_key_exclusions)

"
            }
            ConstraintType::Munki => {
                r"# Munki Constraint Definitions
# Profiles and rules to exclude from Munki integration

"
            }
        };

        let final_content = format!("{header}{content}");

        std::fs::write(&self.constraints_path, final_content).with_context(|| {
            format!(
                "Failed to write constraints: {}",
                self.constraints_path.display()
            )
        })?;

        Ok(())
    }

    /// Every `build/` directory holding output for `baseline`.
    ///
    /// mSCP 1.x built into `build/<baseline>`; 2.0 builds into
    /// `build/<baseline>_<os>_<version>`, so a lookup by bare name found
    /// nothing on a 2.0 tree and discovery returned an empty list — which
    /// reads as "this baseline has no profiles to exclude" rather than as a
    /// failure. Both shapes are accepted.
    ///
    /// The suffix must be a real `_<os>_<version>` and not any underscore:
    /// a live build tree carries `cis_lvl1`, `cis_lvl1_macos_26.0` AND
    /// `cis_lvl1_enterprise`, and the last is a different baseline whose
    /// profiles must not be offered for exclusion under this name.
    fn build_dirs_for(mscp_repo: &Path, baseline: &str) -> Vec<PathBuf> {
        const OS_TOKENS: [&str; 3] = ["macos", "ios", "visionos"];
        let build = mscp_repo.join("build");
        let mut dirs = Vec::new();

        let exact = build.join(baseline);
        if exact.is_dir() {
            dirs.push(exact);
        }
        let Ok(entries) = std::fs::read_dir(&build) else {
            return dirs;
        };
        for entry in entries.filter_map(std::result::Result::ok) {
            if !entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(rest) = name.strip_prefix(&format!("{baseline}_")) else {
                continue;
            };
            // `<os>_<version>` — the os token must match exactly, so
            // `cis_lvl1_enterprise` does not answer for `cis_lvl1`.
            if OS_TOKENS.iter().any(|os| {
                rest.strip_prefix(&format!("{os}_"))
                    .is_some_and(|v| !v.is_empty())
            }) {
                dirs.push(entry.path());
            }
        }
        dirs.sort();
        dirs
    }

    /// Discover profiles from mSCP repository
    pub fn discover_profiles(mscp_repo: &Path, baseline: Option<&str>) -> Result<Vec<ProfileInfo>> {
        let search_paths = if let Some(b) = baseline {
            let dirs = Self::build_dirs_for(mscp_repo, b);
            if dirs.is_empty() {
                // Nothing built under either layout's name. Say so rather than
                // walking every baseline, which would offer the wrong profiles.
                return Ok(Vec::new());
            }
            dirs.into_iter()
                .flat_map(|d| {
                    [
                        d.join("mobileconfigs/unsigned"),
                        d.join("mobileconfigs/signed"),
                        d.join("mobileconfigs"),
                    ]
                })
                .collect()
        } else {
            // Search all baselines
            vec![mscp_repo.join("build")]
        };

        let mut profiles = Vec::new();
        let mut seen_filenames: HashSet<String> = HashSet::new();

        for search_path in search_paths {
            if !search_path.exists() {
                continue;
            }

            for entry in WalkDir::new(&search_path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| {
                    e.path()
                        .extension()
                        .is_some_and(|ext| ext == "mobileconfig")
                })
            {
                let filename = entry.file_name().to_string_lossy().to_string();

                // Deduplicate by filename
                if seen_filenames.insert(filename.clone()) {
                    profiles.push(ProfileInfo {
                        filename,
                        path: entry.path().to_path_buf(),
                    });
                }
            }
        }

        // Sort by filename
        profiles.sort_by(|a, b| a.filename.cmp(&b.filename));

        Ok(profiles)
    }

    /// Add an exclusion
    pub fn add_exclusion(&mut self, profile: ExcludedProfile) {
        // Check if already exists and update if so
        if let Some(existing) = self
            .constraints
            .excluded_profiles
            .iter_mut()
            .find(|p| p.filename == profile.filename)
        {
            *existing = profile;
        } else {
            self.constraints.excluded_profiles.push(profile);
        }
    }

    /// Remove an exclusion by filename
    pub fn remove_exclusion(&mut self, filename: &str) -> bool {
        let original_len = self.constraints.excluded_profiles.len();
        self.constraints
            .excluded_profiles
            .retain(|p| p.filename != filename);
        self.constraints.excluded_profiles.len() != original_len
    }

    /// Get list of excluded profiles
    #[must_use]
    pub fn get_excluded(&self) -> &[ExcludedProfile] {
        &self.constraints.excluded_profiles
    }

    /// Check if a profile is excluded
    #[must_use]
    pub fn is_excluded(&self, filename: &str) -> bool {
        self.constraints
            .excluded_profiles
            .iter()
            .any(|p| p.filename == filename)
    }

    /// Add a script exclusion
    pub fn add_script_exclusion(&mut self, script: ExcludedScript) {
        // Check if already exists and update if so
        if let Some(existing) = self
            .constraints
            .excluded_scripts
            .iter_mut()
            .find(|s| s.rule_id == script.rule_id)
        {
            *existing = script;
        } else {
            self.constraints.excluded_scripts.push(script);
        }
    }

    /// Remove a script exclusion by `rule_id`
    pub fn remove_script_exclusion(&mut self, rule_id: &str) -> bool {
        let original_len = self.constraints.excluded_scripts.len();
        self.constraints
            .excluded_scripts
            .retain(|s| s.rule_id != rule_id);
        self.constraints.excluded_scripts.len() != original_len
    }

    /// Get list of excluded scripts
    #[must_use]
    pub fn get_excluded_scripts(&self) -> &[ExcludedScript] {
        &self.constraints.excluded_scripts
    }

    /// Check if a script is excluded
    #[must_use]
    pub fn is_script_excluded(&self, rule_id: &str) -> bool {
        self.constraints
            .excluded_scripts
            .iter()
            .any(|s| s.rule_id == rule_id)
    }

    /// Discover scripts from mSCP repository
    pub fn discover_scripts(mscp_repo: &Path, baseline: Option<&str>) -> Result<Vec<ScriptInfo>> {
        let extractor = RuleExtractor::new(mscp_repo);

        let rules = if let Some(b) = baseline {
            extractor.extract_rules_for_baseline(b)?
        } else {
            extractor.extract_all_rules()?
        };

        let scripts: Vec<ScriptInfo> = rules
            .into_iter()
            .filter(crate::models::MscpRule::has_executable_fix)
            .map(|r| ScriptInfo {
                rule_id: r.id.clone(),
                title: r.title.clone(),
                category: script_category_from_rule_id(&r.id),
            })
            .collect();

        Ok(scripts)
    }

    /// Get the constraint type
    #[must_use]
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn constraint_type(&self) -> ConstraintType {
        self.constraint_type
    }

    /// Get the constraints path
    #[must_use]
    pub fn constraints_path(&self) -> &Path {
        &self.constraints_path
    }

    /// Read-only access to underlying constraints
    #[must_use]
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn constraints(&self) -> &ConstraintData {
        &self.constraints
    }

    /// Merge category exclusion entries, preserving existing constraints.
    /// Returns counts of what was added vs skipped (idempotent).
    pub fn merge_category_exclusions(&mut self, plan: &CategoryExclusionPlan) -> MergeResult {
        let mut result = MergeResult::default();

        // Merge profile exclusions
        for profile in &plan.excluded_profiles {
            if self.is_excluded(&profile.filename) {
                result.profiles_skipped += 1;
            } else {
                self.add_exclusion(ExcludedProfile {
                    filename: profile.filename.clone(),
                    reason: profile.reason.clone(),
                    fleet_alternative: String::new(),
                    exclude_munki_scripts: true,
                    affected_rules: profile.affected_rules.clone(),
                });
                result.profiles_added += 1;
            }
        }

        // Merge script exclusions
        for script in &plan.excluded_scripts {
            if self.is_script_excluded(&script.rule_id) {
                result.scripts_skipped += 1;
            } else {
                self.add_script_exclusion(ExcludedScript {
                    rule_id: script.rule_id.clone(),
                    reason: script.reason.clone(),
                    alternative: String::new(),
                });
                result.scripts_added += 1;
            }
        }

        result
    }
}

/// Determine script category from rule ID
fn script_category_from_rule_id(rule_id: &str) -> String {
    let id_lower = rule_id.to_lowercase();
    if id_lower.contains("sshd") {
        "sshd".to_string()
    } else if id_lower.contains("ssh") {
        "ssh".to_string()
    } else if id_lower.contains("sharing")
        || id_lower.contains("bluetooth")
        || id_lower.contains("airdrop")
        || id_lower.contains("airplay")
    {
        "sharing".to_string()
    } else if id_lower.contains("audit") || id_lower.contains("asl") {
        "audit".to_string()
    } else if id_lower.contains("auth") || id_lower.contains("pam") {
        "auth".to_string()
    } else if id_lower.contains("pwpolicy") || id_lower.contains("password") {
        "pwpolicy".to_string()
    } else {
        "system".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_constraint_type_default_filename() {
        assert_eq!(
            ConstraintType::Fleet.default_filename(),
            "fleet-constraints.yml"
        );
        assert_eq!(
            ConstraintType::Jamf.default_filename(),
            "jamf-constraints.yml"
        );
        assert_eq!(
            ConstraintType::Munki.default_filename(),
            "munki-constraints.yml"
        );
    }

    #[test]
    fn test_load_nonexistent_creates_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.yml");

        let manager = Constraints::load(ConstraintType::Fleet, Some(path)).unwrap();
        assert!(manager.get_excluded().is_empty());
        assert!(manager.get_excluded_scripts().is_empty());
    }

    #[test]
    fn test_add_and_remove_exclusion() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-constraints.yml");

        let mut manager = Constraints::load(ConstraintType::Fleet, Some(path)).unwrap();

        manager.add_exclusion(ExcludedProfile {
            filename: "test.mobileconfig".to_string(),
            reason: "Test reason".to_string(),
            fleet_alternative: "Test alternative".to_string(),
            exclude_munki_scripts: false,
            affected_rules: vec![],
        });

        assert!(manager.is_excluded("test.mobileconfig"));
        assert_eq!(manager.get_excluded().len(), 1);

        assert!(manager.remove_exclusion("test.mobileconfig"));
        assert!(!manager.is_excluded("test.mobileconfig"));
        assert!(manager.get_excluded().is_empty());
    }

    #[test]
    fn test_add_and_remove_script_exclusion() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-constraints.yml");

        let mut manager = Constraints::load(ConstraintType::Jamf, Some(path)).unwrap();

        manager.add_script_exclusion(ExcludedScript {
            rule_id: "os_sshd_client_alive_count_max_configure".to_string(),
            reason: "SSH managed by Ansible".to_string(),
            alternative: "Use existing SSH playbook".to_string(),
        });

        assert!(manager.is_script_excluded("os_sshd_client_alive_count_max_configure"));
        assert_eq!(manager.get_excluded_scripts().len(), 1);

        assert!(manager.remove_script_exclusion("os_sshd_client_alive_count_max_configure"));
        assert!(!manager.is_script_excluded("os_sshd_client_alive_count_max_configure"));
        assert!(manager.get_excluded_scripts().is_empty());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-constraints.yml");

        let mut manager = Constraints::load(ConstraintType::Fleet, Some(path.clone())).unwrap();
        manager.add_exclusion(ExcludedProfile {
            filename: "test.mobileconfig".to_string(),
            reason: "Test reason".to_string(),
            fleet_alternative: "Test alternative".to_string(),
            exclude_munki_scripts: true,
            affected_rules: vec!["rule1".to_string()],
        });
        manager.save().unwrap();

        let loaded = Constraints::load(ConstraintType::Fleet, Some(path)).unwrap();
        assert_eq!(loaded.get_excluded().len(), 1);
        assert_eq!(loaded.get_excluded()[0].filename, "test.mobileconfig");
        assert!(loaded.get_excluded()[0].exclude_munki_scripts);
    }

    #[test]
    fn test_save_and_load_scripts_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-constraints.yml");

        let mut manager = Constraints::load(ConstraintType::Jamf, Some(path.clone())).unwrap();
        manager.add_script_exclusion(ExcludedScript {
            rule_id: "os_ssh_fips_140_ciphers".to_string(),
            reason: "Custom cipher config".to_string(),
            alternative: "Deploy via separate policy".to_string(),
        });
        manager.save().unwrap();

        let loaded = Constraints::load(ConstraintType::Jamf, Some(path)).unwrap();
        assert_eq!(loaded.get_excluded_scripts().len(), 1);
        assert_eq!(
            loaded.get_excluded_scripts()[0].rule_id,
            "os_ssh_fips_140_ciphers"
        );
        assert_eq!(
            loaded.get_excluded_scripts()[0].alternative,
            "Deploy via separate policy"
        );
    }

    #[test]
    fn test_script_category_from_rule_id() {
        assert_eq!(script_category_from_rule_id("os_sshd_client_alive"), "sshd");
        assert_eq!(script_category_from_rule_id("os_ssh_fips_ciphers"), "ssh");
        assert_eq!(
            script_category_from_rule_id("os_airdrop_disable"),
            "sharing"
        );
        assert_eq!(script_category_from_rule_id("audit_flags_aa"), "audit");
        assert_eq!(
            script_category_from_rule_id("auth_pam_su_smartcard"),
            "auth"
        );
        assert_eq!(
            script_category_from_rule_id("pwpolicy_minimum_length"),
            "pwpolicy"
        );
        assert_eq!(
            script_category_from_rule_id("os_gatekeeper_enable"),
            "system"
        );
    }
}

#[cfg(test)]
mod build_dir_tests {
    use super::*;

    fn build(root: &Path, name: &str) {
        std::fs::create_dir_all(root.join("build").join(name).join("mobileconfigs")).unwrap();
    }

    /// The whole point of the exclusion workflow: an operator lists a
    /// baseline's profiles to drop the ones the MDM does better (FileVault,
    /// say). On a 2.0 build the lookup by bare name found nothing, so the
    /// picker showed an empty list — indistinguishable from "nothing to
    /// exclude", and the conflicting profile shipped.
    #[test]
    fn a_2_0_build_directory_is_found_by_the_bare_baseline_name() {
        let tmp = tempfile::tempdir().unwrap();
        build(tmp.path(), "cis_lvl1_macos_26.0");
        let dirs = Constraints::build_dirs_for(tmp.path(), "cis_lvl1");
        assert_eq!(dirs.len(), 1, "got {dirs:?}");
        assert!(dirs[0].ends_with("cis_lvl1_macos_26.0"));
    }

    #[test]
    fn a_1_x_build_directory_still_resolves() {
        let tmp = tempfile::tempdir().unwrap();
        build(tmp.path(), "cis_lvl1");
        let dirs = Constraints::build_dirs_for(tmp.path(), "cis_lvl1");
        assert_eq!(dirs.len(), 1, "got {dirs:?}");
    }

    #[test]
    fn a_different_baseline_sharing_the_prefix_is_not_matched() {
        // A live build tree carries all three of these side by side.
        // `cis_lvl1_enterprise` is a DIFFERENT baseline; offering its
        // profiles for exclusion under `cis_lvl1` would silently exclude the
        // wrong things.
        let tmp = tempfile::tempdir().unwrap();
        build(tmp.path(), "cis_lvl1");
        build(tmp.path(), "cis_lvl1_macos_26.0");
        build(tmp.path(), "cis_lvl1_enterprise");
        let dirs = Constraints::build_dirs_for(tmp.path(), "cis_lvl1");
        let names: Vec<String> = dirs
            .iter()
            .map(|d| d.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["cis_lvl1", "cis_lvl1_macos_26.0"],
            "got {names:?}"
        );
    }

    #[test]
    fn every_os_and_version_for_one_baseline_is_included() {
        let tmp = tempfile::tempdir().unwrap();
        build(tmp.path(), "cis_lvl1_macos_26.0");
        build(tmp.path(), "cis_lvl1_macos_27.0");
        build(tmp.path(), "cis_lvl1_ios_18.0");
        build(tmp.path(), "cis_lvl1_visionos_26.0");
        assert_eq!(Constraints::build_dirs_for(tmp.path(), "cis_lvl1").len(), 4);
    }

    #[test]
    fn nothing_built_yields_no_directories() {
        let tmp = tempfile::tempdir().unwrap();
        build(tmp.path(), "disa_stig_macos_27.0");
        assert!(Constraints::build_dirs_for(tmp.path(), "cis_lvl1").is_empty());
    }

    #[test]
    fn discovery_returns_empty_rather_than_every_baseline_when_nothing_matches() {
        // Falling back to the whole build/ tree would offer another
        // baseline's profiles under this name.
        let tmp = tempfile::tempdir().unwrap();
        build(tmp.path(), "disa_stig_macos_27.0");
        std::fs::write(
            tmp.path()
                .join("build/disa_stig_macos_27.0/mobileconfigs/com.apple.test.mobileconfig"),
            "<plist/>",
        )
        .unwrap();
        let found = Constraints::discover_profiles(tmp.path(), Some("cis_lvl1")).unwrap();
        assert!(found.is_empty(), "got {found:?}");
    }
}
