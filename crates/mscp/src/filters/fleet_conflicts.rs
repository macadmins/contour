//! Fleet conflict filter — what Fleet already manages natively, so an mSCP
//! baseline does not fight it.
//!
//! # Where the constraints come from — read this before touching `new()`
//!
//! The constraints are DATA, and they live in ONE place:
//! `crates/mscp/fleet-constraints.yml`. That file is compiled into this binary with
//! `include_str!`, so it is always present and always the version that
//! shipped with this build. There is no fallback list in code, and there
//! must not be one.
//!
//! A code-side fallback list would drift from the YAML, and would make "file
//! not found" indistinguishable from "constraints loaded" — absence dressed
//! as data.
//!
//! Resolution order, in full:
//!
//!   1. `from_file(Some(path))` — an operator override. It must exist and
//!      parse. A missing or malformed override is an ERROR, never a silent
//!      substitution of anything else.
//!   2. `from_file(None)`, `new()`, `Default` — the embedded YAML. Always.
//!
//! To change a constraint, edit the YAML. The tests at the bottom load the
//! embedded copy and assert entries only the YAML carries.
#![allow(dead_code, reason = "module under development")]

use anyhow::{Context, Result};
use plist::Value as PlistValue;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Fleet constraint definition from YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FleetConstraints {
    excluded_profiles: Vec<ExcludedProfile>,
    payload_key_exclusions: Vec<PayloadKeyExclusion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExcludedProfile {
    filename: String,
    reason: String,
    fleet_alternative: String,
    #[serde(default)]
    exclude_munki_scripts: bool,
    #[serde(default)]
    affected_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PayloadKeyExclusion {
    payload_type: String,
    keys_to_remove: Vec<String>,
    reason: String,
    fleet_alternative: String,
}

/// Fleet conflict filter - excludes profiles and strips keys that conflict with Fleet native settings
#[derive(Debug)]
pub struct FleetConflictFilter {
    /// Profiles to exclude entirely (by filename)
    excluded_profiles: HashSet<String>,

    /// Payload keys to strip from any profile
    payload_key_exclusions: Vec<PayloadKeyExclusionInternal>,

    /// Constraints loaded from file
    constraints: FleetConstraints,
}

/// Internal representation of payload key exclusion
#[derive(Debug, Clone)]
struct PayloadKeyExclusionInternal {
    payload_type: String,
    keys_to_remove: Vec<String>,
    reason: String,
}

impl FleetConflictFilter {
    /// The embedded constraints. See the module docs for why there is no
    /// other default.
    pub fn new() -> Self {
        Self::embedded()
    }

    /// The constraints compiled into this binary: `crates/mscp/fleet-constraints.yml`.
    pub const EMBEDDED_CONSTRAINTS: &str = include_str!("../../fleet-constraints.yml");

    /// The embedded constraints. Infallible for a shipped build: the YAML is
    /// part of the crate, and `embedded_constraints_parse` fails the build's
    /// test run before a malformed file can reach a user.
    fn embedded() -> Self {
        Self::parse(Self::EMBEDDED_CONSTRAINTS, "embedded fleet-constraints.yml")
            .expect("embedded fleet-constraints.yml is malformed — the crate cannot ship like this")
    }

    /// Load constraints. `None` is the embedded YAML; `Some(path)` is an
    /// operator override that must exist and parse — it never falls back.
    pub fn from_file(path: Option<&Path>) -> Result<Self> {
        let Some(p) = path else {
            return Ok(Self::embedded());
        };
        let content = std::fs::read_to_string(p).with_context(|| {
            format!(
                "Fleet constraints override not readable: {} — an override must exist; \
                 there is no fallback, and the embedded constraints are used only when no \
                 override is given",
                p.display()
            )
        })?;
        let filter = Self::parse(&content, &p.display().to_string())?;
        tracing::info!("Loaded Fleet constraints override from: {}", p.display());
        Ok(filter)
    }

    fn parse(content: &str, source: &str) -> Result<Self> {
        let constraints: FleetConstraints = yaml_serde::from_str(content)
            .with_context(|| format!("Failed to parse Fleet constraints: {source}"))?;
        tracing::debug!(
            "Fleet constraints ({source}): {} excluded profiles, {} key exclusions",
            constraints.excluded_profiles.len(),
            constraints.payload_key_exclusions.len()
        );
        Ok(Self::from_constraints(constraints))
    }

    /// Create from constraints struct
    fn from_constraints(constraints: FleetConstraints) -> Self {
        let mut excluded_profiles = HashSet::new();
        for profile in &constraints.excluded_profiles {
            excluded_profiles.insert(profile.filename.clone());
        }

        let payload_key_exclusions = constraints
            .payload_key_exclusions
            .iter()
            .map(|exclusion| PayloadKeyExclusionInternal {
                payload_type: exclusion.payload_type.clone(),
                keys_to_remove: exclusion.keys_to_remove.clone(),
                reason: exclusion.reason.clone(),
            })
            .collect();

        Self {
            excluded_profiles,
            payload_key_exclusions,
            constraints,
        }
    }

    /// Check if a profile should be excluded
    pub fn should_exclude_profile(&self, filename: &str) -> bool {
        self.excluded_profiles.contains(filename)
    }

    /// Process a profile file, stripping conflicting keys
    /// Returns Ok(true) if the profile was modified, Ok(false) if no changes needed
    pub fn process_profile(&self, profile_path: &Path) -> Result<bool> {
        let filename = profile_path
            .file_name()
            .and_then(|s| s.to_str())
            .context("Invalid profile filename")?;

        // Check if this profile should be excluded entirely
        if self.should_exclude_profile(filename) {
            tracing::info!("Skipping excluded profile: {}", filename);
            return Ok(false);
        }

        // Read the plist
        let file = std::fs::File::open(profile_path)
            .with_context(|| format!("Failed to open profile: {}", profile_path.display()))?;

        let mut plist: PlistValue = plist::from_reader(file).with_context(|| {
            format!("Failed to parse profile plist: {}", profile_path.display())
        })?;

        // Process the plist
        let modified = self.strip_conflicting_keys(&mut plist, filename)?;

        // Write back if modified
        if modified {
            tracing::info!("Stripped conflicting keys from: {}", filename);

            // Write updated plist
            let file = std::fs::File::create(profile_path)
                .with_context(|| format!("Failed to write profile: {}", profile_path.display()))?;

            plist::to_writer_xml(file, &plist).with_context(|| {
                format!("Failed to serialize profile: {}", profile_path.display())
            })?;
        }

        Ok(modified)
    }

    /// Strip conflicting keys from a plist value
    fn strip_conflicting_keys(&self, plist: &mut PlistValue, filename: &str) -> Result<bool> {
        let mut modified = false;

        // Navigate to PayloadContent array
        if let Some(dict) = plist.as_dictionary_mut() {
            if let Some(PlistValue::Array(payload_content)) = dict.get_mut("PayloadContent") {
                // Iterate through each payload
                for payload in payload_content.iter_mut() {
                    if let Some(payload_dict) = payload.as_dictionary_mut() {
                        // Get PayloadType (clone to avoid borrow conflict)
                        let payload_type = payload_dict
                            .get("PayloadType")
                            .and_then(|v| v.as_string())
                            .unwrap_or("")
                            .to_string();

                        // Check if this payload type has key exclusions
                        for exclusion in &self.payload_key_exclusions {
                            if payload_type == exclusion.payload_type {
                                // Remove excluded keys
                                for key in &exclusion.keys_to_remove {
                                    if payload_dict.remove(key).is_some() {
                                        tracing::debug!(
                                            "Removed key '{}' from {} in {}: {}",
                                            key,
                                            payload_type,
                                            filename,
                                            exclusion.reason
                                        );
                                        modified = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Also update PayloadDescription to note the modification
            if modified
                && let Some(desc) = dict.get_mut("PayloadDescription")
                && let Some(desc_str) = desc.as_string()
            {
                let updated_desc = format!(
                    "{desc_str}\n\nNote: This profile has been automatically modified by contour mscp to remove settings that conflict with Fleet native configuration."
                );
                *desc = PlistValue::String(updated_desc);
            }
        }

        Ok(modified)
    }

    /// Filter a list of profile paths, excluding conflicting profiles
    pub fn filter_profiles(&self, profile_paths: Vec<PathBuf>) -> Vec<PathBuf> {
        profile_paths
            .into_iter()
            .filter(|path| {
                if let Some(filename) = path.file_name().and_then(|s| s.to_str())
                    && self.should_exclude_profile(filename)
                {
                    tracing::info!("Excluding profile from baseline: {}", filename);
                    return false;
                }
                true
            })
            .collect()
    }

    /// Get summary of exclusions for reporting
    pub fn get_exclusion_summary(&self) -> String {
        let mut summary = String::new();

        summary.push_str("Fleet Conflict Filter - Exclusions:\n\n");

        summary.push_str("Excluded Profiles:\n");
        for profile in &self.excluded_profiles {
            summary.push_str(&format!("  - {profile}\n"));
        }

        summary.push_str("\nPayload Key Exclusions:\n");
        for exclusion in &self.payload_key_exclusions {
            summary.push_str(&format!(
                "  - {} ({})\n",
                exclusion.payload_type, exclusion.reason
            ));
            for key in &exclusion.keys_to_remove {
                summary.push_str(&format!("      • {key}\n"));
            }
        }

        summary
    }

    /// Get list of Munki rule IDs that should be excluded
    pub fn get_excluded_munki_rules(&self) -> HashSet<String> {
        let mut excluded_rules = HashSet::new();

        for profile in &self.constraints.excluded_profiles {
            if profile.exclude_munki_scripts {
                for rule_id in &profile.affected_rules {
                    excluded_rules.insert(rule_id.clone());
                }
            }
        }

        excluded_rules
    }
}

impl Default for FleetConflictFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped YAML parses. This is what lets `embedded()` be
    /// infallible: a malformed file fails here, in CI, not in a user's
    /// `--fleet-mode` run.
    #[test]
    fn embedded_constraints_parse() {
        FleetConflictFilter::parse(FleetConflictFilter::EMBEDDED_CONSTRAINTS, "test")
            .expect("crates/mscp/fleet-constraints.yml must parse");
    }

    /// `new()` is the YAML, not a code list. Smartcard is the witness: the
    /// YAML excludes it, so `--fleet-mode` must not ship it.
    #[test]
    fn new_loads_the_yaml_not_a_code_list() {
        let filter = FleetConflictFilter::new();
        assert!(filter.should_exclude_profile("com.apple.MCX.FileVault2.mobileconfig"));
        assert!(filter.should_exclude_profile("com.apple.SoftwareUpdate.mobileconfig"));
        assert!(
            filter.should_exclude_profile("com.apple.security.smartcard.mobileconfig"),
            "smartcard is excluded in fleet-constraints.yml; if this fails, new() is not \
             reading the YAML"
        );
        assert!(!filter.should_exclude_profile("com.apple.security.firewall.mobileconfig"));
    }

    /// An override that is not there is an error, not a quiet substitution.
    #[test]
    fn a_missing_override_is_an_error_not_a_fallback() {
        let err =
            FleetConflictFilter::from_file(Some(Path::new("/nonexistent/fleet-constraints.yml")))
                .err()
                .expect("a missing override must not load anything");
        assert!(err.to_string().contains("no fallback"), "{err}");
    }

    #[test]
    fn test_filter_profiles() {
        let filter = FleetConflictFilter::new();

        let profiles = vec![
            PathBuf::from("profiles/com.apple.MCX.FileVault2.mobileconfig"),
            PathBuf::from("profiles/com.apple.security.firewall.mobileconfig"),
            PathBuf::from("profiles/com.apple.SoftwareUpdate.mobileconfig"),
        ];

        let filtered = filter.filter_profiles(profiles);
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered[0].file_name().unwrap().to_str().unwrap(),
            "com.apple.security.firewall.mobileconfig"
        );
    }

    #[test]
    fn test_exclusion_summary() {
        let filter = FleetConflictFilter::new();
        let summary = filter.get_exclusion_summary();

        assert!(summary.contains("com.apple.MCX.FileVault2.mobileconfig"));
        assert!(summary.contains("dontAllowFDEDisable"));
        assert!(summary.contains("com.apple.MCX"));
    }
}
