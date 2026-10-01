//! Jamf conflict filter — what Jamf already manages natively, so an mSCP
//! baseline does not fight it.
//!
//! # Where the constraints come from — read this before touching `new()`
//!
//! The constraints are DATA, and they live in ONE place:
//! `crates/mscp/jamf-constraints.yml`. That file is compiled into this binary with
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
use std::path::Path;

/// Jamf constraint definition from YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JamfConstraints {
    excluded_profiles: Vec<ExcludedProfile>,
    payload_key_exclusions: Vec<PayloadKeyExclusion>,
    #[serde(default)]
    safe_for_jamf: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExcludedProfile {
    filename: String,
    reason: String,
    jamf_alternative: String,
    #[serde(default)]
    note: Option<String>,
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
    jamf_alternative: String,
    #[serde(default)]
    conditional: Option<String>,
}

/// Jamf conflict filter - excludes profiles and strips keys that conflict with Jamf Pro
#[derive(Debug)]
pub struct JamfConflictFilter {
    /// Profiles to exclude entirely (by filename)
    excluded_profiles: HashSet<String>,

    /// Payload keys to strip from profiles
    payload_key_exclusions: Vec<PayloadKeyExclusionInternal>,

    /// Constraints loaded from file
    constraints: JamfConstraints,
}

/// Internal representation of payload key exclusion
#[derive(Debug, Clone)]
struct PayloadKeyExclusionInternal {
    payload_type: String,
    keys_to_remove: Vec<String>,
    reason: String,
}

impl JamfConflictFilter {
    /// The embedded constraints. See the module docs for why there is no
    /// other default.
    pub fn new() -> Result<Self> {
        Ok(Self::embedded())
    }

    /// The constraints compiled into this binary: `crates/mscp/jamf-constraints.yml`.
    pub const EMBEDDED_CONSTRAINTS: &str = include_str!("../../jamf-constraints.yml");

    /// The embedded constraints. Infallible for a shipped build: the YAML is
    /// part of the crate, and `embedded_constraints_parse` fails the build's
    /// test run before a malformed file can reach a user.
    fn embedded() -> Self {
        Self::parse(Self::EMBEDDED_CONSTRAINTS, "embedded jamf-constraints.yml")
            .expect("embedded jamf-constraints.yml is malformed — the crate cannot ship like this")
    }

    /// Load constraints. `None` is the embedded YAML; `Some(path)` is an
    /// operator override that must exist and parse — it never falls back.
    pub fn from_file(path: Option<&Path>) -> Result<Self> {
        let Some(p) = path else {
            return Ok(Self::embedded());
        };
        let content = std::fs::read_to_string(p).with_context(|| {
            format!(
                "Jamf constraints override not readable: {} — an override must exist; \
                 there is no fallback, and the embedded constraints are used only when no \
                 override is given",
                p.display()
            )
        })?;
        let filter = Self::parse(&content, &p.display().to_string())?;
        tracing::info!("Loaded Jamf constraints override from: {}", p.display());
        Ok(filter)
    }

    fn parse(content: &str, source: &str) -> Result<Self> {
        let constraints: JamfConstraints = yaml_serde::from_str(content)
            .with_context(|| format!("Failed to parse Jamf constraints: {source}"))?;
        tracing::debug!(
            "Jamf constraints ({source}): {} excluded profiles, {} key exclusions",
            constraints.excluded_profiles.len(),
            constraints.payload_key_exclusions.len()
        );
        Ok(Self::from_constraints(constraints))
    }

    /// Create from loaded constraints
    fn from_constraints(constraints: JamfConstraints) -> Self {
        let mut excluded_profiles = HashSet::new();
        for profile in &constraints.excluded_profiles {
            excluded_profiles.insert(profile.filename.clone());
        }

        let payload_key_exclusions = constraints
            .payload_key_exclusions
            .iter()
            .map(|exc| PayloadKeyExclusionInternal {
                payload_type: exc.payload_type.clone(),
                keys_to_remove: exc.keys_to_remove.clone(),
                reason: exc.reason.clone(),
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

    /// Get the reason for excluding a profile
    pub fn get_exclusion_reason(&self, filename: &str) -> Option<&str> {
        self.constraints
            .excluded_profiles
            .iter()
            .find(|p| p.filename == filename)
            .map(|p| p.reason.as_str())
    }

    /// Get Jamf alternative for an excluded profile
    pub fn get_jamf_alternative(&self, filename: &str) -> Option<&str> {
        self.constraints
            .excluded_profiles
            .iter()
            .find(|p| p.filename == filename)
            .map(|p| p.jamf_alternative.as_str())
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
            tracing::info!("Skipping excluded profile for Jamf: {}", filename);
            if let Some(reason) = self.get_exclusion_reason(filename) {
                tracing::debug!("  Reason: {}", reason);
            }
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
            tracing::info!("Stripped Jamf-conflicting keys from: {}", filename);

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
                                            "Removed Jamf-conflicting key '{}' from {} in {}: {}",
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
                    "{desc_str}\n\nNote: This profile has been automatically modified by contour mscp to remove settings that conflict with Jamf Pro native configuration."
                );
                *desc = PlistValue::String(updated_desc);
            }
        }

        Ok(modified)
    }

    /// Get summary of exclusions for reporting
    pub fn get_exclusion_summary(&self) -> String {
        let mut summary = String::new();

        summary.push_str("Jamf Conflict Filter - Exclusions:\n\n");

        summary.push_str("Excluded Profiles:\n");
        for profile in &self.constraints.excluded_profiles {
            summary.push_str(&format!("  - {} ({})\n", profile.filename, profile.reason));
            summary.push_str(&format!(
                "      Jamf alternative: {}\n",
                profile.jamf_alternative
            ));
            if let Some(note) = &profile.note {
                summary.push_str(&format!("      Note: {note}\n"));
            }
        }

        summary.push_str("\nPayload Key Exclusions:\n");
        for exclusion in &self.constraints.payload_key_exclusions {
            summary.push_str(&format!(
                "  - {} ({})\n",
                exclusion.payload_type, exclusion.reason
            ));
            for key in &exclusion.keys_to_remove {
                summary.push_str(&format!("      • {key}\n"));
            }
            summary.push_str(&format!(
                "      Jamf alternative: {}\n",
                exclusion.jamf_alternative
            ));
            if let Some(cond) = &exclusion.conditional {
                summary.push_str(&format!("      Conditional: {cond}\n"));
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

impl Default for JamfConflictFilter {
    fn default() -> Self {
        Self::embedded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_constraints_parse() {
        JamfConflictFilter::parse(JamfConflictFilter::EMBEDDED_CONSTRAINTS, "test")
            .expect("crates/mscp/jamf-constraints.yml must parse");
    }

    /// `new()` is the YAML, not a code list. SoftwareUpdate and
    /// SetupAssistant are the witnesses: the YAML excludes both.
    #[test]
    fn new_loads_the_yaml_not_a_code_list() {
        let filter = JamfConflictFilter::new().unwrap();
        assert!(filter.should_exclude_profile("com.apple.MCX.FileVault2.mobileconfig"));
        assert!(
            filter.should_exclude_profile("com.apple.security.FDERecoveryKeyEscrow.mobileconfig")
        );
        assert!(
            filter.should_exclude_profile("com.apple.SoftwareUpdate.mobileconfig"),
            "in jamf-constraints.yml, absent from the old code list"
        );
        assert!(
            filter.should_exclude_profile("com.apple.SetupAssistant.managed.mobileconfig"),
            "in jamf-constraints.yml, absent from the old code list"
        );
        assert!(
            filter.get_exclusion_summary().contains("com.apple.mdm"),
            "the com.apple.mdm key exclusions exist only in the YAML"
        );
        assert!(!filter.should_exclude_profile("com.apple.security.firewall.mobileconfig"));
    }

    #[test]
    fn a_missing_override_is_an_error_not_a_fallback() {
        let err =
            JamfConflictFilter::from_file(Some(Path::new("/nonexistent/jamf-constraints.yml")))
                .err()
                .expect("a missing override must not load anything");
        assert!(err.to_string().contains("no fallback"), "{err}");
    }
}
