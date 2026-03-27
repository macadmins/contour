// Jamf conflict filtering - public API methods
#![allow(dead_code, reason = "module under development")]

use anyhow::{Context, Result};
use plist::Value as PlistValue;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

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
    /// Create a new Jamf conflict filter with default exclusions
    pub fn new() -> Result<Self> {
        Self::from_file(None)
    }

    /// Create from a specific constraints file
    pub fn from_file(path: Option<&Path>) -> Result<Self> {
        let constraints_path = if let Some(p) = path {
            p.to_path_buf()
        } else {
            // Default to jamf-constraints.yml in current directory or repo root
            let default_path = PathBuf::from("jamf-constraints.yml");
            if default_path.exists() {
                default_path
            } else {
                // Fallback to embedded defaults if file doesn't exist
                return Ok(Self::with_defaults());
            }
        };

        // Load constraints from YAML
        let content = std::fs::read_to_string(&constraints_path).with_context(|| {
            format!(
                "Failed to read Jamf constraints: {}",
                constraints_path.display()
            )
        })?;

        let constraints: JamfConstraints = yaml_serde::from_str(&content).with_context(|| {
            format!(
                "Failed to parse Jamf constraints: {}",
                constraints_path.display()
            )
        })?;

        tracing::info!(
            "Loaded Jamf constraints from: {}",
            constraints_path.display()
        );
        tracing::debug!(
            "  Excluded profiles: {}",
            constraints.excluded_profiles.len()
        );
        tracing::debug!(
            "  Payload key exclusions: {}",
            constraints.payload_key_exclusions.len()
        );

        Ok(Self::from_constraints(constraints))
    }

    /// Create with hardcoded defaults (fallback)
    fn with_defaults() -> Self {
        let mut filter = Self {
            excluded_profiles: HashSet::new(),
            payload_key_exclusions: Vec::new(),
            constraints: JamfConstraints {
                excluded_profiles: Vec::new(),
                payload_key_exclusions: Vec::new(),
                safe_for_jamf: Vec::new(),
            },
        };

        // Add basic defaults
        filter
            .excluded_profiles
            .insert("com.apple.MCX.FileVault2.mobileconfig".to_string());
        filter
            .excluded_profiles
            .insert("com.apple.security.FDERecoveryKeyEscrow.mobileconfig".to_string());

        filter
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
        Self::new().unwrap_or_else(|_| Self::with_defaults())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_defaults() {
        let filter = JamfConflictFilter::with_defaults();

        assert!(filter.should_exclude_profile("com.apple.MCX.FileVault2.mobileconfig"));
        assert!(
            filter.should_exclude_profile("com.apple.security.FDERecoveryKeyEscrow.mobileconfig")
        );
        assert!(!filter.should_exclude_profile("com.apple.security.firewall.mobileconfig"));
    }
}
