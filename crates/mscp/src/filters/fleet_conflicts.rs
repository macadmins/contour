// Fleet conflict filtering - public API methods
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
    /// Create a new Fleet conflict filter
    pub fn new() -> Self {
        Self::from_file(None).unwrap_or_else(|_| Self::with_defaults())
    }

    /// Create from a specific constraints file
    pub fn from_file(path: Option<&Path>) -> Result<Self> {
        let constraints_path = if let Some(p) = path {
            p.to_path_buf()
        } else {
            // Default to fleet-constraints.yml in current directory
            let default_path = PathBuf::from("fleet-constraints.yml");
            if default_path.exists() {
                default_path
            } else {
                // Fallback to hardcoded defaults if file doesn't exist
                return Ok(Self::with_defaults());
            }
        };

        // Load constraints from YAML
        let content = std::fs::read_to_string(&constraints_path).with_context(|| {
            format!(
                "Failed to read Fleet constraints: {}",
                constraints_path.display()
            )
        })?;

        let constraints: FleetConstraints = yaml_serde::from_str(&content).with_context(|| {
            format!(
                "Failed to parse Fleet constraints: {}",
                constraints_path.display()
            )
        })?;

        tracing::info!(
            "Loaded Fleet constraints from: {}",
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

    /// Create with hardcoded defaults (fallback)
    fn with_defaults() -> Self {
        let mut filter = Self {
            excluded_profiles: HashSet::new(),
            payload_key_exclusions: Vec::new(),
            constraints: FleetConstraints {
                excluded_profiles: Vec::new(),
                payload_key_exclusions: Vec::new(),
            },
        };

        filter.add_default_exclusions();
        filter
    }

    /// Add default Fleet conflict exclusions (fallback when no YAML file)
    fn add_default_exclusions(&mut self) {
        // 1. FileVault profiles (conflicts with enable_disk_encryption)
        self.excluded_profiles
            .insert("com.apple.MCX.FileVault2.mobileconfig".to_string());

        // 2. Software Update profiles (conflicts with macos_updates/ipados_updates)
        self.excluded_profiles
            .insert("com.apple.SoftwareUpdate.mobileconfig".to_string());

        // 3. macOS Setup profiles (conflicts with macos_setup)
        self.excluded_profiles
            .insert("com.apple.SetupAssistant.managed.mobileconfig".to_string());

        // 4. FileVault-related keys in MCX profiles
        self.payload_key_exclusions
            .push(PayloadKeyExclusionInternal {
                payload_type: "com.apple.MCX".to_string(),
                keys_to_remove: vec![
                    "dontAllowFDEDisable".to_string(),
                    "DestroyFVKeyOnStandby".to_string(),
                    "dontAllowFDEEnable".to_string(),
                ],
                reason: "FileVault settings conflict with Fleet's enable_disk_encryption"
                    .to_string(),
            });

        // 5. Software Update keys in any profile
        self.payload_key_exclusions
            .push(PayloadKeyExclusionInternal {
                payload_type: "com.apple.SoftwareUpdate".to_string(),
                keys_to_remove: vec![
                    "AutomaticCheckEnabled".to_string(),
                    "AutomaticDownload".to_string(),
                    "AutomaticallyInstallMacOSUpdates".to_string(),
                    "ConfigDataInstall".to_string(),
                    "CriticalUpdateInstall".to_string(),
                ],
                reason:
                    "Software Update settings conflict with Fleet's macos_updates/ipados_updates"
                        .to_string(),
            });
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

    #[test]
    fn test_excluded_profiles() {
        let filter = FleetConflictFilter::new();

        assert!(filter.should_exclude_profile("com.apple.MCX.FileVault2.mobileconfig"));
        assert!(filter.should_exclude_profile("com.apple.SoftwareUpdate.mobileconfig"));
        assert!(!filter.should_exclude_profile("com.apple.security.firewall.mobileconfig"));
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
