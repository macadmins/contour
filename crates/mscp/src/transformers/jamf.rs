use anyhow::{Context, Result};
use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// General profile postprocessing options (apply in any mode).
#[derive(Debug, Clone, Default)]
pub struct ProfileOptions {
    /// Organization display name for `PayloadOrganization` (e.g., "Macadmin")
    pub org_name: Option<String>,

    /// Remove `ConsentText` from profiles
    pub remove_consent_text: bool,

    /// Custom `ConsentText` to use (overrides removal if set)
    pub consent_text: Option<String>,

    /// Use deterministic UUIDs based on `PayloadType`
    pub deterministic_uuids: bool,
}

/// Jamf postprocessing options
#[derive(Debug, Clone, Default)]
pub struct JamfOptions {
    /// Remove creation dates from descriptions
    pub no_creation_date: bool,

    /// Use identical UUID for `PayloadIdentifier` and `PayloadUUID`
    pub identical_payload_uuid: bool,

    /// Baseline name for identifier formatting (e.g., "`cis_lvl1`")
    pub baseline: Option<String>,

    /// Organization domain for identifier prefix (e.g., "me.macadmin")
    pub domain: Option<String>,

    /// Organization display name (used for `{org_name}` in `description_format` template)
    pub org_name: Option<String>,

    /// Custom `PayloadDescription` format
    pub description_format: Option<String>,
}

/// General profile postprocessor for mobileconfig files (works in any mode).
#[derive(Debug)]
pub struct ProfilePostprocessor {
    options: ProfileOptions,
}

impl ProfilePostprocessor {
    pub fn new(options: ProfileOptions) -> Self {
        Self { options }
    }

    /// Process a mobileconfig file — set `PayloadOrganization` and handle `ConsentText`.
    pub fn process_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        tracing::debug!(
            "Applying general profile postprocessing to {}",
            path.display()
        );

        // Read plist
        let file = fs::File::open(path).context(format!("Failed to open {}", path.display()))?;
        let mut plist: Value =
            plist::from_reader(file).context(format!("Failed to parse {}", path.display()))?;

        // Apply transformations
        if let Value::Dictionary(ref mut dict) = plist {
            // Set PayloadOrganization if org_name is configured
            if let Some(ref org_name) = self.options.org_name {
                dict.insert(
                    "PayloadOrganization".to_string(),
                    Value::String(org_name.clone()),
                );
                tracing::debug!("Set PayloadOrganization to {org_name}");
            }

            // Handle ConsentText
            self.process_consent_text(dict)?;

            // Apply deterministic UUIDs
            if self.options.deterministic_uuids {
                self.process_uuids(dict)?;
            }
        }

        // Write back
        let file = fs::File::create(path).context(format!("Failed to write {}", path.display()))?;
        plist::to_writer_xml(file, &plist)
            .context(format!("Failed to serialize {}", path.display()))?;

        tracing::debug!(
            "General profile postprocessing complete for {}",
            path.display()
        );
        Ok(())
    }

    /// Process UUIDs — set deterministic `PayloadUUID` on top-level and each `PayloadContent` item.
    fn process_uuids(&self, dict: &mut Dictionary) -> Result<()> {
        let payload_type = dict
            .get("PayloadType")
            .and_then(|v| {
                if let Value::String(s) = v {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "Configuration".to_string());

        let uuid = Self::generate_deterministic_uuid(&payload_type);
        dict.insert("PayloadUUID".to_string(), Value::String(uuid.clone()));
        tracing::debug!("Set deterministic PayloadUUID: {uuid}");

        // Process PayloadContent array
        if let Some(Value::Array(content_array)) = dict.get_mut("PayloadContent") {
            for item in content_array {
                if let Value::Dictionary(item_dict) = item {
                    let item_type = item_dict
                        .get("PayloadType")
                        .and_then(|v| {
                            if let Value::String(s) = v {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| "Item".to_string());

                    let item_uuid = Self::generate_deterministic_uuid(&item_type);
                    item_dict.insert("PayloadUUID".to_string(), Value::String(item_uuid.clone()));
                }
            }
        }

        Ok(())
    }

    /// Generate a deterministic UUID from a string using SHA256.
    /// Format: 8-4-4-4-12 (standard UUID v5 format)
    pub fn generate_deterministic_uuid(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let hash = hasher.finalize();

        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]),
            u16::from_be_bytes([hash[4], hash[5]]),
            u16::from_be_bytes([hash[6], hash[7]]) & 0x0fff | 0x5000, // Version 5 UUID
            u16::from_be_bytes([hash[8], hash[9]]) & 0x3fff | 0x8000, // Variant bits
            u64::from_be_bytes([
                hash[10], hash[11], hash[12], hash[13], hash[14], hash[15], 0, 0
            ]) >> 16
        )
    }

    /// Process `ConsentText` - remove or replace with custom text
    fn process_consent_text(&self, dict: &mut Dictionary) -> Result<()> {
        if let Some(ref custom_text) = self.options.consent_text {
            let mut consent_dict = Dictionary::new();
            consent_dict.insert("default".to_string(), Value::String(custom_text.clone()));
            dict.insert("ConsentText".to_string(), Value::Dictionary(consent_dict));
            tracing::debug!("Set custom ConsentText");
        } else if self.options.remove_consent_text {
            dict.remove("ConsentText");
            tracing::debug!("Removed ConsentText");
        }

        // Also process PayloadContent array
        if let Some(Value::Array(content_array)) = dict.get_mut("PayloadContent") {
            for item in content_array {
                if let Value::Dictionary(item_dict) = item {
                    if let Some(ref custom_text) = self.options.consent_text {
                        let mut consent_dict = Dictionary::new();
                        consent_dict
                            .insert("default".to_string(), Value::String(custom_text.clone()));
                        item_dict
                            .insert("ConsentText".to_string(), Value::Dictionary(consent_dict));
                    } else if self.options.remove_consent_text {
                        item_dict.remove("ConsentText");
                    }
                }
            }
        }

        Ok(())
    }
}

/// Jamf postprocessor for mobileconfig files
#[derive(Debug)]
pub struct JamfPostprocessor {
    options: JamfOptions,
}

impl JamfPostprocessor {
    pub fn new(options: JamfOptions) -> Self {
        Self { options }
    }

    /// Process a mobileconfig file for Jamf compatibility
    pub fn process_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        tracing::debug!("Processing {} for Jamf compatibility", path.display());

        // Read plist
        let file = fs::File::open(path).context(format!("Failed to open {}", path.display()))?;
        let mut plist: Value =
            plist::from_reader(file).context(format!("Failed to parse {}", path.display()))?;

        // Apply transformations
        if let Value::Dictionary(ref mut dict) = plist {
            // Process PayloadDescription
            self.process_description(dict)?;

            if self.options.identical_payload_uuid || self.options.baseline.is_some() {
                self.process_uuids(dict)?;
            }
        }

        // Write back
        let file = fs::File::create(path).context(format!("Failed to write {}", path.display()))?;
        plist::to_writer_xml(file, &plist)
            .context(format!("Failed to serialize {}", path.display()))?;

        tracing::debug!("Jamf processing complete for {}", path.display());
        Ok(())
    }

    /// Process `PayloadDescription` - apply custom format or remove creation date
    fn process_description(&self, dict: &mut Dictionary) -> Result<()> {
        // Get PayloadType for template substitution
        let payload_type = dict.get("PayloadType").and_then(|v| {
            if let Value::String(s) = v {
                Some(s.clone())
            } else {
                None
            }
        });

        if let Some(ref format) = self.options.description_format {
            // Apply custom format
            let baseline = self.options.baseline.as_deref().unwrap_or("baseline");
            let org_name = self.options.org_name.as_deref().unwrap_or("Organization");
            let ptype = payload_type.as_deref().unwrap_or("Configuration");

            let description = format
                .replace("{baseline}", baseline)
                .replace("{payload_type}", ptype)
                .replace("{org_name}", org_name);

            dict.insert(
                "PayloadDescription".to_string(),
                Value::String(description.clone()),
            );
            tracing::debug!("Set PayloadDescription to: {description}");
        } else if self.options.no_creation_date {
            // Just remove creation date lines
            if let Some(Value::String(description)) = dict.get_mut("PayloadDescription") {
                let cleaned: Vec<&str> = description
                    .lines()
                    .filter(|line| !line.trim().starts_with("Created:"))
                    .collect();
                *description = cleaned.join("\n").trim().to_string();
                tracing::debug!("Removed creation date from PayloadDescription");
            }
        }

        // Also process PayloadContent array
        if let Some(Value::Array(content_array)) = dict.get_mut("PayloadContent") {
            for item in content_array {
                if let Value::Dictionary(item_dict) = item {
                    let item_type = item_dict.get("PayloadType").and_then(|v| {
                        if let Value::String(s) = v {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });

                    if let Some(ref format) = self.options.description_format {
                        let baseline = self.options.baseline.as_deref().unwrap_or("baseline");
                        let org_name = self.options.org_name.as_deref().unwrap_or("Organization");
                        let ptype = item_type.as_deref().unwrap_or("Configuration");

                        let description = format
                            .replace("{baseline}", baseline)
                            .replace("{payload_type}", ptype)
                            .replace("{org_name}", org_name);

                        item_dict
                            .insert("PayloadDescription".to_string(), Value::String(description));
                    } else if self.options.no_creation_date
                        && let Some(Value::String(desc)) = item_dict.get_mut("PayloadDescription")
                    {
                        let cleaned: Vec<&str> = desc
                            .lines()
                            .filter(|line| !line.trim().starts_with("Created:"))
                            .collect();
                        *desc = cleaned.join("\n").trim().to_string();
                    }
                }
            }
        }

        Ok(())
    }

    /// Process identifiers for Jamf compatibility.
    ///
    /// Deterministic UUIDs are set by `ProfilePostprocessor` (base layer).
    /// This method handles Jamf-specific extras:
    /// - `identical_payload_uuid`: copies `PayloadUUID` → `PayloadIdentifier`
    /// - `update_identifiers_with_baseline`: rewrites identifiers with `{domain}.{baseline}.{PayloadType}`
    fn process_uuids(&self, dict: &mut Dictionary) -> Result<()> {
        // If identical_payload_uuid, copy existing PayloadUUID to PayloadIdentifier
        if self.options.identical_payload_uuid {
            if let Some(Value::String(uuid)) = dict.get("PayloadUUID") {
                let uuid = uuid.clone();
                dict.insert("PayloadIdentifier".to_string(), Value::String(uuid.clone()));
                tracing::debug!("Set identical PayloadIdentifier from PayloadUUID: {}", uuid);
            }
        }

        // Update identifiers with baseline name if provided
        if let Some(ref baseline) = self.options.baseline {
            self.update_identifiers_with_baseline(dict, baseline)?;
        }

        // Process PayloadContent array
        if let Some(Value::Array(content_array)) = dict.get_mut("PayloadContent") {
            for item in content_array {
                if let Value::Dictionary(item_dict) = item {
                    if self.options.identical_payload_uuid {
                        if let Some(Value::String(uuid)) = item_dict.get("PayloadUUID") {
                            let uuid = uuid.clone();
                            item_dict.insert("PayloadIdentifier".to_string(), Value::String(uuid));
                        }
                    }

                    // Update nested payload identifiers with baseline
                    if let Some(ref baseline) = self.options.baseline {
                        self.update_identifiers_with_baseline(item_dict, baseline)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Update `PayloadIdentifier` and `PayloadDisplayName` with baseline name and domain
    /// Format: `PayloadIdentifier` = {domain}.{baseline}.{PayloadType} (e.g., `io.declarative.cis_lvl1.com.apple.MCX`)
    /// Format: `PayloadDisplayName` = [{baseline}] {`PayloadType`} settings
    fn update_identifiers_with_baseline(
        &self,
        dict: &mut Dictionary,
        baseline: &str,
    ) -> Result<()> {
        // Get PayloadType
        let payload_type = dict.get("PayloadType").and_then(|v| {
            if let Value::String(s) = v {
                Some(s.clone())
            } else {
                None
            }
        });

        if let Some(ptype) = payload_type {
            // Build PayloadIdentifier with optional domain prefix
            // Format: {domain}.{baseline}.{PayloadType} or {baseline}.{PayloadType}
            let identifier = if let Some(ref domain) = self.options.domain {
                format!("{domain}.{baseline}.{ptype}")
            } else {
                format!("{ptype}.{baseline}")
            };
            dict.insert(
                "PayloadIdentifier".to_string(),
                Value::String(identifier.clone()),
            );

            // Set PayloadDisplayName: [cis_lvl1] com.apple.MCX settings
            let display_name = format!("[{baseline}] {ptype} settings");
            dict.insert(
                "PayloadDisplayName".to_string(),
                Value::String(display_name.clone()),
            );

            tracing::debug!("Updated identifiers: {} -> {}", identifier, display_name);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_uuid_generation() {
        let uuid1 =
            ProfilePostprocessor::generate_deterministic_uuid("com.apple.security.firewall");
        let uuid2 =
            ProfilePostprocessor::generate_deterministic_uuid("com.apple.security.firewall");

        // Same input should produce same UUID
        assert_eq!(uuid1, uuid2);

        // Should be valid UUID format
        assert!(uuid1.len() > 30);
        assert!(uuid1.contains('-'));
    }

    #[test]
    fn test_different_inputs_different_uuids() {
        let uuid1 =
            ProfilePostprocessor::generate_deterministic_uuid("com.apple.security.firewall");
        let uuid2 =
            ProfilePostprocessor::generate_deterministic_uuid("com.apple.security.password");

        assert_ne!(uuid1, uuid2);
    }
}
