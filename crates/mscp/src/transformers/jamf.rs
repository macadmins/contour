use anyhow::{Context, Result};
use plist::{Dictionary, Value};
use std::fs;
use std::path::Path;

/// General profile postprocessing options (apply in any mode).
#[derive(Debug, Clone, Default)]
pub struct ProfileOptions {
    /// Organization display name for `PayloadOrganization` (e.g., "Macadmin")
    pub org_name: Option<String>,

    /// Organization reverse-domain (e.g. `com.acme`). When set, every
    /// `PayloadIdentifier` (envelope + payloads) is prefixed with it so the
    /// generated profiles carry the org domain. UUIDs are left untouched.
    pub org_domain: Option<String>,

    /// Remove `ConsentText` from profiles
    pub remove_consent_text: bool,

    /// Custom `ConsentText` to use (overrides removal if set)
    pub consent_text: Option<String>,

    /// UUIDs are v5 of each `PayloadIdentifier`
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

            // Prefix identifiers with the org reverse-domain (UUIDs untouched).
            if let Some(ref org_domain) = self.options.org_domain {
                redomain(dict, org_domain);
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
        contour_profiles::to_writer_xml(file, &plist)
            .context(format!("Failed to serialize {}", path.display()))?;

        tracing::debug!(
            "General profile postprocessing complete for {}",
            path.display()
        );
        Ok(())
    }

    /// Process UUIDs — set `PayloadUUID` on the envelope and each
    /// `PayloadContent` item to v5 of its `PayloadIdentifier` (the scheme
    /// every generator uses), in the case `[uuid] uppercase` asks for.
    fn process_uuids(&self, dict: &mut Dictionary) -> Result<()> {
        set_uuid(dict);
        if let Some(Value::Array(content_array)) = dict.get_mut("PayloadContent") {
            for item in content_array {
                if let Value::Dictionary(item_dict) = item {
                    set_uuid(item_dict);
                }
            }
        }
        Ok(())
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

/// Set `PayloadUUID` to v5 of this dict's `PayloadIdentifier` (left alone
/// when there is no identifier).
fn set_uuid(dict: &mut Dictionary) {
    let Some(Value::String(id)) = dict.get("PayloadIdentifier") else {
        return;
    };
    let uuid = contour_profiles::deterministic_uuid(id);
    let uuid = if contour_core::uuid_uppercase() { uuid } else { uuid.to_lowercase() };
    dict.insert("PayloadUUID".to_string(), Value::String(uuid));
}

/// Prefix the envelope and every payload `PayloadIdentifier` with `{org}.`.
/// UUIDs are left untouched, so cross-references (which use `PayloadUUID`) keep
/// resolving. Idempotent — an identifier already under `{org}.` is left as-is.
fn redomain(dict: &mut Dictionary, org: &str) {
    prefix_identifier(dict, org);
    if let Some(Value::Array(payloads)) = dict.get_mut("PayloadContent") {
        for payload in payloads.iter_mut() {
            if let Value::Dictionary(pd) = payload {
                prefix_identifier(pd, org);
            }
        }
    }
}

/// Prepend `{org}.` to this dict's `PayloadIdentifier` unless already present.
fn prefix_identifier(dict: &mut Dictionary, org: &str) {
    let prefix = format!("{org}.");
    let Some(Value::String(current)) = dict.get("PayloadIdentifier") else {
        return;
    };
    if current.starts_with(&prefix) {
        return;
    }
    let new = format!("{prefix}{current}");
    dict.insert("PayloadIdentifier".to_string(), Value::String(new));
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
        contour_profiles::to_writer_xml(file, &plist)
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
    /// - `update_identifiers_with_baseline`: rewrites identifiers as `{domain}.{baseline}.{PayloadType}`
    ///   (or `{PayloadType}.{baseline}` without a domain)
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
    /// Format: `PayloadIdentifier` = {domain}.{baseline}.{PayloadType} (e.g., `io.declarative.cis_lvl1.com.apple.MCX`),
    /// or {PayloadType}.{baseline} when no domain is configured (e.g., `com.apple.MCX.cis_lvl1`)
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
            // Format: {domain}.{baseline}.{PayloadType} or {PayloadType}.{baseline}
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
    fn redomain_prefixes_envelope_and_payloads_idempotently() {
        let mut payload = Dictionary::new();
        payload.insert(
            "PayloadIdentifier".into(),
            Value::String("mscp.com.apple.MCX.uuid-1".into()),
        );
        payload.insert("PayloadUUID".into(), Value::String("uuid-1".into()));
        let mut dict = Dictionary::new();
        dict.insert(
            "PayloadIdentifier".into(),
            Value::String("com.apple.MCX.cis_lvl1".into()),
        );
        dict.insert(
            "PayloadContent".into(),
            Value::Array(vec![Value::Dictionary(payload)]),
        );

        redomain(&mut dict, "com.acme");
        // Envelope + payload identifiers gain the org prefix…
        assert_eq!(
            dict.get("PayloadIdentifier").and_then(Value::as_string),
            Some("com.acme.com.apple.MCX.cis_lvl1")
        );
        let p = match dict.get("PayloadContent") {
            Some(Value::Array(a)) => a[0].as_dictionary().unwrap(),
            _ => panic!("payload"),
        };
        assert_eq!(
            p.get("PayloadIdentifier").and_then(Value::as_string),
            Some("com.acme.mscp.com.apple.MCX.uuid-1")
        );
        // …while the UUID is untouched (references keep resolving).
        assert_eq!(
            p.get("PayloadUUID").and_then(Value::as_string),
            Some("uuid-1")
        );

        // Idempotent: a second pass changes nothing.
        let before = dict.clone();
        redomain(&mut dict, "com.acme");
        assert_eq!(dict, before);
    }

    fn profile(id: &str, payload_id: &str) -> Dictionary {
        let mut payload = Dictionary::new();
        payload.insert("PayloadType".into(), Value::String("com.apple.MCX".into()));
        payload.insert("PayloadIdentifier".into(), Value::String(payload_id.into()));
        let mut dict = Dictionary::new();
        dict.insert("PayloadType".into(), Value::String("Configuration".into()));
        dict.insert("PayloadIdentifier".into(), Value::String(id.into()));
        dict.insert(
            "PayloadContent".into(),
            Value::Array(vec![Value::Dictionary(payload)]),
        );
        dict
    }

    fn uuids(dict: &Dictionary) -> (String, String) {
        let outer = dict.get("PayloadUUID").and_then(Value::as_string).unwrap();
        let inner = match dict.get("PayloadContent") {
            Some(Value::Array(a)) => a[0]
                .as_dictionary()
                .and_then(|d| d.get("PayloadUUID"))
                .and_then(Value::as_string)
                .unwrap(),
            _ => panic!("payload"),
        };
        (outer.to_string(), inner.to_string())
    }

    #[test]
    fn deterministic_uuids_are_v5_of_each_identifier() {
        let post = ProfilePostprocessor::new(ProfileOptions::default());
        let mut a = profile("com.acme.cis_lvl1.firewall", "com.acme.cis_lvl1.firewall.mcx");
        let mut b = profile("com.acme.cis_lvl1.screensaver", "com.acme.cis_lvl1.screensaver.mcx");
        post.process_uuids(&mut a).unwrap();
        post.process_uuids(&mut b).unwrap();

        // Same PayloadType, different profiles: the UUIDs must differ.
        assert_ne!(uuids(&a).0, uuids(&b).0);
        assert_ne!(uuids(&a).1, uuids(&b).1);
        // The scheme every other generator uses.
        assert_eq!(
            uuids(&a),
            (
                contour_profiles::deterministic_uuid("com.acme.cis_lvl1.firewall"),
                contour_profiles::deterministic_uuid("com.acme.cis_lvl1.firewall.mcx"),
            )
        );
    }
}
