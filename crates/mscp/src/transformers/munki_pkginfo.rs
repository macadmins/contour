// Planned feature: Munki pkginfo generation
#![allow(dead_code, reason = "module under development")]

use anyhow::{Context, Result};
use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Munki pkginfo generation options
#[derive(Debug, Clone)]
pub struct MunkiOptions {
    /// Category for Munki catalog
    pub category: String,

    /// Munki catalog name
    pub catalog: String,

    /// Developer/organization name
    pub developer: String,

    /// Enable unattended install
    pub unattended_install: bool,
}

impl Default for MunkiOptions {
    fn default() -> Self {
        Self {
            category: "Security Compliance".to_string(),
            catalog: super::munki_compliance::DEFAULT_MUNKI_CATALOG.to_string(),
            developer: "mSCP".to_string(),
            unattended_install: true,
        }
    }
}

/// Munki pkginfo generator for mobileconfig files
#[derive(Debug)]
pub struct MunkiPkginfoGenerator {
    options: MunkiOptions,
}

impl MunkiPkginfoGenerator {
    pub fn new(options: MunkiOptions) -> Self {
        Self { options }
    }

    /// Generate pkginfo for a mobileconfig file
    pub fn generate_pkginfo<P: AsRef<Path>>(&self, profile_path: P) -> Result<Dictionary> {
        let profile_path = profile_path.as_ref();

        // Read the profile to extract metadata
        let file = fs::File::open(profile_path)
            .context(format!("Failed to open {}", profile_path.display()))?;
        let profile: Value = plist::from_reader(file)
            .context(format!("Failed to parse {}", profile_path.display()))?;

        let profile_dict = profile
            .as_dictionary()
            .context("Profile is not a dictionary")?;

        // Extract key fields
        let payload_identifier = profile_dict
            .get("PayloadIdentifier")
            .and_then(|v| v.as_string())
            .context("Missing PayloadIdentifier")?
            .to_string();

        let display_name = profile_dict
            .get("PayloadDisplayName")
            .and_then(|v| v.as_string())
            .unwrap_or(&payload_identifier);

        let description = profile_dict
            .get("PayloadDescription")
            .and_then(|v| v.as_string())
            .unwrap_or("");

        // Calculate SHA256 hash of the mobileconfig file
        let file_contents = fs::read(profile_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&file_contents);
        // Convert hash bytes to hex string using fold for efficiency
        let hash_bytes = hasher.finalize();
        use std::fmt::Write as _;
        let hash = hash_bytes
            .iter()
            .fold(String::with_capacity(64), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            });

        // Build pkginfo dictionary
        let mut pkginfo = Dictionary::new();

        // Required fields
        pkginfo.insert(
            "name".to_string(),
            Value::String(payload_identifier.clone()),
        );
        pkginfo.insert(
            "display_name".to_string(),
            Value::String(display_name.to_string()),
        );
        pkginfo.insert(
            "description".to_string(),
            Value::String(description.to_string()),
        );
        pkginfo.insert("version".to_string(), Value::String("1.0".to_string()));
        pkginfo.insert(
            "installer_type".to_string(),
            Value::String("profile".to_string()),
        );
        pkginfo.insert(
            "uninstall_method".to_string(),
            Value::String("remove_profile".to_string()),
        );

        // Profile-specific fields
        pkginfo.insert(
            "PayloadIdentifier".to_string(),
            Value::String(payload_identifier.clone()),
        );
        pkginfo.insert("installer_item_hash".to_string(), Value::String(hash));

        // Get filename
        let filename = profile_path
            .file_name()
            .and_then(|n| n.to_str())
            .context("Invalid filename")?;
        pkginfo.insert(
            "installer_item_location".to_string(),
            Value::String(format!("profiles/{filename}")),
        );

        // Optional fields from options
        pkginfo.insert(
            "category".to_string(),
            Value::String(self.options.category.clone()),
        );
        pkginfo.insert(
            "developer".to_string(),
            Value::String(self.options.developer.clone()),
        );
        pkginfo.insert(
            "unattended_install".to_string(),
            Value::Boolean(self.options.unattended_install),
        );

        // Catalogs array
        let catalogs = vec![Value::String(self.options.catalog.clone())];
        pkginfo.insert("catalogs".to_string(), Value::Array(catalogs));

        // Metadata
        pkginfo.insert(
            "minimum_os_version".to_string(),
            Value::String("10.15".to_string()),
        );

        Ok(pkginfo)
    }

    /// Write pkginfo to file
    pub fn write_pkginfo<P: AsRef<Path>>(
        &self,
        pkginfo: &Dictionary,
        output_path: P,
    ) -> Result<()> {
        let output_path = output_path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = fs::File::create(output_path)
            .context(format!("Failed to create {}", output_path.display()))?;

        plist::to_writer_xml(file, pkginfo)
            .context(format!("Failed to write {}", output_path.display()))?;

        tracing::debug!("Wrote pkginfo to: {}", output_path.display());
        Ok(())
    }

    /// Generate pkginfo for all profiles in a baseline
    pub fn generate_for_baseline<P: AsRef<Path>>(
        &self,
        profiles_dir: P,
        pkginfo_dir: P,
    ) -> Result<Vec<(String, String)>> {
        let profiles_dir = profiles_dir.as_ref();
        let pkginfo_dir = pkginfo_dir.as_ref();

        if !profiles_dir.exists() {
            anyhow::bail!(
                "Profiles directory does not exist: {}",
                profiles_dir.display()
            );
        }

        fs::create_dir_all(pkginfo_dir)?;

        let mut generated = Vec::new();

        // Iterate over all .mobileconfig files
        for entry in fs::read_dir(profiles_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("mobileconfig") {
                let pkginfo = self.generate_pkginfo(&path)?;

                // Get profile name for pkginfo filename
                let profile_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .context("Invalid profile filename")?;

                let pkginfo_path = pkginfo_dir.join(format!("{profile_name}.plist"));
                self.write_pkginfo(&pkginfo, &pkginfo_path)?;

                generated.push((
                    path.display().to_string(),
                    pkginfo_path.display().to_string(),
                ));
            }
        }

        tracing::info!("Generated {} Munki pkginfo files", generated.len());
        Ok(generated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_munki_options_default() {
        let options = MunkiOptions::default();
        assert_eq!(options.category, "Security Compliance");
        assert_eq!(options.catalog, "production");
        assert_eq!(options.developer, "mSCP");
        assert!(options.unattended_install);
    }

    #[test]
    fn test_generator_creation() {
        let options = MunkiOptions::default();
        let _generator = MunkiPkginfoGenerator::new(options);
    }
}
