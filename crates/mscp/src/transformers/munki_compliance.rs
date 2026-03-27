use anyhow::{Context, Result};
use plist::{Dictionary, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// Default path for the mSCP compliance plist on macOS.
pub const DEFAULT_COMPLIANCE_PLIST_PATH: &str =
    "/Library/Managed Preferences/mscp_compliance.plist";
/// Default Munki catalog for mSCP packages.
pub const DEFAULT_MUNKI_CATALOG: &str = "production";
/// Default Munki category for mSCP packages.
pub const DEFAULT_MUNKI_CATEGORY: &str = "mSCP Compliance";
/// Default prefix for mSCP compliance flags.
pub const DEFAULT_FLAG_PREFIX: &str = "mscp_";

/// Munki compliance flag writer options
#[derive(Debug, Clone)]
pub struct MunkiComplianceOptions {
    /// Path where compliance plist should be written on target systems
    /// Default: /Library/Managed `Preferences/mscp_compliance.plist`
    pub target_path: PathBuf,

    /// Prefix for compliance flags (e.g., "`mscp_cis_lvl1`_")
    pub flag_prefix: String,
}

impl Default for MunkiComplianceOptions {
    fn default() -> Self {
        Self {
            target_path: PathBuf::from(DEFAULT_COMPLIANCE_PLIST_PATH),
            flag_prefix: DEFAULT_FLAG_PREFIX.to_string(),
        }
    }
}

/// Munki compliance flag generator
///
/// This generates Munki nopkg items that write compliance flags to a plist file.
/// The flags can then be read by osquery/FleetDM for profile scoping.
///
/// Based on: <https://jc0b.computer/posts/munki-mscp-generator>/
#[derive(Debug)]
pub struct MunkiComplianceGenerator {
    options: MunkiComplianceOptions,
}

impl MunkiComplianceGenerator {
    pub fn new(options: MunkiComplianceOptions) -> Self {
        Self { options }
    }

    /// Generate a nopkg pkginfo that writes compliance flags
    ///
    /// This creates a Munki item that:
    /// 1. Checks if the flag plist needs updating (`installcheck_script`)
    /// 2. Writes the compliance flags to the plist (`postinstall_script`)
    /// 3. Can be scoped via Munki manifests
    ///
    /// The flags are based on profile `PayloadIdentifiers`, which can be read by
    /// osquery/FleetDM for dynamic profile scoping.
    pub fn generate_flag_writer_pkginfo(
        &self,
        baseline_name: &str,
        payload_identifiers: &[String],
    ) -> Result<Dictionary> {
        let mut pkginfo = Dictionary::new();

        // Basic metadata
        let name = format!("{}_{}_flags", self.options.flag_prefix, baseline_name);
        pkginfo.insert("name".to_string(), Value::String(name.clone()));
        pkginfo.insert(
            "display_name".to_string(),
            Value::String(format!("mSCP {baseline_name} Compliance Flags")),
        );
        pkginfo.insert(
            "description".to_string(),
            Value::String(format!(
                "Writes compliance flags for {} baseline to {}. \
                          These flags can be read by osquery/FleetDM for profile scoping.",
                baseline_name,
                self.options.target_path.display()
            )),
        );
        pkginfo.insert("version".to_string(), Value::String("1.0".to_string()));

        // nopkg settings
        pkginfo.insert(
            "installer_type".to_string(),
            Value::String("nopkg".to_string()),
        );
        pkginfo.insert("uninstallable".to_string(), Value::Boolean(false));
        pkginfo.insert("unattended_install".to_string(), Value::Boolean(true));

        // Catalogs
        pkginfo.insert(
            "catalogs".to_string(),
            Value::Array(vec![Value::String(DEFAULT_MUNKI_CATALOG.to_string())]),
        );
        pkginfo.insert(
            "category".to_string(),
            Value::String(DEFAULT_MUNKI_CATEGORY.to_string()),
        );

        // installcheck_script - checks if plist needs updating
        let installcheck_script =
            self.generate_installcheck_script(baseline_name, payload_identifiers);
        pkginfo.insert(
            "installcheck_script".to_string(),
            Value::String(installcheck_script),
        );

        // postinstall_script - writes the compliance flags
        let postinstall_script =
            self.generate_postinstall_script(baseline_name, payload_identifiers);
        pkginfo.insert(
            "postinstall_script".to_string(),
            Value::String(postinstall_script),
        );

        Ok(pkginfo)
    }

    /// Generate installcheck script
    /// Returns exit 0 if flags need to be written/updated
    fn generate_installcheck_script(
        &self,
        baseline_name: &str,
        payload_identifiers: &[String],
    ) -> String {
        let expected_flags: Vec<String> = payload_identifiers
            .iter()
            .map(|id| {
                // Sanitize PayloadIdentifier for use as plist key
                let sanitized = id.replace(['.', '-'], "_");
                format!("{}{}", self.options.flag_prefix, sanitized)
            })
            .collect();

        format!(
            r#"#!/bin/bash
# Installcheck script for mSCP {} compliance flags
# Checks if the compliance plist needs updating

PLIST_PATH="{}"

# If plist doesn't exist, we need to create it
if [[ ! -f "$PLIST_PATH" ]]; then
    exit 0
fi

# Check if all expected flags are present
EXPECTED_FLAGS=(
{}
)

for flag in "${{EXPECTED_FLAGS[@]}}"; do
    if ! /usr/libexec/PlistBuddy -c "Print :$flag" "$PLIST_PATH" &>/dev/null; then
        # Flag missing, need to update
        exit 0
    fi
done

# All flags present, no update needed
exit 1
"#,
            baseline_name,
            self.options.target_path.display(),
            expected_flags
                .iter()
                .map(|f| format!("    \"{f}\""))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    /// Generate postinstall script
    /// Writes compliance flags to the plist
    fn generate_postinstall_script(
        &self,
        baseline_name: &str,
        payload_identifiers: &[String],
    ) -> String {
        let flag_entries: Vec<String> = payload_identifiers
            .iter()
            .map(|id| {
                // Sanitize PayloadIdentifier for use as plist key
                let sanitized = id.replace(['.', '-'], "_");
                let flag_name = format!("{}{}", self.options.flag_prefix, sanitized);
                format!(r#"/usr/libexec/PlistBuddy -c "Add :{flag_name} bool true" "$PLIST_PATH" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c "Set :{flag_name} true" "$PLIST_PATH""#)
            })
            .collect();

        format!(
            r#"#!/bin/bash
# Postinstall script for mSCP {} compliance flags
# Writes compliance flags to plist for osquery/FleetDM integration

PLIST_PATH="{}"
PLIST_DIR="$(dirname "$PLIST_PATH")"

# Ensure directory exists
mkdir -p "$PLIST_DIR"

# Create plist if it doesn't exist
if [[ ! -f "$PLIST_PATH" ]]; then
    /usr/libexec/PlistBuddy -c "Save" "$PLIST_PATH"
fi

# Write compliance flags
{}

# Set proper permissions
chmod 644 "$PLIST_PATH"

echo "Compliance flags written to $PLIST_PATH"
exit 0
"#,
            baseline_name,
            self.options.target_path.display(),
            flag_entries.join("\n")
        )
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

        tracing::debug!(
            "Wrote compliance flag pkginfo to: {}",
            output_path.display()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_options_default() {
        let options = MunkiComplianceOptions::default();
        assert_eq!(
            options.target_path,
            PathBuf::from(DEFAULT_COMPLIANCE_PLIST_PATH)
        );
        assert_eq!(options.flag_prefix, DEFAULT_FLAG_PREFIX);
    }

    #[test]
    fn test_generator_creation() {
        let options = MunkiComplianceOptions::default();
        let _generator = MunkiComplianceGenerator::new(options);
    }

    #[test]
    fn test_pkginfo_generation() {
        let options = MunkiComplianceOptions::default();
        let generator = MunkiComplianceGenerator::new(options);

        let rule_ids = vec![
            "os_firewall_enable".to_string(),
            "os_gatekeeper_enable".to_string(),
        ];

        let pkginfo = generator
            .generate_flag_writer_pkginfo("cis_lvl1", &rule_ids)
            .unwrap();

        // Check required fields
        assert!(pkginfo.contains_key("name"));
        assert!(pkginfo.contains_key("installer_type"));
        assert!(pkginfo.contains_key("installcheck_script"));
        assert!(pkginfo.contains_key("postinstall_script"));

        // Verify installer type
        if let Some(Value::String(installer_type)) = pkginfo.get("installer_type") {
            assert_eq!(installer_type, "nopkg");
        }
    }

    #[test]
    fn test_installcheck_script_contains_flags() {
        let options = MunkiComplianceOptions {
            flag_prefix: "test_".to_string(),
            ..Default::default()
        };
        let generator = MunkiComplianceGenerator::new(options);

        // Payload identifiers (not rule IDs)
        let payload_ids = vec![
            "com.example.rule1".to_string(),
            "com.example.rule2".to_string(),
        ];
        let script = generator.generate_installcheck_script("baseline", &payload_ids);

        // Should contain sanitized payload identifiers with prefix
        assert!(script.contains("test_com_example_rule1"));
        assert!(script.contains("test_com_example_rule2"));
    }
}
