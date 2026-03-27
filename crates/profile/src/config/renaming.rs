use super::ProfileConfig;
use crate::profile::ConfigurationProfile;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

#[derive(Debug)]
pub struct ProfileRenamer<'a> {
    config: &'a ProfileConfig,
}

impl<'a> ProfileRenamer<'a> {
    pub fn new(config: &'a ProfileConfig) -> Self {
        Self { config }
    }

    /// Generate output filename for a profile based on renaming scheme
    pub fn generate_filename(
        &self,
        profile: &ConfigurationProfile,
        _original_path: Option<&Path>,
    ) -> String {
        match self.config.renaming.scheme.as_str() {
            "identifier" => self.identifier_based(profile),
            "display-name" => self.display_name_based(profile),
            "template" => self.template_based(profile),
            _ => {
                // Fallback to display-name if invalid scheme
                self.display_name_based(profile)
            }
        }
    }

    /// Generate full output path (directory + filename)
    pub fn generate_output_path(
        &self,
        profile: &ConfigurationProfile,
        original_path: Option<&Path>,
    ) -> PathBuf {
        let filename = self.generate_filename(profile, original_path);

        if let Some(dir) = &self.config.output.directory {
            Path::new(dir).join(filename)
        } else if let Some(original) = original_path {
            if let Some(parent) = original.parent() {
                parent.join(filename)
            } else {
                PathBuf::from(filename)
            }
        } else {
            PathBuf::from(filename)
        }
    }

    /// Identifier-based naming: com.yourorg.wifi.mobileconfig
    fn identifier_based(&self, profile: &ConfigurationProfile) -> String {
        format!("{}.mobileconfig", profile.payload_identifier)
    }

    /// Display-name-based naming: BTM-OSQuery.mobileconfig
    fn display_name_based(&self, profile: &ConfigurationProfile) -> String {
        let sanitized = self.sanitize_for_filename(&profile.payload_display_name);
        format!("{sanitized}.mobileconfig")
    }

    /// Template-based naming: {org}-{type}-{name}.mobileconfig
    fn template_based(&self, profile: &ConfigurationProfile) -> String {
        let org = self.config.org_name();
        let payload_type = self.extract_type(profile);
        let name = self.sanitize_for_filename(&profile.payload_display_name);
        let identifier = &profile.payload_identifier;
        let uuid = &profile.payload_uuid;

        let filename = self
            .config
            .renaming
            .template
            .replace("{org}", &org)
            .replace("{type}", &payload_type)
            .replace("{name}", &name)
            .replace("{identifier}", identifier)
            .replace("{uuid}", uuid);

        // Ensure .mobileconfig extension
        if filename.ends_with(".mobileconfig") {
            filename
        } else {
            format!("{filename}.mobileconfig")
        }
    }

    /// Extract payload type for template variable
    fn extract_type(&self, profile: &ConfigurationProfile) -> String {
        // Try to get first PayloadContent type
        if let Some(first_content) = profile.payload_content.first() {
            // Extract the last component of the type
            // e.g., "com.apple.servicemanagement" -> "servicemanagement"
            let type_str = &first_content.payload_type;

            if let Some(last_part) = type_str.split('.').next_back() {
                return last_part.to_string();
            }

            return type_str.clone();
        }

        // Fallback to "config"
        "config".to_string()
    }

    /// Sanitize string for use in filename
    fn sanitize_for_filename(&self, input: &str) -> String {
        static RE_INVALID_CHARS: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"[^a-zA-Z0-9\-_.]").expect("invariant: hardcoded regex is valid")
        });
        static RE_MULTI_HYPHENS: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"-+").expect("invariant: hardcoded regex is valid")
        });

        // Replace spaces with hyphens
        let with_hyphens = input.replace(' ', "-");

        // Remove or replace problematic characters
        let sanitized = RE_INVALID_CHARS.replace_all(&with_hyphens, "");

        // Remove multiple consecutive hyphens
        let cleaned = RE_MULTI_HYPHENS.replace_all(&sanitized, "-");

        // Trim hyphens from start and end
        cleaned.trim_matches('-').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OrganizationConfig, OutputConfig, RenamingConfig, UuidConfig};
    use crate::profile::PayloadContent;
    use std::collections::HashMap;

    fn create_test_config(scheme: &str, template: &str) -> ProfileConfig {
        ProfileConfig {
            organization: OrganizationConfig {
                domain: "com.acme".to_string(),
                name: Some("acme".to_string()),
            },
            renaming: RenamingConfig {
                scheme: scheme.to_string(),
                template: template.to_string(),
            },
            uuid: UuidConfig::default(),
            output: OutputConfig::default(),
            processing: None,
            fleet: None,
        }
    }

    fn create_test_profile() -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "12345678-1234-1234-1234-123456789012".to_string(),
            payload_display_name: "BTM - OSQuery".to_string(),
            payload_content: vec![PayloadContent {
                payload_type: "com.apple.servicemanagement".to_string(),
                payload_version: 1,
                payload_identifier: "test.content".to_string(),
                payload_uuid: "87654321-4321-4321-4321-210987654321".to_string(),
                content: HashMap::new(),
            }],
            additional_fields: HashMap::new(),
        }
    }

    #[test]
    fn test_identifier_based_naming() {
        let config = create_test_config("identifier", "");
        let renamer = ProfileRenamer::new(&config);
        let profile = create_test_profile();

        let filename = renamer.generate_filename(&profile, None);
        assert_eq!(filename, "com.test.profile.mobileconfig");
    }

    #[test]
    fn test_display_name_based_naming() {
        let config = create_test_config("display-name", "");
        let renamer = ProfileRenamer::new(&config);
        let profile = create_test_profile();

        let filename = renamer.generate_filename(&profile, None);
        assert_eq!(filename, "BTM-OSQuery.mobileconfig");
    }

    #[test]
    fn test_template_based_naming() {
        let config = create_test_config("template", "{org}-{type}-{name}");
        let renamer = ProfileRenamer::new(&config);
        let profile = create_test_profile();

        let filename = renamer.generate_filename(&profile, None);
        assert_eq!(filename, "acme-servicemanagement-BTM-OSQuery.mobileconfig");
    }

    #[test]
    fn test_sanitize_filename() {
        let config = create_test_config("display-name", "");
        let renamer = ProfileRenamer::new(&config);

        assert_eq!(
            renamer.sanitize_for_filename("Test Profile!"),
            "Test-Profile"
        );
        assert_eq!(renamer.sanitize_for_filename("Config (v2)"), "Config-v2");
        assert_eq!(
            renamer.sanitize_for_filename("WiFi @ Office"),
            "WiFi-Office"
        );
    }
}
