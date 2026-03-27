//! Santa project configuration (santa.toml)

use crate::models::RingConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main santa.toml configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SantaProjectConfig {
    /// Organization settings
    #[serde(default)]
    pub organization: OrganizationConfig,

    /// Ring configuration
    #[serde(default)]
    pub rings: RingsConfig,

    /// Profile generation settings
    #[serde(default)]
    pub profiles: ProfilesConfig,

    /// Fleet GitOps settings
    #[serde(default)]
    pub fleet: FleetConfig,

    /// Validation settings
    #[serde(default)]
    pub validation: ValidationConfig,
}

/// Organization settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationConfig {
    /// Organization name
    #[serde(default = "default_org_name")]
    pub name: String,

    /// Reverse DNS identifier (e.g., com.example)
    #[serde(default = "default_org_domain")]
    pub domain: String,

    /// Contact email for security issues
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_email: Option<String>,
}

fn default_org_name() -> String {
    "Example Organization".to_string()
}

fn default_org_domain() -> String {
    "com.example".to_string()
}

impl Default for OrganizationConfig {
    fn default() -> Self {
        Self {
            name: default_org_name(),
            domain: default_org_domain(),
            security_email: None,
        }
    }
}

/// Ring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingsConfig {
    /// Number of rings (5 or 7 recommended)
    #[serde(default = "default_num_rings")]
    pub count: u8,

    /// Use standard ring configuration (true) or custom (false)
    #[serde(default = "default_true")]
    pub use_standard: bool,

    /// Custom ring definitions (if use_standard is false)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom: Vec<CustomRing>,
}

fn default_num_rings() -> u8 {
    5
}

fn default_true() -> bool {
    true
}

impl Default for RingsConfig {
    fn default() -> Self {
        Self {
            count: default_num_rings(),
            use_standard: true,
            custom: Vec::new(),
        }
    }
}

impl RingsConfig {
    /// Convert to RingConfig
    pub fn to_ring_config(&self) -> RingConfig {
        if self.use_standard {
            match self.count {
                5 => RingConfig::standard_five_rings(),
                7 => RingConfig::standard_seven_rings(),
                n => {
                    let mut config = RingConfig::new();
                    for i in 0..n {
                        config.add_ring(
                            crate::models::Ring::new(format!("ring{i}"), i)
                                .with_description(format!("Ring {}", i + 1))
                                .with_fleet_labels(vec![format!("ring:{i}")]),
                        );
                    }
                    config
                }
            }
        } else {
            let mut config = RingConfig::new();
            for (i, custom) in self.custom.iter().enumerate() {
                let mut ring = crate::models::Ring::new(&custom.name, i as u8);
                if let Some(ref desc) = custom.description {
                    ring = ring.with_description(desc);
                }
                if !custom.fleet_labels.is_empty() {
                    ring = ring.with_fleet_labels(custom.fleet_labels.clone());
                }
                config.add_ring(ring);
            }
            config
        }
    }
}

/// Custom ring definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRing {
    /// Ring name
    pub name: String,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Fleet labels for targeting
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fleet_labels: Vec<String>,
}

/// Profile generation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilesConfig {
    /// Profile name prefix (e.g., "santa" -> santa1a, santa1b)
    #[serde(default = "default_prefix")]
    pub prefix: String,

    /// Use deterministic UUIDs for reproducible builds
    #[serde(default = "default_true")]
    pub deterministic_uuids: bool,

    /// Maximum rules per profile (0 = unlimited)
    #[serde(default)]
    pub max_rules_per_profile: usize,

    /// Output directory for generated profiles
    #[serde(default = "default_output_dir")]
    pub output_directory: String,
}

fn default_prefix() -> String {
    "santa".to_string()
}

fn default_output_dir() -> String {
    "profiles".to_string()
}

impl Default for ProfilesConfig {
    fn default() -> Self {
        Self {
            prefix: default_prefix(),
            deterministic_uuids: true,
            max_rules_per_profile: 0,
            output_directory: default_output_dir(),
        }
    }
}

/// Fleet GitOps settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    /// Enable Fleet output generation
    #[serde(default)]
    pub enabled: bool,

    /// Fleet team name
    #[serde(default = "default_team_name")]
    pub team_name: String,

    /// Base path for profiles in manifest
    #[serde(default = "default_profiles_base_path")]
    pub profiles_base_path: String,

    /// Output directory for Fleet GitOps structure
    #[serde(default = "default_fleet_output_dir")]
    pub output_directory: String,
}

fn default_team_name() -> String {
    "Workstations".to_string()
}

fn default_profiles_base_path() -> String {
    let layout = contour_core::fleet_layout::FleetLayout::default();
    format!("{}/profiles", layout.platforms_dir)
}

fn default_fleet_output_dir() -> String {
    "fleet-gitops".to_string()
}

impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            team_name: default_team_name(),
            profiles_base_path: default_profiles_base_path(),
            output_directory: default_fleet_output_dir(),
        }
    }
}

/// Validation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Strict mode: treat warnings as errors
    #[serde(default)]
    pub strict: bool,

    /// Require descriptions on all rules
    #[serde(default)]
    pub require_descriptions: bool,

    /// Validate TeamID format (10 alphanumeric chars)
    #[serde(default = "default_true")]
    pub validate_team_id_format: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            strict: false,
            require_descriptions: false,
            validate_team_id_format: true,
        }
    }
}

impl SantaProjectConfig {
    /// Load configuration from a file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", path.display()))
    }

    /// Save configuration to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config: {}", path.display()))
    }

    /// Find and load santa.toml from current or parent directories
    pub fn find_and_load() -> Result<Option<Self>> {
        let mut current = std::env::current_dir()?;

        loop {
            let config_path = current.join("santa.toml");
            if config_path.exists() {
                return Ok(Some(Self::load(&config_path)?));
            }

            if !current.pop() {
                break;
            }
        }

        Ok(None)
    }

    /// Generate a default configuration file
    pub fn generate_default() -> String {
        let config = Self::default();
        toml::to_string_pretty(&config).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = SantaProjectConfig::default();
        assert_eq!(config.organization.domain, "com.example");
        assert_eq!(config.rings.count, 5);
        assert!(config.rings.use_standard);
    }

    #[test]
    fn test_config_serialization() {
        let config = SantaProjectConfig::default();
        let toml = toml::to_string_pretty(&config).unwrap();
        assert!(toml.contains("[organization]"));
        assert!(toml.contains("[rings]"));
        assert!(toml.contains("[profiles]"));
    }

    #[test]
    fn test_config_roundtrip() {
        let tmp_dir = TempDir::new().unwrap();
        let config_path = tmp_dir.path().join("santa.toml");

        let config = SantaProjectConfig::default();
        config.save(&config_path).unwrap();

        let loaded = SantaProjectConfig::load(&config_path).unwrap();
        assert_eq!(loaded.organization.domain, config.organization.domain);
        assert_eq!(loaded.rings.count, config.rings.count);
    }

    #[test]
    fn test_ring_config_conversion() {
        let config = RingsConfig {
            count: 5,
            use_standard: true,
            custom: Vec::new(),
        };

        let ring_config = config.to_ring_config();
        assert_eq!(ring_config.rings.len(), 5);
    }
}
