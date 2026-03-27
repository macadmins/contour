//! Profile configuration file handling.
//!
//! Loads and validates `profile.toml` configuration files that customize
//! organization settings, renaming schemes, UUID generation, and Fleet integration.

pub mod renaming;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Main configuration for Profile CLI tool.
///
/// Loaded from `profile.toml` in the current directory or parent directories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// Organization-specific settings.
    pub organization: OrganizationConfig,

    #[serde(default)]
    pub renaming: RenamingConfig,

    #[serde(default)]
    pub uuid: UuidConfig,

    #[serde(default)]
    pub output: OutputConfig,

    #[serde(default)]
    pub processing: Option<ProcessingConfig>,

    #[serde(default)]
    pub fleet: Option<FleetConfig>,
}

/// Organization-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationConfig {
    /// Reverse domain notation (e.g., "com.yourorg")
    pub domain: String,

    /// Short organization name for templates (e.g., "yourorg")
    #[serde(default)]
    pub name: Option<String>,
}

/// Profile renaming configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenamingConfig {
    /// Renaming scheme: "identifier", "display-name", or "template"
    #[serde(default = "default_scheme")]
    pub scheme: String,

    /// Template pattern for "template" scheme
    /// Variables: {org}, {type}, {name}, {identifier}, {uuid}
    #[serde(default = "default_template")]
    pub template: String,
}

/// UUID generation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UuidConfig {
    /// Generate predictable UUIDs by default
    #[serde(default)]
    pub predictable: bool,

    /// Output UUIDs in uppercase
    #[serde(default = "default_true")]
    pub uppercase: bool,
}

/// Output file configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Default output directory
    #[serde(default)]
    pub directory: Option<String>,

    /// Suffix for unsigned files
    #[serde(default = "default_unsigned_suffix")]
    pub unsigned_suffix: String,
}

/// Batch processing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingConfig {
    /// Validate profiles before export
    #[serde(default = "default_true")]
    pub validate_on_export: bool,

    /// Use parallel processing in batch mode
    #[serde(default = "default_true")]
    pub parallel_batch: bool,

    /// Maximum number of threads for parallel processing
    #[serde(default = "default_max_threads")]
    pub max_threads: usize,
}

fn default_max_threads() -> usize {
    4
}

fn default_scheme() -> String {
    "display-name".to_string()
}

fn default_template() -> String {
    "{org}-{type}-{name}".to_string()
}

fn default_true() -> bool {
    true
}

fn default_unsigned_suffix() -> String {
    "-unsigned".to_string()
}

impl Default for RenamingConfig {
    fn default() -> Self {
        Self {
            scheme: default_scheme(),
            template: default_template(),
        }
    }
}

impl Default for UuidConfig {
    fn default() -> Self {
        Self {
            predictable: false,
            uppercase: true,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            directory: None,
            unsigned_suffix: default_unsigned_suffix(),
        }
    }
}

impl ProfileConfig {
    /// Load config from project directory (profile.toml)
    pub fn load() -> Result<Option<Self>> {
        let config_path = Self::find_config_file()?;

        if let Some(path) = config_path {
            let contents = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read config file: {}", path.display()))?;

            let config: ProfileConfig =
                toml::from_str(&contents).with_context(|| "Failed to parse TOML configuration")?;

            config.validate()?;

            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    /// Find profile.toml in current directory or parent directories
    fn find_config_file() -> Result<Option<PathBuf>> {
        let current_dir = std::env::current_dir()?;
        let mut dir = current_dir.as_path();

        loop {
            let config_path = dir.join("profile.toml");
            if config_path.exists() {
                return Ok(Some(config_path));
            }

            match dir.parent() {
                Some(parent) => dir = parent,
                None => break,
            }
        }

        Ok(None)
    }

    /// Validate configuration
    fn validate(&self) -> Result<()> {
        if self.organization.domain.is_empty() {
            anyhow::bail!("organization.domain cannot be empty");
        }

        if !self.organization.domain.contains('.') {
            anyhow::bail!(
                "organization.domain must be in reverse domain format (e.g., com.yourorg)"
            );
        }

        let valid_schemes = ["identifier", "display-name", "template"];
        if !valid_schemes.contains(&self.renaming.scheme.as_str()) {
            anyhow::bail!(
                "Invalid renaming.scheme '{}'. Must be one of: {}",
                self.renaming.scheme,
                valid_schemes.join(", ")
            );
        }

        if self.renaming.scheme == "template" {
            let valid_vars = ["{org}", "{type}", "{name}", "{identifier}", "{uuid}"];
            let has_valid_var = valid_vars
                .iter()
                .any(|var| self.renaming.template.contains(var));

            if !has_valid_var {
                anyhow::bail!(
                    "Template '{}' must contain at least one variable: {}",
                    self.renaming.template,
                    valid_vars.join(", ")
                );
            }
        }

        // Validate Fleet config if present
        if let Some(ref fleet) = self.fleet {
            fleet.validate()?;
        }

        Ok(())
    }

    /// Get org name for templates (use short name or extract from domain)
    pub fn org_name(&self) -> String {
        if let Some(name) = &self.organization.name {
            name.clone()
        } else {
            self.organization
                .domain
                .split('.')
                .next_back()
                .unwrap_or(&self.organization.domain)
                .to_string()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    /// Path to Fleet GitOps repository root
    pub gitops_root: PathBuf,

    /// Target: "global", "team", or "teams"
    pub target: String,

    /// Single team name (when target = "team")
    #[serde(default)]
    pub team_name: Option<String>,

    /// Multiple team names (when target = "teams")
    #[serde(default)]
    pub team_names: Option<Vec<String>>,

    /// Label targeting (Fleet Premium)
    #[serde(default)]
    pub labels_include_any: Option<Vec<String>>,

    /// Profile type to lib/ directory mapping
    pub merge_map: HashMap<String, String>,
}

impl FleetConfig {
    /// Validate Fleet configuration
    pub fn validate(&self) -> Result<()> {
        // Validate target
        match self.target.as_str() {
            "global" => {}
            "team" => {
                if self.team_name.is_none() {
                    anyhow::bail!("team_name required when target='team'");
                }
            }
            "teams" => {
                if self.team_names.is_none() || self.team_names.as_ref().unwrap().is_empty() {
                    anyhow::bail!("team_names required when target='teams'");
                }
            }
            other => anyhow::bail!(
                "Invalid fleet.target '{other}'. Must be 'global', 'team', or 'teams'"
            ),
        }

        // Validate merge_map has default
        if !self.merge_map.contains_key("default") {
            anyhow::bail!("fleet.merge_map must contain 'default' key");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProfileConfig {
            organization: OrganizationConfig {
                domain: "com.example".to_string(),
                name: None,
            },
            renaming: RenamingConfig::default(),
            uuid: UuidConfig::default(),
            output: OutputConfig::default(),
            processing: None,
            fleet: None,
        };

        assert_eq!(config.renaming.scheme, "display-name");
        assert!(config.uuid.uppercase);
    }

    #[test]
    fn test_org_name_extraction() {
        let config = ProfileConfig {
            organization: OrganizationConfig {
                domain: "com.acme.corp".to_string(),
                name: None,
            },
            renaming: RenamingConfig::default(),
            uuid: UuidConfig::default(),
            output: OutputConfig::default(),
            processing: None,
            fleet: None,
        };

        assert_eq!(config.org_name(), "corp");
    }
}
