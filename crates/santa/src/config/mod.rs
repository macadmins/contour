mod santa_config;

pub use santa_config::{
    FleetConfig, OrganizationConfig, ProfilesConfig, RingsConfig, SantaProjectConfig,
    ValidationConfig,
};

use anyhow::{Context, Result};
use clap::ValueEnum;
use plist::Value;
use std::path::Path;

/// Santa client mode
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum ClientMode {
    /// Monitor mode - log only
    #[default]
    Monitor,
    /// Lockdown mode - enforce rules
    Lockdown,
    /// Standalone mode - users locally approve unknown binaries (Santa 2024.10+)
    Standalone,
}

impl ClientMode {
    fn as_int(&self) -> i64 {
        match self {
            ClientMode::Monitor => 1,
            ClientMode::Lockdown => 2,
            ClientMode::Standalone => 3,
        }
    }
}

/// Santa configuration options
#[derive(Debug, Clone)]
pub struct SantaConfig {
    pub mode: ClientMode,
    pub sync_url: Option<String>,
    pub machine_owner_plist: Option<String>,
    pub block_usb: bool,
    /// Org domain: identifier prefix; PayloadOrganization via `org_name_for`.
    pub org: String,
}

impl Default for SantaConfig {
    fn default() -> Self {
        Self {
            mode: ClientMode::Monitor,
            sync_url: None,
            machine_owner_plist: None,
            block_usb: false,
            org: "com.example".to_string(),
        }
    }
}

/// Generate Santa configuration mobileconfig: `{org}.santa.config`, built
/// like every other generator's profile.
pub fn generate_config(config: &SantaConfig) -> Result<Vec<u8>> {
    let mut santa_config = plist::Dictionary::new();
    santa_config.insert(
        "ClientMode".to_string(),
        Value::Integer(config.mode.as_int().into()),
    );
    if let Some(ref url) = config.sync_url {
        santa_config.insert("SyncBaseURL".to_string(), Value::String(url.clone()));
    }
    if let Some(ref plist_path) = config.machine_owner_plist {
        santa_config.insert(
            "MachineOwnerPlist".to_string(),
            Value::String(plist_path.clone()),
        );
    }
    if config.block_usb {
        santa_config.insert("BlockUSBMount".to_string(), Value::Boolean(true));
    }

    contour_profiles::ProfileBuilder::new(
        &contour_core::org_name_for(&config.org),
        &format!("{}.santa.config", config.org),
    )
    .display_name("Santa Configuration")
    .description("Santa binary authorization configuration")
    .removal_disallowed(true)
    .build("com.northpolesec.santa", santa_config)
}

/// Write Santa configuration to file
pub fn write_config_to_file(config: &SantaConfig, path: &Path) -> Result<()> {
    let content = generate_config(config)?;
    std::fs::write(path, content)
        .with_context(|| format!("Failed to write config: {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_default_config() {
        let config = SantaConfig::default();
        let result = generate_config(&config);
        result.unwrap();
    }

    #[test]
    fn test_generate_lockdown_config() {
        let config = SantaConfig {
            mode: ClientMode::Lockdown,
            sync_url: Some("https://santa.example.com".to_string()),
            block_usb: true,
            ..Default::default()
        };

        let result = generate_config(&config).unwrap();
        let content = String::from_utf8(result).unwrap();

        assert!(content.contains("<integer>2</integer>")); // Lockdown mode
        assert!(content.contains("https://santa.example.com"));
        assert!(content.contains("BlockUSBMount"));
    }
}
