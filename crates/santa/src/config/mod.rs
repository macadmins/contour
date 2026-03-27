mod santa_config;

pub use santa_config::{
    FleetConfig, OrganizationConfig, ProfilesConfig, RingsConfig, SantaProjectConfig,
    ValidationConfig,
};

use anyhow::{Context, Result};
use clap::ValueEnum;
use plist::Value;
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

/// Santa client mode
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum ClientMode {
    /// Monitor mode - log only
    #[default]
    Monitor,
    /// Lockdown mode - enforce rules
    Lockdown,
}

impl ClientMode {
    fn as_int(&self) -> i64 {
        match self {
            ClientMode::Monitor => 1,
            ClientMode::Lockdown => 2,
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
    pub identifier: String,
    pub org: String,
}

impl Default for SantaConfig {
    fn default() -> Self {
        Self {
            mode: ClientMode::Monitor,
            sync_url: None,
            machine_owner_plist: None,
            block_usb: false,
            identifier: "com.northpolesec.santa".to_string(),
            org: "Example Org".to_string(),
        }
    }
}

/// Generate Santa configuration mobileconfig
pub fn generate_config(config: &SantaConfig) -> Result<Vec<u8>> {
    let profile_uuid = Uuid::new_v4();
    let payload_uuid = Uuid::new_v4();

    // Build Santa configuration payload content
    let mut santa_config: HashMap<String, Value> = HashMap::new();
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

    // Build payload
    let mut payload: HashMap<String, Value> = HashMap::new();
    payload.insert(
        "PayloadType".to_string(),
        Value::String("com.northpolesec.santa".to_string()),
    );
    payload.insert(
        "PayloadIdentifier".to_string(),
        Value::String(format!("{}.config", config.identifier)),
    );
    payload.insert(
        "PayloadUUID".to_string(),
        Value::String(payload_uuid.to_string().to_uppercase()),
    );
    payload.insert("PayloadVersion".to_string(), Value::Integer(1.into()));
    payload.insert(
        "PayloadDisplayName".to_string(),
        Value::String("Santa Configuration".to_string()),
    );

    // Merge santa config into payload
    for (k, v) in santa_config {
        payload.insert(k, v);
    }

    // Build profile
    let mut profile: HashMap<String, Value> = HashMap::new();
    profile.insert("PayloadVersion".to_string(), Value::Integer(1.into()));
    profile.insert(
        "PayloadType".to_string(),
        Value::String("Configuration".to_string()),
    );
    profile.insert(
        "PayloadIdentifier".to_string(),
        Value::String(config.identifier.clone()),
    );
    profile.insert(
        "PayloadUUID".to_string(),
        Value::String(profile_uuid.to_string().to_uppercase()),
    );
    profile.insert(
        "PayloadDisplayName".to_string(),
        Value::String("Santa Configuration".to_string()),
    );
    profile.insert(
        "PayloadDescription".to_string(),
        Value::String("Santa binary authorization configuration".to_string()),
    );
    profile.insert(
        "PayloadOrganization".to_string(),
        Value::String(config.org.clone()),
    );
    profile.insert(
        "PayloadScope".to_string(),
        Value::String("System".to_string()),
    );
    profile.insert(
        "PayloadContent".to_string(),
        Value::Array(vec![Value::Dictionary(payload.into_iter().collect())]),
    );

    // Serialize to XML plist
    let mut buffer = Vec::new();
    plist::to_writer_xml(
        &mut buffer,
        &Value::Dictionary(profile.into_iter().collect()),
    )
    .context("Failed to serialize mobileconfig")?;

    Ok(buffer)
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
        assert!(result.is_ok());
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
