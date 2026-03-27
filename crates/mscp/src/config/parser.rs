use crate::config::Config;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Load configuration from TOML file
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();

    if !path.exists() {
        anyhow::bail!("Config file not found: {}", path.display());
    }

    let content = fs::read_to_string(path)
        .context(format!("Failed to read config file: {}", path.display()))?;

    let config: Config = toml::from_str(&content)
        .context(format!("Failed to parse config file: {}", path.display()))?;

    tracing::info!("Loaded configuration from: {}", path.display());
    validate_config(&config)?;

    Ok(config)
}

/// Load configuration or use defaults if file doesn't exist
#[allow(dead_code, reason = "reserved for future use")]
pub fn load_config_or_default<P: AsRef<Path>>(path: P) -> Config {
    match load_config(path) {
        Ok(config) => config,
        Err(e) => {
            tracing::warn!("Could not load config: {}. Using defaults.", e);
            Config::default()
        }
    }
}

/// Validate configuration
fn validate_config(config: &Config) -> Result<()> {
    // Validate python_method
    match config.settings.python_method.as_str() {
        "auto" | "uv" | "python3" => {}
        other => {
            anyhow::bail!("Invalid python_method '{other}'. Must be 'auto', 'uv', or 'python3'");
        }
    }

    // Validate baselines
    for (i, baseline) in config.baselines.iter().enumerate() {
        if baseline.name.is_empty() {
            anyhow::bail!("Baseline {i} has empty name");
        }
    }

    // output.structure is validated by serde deserialization (OutputStructure enum)

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_config_invalid_python_method() {
        let mut config = Config::default();
        config.settings.python_method = "invalid".to_string();

        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_valid() {
        let config = Config::default();
        assert!(validate_config(&config).is_ok());
    }
}
