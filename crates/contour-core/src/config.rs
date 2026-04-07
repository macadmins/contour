//! Shared organization configuration for all Contour tools.
//!
//! Reads `.contour/config.toml` from the repository root to provide
//! organization identity and defaults. This eliminates the need for
//! `--org` flags on every invocation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level configuration from `.contour/config.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContourConfig {
    pub organization: OrgConfig,
    #[serde(default)]
    pub defaults: DefaultsConfig,
}

/// Organization identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrgConfig {
    pub name: String,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

/// Optional project-wide defaults.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DefaultsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platforms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deterministic_uuids: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifests_path: Option<PathBuf>,
}

const CONFIG_DIR: &str = ".contour";
const CONFIG_FILE: &str = "config.toml";

impl ContourConfig {
    /// Load config from `{root}/.contour/config.toml`.
    pub fn load(root: &Path) -> Option<Self> {
        let path = root.join(CONFIG_DIR).join(CONFIG_FILE);
        let content = std::fs::read_to_string(&path).ok()?;
        toml::from_str(&content).ok()
    }

    /// Walk up from the current directory looking for `.contour/config.toml`.
    ///
    /// Returns `None` if no config is found before reaching the filesystem root.
    pub fn load_nearest() -> Option<Self> {
        let mut dir = std::env::current_dir().ok()?;
        loop {
            if dir.join(CONFIG_DIR).join(CONFIG_FILE).is_file() {
                return Self::load(&dir);
            }
            if !dir.pop() {
                return None;
            }
        }
    }

    /// Write config to `{root}/.contour/config.toml`, creating the directory if needed.
    pub fn save(&self, root: &Path) -> Result<()> {
        let dir = root.join(CONFIG_DIR);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
        let path = dir.join(CONFIG_FILE);
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;
        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        Ok(())
    }

    /// Return the path where config would be written for a given root.
    pub fn config_path(root: &Path) -> PathBuf {
        root.join(CONFIG_DIR).join(CONFIG_FILE)
    }
}

/// Resolve organization domain from a CLI flag, falling back to `.contour/config.toml`.
///
/// Looks for the org in this order:
/// 1. Explicit CLI `--org` flag value
/// 2. `.contour/config.toml` found by walking up the directory tree
/// 3. Error with guidance to use `contour init`
pub fn resolve_org(org: Option<String>) -> anyhow::Result<String> {
    // 1. Explicit --org flag
    if let Some(o) = org {
        return Ok(o);
    }
    // 2. CONTOUR_ORG environment variable (useful for CI/GitHub Actions)
    if let Ok(env_org) = std::env::var("CONTOUR_ORG") {
        if !env_org.is_empty() {
            return Ok(env_org);
        }
    }
    // 3. .contour/config.toml
    if let Some(cfg) = ContourConfig::load_nearest() {
        return Ok(cfg.organization.domain);
    }
    anyhow::bail!(
        "--org is required. Set it via:\n  \
         • --org com.yourcompany (CLI flag)\n  \
         • CONTOUR_ORG=com.yourcompany (env var, ideal for CI)\n  \
         • contour init (creates .contour/config.toml)"
    )
}

/// Resolve the organization display name from multiple sources.
///
/// Resolution order:
/// 1. Explicit `--name` flag
/// 2. `CONTOUR_NAME` environment variable
/// 3. `.contour/config.toml` `organization.name`
/// 4. `None` (name is optional — profiles work without it)
pub fn resolve_name(name: Option<String>) -> Option<String> {
    if let Some(n) = name {
        return Some(n);
    }
    if let Ok(env_name) = std::env::var("CONTOUR_NAME") {
        if !env_name.is_empty() {
            return Some(env_name);
        }
    }
    if let Some(cfg) = ContourConfig::load_nearest() {
        return Some(cfg.organization.name);
    }
    None
}

/// Shared `[settings]` section for domain config files (btm.toml, notifications.toml).
///
/// Every domain config uses the same metadata block:
/// ```toml
/// [settings]
/// org = "com.example"
/// display_name = "My Profile"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSettings {
    pub org: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Derive a reverse-domain identifier from an organization name.
///
/// Strips common suffixes (Inc, LLC, Corp, etc.), takes the first word,
/// lowercases it, and prepends `com.`.
pub fn derive_domain_from_name(org_name: &str) -> String {
    let parts: Vec<&str> = org_name
        .split_whitespace()
        .filter(|w| {
            ![
                "Inc", "Inc.", "LLC", "Ltd", "Ltd.", "Corp", "Corp.", "Co", "Co.",
            ]
            .contains(w)
        })
        .collect();
    let word = parts
        .first()
        .unwrap_or(&"example")
        .to_lowercase()
        .replace(|c: char| !c.is_alphanumeric(), "");
    format!("com.{word}")
}

/// Derive a likely server hostname from an organization name.
///
/// Returns `fleet.{word}.com` where word is the first cleaned word from the name.
pub fn derive_server_url_from_name(org_name: &str) -> String {
    let parts: Vec<&str> = org_name
        .split_whitespace()
        .filter(|w| {
            ![
                "Inc", "Inc.", "LLC", "Ltd", "Ltd.", "Corp", "Corp.", "Co", "Co.",
            ]
            .contains(w)
        })
        .collect();
    let word = parts
        .first()
        .unwrap_or(&"example")
        .to_lowercase()
        .replace(|c: char| !c.is_alphanumeric(), "");
    format!("https://fleet.{word}.com")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_domain_from_name() {
        assert_eq!(derive_domain_from_name("Acme Corporation"), "com.acme");
        assert_eq!(derive_domain_from_name("Acme Corp."), "com.acme");
        assert_eq!(derive_domain_from_name("Big Co. LLC"), "com.big");
        assert_eq!(derive_domain_from_name(""), "com.example");
    }

    #[test]
    fn test_derive_server_url_from_name() {
        assert_eq!(
            derive_server_url_from_name("Acme Corp"),
            "https://fleet.acme.com"
        );
    }

    #[test]
    fn test_roundtrip() {
        let config = ContourConfig {
            organization: OrgConfig {
                name: "Acme".to_string(),
                domain: "com.acme".to_string(),
                server_url: Some("https://fleet.acme.com".to_string()),
            },
            defaults: DefaultsConfig {
                platforms: Some(vec!["macos".to_string()]),
                deterministic_uuids: Some(true),
                manifests_path: None,
            },
        };

        let dir = tempfile::tempdir().unwrap();
        config.save(dir.path()).unwrap();
        let loaded = ContourConfig::load(dir.path()).unwrap();
        assert_eq!(loaded.organization.name, "Acme");
        assert_eq!(loaded.organization.domain, "com.acme");
        assert_eq!(
            loaded.organization.server_url.as_deref(),
            Some("https://fleet.acme.com")
        );
        assert_eq!(loaded.defaults.platforms, Some(vec!["macos".to_string()]));
        assert_eq!(loaded.defaults.deterministic_uuids, Some(true));
    }

    #[test]
    fn test_load_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ContourConfig::load(dir.path()).is_none());
    }

    #[test]
    fn test_resolve_org_explicit() {
        let result = resolve_org(Some("com.example".into()));
        assert_eq!(result.unwrap(), "com.example");
    }
}
