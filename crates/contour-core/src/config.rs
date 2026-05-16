//! Shared organization configuration for all Contour tools.
//!
//! Reads `.contour/config.toml` from the repository root to provide
//! organization identity and defaults. This eliminates the need for
//! `--org` flags on every invocation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level configuration from `.contour/config.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContourConfig {
    pub organization: OrgConfig,
    #[serde(default)]
    pub defaults: DefaultsConfig,
    /// Default substitutions for `{{PLACEHOLDER}}`-style recipe vars.
    /// CLI `--vars` and recipe-level overrides take precedence; this
    /// table only fills in placeholders the operator hasn't otherwise
    /// supplied.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
    /// Code-signing defaults used by `contour profile sign` when no
    /// `--identity` is given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningConfig>,
    /// Schema-validation policy applied to commands that emit
    /// profiles. Defaults: errors fail the command, warnings don't.
    #[serde(default)]
    pub validation: ValidationConfig,
    /// Secret catalogue: named references resolved by `secret:NAME`,
    /// plus default secret-source settings.
    #[serde(default)]
    pub secrets: SecretsConfig,
    /// MDM deploy-time variable pool: named tokens (`%Username%`,
    /// `FLEET_VAR_*`, …) referenced by `var:NAME` and passed through
    /// untouched for the MDM server to substitute on-device.
    #[serde(default)]
    pub mdm_variables: MdmVariablesConfig,
}

/// MDM deploy-time variable pool.
///
/// `mdm` selects the built-in catalogue (`fleet`, `jamf`, `apple`)
/// used to validate tokens. `pool` maps a friendly name to an MDM
/// token (optionally combined with static text, e.g.
/// `"%Username%@acme.com"`); a recipe field `Foo = "var:NAME"`
/// resolves through this pool and the token is emitted verbatim.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MdmVariablesConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mdm: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pool: BTreeMap<String, String>,
}

/// Secret catalogue and default secret-source settings.
///
/// `refs` maps a logical name to an `op://`/`env:`/`file:` reference;
/// a recipe field `Password = "secret:WIFI_PW"` resolves through this
/// table. `dotenv` overrides the default `.env` path; `op_vault` names
/// a default 1Password vault (reserved for future short-form lookups).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecretsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dotenv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_vault: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub refs: BTreeMap<String, String>,
}

/// Organization identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrgConfig {
    pub name: String,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

/// Code-signing identity defaults.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SigningConfig {
    /// Developer ID Installer identity name (or SHA-1 hash). Passed to
    /// `security cms -S -N <identity>` when no `--identity` flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Apple Developer Team ID — used for `FilterDataProviderDesignatedRequirement`
    /// strings and signature verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
}

/// Schema-validation policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// When true, commands that produce profiles return a non-zero
    /// exit status if the embedded schema reports any error.
    #[serde(default = "default_true")]
    pub fail_on_errors: bool,
    /// When true, warnings also fail the command. Off by default so
    /// advisory hints don't break CI.
    #[serde(default)]
    pub fail_on_warnings: bool,
    /// When true, `profile scan --deprecations` exits non-zero if any
    /// deprecation is found. CLI `--fail-on-deprecations` overrides this.
    #[serde(default)]
    pub fail_on_deprecations: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            fail_on_errors: true,
            fail_on_warnings: false,
            fail_on_deprecations: false,
        }
    }
}

fn default_true() -> bool {
    true
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
    /// Default preset/recipe library directory. When set, commands
    /// like `library import --into`, `library validate <PATH>`,
    /// `library normalize <PATH>`, and `--recipe-path` resolution
    /// fall back to this when no flag is given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library_path: Option<PathBuf>,
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
        let dir = std::env::current_dir().ok()?;
        Self::load_nearest_from(&dir)
    }

    /// Walk up from `start` looking for `.contour/config.toml`. If
    /// `start` is a file, search begins in its parent directory.
    /// Returns `None` if no config is found before reaching the
    /// filesystem root.
    ///
    /// Lets callers anchor lookup at a preset folder or recipe file
    /// path so an operator's `.contour/config.toml` travels with the
    /// preset library, regardless of where the binary is invoked from.
    pub fn load_nearest_from(start: &Path) -> Option<Self> {
        let mut dir = start.canonicalize().ok().or_else(|| Some(start.into()))?;
        if dir.is_file() {
            dir = dir.parent()?.to_path_buf();
        }
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
    resolve_org_with_anchor(org, None)
}

/// Resolve organization domain with an optional path anchor.
///
/// Precedence: CLI flag → `CONTOUR_ORG` env → CWD-walked config →
/// anchor-walked config → error. The CWD-walked config wins over the
/// anchor because the operator's project config represents the
/// operator's identity, while a `.contour/config.toml` shipped inside
/// a preset folder is a vendor-provided default.
pub fn resolve_org_with_anchor(
    org: Option<String>,
    anchor: Option<&Path>,
) -> anyhow::Result<String> {
    if let Some(o) = org {
        return Ok(o);
    }
    if let Ok(env_org) = std::env::var("CONTOUR_ORG") {
        if !env_org.is_empty() {
            return Ok(env_org);
        }
    }
    if let Some(cfg) = ContourConfig::load_nearest() {
        return Ok(cfg.organization.domain);
    }
    if let Some(a) = anchor {
        if let Some(cfg) = ContourConfig::load_nearest_from(a) {
            return Ok(cfg.organization.domain);
        }
    }
    anyhow::bail!(
        "--org is required. Set it via:\n  \
         • --org com.yourcompany (CLI flag)\n  \
         • CONTOUR_ORG=com.yourcompany (env var, ideal for CI)\n  \
         • contour init (creates .contour/config.toml)"
    )
}

/// Merge the `[vars]` table from configs anchored at CWD and at
/// `anchor`, layering the CWD config over the anchor config (so the
/// operator's project overrides a preset folder's defaults). The
/// returned map can be combined with CLI `--vars` by the caller —
/// CLI entries should win on conflict.
pub fn resolve_vars_with_anchor(anchor: Option<&Path>) -> BTreeMap<String, String> {
    let mut merged = BTreeMap::new();
    if let Some(a) = anchor {
        if let Some(cfg) = ContourConfig::load_nearest_from(a) {
            merged.extend(cfg.vars);
        }
    }
    if let Some(cfg) = ContourConfig::load_nearest() {
        merged.extend(cfg.vars);
    }
    merged
}

/// Resolve a signing identity. Precedence: CLI flag → CWD-walked
/// config `[signing]` → anchor-walked config `[signing]` → `None`.
pub fn resolve_signing_with_anchor(
    cli_identity: Option<String>,
    anchor: Option<&Path>,
) -> Option<SigningConfig> {
    if let Some(id) = cli_identity {
        return Some(SigningConfig {
            identity: Some(id),
            team_id: None,
        });
    }
    if let Some(cfg) = ContourConfig::load_nearest() {
        if cfg.signing.is_some() {
            return cfg.signing;
        }
    }
    if let Some(a) = anchor {
        if let Some(cfg) = ContourConfig::load_nearest_from(a) {
            if cfg.signing.is_some() {
                return cfg.signing;
            }
        }
    }
    None
}

/// Resolve the validation policy. CWD config wins over anchor config;
/// falls back to defaults (errors fail, warnings don't).
pub fn resolve_validation_with_anchor(anchor: Option<&Path>) -> ValidationConfig {
    if let Some(cfg) = ContourConfig::load_nearest() {
        return cfg.validation;
    }
    if let Some(a) = anchor {
        if let Some(cfg) = ContourConfig::load_nearest_from(a) {
            return cfg.validation;
        }
    }
    ValidationConfig::default()
}

/// Merge `[secrets]` from configs anchored at CWD and at `anchor`,
/// layering CWD over the anchor (operator project overrides a preset
/// folder's defaults). `refs` maps merge key-by-key; scalar settings
/// (`dotenv`, `op_vault`) take the CWD value when present.
pub fn resolve_secrets_with_anchor(anchor: Option<&Path>) -> SecretsConfig {
    let mut merged = SecretsConfig::default();
    if let Some(a) = anchor {
        if let Some(cfg) = ContourConfig::load_nearest_from(a) {
            merged = cfg.secrets;
        }
    }
    if let Some(cfg) = ContourConfig::load_nearest() {
        let cwd = cfg.secrets;
        merged.refs.extend(cwd.refs);
        if cwd.dotenv.is_some() {
            merged.dotenv = cwd.dotenv;
        }
        if cwd.op_vault.is_some() {
            merged.op_vault = cwd.op_vault;
        }
    }
    merged
}

/// Merge `[mdm_variables]` from configs anchored at CWD and at
/// `anchor`, layering CWD over the anchor. `pool` maps merge
/// key-by-key; `mdm` takes the CWD value when present.
pub fn resolve_mdm_variables_with_anchor(anchor: Option<&Path>) -> MdmVariablesConfig {
    let mut merged = MdmVariablesConfig::default();
    if let Some(a) = anchor {
        if let Some(cfg) = ContourConfig::load_nearest_from(a) {
            merged = cfg.mdm_variables;
        }
    }
    if let Some(cfg) = ContourConfig::load_nearest() {
        let cwd = cfg.mdm_variables;
        merged.pool.extend(cwd.pool);
        if cwd.mdm.is_some() {
            merged.mdm = cwd.mdm;
        }
    }
    merged
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

/// Resolve the preset/recipe library path from a CLI flag, falling
/// back to `.contour/config.toml`'s `defaults.library_path`.
///
/// Lookup order:
/// 1. Explicit CLI value (e.g. `--into <DIR>` or `--recipe-path <DIR>`)
/// 2. `defaults.library_path` from `.contour/config.toml`
/// 3. `None` — caller decides whether the missing value is fatal
///
/// Returns the resolved path as a `PathBuf` so callers don't have to
/// re-parse the string.
pub fn resolve_library_path(cli_value: Option<&str>) -> Option<PathBuf> {
    if let Some(v) = cli_value
        && !v.is_empty()
    {
        return Some(PathBuf::from(v));
    }
    ContourConfig::load_nearest()
        .and_then(|cfg| cfg.defaults.library_path)
        .filter(|p| !p.as_os_str().is_empty())
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
                library_path: None,
            },
            vars: BTreeMap::new(),
            signing: None,
            validation: ValidationConfig::default(),
            secrets: SecretsConfig::default(),
            mdm_variables: MdmVariablesConfig::default(),
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

    #[test]
    fn validation_config_defaults_fail_on_deprecations_false() {
        let v = ValidationConfig::default();
        assert!(v.fail_on_errors);
        assert!(!v.fail_on_warnings);
        assert!(!v.fail_on_deprecations);
    }

    #[test]
    fn validation_config_parses_fail_on_deprecations() {
        let toml = "fail_on_deprecations = true\n";
        let v: ValidationConfig = toml::from_str(toml).unwrap();
        assert!(v.fail_on_deprecations);
        assert!(v.fail_on_errors); // serde default still applies
    }

    #[test]
    fn secrets_config_defaults_empty() {
        let v = SecretsConfig::default();
        assert!(v.dotenv.is_none());
        assert!(v.op_vault.is_none());
        assert!(v.refs.is_empty());
    }

    #[test]
    fn mdm_variables_config_defaults_empty() {
        let v = MdmVariablesConfig::default();
        assert!(v.mdm.is_none());
        assert!(v.pool.is_empty());
    }

    #[test]
    fn mdm_variables_config_parses_pool() {
        let toml = "\
            mdm = \"fleet\"\n\
            [pool]\n\
            SCEP_CHALLENGE = \"FLEET_VAR_NDES_SCEP_CHALLENGE\"\n\
            USER_EMAIL = \"%Username%@acme.com\"\n";
        let v: MdmVariablesConfig = toml::from_str(toml).unwrap();
        assert_eq!(v.mdm.as_deref(), Some("fleet"));
        assert_eq!(
            v.pool.get("SCEP_CHALLENGE").map(String::as_str),
            Some("FLEET_VAR_NDES_SCEP_CHALLENGE")
        );
        assert_eq!(
            v.pool.get("USER_EMAIL").map(String::as_str),
            Some("%Username%@acme.com")
        );
    }

    #[test]
    fn secrets_config_parses_refs_and_sources() {
        let toml = "\
            dotenv = \".env.prod\"\n\
            op_vault = \"Corp\"\n\
            [refs]\n\
            WIFI_PW = \"op://Corp/WiFi/password\"\n\
            API_KEY = \"env:API_KEY\"\n";
        let v: SecretsConfig = toml::from_str(toml).unwrap();
        assert_eq!(v.dotenv.as_deref(), Some(".env.prod"));
        assert_eq!(v.op_vault.as_deref(), Some("Corp"));
        assert_eq!(
            v.refs.get("WIFI_PW").map(String::as_str),
            Some("op://Corp/WiFi/password")
        );
        assert_eq!(
            v.refs.get("API_KEY").map(String::as_str),
            Some("env:API_KEY")
        );
    }
}
