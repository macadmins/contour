// Fleet models - part of public API for planned features
#![allow(dead_code, reason = "module under development")]

use serde::{Deserialize, Serialize};

/// Fleet global configuration structure (default.yml)
///
/// Based on Fleet `GitOps` spec for org-wide settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetGlobalConfig {
    /// Policies that run on all hosts ("All teams" for Premium)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<yaml_serde::Value>>,

    /// Reports that run on all hosts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reports: Option<Vec<yaml_serde::Value>>,

    /// Agent options - path reference to shared config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_options: Option<AgentOptionsRef>,

    /// Controls - only set here OR in no-team.yml, not both
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controls: Option<Controls>,

    /// Organization-wide settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_settings: Option<OrgSettings>,

    /// Labels - can be inline or path references
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<LabelPathRef>>,
}

/// Label path reference for default.yml.
///
/// Exactly one of `path` (single literal file) or `paths` (glob pattern
/// matching many files, e.g. `./lib/labels/mscp-*.labels.yml`) must be set.
/// Fleet disallows labels on entries that use `paths`, but label-path-refs
/// themselves carry no labels, so that constraint does not apply here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelPathRef {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub paths: Option<String>,
}

/// Agent options path reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentOptionsRef {
    pub path: String,
}

/// Organization settings for default.yml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_settings: Option<ServerSettings>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_info: Option<OrgInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<EnrollSecret>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Features>,
}

/// Server settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub server_url: String,
}

/// Organization info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgInfo {
    pub org_name: String,
}

/// Enrollment secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollSecret {
    pub secret: String,
}

/// Feature flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Features {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_host_users: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_software_inventory: Option<bool>,
}

/// Agent options configuration (lib/agent-options.yml)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line_flags: Option<yaml_serde::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<AgentConfig>,
}

/// Agent config section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decorators: Option<Decorators>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<AgentConfigOptions>,
}

/// Decorators for osquery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decorators {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<Vec<String>>,
}

/// Agent config options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfigOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_distributed: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub distributed_interval: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub distributed_plugin: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub distributed_tls_max_attempts: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub logger_tls_endpoint: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_delimiter: Option<String>,
}

/// Team settings for team files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<EnrollSecret>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Features>,
}

/// `FleetDM` fleet configuration structure (Fleet v4.82+)
///
/// Based on Fleet `GitOps` spec: `pkg/spec/gitops.go`
/// Top-level keys: `name`, `settings`, `org_settings`, `agent_options`, `controls`, `policies`, `reports`, `software`, `labels`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetTeamConfig {
    /// Fleet name (top-level, NOT nested under `team:`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    // NOTE: Fleet GitOps does NOT have a `team:` block - name is at top level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controls: Option<Controls>,

    /// Required by Fleet `GitOps` - can be empty array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<yaml_serde::Value>>,

    /// Required by Fleet `GitOps` - can be empty array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reports: Option<Vec<yaml_serde::Value>>,

    /// Required by Fleet `GitOps` - path reference or inline config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_options: Option<yaml_serde::Value>,

    /// Fleet-level settings (Fleet v4.82+: `settings` key in YAML output)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<yaml_serde::Value>,

    /// Required for fleet files - software packages (can be empty)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<Software>,
}

/// Software configuration for team files
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Software {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub packages: Vec<yaml_serde::Value>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub app_store_apps: Vec<yaml_serde::Value>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub fleet_maintained_apps: Vec<yaml_serde::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Controls {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macos_settings: Option<PlatformSettings>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ios_settings: Option<PlatformSettings>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scripts: Option<Vec<Script>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_settings: Option<Vec<CustomSetting>>,
}

/// Configuration profile entry (`configuration_profiles` or `controls.*_settings.custom_settings`).
///
/// Exactly one of `path` or `paths` must be set. Fleet disallows labels on
/// entries that use `paths`, so `labels_*` fields must remain `None` whenever
/// `paths` is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSetting {
    /// Relative path to a single mobileconfig file
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,

    /// Glob pattern matching multiple mobileconfig files (e.g. `../profiles/*.mobileconfig`).
    /// Cannot be combined with any `labels_*` field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub paths: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_include_all: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_include_any: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_exclude_any: Option<Vec<String>>,
}

/// Script reference - Fleet `GitOps` only supports path (`BaseItem` struct).
/// NOTE: Fleet does NOT support label targeting for scripts (only for profiles),
/// so label conflicts with `paths` cannot arise here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Script {
    /// Relative path to a single script file
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,

    /// Glob pattern matching multiple script files (e.g. `../scripts/*.sh`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub paths: Option<String>,
}

/// Policy entry — either a `path:` reference, a `paths:` glob, or an inline value.
///
/// Fleet GitOps supports all three shapes; the generator picks between them
/// based on the baseline's `gitops_glob.policies` configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyEntry {
    /// Reference to a separate YAML file containing policies
    PathRef { path: String },
    /// Glob pattern matching multiple policy YAML files
    PathsRef { paths: String },
    /// Inline policy value (passthrough)
    Inline(yaml_serde::Value),
}

/// Characters forbidden in a literal `path:` field by Fleet GitOps
/// (any one of these makes the path a glob pattern, which must use `paths:`).
pub const PATH_GLOB_METACHARS: &[char] = &['*', '?', '[', '{'];

/// Validate that exactly one of `path` / `paths` is set on an entry,
/// and that literal `path:` values contain no glob metacharacters.
///
/// Used by the generator before serialization to fail fast on invalid output.
pub fn validate_path_xor_paths(
    kind: &str,
    path: Option<&str>,
    paths: Option<&str>,
) -> anyhow::Result<()> {
    match (path, paths) {
        (Some(_), Some(_)) => {
            anyhow::bail!("{kind} entry has both `path` and `paths` set — exactly one is allowed")
        }
        (None, None) => anyhow::bail!(
            "{kind} entry has neither `path` nor `paths` set — exactly one is required"
        ),
        (Some(p), None) if p.contains(PATH_GLOB_METACHARS) => anyhow::bail!(
            "{kind} `path` contains a glob metacharacter ({}) — use `paths` instead: {p}",
            PATH_GLOB_METACHARS
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ),
        _ => Ok(()),
    }
}

impl CustomSetting {
    /// Validate `path`/`paths` invariants plus the Fleet rule that `paths:`
    /// entries cannot carry labels.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_path_xor_paths(
            "configuration_profiles",
            self.path.as_deref(),
            self.paths.as_deref(),
        )?;
        if self.paths.is_some()
            && (self.labels_include_all.is_some()
                || self.labels_include_any.is_some()
                || self.labels_exclude_any.is_some())
        {
            anyhow::bail!(
                "configuration_profiles entry uses `paths:` but also sets labels_* — \
                 Fleet GitOps does not allow labels on glob entries"
            );
        }
        Ok(())
    }
}

impl Script {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_path_xor_paths("scripts", self.path.as_deref(), self.paths.as_deref())
    }
}

impl LabelPathRef {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_path_xor_paths("labels", self.path.as_deref(), self.paths.as_deref())
    }
}

/// Output structure that will be generated
#[derive(Debug, Clone)]
pub struct FleetGitOpsOutput {
    /// Base output directory
    pub output_dir: std::path::PathBuf,

    /// Team configurations to be written
    pub teams: Vec<(String, FleetTeamConfig)>, // (filename, config)

    /// Files to be copied (source, destination)
    pub files_to_copy: Vec<(std::path::PathBuf, std::path::PathBuf)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_path_xor_paths_rejects_both_set() {
        let err = validate_path_xor_paths("scripts", Some("a.sh"), Some("*.sh")).unwrap_err();
        assert!(err.to_string().contains("both"));
    }

    #[test]
    fn validate_path_xor_paths_rejects_neither_set() {
        let err = validate_path_xor_paths("scripts", None, None).unwrap_err();
        assert!(err.to_string().contains("neither"));
    }

    #[test]
    fn validate_path_xor_paths_rejects_glob_metachars_in_path() {
        for bad in ["a*.sh", "a?.sh", "a[1].sh", "a{x}.sh"] {
            let err = validate_path_xor_paths("scripts", Some(bad), None).unwrap_err();
            assert!(
                err.to_string().contains("glob metacharacter"),
                "expected rejection for {bad}"
            );
        }
    }

    #[test]
    fn validate_path_xor_paths_accepts_valid_literal() {
        validate_path_xor_paths("scripts", Some("foo/bar.sh"), None).unwrap();
    }

    #[test]
    fn validate_path_xor_paths_accepts_valid_glob() {
        validate_path_xor_paths("scripts", None, Some("foo/*.sh")).unwrap();
    }

    #[test]
    fn custom_setting_rejects_labels_with_paths() {
        let cs = CustomSetting {
            path: None,
            paths: Some("../profiles/*.mobileconfig".to_string()),
            labels_include_all: Some(vec!["mscp-cis_lvl1".to_string()]),
            labels_include_any: None,
            labels_exclude_any: None,
        };
        let err = cs.validate().unwrap_err();
        assert!(err.to_string().contains("does not allow labels"));
    }

    #[test]
    fn custom_setting_accepts_path_with_labels() {
        let cs = CustomSetting {
            path: Some("../profiles/a.mobileconfig".to_string()),
            paths: None,
            labels_include_all: Some(vec!["mscp-cis_lvl1".to_string()]),
            labels_include_any: None,
            labels_exclude_any: None,
        };
        cs.validate().unwrap();
    }

    #[test]
    fn custom_setting_accepts_paths_without_labels() {
        let cs = CustomSetting {
            path: None,
            paths: Some("../profiles/*.mobileconfig".to_string()),
            labels_include_all: None,
            labels_include_any: None,
            labels_exclude_any: None,
        };
        cs.validate().unwrap();
    }

    #[test]
    fn script_accepts_path_or_paths() {
        Script {
            path: Some("../scripts/a.sh".to_string()),
            paths: None,
        }
        .validate()
        .unwrap();
        Script {
            path: None,
            paths: Some("../scripts/*.sh".to_string()),
        }
        .validate()
        .unwrap();
    }
}
