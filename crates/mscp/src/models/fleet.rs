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

/// Label path reference for default.yml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelPathRef {
    pub path: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSetting {
    /// Relative path to the mobileconfig file
    pub path: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_include_all: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_include_any: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_exclude_any: Option<Vec<String>>,
}

/// Script reference - Fleet `GitOps` only supports path (`BaseItem` struct)
/// NOTE: Fleet does NOT support label targeting for scripts (only for profiles)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Script {
    /// Relative path to the script file
    pub path: String,
}

/// Policy entry — either a path reference to a separate file or an inline value.
///
/// Fleet GitOps supports both inline policies and path references.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyEntry {
    /// Reference to a separate YAML file containing policies
    PathRef { path: String },
    /// Inline policy value (passthrough)
    Inline(yaml_serde::Value),
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
