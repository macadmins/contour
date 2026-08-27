//! Domain types for the AI-tool managed-configuration policy dataset.

/// One managed-configuration key of one AI tool — the dataset's grain is
/// (tool × key), deliberately flat rather than folded into mdm-schema.
#[derive(Debug, Clone, PartialEq)]
pub struct AppPolicyKey {
    /// Stable tool slug (e.g. `claude-code`, `codex`, `cursor`).
    pub tool_id: String,
    /// Display name (e.g. `Claude Code`).
    pub tool_name: String,
    /// Vendor (e.g. `Anthropic`, `OpenAI`).
    pub vendor: String,
    /// Tool category (e.g. `ai-coding-agent`).
    pub category: String,
    /// Where the schema came from (e.g. `upstream_schema`, `vendor_docs`).
    pub source_kind: String,
    /// URL of the upstream schema or documentation.
    pub source_url: String,
    /// Upstream version, when the source declares one.
    pub source_version: Option<String>,
    /// SHA-256 of the source document at ingest time.
    pub source_hash: String,
    /// Full dotted path of the key (e.g. `permissions.allow`).
    pub key_path: String,
    /// Leaf key name.
    pub key_name: String,
    /// Parent key path for nested keys.
    pub parent_key: Option<String>,
    /// Nesting depth (0 = top-level).
    pub depth: u8,
    /// Value type (e.g. `string`, `boolean`, `array`, `object`).
    pub key_type: String,
    /// Element type for arrays.
    pub item_type: Option<String>,
    /// Human-readable title.
    pub title: Option<String>,
    /// Key documentation text.
    pub description: Option<String>,
    /// Default value (string representation).
    pub default_value: Option<String>,
    /// Example value (string representation).
    pub example_value: Option<String>,
    /// Enumerated allowed values, when the key is enum-like.
    pub allowed_values: Option<Vec<String>>,
    /// Scope the key applies at (e.g. `user`, `project`, `managed`).
    pub scope: String,
    /// True when the key is only honored from managed (MDM) configuration.
    pub managed_only: bool,
    /// How the value merges across configuration layers.
    pub merge_strategy: Option<String>,
    /// What the tool does with an invalid value.
    pub invalid_behavior: Option<String>,
    /// True when the key is security-relevant (permissions, lockdown, …).
    pub security_relevant: bool,
    /// Tool version that introduced the key.
    pub introduced: Option<String>,
    /// Tool version that deprecated the key.
    pub deprecated: Option<String>,
    /// Row provenance tag.
    pub provenance: String,
    /// Delivery channels this key can arrive through.
    pub channels: PolicyChannels,
    /// Managed-preferences domain on macOS (e.g. `com.anthropic.claudecode`).
    pub macos_domain: Option<String>,
    /// Human-readable channel names.
    pub channel_names: Option<Vec<String>>,
    /// Compact channel summary string.
    pub channels_summary: String,
    /// Mapped NIST 800-53 control names.
    pub controls: Option<Vec<String>>,
    /// Mapped NIST 800-53 control ids (e.g. `AC-3`).
    pub control_ids: Option<Vec<String>>,
    /// Compliance frameworks the controls belong to.
    pub frameworks: Option<Vec<String>>,
}

/// Which delivery channels a policy key supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyChannels {
    /// macOS managed preferences (mobileconfig / MDM).
    pub macos_plist: bool,
    /// JSON settings file (e.g. `managed-settings.json`).
    pub json_file: bool,
    /// Drop-in directory of merged fragments.
    pub dropin_dir: bool,
    /// Windows registry.
    pub win_registry: bool,
    /// TOML settings file (e.g. Codex `managed_config.toml`).
    pub toml_file: bool,
    /// Vendor cloud-managed configuration.
    pub cloud: bool,
    /// MDM AppConfig (managed app configuration).
    pub managed_app_config: bool,
}
