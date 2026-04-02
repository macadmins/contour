use serde::{Deserialize, Serialize};

/// Baseline metadata (name, title, preamble, authors, platform provenance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMeta {
    pub baseline: String,
    pub title: String,
    pub preamble: Option<String>,
    pub authors: Vec<String>,
    /// Which (platform, os_version) combos this baseline was found on.
    /// E.g. `[("iOS", "18.0"), ("iOS", "26.0")]` for indigo_base.
    pub platforms: Vec<(String, String)>,
}

/// mSCP section (auditing, authentication, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub description: String,
}

/// NIST 800-53 control-to-impact-tier mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlTier {
    pub control_id: String,
    pub tier: String,
}

/// Lightweight rule metadata (no scripts/fixes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMeta {
    pub rule_id: String,
    pub title: String,
    pub discussion: Option<String>,
    pub severity: Option<String>,
    pub has_check: bool,
    pub has_fix: bool,
    pub mobileconfig: bool,
    pub has_ddm_info: bool,
    /// Linux distribution (e.g. "ubuntu"), `None` for macOS/iOS rules.
    pub distro: Option<String>,
}

/// Baseline → section → rule membership edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEdge {
    pub baseline: String,
    pub platform: Option<String>,
    pub os_version: Option<String>,
    pub section: String,
    pub rule_id: String,
    pub parent_values: String,
}

/// Full versioned rule with enforcement metadata and platform support.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleVersioned {
    pub rule_id: String,
    pub platform: String,
    pub os_version: String,
    pub title: String,
    pub severity: Option<String>,
    pub has_check: bool,
    pub has_fix: bool,
    pub has_result: bool,
    pub content_hash: String,
    pub mobileconfig: bool,
    pub has_ddm_info: bool,
    pub enforcement_type: Option<String>,
    pub tags: Vec<String>,
    pub check_mechanism: Option<String>,
    pub osquery_checkable: bool,
    pub osquery_table: Option<String>,
    pub baseline_count: i32,
    pub control_count: i32,
    pub weight: f64,
    pub odv_default: Option<String>,
    pub distro: Option<String>,
}

/// Rule enforcement payloads — scripts, mobileconfig info, DDM declaration details.
#[derive(Debug, Clone, PartialEq)]
pub struct RulePayload {
    pub rule_id: String,
    pub check_script: Option<String>,
    pub fix_script: Option<String>,
    pub expected_result: Option<String>,
    pub odv_options: Option<String>,
    pub mobileconfig_info: Option<String>,
    pub ddm_declaration_type: Option<String>,
    pub ddm_key: Option<String>,
    pub ddm_value: Option<String>,
    pub ddm_service: Option<String>,
    pub ddm_config_file: Option<String>,
    pub ddm_configuration_key: Option<String>,
    pub ddm_configuration_value: Option<String>,
}

/// XML envelope nesting pattern for mobileconfig generation.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvelopePattern {
    pub nesting_pattern: String,
    pub description: String,
    pub inner_payload_type: Option<String>,
    pub envelope_template: String,
    pub default_scope: String,
}

/// Required metadata key for mobileconfig envelope layers.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvelopeMetaKey {
    pub layer: String,
    pub key_name: String,
    pub value_type: String,
    pub required: bool,
    pub default_value: Option<String>,
    pub description: String,
}
