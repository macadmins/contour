pub mod parser;
pub mod template;

pub use parser::*;
pub use template::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

/// Output directory structure layout
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OutputStructure {
    /// Fleet GitOps layout: lib/mscp/<baseline>/, team YAMLs, labels, policies
    #[default]
    Pluggable,
    /// Jamf Pro layout: <baseline>/profiles/, scripts/ — no Fleet artifacts
    Flat,
    /// Munki layout: <baseline>/profiles/, scripts/, munki/ nopkg items
    Nested,
}

impl fmt::Display for OutputStructure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputStructure::Pluggable => write!(f, "pluggable"),
            OutputStructure::Flat => write!(f, "flat"),
            OutputStructure::Nested => write!(f, "nested"),
        }
    }
}

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Global settings
    #[serde(default)]
    pub settings: Settings,

    /// Baseline configurations
    #[serde(default)]
    pub baselines: Vec<BaselineConfig>,

    /// Output configuration
    #[serde(default)]
    pub output: OutputConfig,

    /// Validation settings
    #[serde(default)]
    pub validation: ValidationConfig,
}

/// Organization settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationSettings {
    /// Reverse-domain identifier (e.g., "com.yourorg")
    #[serde(default)]
    pub domain: String,

    /// Organization display name
    #[serde(default)]
    pub name: String,
}

impl Default for OrganizationSettings {
    fn default() -> Self {
        Self {
            domain: "com.example".to_string(),
            name: "Example Organization".to_string(),
        }
    }
}

/// Global settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Organization settings
    #[serde(default)]
    pub organization: OrganizationSettings,

    /// Path to mSCP repository
    pub mscp_repo: PathBuf,

    /// Default output directory
    pub output_dir: PathBuf,

    /// Python execution method: "auto", "uv", or "python3"
    #[serde(default = "default_python_method")]
    pub python_method: String,

    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,

    /// Generate DDM artifacts (pass -D flag to mSCP)
    #[serde(default)]
    pub generate_ddm: bool,

    /// Jamf Pro mode settings
    #[serde(default)]
    pub jamf: JamfSettings,

    /// Fleet mode settings
    #[serde(default)]
    pub fleet: FleetSettings,

    /// Munki integration settings
    #[serde(default)]
    pub munki: MunkiSettings,
}

/// Jamf Pro-specific settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JamfSettings {
    /// Enable Jamf Pro mode
    #[serde(default)]
    pub enabled: bool,

    /// Use deterministic UUIDs based on `PayloadType`
    #[serde(default)]
    pub deterministic_uuids: bool,

    /// Remove creation dates from mobileconfig descriptions
    #[serde(default)]
    pub no_creation_date: bool,

    /// Use identical UUID for `PayloadIdentifier` and `PayloadUUID`
    #[serde(default)]
    pub identical_payload_uuid: bool,

    /// Exclude profiles conflicting with Jamf Pro native capabilities
    #[serde(default)]
    pub exclude_conflicts: bool,

    /// Remove `ConsentText` from profiles
    #[serde(default)]
    pub remove_consent_text: bool,

    /// Custom `ConsentText` to use (if set, overrides removal)
    #[serde(default)]
    pub consent_text: Option<String>,

    /// Custom `PayloadDescription` format
    #[serde(default)]
    pub description_format: Option<String>,
}

/// Fleet-specific settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FleetSettings {
    /// Enable Fleet conflict filtering
    #[serde(default)]
    pub enabled: bool,

    /// Skip generating Fleet label definitions
    #[serde(default)]
    pub no_labels: bool,
}

/// Munki-specific settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MunkiSettings {
    /// Generate Munki compliance flags nopkg item
    #[serde(default)]
    pub compliance_flags: bool,

    /// Path where compliance plist will be written on target systems
    #[serde(default = "default_munki_compliance_path")]
    pub compliance_path: String,

    /// Prefix for compliance flags
    #[serde(default = "default_munki_flag_prefix")]
    pub flag_prefix: String,

    /// Generate Munki script nopkg items from script rules
    #[serde(default)]
    pub script_nopkg: bool,

    /// Munki catalog for script nopkg items
    #[serde(default = "default_munki_catalog")]
    pub catalog: String,

    /// Munki category for script nopkg items
    #[serde(default = "default_munki_category")]
    pub category: String,

    /// Embed fix in installcheck (default) or use separate postinstall
    #[serde(default)]
    pub separate_postinstall: bool,
}

fn default_munki_compliance_path() -> String {
    crate::transformers::munki_compliance::DEFAULT_COMPLIANCE_PLIST_PATH.to_string()
}

fn default_munki_flag_prefix() -> String {
    crate::transformers::munki_compliance::DEFAULT_FLAG_PREFIX.to_string()
}

fn default_munki_catalog() -> String {
    crate::transformers::munki_compliance::DEFAULT_MUNKI_CATALOG.to_string()
}

fn default_munki_category() -> String {
    crate::transformers::munki_compliance::DEFAULT_MUNKI_CATEGORY.to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            organization: OrganizationSettings::default(),
            mscp_repo: PathBuf::from("./macos_security"),
            output_dir: PathBuf::from("./fleet-gitops"),
            python_method: default_python_method(),
            verbose: false,
            generate_ddm: false,
            jamf: JamfSettings::default(),
            fleet: FleetSettings::default(),
            munki: MunkiSettings::default(),
        }
    }
}

fn default_python_method() -> String {
    "auto".to_string()
}

/// Configuration for a single baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    /// Baseline name (e.g., "`cis_lvl1`", "800-53r5_high")
    pub name: String,

    /// Whether to generate this baseline
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Git branch to use (determines platform and OS version)
    /// Examples: "origin/sequoia", "`origin/ios_18`", "origin/sonoma"
    /// If not specified, uses current branch
    pub branch: Option<String>,

    /// Optional team name override
    pub team: Option<String>,

    /// Label targeting
    #[serde(default)]
    pub labels: LabelConfig,

    /// Excluded rules (optional)
    #[serde(default)]
    pub excluded_rules: Vec<String>,

    /// Custom metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,

    /// Fleet GitOps glob configuration.
    ///
    /// Captures per-section decisions made via `mscp process --interactive`:
    /// which sections collapse into a single `paths:` glob and which individual
    /// items are kept as literal `path:` exceptions (optionally moved into a
    /// subfolder so the flat glob doesn't match them). Defaults to "no glob"
    /// for every section, preserving legacy per-item `path:` emission.
    #[serde(default)]
    pub gitops_glob: GitopsGlobConfig,
}

fn default_true() -> bool {
    true
}

/// Label configuration for targeting
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LabelConfig {
    /// Labels that must all be present
    #[serde(default)]
    pub include_all: Vec<String>,

    /// Labels where at least one must be present
    #[serde(default)]
    pub include_any: Vec<String>,

    /// Labels that must not be present
    #[serde(default)]
    pub exclude_any: Vec<String>,
}

/// Per-baseline Fleet GitOps glob configuration.
///
/// Each section (profiles, scripts, labels, policies, reports) is independently
/// globbable. Sections missing from the TOML default to "no glob" and fall
/// through to the legacy per-item `path:` emission.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitopsGlobConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiles: Option<GlobSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scripts: Option<GlobSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<GlobSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<GlobSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reports: Option<GlobSection>,
}

/// Per-section glob settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobSection {
    /// When true, emit a single `paths:` entry covering everything in the
    /// section except items listed in `exceptions`.
    pub enabled: bool,

    /// Required when globbing profiles: baseline-level `mscp-{baseline}`
    /// labels cannot ride on a `paths:` entry, so the interactive flow asks
    /// the user to confirm dropping them for the globbed subset.
    #[serde(default)]
    pub drop_labels: bool,

    /// Items excluded from the glob. Each becomes a literal `path:` entry,
    /// typically placed in a subfolder so the flat glob pattern doesn't
    /// match it on the filesystem.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exceptions: Vec<GlobException>,
}

/// One literal-path exception inside a globbed section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobException {
    /// Filename (basename, no directory component) the exception applies to.
    /// Matched against discovered items by exact string equality.
    pub filename: String,

    /// Subfolder (relative to the section's root directory) to move this
    /// item into. `None` leaves it at the flat location — use only when the
    /// glob pattern would not match it for some other reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subfolder: Option<String>,

    /// Fleet labels for this exception entry (profiles only; ignored for
    /// scripts since Fleet does not support script labels).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels_include_all: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels_include_any: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels_exclude_any: Vec<String>,
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Base directory structure: pluggable (Fleet), flat (Jamf), nested (Munki)
    #[serde(default)]
    pub structure: OutputStructure,

    /// Create subdirectories per baseline
    #[serde(default = "default_true")]
    pub separate_baselines: bool,

    /// Generate diff reports
    #[serde(default)]
    pub generate_diffs: bool,

    /// Keep previous versions
    #[serde(default = "default_versions_to_keep")]
    pub versions_to_keep: usize,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            structure: OutputStructure::default(),
            separate_baselines: true,
            generate_diffs: false,
            versions_to_keep: default_versions_to_keep(),
        }
    }
}

fn default_versions_to_keep() -> usize {
    5
}

/// Validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Path to JSON schemas directory
    pub schemas_path: Option<PathBuf>,

    /// Enable strict validation
    #[serde(default)]
    pub strict: bool,

    /// Check for conflicts across baselines
    #[serde(default = "default_true")]
    pub check_conflicts: bool,

    /// Validate file paths exist
    #[serde(default = "default_true")]
    pub validate_paths: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            schemas_path: None,
            strict: false,
            check_conflicts: true,
            validate_paths: true,
        }
    }
}
