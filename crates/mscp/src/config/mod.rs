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
    /// Fleet GitOps layout (v4.83+): platforms/macos/<kind>/<baseline>/, mscp/<baseline>/baseline.toml, labels/, fleets/
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

    /// osquery detection settings.
    ///
    /// Config-driven generation has no CLI flags to read, so before this
    /// existed `generate-all --config` could not emit osquery output at all,
    /// and `generate --config --osquery` accepted the flag and dropped it —
    /// the command succeeded, nothing was written, and nothing said so.
    #[serde(default)]
    pub osquery: OsquerySettings,
}

/// osquery detection settings — the config form of `--osquery`.
///
/// `format` and `audit` mirror `--osquery-format` and `--osquery-audit` and
/// are parsed by the same code, so an invalid value here fails the same way
/// an invalid flag does rather than silently selecting a default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsquerySettings {
    /// Emit osquery detection (native-table queries + audit script).
    #[serde(default)]
    pub enabled: bool,

    /// Output adapter: `fleet` (default) or `pack`.
    #[serde(default = "default_osquery_format")]
    pub format: String,

    /// Audit-script scope: `slim` (default, residual only) or `full`.
    #[serde(default = "default_osquery_audit")]
    pub audit: String,
}

impl Default for OsquerySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            format: default_osquery_format(),
            audit: default_osquery_audit(),
        }
    }
}

fn default_osquery_format() -> String {
    "fleet".to_string()
}

fn default_osquery_audit() -> String {
    "slim".to_string()
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
            osquery: OsquerySettings::default(),
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

    /// Git branch to build this baseline from — the rule source, not the
    /// target platform. `main` carries every platform; an OS-preview branch
    /// such as `dev_28` carries the next release's rules early. Use
    /// `os` / `os_version` to choose what gets built.
    /// Examples: "main", "origin/main", "dev_28"
    /// If not specified, uses the checkout's current branch.
    pub branch: Option<String>,

    /// Optional fleet name override
    pub fleet: Option<String>,

    /// Label targeting
    #[serde(default)]
    pub labels: LabelConfig,

    /// Excluded rules (optional)
    #[serde(default)]
    pub excluded_rules: Vec<String>,

    /// Custom metadata. Read by nothing and written to no artifact, so a
    /// non-empty table is refused at load — see `config::parser`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
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

    // The three below were parsed and read by nothing, while the generated
    // template set them — `generate_diffs = true` and `versions_to_keep = 5`
    // promised diffs and a version history no run produced. They stay
    // parseable only so `config::parser` can refuse a value that asks for
    // something contour does not do, by name, instead of serde rejecting the
    // key with no reason. `None` is "not written", which is what the
    // template now writes.
    /// Per-baseline subdirectories. Always true: the layout is fixed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub separate_baselines: Option<bool>,

    /// Diff reports during generate. Not implemented; `mscp diff` compares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generate_diffs: Option<bool>,

    /// Previous versions to keep. Not implemented; nothing is kept or pruned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions_to_keep: Option<usize>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            structure: OutputStructure::default(),
            separate_baselines: None,
            generate_diffs: None,
            versions_to_keep: None,
        }
    }
}

/// Validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Path to JSON schemas directory
    pub schemas_path: Option<PathBuf>,

    /// Enable strict validation
    #[serde(default)]
    pub strict: bool,

    /// Cross-baseline conflict detection. Not implemented, so `true` is
    /// refused at load rather than defaulted on and reported as not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_conflicts: Option<bool>,

    /// Validate file paths exist
    #[serde(default = "default_true")]
    pub validate_paths: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            schemas_path: None,
            strict: false,
            check_conflicts: None,
            validate_paths: true,
        }
    }
}
