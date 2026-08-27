use serde::{Deserialize, Serialize};

/// macOS/iOS/etc version string (e.g. "26.0", "15.0").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OsVersion(pub String);

impl OsVersion {
    /// Create a new OS version from a string.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Return the version string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parse into (major, minor) tuple for numeric comparison.
    fn parts(&self) -> (u32, u32) {
        let mut iter = self.0.split('.').filter_map(|s| s.parse::<u32>().ok());
        let major = iter.next().unwrap_or(0);
        let minor = iter.next().unwrap_or(0);
        (major, minor)
    }

    /// True if this version is >= other (numeric major.minor comparison).
    pub fn gte(&self, other: &OsVersion) -> bool {
        self.parts() >= other.parts()
    }
}

/// Apple platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Platform {
    #[serde(alias = "macOS")]
    MacOS,
    #[serde(alias = "iOS")]
    IOS,
    #[serde(alias = "tvOS")]
    TvOS,
    #[serde(alias = "visionOS")]
    VisionOS,
    #[serde(alias = "watchOS")]
    WatchOS,
    /// Windows (windows_capabilities.parquet only).
    Windows,
}

impl Platform {
    /// Return the canonical string for this platform.
    pub fn as_str(&self) -> &str {
        match self {
            Self::MacOS => "macOS",
            Self::IOS => "iOS",
            Self::TvOS => "tvOS",
            Self::VisionOS => "visionOS",
            Self::WatchOS => "watchOS",
            Self::Windows => "Windows",
        }
    }
}

/// Whether a capability comes from MDM profiles or DDM declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PayloadKind {
    /// Traditional MDM configuration profile.
    MdmProfile,
    /// Declarative Device Management declaration.
    DdmDeclaration,
    /// MDM remote command (e.g. DeviceLock, EraseDevice).
    MdmCommand,
    /// MDM check-in protocol message (e.g. TokenUpdate, Authenticate).
    MdmCheckin,
    /// Windows CSP setting node (from Microsoft's DDF v2 files;
    /// `windows_capabilities.parquet` only).
    CspSetting,
    /// Windows ADMX-backed policy surfaced through a CSP
    /// (`windows_capabilities.parquet` only).
    AdmxPolicy,
}

/// DDM declaration category within the device-management schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DdmCategory {
    /// `configurations/` — settings declarations.
    Configuration,
    /// `assets/` — credential/data/identity asset references.
    Asset,
    /// `activations/` — activation predicate declarations.
    Activation,
    /// `management/` — org-info, properties, server-capabilities.
    Management,
}

impl DdmCategory {
    /// Return the canonical string for display.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Configuration => "configuration",
            Self::Asset => "asset",
            Self::Activation => "activation",
            Self::Management => "management",
        }
    }
}

/// DDM apply mode — how multiple declarations of the same type merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApplyMode {
    /// Only one declaration of this type can exist.
    Single,
    /// Multiple declarations coexist independently.
    Multiple,
    /// Multiple declarations are merged per `combinetype` rules.
    Combined,
}

impl ApplyMode {
    /// Return the canonical string for display.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Single => "single",
            Self::Multiple => "multiple",
            Self::Combined => "combined",
        }
    }

    /// Parse from a YAML string value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "single" => Some(Self::Single),
            "multiple" => Some(Self::Multiple),
            "combined" => Some(Self::Combined),
            _ => None,
        }
    }
}

/// OS support entry for a capability on a specific platform.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsSupport {
    /// Platform this support entry applies to.
    pub platform: Platform,
    /// OS version where this capability was introduced.
    pub introduced: Option<String>,
    /// OS version where this capability was deprecated.
    pub deprecated: Option<String>,
    /// OS version where this capability was removed.
    pub removed: Option<String>,
    /// Allowed enrollment types (e.g. "supervised", "device", "user", "local").
    pub allowed_enrollments: Option<Vec<String>>,
    /// Allowed scopes (e.g. "system", "user").
    pub allowed_scopes: Option<Vec<String>>,
    /// Whether supervision is required.
    pub supervised: Option<bool>,
    /// Whether DEP enrollment is required.
    pub requires_dep: Option<bool>,
    /// Whether user-approved MDM is required.
    pub user_approved_mdm: Option<bool>,
    /// Whether manual install is allowed.
    pub allow_manual_install: Option<bool>,
    /// Whether available on the device channel.
    pub device_channel: Option<bool>,
    /// Whether available on the user channel.
    pub user_channel: Option<bool>,
    /// Whether multiple payloads of the same type are allowed.
    pub multiple: Option<bool>,
    /// Whether this is a beta feature.
    pub beta: Option<bool>,
    /// Shared iPad mode constraint (DDM) — e.g. "allowed",
    /// "required", "forbidden". `None` means the schema didn't declare
    /// a constraint.
    pub shared_ipad_mode: Option<String>,
    /// User-enrollment mode constraint (DDM) — e.g. "allowed",
    /// "required", "forbidden". `None` means no constraint.
    pub user_enrollment_mode: Option<String>,
}

/// A single key within a payload type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadKey {
    /// Key name (e.g. "askForPassword").
    pub name: String,
    /// Data type (e.g. "boolean", "integer", "string").
    pub data_type: String,
    /// Whether the key is required or optional.
    pub presence: String,
    /// Default value if any.
    pub default_value: Option<serde_json::Value>,
    /// Range constraints for numeric types.
    pub range_min: Option<f64>,
    /// Upper bound for numeric types.
    pub range_max: Option<f64>,
    /// Allowed values for enumerated types.
    pub range_list: Option<Vec<String>>,
    /// OS version when this key was introduced, per platform — the key's
    /// own `supportedOS`, not the payload's. A platform is absent from the
    /// map when the key is `n/a` (unsupported) there; an entirely empty
    /// map means the parquet carried no per-key data for this key.
    pub introduced: std::collections::HashMap<Platform, String>,
    /// OS version when this key was deprecated, per platform.
    pub deprecated: std::collections::HashMap<Platform, String>,
    /// Whether the key requires a supervised device, per platform.
    /// Populated from the key's own `supportedOS.<platform>.supervised`.
    pub supervised: std::collections::HashMap<Platform, bool>,
    /// Dot-path to parent key, `None` for top-level keys.
    pub parent_key: Option<String>,
    /// Nesting depth: 0 for top-level, 1+ for subkeys.
    pub depth: u32,
    /// DDM merge strategy (e.g. "boolean-or", "number-min", "set-union").
    pub combinetype: Option<String>,
    /// Human-readable title from schema.
    pub key_title: Option<String>,
    /// Description text from the `content` field in schema.
    pub key_description: Option<String>,
    /// Subtype hint (e.g. "url", "hostname", "email").
    pub subtype: Option<String>,
    /// Allowed asset content types (MIME types).
    pub asset_types: Option<Vec<String>>,
    /// Regex validation pattern from the `format` field.
    pub format: Option<String>,
}

impl PayloadKey {
    /// Earliest OS version where this key appears across any platform —
    /// the lexicographically-smallest entry in `introduced`. Returns
    /// `None` if no platform recorded an introduced version.
    ///
    /// Useful for callers that want a single "min version" and don't
    /// care which platform it came from. Lexicographic ordering on
    /// version strings happens to match numeric ordering for the
    /// version shapes Apple emits (e.g. "10.7" < "10.10" lexicographic
    /// is wrong, but Apple is on macOS 11+ now, so "11" / "12" / etc.
    /// sort correctly; for legacy macOS-pre-11 keys callers should
    /// inspect the map directly).
    pub fn earliest_introduced(&self) -> Option<String> {
        self.introduced.values().min().cloned()
    }
}

/// Setup Assistant skip key with platform and version gating.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkipKey {
    pub key: String,
    pub title: String,
    pub description: Option<String>,
    pub platform: String,
    pub introduced: Option<String>,
    pub deprecated: Option<String>,
    pub removed: Option<String>,
    pub always_skippable: Option<bool>,
}

/// A parsed capability (MDM profile or DDM declaration).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Capability {
    /// Payload type identifier (e.g. "com.apple.screensaver").
    pub payload_type: String,
    /// Whether this is an MDM profile or DDM declaration.
    pub kind: PayloadKind,
    /// Human-readable title.
    pub title: String,
    /// Description of this capability.
    pub description: String,
    /// Supported OS versions per platform.
    pub supported_os: Vec<OsSupport>,
    /// Payload keys defined by this capability.
    pub keys: Vec<PayloadKey>,
    /// DDM apply mode (single/multiple/combined).
    pub apply_mode: Option<ApplyMode>,
    /// DDM category (configuration/asset/activation/management).
    pub ddm_category: Option<DdmCategory>,
    /// Windows CSP name (Configuration Service Provider), if applicable.
    pub csp_name: Option<String>,
    /// Upstream manifest source identifier.
    pub manifest_source: Option<String>,
}

impl Capability {
    /// Check if this capability was available on a platform at a given OS version.
    ///
    /// Returns `true` if the capability has an `introduced` version for the
    /// platform and the rule's OS version is >= that introduced version.
    /// Returns `true` if there's no introduced info (assume available).
    /// Returns `false` if introduced is "n/a" or the version is too old.
    pub fn available_at(&self, platform: Platform, os_version: &OsVersion) -> bool {
        let entry = self.supported_os.iter().find(|s| s.platform == platform);
        match entry {
            None => true, // no OS info → assume available
            Some(s) => match &s.introduced {
                None => true,
                Some(v) if v == "n/a" => false,
                Some(v) => os_version.gte(&OsVersion::new(v.as_str())),
            },
        }
    }
}

/// A parsed ProfileCreator manifest (one payload type with its fields).
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadSchema {
    pub payload_type: String,
    /// Capability classification: `"MdmProfile"` / `"MdmConfig"` /
    /// `"DdmDeclaration"` etc. 100% populated in current data;
    /// `None` only when reading older parquets.
    pub kind: Option<String>,
    /// Provenance label — which upstream feed this row originated from
    /// (e.g. `"profilecreator"`, `"apple"`).
    pub manifest_source: Option<String>,
    /// `pfm_interaction` / Apple `apply` mode (`"single"` / `"multiple"`
    /// / `"combined"`). Sparse — only declarations that explicitly
    /// declare an apply mode populate it.
    pub apply_mode: Option<String>,
    pub category: String,
    pub title: String,
    pub description: String,
    pub platforms: PlatformFlags,
    pub min_versions: MinVersions,
    /// macOS-only deprecation marker (sourced from
    /// `pfm_macos_deprecated`). Other platforms lack the equivalent in
    /// ProfileCreator's source data; for full per-OS deprecation
    /// coverage consult `Capability.supported_os` from
    /// `capabilities.parquet`.
    pub deprecated_macos: Option<String>,
    /// Whether this payload deploys on the device channel (derived
    /// from `pfm_targets`).
    pub device_channel: Option<bool>,
    /// Whether this payload deploys on the user channel.
    pub user_channel: Option<bool>,
    pub fields: Vec<ManifestField>,
}

/// Platform support as boolean flags.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PlatformFlags {
    pub macos: bool,
    pub ios: bool,
    pub tvos: bool,
    pub watchos: bool,
    pub visionos: bool,
}

/// Minimum OS versions per platform.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MinVersions {
    pub macos: Option<String>,
    pub ios: Option<String>,
    pub tvos: Option<String>,
    pub watchos: Option<String>,
    pub visionos: Option<String>,
}

/// A single field within a ProfileCreator manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestField {
    pub name: String,
    pub field_type: String,
    pub title: String,
    pub description: String,
    pub required: bool,
    pub supervised: bool,
    /// Now sourced from `pfm_sensitive` (default `false`) instead of
    /// hardcoded `false`. ~7 keys flip to `true` in the current parquet.
    pub sensitive: bool,
    pub default_value: Option<String>,
    pub allowed_values: Option<String>,
    pub depth: u8,
    /// Dot-path to parent key, `None` for top-level keys. Mirrors the
    /// `parent_key` shape on `PayloadKey` in `capabilities.parquet`.
    pub parent_key: Option<String>,
    pub platforms: Option<String>,
    pub min_version: Option<String>,
    /// Subtype hint — `"url"`, `"hostname"`, `"email"`, etc. (sourced
    /// from `pfm_value_unit`). Used as a validation hint by downstream
    /// generators.
    pub subtype: Option<String>,
    /// Regex validation pattern (sourced from `pfm_format`).
    pub format: Option<String>,
}
