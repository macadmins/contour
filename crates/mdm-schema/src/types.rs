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
    /// A third-party or Apple preference domain with no dedicated payload
    /// type (`com.microsoft.wdav`, `com.apple.dock`). Deliverable either
    /// directly or inside the MCX envelope.
    ManagedPreference,
    /// A shared structure from Apple's `other/` directory: the shape of a
    /// key another document carries, or a protocol body — not a payload
    /// anyone installs. `ManifestURL` is the shape of a key in
    /// `InstallEnterpriseApplication` and `ManagedInstalls`, `passwordHash`
    /// of one in `AccountConfiguration`; `MachineInfo` is what a device
    /// POSTs during enrollment, `ESSO` the Enrollment SSO document an MDM
    /// serves. The same trap `ManagedPreference` above describes: until
    /// this variant existed the ingest filed all four as `MdmProfile`, and
    /// `form spec ManifestURL` offered to build a profile out of the shape
    /// of a key.
    SharedStructure,
}

impl PayloadKind {
    /// The name as it appears in the `kind` column of every capabilities
    /// table. Round-trips with [`Self::parse`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MdmProfile => "MdmProfile",
            Self::DdmDeclaration => "DdmDeclaration",
            Self::MdmCommand => "MdmCommand",
            Self::MdmCheckin => "MdmCheckin",
            Self::CspSetting => "CspSetting",
            Self::AdmxPolicy => "AdmxPolicy",
            Self::ManagedPreference => "ManagedPreference",
            Self::SharedStructure => "SharedStructure",
        }
    }

    /// Inverse of [`Self::as_str`]; `None` for anything else, never a default.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "MdmProfile" => Self::MdmProfile,
            "DdmDeclaration" => Self::DdmDeclaration,
            "MdmCommand" => Self::MdmCommand,
            "MdmCheckin" => Self::MdmCheckin,
            "CspSetting" => Self::CspSetting,
            "AdmxPolicy" => Self::AdmxPolicy,
            "ManagedPreference" => Self::ManagedPreference,
            "SharedStructure" => Self::SharedStructure,
            _ => return None,
        })
    }

    /// Whether an operator can author this as a document to deploy.
    ///
    /// Commands and check-in messages are protocol traffic an MDM server
    /// sends; they have a schema, so they are worth describing, but a
    /// profile carrying `PayloadType = DeviceLock` installs nothing and a
    /// composer that lists them offers payloads that can never be built.
    pub fn is_authorable(self) -> bool {
        !matches!(
            self,
            Self::MdmCommand | Self::MdmCheckin | Self::SharedStructure
        )
    }

    /// Why this kind cannot be authored, phrased for the operator who just
    /// asked for it — `None` when it can.
    ///
    /// One sentence, one place. The same refusal is issued by `form`,
    /// `validate`, `generate` and `info`, and when all four carried their own
    /// copy they said "protocol traffic a server sends" about a shared
    /// structure, which is a shape, not traffic.
    pub fn not_authorable_reason(self) -> Option<&'static str> {
        match self {
            Self::MdmCommand => Some(
                "an MDM command — protocol traffic a server sends to a device, not a \
                      document an operator authors",
            ),
            Self::MdmCheckin => Some(
                "an MDM check-in message — protocol traffic a device sends to a server, \
                      not a document an operator authors",
            ),
            Self::SharedStructure => Some(
                "a shared structure from Apple's `other/` — the shape of a key another \
                      document carries, or a protocol body, not a document of its own",
            ),
            _ => None,
        }
    }
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
    /// own `supportedOS`, not the payload's. A platform maps to `"n/a"`
    /// when the key is unsupported there (see [`PayloadKey::unavailable_on`]);
    /// a platform is absent when Apple stated nothing, and an entirely empty
    /// map means the parquet carried no per-key data for this key.
    pub introduced: std::collections::HashMap<Platform, String>,
    /// OS version when this key was deprecated, per platform.
    pub deprecated: std::collections::HashMap<Platform, String>,
    /// OS version when this key was removed, per platform — the key's own
    /// `supportedOS.<platform>.removed`. Apple: a removed key is silently
    /// ignored on that OS and later, so this is the fact behind
    /// `Verdict::Removed`. Empty on an older dataset without the
    /// `key_removed` column.
    pub removed: std::collections::HashMap<Platform, String>,
    /// Whether the key requires a supervised device, per platform.
    /// Populated from the key's own `supportedOS.<platform>.supervised`.
    pub supervised: std::collections::HashMap<Platform, bool>,
    /// The key's OWN `allowed-scopes`, per platform, when it declares any.
    ///
    /// Per-platform for the same reason `introduced` is: one `PayloadKey`
    /// merges the parquet's per-(platform, key) rows, so a single
    /// `Option<Vec<String>>` would keep whichever platform happened to be
    /// read first. `app.settings.Privacy` declares a scope on macOS only,
    /// and iOS arriving first would silently discard it.
    ///
    /// A platform absent from the map means the key inherits its payload's
    /// scope there — **not** that it is unrestricted. The dataset writes NULL
    /// rather than copying the payload value down precisely so a key that
    /// permits both stays distinguishable from one that was never asked.
    ///
    /// Eight keys declare one on the 27.0 release branch, and five
    /// contradict their payload — `app.settings.Privacy` is macOS
    /// user-only inside a payload that permits either.
    pub allowed_scopes: std::collections::HashMap<Platform, Vec<String>>,
    /// Windows only: the CSP this key is addressed under, which is NOT
    /// always its capability's `csp_name`. `Defender` and `CloudDesktop`
    /// each exist both as a standalone CSP and as a Policy area, so the
    /// capability-level name cannot describe both sets of keys.
    pub csp_name: Option<String>,
    /// Windows only: whether this key is addressable on the device channel.
    ///
    /// Per KEY, not per capability: `ADMX_AppCompat` holds 8 device-only
    /// keys and 1 user-only one, and a capability-level answer mislabels
    /// one group or the other. `None` means the key names no channel and is
    /// addressed without a `Device`/`User` segment.
    pub device_channel: Option<bool>,
    /// Windows only: whether this key is addressable on the user channel.
    /// See [`PayloadKey::device_channel`].
    pub user_channel: Option<bool>,
    /// Dot-path to parent key, `None` for top-level keys.
    ///
    /// Joined with `.`, which is lossy: a key name may itself contain dots.
    /// Apple publishes such keys — `com.apple.MCX(EnergySaver).yaml` declares
    /// `- key: com.apple.EnergySaver.desktop.ACPower` — so splitting this on
    /// `.` does not recover the segments. Prefer [`PayloadKey::key_path`].
    pub parent_key: Option<String>,
    /// The key's address with dots inside a segment escaped, so it parses back.
    ///
    /// `\` is escaped as `\\` and `.` as `\.` within each segment; splitting
    /// on unescaped dots therefore recovers exactly the segments that went in.
    /// `None` when the producing parquet predates the column, in which case
    /// `parent_key` + `name` is all there is.
    pub key_path: Option<String>,
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
        self.introduced
            .values()
            .filter(|v| !Self::is_unavailable_marker(v))
            .min()
            .cloned()
    }

    /// Apple's spelling for "this key does not exist on this platform".
    pub fn is_unavailable_marker(v: &str) -> bool {
        v == "n/a"
    }

    /// Platforms on which Apple states the key does **not** exist. Empty
    /// means Apple stated no exclusion — not that the key is everywhere;
    /// it inherits the payload's platforms.
    pub fn unavailable_on(&self) -> Vec<Platform> {
        let mut out: Vec<Platform> = self
            .introduced
            .iter()
            .filter(|(_, v)| Self::is_unavailable_marker(v))
            .map(|(p, _)| *p)
            .collect();
        out.sort_by_key(|p| format!("{p:?}"));
        out
    }

    /// The introduced version on a platform, `None` for an unavailable one.
    pub fn introduced_version(&self, platform: Platform) -> Option<&str> {
        self.introduced
            .get(&platform)
            .map(String::as_str)
            .filter(|v| !Self::is_unavailable_marker(v))
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
    /// Which of several documents under one `payload_type` this describes.
    ///
    /// A payload type is not always one payload. `com.apple.MCX` is the
    /// managed-preferences container and Apple describes six surfaces through
    /// it, putting the discriminator in the FILENAME —
    /// `com.apple.MCX(WiFi).yaml`, `(EnergySaver)`, `(Accounts)`. The dataset
    /// carries that through as a column; `None` means the payload type has one
    /// document, or the producing parquet predates the column.
    pub variant: Option<String>,
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
///
/// The reader is kept, but no ProfileCreator parquet is shipped with this
/// crate.
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadSchema {
    pub payload_type: String,
    /// Capability classification (e.g. `"MdmProfile"` / `"DdmDeclaration"`).
    /// Nullable: `None` when the column is absent or unset.
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
    /// Sourced from `pfm_sensitive`; `false` when the column is absent or
    /// null.
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

/// True for schema-editor artifacts that are not Apple payload keys.
///
/// `PFC_*` is ProfileCreator widget state (e.g. `PFC_SegmentedControl_0`) and
/// `pfm_*` is ProfileManifests metadata. Some scraped upstream manifests carry
/// them alongside real keys, occasionally marked `required`. They must never be
/// emitted into a generated profile nor reported as keys an operator can set.
///
/// Single definition on purpose: this was previously a private predicate in the
/// generate path only, which is why the read path leaked the keys.
pub fn is_editor_metadata_key(name: &str) -> bool {
    name.starts_with("PFC_") || name.starts_with("pfm_")
}

#[cfg(test)]
mod editor_metadata_tests {
    use super::is_editor_metadata_key;

    #[test]
    fn flags_profilecreator_and_manifest_artifacts() {
        assert!(is_editor_metadata_key("PFC_SegmentedControl_0"));
        assert!(is_editor_metadata_key("pfm_title"));
    }

    #[test]
    fn leaves_real_apple_keys_alone() {
        assert!(!is_editor_metadata_key("DisabledPreferencePanes"));
        assert!(!is_editor_metadata_key("allowAirDrop"));
        assert!(!is_editor_metadata_key("DisabledSystemSettings"));
    }
}

/// A key an App Schema document lists outside its settable properties.
///
/// `kind` says which list it came from and therefore what it means for a
/// profile: `runtime` and `dynamic` keys are written by the app or its
/// scripts and must never be managed; `removed` keys are no longer read;
/// `external` keys live in another domain; `deprecated` keys still work but
/// something replaced them.
#[derive(Debug, Clone, PartialEq)]
pub struct AppSchemaKey {
    /// Preference domain the document describes.
    pub domain: String,
    /// `runtime`, `dynamic`, `removed`, `external` or `deprecated`.
    pub kind: String,
    /// Key name, or the name template for a `dynamic` entry.
    pub key: String,
    /// plist type, when the document states one.
    pub plist_type: Option<String>,
    /// Value the app starts from, as JSON text.
    pub default_value: Option<String>,
    /// What the key does, or the effect an `external` key has.
    pub description: Option<String>,
    /// Key-name template, e.g. `{ExtensionID}_badge`.
    pub template: Option<String>,
    /// JSON object mapping each placeholder to the pointer it resolves from.
    pub placeholders: Option<String>,
    /// App version that removed or deprecated the key.
    pub removed_in: Option<String>,
    /// Domain of the replacement, or the owning domain of an `external` key.
    pub replacement_domain: Option<String>,
    /// Key that replaces this one.
    pub replacement_key: Option<String>,
}

impl AppSchemaKey {
    /// Whether setting this key in a profile is a mistake.
    ///
    /// A managed value for a runtime or script-written key is forced, so the
    /// app can never update it again; a removed key is simply not read.
    pub fn is_profile_mistake(&self) -> bool {
        matches!(self.kind.as_str(), "runtime" | "dynamic" | "removed")
    }
}

/// A rule an App Schema document states.
///
/// Predicates stay as JSON in the format's grammar so a consumer can
/// evaluate them without this crate modelling every operator.
#[derive(Debug, Clone, PartialEq)]
pub struct AppSchemaRule {
    /// Preference domain the rule belongs to.
    pub domain: String,
    /// Rule id, unique within the document.
    pub rule_id: String,
    /// `error`, `warning` or `info`.
    pub severity: String,
    /// Pointer the rule runs against; `/` when absent.
    pub scope: Option<String>,
    /// Predicate gating the rule, as JSON.
    pub when_predicate: Option<String>,
    /// Predicate that must hold, as JSON.
    pub assert_predicate: Option<String>,
    /// Informational consequence, as JSON.
    pub effect: Option<String>,
    /// One-sentence message shown on violation.
    pub message: String,
    /// Why the rule exists.
    pub detail: Option<String>,
    /// Where the rule came from.
    pub origin: String,
}

/// One row of `source_versions.parquet`: an upstream, the release label it
/// calls itself, and the commit it actually was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceVersion {
    /// `device-management`, `mscp`, `ProfileManifests`.
    pub source: String,
    pub os: String,
    pub platform: String,
    /// The upstream's own label — `Release-v27.0`, `2.0`.
    pub version: String,
    pub cpe: Option<String>,
    pub date: Option<String>,
    /// The commit read. `None` on datasets that predate the column.
    pub revision: Option<String>,
}

/// One row of `status_items.parquet`: a DDM **status** item — what a device
/// reports back, as opposed to what a declaration configures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusItem {
    pub status_item_type: String,
    pub title: String,
    pub description: String,
    pub platform: String,
    pub introduced: Option<String>,
    pub deprecated: Option<String>,
    pub allowed_enrollments: Option<Vec<String>>,
    pub allowed_scopes: Option<Vec<String>>,
    /// `string`, `integer`, `boolean`, `dictionary`, `array`.
    pub value_type: Option<String>,
    pub value_description: Option<String>,
    pub rangelist: Option<Vec<String>>,
}

/// One row of `mdm_errors.parquet`: an error code Apple documents, per platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdmErrorCode {
    pub error_code: String,
    pub title: String,
    pub description: String,
    pub platform: String,
    pub introduced: Option<String>,
}

#[cfg(test)]
mod kind_vocabulary {
    use super::PayloadKind;

    /// Every kind round-trips between `as_str` and `parse`.
    ///
    /// This is the one vocabulary; the reader delegates here. The match below
    /// is exhaustive, so adding a variant fails to compile until someone
    /// states its wire name. An unknown kind must never default to an
    /// authorable one: SharedStructure, MdmCommand and MdmCheckin exist to be
    /// refused.
    #[test]
    fn every_kind_round_trips() {
        fn wire(k: PayloadKind) -> &'static str {
            match k {
                PayloadKind::MdmProfile => "MdmProfile",
                PayloadKind::DdmDeclaration => "DdmDeclaration",
                PayloadKind::MdmCommand => "MdmCommand",
                PayloadKind::MdmCheckin => "MdmCheckin",
                PayloadKind::CspSetting => "CspSetting",
                PayloadKind::AdmxPolicy => "AdmxPolicy",
                PayloadKind::ManagedPreference => "ManagedPreference",
                PayloadKind::SharedStructure => "SharedStructure",
            }
        }
        for k in [
            PayloadKind::MdmProfile,
            PayloadKind::DdmDeclaration,
            PayloadKind::MdmCommand,
            PayloadKind::MdmCheckin,
            PayloadKind::CspSetting,
            PayloadKind::AdmxPolicy,
            PayloadKind::ManagedPreference,
            PayloadKind::SharedStructure,
        ] {
            let s = wire(k);
            assert_eq!(k.as_str(), s, "as_str disagrees for {s}");
            assert_eq!(PayloadKind::parse(s), Some(k), "{s} does not parse back");
        }
    }

    /// The reader's fallback for an unrecognised kind must be refusable.
    #[test]
    fn the_unknown_kind_fallback_is_not_authorable() {
        assert_eq!(PayloadKind::parse("SomethingAppleAddedLater"), None);
        assert!(
            PayloadKind::SharedStructure
                .not_authorable_reason()
                .is_some(),
            "capabilities.rs falls back to this kind; it must be one that is refused"
        );
    }
}
