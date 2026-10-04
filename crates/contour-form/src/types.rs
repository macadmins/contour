use std::collections::HashMap;

/// A named group of related fields (parsed from pfm_segments)
#[derive(Debug, Clone)]
pub struct Segment {
    pub name: String,
    pub field_names: Vec<String>,
}

/// Represents a payload manifest (schema) for a profile payload type
#[derive(Debug, Clone)]
pub struct PayloadManifest {
    /// Which upstream described this payload: `device-management` (Apple),
    /// `profile-manifests` (the ProfileCreator community manifests),
    /// `app-schema:*` (a vendor's own document), `posture-supplemental`
    /// (stated by the dataset itself, with a citation), or `both`.
    ///
    /// Carried because the trust ranks differ and a caller cannot tell them
    /// apart from the keys alone. The ProfileCreator community corpus is not
    /// loaded at all any more — see
    /// [`REMOVED_COMMUNITY_DOMAINS`](crate::REMOVED_COMMUNITY_DOMAINS).
    /// `None` for manifests built from a local directory, which state no
    /// provenance.
    pub manifest_source: Option<String>,
    /// The payload type identifier (e.g., "com.apple.wifi.managed")
    pub payload_type: String,
    /// What this schema describes: a profile payload, a DDM declaration, an
    /// MDM command, a check-in message, a Windows CSP node… `None` when the
    /// source did not say (external YAML/plist schemas, hand-built manifests)
    /// — never a guessed default, because "unspecified" and "profile" differ
    /// and a command mistaken for a profile is exactly the failure this
    /// field exists to prevent.
    pub kind: Option<mdm_schema::PayloadKind>,
    /// Human-readable title (e.g., "WiFi")
    pub title: String,
    /// Description of what this payload configures
    pub description: String,
    /// Supported platforms
    pub platforms: Platforms,
    /// Minimum OS versions per platform
    pub min_versions: HashMap<Platform, String>,
    /// Per-OS support detail — rich metadata Apple's YAML carries for
    /// each platform: introduced/deprecated/removed versions, allowed
    /// enrollment types, supervision/DEP requirements, channel modes,
    /// `multiple` flag, etc. Used by agents picking the right keys for
    /// "supervised iPad", "user-enrollment iOS", or filtering output
    /// to a target OS. May be empty for payloads that don't carry the
    /// metadata (older schemas, custom prefs).
    pub os_support: HashMap<Platform, OsSupportDetail>,
    /// Apple/DDM `apply` mode — `"single"`, `"multiple"`, or
    /// `"combined"`. `None` when the source schema doesn't declare one
    /// (older parquet, prefs, etc.). Drives the
    /// `single-instance-payload-repeated` lint check.
    pub apply_mode: Option<String>,
    /// Category: "apple", "apps", "prefs"
    pub category: String,
    /// Field paths whose source records OS availability.
    ///
    /// Not a per-payload flag, because a payload need not be from one
    /// source. Apple's device-management schema states
    /// `introduced`/`deprecated`; app-schema and supplemental sources state
    /// nothing. Derived from `manifest_source` per field path so a merge
    /// keeps the distinction.
    ///
    /// Both kinds arrive as the same nulls. Apple's silence means the key
    /// inherits the payload's availability, so `Ok` is truthful there; a
    /// source that records nothing means nobody checked, and `Ok` would
    /// assert a check that never happened.
    ///
    /// Empty for a manifest with no such source; every field path for a
    /// manifest wholly from Apple's schema (`com.apple.wifi.managed` is one).
    pub fields_recording_availability: std::collections::BTreeSet<String>,
    /// Field definitions keyed by dotted path (`FieldDefinition::path`)
    pub fields: HashMap<String, FieldDefinition>,
    /// Field paths in declaration order
    pub field_order: Vec<String>,
    /// Segments grouping field names by category (from pfm_segments)
    pub segments: Vec<Segment>,
}

/// Per-platform support detail for a payload — exposes the rich Apple
/// metadata that the structural validator and the lint pass don't see.
///
/// Agents use this to answer questions like: "is this payload available
/// on the user channel?" or "does it require DEP enrollment on iOS?"
/// Picking the wrong combination produces a profile that silently fails
/// to install.
#[derive(Debug, Clone, Default)]
pub struct OsSupportDetail {
    /// OS version when the payload became available on this platform.
    pub introduced: Option<String>,
    /// OS version when the payload was deprecated (still works, but
    /// flagged by Apple).
    pub deprecated: Option<String>,
    /// OS version when the payload was removed (no longer works).
    pub removed: Option<String>,
    /// Allowed enrollment types (DDM): e.g. ["supervised", "device", "user"].
    pub allowed_enrollments: Option<Vec<String>>,
    /// Allowed scopes (DDM): e.g. ["system", "user"].
    pub allowed_scopes: Option<Vec<String>>,
    /// Whether supervision is required.
    pub supervised: Option<bool>,
    /// Whether DEP (Automated Device Enrollment) is required.
    pub requires_dep: Option<bool>,
    /// Whether user-approved MDM is required.
    pub user_approved_mdm: Option<bool>,
    /// Whether manual install (drag-and-drop / user double-click) is allowed.
    pub allow_manual_install: Option<bool>,
    /// Whether the payload is delivered on the device channel.
    pub device_channel: Option<bool>,
    /// Whether the payload is delivered on the user channel.
    pub user_channel: Option<bool>,
    /// Whether multiple instances of the same payload type are allowed.
    pub multiple: Option<bool>,
    /// Whether the payload is currently in beta.
    pub beta: Option<bool>,
    /// Shared iPad mode (DDM constraint) — string from Apple's schema,
    /// typically "allowed" / "required" / "forbidden". `None` means no
    /// constraint declared.
    pub shared_ipad_mode: Option<String>,
    /// User-enrollment mode (DDM constraint) — same shape as
    /// `shared_ipad_mode`.
    pub user_enrollment_mode: Option<String>,
}

/// Platform support flags
#[derive(Debug, Clone, Default)]
pub struct Platforms {
    pub macos: bool,
    pub ios: bool,
    pub tvos: bool,
    pub watchos: bool,
    pub visionos: bool,
    pub windows: bool,
}

/// Platform identifier
///
/// Serialises as Apple's spelling (`macOS`, `iOS`, …) so it can key a JSON
/// map; orders as Apple lists them, macOS first.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Platform {
    #[serde(rename = "macOS")]
    MacOS,
    #[serde(rename = "iOS")]
    Ios,
    #[serde(rename = "tvOS")]
    TvOS,
    #[serde(rename = "watchOS")]
    WatchOS,
    #[serde(rename = "visionOS")]
    VisionOS,
    /// Windows (the CSP dataset behind `--windows` only).
    #[serde(rename = "Windows")]
    Windows,
}

impl Platform {
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'm' => Some(Platform::MacOS),
            'i' => Some(Platform::Ios),
            't' => Some(Platform::TvOS),
            'w' => Some(Platform::WatchOS),
            'v' => Some(Platform::VisionOS),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::MacOS => "macOS",
            Platform::Ios => "iOS",
            Platform::TvOS => "tvOS",
            Platform::WatchOS => "watchOS",
            Platform::VisionOS => "visionOS",
            Platform::Windows => "Windows",
        }
    }

    /// Parse a CLI-friendly OS name (case-insensitive — `macos`, `Macos`,
    /// `macOS`, `MAC` all map to `Platform::MacOS`). Unknown names → None.
    pub fn from_cli_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "macos" | "mac" | "osx" => Some(Platform::MacOS),
            "ios" | "iphone" | "ipad" | "ipados" => Some(Platform::Ios),
            "tvos" | "tv" => Some(Platform::TvOS),
            "watchos" | "watch" => Some(Platform::WatchOS),
            "visionos" | "vision" => Some(Platform::VisionOS),
            "windows" | "win" => Some(Platform::Windows),
            _ => None,
        }
    }
}

/// Field definition within a payload
#[derive(Debug, Clone)]
pub struct FieldDefinition {
    /// Field name (key)
    pub name: String,
    /// The field's full dotted path — its identity.
    ///
    /// A leaf name is not unique within a payload:
    /// `com.apple.configuration.account.mail` carries `Port` under both
    /// `IncomingServer` and `OutgoingServer`, and 61 DDM keys across 14
    /// declaration types collide that way. Look fields up by this, not by
    /// [`FieldDefinition::name`].
    ///
    /// Sourced from the schema's own `key_path` where the dataset provides it
    /// (dots inside a segment escaped, so it survives a key name containing
    /// dots), otherwise composed from `parent_key` and `name`.
    pub path: String,
    /// Field type
    pub field_type: FieldType,
    /// Field flags (required, supervised, sensitive)
    pub flags: FieldFlags,
    /// Human-readable title
    pub title: String,
    /// Description of the field
    pub description: String,
    /// Default value (as string representation)
    pub default: Option<String>,
    /// Allowed values for enum-like fields
    pub allowed_values: Vec<String>,
    /// The key's OWN `allowed-scopes`, per platform, when it declares any.
    ///
    /// A platform absent means the key inherits the payload's scope there —
    /// not that it is unrestricted. Eight keys declare one on the 27.0
    /// release branch and five contradict their payload.
    pub allowed_scopes: std::collections::HashMap<Platform, Vec<String>>,
    /// Nesting depth (0=top-level, 1=first nested, etc.)
    pub depth: u8,
    /// Dotted path of the parent for nested fields (e.g. "Allowed.AllowedApps"
    /// for its "AppIdentifier" child); what `children_of` matches on.
    pub parent_key: Option<String>,
    /// Platform-specific (empty = all platforms)
    pub platforms: Vec<Platform>,
    /// Minimum version requirement (earliest `introduced` across platforms).
    /// Single-value summary derived from `introduced_by_platform` —
    /// kept for callers that don't care which OS.
    pub min_version: Option<String>,
    /// OS version when this key was deprecated by Apple. Field still
    /// works for now but is flagged in Apple's schema as scheduled for
    /// removal. Authoring tools should warn.
    ///
    /// Single-value summary; per-OS detail in `deprecated_by_platform`.
    pub deprecated_in: Option<String>,
    /// Per-OS `introduced` version — empty for keys without per-OS data
    /// (legacy parquet rows or non-embedded schema sources). Lets agents
    /// answer "when did this key land on iOS vs macOS?" without
    /// collapsing to a single value.
    pub introduced_by_platform: HashMap<Platform, String>,
    /// Per-OS `deprecated` version. Same shape as `introduced_by_platform`.
    pub deprecated_by_platform: HashMap<Platform, String>,
    /// Per-OS `removed` version — the key's own. A key is silently ignored
    /// on that OS and later, so this drives `Verdict::Removed`, which wins
    /// over `Deprecated`: a key both deprecated at 14.0 and removed at 15.0,
    /// targeted at 15.0, is removed. Empty where the source states none.
    pub removed_by_platform: HashMap<Platform, String>,
    /// Lower bound for numeric fields, where Apple states one (561 rows).
    /// `None` means the schema is silent, not that the field is unbounded.
    pub range_min: Option<f64>,
    /// Upper bound for numeric fields (466 rows). See [`range_min`].
    pub range_max: Option<f64>,
    /// Value shape hint — `url`, `hostname`, `email` (498 rows). A renderer
    /// uses it to pick a validator; emitting it is the difference between a
    /// text box and one that rejects a non-URL.
    pub subtype: Option<String>,
    /// Regex the value must match, where Apple states one (396 rows).
    pub format: Option<String>,
    /// MIME types an asset reference accepts (310 rows). Non-empty marks the
    /// field as an asset picker rather than free text.
    pub asset_types: Vec<String>,
    /// DDM merge strategy when multiple declarations carry this key —
    /// e.g. `boolean-or`, `number-min`, `set-union`. Only meaningful for
    /// declaration types; `None` for plain MDM profile keys.
    pub combinetype: Option<String>,
}

/// Field type enumeration
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum FieldType {
    String,
    Integer,
    Boolean,
    Array,
    Dictionary,
    Data,
    Date,
    Real,
}

impl FieldType {
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            's' => Some(FieldType::String),
            'i' => Some(FieldType::Integer),
            'b' => Some(FieldType::Boolean),
            'a' => Some(FieldType::Array),
            'd' => Some(FieldType::Dictionary),
            'x' => Some(FieldType::Data),
            't' => Some(FieldType::Date),
            'r' => Some(FieldType::Real),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FieldType::String => "String",
            FieldType::Integer => "Integer",
            FieldType::Boolean => "Boolean",
            FieldType::Array => "Array",
            FieldType::Dictionary => "Dictionary",
            FieldType::Data => "Data",
            FieldType::Date => "Date",
            FieldType::Real => "Real",
        }
    }
}

/// Field flags
#[derive(Debug, Clone, Default)]
pub struct FieldFlags {
    /// Required field (R flag)
    pub required: bool,
    /// Supervised-only field (S flag) - iOS supervised devices only
    pub supervised: bool,
    /// Sensitive field (X flag) - contains password/credential
    pub sensitive: bool,
}

impl FieldFlags {
    pub fn parse(s: &str) -> Self {
        Self {
            required: s.contains('R'),
            supervised: s.contains('S'),
            sensitive: s.contains('X'),
        }
    }
}

impl Platforms {
    /// Parse platform string like "m,i,t" or "*" or "-"
    pub fn parse(s: &str) -> Self {
        if s == "*" {
            return Self {
                macos: true,
                ios: true,
                tvos: true,
                watchos: true,
                visionos: true,
                // "*" means every Apple platform — never Windows.
                windows: false,
            };
        }
        if s == "-" {
            return Self::default();
        }

        let mut platforms = Self::default();
        for part in s.split(',') {
            match part.trim() {
                "m" => platforms.macos = true,
                "i" => platforms.ios = true,
                "t" => platforms.tvos = true,
                "w" => platforms.watchos = true,
                "v" => platforms.visionos = true,
                _ => {}
            }
        }
        platforms
    }

    /// Get list of supported platform names
    pub fn to_vec(&self) -> Vec<&'static str> {
        let mut result = Vec::new();
        if self.macos {
            result.push("macOS");
        }
        if self.ios {
            result.push("iOS");
        }
        if self.tvos {
            result.push("tvOS");
        }
        if self.watchos {
            result.push("watchOS");
        }
        if self.visionos {
            result.push("visionOS");
        }
        if self.windows {
            result.push("Windows");
        }
        result
    }
}

impl FieldDefinition {
    /// Compose a field's identity from its parent path and leaf name.
    ///
    /// `parent_key` already holds the full ancestor path in the escaped
    /// spelling, so this appends `name` as ONE segment — a dot inside it is
    /// escaped, because Apple ships key names containing dots. The schema's
    /// own `key_path` is still preferred where the dataset carries it.
    pub fn compose_path(parent: Option<&str>, name: &str) -> String {
        let parent = parent.filter(|p| !p.is_empty()).map_or_else(
            crate::path::FieldPath::default,
            crate::path::FieldPath::parse,
        );
        parent.join(name).to_string()
    }
}

impl FieldDefinition {
    /// Both schema sources have a spelling for "the operator supplies this
    /// key name": Apple's DDM and profile YAML write `ANY`; ProfileCreator
    /// writes a `{{key}}` / `{{value}}` pair. Emitted literally either one
    /// produces `<key>{{value}}</key>` in a shipped document.
    pub fn is_placeholder_name(name: &str) -> bool {
        matches!(name, "ANY" | "{{key}}" | "{{value}}")
    }

    /// Whether this field *is* one of those placeholders rather than a key.
    pub fn is_placeholder(&self) -> bool {
        Self::is_placeholder_name(&self.name)
    }
}

impl PayloadManifest {
    /// If `field`'s keys are operator-supplied, the field that describes
    /// each value: Apple's `ANY` child, or ProfileCreator's `{{value}}`
    /// (`{{key}}` is always a string and carries nothing else).
    ///
    /// `None` for an ordinary dictionary. Consumers building a form use
    /// this to render "add entry" instead of a fixed key list; emitters use
    /// it to leave the dictionary empty instead of printing the marker.
    pub fn dynamic_value_shape(&self, field: &FieldDefinition) -> Option<&FieldDefinition> {
        let mut any = None;
        let mut value = None;
        for child in self
            .fields
            .values()
            .filter(|c| c.parent_key.as_deref() == Some(field.path.as_str()))
        {
            match child.name.as_str() {
                "ANY" => any = Some(child),
                "{{value}}" => value = Some(child),
                _ => {}
            }
        }
        any.or(value)
    }

    /// The value shape when the *payload itself* is keyed by the operator —
    /// a root-level `ANY`, as in `com.apple.firstethernet.managed`.
    pub fn root_dynamic_value_shape(&self) -> Option<&FieldDefinition> {
        let mut any = None;
        let mut value = None;
        for f in self.fields.values().filter(|f| f.parent_key.is_none()) {
            match f.name.as_str() {
                "ANY" => any = Some(f),
                "{{value}}" => value = Some(f),
                _ => {}
            }
        }
        any.or(value)
    }

    /// Names of the fields directly under `parent`, in declaration order.
    pub fn child_names(&self, parent: &FieldDefinition) -> Vec<&str> {
        self.fields_in_order()
            .filter(|c| c.parent_key.as_deref() == Some(parent.path.as_str()))
            .map(|c| c.name.as_str())
            .collect()
    }

    /// `false` only for kinds that cannot be deployed as a document — MDM
    /// commands, check-in messages and Apple's shared structures. Unknown
    /// kind is authorable: refusing on missing metadata would block every
    /// external schema.
    pub fn is_authorable(&self) -> bool {
        self.kind.is_none_or(mdm_schema::PayloadKind::is_authorable)
    }

    /// Get fields that are required (have R flag)
    pub fn required_fields(&self) -> Vec<&FieldDefinition> {
        self.fields.values().filter(|f| f.flags.required).collect()
    }

    /// Get fields that are sensitive (have X flag)
    pub fn sensitive_fields(&self) -> Vec<&FieldDefinition> {
        self.fields.values().filter(|f| f.flags.sensitive).collect()
    }

    /// Get top-level fields only (depth = 0)
    pub fn top_level_fields(&self) -> Vec<&FieldDefinition> {
        self.field_order
            .iter()
            .filter_map(|name| self.fields.get(name))
            .filter(|f| f.depth == 0)
            .collect()
    }

    /// Direct children of a field, identified by the field's **full dotted
    /// path** (`parent_key` stores the path to the parent, e.g. a child of
    /// `Allowed.AllowedApps` carries `parent_key = "Allowed.AllowedApps"`).
    /// Returned in declaration order.
    pub fn children_of(&self, parent_path: &str) -> Vec<&FieldDefinition> {
        self.field_order
            .iter()
            .filter_map(|name| self.fields.get(name))
            .filter(|f| f.parent_key.as_deref() == Some(parent_path))
            .collect()
    }

    /// Look a field up by its **path** — the identity.
    ///
    /// Correct whether `fields` is keyed by path or still by leaf name: the
    /// direct hit answers once the map is re-keyed, and the scan answers
    /// meanwhile. That is what lets call sites migrate ahead of the re-key
    /// instead of in the same change.
    pub fn field_by_path(&self, path: &str) -> Option<&FieldDefinition> {
        self.fields
            .get(path)
            .or_else(|| self.fields.values().find(|f| f.path == path))
    }

    /// Look a field up by bare leaf name. **Ambiguous by construction.**
    ///
    /// Where a payload has same-named children under different parents this
    /// returns whichever the map holds, which is why 61 keys were lost. Use
    /// [`PayloadManifest::field_by_path`] wherever the caller knows the path;
    /// this exists for callers holding a name from a document they are
    /// validating, where the name is all there is.
    pub fn field_by_name(&self, name: &str) -> Option<&FieldDefinition> {
        self.fields
            .get(name)
            .or_else(|| self.fields.values().find(|f| f.name == name))
    }

    /// Every field in declaration order.
    ///
    /// Walks `field_order` and resolves each entry, skipping any that does not
    /// resolve — `field_order` and `fields` can disagree, and a name appearing
    /// twice in the order must not emit the same field twice.
    pub fn fields_in_order(&self) -> impl Iterator<Item = &FieldDefinition> {
        let mut seen = std::collections::HashSet::new();
        self.field_order.iter().filter_map(move |k| {
            let f = self.fields.get(k)?;
            seen.insert(f.path.clone()).then_some(f)
        })
    }
}

#[cfg(test)]
mod tests {

    /// A key name containing dots is one segment of the path, not several.
    #[test]
    fn compose_path_escapes_a_dotted_name() {
        assert_eq!(FieldDefinition::compose_path(None, "Plain"), "Plain");
        assert_eq!(
            FieldDefinition::compose_path(Some("Privacy.PermissionDefaults"), "us.zoom.xos"),
            r"Privacy.PermissionDefaults.us\.zoom\.xos"
        );
        assert_eq!(
            FieldDefinition::compose_path(Some(r"com\.apple\.EnergySaver"), "Schedule"),
            r"com\.apple\.EnergySaver.Schedule"
        );
    }

    use super::*;

    // ========== FieldType Tests ==========

    #[test]
    fn test_field_type_from_char() {
        assert_eq!(FieldType::from_char('s'), Some(FieldType::String));
        assert_eq!(FieldType::from_char('i'), Some(FieldType::Integer));
        assert_eq!(FieldType::from_char('b'), Some(FieldType::Boolean));
        assert_eq!(FieldType::from_char('a'), Some(FieldType::Array));
        assert_eq!(FieldType::from_char('d'), Some(FieldType::Dictionary));
        assert_eq!(FieldType::from_char('x'), Some(FieldType::Data));
        assert_eq!(FieldType::from_char('z'), None);
    }

    #[test]
    fn test_field_type_from_char_date_and_real() {
        assert_eq!(FieldType::from_char('t'), Some(FieldType::Date));
        assert_eq!(FieldType::from_char('r'), Some(FieldType::Real));
    }

    #[test]
    fn test_field_type_from_char_invalid() {
        assert_eq!(FieldType::from_char('1'), None);
        assert_eq!(FieldType::from_char(' '), None);
        assert_eq!(FieldType::from_char('\n'), None);
        assert_eq!(FieldType::from_char('S'), None); // Case sensitive
    }

    #[test]
    fn test_field_type_as_str() {
        assert_eq!(FieldType::String.as_str(), "String");
        assert_eq!(FieldType::Integer.as_str(), "Integer");
        assert_eq!(FieldType::Boolean.as_str(), "Boolean");
        assert_eq!(FieldType::Array.as_str(), "Array");
        assert_eq!(FieldType::Dictionary.as_str(), "Dictionary");
        assert_eq!(FieldType::Data.as_str(), "Data");
        assert_eq!(FieldType::Date.as_str(), "Date");
        assert_eq!(FieldType::Real.as_str(), "Real");
    }

    // ========== FieldFlags Tests ==========

    #[test]
    fn test_field_flags_from_str() {
        let flags = FieldFlags::parse("R");
        assert!(flags.required);
        assert!(!flags.supervised);
        assert!(!flags.sensitive);

        let flags = FieldFlags::parse("RX");
        assert!(flags.required);
        assert!(flags.sensitive);

        let flags = FieldFlags::parse("-");
        assert!(!flags.required);
    }

    #[test]
    fn test_field_flags_supervised_only() {
        let flags = FieldFlags::parse("S");
        assert!(!flags.required);
        assert!(flags.supervised);
        assert!(!flags.sensitive);
    }

    #[test]
    fn test_field_flags_all_set() {
        let flags = FieldFlags::parse("RSX");
        assert!(flags.required);
        assert!(flags.supervised);
        assert!(flags.sensitive);
    }

    #[test]
    fn test_field_flags_empty_string() {
        let flags = FieldFlags::parse("");
        assert!(!flags.required);
        assert!(!flags.supervised);
        assert!(!flags.sensitive);
    }

    #[test]
    fn test_field_flags_default() {
        let flags = FieldFlags::default();
        assert!(!flags.required);
        assert!(!flags.supervised);
        assert!(!flags.sensitive);
    }

    // ========== Platform Tests ==========

    #[test]
    fn test_platform_from_char() {
        assert_eq!(Platform::from_char('m'), Some(Platform::MacOS));
        assert_eq!(Platform::from_char('i'), Some(Platform::Ios));
        assert_eq!(Platform::from_char('t'), Some(Platform::TvOS));
        assert_eq!(Platform::from_char('w'), Some(Platform::WatchOS));
        assert_eq!(Platform::from_char('v'), Some(Platform::VisionOS));
    }

    #[test]
    fn test_platform_from_char_invalid() {
        assert_eq!(Platform::from_char('x'), None);
        assert_eq!(Platform::from_char('M'), None); // Case sensitive
        assert_eq!(Platform::from_char(' '), None);
    }

    #[test]
    fn test_platform_as_str() {
        assert_eq!(Platform::MacOS.as_str(), "macOS");
        assert_eq!(Platform::Ios.as_str(), "iOS");
        assert_eq!(Platform::TvOS.as_str(), "tvOS");
        assert_eq!(Platform::WatchOS.as_str(), "watchOS");
        assert_eq!(Platform::VisionOS.as_str(), "visionOS");
    }

    // ========== Platforms Tests ==========

    #[test]
    fn test_platforms_from_str() {
        let p = Platforms::parse("m,i");
        assert!(p.macos);
        assert!(p.ios);
        assert!(!p.tvos);

        let p = Platforms::parse("*");
        assert!(p.macos);
        assert!(p.ios);
        assert!(p.tvos);
        assert!(p.watchos);
        assert!(p.visionos);
    }

    #[test]
    fn test_platforms_from_str_dash() {
        let p = Platforms::parse("-");
        assert!(!p.macos);
        assert!(!p.ios);
        assert!(!p.tvos);
        assert!(!p.watchos);
        assert!(!p.visionos);
    }

    #[test]
    fn test_platforms_from_str_all_individual() {
        let p = Platforms::parse("m,i,t,w,v");
        assert!(p.macos);
        assert!(p.ios);
        assert!(p.tvos);
        assert!(p.watchos);
        assert!(p.visionos);
    }

    #[test]
    fn test_platforms_from_str_with_spaces() {
        let p = Platforms::parse("m, i, t");
        assert!(p.macos);
        assert!(p.ios);
        assert!(p.tvos);
    }

    #[test]
    fn test_platforms_from_str_unknown_platform() {
        let p = Platforms::parse("m,x,i");
        assert!(p.macos);
        assert!(p.ios);
        // Unknown 'x' is silently ignored
    }

    #[test]
    fn test_platforms_to_vec() {
        let p = Platforms::parse("m,i");
        let vec = p.to_vec();
        assert!(vec.contains(&"macOS"));
        assert!(vec.contains(&"iOS"));
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn test_platforms_to_vec_all() {
        let p = Platforms::parse("*");
        let vec = p.to_vec();
        assert_eq!(vec.len(), 5);
        assert!(vec.contains(&"macOS"));
        assert!(vec.contains(&"iOS"));
        assert!(vec.contains(&"tvOS"));
        assert!(vec.contains(&"watchOS"));
        assert!(vec.contains(&"visionOS"));
    }

    #[test]
    fn test_platforms_to_vec_empty() {
        let p = Platforms::parse("-");
        let vec = p.to_vec();
        assert!(vec.is_empty());
    }

    #[test]
    fn test_platforms_default() {
        let p = Platforms::default();
        assert!(!p.macos);
        assert!(!p.ios);
        assert!(!p.tvos);
        assert!(!p.watchos);
        assert!(!p.visionos);
    }

    // ========== PayloadManifest Tests ==========

    #[test]
    fn children_of_and_field_path_resolve_nested_hierarchy() {
        // parent_key holds the dotted PATH to the parent, so children must be
        // matched by path (not bare name): Allowed > AllowedApps > AppIdentifier.
        fn fld(name: &str, depth: u8, parent: Option<&str>) -> FieldDefinition {
            FieldDefinition {
                allowed_scopes: std::collections::HashMap::new(),
                name: name.to_string(),
                range_min: None,
                range_max: None,
                subtype: None,
                format: None,
                asset_types: Vec::new(),
                path: name.to_string(),
                field_type: FieldType::Dictionary,
                flags: FieldFlags {
                    required: false,
                    supervised: false,
                    sensitive: false,
                },
                title: String::new(),
                description: String::new(),
                default: None,
                allowed_values: vec![],
                depth,
                parent_key: parent.map(str::to_string),
                platforms: vec![],
                min_version: None,
                deprecated_in: None,
                introduced_by_platform: HashMap::new(),
                deprecated_by_platform: HashMap::new(),
                removed_by_platform: HashMap::new(),
                combinetype: None,
            }
        }
        let mut fields = HashMap::new();
        fields.insert("Allowed".to_string(), fld("Allowed", 0, None));
        fields.insert(
            "AllowedApps".to_string(),
            fld("AllowedApps", 1, Some("Allowed")),
        );
        fields.insert(
            "AppIdentifier".to_string(),
            fld("AppIdentifier", 2, Some("Allowed.AllowedApps")),
        );
        let m = PayloadManifest {
            manifest_source: None,
            payload_type: "x".to_string(),
            kind: None,
            title: "x".to_string(),
            description: String::new(),
            platforms: Platforms::parse("*"),
            min_versions: HashMap::new(),
            os_support: HashMap::new(),
            apply_mode: None,
            category: "ddm-configuration".to_string(),
            fields_recording_availability: Default::default(),
            fields,
            field_order: vec![
                "Allowed".to_string(),
                "AllowedApps".to_string(),
                "AppIdentifier".to_string(),
            ],
            segments: vec![],
        };
        assert_eq!(m.top_level_fields().len(), 1);
        // Path-based: the grandchild resolves under the full parent path …
        let kids = m.children_of("Allowed.AllowedApps");
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].name, "AppIdentifier");
        // … and NOT under the bare parent name.
        assert!(m.children_of("AllowedApps").is_empty());
    }

    fn create_test_manifest() -> PayloadManifest {
        let mut fields = HashMap::new();
        let mut field_order = Vec::new();

        // Required field
        field_order.push("SSID_STR".to_string());
        fields.insert(
            "SSID_STR".to_string(),
            FieldDefinition {
                allowed_scopes: std::collections::HashMap::new(),
                name: "SSID_STR".to_string(),
                range_min: None,
                range_max: None,
                subtype: None,
                format: None,
                asset_types: Vec::new(),
                path: "SSID_STR".to_string(),
                field_type: FieldType::String,
                flags: FieldFlags {
                    required: true,
                    supervised: false,
                    sensitive: false,
                },
                title: "Network Name".to_string(),
                description: "The SSID of the network".to_string(),
                default: None,
                allowed_values: vec![],
                depth: 0,
                parent_key: None,
                platforms: vec![],
                min_version: None,
                deprecated_in: None,
                introduced_by_platform: std::collections::HashMap::new(),
                deprecated_by_platform: std::collections::HashMap::new(),
                removed_by_platform: std::collections::HashMap::new(),
                combinetype: None,
            },
        );

        // Sensitive field
        field_order.push("Password".to_string());
        fields.insert(
            "Password".to_string(),
            FieldDefinition {
                allowed_scopes: std::collections::HashMap::new(),
                name: "Password".to_string(),
                range_min: None,
                range_max: None,
                subtype: None,
                format: None,
                asset_types: Vec::new(),
                path: "Password".to_string(),
                field_type: FieldType::String,
                flags: FieldFlags {
                    required: false,
                    supervised: false,
                    sensitive: true,
                },
                title: "Password".to_string(),
                description: "Network password".to_string(),
                default: None,
                allowed_values: vec![],
                depth: 0,
                parent_key: None,
                platforms: vec![],
                min_version: None,
                deprecated_in: None,
                introduced_by_platform: std::collections::HashMap::new(),
                deprecated_by_platform: std::collections::HashMap::new(),
                removed_by_platform: std::collections::HashMap::new(),
                combinetype: None,
            },
        );

        // Nested field (depth 1)
        field_order.push("EAPConfig".to_string());
        fields.insert(
            "EAPConfig".to_string(),
            FieldDefinition {
                allowed_scopes: std::collections::HashMap::new(),
                name: "EAPConfig".to_string(),
                range_min: None,
                range_max: None,
                subtype: None,
                format: None,
                asset_types: Vec::new(),
                path: "EAPConfig".to_string(),
                field_type: FieldType::Dictionary,
                flags: FieldFlags::default(),
                title: "EAP Configuration".to_string(),
                description: "EAP settings".to_string(),
                default: None,
                allowed_values: vec![],
                depth: 1,
                parent_key: None,
                platforms: vec![],
                min_version: None,
                deprecated_in: None,
                introduced_by_platform: std::collections::HashMap::new(),
                deprecated_by_platform: std::collections::HashMap::new(),
                removed_by_platform: std::collections::HashMap::new(),
                combinetype: None,
            },
        );

        PayloadManifest {
            manifest_source: None,
            payload_type: "com.apple.wifi.managed".to_string(),
            kind: None,
            title: "WiFi".to_string(),
            description: "Configure WiFi networks".to_string(),
            platforms: Platforms::parse("m,i,t"),
            min_versions: HashMap::new(),
            os_support: HashMap::new(),
            apply_mode: None,
            category: "apple".to_string(),
            fields_recording_availability: Default::default(),
            fields,
            field_order,
            segments: vec![],
        }
    }

    #[test]
    fn test_payload_manifest_required_fields() {
        let manifest = create_test_manifest();
        let required = manifest.required_fields();

        assert_eq!(required.len(), 1);
        assert_eq!(required[0].name, "SSID_STR");
    }

    #[test]
    fn test_payload_manifest_sensitive_fields() {
        let manifest = create_test_manifest();
        let sensitive = manifest.sensitive_fields();

        assert_eq!(sensitive.len(), 1);
        assert_eq!(sensitive[0].name, "Password");
    }

    #[test]
    fn test_payload_manifest_top_level_fields() {
        let manifest = create_test_manifest();
        let top_level = manifest.top_level_fields();

        // depth 0 fields: SSID_STR and Password
        assert_eq!(top_level.len(), 2);
        assert!(top_level.iter().any(|f| f.name == "SSID_STR"));
        assert!(top_level.iter().any(|f| f.name == "Password"));
        // EAPConfig has depth 1, so it's not top-level
        assert!(!top_level.iter().any(|f| f.name == "EAPConfig"));
    }

    #[test]
    fn test_payload_manifest_no_required_fields() {
        let mut manifest = create_test_manifest();
        for field in manifest.fields.values_mut() {
            field.flags.required = false;
        }
        assert!(manifest.required_fields().is_empty());
    }

    #[test]
    fn test_payload_manifest_no_sensitive_fields() {
        let mut manifest = create_test_manifest();
        for field in manifest.fields.values_mut() {
            field.flags.sensitive = false;
        }
        assert!(manifest.sensitive_fields().is_empty());
    }
}
