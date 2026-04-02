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
    /// The payload type identifier (e.g., "com.apple.wifi.managed")
    pub payload_type: String,
    /// Human-readable title (e.g., "WiFi")
    pub title: String,
    /// Description of what this payload configures
    pub description: String,
    /// Supported platforms
    pub platforms: Platforms,
    /// Minimum OS versions per platform
    pub min_versions: HashMap<Platform, String>,
    /// Category: "apple", "apps", "prefs"
    pub category: String,
    /// Field definitions keyed by field name
    pub fields: HashMap<String, FieldDefinition>,
    /// Ordered list of field names (preserves original order)
    pub field_order: Vec<String>,
    /// Segments grouping field names by category (from pfm_segments)
    pub segments: Vec<Segment>,
}

/// Platform support flags
#[derive(Debug, Clone, Default)]
pub struct Platforms {
    pub macos: bool,
    pub ios: bool,
    pub tvos: bool,
    pub watchos: bool,
    pub visionos: bool,
}

/// Platform identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Platform {
    MacOS,
    Ios,
    TvOS,
    WatchOS,
    VisionOS,
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
        }
    }
}

/// Field definition within a payload
#[derive(Debug, Clone)]
pub struct FieldDefinition {
    /// Field name (key)
    pub name: String,
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
    /// Nesting depth (0=top-level, 1=first nested, etc.)
    pub depth: u8,
    /// Parent key name for nested fields (e.g. "CustomRegex" for a "Regex" child key)
    pub parent_key: Option<String>,
    /// Platform-specific (empty = all platforms)
    pub platforms: Vec<Platform>,
    /// Minimum version requirement
    pub min_version: Option<String>,
}

/// Field type enumeration
#[derive(Debug, Clone, PartialEq)]
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
        result
    }
}

impl PayloadManifest {
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
}

#[cfg(test)]
mod tests {
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

    fn create_test_manifest() -> PayloadManifest {
        let mut fields = HashMap::new();
        let mut field_order = Vec::new();

        // Required field
        field_order.push("SSID_STR".to_string());
        fields.insert(
            "SSID_STR".to_string(),
            FieldDefinition {
                name: "SSID_STR".to_string(),
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
            },
        );

        // Sensitive field
        field_order.push("Password".to_string());
        fields.insert(
            "Password".to_string(),
            FieldDefinition {
                name: "Password".to_string(),
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
            },
        );

        // Nested field (depth 1)
        field_order.push("EAPConfig".to_string());
        fields.insert(
            "EAPConfig".to_string(),
            FieldDefinition {
                name: "EAPConfig".to_string(),
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
            },
        );

        PayloadManifest {
            payload_type: "com.apple.wifi.managed".to_string(),
            title: "WiFi".to_string(),
            description: "Configure WiFi networks".to_string(),
            platforms: Platforms::parse("m,i,t"),
            min_versions: HashMap::new(),
            category: "apple".to_string(),
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
