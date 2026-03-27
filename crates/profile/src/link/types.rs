//! Data types for profile cross-reference linking.

use std::collections::HashMap;
use std::path::PathBuf;

/// Specification for a UUID reference field in Apple configuration profiles.
///
/// These fields contain UUIDs that reference other payloads within the same profile
/// (or across profiles when linking).
#[derive(Debug, Clone)]
pub struct ReferenceFieldSpec {
    /// Field name (e.g., "PayloadCertificateUUID")
    pub name: &'static str,
    /// Whether this field is an array of UUIDs
    pub is_array: bool,
    /// Valid target payload types for this reference
    pub target_types: &'static [&'static str],
    /// Path to navigate into nested dictionaries (e.g., `["EAPClientConfiguration"]`)
    pub nested_path: Option<&'static [&'static str]>,
}

/// Known fields that contain UUID references to other payloads.
///
/// Based on Apple's Configuration Profile Reference documentation.
pub const REFERENCE_FIELDS: &[ReferenceFieldSpec] = &[
    // Single UUID - identity certificate for client authentication
    ReferenceFieldSpec {
        name: "PayloadCertificateUUID",
        is_array: false,
        target_types: &[
            "com.apple.security.pkcs12",
            "com.apple.security.scep",
            "com.apple.security.acme",
        ],
        nested_path: None,
    },
    // Array of UUIDs - CA certificates for server validation
    ReferenceFieldSpec {
        name: "PayloadCertificateAnchorUUID",
        is_array: true,
        target_types: &["com.apple.security.root", "com.apple.security.pem"],
        nested_path: None,
    },
    // Nested in EAPClientConfiguration (WiFi/Ethernet)
    ReferenceFieldSpec {
        name: "PayloadCertificateUUID",
        is_array: false,
        target_types: &[
            "com.apple.security.pkcs12",
            "com.apple.security.scep",
            "com.apple.security.acme",
        ],
        nested_path: Some(&["EAPClientConfiguration"]),
    },
    ReferenceFieldSpec {
        name: "TLSTrustedCertificates",
        is_array: true,
        target_types: &["com.apple.security.root", "com.apple.security.pem"],
        nested_path: Some(&["EAPClientConfiguration"]),
    },
    // VPN payloads
    ReferenceFieldSpec {
        name: "LocalIdentifier",
        is_array: false,
        target_types: &[
            "com.apple.security.pkcs12",
            "com.apple.security.scep",
            "com.apple.security.acme",
        ],
        nested_path: Some(&["IKEv2"]),
    },
    // Classroom/Education payloads
    ReferenceFieldSpec {
        name: "LeaderPayloadCertificateAnchorUUID",
        is_array: true,
        target_types: &["com.apple.security.root", "com.apple.security.pem"],
        nested_path: None,
    },
    ReferenceFieldSpec {
        name: "MemberPayloadCertificateAnchorUUID",
        is_array: true,
        target_types: &["com.apple.security.root", "com.apple.security.pem"],
        nested_path: None,
    },
    // Resource certificate in Education Configuration
    ReferenceFieldSpec {
        name: "ResourcePayloadCertificateUUID",
        is_array: false,
        target_types: &["com.apple.security.pkcs12", "com.apple.security.scep"],
        nested_path: None,
    },
    // FileVault recovery key escrow
    ReferenceFieldSpec {
        name: "EncryptCertPayloadUUID",
        is_array: false,
        target_types: &["com.apple.security.pkcs12", "com.apple.security.pem"],
        nested_path: None,
    },
];

/// Payload types that can be referenced by other payloads (certificate providers).
pub const REFERENCEABLE_TYPES: &[&str] = &[
    "com.apple.security.root",
    "com.apple.security.pem",
    "com.apple.security.pkcs1",
    "com.apple.security.pkcs12",
    "com.apple.security.scep",
    "com.apple.security.acme",
];

/// A discovered UUID reference in a profile.
#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug, Clone)]
pub struct UuidReference {
    /// Source profile path
    pub source_profile: PathBuf,
    /// Source payload UUID (the payload containing the reference)
    pub source_payload_uuid: String,
    /// Source payload type
    pub source_payload_type: String,
    /// Source payload identifier
    pub source_payload_identifier: String,
    /// Field name containing the reference
    pub field_name: String,
    /// The referenced UUID value
    pub referenced_uuid: String,
    /// Nesting path if applicable (e.g., `["EAPClientConfiguration"]`)
    pub nested_path: Vec<String>,
    /// Whether this is in an array of UUIDs
    pub is_array_element: bool,
    /// Index in array (if array element)
    pub array_index: Option<usize>,
}

/// A payload that can be referenced (certificate, identity, etc.).
#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug, Clone)]
pub struct ReferenceablePayload {
    /// Source profile path
    pub source_profile: PathBuf,
    /// Payload UUID
    pub payload_uuid: String,
    /// Payload type (com.apple.security.*)
    pub payload_type: String,
    /// Payload identifier
    pub payload_identifier: String,
    /// Payload display name (if present)
    pub display_name: Option<String>,
}

/// UUID mapping from old to new.
#[derive(Debug, Clone, Default)]
pub struct UuidMapping {
    /// Map of old UUID -> new UUID
    pub mapping: HashMap<String, String>,
}

impl UuidMapping {
    /// Create a new empty mapping.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a mapping from old UUID to new UUID.
    pub fn insert(&mut self, old: String, new: String) {
        self.mapping.insert(old, new);
    }

    /// Get the new UUID for an old UUID.
    pub fn get(&self, old: &str) -> Option<&String> {
        self.mapping.get(old)
    }

    /// Check if a UUID has a mapping.
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn contains(&self, old: &str) -> bool {
        self.mapping.contains_key(old)
    }
}

/// Configuration for the link operation.
#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Organization domain for predictable UUIDs
    pub org_domain: Option<String>,
    /// Use predictable UUIDs (v5 based on identifier)
    pub predictable: bool,
    /// Merge all profiles into one output profile
    pub merge: bool,
    /// Validate references after linking
    pub validate: bool,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            org_domain: None,
            predictable: false,
            merge: false,
            validate: true,
        }
    }
}

/// Result of a link operation.
#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug)]
pub struct LinkResult {
    /// Linked profiles (path, profile pairs)
    pub profiles: Vec<(PathBuf, crate::profile::ConfigurationProfile)>,
    /// UUID mapping applied
    pub uuid_mapping: UuidMapping,
    /// Number of references updated
    pub reference_count: usize,
    /// Number of referenceable payloads found
    pub referenceable_count: usize,
}

/// Validation error types for cross-references.
#[derive(Debug, Clone)]
pub enum LinkErrorType {
    /// Referenced UUID not found in any profile
    MissingReference,
    /// Referenced payload has wrong type for the reference field
    TypeMismatch {
        expected: Vec<String>,
        actual: String,
    },
}

/// A validation error for a cross-reference.
#[derive(Debug, Clone)]
pub struct LinkValidationError {
    /// Source payload UUID containing the bad reference
    pub source_payload_uuid: String,
    /// Field name with the bad reference
    pub field_name: String,
    /// The problematic referenced UUID
    pub referenced_uuid: String,
    /// Type of error
    pub error_type: LinkErrorType,
}

/// Result of validating cross-references.
#[derive(Debug)]
pub struct LinkValidationResult {
    /// Whether all references are valid
    pub valid: bool,
    /// Validation errors found
    pub errors: Vec<LinkValidationError>,
    /// Warnings (non-fatal issues)
    pub warnings: Vec<String>,
}

impl LinkValidationResult {
    /// Create a successful validation result.
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn success() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Check if a payload type is referenceable (certificate provider).
pub fn is_referenceable_type(payload_type: &str) -> bool {
    REFERENCEABLE_TYPES.contains(&payload_type)
}
