//! Schema-based validation for configuration profiles
//!
//! Validates profiles against payload schema definitions to ensure:
//! - Required fields are present
//! - Field types match expected types
//! - Values are within allowed ranges
//! - Sensitive fields are handled appropriately
//!
//! Note: This module is reserved for future schema-based validation.
#![allow(dead_code, reason = "module under development")]

use crate::profile::{ConfigurationProfile, PayloadContent};
use crate::schema::{FieldType, PayloadManifest, SchemaRegistry};
use std::collections::HashSet;

/// Severity level for validation issues
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// A single validation issue
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: Severity,
    pub payload_index: Option<usize>,
    pub payload_type: String,
    pub field: Option<String>,
    pub message: String,
    pub code: &'static str,
}

impl ValidationIssue {
    fn error(
        payload_type: &str,
        payload_index: Option<usize>,
        field: Option<&str>,
        message: String,
        code: &'static str,
    ) -> Self {
        Self {
            severity: Severity::Error,
            payload_index,
            payload_type: payload_type.to_string(),
            field: field.map(std::string::ToString::to_string),
            message,
            code,
        }
    }

    fn warning(
        payload_type: &str,
        payload_index: Option<usize>,
        field: Option<&str>,
        message: String,
        code: &'static str,
    ) -> Self {
        Self {
            severity: Severity::Warning,
            payload_index,
            payload_type: payload_type.to_string(),
            field: field.map(std::string::ToString::to_string),
            message,
            code,
        }
    }

    fn info(
        payload_type: &str,
        payload_index: Option<usize>,
        field: Option<&str>,
        message: String,
        code: &'static str,
    ) -> Self {
        Self {
            severity: Severity::Info,
            payload_index,
            payload_type: payload_type.to_string(),
            field: field.map(std::string::ToString::to_string),
            message,
            code,
        }
    }
}

/// Result of schema validation
#[derive(Debug, Default)]
pub struct SchemaValidationResult {
    pub issues: Vec<ValidationIssue>,
    pub payloads_validated: usize,
    pub payloads_unknown: usize,
}

impl SchemaValidationResult {
    pub fn is_valid(&self) -> bool {
        !self.issues.iter().any(|i| i.severity == Severity::Error)
    }

    pub fn errors(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Warning)
            .collect()
    }

    pub fn info(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Info)
            .collect()
    }
}

/// Options for schema validation
#[derive(Debug, Clone, Default)]
pub struct ValidationOptions {
    /// Treat missing required fields as errors (default: true)
    pub check_required: bool,
    /// Validate field types (default: true)
    pub check_types: bool,
    /// Validate allowed values (default: true)
    pub check_allowed_values: bool,
    /// Warn about sensitive fields (default: true)
    pub warn_sensitive: bool,
    /// Warn about unknown payload types (default: true)
    pub warn_unknown_types: bool,
    /// Strict mode: treat unknown types and warnings as errors
    pub strict: bool,
}

impl ValidationOptions {
    pub fn default_checks() -> Self {
        Self {
            check_required: true,
            check_types: true,
            check_allowed_values: true,
            warn_sensitive: true,
            warn_unknown_types: true, // Always warn about unknown types
            strict: false,
        }
    }

    pub fn strict() -> Self {
        Self {
            check_required: true,
            check_types: true,
            check_allowed_values: true,
            warn_sensitive: true,
            warn_unknown_types: true,
            strict: true, // Unknown types become errors
        }
    }
}

/// Schema-based validator
#[derive(Debug)]
pub struct SchemaValidator<'a> {
    registry: &'a SchemaRegistry,
    options: ValidationOptions,
    /// Known third-party identifiers from ProfileManifests (suppresses false-positive warnings)
    known_identifiers: Option<&'a HashSet<String>>,
}

impl<'a> SchemaValidator<'a> {
    pub fn new(registry: &'a SchemaRegistry) -> Self {
        Self {
            registry,
            options: ValidationOptions::default_checks(),
            known_identifiers: None,
        }
    }

    pub fn with_options(registry: &'a SchemaRegistry, options: ValidationOptions) -> Self {
        Self {
            registry,
            options,
            known_identifiers: None,
        }
    }

    /// Set known identifiers for lookup-based warning suppression.
    pub fn with_known_identifiers(mut self, known: &'a HashSet<String>) -> Self {
        self.known_identifiers = Some(known);
        self
    }

    /// Validate a profile against schema definitions
    pub fn validate(&self, profile: &ConfigurationProfile) -> SchemaValidationResult {
        let mut result = SchemaValidationResult::default();

        for (idx, payload) in profile.payload_content.iter().enumerate() {
            self.validate_payload(payload, idx, &mut result);
        }

        result
    }

    /// Validate a single payload
    fn validate_payload(
        &self,
        payload: &PayloadContent,
        index: usize,
        result: &mut SchemaValidationResult,
    ) {
        let Some(manifest) = self.registry.get(&payload.payload_type) else {
            // Check for known custom settings container types (no schema validation needed)
            if is_custom_settings_type(&payload.payload_type) {
                result.payloads_validated += 1;
                // No warning - this is expected for custom settings payloads
                return;
            }

            result.payloads_unknown += 1;
            if self.options.warn_unknown_types {
                // Try to find a similar payload type to suggest
                let suggestion = self.find_similar_payload_type(&payload.payload_type);
                let message = if let Some(similar) = suggestion {
                    format!(
                        "Unknown payload type '{}'. Did you mean '{}'?",
                        payload.payload_type, similar
                    )
                } else {
                    format!(
                        "Unknown payload type '{}' - not in schema registry",
                        payload.payload_type
                    )
                };

                // In strict mode, unknown types are errors; otherwise warnings
                if self.options.strict {
                    result.issues.push(ValidationIssue::error(
                        &payload.payload_type,
                        Some(index),
                        None,
                        message,
                        "UNKNOWN_TYPE",
                    ));
                } else {
                    result.issues.push(ValidationIssue::warning(
                        &payload.payload_type,
                        Some(index),
                        None,
                        message,
                        "UNKNOWN_TYPE",
                    ));
                }
            }
            return;
        };

        result.payloads_validated += 1;

        // Check required fields
        if self.options.check_required {
            self.check_required_fields(payload, index, manifest, result);
        }

        // Check field types
        if self.options.check_types {
            self.check_field_types(payload, index, manifest, result);
        }

        // Check for unknown/misspelled keys
        self.check_unknown_keys(payload, index, manifest, result);

        // Check allowed values
        if self.options.check_allowed_values {
            self.check_allowed_values(payload, index, manifest, result);
        }

        // Warn about sensitive fields
        if self.options.warn_sensitive {
            self.check_sensitive_fields(payload, index, manifest, result);
        }
    }

    /// Check that all required fields are present.
    ///
    /// For nested required fields (depth > 0), only validates when the parent
    /// dictionary is actually present in the payload. This prevents false
    /// positives for optional parent dicts containing required children.
    fn check_required_fields(
        &self,
        payload: &PayloadContent,
        index: usize,
        manifest: &PayloadManifest,
        result: &mut SchemaValidationResult,
    ) {
        for field in manifest.required_fields() {
            if is_standard_payload_key(&field.name) {
                continue;
            }

            // Skip schema placeholders — Apple's schema uses these as structural
            // templates, not literal required key names:
            // - "ANY" = wildcard for any key (com.apple.ManagedClient.preferences)
            // - "*Item" / "*-item" = array element structure (AllowListItem, launchd-item)
            if field.name == "ANY"
                || field.name == "Item"
                || field.name.ends_with("Item")
                || field.name.ends_with("-item")
            {
                continue;
            }

            if field.depth == 0 {
                // Top-level required field — must be present
                if !payload.content.contains_key(&field.name) {
                    result.issues.push(ValidationIssue::error(
                        &payload.payload_type,
                        Some(index),
                        Some(&field.name),
                        format!("Required field '{}' is missing", field.name),
                        "MISSING_REQUIRED",
                    ));
                }
            } else if field.parent_key.is_some() {
                // Nested required field — only check if parent dict is present
                let ancestors = resolve_ancestor_path(&field.name, manifest);
                if let Some(parent_dict) = walk_plist_path(&payload.content, &ancestors) {
                    if !parent_dict.contains_key(&field.name) {
                        let full_path = ancestors.join(".");
                        result.issues.push(ValidationIssue::error(
                            &payload.payload_type,
                            Some(index),
                            Some(&field.name),
                            format!(
                                "Required field '{full_path}.{}' is missing (parent dict is present)",
                                field.name
                            ),
                            "MISSING_NESTED_REQUIRED",
                        ));
                    }
                }
                // If parent dict is absent, the nested required field is not enforced
            }
        }
    }

    /// Check that field types match schema
    fn check_field_types(
        &self,
        payload: &PayloadContent,
        index: usize,
        manifest: &PayloadManifest,
        result: &mut SchemaValidationResult,
    ) {
        for (key, value) in &payload.content {
            if let Some(field_def) = manifest.fields.get(key) {
                let actual_type = plist_value_type(value);
                let expected_type = &field_def.field_type;

                if !types_compatible(&actual_type, expected_type) {
                    result.issues.push(ValidationIssue::error(
                        &payload.payload_type,
                        Some(index),
                        Some(key),
                        format!(
                            "Field '{key}' has type {actual_type:?}, expected {expected_type:?}"
                        ),
                        "TYPE_MISMATCH",
                    ));
                }
            }
        }
    }

    /// Check that values are within allowed ranges
    fn check_allowed_values(
        &self,
        payload: &PayloadContent,
        index: usize,
        manifest: &PayloadManifest,
        result: &mut SchemaValidationResult,
    ) {
        for (key, value) in &payload.content {
            if let Some(field_def) = manifest.fields.get(key)
                && !field_def.allowed_values.is_empty()
            {
                let value_str = plist_value_to_string(value);
                if !field_def.allowed_values.contains(&value_str) {
                    // Suppress if the value is a known third-party identifier
                    if let Some(known) = self.known_identifiers {
                        if known.contains(&value_str) {
                            continue;
                        }
                    }
                    result.issues.push(ValidationIssue::warning(
                        &payload.payload_type,
                        Some(index),
                        Some(key),
                        format!(
                            "Field '{}' value '{}' may not be a recognized value. Known values: {}",
                            key,
                            value_str,
                            field_def.allowed_values.join(", ")
                        ),
                        "INVALID_VALUE",
                    ));
                }
            }
        }
    }

    /// Warn about sensitive fields that may contain secrets
    fn check_sensitive_fields(
        &self,
        payload: &PayloadContent,
        index: usize,
        manifest: &PayloadManifest,
        result: &mut SchemaValidationResult,
    ) {
        for key in payload.content.keys() {
            if let Some(field_def) = manifest.fields.get(key)
                && field_def.flags.sensitive
            {
                result.issues.push(ValidationIssue::info(
                    &payload.payload_type,
                    Some(index),
                    Some(key),
                    format!("Field '{key}' is marked as sensitive (may contain credentials)"),
                    "SENSITIVE_FIELD",
                ));
            }
        }
    }

    /// Check for unknown keys not present in the schema manifest.
    ///
    /// For each key in the payload content that is not a standard payload key
    /// and not defined in the manifest, attempt fuzzy matching to suggest corrections.
    fn check_unknown_keys(
        &self,
        payload: &PayloadContent,
        index: usize,
        manifest: &PayloadManifest,
        result: &mut SchemaValidationResult,
    ) {
        for key in payload.content.keys() {
            // Skip standard payload keys (PayloadType, PayloadVersion, etc.)
            if is_standard_payload_key(key) {
                continue;
            }

            // Skip keys that exist in the manifest (already handled by check_field_types)
            if manifest.fields.contains_key(key) {
                continue;
            }

            // Key is unknown — try fuzzy matching
            if let Some(suggestion) = find_similar_key(key, manifest) {
                let message = format!("Unknown key '{}'. Did you mean '{}'?", key, suggestion);
                if self.options.strict {
                    result.issues.push(ValidationIssue::error(
                        &payload.payload_type,
                        Some(index),
                        Some(key),
                        message,
                        "UNKNOWN_KEY",
                    ));
                } else {
                    result.issues.push(ValidationIssue::warning(
                        &payload.payload_type,
                        Some(index),
                        Some(key),
                        message,
                        "UNKNOWN_KEY",
                    ));
                }
            } else if self.options.strict {
                result.issues.push(ValidationIssue::error(
                    &payload.payload_type,
                    Some(index),
                    Some(key),
                    format!("Unknown key '{}' (strict mode)", key),
                    "UNKNOWN_KEY",
                ));
            }
            // Non-strict + no fuzzy match: silently allow (legitimate vendor/custom key)
        }
    }

    /// Find a similar payload type to suggest for typos
    /// Uses reverse-DNS aware matching optimized for Apple payload types
    fn find_similar_payload_type(&self, unknown_type: &str) -> Option<String> {
        let unknown_lower = unknown_type.to_lowercase();

        // Extract components for reverse-DNS matching
        let unknown_parts: Vec<&str> = unknown_lower.split('.').collect();

        let mut best_match: Option<(String, u32)> = None; // (type, score) - higher is better

        for known_type in self.registry.list() {
            let known_lower = known_type.to_lowercase();

            // Case-insensitive exact match - perfect score
            if unknown_lower == known_lower {
                return Some(known_type.to_string());
            }

            let score = reverse_dns_similarity(&unknown_lower, &unknown_parts, &known_lower);

            // Only consider matches with reasonable similarity (score > 50)
            if score > 50 && (best_match.is_none() || score > best_match.as_ref().unwrap().1) {
                best_match = Some((known_type.to_string(), score));
            }
        }

        best_match.map(|(s, _)| s)
    }
}

/// Calculate similarity score for reverse-DNS style identifiers
/// Returns a score 0-100 where higher is more similar
fn reverse_dns_similarity(_unknown: &str, unknown_parts: &[&str], known: &str) -> u32 {
    let known_parts: Vec<&str> = known.split('.').collect();

    // Must have at least 2 components (e.g., "com.apple")
    if unknown_parts.len() < 2 || known_parts.len() < 2 {
        return 0;
    }

    let mut score: u32 = 0;

    // Check prefix match (com.apple. is very common)
    let prefix_match_count = unknown_parts
        .iter()
        .zip(known_parts.iter())
        .take_while(|(a, b)| a == b)
        .count();

    // Matching prefix is important - each matching segment adds 15 points
    score += (prefix_match_count as u32) * 15;

    // If prefixes don't match at all, very unlikely to be related
    if prefix_match_count == 0 {
        return 0;
    }

    // Extract the "key" part - the distinguishing segment(s) after common prefix
    // For "com.apple.servicemanagement", the key is "servicemanagement"
    // For "com.apple.wifi.managed", the keys are "wifi" and "managed"
    let unknown_key_parts: Vec<&str> = unknown_parts
        .iter()
        .skip(prefix_match_count)
        .copied()
        .collect();
    let known_key_parts: Vec<&str> = known_parts
        .iter()
        .skip(prefix_match_count)
        .copied()
        .collect();

    if unknown_key_parts.is_empty() || known_key_parts.is_empty() {
        // One is a prefix of the other
        return score + 10;
    }

    // Compare key parts
    let unknown_key = unknown_key_parts.join(".");
    let known_key = known_key_parts.join(".");

    // Exact key match after prefix
    if unknown_key == known_key {
        return 100;
    }

    // Check if one key contains the other (substring match)
    if unknown_key.contains(&known_key) || known_key.contains(&unknown_key) {
        score += 40;
    }

    // Check individual key segments for similarity
    for unknown_seg in &unknown_key_parts {
        for known_seg in &known_key_parts {
            // Exact segment match
            if unknown_seg == known_seg {
                score += 25;
                continue;
            }

            // One segment contains the other
            if unknown_seg.contains(known_seg) || known_seg.contains(unknown_seg) {
                score += 20;
                continue;
            }

            // Small edit distance on segment (for typos like "Zservicemanagement" -> "servicemanagement")
            let seg_distance = levenshtein_distance(unknown_seg, known_seg);
            if seg_distance == 1 {
                score += 35; // Very likely a typo
            } else if seg_distance == 2 && unknown_seg.len() > 5 {
                score += 20; // Possible typo for longer words
            }
        }
    }

    // Penalize length differences in key parts
    let len_diff = unknown_key_parts.len().abs_diff(known_key_parts.len()) as u32;
    if len_diff > 0 {
        score = score.saturating_sub(len_diff * 10);
    }

    score.min(100)
}

use contour_core::levenshtein_distance;

/// Resolve the ancestor path for a nested field by walking `parent_key` links.
///
/// Returns the chain from root to immediate parent. For example, for a field
/// `Regex` with parent `CustomRegex`, returns `["CustomRegex"]`.
fn resolve_ancestor_path(field_name: &str, manifest: &PayloadManifest) -> Vec<String> {
    let mut path = Vec::new();
    let mut current = field_name.to_string();

    for _ in 0..32 {
        let parent = manifest
            .fields
            .get(&current)
            .and_then(|f| f.parent_key.as_ref());
        match parent {
            Some(p) => {
                path.push(p.clone());
                current = p.clone();
            }
            None => break,
        }
    }

    path.reverse();
    path
}

/// Walk into a plist payload along a key path.
///
/// The root is a `HashMap<String, plist::Value>` (PayloadContent.content).
/// Nested levels are `plist::Value::Dictionary`. Returns the innermost
/// dictionary if every key resolves, or `None` if any key is absent.
fn walk_plist_path<'a>(
    root: &'a std::collections::HashMap<String, plist::Value>,
    path: &[String],
) -> Option<&'a plist::Dictionary> {
    let (first, rest) = path.split_first()?;
    let plist::Value::Dictionary(dict) = root.get(first)? else {
        return None;
    };
    let mut current = dict;
    for key in rest {
        match current.get(key) {
            Some(plist::Value::Dictionary(nested)) => current = nested,
            _ => return None,
        }
    }
    Some(current)
}

/// Find a schema key similar to the given unknown key.
///
/// Returns the closest matching key from the manifest if one is found via
/// case-insensitive exact match or Levenshtein distance <= 3.
fn find_similar_key(unknown: &str, manifest: &PayloadManifest) -> Option<String> {
    let unknown_lower = unknown.to_lowercase();
    manifest
        .fields
        .keys()
        .filter(|known| {
            let known_lower = known.to_lowercase();
            // Case-insensitive exact match (e.g. Tilesize vs tilesize)
            if known_lower == unknown_lower {
                return true;
            }
            // Levenshtein distance <= 3 (typo)
            levenshtein_distance(&unknown_lower, &known_lower) <= 3
        })
        .min_by_key(|known| levenshtein_distance(&unknown_lower, &known.to_lowercase()))
        .cloned()
}

/// Get the FieldType for a plist value
fn plist_value_type(value: &plist::Value) -> FieldType {
    match value {
        plist::Value::String(_) => FieldType::String,
        plist::Value::Integer(_) => FieldType::Integer,
        plist::Value::Real(_) => FieldType::Real,
        plist::Value::Boolean(_) => FieldType::Boolean,
        plist::Value::Array(_) => FieldType::Array,
        plist::Value::Dictionary(_) => FieldType::Dictionary,
        plist::Value::Data(_) => FieldType::Data,
        plist::Value::Date(_) => FieldType::Date,
        _ => FieldType::String,
    }
}

/// Check if actual type is compatible with expected type
fn types_compatible(actual: &FieldType, expected: &FieldType) -> bool {
    if actual == expected {
        return true;
    }

    // Integer and Real are often interchangeable
    if matches!(
        (actual, expected),
        (FieldType::Integer, FieldType::Real) | (FieldType::Real, FieldType::Integer)
    ) {
        return true;
    }

    false
}

/// Convert plist value to string for comparison
fn plist_value_to_string(value: &plist::Value) -> String {
    match value {
        plist::Value::String(s) => s.clone(),
        plist::Value::Integer(i) => i.to_string(),
        plist::Value::Real(f) => f.to_string(),
        plist::Value::Boolean(b) => b.to_string(),
        _ => format!("{value:?}"),
    }
}

/// Check if this is a standard payload key or ProfileManifests metadata
/// Check if a payload type is a known custom settings container.
/// These types are valid but don't have fixed schemas - they're used
/// to deploy arbitrary managed preferences.
fn is_custom_settings_type(payload_type: &str) -> bool {
    matches!(
        payload_type,
        "com.apple.ManagedClient.preferences" | "com.apple.ManagedClient.diskencryption"
    )
}

fn is_standard_payload_key(name: &str) -> bool {
    // Standard Apple payload keys
    if matches!(
        name,
        "PayloadType"
            | "PayloadVersion"
            | "PayloadIdentifier"
            | "PayloadUUID"
            | "PayloadDisplayName"
            | "PayloadDescription"
            | "PayloadOrganization"
            | "PayloadEnabled"
            | "PayloadScope"
    ) {
        return true;
    }

    // ProfileManifests metadata keys (PFC_ = Profile Creator, pfm_ = manifest)
    if name.starts_with("PFC_") || name.starts_with("pfm_") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_payload(
        payload_type: &str,
        mut content: HashMap<String, plist::Value>,
    ) -> PayloadContent {
        content.insert(
            "PayloadDisplayName".to_string(),
            plist::Value::String("Test".to_string()),
        );
        PayloadContent {
            payload_type: payload_type.to_string(),
            payload_version: 1,
            payload_identifier: "test.payload".to_string(),
            payload_uuid: "TEST-UUID".to_string(),
            content,
        }
    }

    #[test]
    fn test_validation_options_default() {
        let opts = ValidationOptions::default_checks();
        assert!(opts.check_required);
        assert!(opts.check_types);
        assert!(!opts.strict);
    }

    #[test]
    fn test_types_compatible() {
        assert!(types_compatible(&FieldType::String, &FieldType::String));
        assert!(types_compatible(&FieldType::Integer, &FieldType::Real));
        assert!(!types_compatible(&FieldType::String, &FieldType::Boolean));
    }

    #[test]
    fn test_levenshtein_distance() {
        // Identical strings
        assert_eq!(levenshtein_distance("test", "test"), 0);

        // One character difference (substitution)
        assert_eq!(levenshtein_distance("test", "text"), 1);
        assert_eq!(levenshtein_distance("cat", "bat"), 1);

        // Insertions/deletions
        assert_eq!(levenshtein_distance("test", "tests"), 1);
        assert_eq!(levenshtein_distance("tests", "test"), 1);

        // Multiple edits
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);

        // Empty strings
        assert_eq!(levenshtein_distance("", "test"), 4);
        assert_eq!(levenshtein_distance("test", ""), 4);
        assert_eq!(levenshtein_distance("", ""), 0);

        // Case sensitivity
        assert_eq!(levenshtein_distance("Test", "test"), 1);

        // Segment comparison (key part only)
        assert_eq!(
            levenshtein_distance("zservicemanagement", "servicemanagement"),
            1
        );
        assert_eq!(
            levenshtein_distance("servicmanagement", "servicemanagement"),
            1
        );
    }

    #[test]
    fn test_reverse_dns_similarity() {
        // Exact match after lowercasing handled separately, but test scoring

        // Same prefix, typo in key segment (single char insertion)
        let unknown = "com.apple.zservicemanagement";
        let unknown_parts: Vec<&str> = unknown.split('.').collect();
        let score = reverse_dns_similarity(unknown, &unknown_parts, "com.apple.servicemanagement");
        assert!(
            score > 50,
            "Single char typo should score > 50, got {}",
            score
        );

        // Same prefix, substring match
        let unknown2 = "com.apple.wifi";
        let unknown_parts2: Vec<&str> = unknown2.split('.').collect();
        let score2 = reverse_dns_similarity(unknown2, &unknown_parts2, "com.apple.wifi.managed");
        assert!(
            score2 > 50,
            "Substring match should score > 50, got {}",
            score2
        );

        // Different prefix - should score 0
        let unknown3 = "org.example.wifi";
        let unknown_parts3: Vec<&str> = unknown3.split('.').collect();
        let score3 = reverse_dns_similarity(unknown3, &unknown_parts3, "com.apple.wifi.managed");
        assert_eq!(score3, 0, "Different prefix should score 0");

        // Same prefix, completely different key
        let unknown4 = "com.apple.bluetooth";
        let unknown_parts4: Vec<&str> = unknown4.split('.').collect();
        let score4 = reverse_dns_similarity(unknown4, &unknown_parts4, "com.apple.wifi.managed");
        assert!(
            score4 < 50,
            "Different key should score < 50, got {}",
            score4
        );
    }

    #[test]
    fn test_reverse_dns_similarity_edge_cases() {
        // Too few components
        let unknown = "singlecomponent";
        let unknown_parts: Vec<&str> = unknown.split('.').collect();
        assert_eq!(
            reverse_dns_similarity(unknown, &unknown_parts, "com.apple.test"),
            0
        );

        // One is prefix of other
        let unknown2 = "com.apple";
        let unknown_parts2: Vec<&str> = unknown2.split('.').collect();
        let score = reverse_dns_similarity(unknown2, &unknown_parts2, "com.apple.wifi");
        assert!(score > 0, "Prefix relationship should have some score");
    }

    #[test]
    fn test_validation_options_warn_unknown_types_default() {
        let opts = ValidationOptions::default_checks();
        assert!(opts.warn_unknown_types); // Should be true by default now
    }

    // --- Unknown key detection tests ---

    /// Build a minimal manifest with the given field names for testing.
    fn test_manifest(payload_type: &str, field_names: &[&str]) -> PayloadManifest {
        use crate::schema::types::{FieldDefinition, FieldFlags, Platforms};

        let mut fields = HashMap::new();
        let mut field_order = Vec::new();
        for &name in field_names {
            fields.insert(
                name.to_string(),
                FieldDefinition {
                    name: name.to_string(),
                    field_type: FieldType::String,
                    flags: FieldFlags {
                        required: false,
                        supervised: false,
                        sensitive: false,
                    },
                    title: String::new(),
                    description: String::new(),
                    default: None,
                    allowed_values: Vec::new(),
                    depth: 0,
                    parent_key: None,
                    platforms: Vec::new(),
                    min_version: None,
                },
            );
            field_order.push(name.to_string());
        }
        PayloadManifest {
            payload_type: payload_type.to_string(),
            title: String::new(),
            description: String::new(),
            platforms: Platforms::default(),
            min_versions: HashMap::new(),
            category: "apple".to_string(),
            fields,
            field_order,
            segments: Vec::new(),
        }
    }

    /// Build a registry from a single manifest.
    fn registry_from_manifest(manifest: PayloadManifest) -> SchemaRegistry {
        SchemaRegistry::from_manifests_for_test(vec![manifest])
    }

    #[test]
    fn test_unknown_key_with_fuzzy_match() {
        // "Tilesize" vs "tilesize" — case-insensitive exact match
        let manifest = test_manifest("com.apple.dock", &["tilesize", "orientation", "autohide"]);
        let registry = registry_from_manifest(manifest);
        let validator = SchemaValidator::new(&registry);

        let mut content = HashMap::new();
        content.insert("Tilesize".to_string(), plist::Value::Integer(48.into()));
        let payload = create_test_payload("com.apple.dock", content);
        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "test".to_string(),
            payload_uuid: "TEST".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![payload],
            additional_fields: HashMap::new(),
        };

        let result = validator.validate(&profile);
        let warnings = result.warnings();
        assert!(!warnings.is_empty(), "Expected warning for 'Tilesize' typo");
        let warn = &warnings[0];
        assert_eq!(warn.code, "UNKNOWN_KEY");
        assert!(
            warn.message.contains("Did you mean 'tilesize'?"),
            "Expected suggestion for 'tilesize', got: {}",
            warn.message
        );
    }

    #[test]
    fn test_unknown_key_case_mismatch() {
        // "AllowMailDrop" vs "allowMailDrop" — case mismatch
        let manifest = test_manifest("com.apple.airplay", &["allowMailDrop", "forceUnprompted"]);
        let registry = registry_from_manifest(manifest);
        let validator = SchemaValidator::new(&registry);

        let mut content = HashMap::new();
        content.insert("AllowMailDrop".to_string(), plist::Value::Boolean(true));
        let payload = create_test_payload("com.apple.airplay", content);
        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "test".to_string(),
            payload_uuid: "TEST".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![payload],
            additional_fields: HashMap::new(),
        };

        let result = validator.validate(&profile);
        let warnings = result.warnings();
        assert!(
            !warnings.is_empty(),
            "Expected warning for 'AllowMailDrop' case mismatch"
        );
        assert!(
            warnings[0]
                .message
                .contains("Did you mean 'allowMailDrop'?"),
            "Expected suggestion for 'allowMailDrop', got: {}",
            warnings[0].message
        );
    }

    #[test]
    fn test_unknown_key_strict_mode() {
        // Completely unknown key in strict mode — should be an error
        let manifest = test_manifest("com.apple.dock", &["tilesize", "orientation"]);
        let registry = registry_from_manifest(manifest);
        let validator = SchemaValidator::with_options(&registry, ValidationOptions::strict());

        let mut content = HashMap::new();
        content.insert(
            "VendorCustomField".to_string(),
            plist::Value::String("value".to_string()),
        );
        let payload = create_test_payload("com.apple.dock", content);
        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "test".to_string(),
            payload_uuid: "TEST".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![payload],
            additional_fields: HashMap::new(),
        };

        let result = validator.validate(&profile);
        let errors = result.errors();
        let unknown_key_errors: Vec<_> =
            errors.iter().filter(|e| e.code == "UNKNOWN_KEY").collect();
        assert!(
            !unknown_key_errors.is_empty(),
            "Expected error for unknown key in strict mode"
        );
        assert!(
            unknown_key_errors[0].message.contains("strict mode"),
            "Expected strict mode mention, got: {}",
            unknown_key_errors[0].message
        );
    }

    #[test]
    fn test_custom_key_no_warning() {
        // Completely unrelated key in non-strict mode — should be silently allowed
        let manifest = test_manifest("com.apple.dock", &["tilesize", "orientation"]);
        let registry = registry_from_manifest(manifest);
        let validator = SchemaValidator::new(&registry);

        let mut content = HashMap::new();
        content.insert(
            "VendorCustomField".to_string(),
            plist::Value::String("value".to_string()),
        );
        let payload = create_test_payload("com.apple.dock", content);
        let profile = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "test".to_string(),
            payload_uuid: "TEST".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![payload],
            additional_fields: HashMap::new(),
        };

        let result = validator.validate(&profile);
        let unknown_warnings: Vec<_> = result
            .warnings()
            .into_iter()
            .filter(|w| w.code == "UNKNOWN_KEY")
            .collect();
        assert!(
            unknown_warnings.is_empty(),
            "Custom key should not produce warnings in non-strict mode, got: {:?}",
            unknown_warnings
                .iter()
                .map(|w| &w.message)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_levenshtein_basic() {
        // Core distance calculations used by find_similar_key
        assert_eq!(levenshtein_distance("tilesize", "tilesize"), 0);
        assert_eq!(levenshtein_distance("tilesiz", "tilesize"), 1);
        assert_eq!(levenshtein_distance("tilesze", "tilesize"), 1);
        assert_eq!(levenshtein_distance("allowmaildrop", "allowmaildrop"), 0);
        // Case differences counted as substitutions
        assert_eq!(levenshtein_distance("Tilesize", "tilesize"), 1);
    }

    // ========== Nested Required Field Tests ==========

    /// Build a manifest with nested fields (simulates passcode.settings CustomRegex pattern).
    fn test_manifest_with_nesting() -> PayloadManifest {
        use crate::schema::types::{FieldDefinition, FieldFlags, Platforms};

        let mut fields = HashMap::new();
        let mut field_order = Vec::new();

        // Top-level optional field
        let add_field = |fields: &mut HashMap<String, FieldDefinition>,
                         order: &mut Vec<String>,
                         name: &str,
                         required: bool,
                         depth: u8,
                         parent: Option<&str>| {
            fields.insert(
                name.to_string(),
                FieldDefinition {
                    name: name.to_string(),
                    field_type: FieldType::String,
                    flags: FieldFlags {
                        required,
                        supervised: false,
                        sensitive: false,
                    },
                    title: String::new(),
                    description: String::new(),
                    default: None,
                    allowed_values: Vec::new(),
                    depth,
                    parent_key: parent.map(String::from),
                    platforms: Vec::new(),
                    min_version: None,
                },
            );
            order.push(name.to_string());
        };

        // Top-level required
        add_field(
            &mut fields,
            &mut field_order,
            "RequirePasscode",
            true,
            0,
            None,
        );
        // Top-level optional dict
        add_field(&mut fields, &mut field_order, "CustomRegex", false, 0, None);
        // Nested required (only required when CustomRegex is present)
        add_field(
            &mut fields,
            &mut field_order,
            "Regex",
            true,
            1,
            Some("CustomRegex"),
        );
        // Nested optional
        add_field(
            &mut fields,
            &mut field_order,
            "Description",
            false,
            1,
            Some("CustomRegex"),
        );

        PayloadManifest {
            payload_type: "com.apple.configuration.passcode.settings".to_string(),
            title: "Passcode Settings".to_string(),
            description: String::new(),
            platforms: Platforms::default(),
            min_versions: HashMap::new(),
            category: "apple".to_string(),
            fields,
            field_order,
            segments: Vec::new(),
        }
    }

    fn make_profile(
        payload_type: &str,
        content: Vec<(&str, plist::Value)>,
    ) -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.example.test".to_string(),
            payload_uuid: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".to_string(),
            payload_display_name: "Test".to_string(),
            payload_content: vec![PayloadContent {
                payload_type: payload_type.to_string(),
                payload_version: 1,
                payload_identifier: "com.example.test.payload".to_string(),
                payload_uuid: "11111111-2222-3333-4444-555555555555".to_string(),
                content: content
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
            }],
            additional_fields: HashMap::new(),
        }
    }

    #[test]
    fn test_nested_required_absent_parent_no_error() {
        // CustomRegex is absent → Regex (nested required) should NOT be flagged
        let manifest = test_manifest_with_nesting();
        let registry = registry_from_manifest(manifest);

        let profile = make_profile(
            "com.apple.configuration.passcode.settings",
            vec![("RequirePasscode", plist::Value::Boolean(true))],
        );

        let validator = SchemaValidator::new(&registry);
        let result = validator.validate(&profile);

        let missing: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.code == "MISSING_REQUIRED" || i.code == "MISSING_NESTED_REQUIRED")
            .collect();

        assert!(
            missing.is_empty(),
            "Should not flag nested Regex when CustomRegex is absent. Got: {:?}",
            missing.iter().map(|i| &i.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_nested_required_present_parent_missing_child() {
        // CustomRegex IS present but Regex is missing → should flag
        let manifest = test_manifest_with_nesting();
        let registry = registry_from_manifest(manifest);

        let mut custom_regex_dict = plist::Dictionary::new();
        custom_regex_dict.insert(
            "Description".to_string(),
            plist::Value::String("some description".to_string()),
        );

        let profile = make_profile(
            "com.apple.configuration.passcode.settings",
            vec![
                ("RequirePasscode", plist::Value::Boolean(true)),
                ("CustomRegex", plist::Value::Dictionary(custom_regex_dict)),
            ],
        );

        let validator = SchemaValidator::new(&registry);
        let result = validator.validate(&profile);

        let nested: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.code == "MISSING_NESTED_REQUIRED")
            .collect();

        assert_eq!(
            nested.len(),
            1,
            "Should flag missing Regex when CustomRegex is present. Got: {:?}",
            nested.iter().map(|i| &i.message).collect::<Vec<_>>()
        );
        assert!(nested[0].message.contains("Regex"));
    }

    #[test]
    fn test_nested_required_present_parent_with_child() {
        // CustomRegex IS present AND Regex is present → no error
        let manifest = test_manifest_with_nesting();
        let registry = registry_from_manifest(manifest);

        let mut custom_regex_dict = plist::Dictionary::new();
        custom_regex_dict.insert(
            "Regex".to_string(),
            plist::Value::String("^[a-z]+$".to_string()),
        );

        let profile = make_profile(
            "com.apple.configuration.passcode.settings",
            vec![
                ("RequirePasscode", plist::Value::Boolean(true)),
                ("CustomRegex", plist::Value::Dictionary(custom_regex_dict)),
            ],
        );

        let validator = SchemaValidator::new(&registry);
        let result = validator.validate(&profile);

        let missing: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.code == "MISSING_REQUIRED" || i.code == "MISSING_NESTED_REQUIRED")
            .collect();

        assert!(
            missing.is_empty(),
            "No errors when both parent and child are present. Got: {:?}",
            missing.iter().map(|i| &i.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_top_level_required_still_enforced() {
        // RequirePasscode (top-level required) missing → should flag
        let manifest = test_manifest_with_nesting();
        let registry = registry_from_manifest(manifest);

        let profile = make_profile("com.apple.configuration.passcode.settings", vec![]);

        let validator = SchemaValidator::new(&registry);
        let result = validator.validate(&profile);

        let top: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.code == "MISSING_REQUIRED" && i.message.contains("RequirePasscode"))
            .collect();

        assert_eq!(top.len(), 1, "Should flag missing top-level required field");
    }

    #[test]
    fn test_resolve_ancestor_path() {
        let manifest = test_manifest_with_nesting();
        let path = resolve_ancestor_path("Regex", &manifest);
        assert_eq!(path, vec!["CustomRegex"]);

        // Top-level field has no ancestors
        let path = resolve_ancestor_path("RequirePasscode", &manifest);
        assert!(path.is_empty());
    }

    #[test]
    fn test_walk_plist_path_present() {
        let mut inner = plist::Dictionary::new();
        inner.insert("Regex".to_string(), plist::Value::String(".*".to_string()));

        let mut content = HashMap::new();
        content.insert("CustomRegex".to_string(), plist::Value::Dictionary(inner));

        let result = walk_plist_path(&content, &["CustomRegex".to_string()]);
        assert!(result.is_some());
        assert!(result.unwrap().contains_key("Regex"));
    }

    #[test]
    fn test_walk_plist_path_absent() {
        let content: HashMap<String, plist::Value> = HashMap::new();
        let result = walk_plist_path(&content, &["CustomRegex".to_string()]);
        assert!(result.is_none());
    }
}
