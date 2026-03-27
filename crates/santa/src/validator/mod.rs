use crate::models::{Policy, Rule, RuleSet, RuleType};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Empty identifier at rule {index}")]
    EmptyIdentifier { index: usize },

    #[error("Invalid identifier format for {rule_type} at rule {index}: {identifier}")]
    InvalidIdentifierFormat {
        index: usize,
        rule_type: RuleType,
        identifier: String,
    },

    #[error("Duplicate rule key: {key}")]
    DuplicateRule { key: String },

    #[error("Conflicting policies for identifier '{identifier}': {policy1} and {policy2}")]
    ConflictingPolicies {
        identifier: String,
        policy1: String,
        policy2: String,
    },

    #[error("Invalid SHA-256 hash at rule {index}: expected 64 hex characters, got {length}")]
    InvalidSha256Hash { index: usize, length: usize },

    #[error("Invalid CDHASH at rule {index}: expected 40 hex characters, got {length}")]
    InvalidCdhash { index: usize, length: usize },

    #[error(
        "Invalid SigningID format at rule {index}: '{identifier}' (expected TeamID:BundleID or platform:BundleID)"
    )]
    InvalidSigningIdFormat { index: usize, identifier: String },

    #[error(
        "Invalid ring name at rule {index}: '{ring}' (expected ring0-ring9 or custom alphanumeric)"
    )]
    InvalidRingName { index: usize, ring: String },
}

#[derive(Debug)]
pub enum ValidationWarning {
    /// Rule has no description
    MissingDescription { index: usize },
    /// TeamID doesn't match expected format
    SuspiciousTeamId { index: usize, identifier: String },
    /// Large ruleset has rules without groups for organization
    MissingGroup { index: usize },
    /// Suspicious certificate hash (looks like TeamID not SHA-256)
    SuspiciousCertificateHash { index: usize, identifier: String },
    /// CEL expression is very short/simple
    SimpleCelExpression { index: usize },
    /// Rule assigned to many rings (potential global rule)
    TooManyRings { index: usize, count: usize },
}

impl std::fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationWarning::MissingDescription { index } => {
                write!(f, "Rule {index} has no description")
            }
            ValidationWarning::SuspiciousTeamId { index, identifier } => {
                write!(f, "Rule {index} has suspicious TeamID format: {identifier}")
            }
            ValidationWarning::MissingGroup { index } => {
                write!(
                    f,
                    "Rule {index} has no group (recommended for organization)"
                )
            }
            ValidationWarning::SuspiciousCertificateHash { index, identifier } => {
                write!(
                    f,
                    "Rule {index} has suspicious certificate hash (looks like TeamID?): {identifier}"
                )
            }
            ValidationWarning::SimpleCelExpression { index } => {
                write!(f, "Rule {index} has a very simple CEL expression")
            }
            ValidationWarning::TooManyRings { index, count } => {
                write!(
                    f,
                    "Rule {index} is assigned to {count} rings (consider making it global)"
                )
            }
        }
    }
}

/// Validation result
#[derive(Debug, Default)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, error: ValidationError) {
        self.valid = false;
        self.errors.push(error);
    }

    pub fn add_warning(&mut self, warning: ValidationWarning) {
        self.warnings.push(warning);
    }

    pub fn merge(&mut self, other: ValidationResult) {
        if !other.valid {
            self.valid = false;
        }
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }
}

/// Validate a single rule
pub fn validate_rule(rule: &Rule, index: usize) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Check for empty identifier
    if rule.identifier.trim().is_empty() {
        result.add_error(ValidationError::EmptyIdentifier { index });
        return result;
    }

    // Validate identifier format based on rule type
    match rule.rule_type {
        RuleType::TeamId => {
            // TeamID should be 10 alphanumeric characters
            if !is_valid_team_id(&rule.identifier) {
                result.add_warning(ValidationWarning::SuspiciousTeamId {
                    index,
                    identifier: rule.identifier.clone(),
                });
            }
        }
        RuleType::Binary | RuleType::Certificate => {
            // SHA-256 hash should be 64 hex characters
            if is_valid_team_id(&rule.identifier) {
                // Looks like a TeamID, not a SHA-256 hash
                result.add_warning(ValidationWarning::SuspiciousCertificateHash {
                    index,
                    identifier: rule.identifier.clone(),
                });
            } else if !is_valid_sha256(&rule.identifier) {
                result.add_error(ValidationError::InvalidSha256Hash {
                    index,
                    length: rule.identifier.len(),
                });
            }
        }
        RuleType::Cdhash => {
            // CDHASH is 40 hex characters (SHA-1)
            if !is_valid_cdhash(&rule.identifier) {
                result.add_error(ValidationError::InvalidCdhash {
                    index,
                    length: rule.identifier.len(),
                });
            }
        }
        RuleType::SigningId => {
            // SigningID should be in format "TeamID:BundleID" or "platform:BundleID"
            if !is_valid_signing_id(&rule.identifier) {
                result.add_error(ValidationError::InvalidSigningIdFormat {
                    index,
                    identifier: rule.identifier.clone(),
                });
            }
        }
    }

    // Validate ring names
    for ring in &rule.rings {
        if !is_valid_ring_name(ring) {
            result.add_error(ValidationError::InvalidRingName {
                index,
                ring: ring.clone(),
            });
        }
    }

    // Warn about too many ring assignments
    if rule.rings.len() > 5 {
        result.add_warning(ValidationWarning::TooManyRings {
            index,
            count: rule.rings.len(),
        });
    }

    // Validate CEL expression if present
    if let Some(ref cel) = rule.cel_expression
        && cel.len() < 10
    {
        result.add_warning(ValidationWarning::SimpleCelExpression { index });
    }

    // Warn about missing description
    if rule.description.is_none() {
        result.add_warning(ValidationWarning::MissingDescription { index });
    }

    result
}

/// Configuration for validation behavior
#[derive(Debug, Clone, Default)]
pub struct ValidationOptions {
    /// Warn about missing groups in large rulesets
    pub warn_missing_groups: bool,
    /// Minimum ruleset size to trigger group warnings
    pub group_warning_threshold: usize,
}

/// Validate a rule set
pub fn validate_ruleset(rules: &RuleSet) -> ValidationResult {
    validate_ruleset_with_options(rules, &ValidationOptions::default())
}

/// Validate a rule set with custom options
pub fn validate_ruleset_with_options(
    rules: &RuleSet,
    options: &ValidationOptions,
) -> ValidationResult {
    let mut result = ValidationResult::new();
    let mut seen_keys = HashSet::new();
    // Track identifier -> policies for conflict detection
    let mut identifier_policies: HashMap<String, Vec<(usize, Policy)>> = HashMap::new();

    for (i, rule) in rules.rules().iter().enumerate() {
        // Validate individual rule
        let rule_result = validate_rule(rule, i);
        result.merge(rule_result);

        // Check for duplicates
        let key = rule.key();
        if seen_keys.contains(&key) {
            result.add_error(ValidationError::DuplicateRule { key });
        } else {
            seen_keys.insert(key);
        }

        // Track policies per identifier for conflict detection
        identifier_policies
            .entry(rule.identifier.clone())
            .or_default()
            .push((i, rule.policy));

        // Warn about missing groups in large rulesets
        if options.warn_missing_groups
            && rules.len() >= options.group_warning_threshold
            && rule.group.is_none()
        {
            result.add_warning(ValidationWarning::MissingGroup { index: i });
        }
    }

    // Check for conflicting policies on the same identifier
    for (identifier, policies) in identifier_policies {
        if policies.len() > 1 {
            // Check if we have both allow and block policies
            let has_allow = policies
                .iter()
                .any(|(_, p)| matches!(p, Policy::Allowlist | Policy::AllowlistCompiler));
            let has_block = policies
                .iter()
                .any(|(_, p)| matches!(p, Policy::Blocklist | Policy::SilentBlocklist));

            if has_allow && has_block {
                let allow_policy = policies
                    .iter()
                    .find(|(_, p)| matches!(p, Policy::Allowlist | Policy::AllowlistCompiler))
                    .map(|(_, p)| format!("{p:?}"))
                    .unwrap_or_default();
                let block_policy = policies
                    .iter()
                    .find(|(_, p)| matches!(p, Policy::Blocklist | Policy::SilentBlocklist))
                    .map(|(_, p)| format!("{p:?}"))
                    .unwrap_or_default();

                result.add_error(ValidationError::ConflictingPolicies {
                    identifier,
                    policy1: allow_policy,
                    policy2: block_policy,
                });
            }
        }
    }

    result
}

fn is_valid_team_id(s: &str) -> bool {
    // Standard TeamID: 10 alphanumeric characters
    // Special cases: "Software Signing" (Apple platform), "Apple Mac OS Application Signing"
    const SPECIAL_TEAM_IDS: &[&str] = &[
        "Software Signing",
        "Apple Mac OS Application Signing",
        "Developer ID Application",
        "Developer ID Installer",
        "Apple iPhone OS Application Signing",
    ];

    if SPECIAL_TEAM_IDS.contains(&s) {
        return true;
    }

    s.len() == 10 && s.chars().all(|c| c.is_ascii_alphanumeric())
}

fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_cdhash(s: &str) -> bool {
    // CDHASH is 40 hex characters (SHA-1)
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_signing_id(s: &str) -> bool {
    // Format: TeamID:BundleID or platform:BundleID
    // Examples: EQHXZ8M8AV:com.google.Chrome, platform:com.apple.Safari
    // Also allows special prefixes like "Software Signing"
    if let Some(colon_pos) = s.find(':') {
        let prefix = &s[..colon_pos];
        let bundle_id = &s[colon_pos + 1..];

        // Prefix should be TeamID (10 alphanumeric), "platform", or special Apple identifiers
        let valid_prefix = prefix == "platform" || is_valid_team_id(prefix);

        // Bundle ID should have at least one dot and be non-empty
        // Some system bundles may not have dots, so just check non-empty
        let valid_bundle = !bundle_id.is_empty();

        valid_prefix && valid_bundle
    } else {
        false
    }
}

fn is_valid_ring_name(s: &str) -> bool {
    // Ring names must be non-empty and contain only alphanumeric, underscore, or hyphen
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_rule() {
        let rule = Rule::new(RuleType::TeamId, "EQHXZ8M8AV", Policy::Allowlist)
            .with_description("Google LLC");
        let result = validate_rule(&rule, 0);
        assert!(result.valid);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_validate_empty_identifier() {
        let rule = Rule::new(RuleType::TeamId, "", Policy::Allowlist);
        let result = validate_rule(&rule, 0);
        assert!(!result.valid);
        assert!(matches!(
            result.errors[0],
            ValidationError::EmptyIdentifier { .. }
        ));
    }

    #[test]
    fn test_validate_missing_description() {
        let rule = Rule::new(RuleType::TeamId, "EQHXZ8M8AV", Policy::Allowlist);
        let result = validate_rule(&rule, 0);
        assert!(result.valid);
        assert!(matches!(
            result.warnings[0],
            ValidationWarning::MissingDescription { .. }
        ));
    }

    #[test]
    fn test_validate_duplicate_rules() {
        let mut rules = RuleSet::new();
        rules.add(Rule::new(RuleType::TeamId, "ABC", Policy::Allowlist));
        rules.add(Rule::new(RuleType::TeamId, "ABC", Policy::Blocklist));

        let result = validate_ruleset(&rules);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_conflicting_policies() {
        let mut rules = RuleSet::new();
        rules.add(Rule::new(RuleType::TeamId, "EQHXZ8M8AV", Policy::Allowlist));
        rules.add(Rule::new(
            RuleType::Binary,
            "abc123def456",
            Policy::Allowlist,
        )); // Different type, same ident won't conflict

        let mut rules2 = RuleSet::new();
        rules2.add(Rule::new(RuleType::TeamId, "EQHXZ8M8AV", Policy::Allowlist));
        // Create another TeamId with different casing to test conflict
        rules2.add(
            Rule::new(RuleType::TeamId, "EQHXZ8M8AV", Policy::Blocklist)
                .with_description("Duplicate"),
        );

        let result = validate_ruleset(&rules2);
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::ConflictingPolicies { .. }))
        );
    }

    #[test]
    fn test_validate_sha256_hash() {
        // Valid SHA-256
        let valid_hash = "a".repeat(64);
        let rule = Rule::new(RuleType::Binary, &valid_hash, Policy::Allowlist);
        let result = validate_rule(&rule, 0);
        assert!(result.valid);

        // Invalid SHA-256 (too short)
        let invalid_hash = "a".repeat(32);
        let rule = Rule::new(RuleType::Binary, &invalid_hash, Policy::Allowlist);
        let result = validate_rule(&rule, 0);
        assert!(!result.valid);
        assert!(matches!(
            result.errors[0],
            ValidationError::InvalidSha256Hash { .. }
        ));
    }

    #[test]
    fn test_validate_cdhash() {
        // Valid CDHASH (40 hex chars)
        let valid_cdhash = "a".repeat(40);
        let rule = Rule::new(RuleType::Cdhash, &valid_cdhash, Policy::Allowlist);
        let result = validate_rule(&rule, 0);
        assert!(result.valid);

        // Invalid CDHASH (64 chars - SHA-256 format)
        let invalid_cdhash = "a".repeat(64);
        let rule = Rule::new(RuleType::Cdhash, &invalid_cdhash, Policy::Allowlist);
        let result = validate_rule(&rule, 0);
        assert!(!result.valid);
        assert!(matches!(
            result.errors[0],
            ValidationError::InvalidCdhash { .. }
        ));
    }

    #[test]
    fn test_validate_signing_id() {
        // Valid SigningID formats
        let valid_ids = [
            "EQHXZ8M8AV:com.google.Chrome",
            "platform:com.apple.Safari",
            "UBF8T346G9:com.microsoft.VSCode",
        ];

        for id in valid_ids {
            let rule = Rule::new(RuleType::SigningId, id, Policy::Allowlist);
            let result = validate_rule(&rule, 0);
            assert!(
                result.valid,
                "Expected '{}' to be valid, errors: {:?}",
                id, result.errors
            );
        }

        // Invalid SigningID formats
        let invalid_ids = [
            "com.google.Chrome",  // Missing TeamID prefix
            "EQHXZ8M8AV",         // Missing bundle ID
            ":com.google.Chrome", // Empty prefix
            "EQHXZ8M8AV:",        // Empty bundle ID
        ];

        for id in invalid_ids {
            let rule = Rule::new(RuleType::SigningId, id, Policy::Allowlist);
            let result = validate_rule(&rule, 0);
            assert!(!result.valid, "Expected '{}' to be invalid", id);
        }
    }

    #[test]
    fn test_validate_ring_names() {
        // Valid ring names
        let valid_rings = [
            "ring0",
            "ring1",
            "ring9",
            "canary",
            "production",
            "early_adopters",
            "ring-custom",
        ];
        for ring in valid_rings {
            assert!(is_valid_ring_name(ring), "Expected '{}' to be valid", ring);
        }

        // Invalid ring names
        let invalid_rings = ["", "ring with space"];
        for ring in invalid_rings {
            assert!(
                !is_valid_ring_name(ring),
                "Expected '{}' to be invalid",
                ring
            );
        }
    }

    #[test]
    fn test_validate_with_options() {
        let mut rules = RuleSet::new();
        for i in 0..20 {
            rules.add(Rule::new(
                RuleType::TeamId,
                format!("TEAM{:06}", i),
                Policy::Allowlist,
            ));
        }

        // Without group warning
        let options = ValidationOptions::default();
        let result = validate_ruleset_with_options(&rules, &options);
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| matches!(w, ValidationWarning::MissingGroup { .. }))
        );

        // With group warning enabled
        let options = ValidationOptions {
            warn_missing_groups: true,
            group_warning_threshold: 10,
        };
        let result = validate_ruleset_with_options(&rules, &options);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w, ValidationWarning::MissingGroup { .. }))
        );
    }

    #[test]
    fn test_suspicious_certificate_hash() {
        // TeamID used for certificate (common mistake)
        let rule = Rule::new(RuleType::Certificate, "EQHXZ8M8AV", Policy::Allowlist);
        let result = validate_rule(&rule, 0);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w, ValidationWarning::SuspiciousCertificateHash { .. }))
        );
    }
}
