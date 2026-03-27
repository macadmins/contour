//! Semantic validation for Santa CEL expressions.
//!
//! Checks field existence, type correctness, and V1/V2 gating beyond
//! what the CEL compiler's syntax check provides.

use regex::Regex;
use std::sync::LazyLock;

/// Known CEL field with its type and V2-only status.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: &'static str,
    pub field_type: &'static str,
    pub v2_only: bool,
}

/// All known Santa CEL fields (classification + execution context).
pub fn known_fields() -> Vec<FieldInfo> {
    vec![
        // Classification fields (app.*)
        FieldInfo {
            name: "app.app_name",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "app.signing_id",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "app.team_id",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "app.sha256",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "app.version",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "app.bundle_id",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "app.vendor",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "app.path",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "app.device_count",
            field_type: "uint",
            v2_only: false,
        },
        // Static execution fields (target.*)
        FieldInfo {
            name: "target.signing_id",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "target.team_id",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "target.signing_time",
            field_type: "timestamp",
            v2_only: false,
        },
        FieldInfo {
            name: "target.secure_signing_time",
            field_type: "timestamp",
            v2_only: false,
        },
        FieldInfo {
            name: "target.is_platform_binary",
            field_type: "bool",
            v2_only: false,
        },
        // Dynamic execution fields
        FieldInfo {
            name: "args",
            field_type: "list<string>",
            v2_only: false,
        },
        FieldInfo {
            name: "envs",
            field_type: "map<string,string>",
            v2_only: false,
        },
        FieldInfo {
            name: "euid",
            field_type: "int",
            v2_only: false,
        },
        FieldInfo {
            name: "cwd",
            field_type: "string",
            v2_only: false,
        },
        FieldInfo {
            name: "path",
            field_type: "string",
            v2_only: false,
        },
        // V2-only fields
        FieldInfo {
            name: "ancestors",
            field_type: "list<Ancestor>",
            v2_only: true,
        },
        FieldInfo {
            name: "fds",
            field_type: "list<FD>",
            v2_only: true,
        },
    ]
}

/// A validation issue found in a CEL expression.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: Severity,
    pub message: String,
    pub suggestion: Option<String>,
}

/// Issue severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// Validate a CEL expression for semantic correctness.
///
/// Extracts field references from the expression string and checks:
/// 1. All referenced fields exist in the catalog
/// 2. No V2-only fields are used unless `allow_v2` is set
/// 3. Suggests corrections for typos via Levenshtein distance
pub fn validate_expression(expression: &str, allow_v2: bool) -> Vec<ValidationIssue> {
    let fields = known_fields();
    let mut issues = Vec::new();

    let field_refs = extract_field_references(expression);

    for field_ref in &field_refs {
        if let Some(info) = fields.iter().find(|f| f.name == field_ref.as_str()) {
            // Field exists -- check V2 gating
            if info.v2_only && !allow_v2 {
                issues.push(ValidationIssue {
                    severity: Severity::Error,
                    message: format!("field '{}' requires CEL V2 (use action: cel_v2)", field_ref),
                    suggestion: None,
                });
            }
        } else {
            // Unknown field -- find closest match
            let suggestion = find_closest_field(field_ref, &fields);
            issues.push(ValidationIssue {
                severity: Severity::Error,
                message: format!("unknown field '{field_ref}'"),
                suggestion,
            });
        }
    }

    issues
}

/// Regex for dotted fields like `target.signing_id` or `app.team_id`.
static DOTTED_FIELD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(target|app)\.\w+").expect("invariant: hardcoded regex pattern is valid")
});

/// Regex for standalone top-level fields.
static STANDALONE_FIELD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(args|envs|euid|cwd|path|ancestors|fds)\b")
        .expect("invariant: hardcoded regex pattern is valid")
});

/// Extract field references from a CEL expression.
///
/// Skips content inside string literals (single or double quotes) so that
/// string values like `"target.team_id"` are not treated as field references.
fn extract_field_references(expression: &str) -> Vec<String> {
    let stripped = strip_string_literals(expression);
    let mut refs = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Match dotted fields: target.xxx, app.xxx
    for cap in DOTTED_FIELD_RE.find_iter(&stripped) {
        let field = cap.as_str().to_string();
        if seen.insert(field.clone()) {
            refs.push(field);
        }
    }

    // Match standalone fields (only if not already part of a dotted field)
    for cap in STANDALONE_FIELD_RE.find_iter(&stripped) {
        let field = cap.as_str().to_string();
        // Skip if this standalone match is the suffix of a dotted field we already captured
        let start = cap.start();
        let is_dotted = start > 0 && stripped.as_bytes().get(start - 1) == Some(&b'.');
        if !is_dotted && seen.insert(field.clone()) {
            refs.push(field);
        }
    }

    refs
}

/// Replace the contents of string literals with spaces so field-like patterns
/// inside strings are not matched.
fn strip_string_literals(expression: &str) -> String {
    let mut result = String::with_capacity(expression.len());
    let mut chars = expression.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\'' || ch == '"' {
            let quote = ch;
            result.push(quote);
            // Consume everything until the matching close quote
            for inner in chars.by_ref() {
                if inner == quote {
                    result.push(quote);
                    break;
                }
                // Replace literal content with a space
                result.push(' ');
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Find the closest matching field name for typo suggestions.
fn find_closest_field(input: &str, fields: &[FieldInfo]) -> Option<String> {
    fields
        .iter()
        .filter(|f| {
            let dist = levenshtein_distance(input, f.name);
            dist <= 3
        })
        .min_by_key(|f| levenshtein_distance(input, f.name))
        .map(|f| format!("did you mean '{}'?", f.name))
}

/// Standard Levenshtein distance between two strings.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    // Use a single-row buffer for space efficiency.
    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row = vec![0; b_len + 1];

    for (i, a_ch) in a.chars().enumerate() {
        curr_row[0] = i + 1;
        for (j, b_ch) in b.chars().enumerate() {
            let cost = usize::from(a_ch != b_ch);
            curr_row[j + 1] = (prev_row[j + 1] + 1)
                .min(curr_row[j] + 1)
                .min(prev_row[j] + cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_expression() {
        let issues = validate_expression(r#"target.team_id == "X""#, false);
        assert!(issues.is_empty(), "expected no issues, got: {issues:?}");
    }

    #[test]
    fn test_validate_unknown_field() {
        let issues = validate_expression(r#"target.signing_idd == "X""#, false);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(issues[0].message.contains("unknown field"));
        assert!(issues[0].message.contains("target.signing_idd"));
        let suggestion = issues[0].suggestion.as_deref().unwrap();
        assert!(
            suggestion.contains("target.signing_id"),
            "expected suggestion for signing_id, got: {suggestion}"
        );
    }

    #[test]
    fn test_validate_v2_field_rejected() {
        let issues = validate_expression(
            r#"ancestors.exists(a, a.signing_id == "com.apple.launchd")"#,
            false,
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(issues[0].message.contains("requires CEL V2"));
    }

    #[test]
    fn test_validate_v2_field_allowed() {
        let issues = validate_expression(
            r#"ancestors.exists(a, a.signing_id == "com.apple.launchd")"#,
            true,
        );
        assert!(issues.is_empty(), "expected no issues, got: {issues:?}");
    }

    #[test]
    fn test_levenshtein_distance_identical() {
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
    }

    #[test]
    fn test_levenshtein_distance_one_edit() {
        assert_eq!(levenshtein_distance("abc", "ab"), 1);
        assert_eq!(levenshtein_distance("abc", "abcd"), 1);
        assert_eq!(levenshtein_distance("abc", "aXc"), 1);
    }

    #[test]
    fn test_levenshtein_distance_empty() {
        assert_eq!(levenshtein_distance("", "abc"), 3);
        assert_eq!(levenshtein_distance("abc", ""), 3);
        assert_eq!(levenshtein_distance("", ""), 0);
    }

    #[test]
    fn test_extract_field_refs_skips_string_literals() {
        // "target.team_id" inside a string should NOT be extracted as a field ref
        let refs = extract_field_references(r#"app.vendor == "target.team_id""#);
        assert!(refs.contains(&"app.vendor".to_string()));
        assert!(!refs.contains(&"target.team_id".to_string()));
    }

    #[test]
    fn test_extract_field_refs_standalone() {
        let refs = extract_field_references("euid == 0 && cwd == '/tmp'");
        assert!(refs.contains(&"euid".to_string()));
        assert!(refs.contains(&"cwd".to_string()));
    }

    #[test]
    fn test_extract_field_refs_no_duplicates() {
        let refs = extract_field_references(r#"target.team_id == "X" || target.team_id == "Y""#);
        let count = refs
            .iter()
            .filter(|r| r.as_str() == "target.team_id")
            .count();
        assert_eq!(count, 1, "should deduplicate field references");
    }
}
