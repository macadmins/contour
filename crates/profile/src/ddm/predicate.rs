//! NSPredicate reference extraction for DDM activations.
//!
//! Apple's DDM activation declarations carry an optional `Predicate`
//! string (NSPredicate format, evaluated on-device). The predicate may
//! reference:
//!
//! - **`@status('key')`** — a status item the device exposes via a
//!   `com.apple.management.status-subscriptions` declaration. If the
//!   key isn't subscribed, the device returns
//!   `Error.UnableToEvaluatePredicate` and the activation never
//!   installs (different from `Error.PredicateFailed`, which means
//!   the predicate cleanly evaluated to `false`).
//! - **`@property('key')`** — a built-in device property (e.g.
//!   `device.identifier.serial-number`). No subscription required;
//!   Apple maintains the property set.
//!
//! This module extracts both kinds of references from a predicate
//! string. It does **not** evaluate the predicate or validate the
//! NSPredicate syntax beyond reference extraction — for a full
//! evaluator you need Apple's runtime (`NSPredicate` from Foundation).
//!
//! The extractor exists so `compose` can fail with
//! `UnsubscribedStatusKey` at authoring time (PRECONDITION) and so
//! `ddm verify <dir>` can cross-check predicates against
//! status-subscriptions across a set of declarations.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;

/// Status and property keys referenced by an NSPredicate string.
///
/// Both fields are sorted and deduplicated for stable output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PredicateKeys {
    /// Keys referenced via `@status('key')` — must be subscribed via a
    /// `com.apple.management.status-subscriptions` declaration on the
    /// same device.
    pub status: Vec<String>,
    /// Keys referenced via `@property('key')` — built-in device
    /// properties. No subscription required, but the key must be one
    /// Apple recognizes (we don't validate that here).
    pub property: Vec<String>,
}

impl PredicateKeys {
    /// True if the predicate references no `@status` or `@property` keys.
    pub fn is_empty(&self) -> bool {
        self.status.is_empty() && self.property.is_empty()
    }
}

/// Extract `@status(...)` and `@property(...)` references from an
/// NSPredicate format string.
///
/// Tolerates whitespace and both quote styles. Returned keys are
/// deduplicated and sorted alphabetically.
///
/// Example:
/// ```ignore
/// let keys = extract_predicate_keys(
///     "@status('passcode.is-compliant') == TRUE AND \
///      @property('device.model.identifier') BEGINSWITH 'Mac15,'"
/// );
/// assert_eq!(keys.status,   ["passcode.is-compliant"]);
/// assert_eq!(keys.property, ["device.model.identifier"]);
/// ```
pub fn extract_predicate_keys(predicate: &str) -> PredicateKeys {
    PredicateKeys {
        status: extract_with(predicate, status_re()),
        property: extract_with(predicate, property_re()),
    }
}

fn extract_with(predicate: &str, re: &Regex) -> Vec<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for cap in re.captures_iter(predicate) {
        if let Some(m) = cap.get(1) {
            seen.insert(m.as_str().to_string());
        }
    }
    seen.into_iter().collect()
}

fn status_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // @status('key') or @status("key") with optional whitespace.
        // Captured group 1 = the key (string between the quotes).
        Regex::new(r#"@status\s*\(\s*['"]([^'"]+)['"]\s*\)"#).expect("status regex compiles")
    })
}

fn property_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"@property\s*\(\s*['"]([^'"]+)['"]\s*\)"#).expect("property regex compiles")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_yields_no_keys() {
        let keys = extract_predicate_keys("");
        assert!(keys.is_empty());
    }

    #[test]
    fn predicate_without_at_refs_yields_no_keys() {
        let keys = extract_predicate_keys("TRUE");
        assert!(keys.is_empty());
    }

    #[test]
    fn extracts_single_status_key_single_quotes() {
        let keys = extract_predicate_keys("@status('passcode.is-compliant') == TRUE");
        assert_eq!(keys.status, vec!["passcode.is-compliant"]);
        assert!(keys.property.is_empty());
    }

    #[test]
    fn extracts_single_status_key_double_quotes() {
        let keys = extract_predicate_keys(r#"@status("passcode.is-compliant") == TRUE"#);
        assert_eq!(keys.status, vec!["passcode.is-compliant"]);
    }

    #[test]
    fn tolerates_whitespace_in_call() {
        let keys = extract_predicate_keys("@status ( 'k' ) == TRUE");
        assert_eq!(keys.status, vec!["k"]);
    }

    #[test]
    fn extracts_multiple_status_keys_dedup_and_sort() {
        let keys = extract_predicate_keys(
            "@status('zeta') == TRUE AND @status('alpha') == TRUE AND @status('zeta') != FALSE",
        );
        assert_eq!(keys.status, vec!["alpha", "zeta"]);
    }

    #[test]
    fn extracts_property_keys_alongside_status() {
        let keys = extract_predicate_keys(
            "@status('passcode.is-compliant') == TRUE AND \
             @property('device.model.identifier') BEGINSWITH 'Mac15,'",
        );
        assert_eq!(keys.status, vec!["passcode.is-compliant"]);
        assert_eq!(keys.property, vec!["device.model.identifier"]);
    }

    #[test]
    fn ignores_unrelated_at_tokens() {
        // @count, @sum, @average etc. are NSPredicate aggregate functions
        // we should not capture.
        let keys = extract_predicate_keys("@count(items) > 0 AND @status('k') == TRUE");
        assert_eq!(keys.status, vec!["k"]);
    }

    #[test]
    fn handles_dotted_keys() {
        // Apple's status keys are typically dotted (passcode.is-compliant,
        // softwareupdate.install-state, etc.).
        let keys = extract_predicate_keys("@status('softwareupdate.install-state') == 'Idle'");
        assert_eq!(keys.status, vec!["softwareupdate.install-state"]);
    }

    #[test]
    fn handles_complex_compound_predicate() {
        let p = "(@status('passcode.is-compliant') == TRUE) AND \
                 (NOT @status('softwareupdate.install-state') == 'Idle') AND \
                 ('EAS' IN @status('account.list.exchange.protocol-types'))";
        let keys = extract_predicate_keys(p);
        assert_eq!(
            keys.status,
            vec![
                "account.list.exchange.protocol-types",
                "passcode.is-compliant",
                "softwareupdate.install-state",
            ]
        );
    }

    #[test]
    fn empty_string_inside_parens_does_not_capture_empty_key() {
        // @status('') with empty key — current regex requires at least one
        // non-quote char, so empty keys are silently ignored. That's fine
        // for our purposes; a downstream consumer would catch the bad
        // predicate via a different path (deploy-time evaluation error).
        let keys = extract_predicate_keys("@status('') == TRUE");
        assert!(keys.status.is_empty());
    }
}
