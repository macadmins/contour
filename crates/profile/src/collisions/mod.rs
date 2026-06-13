//! Cross-profile payload-domain collision detection.
//!
//! Detects when two or more *separate* profiles or DDM declarations manage the
//! **same payload domain** (a `.mobileconfig` `PayloadType` or a DDM declaration
//! `Type`) within a single co-apply scope — which macOS does not reliably merge —
//! and classifies each managed key as a value **conflict**, **redundant** (same
//! value everywhere), or **complementary** (set in only one file).
//!
//! Pure logic, no IO: the CLI layer (`crate::cli::collisions`) collects + parses
//! files into [`PayloadRecord`]s and feeds them to [`index_collisions`].

use std::collections::{BTreeMap, BTreeSet};

/// Source format of a payload record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Mobileconfig,
    Ddm,
}

/// One managed payload (a profile payload, or a DDM declaration) found in the scan.
#[derive(Debug, Clone)]
pub struct PayloadRecord {
    /// Co-apply scope — the file's parent directory, or `"<flat>"` when `--flat`.
    pub scope: String,
    /// Payload domain: the `PayloadType` (mobileconfig) or declaration `Type` (DDM).
    pub domain: String,
    /// Source file this payload came from.
    pub source_file: String,
    pub format: Format,
    /// Meaningful config keys → canonical value string (envelope keys excluded).
    pub keys: BTreeMap<String, String>,
}

/// Per-key verdict within a colliding domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyVerdict {
    /// Set in 2+ files with **different** values — the dangerous case.
    Conflict,
    /// Set in 2+ files with the **same** value — safe to dedupe.
    Redundant,
    /// Set in exactly one file — the keys to port when consolidating.
    Complementary,
}

/// Analysis of one key across the files managing a domain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyAnalysis {
    pub key: String,
    pub verdict: KeyVerdict,
    /// file → canonical value (only the files that set this key).
    pub values: BTreeMap<String, String>,
}

/// A domain managed by 2+ files within one scope.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DomainCollision {
    pub scope: String,
    pub domain: String,
    pub format: Format,
    /// Files that manage this domain (sorted, unique).
    pub files: Vec<String>,
    pub keys: Vec<KeyAnalysis>,
}

impl DomainCollision {
    pub fn has_conflict(&self) -> bool {
        self.keys.iter().any(|k| k.verdict == KeyVerdict::Conflict)
    }
}

/// Full collision report.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CollisionReport {
    pub collisions: Vec<DomainCollision>,
    pub files_scanned: usize,
    pub payloads_scanned: usize,
}

impl CollisionReport {
    pub fn conflict_count(&self) -> usize {
        self.collisions.iter().filter(|c| c.has_conflict()).count()
    }
    pub fn is_empty(&self) -> bool {
        self.collisions.is_empty()
    }
}

/// Standard payload *envelope* metadata keys — excluded from the managed-key
/// comparison. Note `PayloadContent` is deliberately NOT here: inside a
/// `com.apple.ManagedClient.preferences` payload it holds the actual managed-pref
/// settings, so a blanket `Payload*` prefix-strip would wrongly drop all of it.
const ENVELOPE_KEYS: &[&str] = &[
    "PayloadType",
    "PayloadVersion",
    "PayloadIdentifier",
    "PayloadUUID",
    "PayloadDisplayName",
    "PayloadDescription",
    "PayloadOrganization",
    "PayloadEnabled",
    "PayloadScope",
    "PayloadRemovalDisallowed",
];

/// True when `key` is a standard payload-envelope metadata key (not real config).
pub fn is_envelope_key(key: &str) -> bool {
    ENVELOPE_KEYS.contains(&key)
}

/// Group records into per-`(scope, domain)` collisions. A collision requires the
/// domain to be managed by **2+ distinct files** in the same scope.
pub fn index_collisions(records: &[PayloadRecord]) -> Vec<DomainCollision> {
    let mut groups: BTreeMap<(String, String), Vec<&PayloadRecord>> = BTreeMap::new();
    for r in records {
        groups
            .entry((r.scope.clone(), r.domain.clone()))
            .or_default()
            .push(r);
    }

    let mut out = Vec::new();
    for ((scope, domain), recs) in groups {
        let mut files: Vec<String> = recs.iter().map(|r| r.source_file.clone()).collect();
        files.sort();
        files.dedup();
        if files.len() < 2 {
            continue; // 0 or 1 file manages this domain here — not a collision.
        }
        let format = recs[0].format;
        let keys = analyze_domain(&recs);
        out.push(DomainCollision {
            scope,
            domain,
            format,
            files,
            keys,
        });
    }
    out
}

/// Per-key verdicts across the records managing one domain.
pub fn analyze_domain(records: &[&PayloadRecord]) -> Vec<KeyAnalysis> {
    // key → (file → canonical value)
    let mut by_key: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for r in records {
        for (k, v) in &r.keys {
            by_key
                .entry(k.clone())
                .or_default()
                .insert(r.source_file.clone(), v.clone());
        }
    }

    by_key
        .into_iter()
        .map(|(key, values)| {
            let distinct: BTreeSet<&String> = values.values().collect();
            let verdict = if values.len() < 2 {
                KeyVerdict::Complementary
            } else if distinct.len() > 1 {
                KeyVerdict::Conflict
            } else {
                KeyVerdict::Redundant
            };
            KeyAnalysis {
                key,
                verdict,
                values,
            }
        })
        .collect()
}

/// Canonical, comparable string for a plist value (dict keys sorted, so two
/// equal-but-differently-ordered dicts compare equal). Scalars use the stable
/// `Debug` form.
pub fn canonical_plist(v: &plist::Value) -> String {
    match v {
        plist::Value::String(s) => s.clone(),
        plist::Value::Boolean(b) => b.to_string(),
        plist::Value::Integer(i) => i.to_string(),
        plist::Value::Real(r) => r.to_string(),
        plist::Value::Array(a) => {
            let parts: Vec<String> = a.iter().map(canonical_plist).collect();
            format!("[{}]", parts.join(","))
        }
        plist::Value::Dictionary(d) => {
            let mut entries: Vec<(String, String)> = d
                .iter()
                .map(|(k, val)| (k.clone(), canonical_plist(val)))
                .collect();
            entries.sort();
            let parts: Vec<String> = entries
                .into_iter()
                .map(|(k, val)| format!("{k}={val}"))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        // Data / Date / Uid — rare in config keys; stable Debug form.
        other => format!("{other:?}"),
    }
}

/// Canonical, comparable string for a JSON value (object keys sorted).
pub fn canonical_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(m) => {
            let mut entries: Vec<(&String, String)> =
                m.iter().map(|(k, val)| (k, canonical_json(val))).collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let parts: Vec<String> = entries
                .into_iter()
                .map(|(k, val)| format!("{k}={val}"))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(a) => {
            let parts: Vec<String> = a.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(scope: &str, domain: &str, file: &str, keys: &[(&str, &str)]) -> PayloadRecord {
        PayloadRecord {
            scope: scope.into(),
            domain: domain.into(),
            source_file: file.into(),
            format: Format::Mobileconfig,
            keys: keys
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn single_file_domain_is_not_a_collision() {
        let recs = vec![rec("a", "com.apple.x", "a/one.mobileconfig", &[("K", "1")])];
        assert!(index_collisions(&recs).is_empty());
    }

    #[test]
    fn two_files_same_domain_classify_keys() {
        let recs = vec![
            rec(
                "a",
                "com.apple.x",
                "a/cis.mobileconfig",
                &[("Shared", "1"), ("OnlyCis", "9")],
            ),
            rec(
                "a",
                "com.apple.x",
                "a/org.mobileconfig",
                &[("Shared", "2"), ("OnlyOrg", "5")],
            ),
        ];
        let cols = index_collisions(&recs);
        assert_eq!(cols.len(), 1);
        let c = &cols[0];
        assert_eq!(c.files.len(), 2);
        let verdict = |k: &str| c.keys.iter().find(|a| a.key == k).map(|a| a.verdict);
        assert_eq!(verdict("Shared"), Some(KeyVerdict::Conflict)); // 1 vs 2
        assert_eq!(verdict("OnlyCis"), Some(KeyVerdict::Complementary));
        assert_eq!(verdict("OnlyOrg"), Some(KeyVerdict::Complementary));
        assert!(c.has_conflict());
    }

    #[test]
    fn redundant_key_is_not_a_conflict() {
        let recs = vec![
            rec("a", "com.apple.x", "a/one.mobileconfig", &[("K", "same")]),
            rec("a", "com.apple.x", "a/two.mobileconfig", &[("K", "same")]),
        ];
        let cols = index_collisions(&recs);
        assert_eq!(cols[0].keys[0].verdict, KeyVerdict::Redundant);
        assert!(!cols[0].has_conflict());
    }

    #[test]
    fn different_scopes_do_not_collide() {
        // Same domain, but in two different (per-directory) scopes — multi-tenant case.
        let recs = vec![
            rec(
                "tenant-a",
                "com.apple.x",
                "tenant-a/p.mobileconfig",
                &[("K", "1")],
            ),
            rec(
                "tenant-b",
                "com.apple.x",
                "tenant-b/p.mobileconfig",
                &[("K", "2")],
            ),
        ];
        assert!(index_collisions(&recs).is_empty());

        // …but if both are flattened into one scope, they collide.
        let flat: Vec<PayloadRecord> = recs
            .into_iter()
            .map(|mut r| {
                r.scope = "<flat>".into();
                r
            })
            .collect();
        assert_eq!(index_collisions(&flat).len(), 1);
    }

    #[test]
    fn payload_content_is_not_an_envelope_key() {
        // Regression: ManagedClient.preferences nests its settings under a key
        // literally named `PayloadContent` — it must be kept, not stripped.
        assert!(!is_envelope_key("PayloadContent"));
        assert!(is_envelope_key("PayloadDisplayName"));
        assert!(is_envelope_key("PayloadOrganization"));
        assert!(!is_envelope_key("allowCamera"));
    }

    #[test]
    fn canonical_dict_is_order_independent() {
        let a = plist::Value::Dictionary({
            let mut d = plist::Dictionary::new();
            d.insert("b".into(), plist::Value::Integer(2.into()));
            d.insert("a".into(), plist::Value::Integer(1.into()));
            d
        });
        let b = plist::Value::Dictionary({
            let mut d = plist::Dictionary::new();
            d.insert("a".into(), plist::Value::Integer(1.into()));
            d.insert("b".into(), plist::Value::Integer(2.into()));
            d
        });
        assert_eq!(canonical_plist(&a), canonical_plist(&b));
    }
}
