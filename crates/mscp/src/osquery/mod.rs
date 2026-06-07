//! mSCP → osquery bridge: classify rules onto osquery tables (Tier 1) or a
//! results-plist audit script (Tier 2), then render via an output adapter.

pub mod adapters;
pub mod audit_script;
pub mod catalog;
pub mod classify;
pub mod query;
pub mod report;

use catalog::OsqueryTable;

/// Detection tier for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Native osquery table query.
    Native,
    /// Covered by the audit script + results plist.
    Residual,
    /// Excluded (mSCP helper, not a real check).
    Excluded,
}

/// Effective coverage of a rule after query-building — the honest outcome the
/// report and the audit script both consume.
///
/// Distinct from [`Tier`] (the optimistic classification): a `Tier::Native` rule
/// whose query can't be built becomes [`Coverage::Script`] (covered by an audit
/// block) or, lacking any check, [`Coverage::Uncovered`] (reported, no policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Emitted a native osquery-table query.
    Native,
    /// Covered by an audit block + plist-reading policy.
    Script,
    /// No native query and no check to audit — surfaced as a gap, no policy.
    Uncovered,
    /// mSCP helper, not a real check.
    Excluded,
}

/// How a single rule was routed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub rule_id: String,
    pub tier: Tier,
    pub table: Option<OsqueryTable>,
    pub reason: &'static str,
}

impl Classification {
    /// Optimistic osquery coverage for a single rule — `(osquery_checkable,
    /// osquery_table)` — as surfaced by `schema rule --json`.
    ///
    /// "Checkable" means answerable by osquery *somehow*: a native table, or the
    /// Tier-2 audit-plist pattern (any rule with a check). Only `Tier::Excluded`
    /// (mSCP helpers) and check-less residual rules are not checkable.
    ///
    /// This is the classification-level view; it omits the query-build downgrade
    /// (`Tier::Native` → [`Coverage::Script`]) that only the emitting
    /// [`build`] pass can determine.
    pub fn osquery_coverage(&self, has_check: bool) -> (bool, Option<&'static str>) {
        match self.tier {
            Tier::Excluded => (false, None),
            Tier::Native => (true, self.table.map(OsqueryTable::name)),
            Tier::Residual => (has_check, None),
        }
    }
}

/// Audit-script scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditScope {
    /// Only residual rules (Tier-1 rules use native queries).
    Slim,
    /// All rules (no native queries emitted).
    Full,
}

/// Output adapter selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsqueryFormat {
    Fleet,
    Pack,
}

impl OsqueryFormat {
    /// Parse the `--osquery-format` value.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "fleet" => Ok(Self::Fleet),
            "pack" => Ok(Self::Pack),
            o => anyhow::bail!("unknown --osquery-format '{o}' (fleet|pack)"),
        }
    }
}

impl AuditScope {
    /// Parse the `--osquery-audit` value.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "slim" => Ok(Self::Slim),
            "full" => Ok(Self::Full),
            o => anyhow::bail!("unknown --osquery-audit '{o}' (slim|full)"),
        }
    }
}

/// CLI-facing osquery generation request, threaded from `mscp generate
/// --osquery [...]` down into [`crate::cli::process_baseline`].
///
/// `None` at the call site means osquery emission is disabled. `org` is the
/// reverse-domain identifier used for the audit results-plist path and the
/// launchd label; it is plumbed alongside the flags so the bridge does not have
/// to re-derive it from config.
#[derive(Debug, Clone)]
pub struct OsqueryGenOptions {
    /// `--osquery-format` (fleet|pack); parsed via [`OsqueryFormat::parse`].
    pub format: String,
    /// `--osquery-audit` (slim|full); parsed via [`AuditScope::parse`].
    pub audit: String,
    /// Organization reverse-domain identifier (e.g. `com.acme`). Required: when
    /// no org can be resolved upstream, `--osquery` errors (see
    /// `cli/process.rs`); it never falls back to a placeholder org.
    pub org: Option<String>,
}

use crate::models::MscpRule;
use audit_script::{AuditScript, plist_policy_sql};

/// One emitted osquery query (rule_id + SQL + description).
#[derive(Debug, Clone)]
pub struct OsqueryQuery {
    pub rule_id: String,
    pub title: String,
    pub sql: String,
}

/// Everything the bridge produced for a baseline, before adapter rendering.
#[derive(Debug)]
pub struct OsqueryArtifacts {
    pub queries: Vec<OsqueryQuery>,
    pub audit: AuditScript,
    /// Per-rule routing decisions, retained for callers that want to inspect or
    /// re-report classification (the `mscp` binary writes only `coverage_md`).
    #[allow(
        dead_code,
        reason = "public API consumed by adapters/tests; unused in the bin build"
    )]
    pub classifications: Vec<Classification>,
    pub coverage_md: String,
}

/// Classify + generate queries and the audit script for a baseline.
///
/// `mp_query` builds the `managed_policies` SQL for a rule (provided by the caller
/// so we reuse `transformers/fleet_policy.rs` rather than duplicating it).
pub fn build(
    rules: &[MscpRule],
    org: &str,
    baseline: &str,
    scope: AuditScope,
    mp_query: impl Fn(&MscpRule) -> Option<String>,
) -> OsqueryArtifacts {
    let classifications: Vec<Classification> = rules.iter().map(classify::classify).collect();

    // Pass 1: decide each rule's *effective* coverage and its native SQL (if any).
    // A Tier::Native rule whose query can't be built downgrades to Script (audit
    // block) when it has a check, else Uncovered. Full scope forces everything to
    // the audit plist (no native queries).
    let mut coverage: Vec<Coverage> = Vec::with_capacity(rules.len());
    let mut native_sql: Vec<Option<String>> = Vec::with_capacity(rules.len());
    for (rule, c) in rules.iter().zip(&classifications) {
        if c.tier == Tier::Excluded {
            coverage.push(Coverage::Excluded);
            native_sql.push(None);
            continue;
        }
        let sql = if scope == AuditScope::Slim && c.tier == Tier::Native {
            match c.table {
                Some(catalog::OsqueryTable::ManagedPolicies) => mp_query(rule),
                Some(t) => query::build(t, rule),
                None => None,
            }
        } else {
            None
        };
        coverage.push(if sql.is_some() {
            Coverage::Native
        } else if rule.check.is_some() {
            Coverage::Script
        } else {
            Coverage::Uncovered
        });
        native_sql.push(sql);
    }

    // The audit script covers exactly the Script-coverage rules, so every plist
    // key it writes has a matching policy below — and no policy reads a key the
    // script never writes (the invariant the report depends on).
    let covered: Vec<&MscpRule> = rules
        .iter()
        .zip(&coverage)
        .filter(|(_, cov)| **cov == Coverage::Script)
        .map(|(r, _)| r)
        .collect();
    let audit = audit_script::generate(&covered, org, baseline);

    // Pass 2: emit queries — native SQL for Native, a plist-reading policy for
    // Script; Uncovered/Excluded rules get no query.
    let mut queries = Vec::new();
    for ((rule, cov), sql) in rules.iter().zip(&coverage).zip(native_sql) {
        let sql = match cov {
            Coverage::Native => sql.expect("Native coverage implies a built query"),
            Coverage::Script => plist_policy_sql(&audit.plist_path, &rule.id),
            Coverage::Uncovered | Coverage::Excluded => continue,
        };
        queries.push(OsqueryQuery {
            rule_id: rule.id.clone(),
            title: rule.title.clone(),
            sql,
        });
    }

    let coverage_md = report::coverage_markdown(&classifications, &coverage, baseline);
    OsqueryArtifacts {
        queries,
        audit,
        classifications,
        coverage_md,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mobileconfig-scalar rule classifies Native (managed_policies), but if its
    /// native query can't be built it must fall back to a Tier-2 audit block — not
    /// a plist-reading Fleet policy whose key the audit script never writes.
    /// Regression guard for the "downgraded-native → phantom policy" bug.
    #[test]
    fn downgraded_native_gets_audit_block_not_phantom_policy() {
        let mut rule = MscpRule {
            id: "system_settings_x_enforce".to_string(),
            check: Some("/usr/bin/profiles -P | /usr/bin/grep -c foo".to_string()),
            mobileconfig: true,
            ..Default::default()
        };
        // All-scalar mobileconfig info → classify() returns Native/managed_policies.
        rule.mobileconfig_info =
            Some(yaml_serde::from_str("com.apple.x:\n  Enabled: true").unwrap());

        // mp_query returns None → the native query can't be built (downgrade path).
        let art = build(&[rule], "com.org", "disa_stig", AuditScope::Slim, |_| None);

        // The rule must be covered by an audit block (its key gets written)…
        assert!(
            art.audit
                .covered
                .contains(&"system_settings_x_enforce".to_string()),
            "downgraded native rule must get an audit block; covered={:?}",
            art.audit.covered
        );
        // …and every plist-reading policy key must be written by the audit script.
        for q in &art.queries {
            if let Some(key) = plist_key_of(&q.sql) {
                assert!(
                    art.audit.covered.contains(&key.to_string()),
                    "policy reads plist key '{key}' that no audit block writes"
                );
            }
        }
    }

    /// Extract the `key = '<id>'` value from a plist-policy SQL string, if present.
    fn plist_key_of(sql: &str) -> Option<&str> {
        let after = sql.split("key = '").nth(1)?;
        after.split('\'').next()
    }

    fn classification(tier: Tier, table: Option<OsqueryTable>) -> Classification {
        Classification {
            rule_id: "r".to_string(),
            tier,
            table,
            reason: "test",
        }
    }

    #[test]
    fn osquery_coverage_native_is_checkable_with_table() {
        let c = classification(Tier::Native, Some(OsqueryTable::LaunchdOverrides));
        assert_eq!(c.osquery_coverage(true), (true, Some("launchd_overrides")));
    }

    #[test]
    fn osquery_coverage_excluded_is_never_checkable() {
        let c = classification(Tier::Excluded, None);
        assert_eq!(c.osquery_coverage(true), (false, None));
    }

    #[test]
    fn osquery_coverage_residual_follows_has_check() {
        let c = classification(Tier::Residual, None);
        // Audit-plist covered when it has a check…
        assert_eq!(c.osquery_coverage(true), (true, None));
        // …but uncovered when there is nothing to audit.
        assert_eq!(c.osquery_coverage(false), (false, None));
    }
}
