//! Public query API for the mSCP embedded schema data.
//!
//! Wraps the low-level Parquet readers from [`mscp_schema`] with convenient
//! lookup and filtering functions.

use anyhow::Result;
use mscp_schema::{
    BaselineEdge, BaselineMeta, EnvelopePattern, RulePayload, RuleVersioned, SkipKey,
};

/// Counts for every embedded dataset.
#[derive(Debug)]
pub struct SchemaStats {
    /// Alias for `baseline_meta` — number of baselines.
    pub baselines: usize,
    /// Alias for `rule_meta` — number of distinct rules.
    pub rules: usize,
    pub baseline_meta: usize,
    pub baseline_edges: usize,
    pub rules_versioned: usize,
    pub rule_payloads: usize,
    pub envelope_patterns: usize,
    pub envelope_meta_keys: usize,
    pub skip_keys: usize,
    pub rule_meta: usize,
    pub sections: usize,
    pub control_tiers: usize,
}

/// List all baseline metadata records.
pub fn list_baselines() -> Result<Vec<BaselineMeta>> {
    mscp_schema::baseline_meta::read(mscp_schema::embedded_baseline_meta())
}

/// List versioned rules that belong to a given baseline on a given platform.
///
/// This performs a join: it reads `baseline_edges` to find matching rule IDs,
/// then filters `rules_versioned` to those IDs on the requested platform.
pub fn list_baseline_rules(baseline: &str, platform: &str) -> Result<Vec<RuleVersioned>> {
    let edges: Vec<BaselineEdge> =
        mscp_schema::baseline_edges::read(mscp_schema::embedded_baseline_edges())?;

    let matching_rule_ids: Vec<&str> = edges
        .iter()
        .filter(|e| e.baseline == baseline && e.platform.as_deref().is_some_and(|p| p == platform))
        .map(|e| e.rule_id.as_str())
        .collect();

    let all_rules = mscp_schema::rules_versioned::read(mscp_schema::embedded_rules_versioned())?;

    let filtered = all_rules
        .into_iter()
        .filter(|r| r.platform == platform && matching_rule_ids.contains(&r.rule_id.as_str()))
        .collect();

    Ok(filtered)
}

/// Look up a single rule payload by rule ID.
pub fn get_rule_payload(rule_id: &str) -> Result<Option<RulePayload>> {
    let payloads = mscp_schema::rule_payloads::read(mscp_schema::embedded_rule_payloads())?;
    Ok(payloads.into_iter().find(|p| p.rule_id == rule_id))
}

/// List all envelope patterns.
pub fn list_envelope_patterns() -> Result<Vec<EnvelopePattern>> {
    mscp_schema::envelope_patterns::read(mscp_schema::embedded_envelope_patterns())
}

/// List skip keys filtered by platform and optionally by OS version.
///
/// When `os_version` is provided, a key is included if:
/// - `introduced` is `None` **or** `introduced <= os_version`, **and**
/// - `removed` is `None` **or** `removed > os_version`.
pub fn list_skip_keys(platform: &str, os_version: Option<&str>) -> Result<Vec<SkipKey>> {
    let all = mscp_schema::skip_keys::read(mscp_schema::embedded_skip_keys())?;

    let filtered = all
        .into_iter()
        .filter(|k| {
            if k.platform != platform {
                return false;
            }
            if let Some(ver) = os_version {
                let introduced_ok = k.introduced.as_deref().is_none_or(|intro| intro <= ver);
                let not_removed = k.removed.as_deref().is_none_or(|rem| rem > ver);
                introduced_ok && not_removed
            } else {
                true
            }
        })
        .collect();

    Ok(filtered)
}

/// Compute counts for every embedded dataset.
pub fn schema_stats() -> Result<SchemaStats> {
    let baseline_meta_count =
        mscp_schema::baseline_meta::read(mscp_schema::embedded_baseline_meta())?.len();
    let rule_meta_count = mscp_schema::rule_meta::read(mscp_schema::embedded_rule_meta())?.len();

    Ok(SchemaStats {
        baselines: baseline_meta_count,
        rules: rule_meta_count,
        baseline_meta: baseline_meta_count,
        baseline_edges: mscp_schema::baseline_edges::read(mscp_schema::embedded_baseline_edges())?
            .len(),
        rules_versioned: mscp_schema::rules_versioned::read(
            mscp_schema::embedded_rules_versioned(),
        )?
        .len(),
        rule_payloads: mscp_schema::rule_payloads::read(mscp_schema::embedded_rule_payloads())?
            .len(),
        envelope_patterns: mscp_schema::envelope_patterns::read(
            mscp_schema::embedded_envelope_patterns(),
        )?
        .len(),
        envelope_meta_keys: mscp_schema::envelope_meta_keys::read(
            mscp_schema::embedded_envelope_meta_keys(),
        )?
        .len(),
        skip_keys: mscp_schema::skip_keys::read(mscp_schema::embedded_skip_keys())?.len(),
        rule_meta: rule_meta_count,
        sections: mscp_schema::sections::read(mscp_schema::embedded_sections())?.len(),
        control_tiers: mscp_schema::control_tiers::read(mscp_schema::embedded_control_tiers())?
            .len(),
    })
}

/// Full detail for a single rule including payload and baseline membership.
#[derive(Debug, Clone)]
pub struct RuleDetail {
    pub rule: mscp_schema::RuleVersioned,
    pub payload: Option<mscp_schema::RulePayload>,
    pub baselines: Vec<String>,
}

/// Search rules by keyword across rule_id, title, and tags. Case-insensitive.
pub fn search_rules(query: &str, platform: Option<&str>) -> Result<Vec<RuleVersioned>> {
    let query_lower = query.to_lowercase();
    let rules = mscp_schema::rules_versioned::read(mscp_schema::embedded_rules_versioned())?;
    Ok(rules
        .into_iter()
        .filter(|r| {
            let matches = r.rule_id.to_lowercase().contains(&query_lower)
                || r.title.to_lowercase().contains(&query_lower)
                || r.tags
                    .iter()
                    .any(|t| t.to_lowercase().contains(&query_lower));
            let platform_ok = platform.is_none_or(|p| r.platform.eq_ignore_ascii_case(p));
            matches && platform_ok
        })
        .collect())
}

/// Get full detail for a single rule.
pub fn get_rule_detail(rule_id: &str) -> Result<Option<RuleDetail>> {
    let rules = mscp_schema::rules_versioned::read(mscp_schema::embedded_rules_versioned())?;
    let rule = rules.into_iter().find(|r| r.rule_id == rule_id);
    let Some(rule) = rule else {
        return Ok(None);
    };

    let payloads = mscp_schema::rule_payloads::read(mscp_schema::embedded_rule_payloads())?;
    let payload = payloads.into_iter().find(|p| p.rule_id == rule_id);

    let edges = mscp_schema::baseline_edges::read(mscp_schema::embedded_baseline_edges())?;
    let baselines: Vec<String> = edges
        .iter()
        .filter(|e| e.rule_id == rule_id)
        .map(|e| e.baseline.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    Ok(Some(RuleDetail {
        rule,
        payload,
        baselines,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_baselines() {
        let baselines = list_baselines().expect("list_baselines failed");
        assert!(
            baselines.len() >= 10,
            "Expected at least 10 baselines, got {}",
            baselines.len()
        );
    }

    #[test]
    fn test_list_baseline_rules() {
        let rules = list_baseline_rules("cis_lvl1", "macOS").expect("list_baseline_rules failed");
        assert!(
            !rules.is_empty(),
            "Expected non-empty rules for cis_lvl1 macOS"
        );
    }

    #[test]
    fn test_get_rule_payload() {
        let rules = list_baseline_rules("cis_lvl1", "macOS").expect("list_baseline_rules failed");
        let first_rule_id = &rules
            .first()
            .expect("cis_lvl1 macOS should have at least one rule")
            .rule_id;
        let payload = get_rule_payload(first_rule_id).expect("get_rule_payload failed");
        assert!(
            payload.is_some(),
            "Expected payload for rule {first_rule_id}"
        );
    }

    #[test]
    fn test_get_rule_payload_unknown() {
        let payload = get_rule_payload("nonexistent_rule_that_does_not_exist_12345")
            .expect("get_rule_payload failed");
        assert!(payload.is_none(), "Expected None for nonexistent rule");
    }

    #[test]
    fn test_list_envelope_patterns() {
        let patterns = list_envelope_patterns().expect("list_envelope_patterns failed");
        assert!(
            patterns.len() >= 3,
            "Expected at least 3 envelope patterns, got {}",
            patterns.len()
        );
    }

    #[test]
    fn test_list_skip_keys() {
        let keys = list_skip_keys("macOS", None).expect("list_skip_keys failed");
        assert!(!keys.is_empty(), "Expected non-empty skip keys for macOS");
    }

    #[test]
    fn test_schema_stats() {
        let stats = schema_stats().expect("schema_stats failed");
        assert!(stats.baseline_meta > 0, "baseline_meta count should be > 0");
        assert!(
            stats.baseline_edges > 0,
            "baseline_edges count should be > 0"
        );
        assert!(
            stats.rules_versioned > 0,
            "rules_versioned count should be > 0"
        );
        assert!(stats.rule_payloads > 0, "rule_payloads count should be > 0");
        assert!(
            stats.envelope_patterns > 0,
            "envelope_patterns count should be > 0"
        );
        assert!(
            stats.envelope_meta_keys > 0,
            "envelope_meta_keys count should be > 0"
        );
        assert!(stats.skip_keys > 0, "skip_keys count should be > 0");
        assert!(stats.rule_meta > 0, "rule_meta count should be > 0");
        assert!(stats.sections > 0, "sections count should be > 0");
        assert!(stats.control_tiers > 0, "control_tiers count should be > 0");
    }

    #[test]
    fn test_search_rules_airdrop() {
        let results = search_rules("airdrop", None).expect("search_rules failed");
        assert!(
            !results.is_empty(),
            "Expected non-empty results for 'airdrop'"
        );
        assert!(
            results[0].rule_id.to_lowercase().contains("airdrop"),
            "Expected first result rule_id to contain 'airdrop', got: {}",
            results[0].rule_id
        );
    }

    #[test]
    fn test_search_rules_with_platform() {
        let results =
            search_rules("airdrop", Some("macOS")).expect("search_rules with platform failed");
        assert!(
            !results.is_empty(),
            "Expected non-empty results for 'airdrop' on macOS"
        );
    }

    #[test]
    fn test_search_rules_no_results() {
        let results =
            search_rules("zzz_nonexistent", None).expect("search_rules no results failed");
        assert!(
            results.is_empty(),
            "Expected empty results for nonsense query"
        );
    }

    #[test]
    fn test_get_rule_detail_exists() {
        let detail = get_rule_detail("os_airdrop_disable").expect("get_rule_detail failed");
        assert!(detail.is_some(), "Expected Some for os_airdrop_disable");
        let detail = detail.unwrap();
        assert!(
            !detail.baselines.is_empty(),
            "Expected non-empty baselines for os_airdrop_disable"
        );
    }

    #[test]
    fn test_get_rule_detail_missing() {
        let detail = get_rule_detail("nonexistent").expect("get_rule_detail failed");
        assert!(detail.is_none(), "Expected None for nonexistent rule");
    }
}
