use std::collections::{HashMap, HashSet};

use anyhow::Result;

use crate::models::MscpRule;

/// Convert a `serde_json::Value` into a `yaml_serde::Value`.
///
/// The embedded parquet data stores structured fields (expected_result,
/// mobileconfig_info, odv_options) as JSON strings.  `MscpRule` expects
/// `yaml_serde::Value`, so this helper bridges the two worlds.
fn json_to_yaml_value(v: &serde_json::Value) -> yaml_serde::Value {
    match v {
        serde_json::Value::Null => yaml_serde::Value::Null,
        serde_json::Value::Bool(b) => yaml_serde::Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                yaml_serde::Value::Number(i.into())
            } else if let Some(f) = n.as_f64() {
                yaml_serde::Value::Number(yaml_serde::Number::from(f))
            } else {
                yaml_serde::Value::Null
            }
        }
        serde_json::Value::String(s) => yaml_serde::Value::String(s.clone()),
        serde_json::Value::Array(arr) => {
            yaml_serde::Value::Sequence(arr.iter().map(json_to_yaml_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut m = yaml_serde::Mapping::new();
            for (k, val) in map {
                m.insert(
                    yaml_serde::Value::String(k.clone()),
                    json_to_yaml_value(val),
                );
            }
            yaml_serde::Value::Mapping(m)
        }
    }
}

/// Parse a JSON string into a `yaml_serde::Value`, returning `None` for
/// empty/null/unparseable input.
fn parse_json_field(s: &str) -> Option<yaml_serde::Value> {
    if s.is_empty() || s == "null" {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(s)
        .ok()
        .map(|v| json_to_yaml_value(&v))
}

/// Build `MscpRule` values from embedded parquet data for a given baseline and platform.
///
/// This is the embedded-data counterpart of [`super::RuleExtractor`] which reads
/// rule YAML files from a local mSCP repository checkout.  It joins three datasets:
///
/// 1. **baseline_edges** -- filtered by `baseline` and `platform` to find the set of
///    rule IDs that belong to the requested baseline.
/// 2. **rule_meta** -- title, discussion, severity, mobileconfig flag.
/// 3. **rule_payloads** -- check_script, fix_script, expected_result, mobileconfig_info,
///    odv_options.
///
/// Rules that appear in multiple sections are deduplicated (each rule_id appears once).
/// The `tags` field on the resulting `MscpRule` contains the section names from the
/// baseline edges.
pub fn rules_from_embedded(baseline: &str, platform: &str) -> Result<Vec<MscpRule>> {
    // 1. Read all three datasets from embedded parquet bytes.
    let edges = mscp_schema::baseline_edges::read(mscp_schema::embedded_baseline_edges())?;
    let metas = mscp_schema::rule_meta::read(mscp_schema::embedded_rule_meta())?;
    let payloads = mscp_schema::rule_payloads::read(mscp_schema::embedded_rule_payloads())?;

    // 2. Filter edges to the requested baseline + platform and collect unique rule IDs.
    //    Also accumulate sections per rule for the `tags` field.
    let mut rule_sections: HashMap<String, Vec<String>> = HashMap::new();
    for edge in &edges {
        if edge.baseline != baseline {
            continue;
        }
        if let Some(ref p) = edge.platform {
            if p != platform {
                continue;
            }
        }
        rule_sections
            .entry(edge.rule_id.clone())
            .or_default()
            .push(edge.section.clone());
    }

    if rule_sections.is_empty() {
        return Ok(Vec::new());
    }

    let rule_ids: HashSet<&str> = rule_sections.keys().map(String::as_str).collect();

    // 3. Index rule_meta by rule_id (only those we need).
    let meta_map: HashMap<&str, &mscp_schema::RuleMeta> = metas
        .iter()
        .filter(|m| rule_ids.contains(m.rule_id.as_str()))
        .map(|m| (m.rule_id.as_str(), m))
        .collect();

    // 4. Index rule_payloads by rule_id (only those we need).
    let payload_map: HashMap<&str, &mscp_schema::RulePayload> = payloads
        .iter()
        .filter(|p| rule_ids.contains(p.rule_id.as_str()))
        .map(|p| (p.rule_id.as_str(), p))
        .collect();

    // 5. Assemble MscpRule values.
    let mut rules: Vec<MscpRule> = Vec::with_capacity(rule_ids.len());

    for rule_id in &rule_ids {
        let meta = match meta_map.get(rule_id) {
            Some(m) => m,
            None => continue, // edge references a rule not in rule_meta -- skip
        };

        let payload = payload_map.get(rule_id);

        let sections = rule_sections.get(*rule_id).cloned().unwrap_or_default();

        let check = payload.and_then(|p| p.check_script.clone());
        let fix = payload.and_then(|p| p.fix_script.clone());

        let result = payload
            .and_then(|p| p.expected_result.as_deref())
            .and_then(parse_json_field);

        let mobileconfig_info = payload
            .and_then(|p| p.mobileconfig_info.as_deref())
            .and_then(parse_json_field);

        let odv = payload
            .and_then(|p| p.odv_options.as_deref())
            .and_then(parse_json_field);

        rules.push(MscpRule {
            id: rule_id.to_string(),
            title: meta.title.clone(),
            discussion: meta.discussion.clone().unwrap_or_default(),
            check,
            result,
            fix,
            references: HashMap::new(),
            macos: vec![],
            tags: sections,
            severity: meta.severity.clone(),
            mobileconfig: meta.mobileconfig,
            mobileconfig_info,
            odv,
        });
    }

    // Sort by id for deterministic output.
    rules.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_from_embedded_cis_lvl1() {
        let rules = rules_from_embedded("cis_lvl1", "macOS")
            .expect("failed to read embedded rules for cis_lvl1");
        assert!(
            !rules.is_empty(),
            "Expected non-empty rules for cis_lvl1 / macOS"
        );
        for rule in &rules {
            assert!(!rule.id.is_empty(), "Rule id must not be empty");
            assert!(!rule.title.is_empty(), "Rule title must not be empty");
        }
    }

    #[test]
    fn test_rules_from_embedded_have_scripts() {
        let rules =
            rules_from_embedded("cis_lvl1", "macOS").expect("failed to read embedded rules");
        let with_check = rules.iter().filter(|r| r.check.is_some()).count();
        assert!(
            with_check > 0,
            "Expected at least one rule with a check script, got 0"
        );
    }

    #[test]
    fn test_rules_from_embedded_have_mobileconfig_info() {
        let rules =
            rules_from_embedded("cis_lvl1", "macOS").expect("failed to read embedded rules");
        let with_mc = rules
            .iter()
            .filter(|r| r.mobileconfig && r.mobileconfig_info.is_some())
            .count();
        assert!(
            with_mc > 0,
            "Expected at least one mobileconfig-enforceable rule, got 0"
        );
    }

    #[test]
    fn test_rules_from_embedded_unknown_baseline() {
        let rules = rules_from_embedded("nonexistent_baseline_xyz", "macOS")
            .expect("should not error for unknown baseline");
        assert!(
            rules.is_empty(),
            "Expected empty rules for unknown baseline, got {}",
            rules.len()
        );
    }
}
