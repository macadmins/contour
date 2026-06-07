//! Vendor-neutral osquery query-pack JSON.
use crate::osquery::OsqueryArtifacts;
use serde_json::json;

/// Serialize the queries as an osquery query pack.
pub fn to_pack_json(art: &OsqueryArtifacts) -> String {
    let mut queries = serde_json::Map::new();
    for q in &art.queries {
        queries.insert(
            q.rule_id.clone(),
            json!({ "query": q.sql, "interval": 3600, "platform": "darwin", "description": q.title }),
        );
    }
    serde_json::to_string_pretty(&json!({ "queries": queries })).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MscpRule;
    use crate::osquery::{AuditScope, build};

    #[test]
    fn pack_json_has_a_query_per_covered_rule() {
        let r = MscpRule {
            id: "weird_check".into(),
            title: "Weird".into(),
            check: Some("/usr/bin/true".into()),
            ..Default::default()
        };
        let art = build(&[r], "com.org", "disa_stig", AuditScope::Slim, |_| None);
        let js = to_pack_json(&art);
        assert!(js.contains("\"weird_check\"") && js.contains("FROM plist"));
    }
}
