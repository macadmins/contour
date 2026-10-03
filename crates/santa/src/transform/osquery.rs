use crate::models::{Policy, Rule, RuleSet, RuleType};
use anyhow::{Context, Result};
use serde::Deserialize;

/// Osquery santa_rules table row
#[derive(Debug, Deserialize)]
struct OsqueryRule {
    identifier: String,
    #[serde(rename = "type")]
    rule_type: String,
    state: String,
    #[serde(default)]
    custom_msg: Option<String>,
    #[serde(default)]
    custom_url: Option<String>,
}

/// Parse osquery santa_rules JSON output
pub fn parse_osquery(content: &str) -> Result<RuleSet> {
    let rows: Vec<OsqueryRule> =
        serde_json::from_str(content).context("Failed to parse osquery JSON")?;

    let mut rules = RuleSet::new();

    for row in rows {
        let rule_type = match row.rule_type.as_str() {
            "Binary" => RuleType::Binary,
            "Certificate" => RuleType::Certificate,
            "TeamID" => RuleType::TeamId,
            "SigningID" => RuleType::SigningId,
            "CDHash" => RuleType::Cdhash,
            _ => continue, // Skip unknown types
        };

        let policy = match row.state.as_str() {
            "Allow" | "Allowlist" => Policy::Allowlist,
            "AllowCompiler" | "AllowlistCompiler" => Policy::AllowlistCompiler,
            "Block" | "Blocklist" => Policy::Blocklist,
            "SilentBlock" | "SilentBlocklist" => Policy::SilentBlocklist,
            _ => continue, // Skip unknown policies
        };

        let mut rule = Rule::new(rule_type, row.identifier, policy);
        rule.custom_msg = row.custom_msg.filter(|s| !s.is_empty());
        rule.custom_url = row.custom_url.filter(|s| !s.is_empty());

        rules.add(rule);
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trainer prints `SANTA_RULES` for operators to run; its SELECT list
    /// is the only offline statement of what `santa_rules` returns, and this
    /// parser is its consumer. The two must agree column for column.
    #[test]
    fn trainer_santa_rules_query_selects_what_this_parser_reads() {
        let sql = contour_core::trainer::queries::santa::SANTA_RULES;
        let upper = sql.to_uppercase();
        let (from, to) = (upper.find("SELECT").unwrap() + 6, upper.find("FROM").unwrap());
        let selected: Vec<&str> = sql[from..to].split(',').map(str::trim).collect();
        assert_eq!(selected, ["identifier", "type", "state", "custom_msg", "custom_url"]);
    }

    #[test]
    fn test_parse_osquery() {
        let json = r#"[
            {
                "identifier": "EQHXZ8M8AV",
                "type": "TeamID",
                "state": "Allow"
            },
            {
                "identifier": "/usr/bin/test",
                "type": "Binary",
                "state": "Block",
                "custom_msg": "This is blocked"
            }
        ]"#;

        let rules = parse_osquery(json).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules.rules()[0].rule_type, RuleType::TeamId);
        assert_eq!(rules.rules()[1].policy, Policy::Blocklist);
        assert_eq!(
            rules.rules()[1].custom_msg,
            Some("This is blocked".to_string())
        );
    }
}
