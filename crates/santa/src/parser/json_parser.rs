use crate::models::{Rule, RuleSet};
use anyhow::{Context, Result};

/// Parse rules from JSON content
pub fn parse_json(content: &str) -> Result<RuleSet> {
    let rules: Vec<Rule> = serde_json::from_str(content).context("Failed to parse JSON content")?;
    Ok(RuleSet::from_rules(rules))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Policy, RuleType};

    #[test]
    fn test_parse_json_rules() {
        let json = r#"[
            {
                "rule_type": "TEAMID",
                "identifier": "EQHXZ8M8AV",
                "policy": "ALLOWLIST",
                "description": "Google LLC"
            },
            {
                "rule_type": "BINARY",
                "identifier": "/usr/bin/example",
                "policy": "BLOCKLIST"
            }
        ]"#;
        let rules = parse_json(json).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules.rules()[0].rule_type, RuleType::TeamId);
        assert_eq!(rules.rules()[1].rule_type, RuleType::Binary);
        assert_eq!(rules.rules()[1].policy, Policy::Blocklist);
    }

    #[test]
    fn test_parse_json_empty() {
        let json = "[]";
        let rules = parse_json(json).unwrap();
        assert!(rules.is_empty());
    }
}
