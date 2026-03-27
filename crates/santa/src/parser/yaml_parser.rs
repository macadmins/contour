use crate::models::{Rule, RuleSet};
use anyhow::{Context, Result};

/// Parse rules from YAML content
pub fn parse_yaml(content: &str) -> Result<RuleSet> {
    let rules: Vec<Rule> = yaml_serde::from_str(content).context("Failed to parse YAML content")?;
    Ok(RuleSet::from_rules(rules))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Policy, RuleType};

    #[test]
    fn test_parse_yaml_rules() {
        let yaml = r#"
- rule_type: TEAMID
  identifier: EQHXZ8M8AV
  policy: ALLOWLIST
  description: "Google LLC"
- rule_type: BINARY
  identifier: /usr/bin/example
  policy: BLOCKLIST
"#;
        let rules = parse_yaml(yaml).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules.rules()[0].rule_type, RuleType::TeamId);
        assert_eq!(rules.rules()[0].policy, Policy::Allowlist);
        assert_eq!(rules.rules()[1].rule_type, RuleType::Binary);
    }

    #[test]
    fn test_parse_yaml_with_labels() {
        let yaml = r"
- rule_type: TEAMID
  identifier: ABC123
  policy: ALLOWLIST
  labels:
    - vendor
    - approved
";
        let rules = parse_yaml(yaml).unwrap();
        assert_eq!(rules.rules()[0].labels, vec!["vendor", "approved"]);
    }

    #[test]
    fn test_parse_yaml_empty() {
        let yaml = "[]";
        let rules = parse_yaml(yaml).unwrap();
        assert!(rules.is_empty());
    }
}
