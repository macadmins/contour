use crate::models::{Policy, Rule, RuleSet, RuleType};
use anyhow::{Context, Result};
use plist::Value;
use std::path::Path;

/// Parse rules from an existing Santa mobileconfig
pub fn parse_mobileconfig(content: &[u8]) -> Result<RuleSet> {
    let plist: Value = plist::from_bytes(content).context("Failed to parse mobileconfig plist")?;

    let mut rules = RuleSet::new();

    // Navigate to PayloadContent
    let payload_content = plist
        .as_dictionary()
        .and_then(|d| d.get("PayloadContent"))
        .and_then(|v| v.as_array())
        .context("Invalid mobileconfig structure")?;

    for payload in payload_content {
        let Some(payload_dict) = payload.as_dictionary() else {
            continue;
        };

        // Check if this is a Santa payload
        let payload_type = payload_dict.get("PayloadType").and_then(|v| v.as_string());

        if payload_type != Some("com.google.santa") {
            continue;
        }

        // Look for Rules in PayloadContent or directly in payload
        let santa_rules = payload_dict
            .get("PayloadContent")
            .and_then(|v| v.as_dictionary())
            .and_then(|d| d.get("Rules"))
            .or_else(|| payload_dict.get("Rules"))
            .and_then(|v| v.as_array());

        if let Some(rule_array) = santa_rules {
            for rule_value in rule_array {
                if let Some(rule) = parse_rule(rule_value) {
                    rules.add(rule);
                }
            }
        }
    }

    Ok(rules)
}

/// Parse from file path
pub fn parse_mobileconfig_file(path: &Path) -> Result<RuleSet> {
    let content = std::fs::read(path)
        .with_context(|| format!("Failed to read mobileconfig: {}", path.display()))?;
    parse_mobileconfig(&content)
}

fn parse_rule(value: &Value) -> Option<Rule> {
    let dict = value.as_dictionary()?;

    let rule_type_str = dict.get("rule_type")?.as_string()?;
    let identifier = dict.get("identifier")?.as_string()?;
    let policy_str = dict.get("policy")?.as_string()?;

    let rule_type = match rule_type_str.to_uppercase().as_str() {
        "BINARY" => RuleType::Binary,
        "CERTIFICATE" => RuleType::Certificate,
        "TEAMID" => RuleType::TeamId,
        "SIGNINGID" => RuleType::SigningId,
        "CDHASH" => RuleType::Cdhash,
        _ => return None,
    };

    let policy = match policy_str.to_uppercase().as_str() {
        "ALLOWLIST" => Policy::Allowlist,
        "ALLOWLIST_COMPILER" => Policy::AllowlistCompiler,
        "BLOCKLIST" => Policy::Blocklist,
        "SILENT_BLOCKLIST" => Policy::SilentBlocklist,
        "REMOVE" => Policy::Remove,
        _ => return None,
    };

    let mut rule = Rule::new(rule_type, identifier, policy);

    if let Some(msg) = dict.get("custom_msg").and_then(|v| v.as_string()) {
        rule.custom_msg = Some(msg.to_string());
    }
    if let Some(url) = dict.get("custom_url").and_then(|v| v.as_string()) {
        rule.custom_url = Some(url.to_string());
    }

    Some(rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rule() {
        let value = Value::Dictionary(
            vec![
                ("rule_type".to_string(), Value::String("TEAMID".to_string())),
                (
                    "identifier".to_string(),
                    Value::String("EQHXZ8M8AV".to_string()),
                ),
                ("policy".to_string(), Value::String("ALLOWLIST".to_string())),
            ]
            .into_iter()
            .collect(),
        );

        let rule = parse_rule(&value).unwrap();
        assert_eq!(rule.rule_type, RuleType::TeamId);
        assert_eq!(rule.identifier, "EQHXZ8M8AV");
        assert_eq!(rule.policy, Policy::Allowlist);
    }
}
