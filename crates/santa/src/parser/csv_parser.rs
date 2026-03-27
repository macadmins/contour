use crate::models::{Policy, Rule, RuleSet, RuleType};
use anyhow::{Context, Result};
use serde::Deserialize;

/// CSV row structure
#[derive(Debug, Deserialize)]
struct CsvRow {
    rule_type: String,
    identifier: String,
    policy: String,
    #[serde(default)]
    custom_msg: Option<String>,
    #[serde(default)]
    custom_url: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    labels: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    rings: Option<String>,
    #[serde(default)]
    cel_expression: Option<String>,
    #[serde(default)]
    faa_path: Option<String>,
    #[serde(default)]
    faa_access: Option<String>,
    #[serde(default)]
    faa_process: Option<String>,
}

impl TryFrom<CsvRow> for Rule {
    type Error = anyhow::Error;

    fn try_from(row: CsvRow) -> Result<Self> {
        let rule_type = parse_rule_type(&row.rule_type)?;
        let policy = parse_policy(&row.policy)?;

        let labels = row
            .labels
            .map(|s| s.split(',').map(|l| l.trim().to_string()).collect())
            .unwrap_or_default();

        let rings = row
            .rings
            .map(|s| s.split(',').map(|r| r.trim().to_string()).collect())
            .unwrap_or_default();

        Ok(Rule {
            rule_type,
            identifier: row.identifier,
            policy,
            custom_msg: row.custom_msg.filter(|s| !s.is_empty()),
            custom_url: row.custom_url.filter(|s| !s.is_empty()),
            description: row.description.filter(|s| !s.is_empty()),
            labels,
            group: row.group.filter(|s| !s.is_empty()),
            rings,
            cel_expression: row.cel_expression.filter(|s| !s.is_empty()),
            faa_path: row.faa_path.filter(|s| !s.is_empty()),
            faa_access: row.faa_access.filter(|s| !s.is_empty()),
            faa_process: row.faa_process.filter(|s| !s.is_empty()),
        })
    }
}

fn parse_rule_type(s: &str) -> Result<RuleType> {
    match s.to_uppercase().as_str() {
        "BINARY" => Ok(RuleType::Binary),
        "CERTIFICATE" => Ok(RuleType::Certificate),
        "TEAMID" | "TEAM_ID" => Ok(RuleType::TeamId),
        "SIGNINGID" | "SIGNING_ID" => Ok(RuleType::SigningId),
        "CDHASH" => Ok(RuleType::Cdhash),
        _ => anyhow::bail!("Invalid rule type: {s}"),
    }
}

fn parse_policy(s: &str) -> Result<Policy> {
    match s.to_uppercase().as_str() {
        "ALLOWLIST" | "ALLOW" => Ok(Policy::Allowlist),
        "ALLOWLIST_COMPILER" | "ALLOW_COMPILER" => Ok(Policy::AllowlistCompiler),
        "BLOCKLIST" | "BLOCK" => Ok(Policy::Blocklist),
        "SILENT_BLOCKLIST" | "SILENT_BLOCK" => Ok(Policy::SilentBlocklist),
        "REMOVE" => Ok(Policy::Remove),
        _ => anyhow::bail!("Invalid policy: {s}"),
    }
}

/// Parse rules from CSV content
pub fn parse_csv(content: &str) -> Result<RuleSet> {
    let mut reader = csv::Reader::from_reader(content.as_bytes());
    let mut rules = Vec::new();

    for (i, result) in reader.deserialize().enumerate() {
        let row: CsvRow = result.with_context(|| format!("Failed to parse CSV row {}", i + 1))?;
        let rule = Rule::try_from(row).with_context(|| format!("Invalid rule at row {}", i + 1))?;
        rules.push(rule);
    }

    Ok(RuleSet::from_rules(rules))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csv_rules() {
        let csv = r"rule_type,identifier,policy,description
TEAMID,EQHXZ8M8AV,ALLOWLIST,Google LLC
BINARY,/usr/bin/example,BLOCKLIST,Example binary";

        let rules = parse_csv(csv).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules.rules()[0].rule_type, RuleType::TeamId);
        assert_eq!(rules.rules()[0].identifier, "EQHXZ8M8AV");
        assert_eq!(rules.rules()[0].description, Some("Google LLC".to_string()));
    }

    #[test]
    fn test_parse_csv_with_labels() {
        let csv = r#"rule_type,identifier,policy,labels
TEAMID,ABC123,ALLOWLIST,"vendor,approved""#;

        let rules = parse_csv(csv).unwrap();
        assert_eq!(rules.rules()[0].labels, vec!["vendor", "approved"]);
    }

    #[test]
    fn test_parse_csv_empty() {
        let csv = "rule_type,identifier,policy\n";
        let rules = parse_csv(csv).unwrap();
        assert!(rules.is_empty());
    }
}
