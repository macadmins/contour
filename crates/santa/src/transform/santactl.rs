use crate::models::{Policy, Rule, RuleSet, RuleType};
use anyhow::Result;
use std::collections::HashMap;

/// Parse santactl fileinfo output
pub fn parse_santactl(content: &str) -> Result<RuleSet> {
    let mut rules = RuleSet::new();
    let mut current: HashMap<String, String> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() {
            // End of a block, process accumulated data
            if let Some(rule) = process_santactl_block(&current) {
                rules.add(rule);
            }
            current.clear();
            continue;
        }

        // Parse key: value pairs
        if let Some((key, value)) = line.split_once(':') {
            current.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    // Process any remaining data
    if let Some(rule) = process_santactl_block(&current) {
        rules.add(rule);
    }

    Ok(rules)
}

fn process_santactl_block(data: &HashMap<String, String>) -> Option<Rule> {
    // Try to extract useful identifiers
    // Priority: Signing ID > Team ID > CDHash > SHA-256

    if let Some(signing_id) = data.get("Signing ID")
        && !signing_id.is_empty()
        && signing_id != "None"
    {
        return Some(
            Rule::new(RuleType::SigningId, signing_id, Policy::Allowlist)
                .with_description(data.get("Path").cloned().unwrap_or_default()),
        );
    }

    if let Some(team_id) = data.get("Team ID")
        && !team_id.is_empty()
        && team_id != "None"
    {
        return Some(
            Rule::new(RuleType::TeamId, team_id, Policy::Allowlist)
                .with_description(data.get("Path").cloned().unwrap_or_default()),
        );
    }

    if let Some(cdhash) = data.get("CDHash")
        && !cdhash.is_empty()
        && cdhash != "None"
    {
        return Some(
            Rule::new(RuleType::Cdhash, cdhash, Policy::Allowlist)
                .with_description(data.get("Path").cloned().unwrap_or_default()),
        );
    }

    if let Some(sha256) = data.get("SHA-256")
        && !sha256.is_empty()
    {
        return Some(
            Rule::new(RuleType::Binary, sha256, Policy::Allowlist)
                .with_description(data.get("Path").cloned().unwrap_or_default()),
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_santactl_output() {
        let content = r"
Path                   : /Applications/Example.app/Contents/MacOS/Example
SHA-256                : abc123def456...
Team ID                : EQHXZ8M8AV
Signing ID             : EQHXZ8M8AV:com.example.app
CDHash                 : abcdef123456

Path                   : /usr/bin/unsigned
SHA-256                : 789xyz...
Team ID                : None
Signing ID             : None
CDHash                 : None
";

        let rules = parse_santactl(content).unwrap();
        assert_eq!(rules.len(), 2);

        // First rule should use SigningID (highest priority)
        assert_eq!(rules.rules()[0].rule_type, RuleType::SigningId);
        assert_eq!(rules.rules()[0].identifier, "EQHXZ8M8AV:com.example.app");

        // Second rule should use SHA-256 (only option)
        assert_eq!(rules.rules()[1].rule_type, RuleType::Binary);
    }
}
