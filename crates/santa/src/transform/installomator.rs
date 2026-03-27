use crate::models::{Policy, Rule, RuleSet, RuleType};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Parsed Installomator label with metadata
#[derive(Debug, Clone)]
pub struct InstallomatorLabel {
    pub label: String,
    pub name: Option<String>,
    pub team_id: Option<String>,
    pub app_type: Option<String>,
    pub download_url: Option<String>,
}

/// Parse Installomator labels file to extract TeamIDs with full metadata
pub fn parse_installomator(content: &str) -> Result<RuleSet> {
    let labels = parse_labels(content);
    let mut rules = RuleSet::new();

    // Group labels by TeamID to collect all app names for each
    let mut team_id_apps: HashMap<String, Vec<String>> = HashMap::new();

    for label in &labels {
        if let Some(ref team_id) = label.team_id {
            let app_name = label.name.clone().unwrap_or_else(|| label.label.clone());
            team_id_apps
                .entry(team_id.clone())
                .or_default()
                .push(app_name);
        }
    }

    // Create rules with aggregated descriptions
    for (team_id, apps) in team_id_apps {
        // Deduplicate and sort app names
        let mut unique_apps: Vec<_> = apps.into_iter().collect();
        unique_apps.sort();
        unique_apps.dedup();

        let description = if unique_apps.len() == 1 {
            unique_apps[0].clone()
        } else if unique_apps.len() <= 5 {
            unique_apps.join(", ")
        } else {
            format!(
                "{} and {} more",
                unique_apps[..3].join(", "),
                unique_apps.len() - 3
            )
        };

        let rule = Rule::new(RuleType::TeamId, &team_id, Policy::Allowlist)
            .with_description(&description)
            .with_group("installomator");

        rules.add(rule);
    }

    Ok(rules)
}

/// Parse all labels from Installomator script
pub fn parse_labels(content: &str) -> Vec<InstallomatorLabel> {
    let mut labels = Vec::new();
    let mut current_label: Option<InstallomatorLabel> = None;

    static RE_LABEL_START: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^([a-z][a-z0-9_-]*)\)\s*$")
            .expect("invariant: hardcoded regex pattern is valid")
    });
    static RE_NAME: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"^\s*name\s*=\s*"([^"]+)""#)
            .expect("invariant: hardcoded regex pattern is valid")
    });
    static RE_TEAM_ID: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"^\s*(?:teamID|expectedTeamID)\s*=\s*"([A-Z0-9]{10})""#)
            .expect("invariant: hardcoded regex pattern is valid")
    });
    static RE_TYPE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"^\s*type\s*=\s*"([^"]+)""#)
            .expect("invariant: hardcoded regex pattern is valid")
    });
    static RE_URL: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"^\s*downloadURL\s*=\s*"([^"]+)""#)
            .expect("invariant: hardcoded regex pattern is valid")
    });
    static RE_END: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^\s*;;\s*$").expect("invariant: hardcoded regex pattern is valid")
    });

    let label_start = &*RE_LABEL_START;
    let name_pattern = &*RE_NAME;
    let team_id_pattern = &*RE_TEAM_ID;
    let type_pattern = &*RE_TYPE;
    let url_pattern = &*RE_URL;
    let end_pattern = &*RE_END;

    for line in content.lines() {
        // Check for label start
        if let Some(cap) = label_start.captures(line) {
            // Save previous label if exists
            if let Some(label) = current_label.take()
                && label.team_id.is_some()
            {
                labels.push(label);
            }
            current_label = Some(InstallomatorLabel {
                label: cap[1].to_string(),
                name: None,
                team_id: None,
                app_type: None,
                download_url: None,
            });
            continue;
        }

        // Check for end of label block
        if end_pattern.is_match(line) {
            if let Some(label) = current_label.take()
                && label.team_id.is_some()
            {
                labels.push(label);
            }
            continue;
        }

        // Parse fields within a label block
        if let Some(ref mut label) = current_label {
            if let Some(cap) = name_pattern.captures(line) {
                label.name = Some(cap[1].to_string());
            }
            if let Some(cap) = team_id_pattern.captures(line) {
                label.team_id = Some(cap[1].to_string());
            }
            if let Some(cap) = type_pattern.captures(line) {
                label.app_type = Some(cap[1].to_string());
            }
            if let Some(cap) = url_pattern.captures(line) {
                label.download_url = Some(cap[1].to_string());
            }
        }
    }

    // Don't forget the last label
    if let Some(label) = current_label
        && label.team_id.is_some()
    {
        labels.push(label);
    }

    labels
}

/// Get detailed label information (useful for debugging/exploration)
pub fn get_label_details(content: &str) -> Vec<InstallomatorLabel> {
    parse_labels(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_installomator() {
        let content = r#"
# Installomator labels

googlechrome)
    name="Google Chrome"
    type="dmg"
    expectedTeamID="EQHXZ8M8AV"
    downloadURL="https://dl.google.com/chrome/mac/stable/GGRO/googlechrome.dmg"
    ;;

slack)
    name="Slack"
    type="dmg"
    expectedTeamID="BQR82RBBHL"
    downloadURL="https://slack.com/download/mac"
    ;;
"#;

        let rules = parse_installomator(content).unwrap();
        assert_eq!(rules.len(), 2);

        let ids: Vec<_> = rules.rules().iter().map(|r| &r.identifier).collect();
        assert!(ids.contains(&&"EQHXZ8M8AV".to_string()));
        assert!(ids.contains(&&"BQR82RBBHL".to_string()));

        // All should be in installomator group
        for rule in rules.rules() {
            assert_eq!(rule.group, Some("installomator".to_string()));
        }

        // Should have descriptions
        let chrome_rule = rules
            .rules()
            .iter()
            .find(|r| r.identifier == "EQHXZ8M8AV")
            .unwrap();
        assert_eq!(chrome_rule.description, Some("Google Chrome".to_string()));
    }

    #[test]
    fn test_deduplicates_team_ids() {
        let content = r#"
app1)
    name="App One"
    expectedTeamID="SAME123456"
    ;;
app2)
    name="App Two"
    expectedTeamID="SAME123456"
    ;;
"#;

        let rules = parse_installomator(content).unwrap();
        assert_eq!(rules.len(), 1); // Deduplicated

        // Description should contain both app names
        let rule = &rules.rules()[0];
        assert!(rule.description.as_ref().unwrap().contains("App One"));
        assert!(rule.description.as_ref().unwrap().contains("App Two"));
    }

    #[test]
    fn test_parse_labels() {
        let content = r#"
googlechrome)
    name="Google Chrome"
    type="dmg"
    expectedTeamID="EQHXZ8M8AV"
    downloadURL="https://dl.google.com/chrome/mac/stable/GGRO/googlechrome.dmg"
    ;;
"#;

        let labels = parse_labels(content);
        assert_eq!(labels.len(), 1);

        let label = &labels[0];
        assert_eq!(label.label, "googlechrome");
        assert_eq!(label.name, Some("Google Chrome".to_string()));
        assert_eq!(label.team_id, Some("EQHXZ8M8AV".to_string()));
        assert_eq!(label.app_type, Some("dmg".to_string()));
    }
}
