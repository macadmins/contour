use crate::models::{Policy, Rule, RuleSet, RuleType};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::Read;

/// Parse Fleet CSV software export to extract rules
///
/// Supports Fleet software CSV exports which may contain columns like:
/// - name, version, source, bundle_identifier, vendor
/// - software_title, version, source
/// - team_id (if present)
pub fn parse_fleet_csv<R: Read>(reader: R) -> Result<RuleSet> {
    let mut rules = RuleSet::new();
    let mut rdr = csv::Reader::from_reader(reader);

    // Get headers to find relevant columns
    let headers = rdr.headers()?.clone();
    let col_indices = ColumnIndices::from_headers(&headers);

    let mut seen_identifiers: HashMap<String, bool> = HashMap::new();

    for result in rdr.records() {
        let record = result.context("Failed to read CSV record")?;

        // Try to extract a TeamID or bundle identifier
        if let Some(rule) = extract_rule(&record, &col_indices, &mut seen_identifiers) {
            rules.add(rule);
        }
    }

    Ok(rules)
}

/// Column indices for Fleet CSV
struct ColumnIndices {
    name: Option<usize>,
    #[allow(dead_code, reason = "reserved for future use")]
    version: Option<usize>,
    source: Option<usize>,
    bundle_identifier: Option<usize>,
    team_id: Option<usize>,
    vendor: Option<usize>,
    software_title: Option<usize>,
    #[allow(dead_code, reason = "reserved for future use")]
    host_count: Option<usize>,
}

impl ColumnIndices {
    fn from_headers(headers: &csv::StringRecord) -> Self {
        let find_col = |names: &[&str]| -> Option<usize> {
            for name in names {
                if let Some(idx) = headers.iter().position(|h| {
                    h.eq_ignore_ascii_case(name) || h.replace('_', " ").eq_ignore_ascii_case(name)
                }) {
                    return Some(idx);
                }
            }
            None
        };

        Self {
            name: find_col(&["name", "software_name", "app_name"]),
            version: find_col(&["version", "software_version"]),
            source: find_col(&["source", "software_source", "install_source", "path"]),
            bundle_identifier: find_col(&["bundle_identifier", "bundleid", "bundle_id"]),
            // Fleet uses "team_identifier" in software exports
            team_id: find_col(&["team_identifier", "team_id", "teamid", "developer_id"]),
            vendor: find_col(&["vendor", "publisher", "developer", "authority"]),
            software_title: find_col(&["software_title", "title"]),
            host_count: find_col(&["host_count", "hosts_count", "count"]),
        }
    }

    fn get_value<'a>(&self, record: &'a csv::StringRecord, idx: Option<usize>) -> Option<&'a str> {
        idx.and_then(|i| record.get(i)).filter(|s| !s.is_empty())
    }
}

fn extract_rule(
    record: &csv::StringRecord,
    cols: &ColumnIndices,
    seen: &mut HashMap<String, bool>,
) -> Option<Rule> {
    // Get app name for description
    let name = cols
        .get_value(record, cols.name)
        .or_else(|| cols.get_value(record, cols.software_title))
        .unwrap_or("Unknown");

    let vendor = cols.get_value(record, cols.vendor);
    let source = cols.get_value(record, cols.source);

    // Build description
    let description = match (vendor, source) {
        (Some(v), Some(s)) => format!("{} ({}, {})", name, v, s),
        (Some(v), None) => format!("{} ({})", name, v),
        (None, Some(s)) => format!("{} ({})", name, s),
        (None, None) => name.to_string(),
    };

    // Try to get TeamID first (most useful for Santa)
    if let Some(team_id) = cols.get_value(record, cols.team_id) {
        // Validate TeamID format
        if team_id.len() == 10
            && team_id.chars().all(|c| c.is_ascii_alphanumeric())
            && !seen.contains_key(team_id)
        {
            seen.insert(team_id.to_string(), true);
            return Some(
                Rule::new(RuleType::TeamId, team_id, Policy::Allowlist)
                    .with_description(&description)
                    .with_group("fleet"),
            );
        }
    }

    // Fall back to bundle identifier as SigningID hint
    if let Some(bundle_id) = cols.get_value(record, cols.bundle_identifier) {
        // Bundle identifiers like com.apple.Safari can be used with platform: prefix
        if bundle_id.contains('.') && !seen.contains_key(bundle_id) {
            seen.insert(bundle_id.to_string(), true);
            // Note: We create a TeamID rule placeholder - user should verify with codesign
            return Some(
                Rule::new(
                    RuleType::SigningId,
                    format!("platform:{}", bundle_id),
                    Policy::Allowlist,
                )
                .with_description(format!("{} (bundle: {})", name, bundle_id))
                .with_group("fleet"),
            );
        }
    }

    None
}

/// Parse Fleet CSV from a file path
pub fn parse_fleet_csv_file(path: &std::path::Path) -> Result<RuleSet> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open Fleet CSV: {}", path.display()))?;
    parse_fleet_csv(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fleet_csv() {
        let csv_data = r"name,version,source,team_id,bundle_identifier
Google Chrome,120.0,apps,EQHXZ8M8AV,com.google.Chrome
Slack,4.35,apps,BQR82RBBHL,com.tinyspeck.slackmacgap
Safari,17.0,apps,,com.apple.Safari
";

        let rules = parse_fleet_csv(csv_data.as_bytes()).unwrap();
        assert_eq!(rules.len(), 3);

        // Chrome and Slack should have TeamID rules
        let chrome = rules.rules().iter().find(|r| r.identifier == "EQHXZ8M8AV");
        assert!(chrome.is_some());
        assert_eq!(chrome.unwrap().rule_type, RuleType::TeamId);

        // Safari has no TeamID, should use bundle identifier
        let safari = rules
            .rules()
            .iter()
            .find(|r| r.identifier.contains("com.apple.Safari"));
        assert!(safari.is_some());
    }

    #[test]
    fn test_deduplicates_team_ids() {
        let csv_data = r"name,version,team_id
Google Chrome,120.0,EQHXZ8M8AV
Google Chrome Beta,121.0,EQHXZ8M8AV
Google Drive,3.0,EQHXZ8M8AV
";

        let rules = parse_fleet_csv(csv_data.as_bytes()).unwrap();
        assert_eq!(rules.len(), 1); // Deduplicated
    }
}
