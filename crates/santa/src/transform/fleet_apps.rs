//! Adapter for the fleet-maintained-apps **`app_security_info.json`** dataset
//! (<https://github.com/allenhouchins/fleet-maintained-apps-growth-tracker>).
//!
//! Each record carries code-signing identifiers — `signingId` (`TEAMID:bundle`),
//! `teamId`, `cdhash`, `sha256` — that map directly onto Santa rules and, via
//! `app_settings`, DDM `com.apple.configuration.app.settings` binary entries.
//! This adapter normalizes the catalog into a [`RuleSet`]; downstream emitters
//! turn it into a Santa `.mobileconfig` and/or a DDM declaration.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::models::{Policy, Rule, RuleSet, RuleType};

/// Which signing identifier each app is ruled on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOn {
    /// `signingId` (`TEAMID:bundle`) — per-app, survives version updates. Default.
    SigningId,
    /// `teamId` — per-vendor; broadest, dedupes to one rule per developer.
    TeamId,
    /// `cdhash` — per-build; strictest, churns on every app update.
    Cdhash,
}

#[derive(Debug, Deserialize)]
struct Dataset {
    apps: Vec<AppRecord>,
}

#[derive(Debug, Deserialize)]
struct AppRecord {
    name: Option<String>,
    version: Option<String>,
    #[serde(rename = "signingId")]
    signing_id: Option<String>,
    #[serde(rename = "teamId")]
    team_id: Option<String>,
    cdhash: Option<String>,
}

/// Parse the dataset JSON into a Santa [`RuleSet`], ruling on `match_on` with
/// `policy`. Records missing the chosen identifier are skipped; duplicate
/// identifiers (especially `teamId`) collapse to a single rule.
pub fn parse_fleet_apps(data: &str, match_on: MatchOn, policy: Policy) -> Result<RuleSet> {
    let dataset: Dataset = serde_json::from_str(data)
        .context("parsing app_security_info.json (expected an object with an \"apps\" array)")?;

    let mut rules = RuleSet::new();
    let mut seen: HashSet<String> = HashSet::new();

    for app in &dataset.apps {
        let (rule_type, identifier) = match match_on {
            MatchOn::SigningId => (RuleType::SigningId, app.signing_id.clone()),
            MatchOn::TeamId => (RuleType::TeamId, app.team_id.clone()),
            MatchOn::Cdhash => (RuleType::Cdhash, app.cdhash.clone()),
        };
        let Some(identifier) = identifier.filter(|s| !s.is_empty()) else {
            continue;
        };
        if !seen.insert(identifier.clone()) {
            continue;
        }
        let description = match (&app.name, &app.version) {
            (Some(n), Some(v)) => format!("{n} {v}"),
            (Some(n), None) => n.clone(),
            _ => "fleet-maintained app".to_string(),
        };
        rules.add(
            Rule::new(rule_type, identifier, policy)
                .with_description(description)
                .with_group("fleet-apps"),
        );
    }
    Ok(rules)
}

/// Parse the dataset from a file path.
pub fn parse_fleet_apps_file(path: &Path, match_on: MatchOn, policy: Policy) -> Result<RuleSet> {
    let data =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_fleet_apps(&data, match_on, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "lastUpdated": "2026-06-16T10:52:53Z",
      "apps": [
        {"name":"010 Editor","version":"16.0.4","sha256":"f686","cdhash":"b60539",
         "signingId":"252VCA66Z8:com.SweetScape.010Editor","teamId":"252VCA66Z8"},
        {"name":"Other","version":"1.0","signingId":"252VCA66Z8:com.other","teamId":"252VCA66Z8"},
        {"name":"NoSign"}
      ]
    }"#;

    #[test]
    fn signing_id_match_keeps_per_app_and_skips_unsigned() {
        let rules = parse_fleet_apps(SAMPLE, MatchOn::SigningId, Policy::Allowlist).unwrap();
        assert_eq!(rules.len(), 2); // NoSign skipped
        assert_eq!(rules.rules()[0].rule_type, RuleType::SigningId);
        assert_eq!(
            rules.rules()[0].identifier,
            "252VCA66Z8:com.SweetScape.010Editor"
        );
        assert_eq!(rules.rules()[0].policy, Policy::Allowlist);
    }

    #[test]
    fn team_id_match_dedupes_per_vendor() {
        let rules = parse_fleet_apps(SAMPLE, MatchOn::TeamId, Policy::Allowlist).unwrap();
        assert_eq!(rules.len(), 1); // both apps share one teamId
        assert_eq!(rules.rules()[0].rule_type, RuleType::TeamId);
        assert_eq!(rules.rules()[0].identifier, "252VCA66Z8");
    }

    #[test]
    fn deny_policy_is_propagated() {
        let rules = parse_fleet_apps(SAMPLE, MatchOn::Cdhash, Policy::Blocklist).unwrap();
        assert_eq!(rules.len(), 1); // only first record has a cdhash
        assert_eq!(rules.rules()[0].policy, Policy::Blocklist);
    }
}
