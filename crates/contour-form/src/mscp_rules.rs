//! Compliance rules whose title matches a request.
//!
//! The schema's own text does not say that "Disable Siri" means
//! `allowAssistant: false`, or that nothing in a profile turns on System
//! Integrity Protection. mSCP does, rule by rule, so the rules are searched
//! beside the keys: a hit carries the settings it prescribes with their
//! values, or says that no profile enforces it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::Serialize;

/// One macOS mSCP rule that matched.
#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub rule_id: String,
    pub title: String,
    /// `profile`, `declaration`, or `script` when neither can enforce it.
    pub enforced_by: &'static str,
    /// The rule's `mobileconfig_info`: `[{payload_type, keys: {key: value}}]`.
    /// Empty unless `enforced_by` is `profile`.
    pub settings: serde_json::Value,
    pub score: f32,
    /// mSCP's remediation for the rule, as shell, when it has one. Not
    /// serialized: a search result is read by a model, and forty scripts
    /// are not what it asked for.
    #[serde(skip)]
    pub fix_script: Option<String>,
}

impl Rule {
    /// Every `(payload type, key, value)` the rule deploys.
    pub fn keys(&self) -> Vec<(String, String, serde_json::Value)> {
        self.settings
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|item| {
                let payload_type = item["payload_type"].as_str().unwrap_or_default().to_string();
                item["keys"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(move |(k, v)| (payload_type.clone(), k.clone(), v.clone()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

struct Index {
    /// `(rule id, title, has a declaration)`, one per rule.
    rules: Vec<(String, String, bool)>,
    docs: Vec<[String; 3]>,
    /// Rule id to its parsed `mobileconfig_info`.
    settings: BTreeMap<String, serde_json::Value>,
    /// Rule id to its remediation script.
    fixes: BTreeMap<String, String>,
    /// Baseline name to its macOS rule ids, at the newest OS it is built for.
    baselines: BTreeMap<String, Vec<String>>,
    /// The oldest and newest macOS the rules are written for.
    macos: Option<(String, String)>,
}

/// `a` is a newer OS version than `b`. Not a version at all sorts oldest.
fn newer(a: &str, b: &str) -> bool {
    crate::version::at_least(a, b) == Some(true) && crate::version::at_least(b, a) != Some(true)
}

fn index() -> &'static Index {
    static CACHE: OnceLock<Index> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut seen = BTreeSet::new();
        let mut rules = Vec::new();
        let mut docs = Vec::new();
        for r in mscp_schema::rule_meta::read(mscp_schema::embedded_rule_meta()).unwrap_or_default() {
            if !seen.insert(r.rule_id.clone()) {
                continue;
            }
            docs.push([
                r.title.clone(),
                r.rule_id.replace('_', " "),
                r.discussion.unwrap_or_default(),
            ]);
            rules.push((r.rule_id, r.title, r.has_ddm_info));
        }
        // A rule has a row per OS version; the newest one is the rule as it stands.
        let mut macos: Option<(String, String)> = None;
        let mut newest: BTreeMap<String, (String, Option<serde_json::Value>, Option<String>)> = BTreeMap::new();
        for p in mscp_schema::rule_payloads::read(mscp_schema::embedded_rule_payloads()).unwrap_or_default() {
            if !p.platform.eq_ignore_ascii_case("macOS") {
                continue;
            }
            macos = Some(match macos {
                None => (p.os_version.clone(), p.os_version.clone()),
                Some((oldest, latest)) => (
                    if newer(&oldest, &p.os_version) { p.os_version.clone() } else { oldest },
                    if newer(&p.os_version, &latest) { p.os_version.clone() } else { latest },
                ),
            });
            if newest.get(&p.rule_id).is_some_and(|(have, _, _)| !newer(&p.os_version, have)) {
                continue;
            }
            let parsed = p.mobileconfig_info.as_deref().and_then(|i| serde_json::from_str(i).ok());
            let fix = p.fix_script.filter(|f| !f.trim().is_empty());
            newest.insert(p.rule_id, (p.os_version, parsed, fix));
        }
        let mut settings = BTreeMap::new();
        let mut fixes = BTreeMap::new();
        for (id, (_, parsed, fix)) in newest {
            if let Some(parsed) = parsed {
                settings.insert(id.clone(), parsed);
            }
            if let Some(fix) = fix {
                fixes.insert(id, fix);
            }
        }

        let mut baselines: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
        for e in mscp_schema::baseline_edges::read(mscp_schema::embedded_baseline_edges()).unwrap_or_default() {
            if !e.platform.as_deref().is_some_and(|p| p.eq_ignore_ascii_case("macOS")) {
                continue;
            }
            let os = e.os_version.unwrap_or_default();
            let entry = baselines.entry(e.baseline).or_insert_with(|| (os.clone(), Vec::new()));
            if newer(&os, &entry.0) {
                *entry = (os.clone(), Vec::new());
            }
            if os == entry.0 && !entry.1.contains(&e.rule_id) {
                entry.1.push(e.rule_id);
            }
        }
        Index {
            rules,
            docs,
            settings,
            fixes,
            macos,
            baselines: baselines.into_iter().map(|(name, (_, ids))| (name, ids)).collect(),
        }
    })
}

fn rule(index: &Index, i: usize, score: f32) -> Rule {
    let (rule_id, title, has_declaration) = &index.rules[i];
    let settings = index.settings.get(rule_id);
    Rule {
        rule_id: rule_id.clone(),
        title: title.clone(),
        enforced_by: if settings.is_some() {
            "profile"
        } else if *has_declaration {
            "declaration"
        } else {
            "script"
        },
        settings: settings.cloned().unwrap_or_else(|| serde_json::json!([])),
        score,
        fix_script: index.fixes.get(rule_id).cloned(),
    }
}

/// The rules whose title, id or discussion best match `query`, best first.
pub fn matching(query: &str, limit: usize) -> Vec<Rule> {
    let index = index();
    crate::rank_text(&index.docs, query)
        .into_iter()
        .take(limit)
        .map(|(i, score)| rule(index, i, score))
        .collect()
}

/// The oldest and the newest macOS version mSCP's rules here are written
/// for, e.g. `("15.0", "27.0")`. Baselines are built from the newest.
pub fn macos_coverage() -> Option<(String, String)> {
    index().macos.clone()
}

/// The names of the macOS baselines, e.g. `cis_lvl1`, `800-53r5_low`.
pub fn baselines() -> Vec<String> {
    index().baselines.keys().cloned().collect()
}

/// Every rule of one macOS baseline, in the baseline's own order. `None`
/// when there is no baseline of that name.
pub fn baseline(name: &str) -> Option<Vec<Rule>> {
    let index = index();
    let ids = index.baselines.get(name)?;
    Some(
        ids.iter()
            .filter_map(|id| index.rules.iter().position(|r| r.0 == *id))
            .map(|i| rule(index, i, 0.0))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_baseline_lists_its_rules_and_how_each_is_enforced() {
        assert!(baselines().iter().any(|b| b == "cis_lvl1"));
        let rules = baseline("cis_lvl1").unwrap();
        assert!(rules.len() > 50, "{}", rules.len());
        let airdrop = rules.iter().find(|r| r.rule_id == "os_airdrop_disable").unwrap();
        assert_eq!(airdrop.enforced_by, "profile");
        assert_eq!(
            airdrop.keys(),
            [("com.apple.applicationaccess".to_string(), "allowAirDrop".to_string(), serde_json::json!(false))]
        );
        let sip = rules.iter().find(|r| r.rule_id == "os_sip_enable").unwrap();
        assert_eq!(sip.enforced_by, "script");
        assert!(sip.fix_script.as_deref().is_some_and(|f| f.contains("csrutil")));
        assert!(baseline("no_such_baseline").is_none());
        let (oldest, newest) = macos_coverage().unwrap();
        assert!(crate::version::at_least(&newest, &oldest) == Some(true), "{oldest}..{newest}");
    }
}
