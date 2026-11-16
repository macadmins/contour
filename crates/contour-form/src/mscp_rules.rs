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

/// The platforms mSCP writes rules for, as the dataset names them.
const MAC: &str = "macOS";

struct Index {
    /// `(rule id, title, has a declaration)`, one per rule.
    rules: Vec<(String, String, bool)>,
    docs: Vec<[String; 3]>,
    /// `(platform, rule id)` to its parsed `mobileconfig_info`, at the
    /// newest OS version that platform's rule is written for.
    settings: BTreeMap<(String, String), serde_json::Value>,
    /// `(platform, rule id)` to its remediation script.
    fixes: BTreeMap<(String, String), String>,
    /// `(platform, baseline)` to its rule ids, at the newest OS it is built for.
    baselines: BTreeMap<(String, String), Vec<String>>,
    /// Per platform, the oldest and newest OS the rules are written for.
    coverage: BTreeMap<String, (String, String)>,
}

/// `a` is a newer OS version than `b`. Not a version at all sorts oldest.
fn newer(a: &str, b: &str) -> bool {
    crate::version::at_least(a, b) == Some(true) && crate::version::at_least(b, a) != Some(true)
}

/// The dataset's spelling of a platform: `ios` and `iOS` alike.
fn platform_name(p: &str) -> String {
    match p.to_ascii_lowercase().as_str() {
        "macos" => "macOS".into(),
        "ios" | "ipados" => "iOS".into(),
        "visionos" => "visionOS".into(),
        "tvos" => "tvOS".into(),
        other => other.to_string(),
    }
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
        // A rule has a row per platform and OS version; the newest one on a
        // platform is the rule as it stands there.
        let mut coverage: BTreeMap<String, (String, String)> = BTreeMap::new();
        type Newest = BTreeMap<(String, String), (String, Option<serde_json::Value>, Option<String>)>;
        let mut newest: Newest = BTreeMap::new();
        for p in mscp_schema::rule_payloads::read(mscp_schema::embedded_rule_payloads()).unwrap_or_default() {
            let platform = platform_name(&p.platform);
            let span = coverage.entry(platform.clone()).or_insert_with(|| (p.os_version.clone(), p.os_version.clone()));
            if newer(&span.0, &p.os_version) {
                span.0 = p.os_version.clone();
            }
            if newer(&p.os_version, &span.1) {
                span.1 = p.os_version.clone();
            }
            let key = (platform, p.rule_id);
            if newest.get(&key).is_some_and(|(have, _, _)| !newer(&p.os_version, have)) {
                continue;
            }
            let parsed = p.mobileconfig_info.as_deref().and_then(|i| serde_json::from_str(i).ok());
            let fix = p.fix_script.filter(|f| !f.trim().is_empty());
            newest.insert(key, (p.os_version, parsed, fix));
        }
        let mut settings = BTreeMap::new();
        let mut fixes = BTreeMap::new();
        for (key, (_, parsed, fix)) in newest {
            if let Some(parsed) = parsed {
                settings.insert(key.clone(), parsed);
            }
            if let Some(fix) = fix {
                fixes.insert(key, fix);
            }
        }

        let mut baselines: BTreeMap<(String, String), (String, Vec<String>)> = BTreeMap::new();
        for e in mscp_schema::baseline_edges::read(mscp_schema::embedded_baseline_edges()).unwrap_or_default() {
            let Some(platform) = e.platform.as_deref().map(platform_name) else { continue };
            let os = e.os_version.unwrap_or_default();
            let entry = baselines.entry((platform, e.baseline)).or_insert_with(|| (os.clone(), Vec::new()));
            if newer(&os, &entry.0) {
                *entry = (os.clone(), Vec::new());
            }
            if os == entry.0 && !entry.1.contains(&e.rule_id) {
                entry.1.push(e.rule_id);
            }
        }
        let mut baselines: BTreeMap<(String, String), Vec<String>> = baselines.into_iter().map(|(key, (_, ids))| (key, ids)).collect();
        add_branch_baselines(&mut rules, &mut docs, &mut settings, &mut baselines);
        Index {
            rules,
            docs,
            settings,
            fixes,
            baselines,
            coverage,
        }
    })
}

/// A baseline mSCP has on a 1.x branch but not yet in 2.0: rule ids, the
/// 2.0 names of renamed rules, and the rules 2.0 dropped with their keys.
#[derive(serde::Deserialize)]
struct BranchBaselines {
    platform: String,
    #[serde(default)]
    renamed: BTreeMap<String, String>,
    #[serde(default)]
    rule: Vec<BranchRule>,
    baselines: BTreeMap<String, BranchBaseline>,
}

#[derive(serde::Deserialize)]
struct BranchRule {
    id: String,
    title: String,
    settings: String,
}

#[derive(serde::Deserialize)]
struct BranchBaseline {
    rules: Vec<String>,
}

/// BSI Indigo for iOS, from mSCP's `ios_26` branch (see the file). The
/// dataset's own baseline of the same name, once there is one, wins.
// ponytail: carried in contour until posture imports it; drop the file then.
fn add_branch_baselines(
    rules: &mut Vec<(String, String, bool)>,
    docs: &mut Vec<[String; 3]>,
    settings: &mut BTreeMap<(String, String), serde_json::Value>,
    baselines: &mut BTreeMap<(String, String), Vec<String>>,
) {
    let Ok(branch) = toml::from_str::<BranchBaselines>(include_str!("mscp_indigo_ios_26.toml")) else { return };
    let platform = platform_name(&branch.platform);
    for r in branch.rule {
        if !rules.iter().any(|x| x.0 == r.id) {
            docs.push([r.title.clone(), r.id.replace('_', " "), String::new()]);
            rules.push((r.id.clone(), r.title, false));
        }
        if let Ok(v) = serde_json::from_str(&r.settings) {
            settings.entry((platform.clone(), r.id)).or_insert(v);
        }
    }
    for (name, b) in branch.baselines {
        let ids = b.rules.iter().map(|id| branch.renamed.get(id).cloned().unwrap_or_else(|| id.clone())).collect();
        baselines.entry((platform.clone(), name)).or_insert(ids);
    }
}

fn rule(index: &Index, platform: &str, i: usize, score: f32) -> Rule {
    let (rule_id, title, has_declaration) = &index.rules[i];
    let key = (platform.to_string(), rule_id.clone());
    let settings = index.settings.get(&key);
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
        fix_script: index.fixes.get(&key).cloned(),
    }
}

/// The rules whose title, id or discussion best match `query`, best first,
/// as they stand on macOS.
pub fn matching(query: &str, limit: usize) -> Vec<Rule> {
    let index = index();
    crate::rank_text(&index.docs, query)
        .into_iter()
        .take(limit)
        .map(|(i, score)| rule(index, MAC, i, score))
        .collect()
}

/// The oldest and the newest macOS version mSCP's rules here are written
/// for, e.g. `("15.0", "27.0")`. Baselines are built from the newest.
pub fn macos_coverage() -> Option<(String, String)> {
    coverage_for(MAC)
}

/// The same for any platform mSCP covers (`iOS`, `visionOS`).
pub fn coverage_for(platform: &str) -> Option<(String, String)> {
    index().coverage.get(&platform_name(platform)).cloned()
}

/// The names of the macOS baselines, e.g. `cis_lvl1`, `800-53r5_low`.
pub fn baselines() -> Vec<String> {
    baselines_for(MAC)
}

/// The names of one platform's baselines: `ios_stig` and
/// `cis_lvl1_enterprise` for iOS. Empty for a platform mSCP does not cover.
pub fn baselines_for(platform: &str) -> Vec<String> {
    let p = platform_name(platform);
    index().baselines.keys().filter(|(bp, _)| *bp == p).map(|(_, name)| name.clone()).collect()
}

/// Every rule of one macOS baseline, in the baseline's own order. `None`
/// when there is no baseline of that name.
pub fn baseline(name: &str) -> Option<Vec<Rule>> {
    baseline_for(MAC, name)
}

/// Every rule of one platform's baseline, as the rule stands there.
pub fn baseline_for(platform: &str, name: &str) -> Option<Vec<Rule>> {
    let index = index();
    let p = platform_name(platform);
    let ids = index.baselines.get(&(p.clone(), name.to_string()))?;
    Some(
        ids.iter()
            .filter_map(|id| index.rules.iter().position(|r| r.0 == *id))
            .map(|i| rule(index, &p, i, 0.0))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// iOS has baselines of its own, with its own rules' settings.
    #[test]
    fn ios_has_its_own_baselines() {
        let ios = baselines_for("iOS");
        assert!(ios.iter().any(|b| b == "ios_stig") && ios.iter().any(|b| b == "cis_lvl1_enterprise"), "{ios:?}");
        assert!(!baselines().iter().any(|b| b == "ios_stig"), "not a macOS baseline");
        let stig = baseline_for("ios", "ios_stig").unwrap();
        assert!(stig.iter().any(|r| r.enforced_by == "profile" && !r.keys().is_empty()));
        assert!(baselines_for("tvOS").is_empty());
    }

    /// BSI Indigo, from mSCP's ios_26 branch: every rule resolves, renamed
    /// ones by their 2.0 name, dropped ones with their own keys.
    #[test]
    fn indigo_comes_from_the_ios_26_branch() {
        for (name, count) in [("indigo_base", 79), ("indigo_high", 121)] {
            let rules = baseline_for("iOS", name).unwrap();
            assert_eq!(rules.len(), count, "{name}: every rule found");
            assert!(rules.iter().filter(|r| r.enforced_by == "profile").count() > count * 8 / 10, "{name}");
        }
        let base = baseline_for("iOS", "indigo_base").unwrap();
        let trust = base.iter().find(|r| r.rule_id == "os_disallow_enterprise_app_trust").unwrap();
        assert_eq!(trust.keys(), [("com.apple.applicationaccess".to_string(), "allowEnterpriseAppTrust".to_string(), serde_json::json!(false))]);
        assert!(base.iter().any(|r| r.rule_id == "system_settings_siri_disable"), "renamed to the 2.0 rule");
        assert!(!baselines().iter().any(|b| b.starts_with("indigo")), "not a macOS baseline");
    }

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
