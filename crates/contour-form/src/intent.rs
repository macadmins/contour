//! A set of settings as a file, and a compliance baseline as a set of
//! settings.
//!
//! An [`Intent`] says what to deploy, by payload type, and optionally for
//! whom. contour renders the documents from it, so the file is what is
//! kept, reviewed and shared; the documents are its output.
//!
//! [`sort_baseline`] turns one mSCP baseline into the settings a profile can
//! carry and a list of what it cannot, and [`script_documents`] gives the
//! remediation scripts for that second list.
//!
//! No filesystem and no network: a server saves the text this produces, a
//! browser keeps it in its own storage.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{SchemaRegistry, Setting, mscp_rules};

/// Recipe name to its variables.
pub type Recipes = BTreeMap<String, BTreeMap<String, String>>;

/// A session as a file: what to set, by payload type, and for whom.
///
/// ```toml
/// org = "com.acme"
/// platform = "macOS"
///
/// [settings."com.apple.applicationaccess"]
/// allowAirDrop = false
/// ```
///
/// Keys are the dotted paths search returns, so a nested key is one quoted
/// name (`"Deferrals.MajorPeriodInDays" = 14`). Both levels are sorted, so
/// the same settings always give the same bytes.
///
/// `org` is optional. A file without it is one to share: it says what to
/// set and not whose devices they are, and each organisation that uses it
/// passes `--org`. Identifiers and UUIDs derive from the organisation, so
/// two organisations rendering the same file get documents that differ only
/// there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Intent {
    /// What this file is, for the person who is handed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Words that say what the intent took in along the way, so it still
    /// says so when the choice is undone: `baseline:800-171`,
    /// `recipe:okta`, and any the person or agent adds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// What the session held when the intent was last written: its payload
    /// types and tags. What changed since is what the intent may not cover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub described_from: Option<DescribedFrom>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    pub platform: String,
    /// The one mSCP baseline the settings start from, when there is one.
    /// Only one at a time: two baselines are two answers to the same
    /// questions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
    /// Baselines whose script-enforced rules are rendered as remediation
    /// scripts, for what no profile can carry: `scripts = ["cis_lvl1"]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub settings: BTreeMap<String, BTreeMap<String, Value>>,
    /// Recipes to render beside the settings, each with its variables:
    ///
    /// ```toml
    /// [recipes.okta]
    /// OKTA_DOMAIN = "acme.okta.com"
    /// SCEP_CHALLENGE = "op://vault/okta/scep"
    /// ```
    ///
    /// A secret stays the reference it was written as. It is resolved when
    /// the documents are rendered for deployment, never into this file.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub recipes: Recipes,
    /// Payload types whose profile is also written as a DDM
    /// `com.apple.configuration.legacy` declaration pointing at it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy: Vec<String>,
    /// Where those profiles are served, for the declaration's `ProfileURL`:
    /// `https://mdm.acme.com/profiles/{name}`, `{name}` the profile's file name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_url: Option<String>,
    /// A wrapped profile's own address, by payload type, over `legacy_url`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub legacy_urls: BTreeMap<String, String>,
    /// The OS version the devices run (`"27.2"`). What Apple removed by
    /// then is left out of the documents, because the device ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Removed by `os_version` but written anyway, for older devices: a
    /// payload type (`com.apple.SoftwareUpdate`) or a type and key
    /// (`com.apple.applicationaccess forceDelayedSoftwareUpdates`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keep_removed: Vec<String>,
    /// Payload types written as given where the schema does not know them
    /// (a vendor's domain contour has no schema for, or undocumented keys):
    /// accepted by the person, unchecked by contour.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept_unknown: Vec<String>,
    /// Folders the settings came from, relative to this file
    /// (`../sprouted/profiles/macos`): where to look again, offered as
    /// folders to open. Rendering never reads them; the settings above are
    /// the intent, whatever the folders hold now.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}

/// The payload types and tags an intent was written from.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DescribedFrom {
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// mSCP's remediation scripts for the rules of `baselines` that a profile
/// cannot enforce, one file per rule.
///
/// The script body is mSCP's own `fix`. A rule with no profile and no fix
/// is manual, and gets no file.
pub fn script_documents(baselines: &[String]) -> Vec<Value> {
    baselines
        .iter()
        .flat_map(|baseline| {
            mscp_rules::baseline(baseline)
                .unwrap_or_default()
                .into_iter()
                .filter(|r| r.enforced_by != "profile")
                .filter_map(move |r| {
                    let fix = r.fix_script?;
                    Some(json!({
                        "filename": format!("scripts/{baseline}/{}.sh", r.rule_id),
                        "format": "script",
                        "baseline": baseline,
                        "rule_id": r.rule_id,
                        "title": r.title,
                        "body": format!(
                            "#!/bin/zsh\n# mSCP remediation: {}\n# Rule: {}\n# Baseline: {baseline}\n#\n# Changes the system and must run as root. Remediation only: it does not\n# check first. Review it before deploying.\n\nset -e\n\n{}\n",
                            r.title,
                            r.rule_id,
                            fix.trim_end()
                        ),
                    }))
                })
        })
        .collect()
}


const INTENT_HEADER: &str = "# contour intent: the settings to deploy, by payload type.\n\
# contour renders the documents from this file; nobody edits a profile.\n\
#   contour-session --intent <this file>                  open it as a shared session\n\
#   contour-session --intent <this file> --render <dir>   write the documents\n\
# A file with no `org` is shareable: add --org <your domain> to either command.\n\n";

impl Intent {
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).context("not a contour intent file")
    }

    pub fn to_toml(&self) -> Result<String> {
        Ok(format!("{INTENT_HEADER}{}", toml::to_string(self).context("a value in the session cannot be written to the intent file")?))
    }

    pub fn settings(&self) -> Vec<Setting> {
        self.settings
            .iter()
            .flat_map(|(type_id, keys)| {
                keys.iter().map(move |(path, value)| Setting {
                    type_id: type_id.clone(),
                    path: path.clone(),
                    value: value.clone(),
                })
            })
            .collect()
    }
}


/// A baseline's rules, by whether a profile can carry them.
#[derive(Debug, Clone)]
pub struct SortedBaseline {
    pub name: String,
    /// The platform the baseline is for: `macOS`, `iOS`.
    pub platform: String,
    pub rules: usize,
    /// Every setting of every rule in `by_profile`.
    pub settings: Vec<Setting>,
    pub by_profile: Vec<Value>,
    pub not_by_profile: Vec<Value>,
    pub not_in_schema: Vec<Value>,
    /// How many of `not_by_profile` have a remediation script.
    pub scripted: usize,
}

impl SortedBaseline {
    pub fn report(&self) -> Value {
        json!({
            "baseline": self.name,
            "rules": self.rules,
            "by_profile": self.by_profile,
            "not_by_profile": self.not_by_profile,
            "not_in_schema": self.not_in_schema,
            "remediation_scripts_available": self.scripted,
            "applied": false,
        })
    }

    /// What a shared file says about itself, so its reader knows what it
    /// covers, what it leaves out, and which OS versions it is for.
    pub fn summary(&self) -> String {
        format!(
            "mSCP baseline {} for {}: {} of {} rules, the ones a profile can carry. Not included: {} enforced by a script or declaration, {} whose keys are not in the schema. {}",
            self.name,
            self.platform,
            self.by_profile.len(),
            self.rules,
            self.not_by_profile.len(),
            self.not_in_schema.len(),
            os_coverage_for(&self.platform)
        )
    }
}

/// Which macOS versions the baselines are for, in one sentence, from the
/// rules themselves. `15.0` and `27.0` read as "macOS 15" and "macOS 27".
pub fn os_coverage() -> String {
    os_coverage_for("macOS")
}

/// The same for one platform's baselines.
pub fn os_coverage_for(platform: &str) -> String {
    let major = |v: &str| v.split('.').next().unwrap_or(v).to_string();
    match mscp_rules::coverage_for(platform) {
        Some((oldest, newest)) => format!(
            "For {platform} {} and later only: mSCP has no rules for older versions. Built from the {platform} {} rule set; each document states the minimum {platform} its own keys need.",
            major(&oldest),
            major(&newest)
        ),
        None => format!("The embedded dataset carries no mSCP rules for {platform}."),
    }
}

/// The setting a rule's `(payload type, key, value)` means in this schema,
/// when the schema has the key. mSCP names a top-level key by its name; the
/// schema's path escapes dots in it.
pub fn setting_for(reg: &SchemaRegistry, type_id: &str, key: &str, value: &Value) -> Option<Setting> {
    let m = reg
        .get(type_id)
        .or_else(|| reg.all().find(|m| m.payload_type.eq_ignore_ascii_case(type_id)))?;
    let field = m
        .fields
        .values()
        .find(|f| f.depth == 0 && (f.path == key || f.name == key))?;
    Some(Setting {
        type_id: m.payload_type.clone(),
        path: field.path.clone(),
        value: crate::emit::typed(field, value.clone()),
    })
}

pub fn sort_baseline(reg: &SchemaRegistry, name: &str) -> Result<SortedBaseline, String> {
    sort_baseline_for(reg, "macOS", name)
}

/// One platform's baseline, sorted the same way: `iOS` `ios_stig`.
pub fn sort_baseline_for(reg: &SchemaRegistry, platform: &str, name: &str) -> Result<SortedBaseline, String> {
    let known = mscp_rules::baselines_for(platform);
    let rules = mscp_rules::baseline_for(platform, name).ok_or_else(|| {
        if known.is_empty() {
            format!("mSCP has no baselines for {platform}")
        } else {
            format!("no {platform} baseline named `{name}`; known: {}", known.join(", "))
        }
    })?;
    let mut sorted = SortedBaseline {
        name: name.to_string(),
        platform: platform.to_string(),
        rules: rules.len(),
        settings: Vec::new(),
        by_profile: Vec::new(),
        not_by_profile: Vec::new(),
        not_in_schema: Vec::new(),
        scripted: 0,
    };
    for r in &rules {
        if r.enforced_by != "profile" {
            sorted.scripted += usize::from(r.fix_script.is_some());
            sorted.not_by_profile.push(json!({
                "rule_id": r.rule_id, "title": r.title, "enforced_by": r.enforced_by,
                "has_script": r.fix_script.is_some(),
            }));
            continue;
        }
        let keys = r.keys();
        let found: Vec<Setting> = keys.iter().filter_map(|(t, k, v)| setting_for(reg, t, k, v)).collect();
        if found.len() < keys.len() {
            // Part of a rule is not the rule. Leave it out whole and say why.
            let missing: Vec<String> = keys
                .iter()
                .filter(|(t, k, v)| setting_for(reg, t, k, v).is_none())
                .map(|(t, k, _)| format!("{t} {k}"))
                .collect();
            sorted
                .not_in_schema
                .push(json!({"rule_id": r.rule_id, "title": r.title, "keys": missing}));
            continue;
        }
        sorted
            .by_profile
            .push(json!({"rule_id": r.rule_id, "title": r.title, "settings": found}));
        sorted.settings.extend(found);
    }
    Ok(sorted)
}


