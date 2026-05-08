//! Aggregate the mobileconfig-bearing rules of an mSCP baseline into
//! a single contour recipe TOML.
//!
//! Each baseline rule may declare a `mobileconfig_info` mapping whose
//! TOP-LEVEL keys are the Apple payload type identifiers (e.g.
//! `com.apple.security.firewall`) and whose values are flat dicts of
//! settings. Rules that target the same payload type are merged into
//! one `[[profile]]` block in the resulting recipe.
//!
//! On key collision within a payload type the writer warns to stderr
//! and the later writer wins. Compliance baselines are mostly
//! collision-free in practice; this matches the behavior of mSCP's
//! own Python generator.
//!
//! The recipe TOML output is consumed by
//! `contour profile generate --recipe <path>` so a baseline becomes a
//! reusable, library-shaped artifact rather than ~100 standalone
//! mobileconfig files.
//!
//! Example: `cis_lvl1.toml` typically yields roughly fifteen
//! `[[profile]]` blocks (firewall, screensaver, password policy, …).

use anyhow::{Context, Result};
use contour_profiles::{RecipeProfile, write_recipe_toml};
use plist::{Dictionary, Value as PlistValue};
use std::collections::BTreeMap;

use crate::models::MscpRule;

/// One key collision encountered while aggregating rules.
///
/// Returned alongside the rendered recipe so callers can surface the
/// list however they want (stderr line, JSON envelope, …) without the
/// aggregator dictating a printing strategy.
#[derive(Debug, Clone)]
pub struct ConflictWarning {
    pub payload_type: String,
    pub key: String,
    pub previous_rule: String,
    pub previous_value: String,
    pub winning_rule: String,
    pub winning_value: String,
}

impl std::fmt::Display for ConflictWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] key '{}' set by '{}' = {} then by '{}' = {}; using last writer",
            self.payload_type,
            self.key,
            self.previous_rule,
            self.previous_value,
            self.winning_rule,
            self.winning_value,
        )
    }
}

/// Aggregate `rules` into a recipe TOML string for `baseline_name`.
///
/// Returns the rendered TOML and the list of key collisions detected
/// during merging.
pub fn baseline_to_recipe(
    baseline_name: &str,
    org: Option<&str>,
    rules: &[MscpRule],
) -> Result<(String, Vec<ConflictWarning>)> {
    // Stable order: iterate in payload-type alphabetical order so the
    // resulting TOML is deterministic across invocations.
    let mut grouped: BTreeMap<String, Group> = BTreeMap::new();
    let mut warnings: Vec<ConflictWarning> = Vec::new();

    // Sort rules by id so "last writer wins" is deterministic — the
    // rule extractor walks the filesystem and returns rules in
    // walkdir order, which varies by platform.
    let mut sorted: Vec<&MscpRule> = rules.iter().filter(|r| r.mobileconfig).collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));

    for rule in sorted {
        let Some(info) = rule.mobileconfig_info.as_ref() else {
            continue;
        };
        let Some(mapping) = info.as_mapping() else {
            continue;
        };

        for (payload_key, payload_fields) in mapping {
            let Some(payload_type) = payload_key.as_str() else {
                continue;
            };
            let Some(field_map) = payload_fields.as_mapping() else {
                continue;
            };

            let group = grouped
                .entry(payload_type.to_string())
                .or_insert_with(|| Group::new(payload_type));

            for (field_key, field_val) in field_map {
                let Some(key_str) = field_key.as_str() else {
                    continue;
                };
                let plist_val = yaml_to_plist(field_val).with_context(|| {
                    format!("converting key '{key_str}' from rule '{}'", rule.id)
                })?;

                if let Some(prev) = group.fields.get(key_str) {
                    let prev_rule = group
                        .field_origin
                        .get(key_str)
                        .cloned()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    warnings.push(ConflictWarning {
                        payload_type: payload_type.to_string(),
                        key: key_str.to_string(),
                        previous_rule: prev_rule,
                        previous_value: short_repr(prev),
                        winning_rule: rule.id.clone(),
                        winning_value: short_repr(&plist_val),
                    });
                }

                group.fields.insert(key_str.to_string(), plist_val);
                group
                    .field_origin
                    .insert(key_str.to_string(), rule.id.clone());
            }
        }
    }

    let profiles: Vec<RecipeProfile> = grouped.into_values().map(Group::into_profile).collect();

    let body = write_recipe_toml(
        baseline_name,
        &format!(
            "mSCP {} baseline aggregated into one recipe ({} profile(s))",
            baseline_name,
            profiles.len()
        ),
        org,
        &profiles,
    )?;

    Ok((body, warnings))
}

struct Group {
    payload_type: String,
    fields: Dictionary,
    field_origin: BTreeMap<String, String>,
}

impl Group {
    fn new(payload_type: &str) -> Self {
        Self {
            payload_type: payload_type.to_string(),
            fields: Dictionary::new(),
            field_origin: BTreeMap::new(),
        }
    }

    fn into_profile(self) -> RecipeProfile {
        let tail = self
            .payload_type
            .rsplit('.')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.payload_type);
        RecipeProfile {
            filename: format!("{tail}.mobileconfig"),
            payload_type: self.payload_type.clone(),
            // Schema-aware display names belong in a follow-on; for
            // now the payload-type tail is a usable identifier.
            display_name: humanize_tail(tail),
            description: String::new(),
            removal_disallowed: true,
            fields: self.fields,
        }
    }
}

fn yaml_to_plist(value: &yaml_serde::Value) -> Result<PlistValue> {
    Ok(match value {
        yaml_serde::Value::Null => PlistValue::String(String::new()),
        yaml_serde::Value::Bool(b) => PlistValue::Boolean(*b),
        yaml_serde::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PlistValue::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                PlistValue::Integer(u.into())
            } else if let Some(f) = n.as_f64() {
                PlistValue::Real(f)
            } else {
                anyhow::bail!("unsupported YAML number: {n}");
            }
        }
        yaml_serde::Value::String(s) => PlistValue::String(s.clone()),
        yaml_serde::Value::Sequence(seq) => {
            let mut out = Vec::with_capacity(seq.len());
            for v in seq {
                out.push(yaml_to_plist(v)?);
            }
            PlistValue::Array(out)
        }
        yaml_serde::Value::Mapping(map) => {
            let mut dict = Dictionary::new();
            for (k, v) in map {
                let key = k
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("non-string YAML mapping key: {k:?}"))?;
                dict.insert(key.to_string(), yaml_to_plist(v)?);
            }
            PlistValue::Dictionary(dict)
        }
        yaml_serde::Value::Tagged(tagged) => yaml_to_plist(&tagged.value)?,
    })
}

fn short_repr(v: &PlistValue) -> String {
    match v {
        PlistValue::String(s) => format!("\"{}\"", truncate(s, 40)),
        PlistValue::Boolean(b) => b.to_string(),
        PlistValue::Integer(i) => i.to_string(),
        PlistValue::Real(f) => f.to_string(),
        PlistValue::Array(_) => "<array>".to_string(),
        PlistValue::Dictionary(_) => "<dict>".to_string(),
        _ => "<value>".to_string(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n).collect();
        format!("{head}…")
    }
}

fn humanize_tail(tail: &str) -> String {
    // "Firewall" → "Firewall"; "screensaver" → "Screensaver"; mixed
    // case stays as-is. Apple's payload-type tails are already
    // human-friendly.
    let mut chars = tail.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, info: yaml_serde::Value) -> MscpRule {
        MscpRule {
            id: id.to_string(),
            title: id.to_string(),
            discussion: String::new(),
            check: None,
            result: None,
            fix: None,
            references: std::collections::HashMap::default(),
            macos: Vec::new(),
            tags: Vec::new(),
            severity: None,
            mobileconfig: true,
            mobileconfig_info: Some(info),
            odv: None,
        }
    }

    #[test]
    fn aggregates_two_rules_same_payload() {
        let info_a: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: true\n").unwrap();
        let info_b: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  LoggingOption: throttled\n")
                .unwrap();
        let rules = vec![rule("fw_on", info_a), rule("fw_log", info_b)];

        let (toml, warnings) = baseline_to_recipe("test", Some("com.acme"), &rules).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(toml.matches("[[profile]]").count(), 1);
        assert!(toml.contains("EnableFirewall = true"));
        assert!(toml.contains("LoggingOption = \"throttled\""));
    }

    #[test]
    fn separate_payload_types_yield_separate_profiles() {
        let info_a: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: true\n").unwrap();
        let info_b: yaml_serde::Value =
            yaml_serde::from_str("com.apple.screensaver:\n  idleTime: 300\n").unwrap();
        let rules = vec![rule("fw", info_a), rule("ss", info_b)];

        let (toml, warnings) = baseline_to_recipe("two", None, &rules).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(toml.matches("[[profile]]").count(), 2);
    }

    #[test]
    fn collision_emits_warning_last_writer_wins() {
        let info_a: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: false\n")
                .unwrap();
        let info_b: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: true\n").unwrap();
        let rules = vec![rule("fw_off", info_a), rule("fw_on", info_b)];

        let (toml, warnings) = baseline_to_recipe("c", None, &rules).unwrap();
        assert_eq!(warnings.len(), 1);
        let w = &warnings[0];
        assert_eq!(w.key, "EnableFirewall");
        assert_eq!(w.previous_rule, "fw_off");
        assert_eq!(w.winning_rule, "fw_on");
        assert!(toml.contains("EnableFirewall = true"));
    }

    #[test]
    fn skips_non_mobileconfig_rules() {
        let info: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: true\n").unwrap();
        let mut r = rule("fw", info);
        r.mobileconfig = false;
        let (toml, _) = baseline_to_recipe("none", None, &[r]).unwrap();
        assert_eq!(toml.matches("[[profile]]").count(), 0);
    }
}
