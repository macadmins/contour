//! Aggregate the mobileconfig- and DDM-bearing rules of an mSCP
//! baseline into a single contour recipe TOML.
//!
//! Each baseline rule may declare:
//!   * a `mobileconfig_info` mapping (top-level keys = Apple payload
//!     types, values = flat field dicts) — rules with the same payload
//!     type merge into one `[[profile]]` block.
//!   * a `ddm_info` mapping with `declarationtype` + `ddm_key` +
//!     `ddm_value` — rules with the same `declarationtype` merge into
//!     one `[[ddm]]` block whose configuration payload is the union
//!     of every contributor's `ddm_key → ddm_value` pair.
//!
//! On key collision (same payload-type key OR same DDM key inside a
//! configuration) the writer warns to stderr and the later writer
//! wins. Compliance baselines are mostly collision-free in practice;
//! this matches the behavior of mSCP's own Python generator.
//!
//! The recipe TOML output is consumed by
//! `contour profile generate --recipe <path>` so a baseline becomes a
//! reusable, library-shaped artifact rather than ~100 standalone
//! mobileconfig files plus loose DDM declarations.
//!
//! Example: `cis_lvl1.toml` typically yields roughly fifteen
//! `[[profile]]` blocks (firewall, screensaver, password policy, …)
//! plus a handful of `[[ddm]]` blocks (software-update settings,
//! diagnostic submission, …).

use anyhow::{Context, Result};
use contour_profiles::{RecipeProfile, write_recipe_toml};
use plist::{Dictionary, Value as PlistValue};
use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::models::MscpRule;

/// Counts surfaced alongside the rendered recipe so callers (CLI,
/// dispatch, future JSON envelope) don't need to grep the body
/// string to report what landed.
#[derive(Debug, Clone, Default)]
pub struct AggregateStats {
    /// Number of `[[profile]]` blocks emitted (unique mobileconfig
    /// payload types across all contributing rules).
    pub profile_count: usize,
    /// Number of `[[ddm]]` blocks emitted (unique DDM declaration
    /// types across all contributing rules).
    pub ddm_count: usize,
    /// Rules whose `mobileconfig: true` made them eligible for the
    /// profile pass (whether they had `mobileconfig_info` or not).
    pub mobileconfig_rule_count: usize,
    /// Rules with a `ddm_info:` block that contributed to the DDM
    /// pass.
    pub ddm_rule_count: usize,
}

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
/// Returns the rendered TOML, the list of key collisions detected
/// during merging (covers both profile and DDM passes), and the
/// per-pass counts.
pub fn baseline_to_recipe(
    baseline_name: &str,
    org: Option<&str>,
    rules: &[MscpRule],
) -> Result<(String, Vec<ConflictWarning>, AggregateStats)> {
    let mut warnings: Vec<ConflictWarning> = Vec::new();
    let mut stats = AggregateStats::default();

    let profiles = aggregate_profiles(rules, &mut warnings, &mut stats)?;
    let ddm_bundles = aggregate_ddm(rules, &mut warnings, &mut stats)?;

    stats.profile_count = profiles.len();
    stats.ddm_count = ddm_bundles.len();

    let description = format!(
        "mSCP {} baseline aggregated into one recipe ({} profile(s), {} ddm bundle(s))",
        baseline_name, stats.profile_count, stats.ddm_count
    );
    let mut body = write_recipe_toml(baseline_name, &description, org, &profiles)?;

    if !ddm_bundles.is_empty() {
        let ddm_section = render_ddm_section(&ddm_bundles)?;
        body.push_str(&ddm_section);
    }

    Ok((body, warnings, stats))
}

fn aggregate_profiles(
    rules: &[MscpRule],
    warnings: &mut Vec<ConflictWarning>,
    stats: &mut AggregateStats,
) -> Result<Vec<RecipeProfile>> {
    // Stable order: iterate in payload-type alphabetical order so the
    // resulting TOML is deterministic across invocations.
    let mut grouped: BTreeMap<String, Group> = BTreeMap::new();

    // Sort rules by id so "last writer wins" is deterministic — the
    // rule extractor walks the filesystem and returns rules in
    // walkdir order, which varies by platform.
    let mut sorted: Vec<&MscpRule> = rules.iter().filter(|r| r.mobileconfig).collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    stats.mobileconfig_rule_count = sorted.len();

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

    Ok(grouped.into_values().map(Group::into_profile).collect())
}

fn aggregate_ddm(
    rules: &[MscpRule],
    warnings: &mut Vec<ConflictWarning>,
    stats: &mut AggregateStats,
) -> Result<Vec<DdmBundle>> {
    let mut grouped: BTreeMap<String, DdmGroup> = BTreeMap::new();

    let mut sorted: Vec<&MscpRule> = rules.iter().filter(|r| r.ddm_info.is_some()).collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    stats.ddm_rule_count = sorted.len();

    for rule in sorted {
        let info = rule
            .ddm_info
            .as_ref()
            .and_then(yaml_serde::Value::as_mapping)
            .ok_or_else(|| anyhow::anyhow!("rule '{}' ddm_info must be a mapping", rule.id))?;

        let declarationtype = info
            .get("declarationtype")
            .and_then(yaml_serde::Value::as_str)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "rule '{}' ddm_info missing string `declarationtype`",
                    rule.id
                )
            })?
            .to_string();

        // mSCP carries TWO `ddm_info` shapes:
        //   * settings-style: `ddm_key` + `ddm_value` (handled here)
        //   * services-configuration-files: `service` + `config_file` +
        //     `configuration_key` + `configuration_value` — these
        //     translate to Apple's
        //     `com.apple.configuration.services.configuration-files`
        //     declaration which requires a paired asset bundle. That
        //     translation is out of scope for this aggregator; skip
        //     with a stderr note and let operators author the
        //     services recipe manually.
        let Some(ddm_key) = info.get("ddm_key").and_then(yaml_serde::Value::as_str) else {
            eprintln!(
                "warning: rule '{}' uses an unsupported ddm_info shape (declarationtype={}); \
                 skipping — services-configuration-files bundles are not aggregated",
                rule.id, declarationtype
            );
            continue;
        };
        let ddm_key = ddm_key.to_string();
        let ddm_value_yaml = info
            .get("ddm_value")
            .ok_or_else(|| anyhow::anyhow!("rule '{}' ddm_info missing `ddm_value`", rule.id))?;
        let ddm_value = yaml_to_plist(ddm_value_yaml)
            .with_context(|| format!("converting ddm_value of rule '{}'", rule.id))?;

        let group = grouped
            .entry(declarationtype.clone())
            .or_insert_with(|| DdmGroup::new(&declarationtype));

        if let Some(prev) = group.payload.get(&ddm_key) {
            let prev_rule = group
                .field_origin
                .get(&ddm_key)
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            warnings.push(ConflictWarning {
                payload_type: declarationtype.clone(),
                key: ddm_key.clone(),
                previous_rule: prev_rule,
                previous_value: short_repr(prev),
                winning_rule: rule.id.clone(),
                winning_value: short_repr(&ddm_value),
            });
        }

        group.payload.insert(ddm_key.clone(), ddm_value);
        group.field_origin.insert(ddm_key, rule.id.clone());
    }

    Ok(grouped.into_values().map(DdmGroup::into_bundle).collect())
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

struct DdmGroup {
    declarationtype: String,
    payload: Dictionary,
    field_origin: BTreeMap<String, String>,
}

impl DdmGroup {
    fn new(declarationtype: &str) -> Self {
        Self {
            declarationtype: declarationtype.to_string(),
            payload: Dictionary::new(),
            field_origin: BTreeMap::new(),
        }
    }

    fn into_bundle(self) -> DdmBundle {
        DdmBundle {
            intent_name: derive_intent_name(&self.declarationtype),
            declarationtype: self.declarationtype,
            payload: self.payload,
        }
    }
}

/// Internal representation of one rendered `[[ddm]]` block. Mirror of
/// the on-disk recipe shape consumed by `crates/profile/src/recipe`.
struct DdmBundle {
    intent_name: String,
    declarationtype: String,
    payload: Dictionary,
}

/// Derive a short, identifier-friendly bundle name from a DDM
/// `declarationtype`. Strips Apple's well-known prefixes so the
/// resulting `intent_name` matches the convention used by the
/// embedded `hardening-macos-baseline` recipe.
///
/// `com.apple.configuration.softwareupdate.settings` →
/// `softwareupdate-settings`.
fn derive_intent_name(declarationtype: &str) -> String {
    const PREFIXES: &[&str] = &[
        "com.apple.configuration.",
        "com.apple.management.",
        "com.apple.activation.",
        "com.apple.asset.",
    ];
    let stripped = PREFIXES
        .iter()
        .find_map(|p| declarationtype.strip_prefix(p))
        .unwrap_or(declarationtype);
    stripped.replace('.', "-")
}

/// Render the `[[ddm]]` section of a recipe. Each bundle becomes
/// one block with the canonical `intent_name`/`configuration`/
/// `activation` shape that `crates/profile/src/ddm/compose.rs::Bundle`
/// deserializes.
///
/// Implementation: serialize the bundle's body as a flat
/// `toml::Value::Table` with `configuration` and `activation`
/// subtables, then prepend the `[[ddm]]` array-of-tables header and
/// rewrite the section headers to live under `ddm.*`.
fn render_ddm_section(bundles: &[DdmBundle]) -> Result<String> {
    use toml::Value as TVal;

    let mut out = String::new();
    for bundle in bundles {
        let _ = writeln!(out);
        let _ = writeln!(out, "[[ddm]]");
        let _ = writeln!(out, "intent_name = {}", quote_toml_str(&bundle.intent_name));

        // Configuration subtable.
        let mut config_tbl = toml::map::Map::new();
        config_tbl.insert(
            "type".to_string(),
            TVal::String(bundle.declarationtype.clone()),
        );
        config_tbl.insert(
            "payload".to_string(),
            plist_dict_to_toml_table(&bundle.payload)?,
        );
        let config_serialized =
            toml::to_string(&TVal::Table(config_tbl)).context("serializing ddm.configuration")?;
        let _ = writeln!(out);
        let _ = writeln!(out, "[ddm.configuration]");
        rewrite_subtables(&config_serialized, "configuration", &mut out);

        // Activation: bare `simple` activation. mSCP rules don't
        // express predicates today; operators wanting gated
        // activations edit the rendered TOML.
        let _ = writeln!(out);
        let _ = writeln!(out, "[ddm.activation]");
        let _ = writeln!(out, r#"type = "com.apple.activation.simple""#);
    }
    Ok(out)
}

/// Append a serialized TOML block under a `ddm.<section>` namespace.
/// The input is the output of `toml::to_string(&Value::Table(...))`
/// where the root has `type = ...` and a nested `payload` table.
/// Lines that aren't section headers go through unchanged; section
/// headers are rewritten so `[payload]` → `[ddm.<section>.payload]`,
/// `[payload.foo]` → `[ddm.<section>.payload.foo]`, etc. Because the
/// caller already wrote the top-level `[ddm.<section>]` header, we
/// skip the root `[<section>]` line if present.
fn rewrite_subtables(serialized: &str, section: &str, out: &mut String) {
    for line in serialized.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix('[') {
            // `[name]` or `[name.sub]` — rewrite under ddm.<section>.
            // The serializer also emits `[[name]]`-style array
            // tables; treat them with the same rewrite.
            let array_table = rest.starts_with('[');
            let inner = if array_table {
                &rest[1..rest.len().saturating_sub(2)]
            } else {
                &rest[..rest.len().saturating_sub(1)]
            };
            if array_table {
                let _ = writeln!(out, "[[ddm.{section}.{inner}]]");
            } else {
                let _ = writeln!(out, "[ddm.{section}.{inner}]");
            }
        } else {
            let _ = writeln!(out, "{line}");
        }
    }
}

/// Convert a `plist::Dictionary` to a `toml::Value::Table`. Mirrors
/// the converter in `contour-profiles::recipe_writer` but is
/// duplicated here to avoid widening that crate's API for one
/// caller.
fn plist_dict_to_toml_table(dict: &Dictionary) -> Result<toml::Value> {
    let mut tbl = toml::map::Map::new();
    for (k, v) in dict {
        tbl.insert(k.clone(), plist_to_toml(v)?);
    }
    Ok(toml::Value::Table(tbl))
}

fn plist_to_toml(v: &PlistValue) -> Result<toml::Value> {
    Ok(match v {
        PlistValue::String(s) => toml::Value::String(s.clone()),
        PlistValue::Boolean(b) => toml::Value::Boolean(*b),
        PlistValue::Integer(i) => i
            .as_signed()
            .map(toml::Value::Integer)
            .or_else(|| {
                i.as_unsigned()
                    .and_then(|u| i64::try_from(u).ok().map(toml::Value::Integer))
            })
            .ok_or_else(|| anyhow::anyhow!("integer out of i64 range"))?,
        PlistValue::Real(f) => toml::Value::Float(*f),
        PlistValue::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(plist_to_toml(item)?);
            }
            toml::Value::Array(out)
        }
        PlistValue::Dictionary(d) => plist_dict_to_toml_table(d)?,
        _ => anyhow::bail!("unsupported plist value variant for ddm payload"),
    })
}

fn quote_toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
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
            ddm_info: None,
            odv: None,
        }
    }

    fn ddm_rule(id: &str, ddm_yaml: &str) -> MscpRule {
        let value: yaml_serde::Value = yaml_serde::from_str(ddm_yaml).unwrap();
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
            mobileconfig: false,
            mobileconfig_info: None,
            ddm_info: Some(value),
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

        let (toml, warnings, stats) = baseline_to_recipe("test", Some("com.acme"), &rules).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(toml.matches("[[profile]]").count(), 1);
        assert_eq!(stats.profile_count, 1);
        assert_eq!(stats.ddm_count, 0);
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

        let (toml, warnings, stats) = baseline_to_recipe("two", None, &rules).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(toml.matches("[[profile]]").count(), 2);
        assert_eq!(stats.profile_count, 2);
    }

    #[test]
    fn collision_emits_warning_last_writer_wins() {
        let info_a: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: false\n")
                .unwrap();
        let info_b: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: true\n").unwrap();
        let rules = vec![rule("fw_off", info_a), rule("fw_on", info_b)];

        let (toml, warnings, _stats) = baseline_to_recipe("c", None, &rules).unwrap();
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
        let (toml, _, stats) = baseline_to_recipe("none", None, &[r]).unwrap();
        assert_eq!(toml.matches("[[profile]]").count(), 0);
        assert_eq!(stats.profile_count, 0);
    }

    // ── DDM coverage ──────────────────────────────────────────────

    #[test]
    fn derives_intent_name_from_known_prefixes() {
        assert_eq!(
            derive_intent_name("com.apple.configuration.softwareupdate.settings"),
            "softwareupdate-settings"
        );
        assert_eq!(
            derive_intent_name("com.apple.management.status-subscriptions"),
            "status-subscriptions"
        );
        assert_eq!(
            derive_intent_name("com.example.custom.config"),
            "com-example-custom-config"
        );
    }

    #[test]
    fn ddm_rule_emits_one_bundle() {
        let r = ddm_rule(
            "su_download",
            "declarationtype: com.apple.configuration.softwareupdate.settings\n\
             ddm_key: AutomaticActions\n\
             ddm_value:\n  Download: AlwaysOn\n",
        );
        let (toml, warnings, stats) = baseline_to_recipe("ddm", Some("com.acme"), &[r]).unwrap();
        assert!(warnings.is_empty(), "no collisions for a single rule");
        assert_eq!(stats.profile_count, 0);
        assert_eq!(stats.ddm_count, 1);
        assert_eq!(stats.ddm_rule_count, 1);
        assert_eq!(toml.matches("[[ddm]]").count(), 1);
        assert!(toml.contains(r#"intent_name = "softwareupdate-settings""#));
        assert!(toml.contains(r#"type = "com.apple.configuration.softwareupdate.settings""#));
        // Nested payload survives plist→toml conversion.
        assert!(toml.contains("[ddm.configuration.payload.AutomaticActions]"));
        assert!(toml.contains(r#"Download = "AlwaysOn""#));
        // Default activation gets emitted.
        assert!(toml.contains("[ddm.activation]"));
        assert!(toml.contains(r#"type = "com.apple.activation.simple""#));
    }

    #[test]
    fn two_ddm_rules_same_type_merge_into_one_bundle() {
        let a = ddm_rule(
            "su_a",
            "declarationtype: com.apple.configuration.softwareupdate.settings\n\
             ddm_key: AutomaticActions\n\
             ddm_value:\n  Download: AlwaysOn\n",
        );
        let b = ddm_rule(
            "su_b",
            "declarationtype: com.apple.configuration.softwareupdate.settings\n\
             ddm_key: Notifications\n\
             ddm_value: true\n",
        );
        let (toml, warnings, stats) = baseline_to_recipe("ddm", None, &[a, b]).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(stats.ddm_count, 1);
        assert_eq!(toml.matches("[[ddm]]").count(), 1);
        assert!(toml.contains("Notifications = true"));
        assert!(toml.contains("[ddm.configuration.payload.AutomaticActions]"));
    }

    #[test]
    fn ddm_collision_emits_warning_last_writer_wins() {
        let a = ddm_rule(
            "su_off",
            "declarationtype: com.apple.configuration.softwareupdate.settings\n\
             ddm_key: Notifications\n\
             ddm_value: false\n",
        );
        let b = ddm_rule(
            "su_on",
            "declarationtype: com.apple.configuration.softwareupdate.settings\n\
             ddm_key: Notifications\n\
             ddm_value: true\n",
        );
        let (toml, warnings, _stats) = baseline_to_recipe("ddm", None, &[a, b]).unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].previous_rule, "su_off");
        assert_eq!(warnings[0].winning_rule, "su_on");
        // Last writer wins → Notifications = true survives.
        assert!(toml.contains("Notifications = true"));
        assert!(!toml.contains("Notifications = false"));
    }

    #[test]
    fn mixed_mobileconfig_and_ddm_emits_both_blocks() {
        let info_a: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: true\n").unwrap();
        let mc = rule("fw", info_a);
        let dd = ddm_rule(
            "su",
            "declarationtype: com.apple.configuration.softwareupdate.settings\n\
             ddm_key: AutomaticActions\n\
             ddm_value:\n  Download: AlwaysOn\n",
        );
        let (toml, warnings, stats) = baseline_to_recipe("mix", None, &[mc, dd]).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(stats.profile_count, 1);
        assert_eq!(stats.ddm_count, 1);
        assert_eq!(toml.matches("[[profile]]").count(), 1);
        assert_eq!(toml.matches("[[ddm]]").count(), 1);
    }
}
