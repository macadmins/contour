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
//! Rules that set the same key merge: dictionaries key by key, lists as
//! a union. Two rules giving one scalar different values is a conflict,
//! and `mscp recipe` refuses rather than write either value.
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
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use crate::models::MscpRule;

/// Rendering mode for mSCP `$ODV` placeholders.
///
/// `Variable` (default) preserves the `"$ODV"` literal in each field and
/// collects defaults into a top-level `[odv]` table directly under
/// `[recipe]` — operators edit the table once and every consumer
/// (mobileconfig payloads, DDM declarations) picks up the override at
/// `profile generate --recipe` time. `Inline` is the opt-out: the
/// resolved per-baseline default is baked directly into each field for
/// ad-hoc / one-shot recipes that don't need an editable surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OdvMode {
    /// Substitute the resolved default inline.
    Inline,
    /// Keep `"$ODV"` literal, emit defaults in `[odv]` (default).
    #[default]
    Variable,
}

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
    /// Number of `$ODV` placeholders substituted with the rule's
    /// per-baseline default (or `recommended` fallback) during
    /// aggregation.
    pub odv_resolved: usize,
    /// Number of `$ODV` placeholders left intact because the rule
    /// had no `odv:` block or no usable default for this baseline.
    /// These flow through to the rendered recipe verbatim — the
    /// operator must edit them before generating, or `profile
    /// generate --recipe` will emit a literal `"$ODV"` payload value.
    pub odv_unresolved: usize,
    /// Of `odv_resolved`, how many took their value from an operator
    /// override file (`--odv` / auto-detected `odv_<baseline>.yaml`)
    /// rather than the rule's per-baseline default.
    pub odv_from_overrides: usize,
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
            "[{}] {}: '{}' sets {}, '{}' sets {}",
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
/// `$ODV` placeholders inside each rule's payload are resolved using
/// the per-baseline default from `rule.odv.<baseline_name>` (falling
/// back to `rule.odv.recommended`). The `mode` parameter chooses the
/// rendering shape:
///   * [`OdvMode::Inline`]: substitute resolved values directly into
///     the field (e.g. `timeServer = "time.apple.com"`).
///   * [`OdvMode::Variable`]: keep `"$ODV"` literal in the field and
///     emit defaults under a top-level `[odv]` table — paired with
///     the `[odv]` substitution pass that
///     `crates/profile/src/recipe::Recipe::resolve_odv` runs at load
///     time.
///
/// Placeholders with no usable default flow through verbatim under
/// either mode and are counted in `stats.odv_unresolved`.
///
/// Returns the rendered TOML, the list of key collisions detected
/// during merging, and the per-pass counts.
// `#[allow]` not `#[expect]`: this module is compiled into both the mscp
// lib and bin, and `implicit_hasher` only fires in the lib context — an
// `#[expect]` would be unfulfilled (and error) in the bin build.
#[allow(
    clippy::implicit_hasher,
    reason = "override map is always built with the default hasher; a generic S would ripple through five private helpers for no caller benefit"
)]
#[allow(
    dead_code,
    reason = "the mscp binary compiles this module too and calls only the _excluding form"
)]
pub fn baseline_to_recipe(
    baseline_name: &str,
    org: Option<&str>,
    rules: &[MscpRule],
    mode: OdvMode,
    odv_overrides: &HashMap<String, yaml_serde::Value>,
) -> Result<(String, Vec<ConflictWarning>, AggregateStats)> {
    baseline_to_recipe_excluding(
        baseline_name,
        org,
        rules,
        mode,
        odv_overrides,
        &RecipeSelection::default(),
    )
}

/// What the operator and the baseline file say about which rules apply.
#[derive(Debug, Default)]
pub struct RecipeSelection<'a> {
    /// `--exclude-rule` ids; each must be among the baseline's rules.
    pub excluded: &'a [String],
    /// Rules the baseline file's own `Excluded` section names (mSCP
    /// tailoring); already absent from the rule set.
    pub tailored_out: &'a [String],
    /// Member rules in the order the baseline file lists them, for saying
    /// which value mSCP's own generator would ship on a conflict.
    pub listed_order: &'a [String],
}

/// [`baseline_to_recipe`] with rules left out by id.
///
/// For a baseline that lists two rules setting one key differently: the
/// operator names the rule that does not apply. Every id must be in
/// `rules`, so a typo cannot pass as an exclusion. The recipe's
/// description names `--exclude-rule` and tailored-out rules alike.
#[allow(
    clippy::implicit_hasher,
    reason = "override map is always built with the default hasher"
)]
pub fn baseline_to_recipe_excluding(
    baseline_name: &str,
    org: Option<&str>,
    rules: &[MscpRule],
    mode: OdvMode,
    odv_overrides: &HashMap<String, yaml_serde::Value>,
    selection: &RecipeSelection<'_>,
) -> Result<(String, Vec<ConflictWarning>, AggregateStats)> {
    let RecipeSelection {
        excluded,
        tailored_out,
        listed_order,
    } = *selection;
    let unknown: Vec<&str> = excluded
        .iter()
        .filter(|id| !rules.iter().any(|r| &r.id == *id))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        anyhow::bail!(
            "--exclude-rule: not in baseline '{baseline_name}': {}",
            unknown.join(", ")
        );
    }
    let kept: Vec<MscpRule> = rules
        .iter()
        .filter(|r| !excluded.contains(&r.id))
        .cloned()
        .collect();
    let rules = kept.as_slice();

    let mut warnings: Vec<ConflictWarning> = Vec::new();
    let mut stats = AggregateStats::default();
    // Variable mode collects defaults here; inline mode leaves it empty.
    let mut odv_defaults: BTreeMap<String, PlistValue> = BTreeMap::new();

    let profiles = aggregate_profiles(
        baseline_name,
        rules,
        listed_order,
        mode,
        &mut warnings,
        &mut stats,
        &mut odv_defaults,
        odv_overrides,
    )?;
    let ddm_bundles = aggregate_ddm(
        baseline_name,
        rules,
        listed_order,
        mode,
        &mut warnings,
        &mut stats,
        &mut odv_defaults,
        odv_overrides,
    )?;

    stats.profile_count = profiles.len();
    stats.ddm_count = ddm_bundles.len();

    let mut description = format!(
        "mSCP {} baseline aggregated into one recipe ({} profile(s), {} ddm bundle(s))",
        baseline_name, stats.profile_count, stats.ddm_count
    );
    if !tailored_out.is_empty() {
        let _ = write!(
            description,
            "; excluded by the tailored baseline: {}",
            tailored_out.join(", ")
        );
    }
    if !excluded.is_empty() {
        let _ = write!(description, "; rules excluded: {}", excluded.join(", "));
    }
    for c in &warnings {
        let _ = write!(
            description,
            "; conflict kept as mSCP does: {} = {} from {} (not {} from {})",
            c.key, c.winning_value, c.winning_rule, c.previous_value, c.previous_rule
        );
    }
    // mscp renders its own `[[ddm]]` section below (it splices `[odv]`
    // mid-document and needs per-bundle control), so pass no DDMs here.
    let body_with_profiles = write_recipe_toml(baseline_name, &description, org, &profiles, &[])?;

    // Build [odv] block separately so we can splice it directly under
    // [recipe] (before the first [[profile]]) — operators expect to see
    // editable defaults at the top of the file, not buried after profiles.
    let odv_block = if mode == OdvMode::Variable && !odv_defaults.is_empty() {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "# Operator-editable defaults. Each key matches the parent field name"
        );
        let _ = writeln!(
            s,
            "# of every `\"$ODV\"` placeholder elsewhere in this recipe."
        );
        let _ = writeln!(s, "[odv]");
        for (k, v) in &odv_defaults {
            let _ = writeln!(s, "{} = {}", toml_key(k), render_toml_scalar(v)?);
        }
        let _ = writeln!(s);
        s
    } else {
        String::new()
    };

    let mut body = if odv_block.is_empty() {
        body_with_profiles
    } else if let Some(pos) = body_with_profiles.find("\n[[profile]]") {
        // Splice before the first [[profile]] so [odv] sits between
        // the [recipe] header and the profiles.
        let mut spliced = String::with_capacity(body_with_profiles.len() + odv_block.len());
        spliced.push_str(&body_with_profiles[..=pos]);
        spliced.push_str(&odv_block);
        spliced.push_str(&body_with_profiles[pos + 1..]);
        spliced
    } else {
        // No profiles at all (DDM-only recipe) — append after [recipe].
        let mut s = body_with_profiles;
        s.push_str(&odv_block);
        s
    };

    if !ddm_bundles.is_empty() {
        let ddm_section = render_ddm_section(&ddm_bundles)?;
        body.push_str(&ddm_section);
    }

    // Two rules requiring different values for one setting keep mSCP's pick
    // (the rule the baseline lists later). The caller prints the warnings;
    // the recipe itself says what was kept, so the file carries it too.
    Ok((body, warnings, stats))
}

/// Render a `plist::Value` as a TOML right-hand-side scalar/value.
/// Reuses the existing `plist_to_toml` converter so dicts and arrays
/// serialize correctly via `toml::to_string` (compact one-line form
/// is fine for `[odv]` defaults).
fn render_toml_scalar(v: &PlistValue) -> Result<String> {
    let toml_val = plist_to_toml(v)?;
    // toml::to_string requires a top-level table; wrap and unwrap.
    let mut wrapper = toml::map::Map::new();
    wrapper.insert("__v__".to_string(), toml_val);
    let serialized = toml::to_string(&toml::Value::Table(wrapper))?;
    // serialized is `__v__ = <value>\n` (or a multi-line table for
    // dict values). Strip the `__v__ = ` prefix on the first line.
    let line = serialized
        .strip_prefix("__v__ = ")
        .unwrap_or(serialized.as_str())
        .trim_end()
        .to_string();
    Ok(line)
}

/// Group `mobileconfig: true` rules by Apple payload type and merge
/// their `mobileconfig_info` fields; on a scalar two rules set differently
/// the rule the baseline file lists later wins, as in mSCP's generator.
#[expect(
    clippy::too_many_arguments,
    reason = "the aggregation state, passed through"
)]
fn aggregate_profiles(
    baseline_name: &str,
    rules: &[MscpRule],
    listed_order: &[String],
    mode: OdvMode,
    warnings: &mut Vec<ConflictWarning>,
    stats: &mut AggregateStats,
    odv_defaults: &mut BTreeMap<String, PlistValue>,
    odv_overrides: &HashMap<String, yaml_serde::Value>,
) -> Result<Vec<RecipeProfile>> {
    // Stable order: iterate in payload-type alphabetical order so the
    // resulting TOML is deterministic across invocations.
    let mut grouped: BTreeMap<String, Group> = BTreeMap::new();

    // Baseline-file order, so the rule mSCP's generator keeps on a conflict
    // (the one listed later) is the one kept here. Rules the file does not
    // list follow, by id: the extractor's walkdir order varies by platform.
    let mut sorted: Vec<&MscpRule> = rules.iter().filter(|r| r.mobileconfig).collect();
    sort_listed(&mut sorted, listed_order);
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

            // MCX payloads are special: each top-level key under
            // `com.apple.ManagedClient.preferences` is a *preference domain*,
            // and mSCP emits it wrapped in the canonical
            // `PayloadContent.<domain>.Forced[0].mcx_preference_settings`
            // envelope. Build that envelope here (multi-domain safe) and
            // nest every domain under one literal `PayloadContent` field —
            // the literal-insert renderer reproduces it byte-for-byte.
            if payload_type == "com.apple.ManagedClient.preferences" {
                for (domain_key, prefs_val) in field_map {
                    let Some(domain) = domain_key.as_str() else {
                        continue;
                    };
                    let Some(prefs_map) = prefs_val.as_mapping() else {
                        continue;
                    };
                    let mut prefs = Dictionary::new();
                    for (pk, pv) in prefs_map {
                        let Some(pk_str) = pk.as_str() else {
                            continue;
                        };
                        let resolved = substitute_odv(
                            pk_str,
                            pv,
                            rule,
                            baseline_name,
                            mode,
                            stats,
                            odv_defaults,
                            odv_overrides,
                        );
                        let plist_val = yaml_to_plist(&resolved).with_context(|| {
                            format!("converting MCX key '{pk_str}' from rule '{}'", rule.id)
                        })?;
                        prefs.insert(pk_str.to_string(), plist_val);
                    }

                    // Merge this domain into the group's shared
                    // `PayloadContent` dict (multiple rules contribute
                    // different domains to the same payload).
                    if !group.fields.contains_key("PayloadContent") {
                        group.fields.insert(
                            "PayloadContent".to_string(),
                            PlistValue::Dictionary(Dictionary::new()),
                        );
                    }
                    if let Some(PlistValue::Dictionary(pc)) = group.fields.get_mut("PayloadContent")
                    {
                        // A second rule for the same domain adds to it; it
                        // used to replace the first rule's settings.
                        let prefs = match pc.get(domain).and_then(mcx_prefs) {
                            Some(existing) => {
                                let prev_rule = group
                                    .field_origin
                                    .get(&format!("PayloadContent.{domain}"))
                                    .cloned()
                                    .unwrap_or_default();
                                match merge_rule_value(
                                    &PlistValue::Dictionary(existing.clone()),
                                    PlistValue::Dictionary(prefs),
                                    domain,
                                    payload_type,
                                    &prev_rule,
                                    &rule.id,
                                    warnings,
                                ) {
                                    PlistValue::Dictionary(d) => d,
                                    _ => unreachable!("two dictionaries merge to one"),
                                }
                            }
                            None => prefs,
                        };
                        pc.insert(
                            domain.to_string(),
                            PlistValue::Dictionary(mcx_envelope(prefs)),
                        );
                    }
                    group
                        .field_origin
                        .insert(format!("PayloadContent.{domain}"), rule.id.clone());
                }
                continue;
            }

            for (field_key, field_val) in field_map {
                let Some(key_str) = field_key.as_str() else {
                    continue;
                };
                let resolved = substitute_odv(
                    key_str,
                    field_val,
                    rule,
                    baseline_name,
                    mode,
                    stats,
                    odv_defaults,
                    odv_overrides,
                );
                let plist_val = yaml_to_plist(&resolved).with_context(|| {
                    format!("converting key '{key_str}' from rule '{}'", rule.id)
                })?;

                let plist_val = match group.fields.get(key_str) {
                    Some(prev) => {
                        let prev_rule = group
                            .field_origin
                            .get(key_str)
                            .cloned()
                            .unwrap_or_else(|| "<unknown>".to_string());
                        merge_rule_value(
                            prev,
                            plist_val,
                            key_str,
                            payload_type,
                            &prev_rule,
                            &rule.id,
                            warnings,
                        )
                    }
                    None => plist_val,
                };

                group.fields.insert(key_str.to_string(), plist_val);
                group
                    .field_origin
                    .insert(key_str.to_string(), rule.id.clone());
            }
        }
    }

    Ok(grouped.into_values().map(Group::into_profile).collect())
}

/// Group rules with `ddm_info` by `declarationtype` and merge their
/// `ddm_key → ddm_value` pairs; dictionary values merge, and only a leaf two
/// rules set differently is a collision (last writer wins, with a warning).
/// Skips rules using the unsupported services-configuration-files
/// shape (those need paired asset bundles, out of scope here).
#[expect(
    clippy::too_many_arguments,
    reason = "the aggregation state, passed through"
)]
fn aggregate_ddm(
    baseline_name: &str,
    rules: &[MscpRule],
    listed_order: &[String],
    mode: OdvMode,
    warnings: &mut Vec<ConflictWarning>,
    stats: &mut AggregateStats,
    odv_defaults: &mut BTreeMap<String, PlistValue>,
    odv_overrides: &HashMap<String, yaml_serde::Value>,
) -> Result<Vec<DdmBundle>> {
    let mut grouped: BTreeMap<String, DdmGroup> = BTreeMap::new();

    let mut sorted: Vec<&MscpRule> = rules.iter().filter(|r| r.ddm_info.is_some()).collect();
    sort_listed(&mut sorted, listed_order);
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
        let resolved = substitute_odv(
            &ddm_key,
            ddm_value_yaml,
            rule,
            baseline_name,
            mode,
            stats,
            odv_defaults,
            odv_overrides,
        );
        let ddm_value = yaml_to_plist(&resolved)
            .with_context(|| format!("converting ddm_value of rule '{}'", rule.id))?;

        let group = grouped
            .entry(declarationtype.clone())
            .or_insert_with(|| DdmGroup::new(&declarationtype));

        let ddm_value = match group.payload.get(&ddm_key) {
            Some(prev) => {
                let prev_rule = group
                    .field_origin
                    .get(&ddm_key)
                    .cloned()
                    .unwrap_or_else(|| "<unknown>".to_string());
                merge_rule_value(
                    prev,
                    ddm_value,
                    &ddm_key,
                    &declarationtype,
                    &prev_rule,
                    &rule.id,
                    warnings,
                )
            }
            None => ddm_value,
        };

        group.payload.insert(ddm_key.clone(), ddm_value);
        group.field_origin.insert(ddm_key, rule.id.clone());
    }

    Ok(grouped.into_values().map(DdmGroup::into_bundle).collect())
}

/// Order rules by their position in the baseline file; rules it does not
/// list follow, by id.
fn sort_listed(rules: &mut [&MscpRule], listed_order: &[String]) {
    let rank = |r: &MscpRule| {
        listed_order
            .iter()
            .position(|id| *id == r.id)
            .unwrap_or(usize::MAX)
    };
    rules.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| a.id.cmp(&b.id)));
}

/// The settings two of `rules` require different values for, found the way
/// the recipe aggregates them (dictionaries merge, lists union). For a path
/// that hands the rules to mSCP's own generator, which keeps the later
/// rule's value silently, this is what to warn about first.
pub fn find_conflicts(
    baseline_name: &str,
    rules: &[MscpRule],
    listed_order: &[String],
) -> Result<Vec<ConflictWarning>> {
    let mut warnings = Vec::new();
    let mut stats = AggregateStats::default();
    let mut odv_defaults = BTreeMap::new();
    let none = HashMap::new();
    aggregate_profiles(
        baseline_name,
        rules,
        listed_order,
        OdvMode::Inline,
        &mut warnings,
        &mut stats,
        &mut odv_defaults,
        &none,
    )?;
    aggregate_ddm(
        baseline_name,
        rules,
        listed_order,
        OdvMode::Inline,
        &mut warnings,
        &mut stats,
        &mut odv_defaults,
        &none,
    )?;
    Ok(warnings)
}

/// What to print when a baseline lists two rules that set one key to
/// different values. contour keeps the value mSCP's own generator keeps
/// (the rule the baseline file lists later) and says so, which mSCP does not.
pub fn conflict_report(baseline_name: &str, conflicts: &[ConflictWarning]) -> String {
    let mut out = format!(
        "'{baseline_name}' lists rules that set the same key to different values \
         ({} conflict(s)). Kept the value mSCP's generator keeps, the rule the baseline \
         lists later; mSCP itself does this without a word:\n",
        conflicts.len()
    );
    for c in conflicts {
        let _ = writeln!(
            out,
            "  [{}] {} = {} from '{}' (not {} from '{}')",
            c.payload_type,
            c.key,
            c.winning_value,
            c.winning_rule,
            c.previous_value,
            c.previous_rule
        );
    }
    out.push_str(
        "If the other value applies: tailor the baseline (mSCP's generate_baseline.py -t \
         moves the rule that does not apply into an `Excluded` section, which contour \
         honors), or name that rule with --exclude-rule <id> (mscp recipe).",
    );
    out
}

/// Combine two rules' values for one key.
///
/// Dictionaries merge key by key, recursively: mSCP splits one setting
/// across rules (`Apps` → `Mail`, `Apps` → `Notes` in intelligence.settings;
/// `AutomaticActions` in softwareupdate.settings), and keeping only the last
/// rule's dictionary dropped the others' controls from the baseline. Lists
/// take the union. Only two different scalars at the same leaf are a
/// conflict, recorded with the full key path; `mscp recipe` refuses on any.
fn merge_rule_value(
    prev: &PlistValue,
    next: PlistValue,
    path: &str,
    payload_type: &str,
    prev_rule: &str,
    next_rule: &str,
    warnings: &mut Vec<ConflictWarning>,
) -> PlistValue {
    match (prev, next) {
        (PlistValue::Dictionary(old), PlistValue::Dictionary(new)) => {
            let mut merged = old.clone();
            for (k, v) in new {
                let child = match old.get(&k) {
                    Some(o) => merge_rule_value(
                        o,
                        v,
                        &format!("{path}.{k}"),
                        payload_type,
                        prev_rule,
                        next_rule,
                        warnings,
                    ),
                    None => v,
                };
                merged.insert(k, child);
            }
            PlistValue::Dictionary(merged)
        }
        // A list two rules contribute to is a union: mSCP gives each
        // DisabledSystemSettings pane, SkipSetupItems screen and alr DenyList
        // app its own rule, and all of them are required.
        (PlistValue::Array(old), PlistValue::Array(new)) => {
            let mut merged = old.clone();
            for item in new {
                if !merged.contains(&item) {
                    merged.push(item);
                }
            }
            PlistValue::Array(merged)
        }
        (old, new) => {
            if *old != new {
                warnings.push(ConflictWarning {
                    payload_type: payload_type.to_string(),
                    key: path.to_string(),
                    previous_rule: prev_rule.to_string(),
                    previous_value: short_repr(old),
                    winning_rule: next_rule.to_string(),
                    winning_value: short_repr(&new),
                });
            }
            new
        }
    }
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

/// Render every bundle as one canonical `[[ddm]]` recipe block.
///
/// Each block carries `intent_name` plus `configuration` and
/// `activation` subtables matching the shape that
/// `crates/profile/src/ddm/compose.rs::Bundle` deserializes.
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

/// Render `key` as a TOML key: bare when it's a valid bare key
/// (`A-Za-z0-9_-`), otherwise quoted. Dotted ODV keys like
/// `com.apple.autologout.AutoLogOutDelay` MUST be quoted — an unquoted
/// dotted key is parsed as nested tables, which silently breaks the
/// flat-key `$ODV` lookup in `Recipe::resolve_odv` (the placeholder is
/// then left literal in the rendered profile).
fn toml_key(key: &str) -> String {
    let is_bare = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if is_bare {
        key.to_string()
    } else {
        quote_toml_str(key)
    }
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

/// Walk `value` and handle every literal `"$ODV"` string according
/// to `mode`:
///   * [`OdvMode::Inline`]: replace with the resolved default for
///     `rule` under `baseline_name`.
///   * [`OdvMode::Variable`]: leave `"$ODV"` in place and capture
///     the resolved default into `odv_defaults`, keyed by
///     `parent_key`. The downstream `[odv]` table emits these.
///
/// Substitution policy:
///   0. operator override (`odv_overrides[rule.id]`, from `--odv` /
///      auto-detected `odv_<baseline>.yaml`) — highest precedence
///   1. `rule.odv.<baseline_name>` (per-baseline default)
///   2. `rule.odv.recommended` (upstream-recommended fallback)
///   3. literal `$ODV` (counted as unresolved, surfaced to the operator)
///
/// `parent_key` is the immediate map key whose value is being
/// walked; nested dicts override it on each recursion so the lookup
/// table emitted in variable mode keys by the operator-visible name.
fn substitute_odv(
    parent_key: &str,
    value: &yaml_serde::Value,
    rule: &MscpRule,
    baseline_name: &str,
    mode: OdvMode,
    stats: &mut AggregateStats,
    odv_defaults: &mut BTreeMap<String, PlistValue>,
    odv_overrides: &HashMap<String, yaml_serde::Value>,
) -> yaml_serde::Value {
    match value {
        yaml_serde::Value::String(s) if s == "$ODV" => {
            match resolve_odv_for_rule(rule, baseline_name, odv_overrides) {
                Some(resolved) => {
                    stats.odv_resolved += 1;
                    if odv_overrides.contains_key(&rule.id) {
                        stats.odv_from_overrides += 1;
                    }
                    match mode {
                        OdvMode::Inline => resolved,
                        OdvMode::Variable => {
                            if let Ok(plist_val) = yaml_to_plist(&resolved) {
                                odv_defaults
                                    .entry(parent_key.to_string())
                                    .or_insert(plist_val);
                            }
                            value.clone()
                        }
                    }
                }
                None => {
                    stats.odv_unresolved += 1;
                    value.clone()
                }
            }
        }
        yaml_serde::Value::Mapping(m) => {
            let mut out = yaml_serde::Mapping::new();
            for (k, v) in m {
                let next_key = k.as_str().unwrap_or(parent_key).to_string();
                out.insert(
                    k.clone(),
                    substitute_odv(
                        &next_key,
                        v,
                        rule,
                        baseline_name,
                        mode,
                        stats,
                        odv_defaults,
                        odv_overrides,
                    ),
                );
            }
            yaml_serde::Value::Mapping(out)
        }
        yaml_serde::Value::Sequence(seq) => yaml_serde::Value::Sequence(
            seq.iter()
                .map(|v| {
                    substitute_odv(
                        parent_key,
                        v,
                        rule,
                        baseline_name,
                        mode,
                        stats,
                        odv_defaults,
                        odv_overrides,
                    )
                })
                .collect(),
        ),
        yaml_serde::Value::Tagged(tagged) => {
            let inner = substitute_odv(
                parent_key,
                &tagged.value,
                rule,
                baseline_name,
                mode,
                stats,
                odv_defaults,
                odv_overrides,
            );
            yaml_serde::Value::Tagged(Box::new(yaml_serde::value::TaggedValue {
                tag: tagged.tag.clone(),
                value: inner,
            }))
        }
        other => other.clone(),
    }
}

/// Look up the per-baseline default in `rule.odv`, falling back to
/// `recommended`. Returns `None` if the rule has no `odv:` block or
/// neither key is present.
fn resolve_odv_for_rule(
    rule: &MscpRule,
    baseline_name: &str,
    odv_overrides: &HashMap<String, yaml_serde::Value>,
) -> Option<yaml_serde::Value> {
    // Operator override wins over the rule's baked-in defaults, and
    // applies even when the rule has no `odv:` block of its own.
    if let Some(custom) = odv_overrides.get(&rule.id) {
        return Some(custom.clone());
    }
    let odv = rule.odv.as_ref()?.as_mapping()?;
    let key_baseline = yaml_serde::Value::String(baseline_name.to_string());
    let key_recommended = yaml_serde::Value::String("recommended".to_string());
    odv.get(&key_baseline)
        .cloned()
        .or_else(|| odv.get(&key_recommended).cloned())
}

/// Wrap a flat MCX preference dict in the canonical envelope mSCP emits at
/// build time: `{ Forced: [ { mcx_preference_settings: <prefs> } ] }`. This is
/// the same shape `wrap_mcx_payload` produces in the profile renderer, kept in
/// sync so import↔aggregate↔render round-trips agree.
/// The preference settings inside an envelope [`mcx_envelope`] built.
fn mcx_prefs(domain: &PlistValue) -> Option<&Dictionary> {
    domain
        .as_dictionary()?
        .get("Forced")?
        .as_array()?
        .first()?
        .as_dictionary()?
        .get("mcx_preference_settings")?
        .as_dictionary()
}

fn mcx_envelope(prefs: Dictionary) -> Dictionary {
    let mut forced_entry = Dictionary::new();
    forced_entry.insert(
        "mcx_preference_settings".to_string(),
        PlistValue::Dictionary(prefs),
    );
    let mut domain = Dictionary::new();
    domain.insert(
        "Forced".to_string(),
        PlistValue::Array(vec![PlistValue::Dictionary(forced_entry)]),
    );
    domain
}

fn yaml_to_plist(value: &yaml_serde::Value) -> Result<PlistValue> {
    Ok(match value {
        // A blank value has no plist form. It used to become "", which wrote
        // a profile setting the key to an empty string no rule asked for.
        yaml_serde::Value::Null => anyhow::bail!("the value is empty (YAML null)"),
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

    fn dict(pairs: &[(&str, PlistValue)]) -> PlistValue {
        let mut d = Dictionary::new();
        for (k, v) in pairs {
            d.insert((*k).to_string(), v.clone());
        }
        PlistValue::Dictionary(d)
    }

    /// CIS L1 splits intelligence.settings' `Apps` across three rules. Each
    /// rule's control has to survive into the one declaration; keeping the
    /// last rule's dictionary dropped Mail and half of Notes.
    #[test]
    fn rules_that_share_a_dictionary_key_all_keep_their_controls() {
        let mail = dict(&[(
            "Mail",
            dict(&[("AllowSummary", PlistValue::Boolean(false))]),
        )]);
        let notes_a = dict(&[(
            "Notes",
            dict(&[("AllowTranscription", PlistValue::Boolean(false))]),
        )]);
        let notes_b = dict(&[(
            "Notes",
            dict(&[("AllowTranscriptionSummary", PlistValue::Boolean(false))]),
        )]);
        let mut warnings = Vec::new();
        let t = "com.apple.configuration.intelligence.settings";
        let v = merge_rule_value(&mail, notes_a, "Apps", t, "mail", "notes_a", &mut warnings);
        let v = merge_rule_value(&v, notes_b, "Apps", t, "notes_a", "notes_b", &mut warnings);
        let expected = dict(&[
            (
                "Mail",
                dict(&[("AllowSummary", PlistValue::Boolean(false))]),
            ),
            (
                "Notes",
                dict(&[
                    ("AllowTranscription", PlistValue::Boolean(false)),
                    ("AllowTranscriptionSummary", PlistValue::Boolean(false)),
                ]),
            ),
        ]);
        assert_eq!(v, expected);
        assert!(warnings.is_empty(), "no leaf disagreed: {warnings:?}");
    }

    /// Two rules for one MCX preference domain both keep their settings.
    #[test]
    fn mcx_rules_sharing_a_domain_merge() {
        let a: yaml_serde::Value = yaml_serde::from_str(
            "com.apple.ManagedClient.preferences:\n  com.apple.Safari:\n    A: true\n",
        )
        .unwrap();
        let b: yaml_serde::Value = yaml_serde::from_str(
            "com.apple.ManagedClient.preferences:\n  com.apple.Safari:\n    B: false\n",
        )
        .unwrap();
        let (toml, _, _) = baseline_to_recipe(
            "m",
            None,
            &[rule("a", a), rule("b", b)],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert!(
            toml.contains("A = true") && toml.contains("B = false"),
            "{toml}"
        );
    }

    /// Excluding one rule of a conflicting pair builds the recipe and says
    /// so; an id the baseline does not hold is refused.
    #[test]
    fn exclude_rule_resolves_a_conflict_and_is_recorded() {
        let on: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: true\n").unwrap();
        let off: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: false\n")
                .unwrap();
        let rules = vec![rule("fw_on", on), rule("fw_off", off)];
        let none = std::collections::HashMap::new();
        let (toml, _, _) = baseline_to_recipe_excluding(
            "c",
            None,
            &rules,
            OdvMode::Inline,
            &none,
            &RecipeSelection {
                excluded: &["fw_off".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(toml.contains("EnableFirewall = true"), "{toml}");
        assert!(toml.contains("rules excluded: fw_off"), "{toml}");
        let err = baseline_to_recipe_excluding(
            "c",
            None,
            &rules,
            OdvMode::Inline,
            &none,
            &RecipeSelection {
                excluded: &["fw_of".to_string()],
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("fw_of"), "{err}");
    }

    /// 800-53r5 High hides several System Settings panes, one rule each.
    #[test]
    fn lists_from_several_rules_are_a_union() {
        let one = |s: &str| {
            dict(&[(
                "DisabledSystemSettings",
                PlistValue::Array(vec![PlistValue::String(s.into())]),
            )])
        };
        let mut warnings = Vec::new();
        let v = merge_rule_value(
            &one("Bluetooth"),
            one("TouchID"),
            "k",
            "t",
            "a",
            "b",
            &mut warnings,
        );
        let v = merge_rule_value(&v, one("Bluetooth"), "k", "t", "b", "c", &mut warnings);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            v,
            dict(&[(
                "DisabledSystemSettings",
                PlistValue::Array(vec![
                    PlistValue::String("Bluetooth".into()),
                    PlistValue::String("TouchID".into())
                ])
            )])
        );
    }

    /// Two rules setting one leaf differently is a real conflict, recorded
    /// with the full path; `mscp recipe` refuses on it.
    #[test]
    fn a_leaf_two_rules_set_differently_is_a_conflict() {
        let a = dict(&[("Download", PlistValue::String("AlwaysOn".into()))]);
        let b = dict(&[("Download", PlistValue::String("AlwaysOff".into()))]);
        let mut warnings = Vec::new();
        let v = merge_rule_value(&a, b, "AutomaticActions", "t", "r1", "r2", &mut warnings);
        assert_eq!(
            v,
            dict(&[("Download", PlistValue::String("AlwaysOff".into()))])
        );
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].key, "AutomaticActions.Download");
    }

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

        let (toml, warnings, stats) = baseline_to_recipe(
            "test",
            Some("com.acme"),
            &rules,
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
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

        let (toml, warnings, stats) = baseline_to_recipe(
            "two",
            None,
            &rules,
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(toml.matches("[[profile]]").count(), 2);
        assert_eq!(stats.profile_count, 2);
    }

    #[test]
    /// Like mSCP's generator: the rule the baseline lists later wins, here
    /// against id order (fw_off < fw_on), and the conflict is reported.
    fn a_profile_key_conflict_keeps_the_later_listed_rule_and_warns() {
        let info_a: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: false\n")
                .unwrap();
        let info_b: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: true\n").unwrap();
        let rules = vec![rule("fw_off", info_a), rule("fw_on", info_b)];
        let order = ["fw_on".to_string(), "fw_off".to_string()];

        let (toml, conflicts, _) = baseline_to_recipe_excluding(
            "c",
            None,
            &rules,
            OdvMode::Inline,
            &std::collections::HashMap::new(),
            &RecipeSelection {
                listed_order: &order,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(toml.contains("EnableFirewall = false"), "{toml}");
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].winning_rule, "fw_off");
        assert!(toml.contains("conflict kept as mSCP does"), "{toml}");
        let report = conflict_report("c", &conflicts);
        assert!(
            report.contains("EnableFirewall = false from 'fw_off'"),
            "{report}"
        );
    }

    #[test]
    fn mcx_payload_gets_forced_envelope_per_domain() {
        // Two rules each contribute a different preference domain to the
        // single `com.apple.ManagedClient.preferences` payload. Both must
        // land under one `PayloadContent` field, each wrapped in the
        // canonical `Forced[0].mcx_preference_settings` envelope.
        let info_a: yaml_serde::Value = yaml_serde::from_str(
            "com.apple.ManagedClient.preferences:\n  com.apple.timed:\n    TMAutomaticTimeOnlyEnabled: true\n",
        )
        .unwrap();
        let info_b: yaml_serde::Value = yaml_serde::from_str(
            "com.apple.ManagedClient.preferences:\n  com.apple.MCXBluetooth:\n    DisableBluetooth: true\n",
        )
        .unwrap();
        let rules = vec![rule("timed", info_a), rule("bt", info_b)];

        let profiles = {
            let mut warnings = Vec::new();
            let mut stats = AggregateStats::default();
            let mut odv_defaults = BTreeMap::new();
            aggregate_profiles(
                "mcx",
                &rules,
                &[],
                OdvMode::Inline,
                &mut warnings,
                &mut stats,
                &mut odv_defaults,
                &std::collections::HashMap::new(),
            )
            .unwrap()
        };

        assert_eq!(profiles.len(), 1);
        let p = &profiles[0];
        assert_eq!(p.payload_type, "com.apple.ManagedClient.preferences");

        // One `PayloadContent` field holding both domains.
        let PlistValue::Dictionary(pc) = p.fields.get("PayloadContent").unwrap() else {
            panic!("PayloadContent is not a dict");
        };
        for domain in ["com.apple.timed", "com.apple.MCXBluetooth"] {
            let PlistValue::Dictionary(d) = pc.get(domain).unwrap() else {
                panic!("{domain} is not a dict");
            };
            let PlistValue::Array(forced) = d.get("Forced").unwrap() else {
                panic!("{domain}.Forced is not an array");
            };
            let PlistValue::Dictionary(entry) = &forced[0] else {
                panic!("{domain}.Forced[0] is not a dict");
            };
            let PlistValue::Dictionary(prefs) = entry.get("mcx_preference_settings").unwrap()
            else {
                panic!("{domain} missing mcx_preference_settings");
            };
            assert_eq!(prefs.len(), 1, "{domain} should carry exactly one pref");
        }
    }

    #[test]
    fn skips_non_mobileconfig_rules() {
        let info: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: true\n").unwrap();
        let mut r = rule("fw", info);
        r.mobileconfig = false;
        let (toml, _, stats) = baseline_to_recipe(
            "none",
            None,
            &[r],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
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
        let (toml, warnings, stats) = baseline_to_recipe(
            "ddm",
            Some("com.acme"),
            &[r],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
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
        let (toml, warnings, stats) = baseline_to_recipe(
            "ddm",
            None,
            &[a, b],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(stats.ddm_count, 1);
        assert_eq!(toml.matches("[[ddm]]").count(), 1);
        assert!(toml.contains("Notifications = true"));
        assert!(toml.contains("[ddm.configuration.payload.AutomaticActions]"));
    }

    #[test]
    fn a_ddm_key_conflict_keeps_the_later_listed_rule() {
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
        let order = ["su_on".to_string(), "su_off".to_string()];
        let (toml, conflicts, _) = baseline_to_recipe_excluding(
            "ddm",
            None,
            &[a, b],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
            &RecipeSelection {
                listed_order: &order,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(toml.contains("Notifications = false"), "{toml}");
        assert_eq!(conflicts[0].winning_rule, "su_off");
    }

    // ── ODV resolution ────────────────────────────────────────────

    fn rule_with_odv(id: &str, info: yaml_serde::Value, odv_yaml: &str) -> MscpRule {
        let mut r = rule(id, info);
        r.odv = Some(yaml_serde::from_str(odv_yaml).unwrap());
        r
    }

    #[test]
    fn dotted_odv_key_is_quoted_and_parses_flat() {
        // A dotted field name (e.g. the GlobalPreferences key
        // `com.apple.autologout.AutoLogOutDelay`) must render its `[odv]`
        // entry QUOTED. An unquoted dotted key is parsed by TOML as nested
        // tables, which breaks the flat-key `$ODV` lookup in the recipe
        // loader and leaves the literal `"$ODV"` string in the profile.
        let info: yaml_serde::Value = yaml_serde::from_str(
            ".GlobalPreferences:\n  com.apple.autologout.AutoLogOutDelay: $ODV\n",
        )
        .unwrap();
        let r = rule_with_odv("autologout", info, "recommended: 86400\n");
        let (toml_str, _w, _s) = baseline_to_recipe(
            "test",
            None,
            &[r],
            OdvMode::Variable,
            &std::collections::HashMap::new(),
        )
        .unwrap();

        assert!(
            toml_str.contains(r#""com.apple.autologout.AutoLogOutDelay" = 86400"#),
            "odv key must be quoted; got:\n{toml_str}"
        );
        // And it must re-parse as ONE flat key, not nested `com.apple…` tables.
        let parsed: toml::Value = toml::from_str(&toml_str).unwrap();
        let odv = parsed.get("odv").and_then(|v| v.as_table()).unwrap();
        assert!(
            odv.contains_key("com.apple.autologout.AutoLogOutDelay"),
            "dotted odv key must stay flat; odv table was: {odv:?}"
        );
    }

    #[test]
    fn odv_resolves_baseline_default_in_profile_field() {
        // mobileconfig_info has $ODV; rule.odv has cis_lvl1 default.
        let info: yaml_serde::Value =
            yaml_serde::from_str("com.apple.MCX:\n  timeServer: $ODV\n").unwrap();
        let r = rule_with_odv(
            "ts",
            info,
            "recommended: time.nist.gov\ncis_lvl1: time.apple.com\n",
        );
        let (toml, warnings, stats) = baseline_to_recipe(
            "cis_lvl1",
            None,
            &[r],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(stats.odv_resolved, 1);
        assert_eq!(stats.odv_unresolved, 0);
        // Per-baseline default beats `recommended`.
        assert!(toml.contains(r#"timeServer = "time.apple.com""#));
        assert!(!toml.contains("$ODV"));
    }

    #[test]
    fn odv_falls_back_to_recommended_when_baseline_missing() {
        let info: yaml_serde::Value =
            yaml_serde::from_str("com.apple.MCX:\n  timeServer: $ODV\n").unwrap();
        let r = rule_with_odv(
            "ts",
            info,
            "recommended: time.nist.gov\nstig: time.usno.navy.mil\n",
        );
        let (toml, _warnings, stats) = baseline_to_recipe(
            "cis_lvl1",
            None,
            &[r],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert_eq!(stats.odv_resolved, 1);
        assert_eq!(stats.odv_unresolved, 0);
        assert!(toml.contains(r#"timeServer = "time.nist.gov""#));
    }

    #[test]
    fn odv_unresolved_when_rule_has_no_defaults() {
        let info: yaml_serde::Value =
            yaml_serde::from_str("com.apple.MCX:\n  timeServer: $ODV\n").unwrap();
        let r = rule("ts", info); // no odv block
        let (toml, _warnings, stats) = baseline_to_recipe(
            "cis_lvl1",
            None,
            &[r],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert_eq!(stats.odv_resolved, 0);
        assert_eq!(stats.odv_unresolved, 1);
        // $ODV passes through verbatim — the operator must edit before generate.
        assert!(toml.contains(r#"timeServer = "$ODV""#));
    }

    #[test]
    fn odv_resolves_inside_ddm_value_dict() {
        // DDM rules carry $ODV nested in dicts and as bare scalars.
        let info: yaml_serde::Value =
            yaml_serde::from_str("com.apple.MCX:\n  passcode:\n    MaximumFailedAttempts: $ODV\n")
                .unwrap();
        let r = rule_with_odv("p", info, "recommended: 5\ncis_lvl1: 4\n");
        let (toml, _warnings, stats) = baseline_to_recipe(
            "cis_lvl1",
            None,
            &[r],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert_eq!(stats.odv_resolved, 1);
        assert!(toml.contains("MaximumFailedAttempts = 4"));
    }

    #[test]
    fn odv_resolves_in_ddm_block() {
        let r = MscpRule {
            id: "su".to_string(),
            title: "su".to_string(),
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
            ddm_info: Some(
                yaml_serde::from_str(
                    "declarationtype: com.apple.configuration.passcode.settings\n\
                     ddm_key: MinimumLength\n\
                     ddm_value: $ODV\n",
                )
                .unwrap(),
            ),
            odv: Some(yaml_serde::from_str("recommended: 8\ncis_lvl2: 12\n").unwrap()),
        };
        let (toml, _warnings, stats) = baseline_to_recipe(
            "cis_lvl2",
            None,
            &[r],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert_eq!(stats.odv_resolved, 1);
        assert!(toml.contains("MinimumLength = 12"));
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
        let (toml, warnings, stats) = baseline_to_recipe(
            "mix",
            None,
            &[mc, dd],
            OdvMode::Inline,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(stats.profile_count, 1);
        assert_eq!(stats.ddm_count, 1);
        assert_eq!(toml.matches("[[profile]]").count(), 1);
        assert_eq!(toml.matches("[[ddm]]").count(), 1);
    }

    // ── Variable mode: $ODV stays + [odv] table emitted ─────────────

    #[test]
    fn variable_mode_emits_odv_table_and_keeps_placeholder() {
        // Profile $ODV and DDM $ODV both contribute to the [odv] table.
        let info: yaml_serde::Value =
            yaml_serde::from_str("com.apple.MCX:\n  timeServer: $ODV\n").unwrap();
        let mc = rule_with_odv(
            "ts",
            info,
            "recommended: time.nist.gov\ncis_lvl1: time.apple.com\n",
        );
        let dd = MscpRule {
            id: "p".to_string(),
            title: "p".to_string(),
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
            ddm_info: Some(
                yaml_serde::from_str(
                    "declarationtype: com.apple.configuration.passcode.settings\n\
                     ddm_key: MinimumLength\n\
                     ddm_value: $ODV\n",
                )
                .unwrap(),
            ),
            odv: Some(yaml_serde::from_str("recommended: 8\ncis_lvl1: 15\n").unwrap()),
        };

        let (toml, warnings, stats) = baseline_to_recipe(
            "cis_lvl1",
            None,
            &[mc, dd],
            OdvMode::Variable,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(stats.odv_resolved, 2);
        assert_eq!(stats.odv_unresolved, 0);

        // Field keeps the literal "$ODV"; defaults live in [odv].
        assert!(toml.contains(r#"timeServer = "$ODV""#));
        assert!(toml.contains(r#"MinimumLength = "$ODV""#));
        assert!(toml.contains("[odv]"));
        assert!(toml.contains(r#"timeServer = "time.apple.com""#));
        assert!(toml.contains("MinimumLength = 15"));
    }

    #[test]
    fn odv_override_seeds_recipe_table_over_rule_default() {
        // Rule's per-baseline default is 5; an operator override (--odv /
        // odv_<baseline>.yaml) sets rule "ssd" to 3. The emitted [odv]
        // table must carry the override, not the rule default.
        let info: yaml_serde::Value =
            yaml_serde::from_str("com.apple.screensaver:\n  askForPasswordDelay: $ODV\n").unwrap();
        let rule = rule_with_odv("ssd", info, "recommended: 5\ncis_lvl1: 5\n");

        let mut overrides = std::collections::HashMap::new();
        overrides.insert("ssd".to_string(), yaml_serde::Value::Number(3.into()));

        let (toml, warnings, stats) =
            baseline_to_recipe("cis_lvl1", None, &[rule], OdvMode::Variable, &overrides).unwrap();

        assert!(warnings.is_empty());
        assert!(
            toml.contains("askForPasswordDelay = 3"),
            "override value must win; toml:\n{toml}"
        );
        assert!(
            !toml.contains("askForPasswordDelay = 5"),
            "rule default must NOT appear"
        );
        assert_eq!(stats.odv_resolved, 1);
        assert_eq!(stats.odv_from_overrides, 1);
    }

    #[test]
    fn variable_mode_omits_odv_table_when_no_placeholders() {
        // No $ODV in the field — [odv] should NOT appear at all.
        let info: yaml_serde::Value =
            yaml_serde::from_str("com.apple.security.firewall:\n  EnableFirewall: true\n").unwrap();
        let r = rule("fw", info);
        let (toml, _w, stats) = baseline_to_recipe(
            "cis_lvl1",
            None,
            &[r],
            OdvMode::Variable,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert_eq!(stats.odv_resolved, 0);
        assert!(!toml.contains("[odv]"));
    }

    // Round-trip through profile crate's `Recipe::resolve_odv` is
    // exercised end-to-end by crates/contour/tests/sop_traps_mscp_round_trip.rs
    // (`trap_21_mscp_recipe_variable_mode_round_trips_through_odv_edits`).
}
