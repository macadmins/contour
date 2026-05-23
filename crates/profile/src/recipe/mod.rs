//! Recipe data model for multi-profile generation.
//!
//! Recipes define bundles of related profiles (e.g., Okta SSO setup)
//! that can be generated together from a single command.

pub mod loader;

use crate::ddm::compose::Bundle;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A recipe defines a bundle of related profiles to generate together.
///
/// Optional `[[ddm]]` blocks let a single recipe emit DDM declarations
/// alongside its mobileconfig profiles — used for hardening/baseline
/// intents that need both delivery channels (e.g. the embedded
/// `hardening-macos-baseline`).
///
/// Optional `[odv]` table holds operator-editable defaults for any
/// field whose value is the literal string `"$ODV"`. Substitution
/// happens at load time via [`Recipe::resolve_odv`] keyed by the
/// field's immediate parent name — lets mSCP-derived recipes carry
/// per-baseline defaults inline (e.g. `timeServer = "time.apple.com"`)
/// while keeping the reusable placeholder shape mSCP rules use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    pub recipe: RecipeMeta,
    #[serde(rename = "profile", default)]
    pub profiles: Vec<ProfileSpec>,
    /// DDM bundles emitted under `<output_dir>/<intent_name>/` per
    /// entry. Same shape as a standalone DDM preset bundle.
    #[serde(rename = "ddm", default, skip_serializing_if = "Vec::is_empty")]
    pub ddm: Vec<Bundle>,
    /// Operator-editable defaults for `"$ODV"` placeholders. Keys are
    /// the immediate parent field names (e.g. `timeServer`,
    /// `MaximumFailedAttempts`). `BTreeMap` for byte-stable
    /// serialization.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub odv: BTreeMap<String, toml::Value>,
}

/// Recipe metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeMeta {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub vendor: Option<String>,
    /// Required variables that must be set via `--set KEY=VALUE`.
    /// If present (even empty), only listed vars are shown as required.
    /// If absent, all `{{...}}` placeholders are auto-discovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<Vec<String>>,
    /// Secret variables that should come from `op://`, `env:`, or `file:` sources.
    /// Advisory — shown in `--list-recipes` with `op://` hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
    /// Optional output-shape knob. Default emission is one
    /// `.mobileconfig` per `[[profile]]` block. Setting
    /// `output.combined = true` (or passing `--combined` at generate
    /// time) emits one `.mobileconfig` carrying every profile as inner
    /// `PayloadContent` entries — useful for vendor bundles like
    /// CrowdStrike that ship pieces independently but install together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<RecipeOutput>,
}

/// Output-shape knob for `[recipe]`. See `RecipeMeta::output`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeOutput {
    /// When true, all `[[profile]]` blocks render into ONE
    /// `.mobileconfig` with N inner `PayloadContent` entries. When
    /// false (default), each `[[profile]]` writes to its own file.
    #[serde(default)]
    pub combined: bool,
    /// Override for the combined output filename. Defaults to
    /// `<recipe.name>.mobileconfig`. Ignored when `combined = false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub combined_filename: Option<String>,
}

/// Specification for a single profile within a recipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSpec {
    pub filename: String,
    pub payload_type: String,
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub removal_disallowed: bool,
    /// MCX preference domain — set this on a
    /// `com.apple.ManagedClient.preferences` profile to author the
    /// preferences flat under `[profile.fields]` instead of writing the
    /// full `PayloadContent.<domain>.Forced[0].mcx_preference_settings`
    /// envelope by hand. The generator re-wraps on output; the importer
    /// auto-unwraps on input. Leave unset for non-MCX profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcx_domain: Option<String>,
    /// Field overrides matching schema field names.
    ///
    /// `BTreeMap` (not `HashMap`) so iteration is sorted and serialized
    /// output is byte-stable across runs — without this, every CI
    /// regeneration produces a spurious diff from re-ordered keys
    /// (semantically harmless since Apple parses dicts by key, not
    /// position, but creates churn).
    #[serde(default)]
    pub fields: BTreeMap<String, toml::Value>,
    /// Extra fields NOT in schema (vendor-specific, dot notation for nesting).
    /// Same `BTreeMap` rationale as `fields`.
    #[serde(default)]
    pub extra_fields: BTreeMap<String, toml::Value>,
}

/// Stats collected by [`Recipe::resolve_odv`] so callers can report
/// what happened.
#[derive(Debug, Clone, Default)]
pub struct OdvResolveStats {
    /// `"$ODV"` placeholders replaced with a value from `recipe.odv`.
    pub resolved: usize,
    /// Placeholders left intact because `recipe.odv` had no entry
    /// keyed by the parent field name — these flow through to the
    /// rendered profile verbatim, signaling a missing default.
    pub unresolved: usize,
}

impl Recipe {
    /// Replace literal `"$ODV"` strings inside profile fields and
    /// DDM payloads with values from the top-level `[odv]` table.
    ///
    /// Lookup uses the field's immediate parent key — the same name
    /// the operator would use when editing the `[odv]` table. Nested
    /// dictionaries are walked recursively; inside a nested dict the
    /// key is the immediate property name (not the full dotted
    /// path). When `[odv]` is empty, this is a no-op.
    pub fn resolve_odv(&mut self) -> OdvResolveStats {
        let mut stats = OdvResolveStats::default();

        for profile in &mut self.profiles {
            substitute_odv_in_toml_map(&mut profile.fields, &self.odv, &mut stats);
            substitute_odv_in_toml_map(&mut profile.extra_fields, &self.odv, &mut stats);
        }
        for bundle in &mut self.ddm {
            substitute_odv_in_json_map(&mut bundle.configuration.payload, &self.odv, &mut stats);
            if let Some(asset) = bundle.asset.as_mut() {
                substitute_odv_in_json_map(&mut asset.payload, &self.odv, &mut stats);
            }
        }
        stats
    }
}

fn substitute_odv_in_toml_map(
    map: &mut BTreeMap<String, toml::Value>,
    odv: &BTreeMap<String, toml::Value>,
    stats: &mut OdvResolveStats,
) {
    for (key, value) in map.iter_mut() {
        substitute_odv_in_toml_value(key, value, odv, stats);
    }
}

fn substitute_odv_in_toml_value(
    key: &str,
    value: &mut toml::Value,
    odv: &BTreeMap<String, toml::Value>,
    stats: &mut OdvResolveStats,
) {
    match value {
        toml::Value::String(s) if s == "$ODV" => match odv.get(key) {
            Some(replacement) => {
                *value = replacement.clone();
                stats.resolved += 1;
            }
            None => stats.unresolved += 1,
        },
        toml::Value::Table(t) => {
            for (k, v) in t.iter_mut() {
                substitute_odv_in_toml_value(k, v, odv, stats);
            }
        }
        toml::Value::Array(arr) => {
            for v in arr.iter_mut() {
                // Arrays don't carry parent-key context — substitute
                // by current key (rare but symmetric with mSCP shape).
                substitute_odv_in_toml_value(key, v, odv, stats);
            }
        }
        _ => {}
    }
}

fn substitute_odv_in_json_map(
    map: &mut serde_json::Map<String, serde_json::Value>,
    odv: &BTreeMap<String, toml::Value>,
    stats: &mut OdvResolveStats,
) {
    for (key, value) in map.iter_mut() {
        substitute_odv_in_json_value(key, value, odv, stats);
    }
}

fn substitute_odv_in_json_value(
    key: &str,
    value: &mut serde_json::Value,
    odv: &BTreeMap<String, toml::Value>,
    stats: &mut OdvResolveStats,
) {
    match value {
        serde_json::Value::String(s) if s == "$ODV" => match odv.get(key) {
            Some(replacement) => {
                *value = toml_to_json_value(replacement);
                stats.resolved += 1;
            }
            None => stats.unresolved += 1,
        },
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                substitute_odv_in_json_value(k, v, odv, stats);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                substitute_odv_in_json_value(key, v, odv, stats);
            }
        }
        _ => {}
    }
}

fn toml_to_json_value(v: &toml::Value) -> serde_json::Value {
    match v {
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::Value::Number((*i).into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::Datetime(d) => serde_json::Value::String(d.to_string()),
        toml::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(toml_to_json_value).collect())
        }
        toml::Value::Table(t) => {
            let mut out = serde_json::Map::with_capacity(t.len());
            for (k, val) in t {
                out.insert(k.clone(), toml_to_json_value(val));
            }
            serde_json::Value::Object(out)
        }
    }
}

#[cfg(test)]
mod odv_tests {
    use super::*;

    fn parse_recipe(toml_str: &str) -> Recipe {
        toml::from_str(toml_str).expect("recipe must parse")
    }

    #[test]
    fn resolve_odv_replaces_field_string_with_table_value() {
        let mut r = parse_recipe(
            r#"[recipe]
name = "test"
description = "test"

[odv]
timeServer = "time.apple.com"

[[profile]]
filename = "x.mobileconfig"
payload_type = "com.apple.MCX"
display_name = "MCX"
[profile.fields]
timeServer = "$ODV"
otherField = "untouched"
"#,
        );
        let stats = r.resolve_odv();
        assert_eq!(stats.resolved, 1);
        assert_eq!(stats.unresolved, 0);
        assert_eq!(
            r.profiles[0].fields.get("timeServer").unwrap().as_str(),
            Some("time.apple.com")
        );
        assert_eq!(
            r.profiles[0].fields.get("otherField").unwrap().as_str(),
            Some("untouched")
        );
    }

    #[test]
    fn resolve_odv_preserves_integer_type() {
        let mut r = parse_recipe(
            r#"[recipe]
name = "test"
description = "test"

[odv]
MaximumFailedAttempts = 5

[[profile]]
filename = "x.mobileconfig"
payload_type = "com.apple.MCX"
display_name = "MCX"
[profile.fields]
MaximumFailedAttempts = "$ODV"
"#,
        );
        let stats = r.resolve_odv();
        assert_eq!(stats.resolved, 1);
        // Integer landed as integer, not as a string.
        assert_eq!(
            r.profiles[0]
                .fields
                .get("MaximumFailedAttempts")
                .unwrap()
                .as_integer(),
            Some(5)
        );
    }

    #[test]
    fn resolve_odv_unresolved_when_key_missing() {
        let mut r = parse_recipe(
            r#"[recipe]
name = "test"
description = "test"

[odv]
otherKey = "value"

[[profile]]
filename = "x.mobileconfig"
payload_type = "com.apple.MCX"
display_name = "MCX"
[profile.fields]
timeServer = "$ODV"
"#,
        );
        let stats = r.resolve_odv();
        assert_eq!(stats.resolved, 0);
        assert_eq!(stats.unresolved, 1);
        // Placeholder flows through unchanged.
        assert_eq!(
            r.profiles[0].fields.get("timeServer").unwrap().as_str(),
            Some("$ODV")
        );
    }

    #[test]
    fn resolve_odv_walks_nested_table_fields() {
        let mut r = parse_recipe(
            r#"[recipe]
name = "test"
description = "test"

[odv]
Download = "AlwaysOn"

[[profile]]
filename = "x.mobileconfig"
payload_type = "com.apple.MCX"
display_name = "MCX"
[profile.fields]
[profile.fields.AutomaticActions]
Download = "$ODV"
"#,
        );
        let stats = r.resolve_odv();
        assert_eq!(stats.resolved, 1);
        let auto = r.profiles[0].fields.get("AutomaticActions").unwrap();
        let auto_table = auto.as_table().expect("nested table");
        assert_eq!(
            auto_table.get("Download").unwrap().as_str(),
            Some("AlwaysOn")
        );
    }

    #[test]
    fn resolve_odv_no_op_when_table_empty() {
        let mut r = parse_recipe(
            r#"[recipe]
name = "test"
description = "test"

[[profile]]
filename = "x.mobileconfig"
payload_type = "com.apple.MCX"
display_name = "MCX"
[profile.fields]
timeServer = "$ODV"
"#,
        );
        let stats = r.resolve_odv();
        assert_eq!(stats.resolved, 0);
        assert_eq!(stats.unresolved, 1);
    }
}
