//! Values for `ddm generate` and `command generate`: one way in for both.
//!
//! `--payload FILE` (JSON or TOML object) is the base; each `--set PATH=VALUE`
//! is applied over it. A dotted PATH builds nested dictionaries
//! (`--set Updates=…`, `--set IncomingServer.Port=993`). A VALUE takes the
//! type of the schema key it sets: text for a string key, a number for an
//! integer key, `true`/`false` for a boolean, JSON for an array or a
//! dictionary. A key the schema does not know takes JSON when it parses, and
//! text otherwise.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// What the schema says about one key path.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    /// `string`, `integer`, `real`, `boolean`, `date`, `data`, `array`,
    /// `dictionary` or `any`.
    pub data_type: String,
    pub required: bool,
    pub allowed: Vec<String>,
}

/// The payload file merged with every `--set`, typed by `schema`.
///
/// # Errors
///
/// A file that cannot be read or parsed, a `--set` without `=`, or a value
/// its key's type cannot take.
pub fn collect(
    payload_file: Option<&str>,
    sets: &[String],
    schema: &BTreeMap<String, KeyInfo>,
) -> Result<Map<String, Value>> {
    let mut values = match payload_file {
        Some(path) => read_file(path)?,
        None => Map::new(),
    };
    for set in sets {
        let (path, raw) = set
            .split_once('=')
            .with_context(|| format!("--set '{set}': expected PATH=VALUE"))?;
        let value = typed(raw, schema.get(path).map(|k| k.data_type.as_str()))
            .with_context(|| format!("--set {path}"))?;
        contour_form::FieldPath::parse(path)
            .insert_json(&mut values, value)
            .map_err(|e| anyhow::anyhow!("--set {path}: {e}"))?;
    }
    Ok(values)
}

/// Problems with `values` against `schema`: unknown top-level keys, missing
/// required top-level keys, scalars of the wrong type or outside their
/// allowed values. Empty when the values fit.
pub fn check(values: &Map<String, Value>, schema: &BTreeMap<String, KeyInfo>) -> Vec<String> {
    let mut out = Vec::new();
    let top: Vec<&str> = schema.keys().filter(|p| !p.contains('.')).map(String::as_str).collect();
    for key in values.keys() {
        if !top.contains(&key.as_str()) {
            out.push(format!("'{key}' is not a key of this type; known: {}", top.join(", ")));
        }
    }
    for (path, info) in schema.iter().filter(|(p, _)| !p.contains('.')) {
        if info.required && !values.contains_key(path) {
            out.push(format!("'{path}' is required"));
        }
    }
    walk(values, "", schema, &mut out);
    out
}

fn walk(values: &Map<String, Value>, prefix: &str, schema: &BTreeMap<String, KeyInfo>, out: &mut Vec<String>) {
    for (key, value) in values {
        let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
        let Some(info) = schema.get(&path) else {
            if let Value::Object(inner) = value {
                walk(inner, &path, schema, out);
            }
            continue;
        };
        let fits = match (info.data_type.as_str(), value) {
            ("any", _) => true,
            ("string" | "date" | "data", Value::String(_)) => true,
            ("integer", Value::Number(n)) => n.is_i64() || n.is_u64(),
            ("real", Value::Number(_)) | ("boolean", Value::Bool(_)) => true,
            ("array", Value::Array(_)) | ("dictionary", Value::Object(_)) => true,
            _ => false,
        };
        if !fits {
            out.push(format!("'{path}' takes {}, got {value}", info.data_type));
            continue;
        }
        if !info.allowed.is_empty() && !matches!(value, Value::Array(_) | Value::Object(_)) {
            let shown = value.as_str().map_or_else(|| value.to_string(), str::to_string);
            if !info.allowed.contains(&shown) {
                out.push(format!("'{path}' is {shown}; allowed: {}", info.allowed.join(", ")));
            }
        }
        if let Value::Object(inner) = value {
            walk(inner, &path, schema, out);
        }
    }
}

/// Merge `over` into `base`: dictionaries merge key by key, anything else
/// replaces.
pub fn deep_merge(base: &mut Map<String, Value>, over: Map<String, Value>) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(Value::Object(b)), Value::Object(o)) => deep_merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

fn read_file(path: &str) -> Result<Map<String, Value>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading payload file '{path}'"))?;
    let value: Value = if std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("toml"))
    {
        serde_json::to_value(toml::from_str::<toml::Value>(&text).with_context(|| format!("parsing TOML '{path}'"))?)?
    } else {
        serde_json::from_str(&text).with_context(|| format!("parsing JSON '{path}'"))?
    };
    match value {
        Value::Object(map) => Ok(map),
        _ => bail!("payload file '{path}' must hold an object of key/values"),
    }
}

/// `raw` as a plist value of `data_type`, for a prompt's answer.
///
/// # Errors
///
/// A value the type cannot take, or one with no plist form (JSON `null`).
pub fn plist_value(raw: &str, data_type: &str) -> Result<plist::Value> {
    let v = typed(raw, Some(&data_type.to_ascii_lowercase()))?;
    serde_json::from_value(v).context("no plist form")
}

/// `raw` as the value a key of `data_type` takes.
fn typed(raw: &str, data_type: Option<&str>) -> Result<Value> {
    Ok(match data_type {
        Some("string" | "date" | "data") => Value::String(raw.to_string()),
        Some("integer") => Value::from(raw.parse::<i64>().with_context(|| format!("'{raw}' is not an integer"))?),
        Some("real") => Value::from(raw.parse::<f64>().with_context(|| format!("'{raw}' is not a number"))?),
        Some("boolean") => match raw.to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Value::Bool(true),
            "false" | "no" | "0" => Value::Bool(false),
            _ => bail!("'{raw}' is not true or false"),
        },
        Some("array" | "dictionary") => serde_json::from_str(raw)
            .with_context(|| format!("'{raw}' is not JSON for a {}", data_type.unwrap_or_default()))?,
        _ => serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> BTreeMap<String, KeyInfo> {
        let k = |t: &str, required: bool, allowed: &[&str]| KeyInfo {
            data_type: t.into(),
            required,
            allowed: allowed.iter().map(|s| (*s).to_string()).collect(),
        };
        BTreeMap::from([
            ("Version".into(), k("string", true, &[])),
            ("Port".into(), k("integer", false, &[])),
            ("Mode".into(), k("string", false, &["On", "Off"])),
            ("Server".into(), k("dictionary", false, &[])),
            ("Server.Host".into(), k("string", false, &[])),
            ("Updates".into(), k("array", false, &[])),
        ])
    }

    #[test]
    fn a_value_takes_its_keys_type_and_a_dotted_path_nests() {
        let sets = [
            "Version=27".to_string(),
            "Port=993".to_string(),
            "Server.Host=mail.acme.com".to_string(),
            r#"Updates=[{"ProductKey":"MSU_UPDATE_26B131_patch_27.2.1_minor"}]"#.to_string(),
        ];
        let v = collect(None, &sets, &schema()).unwrap();
        assert_eq!(v["Version"], "27", "a string key keeps 27 as text");
        assert_eq!(v["Port"], 993);
        assert_eq!(v["Server"]["Host"], "mail.acme.com");
        assert_eq!(v["Updates"][0]["ProductKey"], "MSU_UPDATE_26B131_patch_27.2.1_minor");
        assert!(check(&v, &schema()).is_empty(), "{:?}", check(&v, &schema()));
    }

    #[test]
    fn bad_values_unknown_keys_and_missing_required_keys_are_named() {
        collect(None, &["Port=abc".to_string()], &schema()).unwrap_err();
        let v = collect(None, &["Mode=Maybe".to_string(), "Typo=1".to_string()], &schema()).unwrap();
        let problems = check(&v, &schema()).join("\n");
        assert!(problems.contains("'Typo' is not a key"), "{problems}");
        assert!(problems.contains("'Version' is required"), "{problems}");
        assert!(problems.contains("'Mode' is Maybe"), "{problems}");
    }

    #[test]
    fn set_wins_over_the_payload_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("values.json");
        std::fs::write(&file, r#"{"Version":"26","Server":{"Host":"old"}}"#).unwrap();
        let v = collect(file.to_str(), &["Server.Host=new".to_string()], &schema()).unwrap();
        assert_eq!((v["Version"].as_str(), v["Server"]["Host"].as_str()), (Some("26"), Some("new")));
    }
}
