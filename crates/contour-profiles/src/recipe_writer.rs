//! Shared recipe-TOML emitter for tools that build inner payloads
//! and want to publish them into the contour library workflow
//! (`contour profile library`) instead of emitting `.mobileconfig`
//! XML directly.
//!
//! The output shape mirrors `crates/profile/src/recipe/mod.rs::Recipe`:
//!
//! ```toml
//! [recipe]
//! name = "..."
//! description = "..."
//! vendor = "..."           # optional
//!
//! [[profile]]
//! filename = "..."
//! payload_type = "..."
//! display_name = "..."
//! description = "..."      # may be empty
//! removal_disallowed = false
//!
//! [profile.fields]
//! <flat key/value pairs from the inner payload>
//! ```
//!
//! Used by `btm`, `notifications`, and `pppc` so a scan-then-author
//! workflow can land directly in the operator's preset library
//! without a `.mobileconfig` round-trip.

use anyhow::{Context, Result};
use plist::{Dictionary, Value};
use std::fmt::Write as _;

/// One inner-payload contribution to a combined recipe TOML.
///
/// Callers build the `fields` `Dictionary` exactly as they would for
/// `ProfileBuilder::build` — the writer flattens it into a TOML
/// `[profile.fields]` table.
#[derive(Debug, Clone)]
pub struct RecipeProfile {
    /// `<filename>.mobileconfig` written when the recipe is later
    /// rendered via `contour profile generate --recipe …`.
    pub filename: String,
    /// Apple payload type identifier (e.g. `com.apple.servicemanagement.managed`).
    pub payload_type: String,
    /// Human-readable name shown in MDM consoles + listings.
    pub display_name: String,
    /// Optional descriptive text. Empty string is fine.
    pub description: String,
    /// Whether the rendered profile should set `PayloadRemovalDisallowed = true`.
    pub removal_disallowed: bool,
    /// Inner payload content. Keys here become `[profile.fields].<key>`.
    pub fields: Dictionary,
}

/// Render a combined recipe TOML body for `profiles`. The body is
/// returned as a `String` — the caller decides where to write it.
pub fn write_recipe_toml(
    name: &str,
    description: &str,
    vendor: Option<&str>,
    profiles: &[RecipeProfile],
) -> Result<String> {
    let mut out = String::new();
    let _ = writeln!(out, "[recipe]");
    let _ = writeln!(out, "name = {}", quote_toml_str(name));
    let _ = writeln!(out, "description = {}", quote_toml_str(description));
    if let Some(v) = vendor {
        let _ = writeln!(out, "vendor = {}", quote_toml_str(v));
    }
    let _ = writeln!(out);

    for spec in profiles {
        let _ = writeln!(out, "[[profile]]");
        let _ = writeln!(out, "filename = {}", quote_toml_str(&spec.filename));
        let _ = writeln!(out, "payload_type = {}", quote_toml_str(&spec.payload_type));
        let _ = writeln!(out, "display_name = {}", quote_toml_str(&spec.display_name));
        let _ = writeln!(out, "description = {}", quote_toml_str(&spec.description));
        let _ = writeln!(out, "removal_disallowed = {}", spec.removal_disallowed);
        let _ = writeln!(out);

        if !spec.fields.is_empty() {
            // Build a one-key wrapper so the toml serializer emits a
            // `[__fields__]` section we can rewrite into
            // `[profile.fields]`. This sidesteps the need to walk the
            // dict ourselves while still producing valid TOML for
            // nested tables and arrays.
            let toml_value = plist_to_toml(&Value::Dictionary(spec.fields.clone()))
                .context("failed to convert payload to TOML")?;
            let mut wrapper = toml::map::Map::new();
            wrapper.insert("__fields__".to_string(), toml_value);
            let serialized = toml::to_string(&toml::Value::Table(wrapper))
                .context("failed to serialize TOML")?;
            for line in serialized.lines() {
                let rewritten = if let Some(rest) = line.strip_prefix("[__fields__") {
                    if rest == "]" {
                        "[profile.fields]".to_string()
                    } else {
                        format!("[profile.fields{rest}")
                    }
                } else if let Some(rest) = line.strip_prefix("[[__fields__") {
                    format!("[[profile.fields{rest}")
                } else {
                    line.to_string()
                };
                let _ = writeln!(out, "{rewritten}");
            }
            let _ = writeln!(out);
        }
    }

    Ok(out)
}

/// Convert a `plist::Value` to a `toml::Value`. Mirror of (and
/// simpler than) `import_recipe::plist_value_to_toml` — these crates
/// don't carry MDM placeholder mappings.
fn plist_to_toml(v: &Value) -> Result<toml::Value> {
    Ok(match v {
        Value::String(s) => toml::Value::String(s.clone()),
        Value::Boolean(b) => toml::Value::Boolean(*b),
        Value::Integer(i) => i
            .as_signed()
            .map(toml::Value::Integer)
            .or_else(|| {
                i.as_unsigned()
                    .and_then(|u| i64::try_from(u).ok().map(toml::Value::Integer))
            })
            .ok_or_else(|| anyhow::anyhow!("integer out of i64 range"))?,
        Value::Real(f) => toml::Value::Float(*f),
        Value::Date(d) => {
            let text: String = d.to_xml_format();
            text.parse::<toml::value::Datetime>()
                .map(toml::Value::Datetime)
                .map_err(|e| anyhow::anyhow!("plist date '{text}' not TOML datetime: {e}"))?
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(plist_to_toml(item)?);
            }
            toml::Value::Array(out)
        }
        Value::Dictionary(dict) => {
            let mut tbl = toml::map::Map::new();
            for (k, val) in dict {
                tbl.insert(k.clone(), plist_to_toml(val)?);
            }
            toml::Value::Table(tbl)
        }
        Value::Data(_) => {
            anyhow::bail!(
                "<data> binary value not supported in recipe export — these crates don't author binary keys"
            )
        }
        _ => anyhow::bail!("unsupported plist value variant"),
    })
}

/// Quote a string as a TOML basic string literal. Handles the common
/// escapes (`\\`, `"`, control chars). Used for the top-level
/// `[recipe]` fields where we hand-roll the TOML.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> RecipeProfile {
        let mut fields = Dictionary::new();
        fields.insert("EnableFirewall".into(), Value::Boolean(true));
        fields.insert("LoggingOption".into(), Value::String("throttled".into()));
        RecipeProfile {
            filename: "fw.mobileconfig".into(),
            payload_type: "com.apple.security.firewall".into(),
            display_name: "Firewall".into(),
            description: String::new(),
            removal_disallowed: false,
            fields,
        }
    }

    #[test]
    fn writes_recipe_header_and_profile() {
        let toml = write_recipe_toml("fw", "demo", Some("Acme"), &[sample_profile()]).unwrap();
        assert!(toml.contains("[recipe]"));
        assert!(toml.contains("name = \"fw\""));
        assert!(toml.contains("vendor = \"Acme\""));
        assert!(toml.contains("[[profile]]"));
        assert!(toml.contains("payload_type = \"com.apple.security.firewall\""));
        assert!(toml.contains("[profile.fields]"));
        assert!(toml.contains("EnableFirewall = true"));
        assert!(toml.contains("LoggingOption = \"throttled\""));
    }

    #[test]
    fn round_trips_through_toml_parser() {
        let toml_body = write_recipe_toml("fw", "demo", None, &[sample_profile()]).unwrap();
        // Parse via the toml crate to confirm the body is well-formed.
        let _: toml::Value = toml::from_str(&toml_body).expect("parses");
    }

    #[test]
    fn vendor_omitted_when_none() {
        let toml = write_recipe_toml("x", "y", None, &[]).unwrap();
        assert!(!toml.contains("vendor"));
    }

    #[test]
    fn quotes_escape_special_chars() {
        let mut fields = Dictionary::new();
        fields.insert("Quote".into(), Value::String("he said \"hi\"".into()));
        let toml = write_recipe_toml(
            "x",
            "with \"quotes\" and \\ backslash",
            None,
            &[RecipeProfile {
                filename: "x.mobileconfig".into(),
                payload_type: "x.y".into(),
                display_name: "X".into(),
                description: String::new(),
                removal_disallowed: false,
                fields,
            }],
        )
        .unwrap();
        // The hand-rolled `[recipe]` section uses our quote_toml_str —
        // quotes escape via `\"`.
        assert!(toml.contains(r#"description = "with \"quotes\" and \\ backslash""#));
        // The fields section goes through the toml serializer, which
        // may pick literal-string syntax for values containing `"`.
        // Either path must produce a parseable document.
        let parsed: toml::Value = toml::from_str(&toml).expect("escaped TOML must parse");
        let q = parsed["profile"][0]["fields"]["Quote"]
            .as_str()
            .expect("Quote field must round-trip as a string");
        assert_eq!(q, "he said \"hi\"");
    }
}
