//! Pure transforms applied to an example declaration's JSON.

use anyhow::{Context, Result};
use serde_json::Value;

/// Known placeholder substrings Apple uses in examples.
const PLACEHOLDER_MARKERS: &[&str] = &["com.example.", "ABCD1234"];

/// Derive a short name from a declaration `Type` for use in the Identifier.
/// `com.apple.configuration.app.settings` -> `app.settings`; non-Apple types
/// are returned unchanged.
pub fn short_name_from_type(type_str: &str) -> &str {
    type_str
        .strip_prefix("com.apple.")
        .map_or(type_str, |rest| {
            rest.find('.').map_or(rest, |idx| &rest[idx + 1..])
        })
}

/// Org-scope the `Identifier` and strip the MDM-assigned `ServerToken`.
pub fn structural_fixups(v: &mut Value, org: &str, short_name: &str, index: u32) {
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "Identifier".to_string(),
            Value::String(format!("{org}.{short_name}.{index}")),
        );
        obj.remove("ServerToken");
    }
}

/// Apply ordered string `find→replace` pairs over the serialized JSON.
pub fn apply_find_replace(v: &Value, pairs: &[(String, String)]) -> Result<Value> {
    let mut text = serde_json::to_string(v).context("serializing example")?;
    for (find, replace) in pairs {
        if !find.is_empty() {
            text = text.replace(find.as_str(), replace);
        }
    }
    serde_json::from_str(&text).context("re-parsing after find/replace")
}

/// Apply ordered string find→replace pairs over raw text (any format).
pub fn apply_find_replace_text(text: &str, pairs: &[(String, String)]) -> String {
    let mut out = text.to_string();
    for (find, replace) in pairs {
        if !find.is_empty() {
            out = out.replace(find.as_str(), replace);
        }
    }
    out
}

/// Return the distinct placeholder markers still present in the JSON.
pub fn remaining_placeholders(v: &Value) -> Vec<String> {
    let text = v.to_string();
    PLACEHOLDER_MARKERS
        .iter()
        .filter(|m| text.contains(**m))
        .map(|m| (*m).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn structural_fixups_set_identifier_and_strip_server_token() {
        let mut v = json!({
            "Type": "com.apple.configuration.app.settings",
            "Identifier": "245E4CBC-021B-4DB0-9B30-25F581119A2A",
            "ServerToken": "D6472788-7568-4268-99CE-AD8AE114B28C",
            "Payload": {}
        });
        structural_fixups(&mut v, "com.acme", "app.settings", 1);
        assert_eq!(v["Identifier"], "com.acme.app.settings.1");
        assert!(v.get("ServerToken").is_none());
    }

    #[test]
    fn short_name_from_type_strips_apple_and_category() {
        assert_eq!(
            short_name_from_type("com.apple.configuration.app.settings"),
            "app.settings"
        );
        assert_eq!(
            short_name_from_type("com.apple.activation.simple"),
            "simple"
        );
        assert_eq!(short_name_from_type("custom.thing"), "custom.thing");
    }

    #[test]
    fn find_replace_applies_over_serialized_json() {
        let v = json!({"Payload": {"x": "com.example.scanner (ABCD1234)"}});
        let out = apply_find_replace(
            &v,
            &[
                ("com.example.scanner".into(), "us.zoom.xos".into()),
                ("ABCD1234".into(), "BJ4HAAB9B3".into()),
            ],
        )
        .unwrap();
        assert_eq!(out["Payload"]["x"], "us.zoom.xos (BJ4HAAB9B3)");
    }

    #[test]
    fn apply_find_replace_text_replaces_in_any_format() {
        let xml = "<string>com.example.app</string><string>ABCD1234</string>";
        let pairs = vec![
            ("com.example.app".to_string(), "com.acme.myapp".to_string()),
            ("ABCD1234".to_string(), "XYZ99999".to_string()),
        ];
        let result = apply_find_replace_text(xml, &pairs);
        assert_eq!(
            result,
            "<string>com.acme.myapp</string><string>XYZ99999</string>"
        );
    }

    #[test]
    fn apply_find_replace_text_skips_empty_find() {
        let text = "hello world";
        let pairs = vec![(String::new(), "SHOULD_NOT_APPEAR".to_string())];
        assert_eq!(apply_find_replace_text(text, &pairs), "hello world");
    }

    #[test]
    fn placeholder_scan_flags_and_clears() {
        let dirty = json!({"Payload": {"a": "com.example.app"}});
        assert!(
            remaining_placeholders(&dirty)
                .iter()
                .any(|h| h.contains("com.example."))
        );
        let clean = json!({"Payload": {"a": "us.zoom.xos"}});
        assert!(remaining_placeholders(&clean).is_empty());
    }
}
