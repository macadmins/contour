//! `SkipSetupItems` entries, checked against Apple's skip-key registry.
//!
//! Apple types the array as plain strings, so a typo is schema-valid: the
//! profile validates, deploys, and the Setup Assistant pane it was meant to
//! suppress still appears. Nothing reports a problem, because nothing looked.
//!
//! contour already embeds the registry for `profile enrollment`, so it can
//! say which names exist. This module is the lookup only — turning a finding
//! into a validation issue is the caller's job.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use contour_core::levenshtein_distance;

use crate::mcx::MCX_PAYLOAD_TYPE;
use crate::profile::PayloadContent;

/// The managed-preference domain that carries `SkipSetupItems`.
pub const SETUP_ASSISTANT_DOMAIN: &str = "com.apple.SetupAssistant.managed";

/// The array key naming the panes to skip.
pub const SKIP_SETUP_ITEMS: &str = "SkipSetupItems";

/// An entry that matches no documented skip key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownSkipItem {
    /// The entry as written in the profile.
    pub item: String,
    /// The closest documented key, when one is near enough to be a likely typo.
    pub suggestion: Option<String>,
}

/// Every skip key Apple documents, across every platform and both channels.
///
/// Deliberately platform-agnostic. A profile does not state which platform it
/// targets, and the same array is legitimately reused across them, so
/// narrowing by platform would produce false findings. The beta dataset is
/// folded in for the same reason: a key that is seed-only today is a real key,
/// and warning about it would be wrong.
fn known_skip_keys() -> &'static BTreeSet<String> {
    static KEYS: OnceLock<BTreeSet<String>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut set = BTreeSet::new();
        for bytes in [
            mdm_schema::embedded_skip_keys(),
            mdm_schema::embedded_skip_keys_beta(),
        ] {
            if let Ok(keys) = mdm_schema::skip_keys::read(bytes) {
                set.extend(keys.into_iter().map(|k| k.key));
            }
        }
        set
    })
}

/// The `SkipSetupItems` entries this payload carries, from either shape.
///
/// Two shapes, because the key is delivered two ways: directly on a
/// `com.apple.SetupAssistant.managed` payload, or nested inside the MCX
/// wrapper under that domain. Both appear in the wild, often for the same
/// setting.
fn items_in(payload: &PayloadContent) -> Vec<String> {
    if payload.payload_type == SETUP_ASSISTANT_DOMAIN {
        return strings(payload.content.get(SKIP_SETUP_ITEMS));
    }
    if payload.payload_type != MCX_PAYLOAD_TYPE {
        return Vec::new();
    }

    let Some(body) = payload
        .content
        .get("PayloadContent")
        .and_then(plist::Value::as_dictionary)
        .and_then(|domains| domains.get(SETUP_ASSISTANT_DOMAIN))
        .and_then(plist::Value::as_dictionary)
    else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for mode in ["Forced", "Set"] {
        let Some(entries) = body.get(mode).and_then(plist::Value::as_array) else {
            continue;
        };
        for entry in entries {
            let settings = entry
                .as_dictionary()
                .and_then(|d| d.get("mcx_preference_settings"))
                .and_then(plist::Value::as_dictionary);
            if let Some(settings) = settings {
                out.extend(strings(settings.get(SKIP_SETUP_ITEMS)));
            }
        }
    }
    out
}

/// The string members of a plist array, ignoring anything else in it.
fn strings(value: Option<&plist::Value>) -> Vec<String> {
    value
        .and_then(plist::Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|v| v.as_string().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Entries in this payload that match no documented skip key.
///
/// Empty for a payload that carries no `SkipSetupItems` at all, which is
/// every payload but the two Setup Assistant shapes.
pub fn unknown_items(payload: &PayloadContent) -> Vec<UnknownSkipItem> {
    let known = known_skip_keys();
    items_in(payload)
        .into_iter()
        .filter(|item| !known.contains(item))
        .map(|item| {
            let lower = item.to_lowercase();
            let suggestion = known
                .iter()
                .filter(|k| levenshtein_distance(&k.to_lowercase(), &lower) <= 3)
                .min_by_key(|k| levenshtein_distance(&k.to_lowercase(), &lower))
                .cloned();
            UnknownSkipItem { item, suggestion }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn mcx_payload(items: &[&str]) -> PayloadContent {
        let array = plist::Value::Array(
            items
                .iter()
                .map(|s| plist::Value::String((*s).to_string()))
                .collect(),
        );
        let mut settings = plist::Dictionary::new();
        settings.insert(SKIP_SETUP_ITEMS.to_string(), array);

        let mut forced_entry = plist::Dictionary::new();
        forced_entry.insert(
            "mcx_preference_settings".to_string(),
            plist::Value::Dictionary(settings),
        );

        let mut domain = plist::Dictionary::new();
        domain.insert(
            "Forced".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(forced_entry)]),
        );

        let mut domains = plist::Dictionary::new();
        domains.insert(
            SETUP_ASSISTANT_DOMAIN.to_string(),
            plist::Value::Dictionary(domain),
        );

        let mut content = BTreeMap::new();
        content.insert(
            "PayloadContent".to_string(),
            plist::Value::Dictionary(domains),
        );

        PayloadContent {
            payload_type: MCX_PAYLOAD_TYPE.to_string(),
            payload_version: 1,
            payload_identifier: "com.acme.skip".to_string(),
            payload_uuid: "8E1B1E1C-0000-4000-8000-000000000001".to_string(),
            content,
        }
    }

    fn direct_payload(items: &[&str]) -> PayloadContent {
        let mut content = BTreeMap::new();
        content.insert(
            SKIP_SETUP_ITEMS.to_string(),
            plist::Value::Array(
                items
                    .iter()
                    .map(|s| plist::Value::String((*s).to_string()))
                    .collect(),
            ),
        );
        PayloadContent {
            payload_type: SETUP_ASSISTANT_DOMAIN.to_string(),
            payload_version: 1,
            payload_identifier: "com.acme.skip".to_string(),
            payload_uuid: "8E1B1E1C-0000-4000-8000-000000000002".to_string(),
            content,
        }
    }

    #[test]
    fn documented_keys_are_quiet() {
        // LiquidGlass is 27.0 — recent, and the reason this check exists.
        let p = mcx_payload(&["Diagnostics", "FileVault", "LiquidGlass", "Welcome"]);
        assert_eq!(unknown_items(&p), Vec::new());
    }

    #[test]
    fn a_typo_is_reported_with_the_key_it_resembles() {
        let p = mcx_payload(&["LiquidGlas"]);
        let found = unknown_items(&p);
        assert_eq!(found.len(), 1, "expected one finding, got {found:?}");
        assert_eq!(found[0].item, "LiquidGlas");
        assert_eq!(found[0].suggestion.as_deref(), Some("LiquidGlass"));
    }

    #[test]
    fn a_name_resembling_nothing_is_still_reported() {
        let p = mcx_payload(&["NotAPaneAtAll"]);
        let found = unknown_items(&p);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].suggestion, None);
    }

    #[test]
    fn the_direct_payload_shape_is_read_too() {
        let p = direct_payload(&["Diagnostics", "Zzzzzzzzzzzz"]);
        let found = unknown_items(&p);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].item, "Zzzzzzzzzzzz");
    }

    #[test]
    fn an_unrelated_payload_yields_nothing() {
        let mut content = BTreeMap::new();
        content.insert("allowScreenShot".to_string(), plist::Value::Boolean(false));
        let p = PayloadContent {
            payload_type: "com.apple.applicationaccess".to_string(),
            payload_version: 1,
            payload_identifier: "com.acme.restrictions".to_string(),
            payload_uuid: "8E1B1E1C-0000-4000-8000-000000000003".to_string(),
            content,
        };
        assert_eq!(unknown_items(&p), Vec::new());
    }
}
