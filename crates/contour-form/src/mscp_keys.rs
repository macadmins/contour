//! Payload keys mSCP prescribes, from the embedded rule payloads.
//!
//! Apple's schema is the authority on what a payload type accepts, but some
//! keys mSCP sets predate it or were never documented (`com.apple.MCX`
//! `forceInternetSharingOff`, the guest-account pair). A profile that carries
//! one is following the baseline contour itself generates, so strict
//! validation must not call it unknown. This index says, per payload type,
//! which keys mSCP sets and which rules set them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// `payload_type -> key -> rule ids`.
pub type PrescribedKeys = BTreeMap<String, BTreeMap<String, BTreeSet<String>>>;

/// Every (payload type, key) an mSCP rule's `mobileconfig_info` sets, built
/// once from the embedded `rule_payloads` table. A row whose JSON does not
/// parse is skipped: the table is generated, and one bad row must not hide
/// the rest.
pub fn prescribed_keys() -> &'static PrescribedKeys {
    static CACHE: OnceLock<PrescribedKeys> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out = PrescribedKeys::new();
        let rows = mscp_schema::rule_payloads::read(mscp_schema::embedded_rule_payloads())
            .unwrap_or_default();
        for row in rows {
            let Some(info) = row.mobileconfig_info.as_deref() else {
                continue;
            };
            let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(info) else {
                continue;
            };
            for item in items {
                let (Some(payload_type), Some(keys)) = (
                    item.get("payload_type").and_then(|v| v.as_str()),
                    item.get("keys").and_then(|v| v.as_object()),
                ) else {
                    continue;
                };
                let by_key = out.entry(payload_type.to_string()).or_default();
                for key in keys.keys() {
                    by_key
                        .entry(key.clone())
                        .or_default()
                        .insert(row.rule_id.clone());
                }
            }
        }
        out
    })
}

/// The mSCP rules that set `key` on `payload_type`, or `None` when no rule
/// does.
pub fn rules_prescribing(payload_type: &str, key: &str) -> Option<&'static BTreeSet<String>> {
    prescribed_keys().get(payload_type)?.get(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The case from issue #14: contour's own mSCP data prescribes this key,
    /// Apple's schema does not list it.
    #[test]
    fn mcx_internet_sharing_is_prescribed() {
        let rules = rules_prescribing("com.apple.MCX", "forceInternetSharingOff")
            .expect("forceInternetSharingOff is set by system_settings_internet_sharing_disable");
        assert!(rules.contains("system_settings_internet_sharing_disable"), "{rules:?}");
        assert!(rules_prescribing("com.apple.MCX", "noSuchKey").is_none());
        assert!(prescribed_keys().len() > 20, "expected dozens of payload types");
    }
}
