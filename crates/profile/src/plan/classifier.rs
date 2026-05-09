//! Payload-pairing and tier classification.
//!
//! Algorithm:
//! 1. Build a `(PayloadType, PayloadIdentifier)` → payload index map for
//!    each side.
//! 2. For every key present on either side:
//!    - both sides → compare `PayloadUUID` and content; emit
//!      [`ChangeTier::Noop`] / [`ChangeTier::InPlaceUpdate`] /
//!      [`ChangeTier::Replace`] accordingly.
//!    - baseline only → emit [`ChangeTier::Remove`].
//!    - proposed only → emit [`ChangeTier::Add`].
//! 3. Sort changes by `(payload_index, tier)` for stable, reviewable output.
//!
//! REF_BROKEN, TYPE_INVALID, SCOPE_BROADENED, and DEPRECATED tiers are
//! computed by sibling modules and folded into the same `Vec<PayloadChange>`
//! by the higher-level orchestrator (added in subsequent slices).

use super::change::{ChangeTier, PayloadChange, Plan};
use crate::profile::{ConfigurationProfile, PayloadContent};
use std::collections::BTreeMap;

/// Classify the payload-level differences between `baseline` and
/// `proposed`. Both profiles should already have been normalized so
/// identifiers and PayloadOrganization are canonical; otherwise every
/// trivial difference will surface as `InPlaceUpdate`.
pub fn plan_profiles(baseline: &ConfigurationProfile, proposed: &ConfigurationProfile) -> Plan {
    let baseline_index = index_payloads(&baseline.payload_content);
    let proposed_index = index_payloads(&proposed.payload_content);

    let mut all_keys: Vec<&PayloadKey> = baseline_index.keys().collect();
    for k in proposed_index.keys() {
        if !baseline_index.contains_key(k) {
            all_keys.push(k);
        }
    }
    all_keys.sort();

    let mut changes = Vec::new();
    for key in all_keys {
        let baseline_payload = baseline_index
            .get(key)
            .map(|i| &baseline.payload_content[*i]);
        let proposed_payload = proposed_index
            .get(key)
            .map(|i| &proposed.payload_content[*i]);

        let change = match (baseline_payload, proposed_payload) {
            (None, None) => continue, // unreachable; key came from one side
            (None, Some(p)) => add_change(p, proposed_index[key]),
            (Some(b), None) => remove_change(b, baseline_index[key]),
            (Some(b), Some(p)) => compare_change(b, p, proposed_index[key]),
        };
        changes.push(change);
    }

    Plan::from_changes(changes)
}

/// Pairing key. Two payloads are "the same role" if their `PayloadType`
/// and `PayloadIdentifier` match. `PayloadUUID` deliberately is *not*
/// part of the key — that's what lets the classifier distinguish
/// `Replace` from `Add`+`Remove`.
type PayloadKey = (String, String);

fn payload_key(p: &PayloadContent) -> PayloadKey {
    (p.payload_type.clone(), p.payload_identifier.clone())
}

fn index_payloads(payloads: &[PayloadContent]) -> BTreeMap<PayloadKey, usize> {
    let mut idx = BTreeMap::new();
    for (i, p) in payloads.iter().enumerate() {
        // Last-wins on duplicate keys; the duplicate-PayloadIdentifier
        // case is already a lint Tier-1 error (see lint.rs), so this
        // tolerance only matters when the lint is bypassed.
        idx.insert(payload_key(p), i);
    }
    idx
}

fn add_change(proposed: &PayloadContent, idx: usize) -> PayloadChange {
    PayloadChange {
        tier: ChangeTier::Add,
        payload_type: proposed.payload_type.clone(),
        payload_identifier: proposed.payload_identifier.clone(),
        payload_index: idx,
        baseline_uuid: None,
        proposed_uuid: Some(proposed.payload_uuid.clone()),
        fields_changed: vec![],
        evidence: format!(
            "new payload {} ({}) installed alongside existing payloads",
            proposed.payload_identifier, proposed.payload_type
        ),
    }
}

fn remove_change(baseline: &PayloadContent, idx: usize) -> PayloadChange {
    PayloadChange {
        tier: ChangeTier::Remove,
        payload_type: baseline.payload_type.clone(),
        payload_identifier: baseline.payload_identifier.clone(),
        payload_index: idx,
        baseline_uuid: Some(baseline.payload_uuid.clone()),
        proposed_uuid: None,
        fields_changed: vec![],
        evidence: format!(
            "payload {} ({}) removed from device",
            baseline.payload_identifier, baseline.payload_type
        ),
    }
}

fn compare_change(
    baseline: &PayloadContent,
    proposed: &PayloadContent,
    idx: usize,
) -> PayloadChange {
    let uuid_changed = baseline.payload_uuid != proposed.payload_uuid;
    let fields_changed = diff_content_keys(&baseline.content, &proposed.content);
    let version_changed = baseline.payload_version != proposed.payload_version;

    let tier = if uuid_changed {
        ChangeTier::Replace
    } else if fields_changed.is_empty() && !version_changed {
        ChangeTier::Noop
    } else {
        ChangeTier::InPlaceUpdate
    };

    let evidence = match tier {
        ChangeTier::Replace => format!(
            "PayloadUUID changed {} → {}; MDM will remove and reinstall this payload",
            baseline.payload_uuid, proposed.payload_uuid
        ),
        ChangeTier::InPlaceUpdate => {
            if fields_changed.is_empty() {
                "PayloadVersion changed; in-place update".to_string()
            } else {
                format!("{} field(s) changed in place", fields_changed.len())
            }
        }
        ChangeTier::Noop => "no semantic change after normalize".to_string(),
        // Other tiers do not come out of this comparator.
        _ => String::new(),
    };

    PayloadChange {
        tier,
        payload_type: proposed.payload_type.clone(),
        payload_identifier: proposed.payload_identifier.clone(),
        payload_index: idx,
        baseline_uuid: Some(baseline.payload_uuid.clone()),
        proposed_uuid: Some(proposed.payload_uuid.clone()),
        fields_changed,
        evidence,
    }
}

/// Return the union-symmetric-difference of keys that differ in value.
/// Both maps are `BTreeMap<String, plist::Value>` so iteration is
/// deterministic; output is sorted by key.
fn diff_content_keys(
    baseline: &BTreeMap<String, plist::Value>,
    proposed: &BTreeMap<String, plist::Value>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (k, b_val) in baseline {
        match proposed.get(k) {
            None => out.push(k.clone()),
            Some(p_val) if p_val != b_val => out.push(k.clone()),
            _ => {}
        }
    }
    for k in proposed.keys() {
        if !baseline.contains_key(k) {
            out.push(k.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_with(payloads: Vec<PayloadContent>) -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".into(),
            payload_version: 1,
            payload_identifier: "com.acme.test".into(),
            payload_uuid: "PROFILE-UUID".into(),
            payload_display_name: "Test".into(),
            payload_content: payloads,
            additional_fields: BTreeMap::new(),
        }
    }

    fn payload(ty: &str, ident: &str, uuid: &str, kvs: &[(&str, plist::Value)]) -> PayloadContent {
        let mut content = BTreeMap::new();
        for (k, v) in kvs {
            content.insert((*k).to_string(), v.clone());
        }
        PayloadContent {
            payload_type: ty.into(),
            payload_version: 1,
            payload_identifier: ident.into(),
            payload_uuid: uuid.into(),
            content,
        }
    }

    #[test]
    fn identical_profiles_emit_noop() {
        let p = payload("com.apple.x", "com.acme.x", "AAA", &[]);
        let baseline = profile_with(vec![p.clone()]);
        let proposed = profile_with(vec![p]);
        let plan = plan_profiles(&baseline, &proposed);
        assert_eq!(plan.summary.noop, 1);
        assert_eq!(plan.summary.replace, 0);
        assert_eq!(plan.summary.in_place_update, 0);
    }

    #[test]
    fn payload_uuid_change_with_same_identifier_is_replace() {
        // The 15k-CA-storm pattern: same role, regenerated UUID.
        let baseline = profile_with(vec![payload(
            "com.apple.security.scep",
            "com.acme.scep",
            "OLD-SCEP-UUID",
            &[],
        )]);
        let proposed = profile_with(vec![payload(
            "com.apple.security.scep",
            "com.acme.scep",
            "NEW-SCEP-UUID",
            &[],
        )]);
        let plan = plan_profiles(&baseline, &proposed);
        assert_eq!(plan.summary.replace, 1);
        assert_eq!(plan.summary.noop, 0);
        let change = &plan.changes[0];
        assert_eq!(change.tier, ChangeTier::Replace);
        assert_eq!(change.baseline_uuid.as_deref(), Some("OLD-SCEP-UUID"));
        assert_eq!(change.proposed_uuid.as_deref(), Some("NEW-SCEP-UUID"));
        assert!(change.evidence.contains("remove and reinstall"));
    }

    #[test]
    fn value_change_with_same_uuid_is_in_place_update() {
        let baseline = profile_with(vec![payload(
            "com.apple.applicationaccess",
            "com.acme.access",
            "AAA",
            &[("allowAirDrop", plist::Value::Boolean(true))],
        )]);
        let proposed = profile_with(vec![payload(
            "com.apple.applicationaccess",
            "com.acme.access",
            "AAA",
            &[("allowAirDrop", plist::Value::Boolean(false))],
        )]);
        let plan = plan_profiles(&baseline, &proposed);
        assert_eq!(plan.summary.in_place_update, 1);
        assert_eq!(plan.summary.replace, 0);
        let change = &plan.changes[0];
        assert_eq!(change.fields_changed, vec!["allowAirDrop"]);
    }

    #[test]
    fn new_payload_in_proposed_only_is_add() {
        let baseline = profile_with(vec![]);
        let proposed = profile_with(vec![payload("com.apple.x", "com.acme.x", "AAA", &[])]);
        let plan = plan_profiles(&baseline, &proposed);
        assert_eq!(plan.summary.add, 1);
    }

    #[test]
    fn payload_only_in_baseline_is_remove() {
        let baseline = profile_with(vec![payload("com.apple.x", "com.acme.x", "AAA", &[])]);
        let proposed = profile_with(vec![]);
        let plan = plan_profiles(&baseline, &proposed);
        assert_eq!(plan.summary.remove, 1);
    }

    #[test]
    fn predictable_uuids_collapse_to_noop_under_normalize() {
        // The contract: when both sides normalize with --predictable v5
        // UUIDs derived from (org, identifier), the UUIDs match and a
        // pure cosmetic diff disappears. Simulate that by handing the
        // classifier matched UUIDs.
        let baseline = profile_with(vec![payload(
            "com.apple.x",
            "com.acme.x",
            "STABLE-V5-UUID",
            &[("k", plist::Value::String("v".into()))],
        )]);
        let proposed = profile_with(vec![payload(
            "com.apple.x",
            "com.acme.x",
            "STABLE-V5-UUID",
            &[("k", plist::Value::String("v".into()))],
        )]);
        assert_eq!(plan_profiles(&baseline, &proposed).summary.noop, 1);
    }

    #[test]
    fn fleet_okta_scep_pattern_is_replace() {
        // The exact CodeRabbit finding: regenerated SCEP PayloadUUID,
        // identical content. Plan must report REPLACE.
        let baseline = profile_with(vec![payload(
            "com.apple.security.scep",
            "com.fleet.okta.scep",
            "478f8ebd-ded5-5808-962d-36da7aa06afe",
            &[],
        )]);
        let proposed = profile_with(vec![payload(
            "com.apple.security.scep",
            "com.fleet.okta.scep",
            "E42B2DBC-DB2A-4DD8-A413-41E432842F2B",
            &[],
        )]);
        let plan = plan_profiles(&baseline, &proposed);
        assert_eq!(plan.summary.replace, 1);
        assert!(plan.summary.has_default_blocker());
    }
}
