//! DEPRECATED tier — fold lint findings into the plan.
//!
//! Surfaces only the *new* deprecated payload types that the proposed
//! profile introduced. If a baseline already had a deprecated payload
//! and the proposed kept it, that's the user's pre-existing situation
//! and not a *change* this PR introduced — don't double-flag it.

use super::change::{ChangeTier, PayloadChange};
use crate::migrate::MigrationRegistry;
use crate::profile::ConfigurationProfile;
use crate::profile::lint::check_deprecated_payload_types;
use std::collections::BTreeSet;

/// Compute DEPRECATED findings on the proposed profile, filtered by
/// what the baseline did *not* already contain.
pub fn check_new_deprecations(
    baseline: Option<&ConfigurationProfile>,
    proposed: &ConfigurationProfile,
) -> Vec<PayloadChange> {
    let registry = MigrationRegistry::new();

    let baseline_offenders = baseline
        .map(|p| collect_deprecated_keys(p, &registry))
        .unwrap_or_default();

    let proposed_value = match plist::to_value(proposed) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let findings = check_deprecated_payload_types(&proposed_value, &registry);

    let mut changes = Vec::new();
    for finding in findings {
        let Some(idx) = finding.payload_index else {
            continue; // outer-profile-level finding; not a payload-level change
        };
        if idx >= proposed.payload_content.len() {
            continue;
        }
        let payload = &proposed.payload_content[idx];
        let key = (
            payload.payload_type.clone(),
            payload.payload_identifier.clone(),
        );
        if baseline_offenders.contains(&key) {
            continue; // pre-existing; not a *new* deprecation introduced by this change
        }
        changes.push(PayloadChange {
            tier: ChangeTier::Deprecated,
            payload_type: payload.payload_type.clone(),
            payload_identifier: payload.payload_identifier.clone(),
            payload_index: idx,
            baseline_uuid: None,
            proposed_uuid: Some(payload.payload_uuid.clone()),
            fields_changed: vec![],
            evidence: finding.message,
        });
    }
    changes
}

/// Return the set of (PayloadType, PayloadIdentifier) pairs that lint
/// flagged as deprecated in the given profile.
fn collect_deprecated_keys(
    profile: &ConfigurationProfile,
    registry: &MigrationRegistry,
) -> BTreeSet<(String, String)> {
    let value = match plist::to_value(profile) {
        Ok(v) => v,
        Err(_) => return BTreeSet::new(),
    };
    let findings = check_deprecated_payload_types(&value, registry);
    findings
        .into_iter()
        .filter_map(|f| {
            let idx = f.payload_index?;
            let p = profile.payload_content.get(idx)?;
            Some((p.payload_type.clone(), p.payload_identifier.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::PayloadContent;
    use std::collections::BTreeMap;

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

    fn payload(ty: &str, ident: &str, uuid: &str) -> PayloadContent {
        PayloadContent {
            payload_type: ty.into(),
            payload_version: 1,
            payload_identifier: ident.into(),
            payload_uuid: uuid.into(),
            content: BTreeMap::new(),
        }
    }

    #[test]
    fn unknown_payload_type_emits_no_findings() {
        // A PayloadType the migration registry doesn't track produces
        // no DEPRECATED finding (whether it's truly modern or just
        // unknown — DEPRECATED is for known-deprecated types only).
        let p = profile_with(vec![payload(
            "com.example.unknown.test",
            "com.acme.x",
            "AAA",
        )]);
        let changes = check_new_deprecations(None, &p);
        assert!(
            changes.is_empty(),
            "unknown PayloadType produced findings: {:?}",
            changes
        );
    }

    #[test]
    fn pre_existing_deprecation_is_not_re_flagged() {
        // If both baseline and proposed contain the same deprecated
        // payload (e.g. com.apple.applicationaccess, registry status
        // Partial), plan must NOT re-flag it as a *new* change.
        let p = profile_with(vec![payload(
            "com.apple.applicationaccess",
            "com.acme.access",
            "AAA",
        )]);
        let baseline_changes = check_new_deprecations(Some(&p), &p);
        assert!(
            baseline_changes.is_empty(),
            "pre-existing deprecation should not be re-flagged: {:?}",
            baseline_changes
        );
    }

    #[test]
    fn newly_introduced_deprecation_is_flagged() {
        // baseline has no payloads; proposed introduces a deprecated
        // PayloadType. Plan must report Deprecated.
        let baseline = profile_with(vec![]);
        let proposed = profile_with(vec![payload(
            "com.apple.applicationaccess",
            "com.acme.access",
            "AAA",
        )]);
        let changes = check_new_deprecations(Some(&baseline), &proposed);
        assert!(
            !changes.is_empty(),
            "newly introduced deprecated PayloadType was not flagged"
        );
        assert_eq!(changes[0].tier, ChangeTier::Deprecated);
    }
}
