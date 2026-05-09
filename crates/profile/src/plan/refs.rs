//! Cross-reference integrity check for `profile plan`.
//!
//! Maps every `link::LinkValidationError` on the *proposed* profile to a
//! `PayloadChange` with `tier = RefBroken`. This is the slice that
//! catches the Okta SCEP / `PayloadCertificateUUID` orphan pattern
//! flagged by CodeRabbit on the Fleet GitOps PR.
//!
//! The lib already has the heavy machinery in `crate::link`; this
//! module just adapts the result into the plan vocabulary.

use super::change::{ChangeTier, PayloadChange};
use crate::link::types::LinkErrorType;
use crate::link::validator::validate_cross_references;
use crate::profile::ConfigurationProfile;
use std::path::Path;

/// Compute `RefBroken` findings on the proposed profile.
///
/// `path` is purely cosmetic — it lets `link::validate_cross_references`
/// produce nicer diagnostics. Callers passing in-memory profiles can
/// supply any path (e.g., the relative profile path).
pub fn check_proposed_refs(proposed: &ConfigurationProfile, path: &Path) -> Vec<PayloadChange> {
    let result = validate_cross_references(&[(path, proposed.clone())]);
    if result.valid {
        return Vec::new();
    }

    let mut changes = Vec::new();
    for err in &result.errors {
        // Find which payload in the proposed profile owns the bad reference,
        // so we can report a useful payload_type / payload_identifier /
        // payload_index instead of just the orphaned UUID.
        let (payload_index, payload_type, payload_identifier) =
            match locate_payload_by_uuid(proposed, &err.source_payload_uuid) {
                Some(found) => found,
                None => (
                    usize::MAX,
                    "(unknown)".to_string(),
                    err.source_payload_uuid.clone(),
                ),
            };

        let evidence = match &err.error_type {
            LinkErrorType::MissingReference => format!(
                "{} = {} resolves to no payload — installs but will not bind",
                err.field_name, err.referenced_uuid
            ),
            LinkErrorType::TypeMismatch { expected, actual } => format!(
                "{} = {} resolves to a {} payload; expected one of {}",
                err.field_name,
                err.referenced_uuid,
                actual,
                expected.join(", ")
            ),
        };

        changes.push(PayloadChange {
            tier: ChangeTier::RefBroken,
            payload_type,
            payload_identifier,
            payload_index,
            baseline_uuid: None,
            proposed_uuid: Some(err.source_payload_uuid.clone()),
            fields_changed: vec![err.field_name.clone()],
            evidence,
        });
    }
    changes
}

fn locate_payload_by_uuid(
    profile: &ConfigurationProfile,
    uuid: &str,
) -> Option<(usize, String, String)> {
    profile
        .payload_content
        .iter()
        .enumerate()
        .find_map(|(i, p)| {
            if p.payload_uuid == uuid {
                Some((i, p.payload_type.clone(), p.payload_identifier.clone()))
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::PayloadContent;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

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

    fn profile_with(payloads: Vec<PayloadContent>) -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".into(),
            payload_version: 1,
            payload_identifier: "com.fleet.okta".into(),
            payload_uuid: "PROFILE-UUID".into(),
            payload_display_name: "Test".into(),
            payload_content: payloads,
            additional_fields: BTreeMap::new(),
        }
    }

    #[test]
    fn fleet_okta_orphaned_payload_certificate_uuid_is_ref_broken() {
        // Reproduce the exact CodeRabbit finding: the SCEP payload UUID
        // was regenerated to E42B…, but the identity-preference payload
        // still points at the old 478f… UUID. plan must report
        // RefBroken on that payload.
        let scep = payload(
            "com.apple.security.scep",
            "com.fleet.okta.scep",
            "E42B2DBC-DB2A-4DD8-A413-41E432842F2B",
            &[],
        );
        let identity = payload(
            "com.apple.security.identity",
            "com.fleet.okta.identity-pref",
            "11111111-2222-3333-4444-555555555555",
            &[(
                "PayloadCertificateUUID",
                plist::Value::String("478f8ebd-ded5-5808-962d-36da7aa06afe".into()),
            )],
        );
        let proposed = profile_with(vec![scep, identity]);

        let changes = check_proposed_refs(&proposed, &PathBuf::from("test.mobileconfig"));
        assert!(!changes.is_empty(), "expected at least one RefBroken");
        assert!(
            changes.iter().any(|c| c.tier == ChangeTier::RefBroken
                && c.fields_changed == vec!["PayloadCertificateUUID"]),
            "expected RefBroken on PayloadCertificateUUID, got {:?}",
            changes
        );
    }

    #[test]
    fn well_formed_profile_emits_no_ref_broken() {
        // SCEP and identity-preference UUIDs match → no break.
        let scep = payload("com.apple.security.scep", "com.fleet.okta.scep", "AAA", &[]);
        let identity = payload(
            "com.apple.security.identity",
            "com.fleet.okta.identity-pref",
            "BBB",
            &[("PayloadCertificateUUID", plist::Value::String("AAA".into()))],
        );
        let proposed = profile_with(vec![scep, identity]);
        let changes = check_proposed_refs(&proposed, &PathBuf::from("test.mobileconfig"));
        assert!(changes.is_empty(), "got unexpected changes: {:?}", changes);
    }
}
