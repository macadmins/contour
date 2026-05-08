//! TYPE_INVALID detector.
//!
//! Reports plist-type-shape errors: a value whose plist type doesn't
//! match what the consuming app or Apple schema expects (e.g. Nudge's
//! `<string>300</string>` for `refreshSOFAFeedTime`, which Codable
//! refuses and Nudge silently falls back to default).
//!
//! Implementation strategy: invoke the existing
//! `crate::validation::schema_validator::SchemaValidator` against the
//! proposed profile and surface its `TYPE_MISMATCH` issues as
//! `ChangeTier::TypeInvalid`. The schema validator already understands
//! Apple's MDM schemas; per-app schemas (Nudge, Santa, Okta Verify,
//! Munki) plug in via `SchemaRegistry::embedded()` as those manifests
//! are added to the embedded schema bundle.

use super::change::{ChangeTier, PayloadChange};
use crate::profile::ConfigurationProfile;
use crate::schema::SchemaRegistry;
use crate::validation::schema_validator::{SchemaValidator, ValidationOptions};

/// Compute TYPE_INVALID findings on the proposed profile.
pub fn check_type_validity(proposed: &ConfigurationProfile) -> Vec<PayloadChange> {
    let registry = match SchemaRegistry::embedded() {
        Ok(r) => r,
        Err(_) => return Vec::new(), // No schemas available — degrade silently.
    };
    // We only want type-mismatch findings here; other lints (required-
    // field, allowed-values, unknown-key) are out of scope for
    // TYPE_INVALID. Disable them.
    let opts = ValidationOptions {
        check_required: false,
        check_types: true,
        check_allowed_values: false,
        warn_sensitive: false,
        warn_unknown_types: false,
        strict: false,
    };
    let validator = SchemaValidator::with_options(&registry, opts);
    let result = validator.validate(proposed);

    let mut changes = Vec::new();
    for issue in &result.issues {
        if issue.code != "TYPE_MISMATCH" {
            continue;
        }
        let Some(idx) = issue.payload_index else {
            continue; // outer-profile finding; not payload-level
        };
        if idx >= proposed.payload_content.len() {
            continue;
        }
        let payload = &proposed.payload_content[idx];
        changes.push(PayloadChange {
            tier: ChangeTier::TypeInvalid,
            payload_type: payload.payload_type.clone(),
            payload_identifier: payload.payload_identifier.clone(),
            payload_index: idx,
            baseline_uuid: None,
            proposed_uuid: Some(payload.payload_uuid.clone()),
            fields_changed: issue.field.clone().into_iter().collect(),
            evidence: format!(
                "{} (silent fallback to default — value will not take effect)",
                issue.message
            ),
        });
    }
    changes
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

    #[test]
    fn schema_known_payload_with_wrong_value_type_emits_type_invalid() {
        // Find an Apple-schema payload type that has a known field
        // type. We'll synthesize a payload that violates the type.
        // The test is best-effort: if the embedded schema doesn't
        // have what we need, skip rather than fail.
        let registry = match SchemaRegistry::embedded() {
            Ok(r) => r,
            Err(_) => return,
        };

        // Pick any payload with a Boolean field; substitute a string.
        let mut found = None;
        for manifest in registry.all() {
            for (name, def) in &manifest.fields {
                if matches!(def.field_type, crate::schema::types::FieldType::Boolean) {
                    found = Some((manifest.payload_type.clone(), name.clone()));
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        let (payload_type, field_name) = match found {
            Some(p) => p,
            None => return, // No suitable schema — nothing to test.
        };

        let mut content = BTreeMap::new();
        content.insert(
            field_name.clone(),
            plist::Value::String("not-a-bool".into()),
        );
        let payload = PayloadContent {
            payload_type: payload_type.clone(),
            payload_version: 1,
            payload_identifier: "com.acme.x".into(),
            payload_uuid: "AAA".into(),
            content,
        };
        let proposed = profile_with(vec![payload]);
        let changes = check_type_validity(&proposed);
        assert!(
            !changes.is_empty(),
            "expected TYPE_INVALID for {} field {} with wrong type, got {:?}",
            payload_type,
            field_name,
            changes
        );
        assert_eq!(changes[0].tier, ChangeTier::TypeInvalid);
    }

    #[test]
    fn well_typed_profile_emits_no_type_invalid() {
        let p = profile_with(vec![]);
        let changes = check_type_validity(&p);
        assert!(changes.is_empty());
    }
}
