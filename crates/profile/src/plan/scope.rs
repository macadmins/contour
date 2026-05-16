//! SCOPE_BROADENED detector.
//!
//! Catches changes that *widen* the access surface a profile grants:
//!
//! 1. **TCC ACL rule shape**. `BundleIdentifier` (exact) →
//!    `BundleIdentifierPrefix` (prefix match). `Path` (exact) →
//!    `PathPrefix`. The CodeRabbit-flagged Okta case is the canonical
//!    example: `BundleIdentifier=com.okta.mobile` →
//!    `BundleIdentifierPrefix=com.okta.` lets every Okta-signed bundle
//!    match the rule.
//! 2. **PayloadScope**. `User` → `System` widens the install scope
//!    from per-user to machine-wide.
//!
//! This module compares one (baseline_payload, proposed_payload) pair
//! at a time. The classifier calls into it for every payload pair where
//! `(PayloadType, PayloadIdentifier)` matches on both sides.

use super::change::{ChangeTier, PayloadChange};
use crate::profile::{ConfigurationProfile, PayloadContent};
use plist::Value;
use std::collections::BTreeMap;

/// Compute SCOPE_BROADENED findings for one (baseline, proposed) pair.
pub fn check_scope_broadening(
    baseline: &ConfigurationProfile,
    proposed: &ConfigurationProfile,
) -> Vec<PayloadChange> {
    let baseline_idx = index_payloads(&baseline.payload_content);

    let mut changes = Vec::new();
    for (proposed_idx, p_payload) in proposed.payload_content.iter().enumerate() {
        let key = (
            p_payload.payload_type.clone(),
            p_payload.payload_identifier.clone(),
        );
        let Some(b_idx) = baseline_idx.get(&key) else {
            continue; // ADD: handled by classifier; nothing to compare here
        };
        let b_payload = &baseline.payload_content[*b_idx];

        // Outer-payload PayloadScope widening
        if let Some(evidence) = scope_field_widened(b_payload, p_payload) {
            changes.push(PayloadChange {
                tier: ChangeTier::ScopeBroadened,
                payload_type: p_payload.payload_type.clone(),
                payload_identifier: p_payload.payload_identifier.clone(),
                payload_index: proposed_idx,
                baseline_uuid: Some(b_payload.payload_uuid.clone()),
                proposed_uuid: Some(p_payload.payload_uuid.clone()),
                fields_changed: vec!["PayloadScope".to_string()],
                evidence,
            });
        }

        // TCC ACL widening (for com.apple.TCC.configuration-profile-policy)
        if p_payload.payload_type == "com.apple.TCC.configuration-profile-policy" {
            for change in compare_tcc_acl(b_payload, p_payload, proposed_idx) {
                changes.push(change);
            }
        }
    }
    changes
}

fn index_payloads(payloads: &[PayloadContent]) -> BTreeMap<(String, String), usize> {
    payloads
        .iter()
        .enumerate()
        .map(|(i, p)| ((p.payload_type.clone(), p.payload_identifier.clone()), i))
        .collect()
}

/// Detect `PayloadScope` widening: `User` → `System`.
fn scope_field_widened(b: &PayloadContent, p: &PayloadContent) -> Option<String> {
    let b_scope = b.content.get("PayloadScope").and_then(Value::as_string);
    let p_scope = p.content.get("PayloadScope").and_then(Value::as_string);
    match (b_scope, p_scope) {
        (Some("User"), Some("System")) => Some(
            "PayloadScope widened from User to System — payload now \
             installs machine-wide instead of per-user."
                .to_string(),
        ),
        // Adding PayloadScope=System where there was none before may
        // also be a widening, but the default scope is implementation-
        // defined per Apple. Don't flag without a known baseline.
        _ => None,
    }
}

/// Compare TCC ACL rules across baseline and proposed and emit one
/// SCOPE_BROADENED finding per widened rule.
///
/// TCC profile structure:
/// ```text
/// PayloadContent:
///   Services:
///     <ServiceName>:                # e.g. SystemPolicyAllFiles
///       - { Identifier, IdentifierType, CodeRequirement, Allowed, ... }
///       - { Identifier, IdentifierType, ... }
/// ```
/// `IdentifierType` controls the matching mode: `bundleID` or
/// `bundleIDPrefix`, `path` or `pathPrefix`.
fn compare_tcc_acl(
    baseline: &PayloadContent,
    proposed: &PayloadContent,
    payload_idx: usize,
) -> Vec<PayloadChange> {
    let mut findings = Vec::new();
    let Some(Value::Dictionary(b_services)) = baseline.content.get("Services") else {
        return findings;
    };
    let Some(Value::Dictionary(p_services)) = proposed.content.get("Services") else {
        return findings;
    };

    for (service_name, p_value) in p_services {
        let Some(b_value) = b_services.get(service_name) else {
            continue;
        };
        let (Value::Array(b_rules), Value::Array(p_rules)) = (b_value, p_value) else {
            continue;
        };

        // Pair rules by Identifier: exact + prefix variants of the same
        // Identifier are *the same rule, redefined*. Pair conservatively
        // and only flag the exact->prefix transition.
        let b_rules_by_id = rules_by_identifier(b_rules);
        for p_rule in p_rules {
            let Value::Dictionary(p_dict) = p_rule else {
                continue;
            };
            let Some(p_id) = p_dict.get("Identifier").and_then(Value::as_string) else {
                continue;
            };
            let p_id_type = p_dict.get("IdentifierType").and_then(Value::as_string);

            // Look for a baseline rule with Identifier that this prefix
            // would now also match.
            for b_rule in b_rules_by_id.values().flatten() {
                let Some(b_id) = b_rule.get("Identifier").and_then(Value::as_string) else {
                    continue;
                };
                let b_id_type = b_rule.get("IdentifierType").and_then(Value::as_string);

                if let Some(evidence) =
                    detect_identifier_widening(b_id, b_id_type, p_id, p_id_type, service_name)
                {
                    findings.push(PayloadChange {
                        tier: ChangeTier::ScopeBroadened,
                        payload_type: proposed.payload_type.clone(),
                        payload_identifier: proposed.payload_identifier.clone(),
                        payload_index: payload_idx,
                        baseline_uuid: Some(baseline.payload_uuid.clone()),
                        proposed_uuid: Some(proposed.payload_uuid.clone()),
                        fields_changed: vec![format!("Services.{service_name}.Identifier")],
                        evidence,
                    });
                }
            }
        }
    }
    findings
}

/// Group baseline rules by their Identifier value so the comparator
/// can hop straight to the candidate(s) without an O(n*m) scan.
fn rules_by_identifier(rules: &[Value]) -> BTreeMap<String, Vec<&plist::Dictionary>> {
    let mut by_id: BTreeMap<String, Vec<&plist::Dictionary>> = BTreeMap::new();
    for rule in rules {
        if let Value::Dictionary(d) = rule
            && let Some(id) = d.get("Identifier").and_then(Value::as_string)
        {
            by_id.entry(id.to_string()).or_default().push(d);
        }
    }
    by_id
}

/// Decide whether `(b_id, b_id_type)` → `(p_id, p_id_type)` widens the
/// rule's match surface. Returns the human-readable evidence string if
/// it does, `None` otherwise.
fn detect_identifier_widening(
    b_id: &str,
    b_id_type: Option<&str>,
    p_id: &str,
    p_id_type: Option<&str>,
    service_name: &str,
) -> Option<String> {
    // Exact bundleID → prefix bundleID, where the prefix would still
    // match the exact value, AND the prefix is broader (i.e. would
    // match additional bundle IDs).
    if b_id_type == Some("bundleID")
        && p_id_type == Some("bundleIDPrefix")
        && b_id.starts_with(p_id)
        && b_id != p_id
    {
        return Some(format!(
            "Services.{service}: rule changed from \
             IdentifierType=bundleID Identifier={b:?} to \
             IdentifierType=bundleIDPrefix Identifier={p:?} — \
             access surface broadened to all bundle IDs starting with \
             {p:?}.",
            service = service_name,
            b = b_id,
            p = p_id,
        ));
    }
    // Same shape for path → pathPrefix.
    if b_id_type == Some("path")
        && p_id_type == Some("pathPrefix")
        && b_id.starts_with(p_id)
        && b_id != p_id
    {
        return Some(format!(
            "Services.{service}: rule changed from \
             IdentifierType=path Identifier={b:?} to \
             IdentifierType=pathPrefix Identifier={p:?} — \
             access surface broadened to all paths under {p:?}.",
            service = service_name,
            b = b_id,
            p = p_id,
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload_with_services(services: plist::Dictionary) -> PayloadContent {
        let mut content = BTreeMap::new();
        content.insert("Services".to_string(), Value::Dictionary(services));
        PayloadContent {
            payload_type: "com.apple.TCC.configuration-profile-policy".into(),
            payload_version: 1,
            payload_identifier: "com.fleet.okta-verify".into(),
            payload_uuid: "PLD-UUID".into(),
            content,
        }
    }

    fn profile_of(payloads: Vec<PayloadContent>) -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".into(),
            payload_version: 1,
            payload_identifier: "com.fleet.okta-verify".into(),
            payload_uuid: "PROF-UUID".into(),
            payload_display_name: "Okta TCC".into(),
            payload_content: payloads,
            additional_fields: BTreeMap::new(),
        }
    }

    fn rule(id: &str, id_type: &str) -> Value {
        let mut d = plist::Dictionary::new();
        d.insert("Identifier".to_string(), Value::String(id.to_string()));
        d.insert(
            "IdentifierType".to_string(),
            Value::String(id_type.to_string()),
        );
        Value::Dictionary(d)
    }

    fn services_with_one_rule(service: &str, r: Value) -> plist::Dictionary {
        let mut services = plist::Dictionary::new();
        services.insert(service.to_string(), Value::Array(vec![r]));
        services
    }

    #[test]
    fn okta_bundle_id_to_prefix_is_scope_broadened() {
        // The exact CodeRabbit finding.
        let baseline_payload = payload_with_services(services_with_one_rule(
            "SystemPolicyAllFiles",
            rule("com.okta.mobile", "bundleID"),
        ));
        let proposed_payload = payload_with_services(services_with_one_rule(
            "SystemPolicyAllFiles",
            rule("com.okta.", "bundleIDPrefix"),
        ));
        let baseline = profile_of(vec![baseline_payload]);
        let proposed = profile_of(vec![proposed_payload]);
        let changes = check_scope_broadening(&baseline, &proposed);
        assert!(!changes.is_empty(), "expected SCOPE_BROADENED finding");
        assert_eq!(changes[0].tier, ChangeTier::ScopeBroadened);
        assert!(changes[0].evidence.contains("bundleIDPrefix"));
        assert!(changes[0].evidence.contains("com.okta."));
    }

    #[test]
    fn unchanged_rule_emits_nothing() {
        let same = payload_with_services(services_with_one_rule(
            "SystemPolicyAllFiles",
            rule("com.okta.mobile", "bundleID"),
        ));
        let baseline = profile_of(vec![same.clone()]);
        let proposed = profile_of(vec![same]);
        assert!(check_scope_broadening(&baseline, &proposed).is_empty());
    }

    #[test]
    fn payload_scope_user_to_system_is_broadened() {
        let mut b_content = BTreeMap::new();
        b_content.insert("PayloadScope".to_string(), Value::String("User".into()));
        let mut p_content = BTreeMap::new();
        p_content.insert("PayloadScope".to_string(), Value::String("System".into()));

        let b = PayloadContent {
            payload_type: "com.example.test".into(),
            payload_version: 1,
            payload_identifier: "com.acme.x".into(),
            payload_uuid: "AAA".into(),
            content: b_content,
        };
        let p = PayloadContent {
            payload_type: "com.example.test".into(),
            payload_version: 1,
            payload_identifier: "com.acme.x".into(),
            payload_uuid: "AAA".into(),
            content: p_content,
        };
        let baseline = profile_of(vec![b]);
        let proposed = profile_of(vec![p]);
        let changes = check_scope_broadening(&baseline, &proposed);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].fields_changed, vec!["PayloadScope"]);
        assert!(changes[0].evidence.contains("User"));
        assert!(changes[0].evidence.contains("System"));
    }

    #[test]
    fn prefix_to_exact_is_not_broadening() {
        // exact → prefix widens; prefix → exact narrows. Don't flag.
        let baseline_payload = payload_with_services(services_with_one_rule(
            "SystemPolicyAllFiles",
            rule("com.okta.", "bundleIDPrefix"),
        ));
        let proposed_payload = payload_with_services(services_with_one_rule(
            "SystemPolicyAllFiles",
            rule("com.okta.mobile", "bundleID"),
        ));
        let baseline = profile_of(vec![baseline_payload]);
        let proposed = profile_of(vec![proposed_payload]);
        let changes = check_scope_broadening(&baseline, &proposed);
        assert!(
            changes.is_empty(),
            "narrowing should not be flagged: {:?}",
            changes
        );
    }
}
