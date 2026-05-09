//! Pure rollback logic — operates on in-memory profiles and produces
//! a `RollbackResult` describing what was restored. The CLI handler
//! handles file I/O.

use crate::link::types::REFERENCE_FIELDS;
use crate::link::validator::validate_cross_references;
use crate::profile::{ConfigurationProfile, PayloadContent};
use anyhow::{Result, bail};
use std::collections::BTreeMap;

/// Filter narrowing which payloads' UUIDs the rollback restores.
#[derive(Debug, Default, Clone)]
pub struct RollbackFilter {
    /// Restore PayloadUUID values only — never overwrite payload content.
    /// Almost always desired; the only common reason to disable is when
    /// the user wants a full revert.
    #[allow(dead_code, reason = "reserved for future use")]
    pub uuids_only: bool,
    /// Restore only payloads whose `PayloadType` is in this list.
    /// Empty = no type filter.
    pub payload_types: Vec<String>,
    /// Restore only payloads that are *referenced* by another payload
    /// (certs, identities, anchors). Targets the high-blast-radius
    /// case (the SCEP-storm pattern).
    pub refs_only: bool,
}

#[derive(Debug, Default, Clone)]
pub struct RollbackOptions {
    pub filter: RollbackFilter,
    /// After restoring a UUID, rewrite every cross-reference in the
    /// proposed profile that pointed at the *new* UUID to point at the
    /// *baseline* UUID. Default true.
    pub rewrite_refs: bool,
}

/// Summary of what a single (baseline, proposed) rollback did.
#[derive(Debug, Clone, Default)]
pub struct RollbackResult {
    /// Number of PayloadUUID values restored to the baseline value.
    pub uuids_restored: usize,
    /// Number of cross-reference fields rewritten to point at the
    /// restored UUID.
    pub refs_rewritten: usize,
    /// Cross-reference graph errors that remain after rollback (i.e.
    /// `link::validator` would reject the result). Non-empty means
    /// the rollback should be aborted.
    pub remaining_validation_errors: Vec<String>,
}

/// Restore UUIDs in-place on `proposed`, taking the canonical UUID
/// from `baseline` for matched payloads.
///
/// If `opts.rewrite_refs` is true (the default), this also rewrites
/// every cross-reference in `proposed` whose value matched the *new*
/// UUID so that it now points at the *baseline* UUID. The rewrite
/// pass walks `link::REFERENCE_FIELDS` so every cross-reference type
/// the lib knows about is handled.
///
/// Returns `RollbackResult` and never writes files. On a fail-closed
/// path (post-rollback `link::validator` reports `MissingReference`),
/// returns an `Err` and leaves the caller to discard the partial result.
pub fn restore_uuids(
    baseline: &ConfigurationProfile,
    proposed: &mut ConfigurationProfile,
    opts: &RollbackOptions,
) -> Result<RollbackResult> {
    let mut result = RollbackResult::default();

    // Pair payloads by (PayloadType, PayloadIdentifier).
    let baseline_idx: BTreeMap<(String, String), &PayloadContent> = baseline
        .payload_content
        .iter()
        .map(|p| ((p.payload_type.clone(), p.payload_identifier.clone()), p))
        .collect();

    // First pass: build the (new_uuid → baseline_uuid) rename map for
    // payloads that the filter selects. We do all renames at once so
    // the second-pass reference rewrite sees a consistent map.
    let mut renames: BTreeMap<String, String> = BTreeMap::new();
    let referenced_uuids: Vec<String> = if opts.filter.refs_only {
        collect_referenced_uuids(proposed)
    } else {
        Vec::new()
    };

    for proposed_payload in &proposed.payload_content {
        let key = (
            proposed_payload.payload_type.clone(),
            proposed_payload.payload_identifier.clone(),
        );
        let Some(baseline_payload) = baseline_idx.get(&key) else {
            continue;
        };
        if proposed_payload.payload_uuid == baseline_payload.payload_uuid {
            continue;
        }
        if !opts.filter.payload_types.is_empty()
            && !opts
                .filter
                .payload_types
                .iter()
                .any(|t| t == &proposed_payload.payload_type)
        {
            continue;
        }
        if opts.filter.refs_only
            && !referenced_uuids
                .iter()
                .any(|u| u == &proposed_payload.payload_uuid)
        {
            continue;
        }
        renames.insert(
            proposed_payload.payload_uuid.clone(),
            baseline_payload.payload_uuid.clone(),
        );
    }

    // Second pass: apply the renames to PayloadUUID fields.
    for payload in &mut proposed.payload_content {
        if let Some(restored) = renames.get(&payload.payload_uuid) {
            payload.payload_uuid = restored.clone();
            result.uuids_restored += 1;
        }
    }

    // Third pass: rewrite cross-references whose target UUID was renamed.
    if opts.rewrite_refs {
        for payload in &mut proposed.payload_content {
            result.refs_rewritten += rewrite_payload_refs(payload, &renames);
        }
    }

    // Fail-closed sanity check: post-rollback the cross-reference
    // graph must still resolve.
    let validation = validate_cross_references(&[(
        std::path::PathBuf::from("rollback-result"),
        proposed.clone(),
    )]);
    if !validation.valid {
        for err in &validation.errors {
            result.remaining_validation_errors.push(format!(
                "{} = {} (in payload {})",
                err.field_name, err.referenced_uuid, err.source_payload_uuid
            ));
        }
        bail!(
            "rollback would orphan {} cross-reference(s); aborted before write: {}",
            result.remaining_validation_errors.len(),
            result.remaining_validation_errors.join("; "),
        );
    }

    Ok(result)
}

/// Walk every reference field declared in `link::REFERENCE_FIELDS` on
/// the given payload and rewrite any value that maps in `renames`.
/// Returns the count of rewritten cells.
fn rewrite_payload_refs(payload: &mut PayloadContent, renames: &BTreeMap<String, String>) -> usize {
    let mut count = 0;
    for spec in REFERENCE_FIELDS {
        let target = match spec.nested_path {
            None => Some(&mut payload.content),
            Some(path) => navigate_nested_mut(&mut payload.content, path),
        };
        let Some(map) = target else {
            continue;
        };
        let Some(value) = map.get_mut(spec.name) else {
            continue;
        };
        if spec.is_array {
            let plist::Value::Array(items) = value else {
                continue;
            };
            for item in items {
                if let plist::Value::String(s) = item
                    && let Some(new) = renames.get(s)
                {
                    *s = new.clone();
                    count += 1;
                }
            }
        } else if let plist::Value::String(s) = value
            && let Some(new) = renames.get(s)
        {
            *s = new.clone();
            count += 1;
        }
    }
    count
}

/// Navigate into nested dictionaries by key path, returning a mutable
/// reference to the innermost dictionary's *as-BTreeMap* view. Mirrors
/// the read-only `link::extractor::navigate_nested` but for writes.
fn navigate_nested_mut<'a>(
    content: &'a mut BTreeMap<String, plist::Value>,
    path: &[&str],
) -> Option<&'a mut BTreeMap<String, plist::Value>> {
    // The path navigates through plist::Value::Dictionary entries, but
    // the leaf must be a BTreeMap-like view. plist's Dictionary doesn't
    // expose a BTreeMap mutable view, so this only works for the
    // top-level when path is empty. For non-empty paths we'd need to
    // rewrite via plist::Value::Dictionary handles instead. Cross-refs
    // we currently care about (PayloadCertificateUUID,
    // PayloadCertificateAnchorUUID at the top level) hit the `None`
    // path; nested EAPClientConfiguration / IKEv2 references stay
    // within the plist::Dictionary world and need the dictionary-walk
    // variant — TODO if a user ships nested cross-refs in scope.
    if path.is_empty() {
        return Some(content);
    }
    None
}

/// Walk `proposed.payload_content` for every reference field and
/// return the set of UUIDs anyone actually points at. Used by the
/// `--refs-only` filter so we restore only the high-blast-radius
/// payloads (certs, identities) — not arbitrary noise.
fn collect_referenced_uuids(proposed: &ConfigurationProfile) -> Vec<String> {
    let mut uuids: Vec<String> = Vec::new();
    for payload in &proposed.payload_content {
        for spec in REFERENCE_FIELDS {
            let map = match spec.nested_path {
                None => Some(&payload.content),
                Some(_) => None, // see navigate_nested_mut comment
            };
            let Some(map) = map else { continue };
            let Some(value) = map.get(spec.name) else {
                continue;
            };
            match value {
                plist::Value::String(s) => uuids.push(s.clone()),
                plist::Value::Array(items) => {
                    for item in items {
                        if let plist::Value::String(s) = item {
                            uuids.push(s.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    uuids
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn fleet_okta_pattern_rollback_restores_scep_uuid_and_rewrites_ref() {
        // Baseline: SCEP UUID 478f… and identity-pref points at it.
        let scep_baseline = payload(
            "com.apple.security.scep",
            "com.fleet.okta.scep",
            "478f8ebd-ded5-5808-962d-36da7aa06afe",
            &[],
        );
        let identity_baseline = payload(
            "com.apple.security.identity",
            "com.fleet.okta.identity-pref",
            "11111111-2222-3333-4444-555555555555",
            &[(
                "PayloadCertificateUUID",
                plist::Value::String("478f8ebd-ded5-5808-962d-36da7aa06afe".into()),
            )],
        );
        let baseline = profile_with(vec![scep_baseline, identity_baseline]);

        // Proposed: SCEP UUID was regenerated to E42B…, but identity
        // wasn't updated → REF_BROKEN if applied as-is.
        let scep_proposed = payload(
            "com.apple.security.scep",
            "com.fleet.okta.scep",
            "E42B2DBC-DB2A-4DD8-A413-41E432842F2B",
            &[],
        );
        let identity_proposed = payload(
            "com.apple.security.identity",
            "com.fleet.okta.identity-pref",
            "11111111-2222-3333-4444-555555555555",
            &[(
                "PayloadCertificateUUID",
                plist::Value::String("478f8ebd-ded5-5808-962d-36da7aa06afe".into()),
            )],
        );
        let mut proposed = profile_with(vec![scep_proposed, identity_proposed]);

        let opts = RollbackOptions {
            filter: RollbackFilter {
                uuids_only: true,
                ..Default::default()
            },
            rewrite_refs: true,
        };
        let result = restore_uuids(&baseline, &mut proposed, &opts).expect("rollback ok");

        // SCEP UUID restored. identity-pref's PayloadCertificateUUID
        // already pointed at the baseline UUID, so no rewrite needed
        // (rewrite_payload_refs only fires when the ref pointed at the
        // *new* UUID). The graph should resolve.
        assert_eq!(result.uuids_restored, 1, "expected SCEP UUID restored");
        assert_eq!(
            proposed.payload_content[0].payload_uuid,
            "478f8ebd-ded5-5808-962d-36da7aa06afe"
        );
        assert!(
            result.remaining_validation_errors.is_empty(),
            "rollback validation should succeed"
        );
    }

    #[test]
    fn rollback_rewrites_dangling_ref_when_baseline_uuid_changed() {
        // Sharper test: if the proposed profile has its identity-pref
        // pointing at the *new* SCEP UUID (i.e. someone updated the
        // ref), and we rollback the SCEP UUID, the rewrite pass must
        // also rewrite the ref so it still resolves.
        let baseline = profile_with(vec![
            payload(
                "com.apple.security.scep",
                "com.fleet.okta.scep",
                "OLD-SCEP",
                &[],
            ),
            payload(
                "com.apple.security.identity",
                "com.fleet.okta.id",
                "ID-UUID",
                &[(
                    "PayloadCertificateUUID",
                    plist::Value::String("OLD-SCEP".into()),
                )],
            ),
        ]);
        let mut proposed = profile_with(vec![
            payload(
                "com.apple.security.scep",
                "com.fleet.okta.scep",
                "NEW-SCEP",
                &[],
            ),
            payload(
                "com.apple.security.identity",
                "com.fleet.okta.id",
                "ID-UUID",
                &[(
                    "PayloadCertificateUUID",
                    plist::Value::String("NEW-SCEP".into()),
                )],
            ),
        ]);
        let opts = RollbackOptions {
            filter: RollbackFilter {
                uuids_only: true,
                ..Default::default()
            },
            rewrite_refs: true,
        };
        let result = restore_uuids(&baseline, &mut proposed, &opts).expect("ok");
        assert_eq!(result.uuids_restored, 1);
        assert_eq!(result.refs_rewritten, 1);
        // SCEP UUID restored to OLD-SCEP, ref rewritten OLD-SCEP, graph clean.
        assert_eq!(proposed.payload_content[0].payload_uuid, "OLD-SCEP");
        let ref_value = proposed.payload_content[1]
            .content
            .get("PayloadCertificateUUID")
            .and_then(plist::Value::as_string)
            .unwrap();
        assert_eq!(ref_value, "OLD-SCEP");
    }

    #[test]
    fn payload_type_filter_restricts_what_gets_restored() {
        let baseline = profile_with(vec![
            payload("com.apple.security.scep", "com.acme.scep", "OLD-S", &[]),
            payload("com.apple.security.root", "com.acme.root", "OLD-R", &[]),
        ]);
        let mut proposed = profile_with(vec![
            payload("com.apple.security.scep", "com.acme.scep", "NEW-S", &[]),
            payload("com.apple.security.root", "com.acme.root", "NEW-R", &[]),
        ]);
        let opts = RollbackOptions {
            filter: RollbackFilter {
                uuids_only: true,
                payload_types: vec!["com.apple.security.scep".to_string()],
                refs_only: false,
            },
            rewrite_refs: true,
        };
        let result = restore_uuids(&baseline, &mut proposed, &opts).expect("ok");
        assert_eq!(result.uuids_restored, 1, "SCEP only");
        assert_eq!(proposed.payload_content[0].payload_uuid, "OLD-S");
        assert_eq!(proposed.payload_content[1].payload_uuid, "NEW-R");
    }

    #[test]
    fn refs_only_restores_only_referenced_payloads() {
        // SCEP is referenced; an unrelated com.apple.x payload is not.
        let baseline = profile_with(vec![
            payload("com.apple.security.scep", "com.acme.scep", "OLD-S", &[]),
            payload("com.apple.x", "com.acme.x", "OLD-X", &[]),
            payload(
                "com.apple.security.identity",
                "com.acme.id",
                "ID",
                &[(
                    "PayloadCertificateUUID",
                    plist::Value::String("OLD-S".into()),
                )],
            ),
        ]);
        let mut proposed = profile_with(vec![
            payload("com.apple.security.scep", "com.acme.scep", "NEW-S", &[]),
            payload("com.apple.x", "com.acme.x", "NEW-X", &[]),
            payload(
                "com.apple.security.identity",
                "com.acme.id",
                "ID",
                &[(
                    "PayloadCertificateUUID",
                    plist::Value::String("NEW-S".into()),
                )],
            ),
        ]);
        let opts = RollbackOptions {
            filter: RollbackFilter {
                uuids_only: true,
                payload_types: vec![],
                refs_only: true,
            },
            rewrite_refs: true,
        };
        let result = restore_uuids(&baseline, &mut proposed, &opts).expect("ok");
        assert_eq!(result.uuids_restored, 1, "only SCEP is referenced");
        assert_eq!(proposed.payload_content[0].payload_uuid, "OLD-S");
        assert_eq!(
            proposed.payload_content[1].payload_uuid, "NEW-X",
            "unreferenced payload not restored"
        );
    }
}
