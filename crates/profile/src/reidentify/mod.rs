//! Make a profile's PayloadIdentifiers consistent with its UUIDs.
//!
//! `uuid` scheme: identifier becomes `{org}.{PayloadUUID}` (keep UUIDs, no ref
//! remap). `name` scheme: identifier is derived from the display name, UUIDs are
//! regenerated deterministically, and cross-references are remapped.

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;

use crate::link::types::UuidMapping;
use crate::uuid::{UuidConfig, regenerate_uuid};

use crate::profile::ConfigurationProfile;

/// Identifier-generation scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scheme {
    /// `{org}.{PayloadUUID}` — keep UUIDs, just sync the identifier.
    Uuid,
    /// `{org}.profile.{slug}` from the display name; regenerate UUIDs + remap refs.
    Name,
    /// Rewrite an identifier prefix across the envelope and every payload.
    ///
    /// UUIDs are preserved by default: MDM keys installed payloads by UUID, so
    /// keeping them makes this an *update* rather than a remove-and-reinstall
    /// on every enrolled device. `regenerate_uuid` opts into new (deterministic
    /// v5) UUIDs, in which case cross-references are remapped to match.
    Pattern {
        from: String,
        to: String,
        regenerate_uuid: bool,
    },
}

/// Configuration for [`reidentify_profile`].
#[derive(Debug)]
pub struct ReidentifyConfig {
    pub org_domain: String,
    pub scheme: Scheme,
}

/// An old → new value pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub old: String,
    pub new: String,
}

/// Identifier + UUID change for one payload (or the envelope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdChange {
    pub identifier: Change,
    pub uuid: Change,
}

/// A reference whose target UUID is not a payload in this profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrphanRef {
    pub source_payload_uuid: String,
    pub field: String,
    pub uuid: String,
}

/// Result of reidentifying one profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReidentifyReport {
    pub slug: String,
    pub envelope: IdChange,
    pub payloads: Vec<IdChange>,
    pub refs_remapped: usize,
    pub orphan_refs: Vec<OrphanRef>,
    pub changed: bool,
}

/// Slugify a display name: lowercase, runs of non-alphanumerics become a single
/// `-`, trimmed. Parens/colons/spaces all act as separators, keeping the detail
/// inside parentheses.
pub fn slugify(name: &str) -> String {
    let mut slug = String::new();
    let mut prev_dash = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            slug.push('-');
            prev_dash = true;
        }
    }
    slug.trim_matches('-').to_string()
}

/// Reidentify a profile in place.
pub fn reidentify_profile(
    profile: &mut ConfigurationProfile,
    config: &ReidentifyConfig,
) -> Result<ReidentifyReport> {
    match &config.scheme {
        Scheme::Uuid => Ok(reidentify_uuid(profile, &config.org_domain)),
        Scheme::Name => reidentify_name(profile, &config.org_domain),
        Scheme::Pattern {
            from,
            to,
            regenerate_uuid,
        } => reidentify_pattern(profile, from, to, *regenerate_uuid),
    }
}

/// Rewrite `from` → `to` at the start of an identifier, matching only on a dot
/// boundary so `com.acmecorp` is never caught by a `com.acme` prefix.
fn rewrite_prefix(identifier: &str, from: &str, to: &str) -> Option<String> {
    let rest = identifier.strip_prefix(from)?;
    (rest.is_empty() || rest.starts_with('.')).then(|| format!("{to}{rest}"))
}

/// `pattern` scheme: prefix-rewrite the envelope and every payload identifier.
///
/// Keeps UUIDs unless `regenerate_uuid`, in which case each changed identifier
/// gets a deterministic v5 UUID and every cross-reference is remapped so
/// linked payloads (Wi-Fi → certificate) stay intact.
fn reidentify_pattern(
    profile: &mut ConfigurationProfile,
    from: &str,
    to: &str,
    regenerate_uuid_flag: bool,
) -> Result<ReidentifyReport> {
    let env_old_id = profile.payload_identifier.clone();
    let env_old_uuid = profile.payload_uuid.clone();
    let env_new_id = rewrite_prefix(&env_old_id, from, to).unwrap_or_else(|| env_old_id.clone());

    // The v5 namespace comes from the new prefix — the operator's org.
    let uuid_cfg = UuidConfig {
        org_domain: Some(to.to_string()),
        predictable: true,
    };
    let mut mapping = UuidMapping::new();

    let env_new_uuid = if regenerate_uuid_flag && env_new_id != env_old_id {
        let new = regenerate_uuid(&env_old_uuid, &uuid_cfg, &env_new_id)?;
        mapping.insert(env_old_uuid.clone(), new.clone());
        new
    } else {
        env_old_uuid.clone()
    };
    profile.payload_identifier = env_new_id.clone();

    let mut payloads = Vec::new();
    for p in &mut profile.payload_content {
        let old_id = p.payload_identifier.clone();
        let old_uuid = p.payload_uuid.clone();
        let new_id = rewrite_prefix(&old_id, from, to).unwrap_or_else(|| old_id.clone());
        let new_uuid = if regenerate_uuid_flag && new_id != old_id && !old_uuid.is_empty() {
            let new = regenerate_uuid(&old_uuid, &uuid_cfg, &new_id)?;
            mapping.insert(old_uuid.clone(), new.clone());
            new
        } else {
            old_uuid.clone()
        };
        p.payload_identifier = new_id.clone();
        payloads.push(IdChange {
            identifier: Change {
                old: old_id,
                new: new_id,
            },
            uuid: Change {
                old: old_uuid,
                new: new_uuid,
            },
        });
    }

    // Only when UUIDs moved: rewrite them and every reference that names them.
    let refs_remapped = if mapping.mapping.is_empty() {
        0
    } else {
        let (refs, _) = crate::link::extractor::extract_references(std::slice::from_ref(&(
            std::path::PathBuf::new(),
            profile.clone(),
        )));
        let remapped = refs
            .iter()
            .filter(|r| mapping.get(&r.referenced_uuid).is_some())
            .count();
        profile.payload_uuid = env_new_uuid.clone();
        for (p, change) in profile.payload_content.iter_mut().zip(&payloads) {
            p.payload_uuid = change.uuid.new.clone();
        }
        crate::link::linker::remap_uuids_in_profile(profile, &mapping)?;
        remapped
    };

    let envelope = IdChange {
        identifier: Change {
            old: env_old_id.clone(),
            new: env_new_id.clone(),
        },
        uuid: Change {
            old: env_old_uuid,
            new: env_new_uuid,
        },
    };
    let changed = envelope.identifier.old != envelope.identifier.new
        || payloads
            .iter()
            .any(|p| p.identifier.old != p.identifier.new);

    Ok(ReidentifyReport {
        slug: String::new(),
        envelope,
        payloads,
        refs_remapped,
        orphan_refs: Vec::new(),
        changed,
    })
}

/// `uuid` scheme: set each identifier to `{org}.{own PayloadUUID}`.
fn reidentify_uuid(profile: &mut ConfigurationProfile, org: &str) -> ReidentifyReport {
    let env_old_id = profile.payload_identifier.clone();
    let env_new_id = format!("{org}.{}", profile.payload_uuid);
    profile.payload_identifier = env_new_id.clone();

    let mut payloads = Vec::new();
    for p in &mut profile.payload_content {
        let old_id = p.payload_identifier.clone();
        // Skip a payload with no UUID — nothing to sync to.
        if !p.payload_uuid.is_empty() {
            p.payload_identifier = format!("{org}.{}", p.payload_uuid);
        }
        payloads.push(IdChange {
            identifier: Change {
                old: old_id,
                new: p.payload_identifier.clone(),
            },
            uuid: Change {
                old: p.payload_uuid.clone(),
                new: p.payload_uuid.clone(),
            },
        });
    }

    let envelope = IdChange {
        identifier: Change {
            old: env_old_id,
            new: env_new_id,
        },
        uuid: Change {
            old: profile.payload_uuid.clone(),
            new: profile.payload_uuid.clone(),
        },
    };
    let changed = envelope.identifier.old != envelope.identifier.new
        || payloads
            .iter()
            .any(|c| c.identifier.old != c.identifier.new);

    ReidentifyReport {
        slug: String::new(),
        envelope,
        payloads,
        refs_remapped: 0,
        orphan_refs: Vec::new(),
        changed,
    }
}

/// `name` scheme: derive identifiers from the display name. (UUID regeneration
/// and reference remap are added in Task 4.)
fn reidentify_name(profile: &mut ConfigurationProfile, org: &str) -> Result<ReidentifyReport> {
    let slug = {
        let s = slugify(&profile.payload_display_name);
        if s.is_empty() {
            // Fall back to the last segment of the existing envelope identifier.
            slugify(profile.payload_identifier.rsplit('.').next().unwrap_or(""))
        } else {
            s
        }
    };

    let env_old_id = profile.payload_identifier.clone();
    let env_new_id = format!("{org}.profile.{slug}");

    // Build payload identifiers with per-type suffix de-duplication.
    let mut counts: HashMap<String, usize> = HashMap::new();
    let new_payload_ids: Vec<String> = profile
        .payload_content
        .iter()
        .map(|p| {
            let suffix = p.payload_type.rsplit('.').next().unwrap_or("payload");
            let n = counts.entry(suffix.to_string()).or_insert(0);
            *n += 1;
            if *n == 1 {
                format!("{org}.{slug}.{suffix}")
            } else {
                format!("{org}.{slug}.{suffix}-{n}")
            }
        })
        .collect();

    // Detect orphan references (UUIDs that point outside this profile) BEFORE
    // remapping, using the link extractor.
    let own_uuids: std::collections::HashSet<String> =
        std::iter::once(profile.payload_uuid.clone())
            .chain(
                profile
                    .payload_content
                    .iter()
                    .map(|p| p.payload_uuid.clone()),
            )
            .collect();
    let (refs, _) = crate::link::extractor::extract_references(std::slice::from_ref(&(
        std::path::PathBuf::new(),
        profile.clone(),
    )));
    let orphan_refs: Vec<OrphanRef> = refs
        .iter()
        .filter(|r| !own_uuids.contains(&r.referenced_uuid))
        .map(|r| OrphanRef {
            source_payload_uuid: r.source_payload_uuid.clone(),
            field: r.field_name.clone(),
            uuid: r.referenced_uuid.clone(),
        })
        .collect();
    let refs_remapped = refs.len() - orphan_refs.len();

    // Apply identifiers, build the UUID mapping (deterministic v5 from identifier).
    let uuid_cfg = UuidConfig {
        org_domain: Some(org.to_string()),
        predictable: true,
    };
    let mut mapping = UuidMapping::new();

    let env_new_uuid = regenerate_uuid(&profile.payload_uuid, &uuid_cfg, &env_new_id)?;
    mapping.insert(profile.payload_uuid.clone(), env_new_uuid.clone());
    let env_old_uuid = profile.payload_uuid.clone();
    profile.payload_identifier = env_new_id.clone();

    let mut payloads = Vec::new();
    for (p, new_id) in profile.payload_content.iter_mut().zip(new_payload_ids) {
        let old_id = p.payload_identifier.clone();
        let old_uuid = p.payload_uuid.clone();
        let new_uuid = regenerate_uuid(&old_uuid, &uuid_cfg, &new_id)?;
        mapping.insert(old_uuid.clone(), new_uuid.clone());
        p.payload_identifier = new_id.clone();
        payloads.push(IdChange {
            identifier: Change {
                old: old_id,
                new: new_id,
            },
            uuid: Change {
                old: old_uuid,
                new: new_uuid,
            },
        });
    }

    // Rewrite UUIDs + references throughout the profile.
    crate::link::linker::remap_uuids_in_profile(profile, &mapping)?;

    let envelope = IdChange {
        identifier: Change {
            old: env_old_id,
            new: env_new_id,
        },
        uuid: Change {
            old: env_old_uuid,
            new: env_new_uuid,
        },
    };

    let changed = envelope.identifier.old != envelope.identifier.new
        || envelope.uuid.old != envelope.uuid.new
        || payloads
            .iter()
            .any(|c| c.identifier.old != c.identifier.new || c.uuid.old != c.uuid.new);

    Ok(ReidentifyReport {
        slug,
        envelope,
        payloads,
        refs_remapped,
        orphan_refs,
        changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::PayloadContent;
    use std::collections::BTreeMap;

    fn payload(ptype: &str, identifier: &str, uuid: &str) -> PayloadContent {
        PayloadContent {
            payload_type: ptype.to_string(),
            payload_version: 1,
            payload_identifier: identifier.to_string(),
            payload_uuid: uuid.to_string(),
            content: BTreeMap::new(),
        }
    }

    fn profile(
        display: &str,
        ident: &str,
        uuid: &str,
        payloads: Vec<PayloadContent>,
    ) -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_display_name: display.to_string(),
            payload_identifier: ident.to_string(),
            payload_uuid: uuid.to_string(),
            payload_content: payloads,
            additional_fields: BTreeMap::new(),
        }
    }

    #[test]
    fn uuid_scheme_syncs_identifier_to_payload_uuid() {
        let mut p = profile(
            "Anything",
            "com.org.1B0BD287-ED66-48B2-9366-36F1BE8FC6A4",
            "6B7D8FE7-9D7D-4ECE-9B2E-A78C36181507",
            vec![payload(
                "com.apple.security.root",
                "com.org.AAAA1111-0000-0000-0000-000000000000",
                "CCCCDDDD-0000-0000-0000-000000000000",
            )],
        );
        let cfg = ReidentifyConfig {
            org_domain: "com.org".into(),
            scheme: Scheme::Uuid,
        };
        let report = reidentify_profile(&mut p, &cfg).unwrap();

        // Identifier now embeds the (unchanged) PayloadUUID.
        assert_eq!(
            p.payload_identifier,
            "com.org.6B7D8FE7-9D7D-4ECE-9B2E-A78C36181507"
        );
        assert_eq!(p.payload_uuid, "6B7D8FE7-9D7D-4ECE-9B2E-A78C36181507"); // unchanged
        assert_eq!(
            p.payload_content[0].payload_identifier,
            "com.org.CCCCDDDD-0000-0000-0000-000000000000"
        );
        assert!(report.changed);
        assert!(report.orphan_refs.is_empty());
        assert_eq!(report.refs_remapped, 0);
    }

    #[test]
    fn uuid_scheme_is_idempotent() {
        let mut p = profile(
            "Anything",
            "com.org.6B7D8FE7-9D7D-4ECE-9B2E-A78C36181507",
            "6B7D8FE7-9D7D-4ECE-9B2E-A78C36181507",
            vec![],
        );
        let cfg = ReidentifyConfig {
            org_domain: "com.org".into(),
            scheme: Scheme::Uuid,
        };
        let report = reidentify_profile(&mut p, &cfg).unwrap();
        assert!(!report.changed);
    }

    #[test]
    fn name_scheme_builds_identifiers_and_dedups() {
        let mut p = profile(
            "System - Certificate (Company Root)",
            "com.org.1B0BD287-ED66-48B2-9366-36F1BE8FC6A4",
            "6B7D8FE7-9D7D-4ECE-9B2E-A78C36181507",
            vec![
                payload(
                    "com.apple.security.root",
                    "old.a",
                    "A0000000-0000-0000-0000-000000000000",
                ),
                payload(
                    "com.apple.security.root",
                    "old.b",
                    "B0000000-0000-0000-0000-000000000000",
                ),
            ],
        );
        let cfg = ReidentifyConfig {
            org_domain: "com.org".into(),
            scheme: Scheme::Name,
        };
        let report = reidentify_profile(&mut p, &cfg).unwrap();

        assert_eq!(report.slug, "system-certificate-company-root");
        assert_eq!(
            p.payload_identifier,
            "com.org.profile.system-certificate-company-root"
        );
        // Same payload type → suffix de-duplicated.
        assert_eq!(
            p.payload_content[0].payload_identifier,
            "com.org.system-certificate-company-root.root"
        );
        assert_eq!(
            p.payload_content[1].payload_identifier,
            "com.org.system-certificate-company-root.root-2"
        );
        // Stray Jamf UUID is gone from the envelope identifier.
        assert!(!p.payload_identifier.contains("1B0BD287"));
    }

    fn payload_with_ref(
        ptype: &str,
        uuid: &str,
        ref_field: &str,
        ref_uuid: &str,
    ) -> PayloadContent {
        let mut content = BTreeMap::new();
        content.insert(
            ref_field.to_string(),
            plist::Value::String(ref_uuid.to_string()),
        );
        PayloadContent {
            payload_type: ptype.to_string(),
            payload_version: 1,
            payload_identifier: format!("{ptype}.test"),
            payload_uuid: uuid.to_string(),
            content,
        }
    }

    #[test]
    fn name_scheme_regenerates_uuids_and_remaps_references() {
        // A Wi-Fi payload references the pkcs12 identity payload by UUID.
        let cert_uuid = "C0000000-0000-0000-0000-000000000000";
        let mut p = profile(
            "Corp Wi-Fi",
            "com.org.envelope",
            "E0000000-0000-0000-0000-000000000000",
            vec![
                payload("com.apple.security.pkcs12", "old.cert", cert_uuid),
                payload_with_ref(
                    "com.apple.wifi.managed",
                    "W0000000-0000-0000-0000-000000000000",
                    "PayloadCertificateUUID",
                    cert_uuid,
                ),
            ],
        );
        let cfg = ReidentifyConfig {
            org_domain: "com.org".into(),
            scheme: Scheme::Name,
        };
        let report = reidentify_profile(&mut p, &cfg).unwrap();

        // Cert payload UUID changed; the Wi-Fi reference now points at the new value.
        let new_cert_uuid = &p.payload_content[0].payload_uuid;
        assert_ne!(new_cert_uuid, cert_uuid);
        let wifi_ref = p.payload_content[1]
            .content
            .get("PayloadCertificateUUID")
            .and_then(plist::Value::as_string)
            .unwrap();
        assert_eq!(wifi_ref, new_cert_uuid);
        assert_eq!(report.refs_remapped, 1);
        assert!(report.orphan_refs.is_empty());
    }

    #[test]
    fn name_scheme_is_idempotent_and_flags_orphan_refs() {
        // Reference to a UUID that is not a payload in this profile = orphan.
        let mut p = profile(
            "Corp Wi-Fi",
            "com.org.envelope",
            "E0000000-0000-0000-0000-000000000000",
            vec![payload_with_ref(
                "com.apple.wifi.managed",
                "W0000000-0000-0000-0000-000000000000",
                "PayloadCertificateUUID",
                "EXTERNAL0-0000-0000-0000-000000000000",
            )],
        );
        let cfg = ReidentifyConfig {
            org_domain: "com.org".into(),
            scheme: Scheme::Name,
        };
        let report = reidentify_profile(&mut p, &cfg).unwrap();
        assert_eq!(report.orphan_refs.len(), 1);
        assert_eq!(report.orphan_refs[0].field, "PayloadCertificateUUID");

        // Second run on the now-clean profile changes nothing.
        let report2 = reidentify_profile(&mut p.clone(), &cfg).unwrap();
        let mut twice = p.clone();
        reidentify_profile(&mut twice, &cfg).unwrap();
        assert_eq!(twice.payload_identifier, p.payload_identifier);
        assert_eq!(
            twice.payload_content[0].payload_uuid,
            p.payload_content[0].payload_uuid
        );
        let _ = report2;
    }

    #[test]
    fn slug_keeps_parenthetical_detail() {
        assert_eq!(
            slugify("System - Certificate (Company Root)"),
            "system-certificate-company-root"
        );
        assert_eq!(slugify("OneDrive (Settings)"), "onedrive-settings");
    }

    #[test]
    fn slug_collapses_and_trims_separators() {
        assert_eq!(slugify("  A -- B :: C  "), "a-b-c");
        assert_eq!(slugify("Wi-Fi"), "wi-fi");
    }

    #[test]
    fn slug_of_empty_or_symbolic_is_empty() {
        assert_eq!(slugify(""), "");
        assert_eq!(slugify(" - () : "), "");
    }

    // ── Pattern scheme (batch identifier rewriting) ──────────────────────

    fn linked_profile() -> ConfigurationProfile {
        let cert = PayloadContent {
            payload_type: "com.apple.security.root".into(),
            payload_version: 1,
            payload_identifier: "com.fleetdm.wifi.ca".into(),
            payload_uuid: "CERT-UUID".into(),
            content: BTreeMap::new(),
        };
        let mut wifi_content = BTreeMap::new();
        wifi_content.insert(
            "PayloadCertificateAnchorUUID".to_string(),
            plist::Value::Array(vec![plist::Value::String("CERT-UUID".into())]),
        );
        let wifi = PayloadContent {
            payload_type: "com.apple.wifi.managed".into(),
            payload_version: 1,
            payload_identifier: "com.fleetdm.wifi.network".into(),
            payload_uuid: "WIFI-UUID".into(),
            content: wifi_content,
        };
        ConfigurationProfile {
            payload_type: "Configuration".into(),
            payload_version: 1,
            payload_identifier: "com.fleetdm.wifi".into(),
            payload_uuid: "ENV-UUID".into(),
            payload_display_name: "Corp WiFi".into(),
            payload_content: vec![cert, wifi],
            additional_fields: std::collections::BTreeMap::new(),
        }
    }

    /// Prefix rewrite renames the envelope and every payload, and — by
    /// default — leaves UUIDs alone, so MDM sees an update rather than a
    /// remove-and-reinstall.
    #[test]
    fn pattern_rewrites_identifiers_and_keeps_uuids_by_default() {
        let mut profile = linked_profile();
        let report = reidentify_profile(
            &mut profile,
            &ReidentifyConfig {
                org_domain: String::new(),
                scheme: Scheme::Pattern {
                    from: "com.fleetdm".into(),
                    to: "com.acme.config".into(),
                    regenerate_uuid: false,
                },
            },
        )
        .unwrap();

        assert_eq!(profile.payload_identifier, "com.acme.config.wifi");
        assert_eq!(
            profile.payload_content[0].payload_identifier,
            "com.acme.config.wifi.ca"
        );
        assert_eq!(
            profile.payload_content[1].payload_identifier,
            "com.acme.config.wifi.network"
        );

        // UUIDs untouched — the whole point of the default.
        assert_eq!(profile.payload_uuid, "ENV-UUID");
        assert_eq!(profile.payload_content[0].payload_uuid, "CERT-UUID");
        assert!(report.changed);
        assert!(
            report.envelope.uuid.old == report.envelope.uuid.new,
            "report must show the UUID as unchanged"
        );
    }

    /// With --regenerate-uuid the UUIDs change AND the cross-reference to the
    /// certificate must follow, or the Wi-Fi payload dangles.
    #[test]
    fn pattern_with_regenerate_uuid_remaps_cross_references() {
        let mut profile = linked_profile();
        reidentify_profile(
            &mut profile,
            &ReidentifyConfig {
                org_domain: String::new(),
                scheme: Scheme::Pattern {
                    from: "com.fleetdm".into(),
                    to: "com.acme.config".into(),
                    regenerate_uuid: true,
                },
            },
        )
        .unwrap();

        let new_cert_uuid = profile.payload_content[0].payload_uuid.clone();
        assert_ne!(new_cert_uuid, "CERT-UUID", "UUID regenerated");

        let anchor = profile.payload_content[1]
            .content
            .get("PayloadCertificateAnchorUUID")
            .and_then(plist::Value::as_array)
            .and_then(|a| a.first())
            .and_then(plist::Value::as_string)
            .unwrap();
        assert_eq!(
            anchor, new_cert_uuid,
            "the reference must follow the regenerated UUID"
        );
    }

    /// A prefix that matches nothing leaves the profile untouched and says so.
    #[test]
    fn pattern_reports_no_change_when_prefix_does_not_match() {
        let mut profile = linked_profile();
        let report = reidentify_profile(
            &mut profile,
            &ReidentifyConfig {
                org_domain: String::new(),
                scheme: Scheme::Pattern {
                    from: "com.other".into(),
                    to: "com.acme".into(),
                    regenerate_uuid: false,
                },
            },
        )
        .unwrap();
        assert!(!report.changed, "nothing matched");
        assert_eq!(profile.payload_identifier, "com.fleetdm.wifi");
    }

    /// Dot-boundary safety, same rule as the DDM side.
    #[test]
    fn pattern_respects_dot_boundaries() {
        let mut profile = linked_profile();
        profile.payload_identifier = "com.fleetdmother.wifi".into();
        let report = reidentify_profile(
            &mut profile,
            &ReidentifyConfig {
                org_domain: String::new(),
                scheme: Scheme::Pattern {
                    from: "com.fleetdm".into(),
                    to: "com.acme".into(),
                    regenerate_uuid: false,
                },
            },
        )
        .unwrap();
        assert_eq!(
            profile.payload_identifier, "com.fleetdmother.wifi",
            "com.fleetdmother must not match com.fleetdm"
        );
        // payloads still match, so the profile did change overall
        assert!(report.changed);
    }
}
