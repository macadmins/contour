//! Adapters that turn identifier sources into `app.settings` entries.
//!
//! Every input — a live [`ScannedApp`], or an existing Santa [`Rule`] (the
//! converter) — is normalized to a [`BinaryIdentifier`] + [`BinaryPolicy`], or
//! an [`AppIdentifier`] for the bundle-ID lists. Validation of the result
//! (schema `notes` rules) lives in [`super::validate`].

use crate::cli::ScanRuleType;
use crate::cli::scan::ScannedApp;
use crate::models::{Policy, Rule, RuleType};

use super::model::{AppIdentifier, BinaryIdentifier, BinaryPolicy, ComposedIdentifier};

/// Derive the TeamID embedded in a SigningID (`TEAMID:bundle`).
///
/// Returns `None` for the `platform:` prefix or a malformed value. Pairing the
/// TeamID with a SigningID makes the entry valid for `AllowedBinaries` (which
/// requires CDHash or TeamID) without losing the SigningID's specificity, and
/// is a no-op for `DeniedBinaries` (the TeamID is already implied).
fn team_id_from_signing_id(signing_id: &str) -> Option<String> {
    let (team, _bundle) = signing_id.split_once(':')?;
    crate::cel::is_valid_team_id(team).then(|| team.to_string())
}

/// The `TeamID` an allow entry keyed on this Santa signing ID takes: the
/// team for a third-party `TEAMID:bundle`, and Apple's `*APPLE*` sentinel for
/// a `platform:` binary, whose team identifier is empty.
fn allow_team_for_signing_id(signing_id: &str) -> Option<String> {
    if signing_id.starts_with("platform:") {
        return Some(crate::app_settings::validate::APPLE_TEAM_ID.to_string());
    }
    team_id_from_signing_id(signing_id)
}

/// Apple's `SigningID` field is the **bare** code-signing identifier (the
/// `Identifier=` from `codesign -dvvv`), e.g. `us.zoom.xos`. Santa formats signing
/// IDs as `<TeamID-or-"platform">:<signing-id>`; strip that prefix. A payload whose
/// SigningID still carries the prefix is rejected on-device as malformed (Code -319).
/// The TeamID part is captured separately via [`team_id_from_signing_id`].
fn apple_signing_id(santa_signing_id: &str) -> String {
    santa_signing_id
        .split_once(':')
        .map(|(_, sid)| sid.to_string())
        .unwrap_or_else(|| santa_signing_id.to_string())
}

/// Build a [`BinaryIdentifier`] from a scanned app using the selected match type.
///
/// `Auto` chooses a schema-valid identifier that works for the policy:
///
/// - allow: the vendor's `TeamID` — `*APPLE*` for an Apple platform app — and
///   `CDHash` only when there is no team. Not `TeamID` + `SigningID`: an allow
///   entry is matched against every binary that runs, and an app's helpers,
///   XPC services and updaters carry signing IDs of their own under the same
///   team. A per-app allow list blocks them, and the app with them.
/// - deny: `SigningID` with its team (this app, not its vendor), then
///   `TeamID`, then `CDHash`.
///
/// Empty when the app carries no usable identifier for the chosen mode.
///
/// Usually one entry. A CDHash names a single architecture slice, so when the
/// scan read every slice, a CDHash result becomes one entry per slice that
/// [`cdhash_slices_for`] selects for this policy.
pub fn from_scanned_app(
    app: &ScannedApp,
    rule_type: ScanRuleType,
    policy: BinaryPolicy,
) -> Vec<(BinaryIdentifier, BinaryPolicy)> {
    let valid_cdhash = app
        .cdhash
        .clone()
        .filter(|c| crate::cel::is_valid_cdhash(c));

    let bi = match rule_type {
        ScanRuleType::TeamId => BinaryIdentifier {
            team_id: app.team_id.clone(),
            ..Default::default()
        },
        ScanRuleType::SigningId => BinaryIdentifier {
            team_id: app.signing_id.as_deref().and_then(team_id_from_signing_id),
            signing_id: app.signing_id.as_deref().map(apple_signing_id),
            ..Default::default()
        },
        ScanRuleType::Cdhash => BinaryIdentifier {
            cdhash: valid_cdhash,
            ..Default::default()
        },
        ScanRuleType::Auto => match policy {
            // Vendor-level: see the doc comment for why not per-app.
            BinaryPolicy::Allow => {
                let team = app.team_id.clone().or_else(|| {
                    app.signing_id
                        .as_deref()
                        .and_then(allow_team_for_signing_id)
                });
                BinaryIdentifier {
                    cdhash: team.is_none().then_some(valid_cdhash).flatten(),
                    team_id: team,
                    ..Default::default()
                }
            }
            // Deny may use SigningID; prefer the most specific available.
            BinaryPolicy::Deny => {
                if let Some(signing_id) = &app.signing_id {
                    BinaryIdentifier {
                        team_id: team_id_from_signing_id(signing_id),
                        signing_id: Some(apple_signing_id(signing_id)),
                        ..Default::default()
                    }
                } else if let Some(team_id) = &app.team_id {
                    BinaryIdentifier {
                        team_id: Some(team_id.clone()),
                        ..Default::default()
                    }
                } else {
                    BinaryIdentifier {
                        cdhash: valid_cdhash,
                        ..Default::default()
                    }
                }
            }
        },
    };

    if bi.is_empty() {
        return Vec::new();
    }

    // Only a CDHash result depends on the slice; TeamID and SigningID are
    // identical across every slice of the same binary.
    if bi.cdhash.is_some() && !app.cdhash_slices.is_empty() {
        let per_slice: Vec<_> = cdhash_slices_for(&app.cdhash_slices, policy)
            .into_iter()
            .filter(|s| crate::cel::is_valid_cdhash(&s.cdhash))
            .map(|s| {
                let entry = BinaryIdentifier {
                    cdhash: Some(s.cdhash.clone()),
                    ..bi.clone()
                };
                (entry, policy)
            })
            .collect();
        if !per_slice.is_empty() {
            return per_slice;
        }
    }

    vec![(bi, policy)]
}

/// Convert an existing Santa [`Rule`] into an `app.settings` entry.
///
/// Maps Santa rule/policy semantics to the DDM-native equivalent. Rule types
/// without an `app.settings` matcher (`Binary` = SHA-256, `Certificate`) and
/// non-static policies (`Remove`, `Cel`) are rejected with a reason the caller
/// can report and skip.
pub fn from_santa_rule(rule: &Rule) -> Result<(BinaryIdentifier, BinaryPolicy), String> {
    let policy = match rule.policy {
        Policy::Allowlist | Policy::AllowlistCompiler => BinaryPolicy::Allow,
        Policy::Blocklist | Policy::SilentBlocklist => BinaryPolicy::Deny,
        Policy::Remove => {
            return Err("Remove policy has no app.settings equivalent".to_string());
        }
        Policy::Cel => {
            return Err("CEL rules cannot map to static app.settings identifiers".to_string());
        }
    };

    let id = rule.identifier.clone();
    let bi = match rule.rule_type {
        RuleType::TeamId => BinaryIdentifier {
            team_id: Some(id),
            ..Default::default()
        },
        RuleType::SigningId => BinaryIdentifier {
            team_id: team_id_from_signing_id(&id),
            signing_id: Some(apple_signing_id(&id)),
            ..Default::default()
        },
        RuleType::Cdhash => BinaryIdentifier {
            cdhash: Some(id),
            ..Default::default()
        },
        RuleType::Binary => {
            return Err(
                "Binary (SHA-256) rules have no app.settings matcher; re-scan for CDHash"
                    .to_string(),
            );
        }
        RuleType::Certificate => {
            return Err("Certificate rules have no app.settings matcher".to_string());
        }
    };

    Ok((bi, policy))
}

/// Build an [`AppIdentifier`] (bundle-ID list entry) from a scanned app.
pub fn app_from_scanned(
    app: &ScannedApp,
    policy: BinaryPolicy,
) -> Option<(AppIdentifier, BinaryPolicy)> {
    app.bundle_id.as_ref().filter(|b| !b.is_empty()).map(|b| {
        (
            AppIdentifier {
                app_identifier: b.clone(),
            },
            policy,
        )
    })
}

/// Build a macOS Privacy [`ComposedIdentifier`] (`Bundle (TeamID)`) from a scan.
pub fn composed_from_scanned(app: &ScannedApp) -> Option<ComposedIdentifier> {
    app.bundle_id
        .as_ref()
        .filter(|b| !b.is_empty())
        .map(|b| ComposedIdentifier {
            bundle_id: b.clone(),
            team_id: app.team_id.clone(),
            designated_requirement: None,
        })
}

/// Whether a slice runs natively on Apple silicon.
///
/// `arm64e` counts: Apple's own binaries ship the pointer-authentication
/// slice, so matching on the exact string `arm64` would miss every one of them.
pub fn is_apple_silicon(arch: &str) -> bool {
    arch.starts_with("arm64")
}

/// Which of a binary's slices should become CDHash rules.
///
/// A universal binary has a different CDHash per slice, and a CDHash rule
/// matches only the slice that actually executes. On Apple silicon that is
/// the arm64/arm64e slice — unless the app is launched under Rosetta, in
/// which case the x86_64 slice runs instead.
///
/// So the choice is not neutral, and it cuts differently per list:
///
/// - `Allow` with native slices only: one rule per app, but a Rosetta launch
///   runs a slice no rule names.
/// - `Deny` with native slices only: a Rosetta launch runs a slice no rule
///   names — which for a deny list means the denied app runs.
///
/// The policy: deny covers every slice, so Rosetta cannot route around it;
/// allow covers native slices only, so a Rosetta launch fails closed.
///
/// Returns the slices to emit; empty means "no CDHash rule for this binary".
pub fn cdhash_slices_for(
    slices: &[contour_core::SliceCdHash],
    policy: BinaryPolicy,
) -> Vec<&contour_core::SliceCdHash> {
    match policy {
        // Every slice: a deny rule that skips x86_64 is bypassed by launching
        // the app under Rosetta, so the denied app runs.
        BinaryPolicy::Deny => slices.iter().collect(),
        // Native slices only — a Rosetta launch then fails closed, which is
        // safe. But an Intel-only binary has no native slice, and its x86_64
        // slice is the only one that ever runs; filtering it out would leave
        // the app with no allow rule at all.
        BinaryPolicy::Allow => {
            let native: Vec<_> = slices
                .iter()
                .filter(|s| is_apple_silicon(&s.arch))
                .collect();
            if native.is_empty() {
                slices.iter().collect()
            } else {
                native
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice(arch: &str) -> contour_core::SliceCdHash {
        contour_core::SliceCdHash {
            arch: arch.to_string(),
            cdhash: format!("{:0<40}", arch),
        }
    }

    fn archs(v: Vec<&contour_core::SliceCdHash>) -> Vec<&str> {
        v.iter().map(|s| s.arch.as_str()).collect()
    }

    #[test]
    fn deny_covers_every_slice_so_rosetta_cannot_bypass_it() {
        let universal = [slice("x86_64"), slice("arm64")];
        assert_eq!(
            archs(cdhash_slices_for(&universal, BinaryPolicy::Deny)),
            ["x86_64", "arm64"]
        );
    }

    #[test]
    fn allow_takes_only_the_native_slice() {
        let universal = [slice("x86_64"), slice("arm64")];
        assert_eq!(
            archs(cdhash_slices_for(&universal, BinaryPolicy::Allow)),
            ["arm64"]
        );
    }

    #[test]
    fn allow_counts_arm64e_as_native() {
        // Apple's own binaries ship arm64e, not arm64.
        let apple = [slice("x86_64"), slice("arm64e")];
        assert_eq!(
            archs(cdhash_slices_for(&apple, BinaryPolicy::Allow)),
            ["arm64e"]
        );
    }

    #[test]
    fn allow_keeps_an_intel_only_binary_rather_than_dropping_it() {
        // No native slice: x86_64 is the only one that ever runs, so filtering
        // it out would leave the app with no allow rule at all.
        let intel_only = [slice("x86_64")];
        assert_eq!(
            archs(cdhash_slices_for(&intel_only, BinaryPolicy::Allow)),
            ["x86_64"]
        );
    }

    fn app() -> ScannedApp {
        ScannedApp {
            name: "Example".to_string(),
            path: "/Applications/Example.app".to_string(),
            version: Some("1.0".to_string()),
            team_id: Some("ABCDE12345".to_string()),
            signing_id: Some("ABCDE12345:com.example.app".to_string()),
            sha256: Some("a".repeat(64)),
            cdhash: Some("b".repeat(40)),
            bundle_id: Some("com.example.app".to_string()),
            cdhash_slices: Vec::new(),
        }
    }

    #[test]
    fn scanned_app_team_id_mode() {
        let entries = from_scanned_app(&app(), ScanRuleType::TeamId, BinaryPolicy::Allow);
        assert_eq!(
            entries.len(),
            1,
            "a TeamID rule is one rule, whatever the slices"
        );
        let (bi, pol) = entries.into_iter().next().unwrap();
        assert_eq!(bi.team_id.as_deref(), Some("ABCDE12345"));
        assert!(bi.signing_id.is_none() && bi.cdhash.is_none());
        assert_eq!(pol, BinaryPolicy::Allow);
    }

    #[test]
    fn auto_allow_uses_the_vendor_auto_deny_uses_the_app() {
        // Allow: the vendor's TeamID, so the app's helpers — other signing
        // IDs, same team — are allowed with it.
        let (allow, _) = from_scanned_app(&app(), ScanRuleType::Auto, BinaryPolicy::Allow)
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(allow.team_id.as_deref(), Some("ABCDE12345"));
        assert!(
            allow.signing_id.is_none(),
            "a per-app allow entry would block the app's own helpers"
        );

        let (deny, _) = from_scanned_app(&app(), ScanRuleType::Auto, BinaryPolicy::Deny)
            .into_iter()
            .next()
            .unwrap();
        // Apple SigningID is the bare identifier — the TEAMID: prefix is stripped.
        assert_eq!(deny.signing_id.as_deref(), Some("com.example.app"));
    }

    /// An Apple platform app has no team identifier; Santa spells it
    /// `platform:`. Allowed, it is Apple's `*APPLE*` sentinel — not a CDHash,
    /// which would stop matching at the next OS update.
    #[test]
    fn auto_allows_an_apple_app_by_the_apple_sentinel() {
        let mut a = app();
        a.team_id = None;
        a.signing_id = Some("platform:com.apple.Safari".to_string());
        let (bi, _) = from_scanned_app(&a, ScanRuleType::Auto, BinaryPolicy::Allow)
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(bi.team_id.as_deref(), Some("*APPLE*"));
        assert!(bi.signing_id.is_none() && bi.cdhash.is_none());
        crate::app_settings::validate::validate_binary(&bi, BinaryPolicy::Allow).unwrap();
    }

    /// A universal app with real 40-hex CDHashes per slice.
    fn universal_app() -> ScannedApp {
        let mut a = app();
        a.team_id = None; // force Auto/Allow onto CDHash:
        a.signing_id = None; // no team anywhere, so no TeamID entry
        a.cdhash_slices = vec![
            contour_core::SliceCdHash {
                arch: "x86_64".to_string(),
                cdhash: "c".repeat(40),
            },
            contour_core::SliceCdHash {
                arch: "arm64".to_string(),
                cdhash: "a".repeat(40),
            },
        ];
        a
    }

    #[test]
    fn a_deny_cdhash_rule_is_emitted_for_every_slice() {
        let entries = from_scanned_app(&universal_app(), ScanRuleType::Cdhash, BinaryPolicy::Deny);
        let hashes: Vec<_> = entries
            .iter()
            .filter_map(|(b, _)| b.cdhash.as_deref())
            .collect();
        assert_eq!(hashes, ["c".repeat(40), "a".repeat(40)]);
    }

    #[test]
    fn an_allow_cdhash_rule_names_only_the_native_slice() {
        let entries = from_scanned_app(&universal_app(), ScanRuleType::Cdhash, BinaryPolicy::Allow);
        let hashes: Vec<_> = entries
            .iter()
            .filter_map(|(b, _)| b.cdhash.as_deref())
            .collect();
        assert_eq!(hashes, ["a".repeat(40)]);
    }

    #[test]
    fn slices_do_not_multiply_a_non_cdhash_rule() {
        // TeamID is the same on every slice; three slices must not make three rules.
        let mut a = universal_app();
        a.team_id = Some("ABCDE12345".to_string());
        assert_eq!(
            from_scanned_app(&a, ScanRuleType::TeamId, BinaryPolicy::Deny).len(),
            1
        );
    }

    #[test]
    fn without_slices_the_single_cdhash_is_kept() {
        // A CSV written before the `cdhashes` column existed.
        let entries = from_scanned_app(&app(), ScanRuleType::Cdhash, BinaryPolicy::Deny);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].0.cdhash.as_deref(),
            Some("b".repeat(40).as_str())
        );
    }

    #[test]
    fn unsigned_app_yields_no_identifier() {
        let mut a = app();
        a.team_id = None;
        a.signing_id = None;
        a.cdhash = None;
        assert!(from_scanned_app(&a, ScanRuleType::Auto, BinaryPolicy::Allow).is_empty());
    }

    #[test]
    fn invalid_cdhash_is_dropped() {
        let mut a = app();
        a.cdhash = Some("not-a-hash".to_string());
        a.team_id = None;
        // Auto allow with no team id falls back to cdhash, which is invalid → None.
        assert!(from_scanned_app(&a, ScanRuleType::Cdhash, BinaryPolicy::Allow).is_empty());
    }

    #[test]
    fn santa_rule_converter_maps_policy_and_type() {
        let allow = Rule::new(RuleType::TeamId, "ABCDE12345", Policy::Allowlist);
        let (bi, pol) = from_santa_rule(&allow).unwrap();
        assert_eq!(bi.team_id.as_deref(), Some("ABCDE12345"));
        assert_eq!(pol, BinaryPolicy::Allow);

        let block = Rule::new(RuleType::SigningId, "ABCDE12345:com.x", Policy::Blocklist);
        let (bi, pol) = from_santa_rule(&block).unwrap();
        assert_eq!(bi.signing_id.as_deref(), Some("com.x"));
        assert_eq!(pol, BinaryPolicy::Deny);
    }

    #[test]
    fn signing_id_pairs_team_id_for_valid_allow() {
        // A SigningID allowlist rule must become a schema-valid AllowedBinaries
        // entry: the TeamID is derived from the SigningID prefix.
        let allow = Rule::new(RuleType::SigningId, "ABCDE12345:com.x", Policy::Allowlist);
        let (bi, pol) = from_santa_rule(&allow).unwrap();
        assert_eq!(bi.team_id.as_deref(), Some("ABCDE12345"));
        assert_eq!(bi.signing_id.as_deref(), Some("com.x"));
        assert_eq!(pol, BinaryPolicy::Allow);
        // It now passes allow validation (which requires CDHash or TeamID).
        super::super::validate::validate_binary(&bi, BinaryPolicy::Allow).unwrap();
    }

    #[test]
    fn signing_id_without_valid_team_prefix_stays_signing_only() {
        // `platform:` SigningIDs have no derivable TeamID; the prefix is stripped to
        // the bare Apple signing identifier.
        let r = Rule::new(
            RuleType::SigningId,
            "platform:com.apple.x",
            Policy::Blocklist,
        );
        let (bi, _) = from_santa_rule(&r).unwrap();
        assert!(bi.team_id.is_none());
        assert_eq!(bi.signing_id.as_deref(), Some("com.apple.x"));
    }

    #[test]
    fn santa_rule_converter_rejects_unmappable() {
        let bin = Rule::new(RuleType::Binary, "a".repeat(64), Policy::Allowlist);
        assert!(
            from_santa_rule(&bin).is_err(),
            "SHA-256 binary rules cannot map"
        );
        let cel = Rule::new(RuleType::TeamId, "ABCDE12345", Policy::Cel);
        assert!(from_santa_rule(&cel).is_err(), "CEL rules cannot map");
    }

    #[test]
    fn composed_identifier_from_scan_includes_team() {
        let c = composed_from_scanned(&app()).unwrap();
        assert_eq!(c.render(), "com.example.app (ABCDE12345)");
    }
}
