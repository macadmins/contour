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

/// Build a [`BinaryIdentifier`] from a scanned app using the selected match type.
///
/// `Auto` chooses a schema-valid identifier for the policy: allow prefers
/// `TeamID` (vendor-level) then `CDHash`; deny prefers `SigningID` (this app)
/// then `TeamID` then `CDHash`. Returns `None` when the app carries no usable
/// identifier for the chosen mode.
pub fn from_scanned_app(
    app: &ScannedApp,
    rule_type: ScanRuleType,
    policy: BinaryPolicy,
) -> Option<(BinaryIdentifier, BinaryPolicy)> {
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
            signing_id: app.signing_id.clone(),
            ..Default::default()
        },
        ScanRuleType::Cdhash => BinaryIdentifier {
            cdhash: valid_cdhash,
            ..Default::default()
        },
        ScanRuleType::Auto => match policy {
            // Allow needs CDHash or TeamID; SigningID alone is invalid for allow.
            BinaryPolicy::Allow => BinaryIdentifier {
                team_id: app.team_id.clone(),
                cdhash: app.team_id.is_none().then_some(valid_cdhash).flatten(),
                ..Default::default()
            },
            // Deny may use SigningID; prefer the most specific available.
            BinaryPolicy::Deny => {
                if let Some(signing_id) = &app.signing_id {
                    BinaryIdentifier {
                        signing_id: Some(signing_id.clone()),
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

    (!bi.is_empty()).then_some((bi, policy))
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
            signing_id: Some(id),
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

#[cfg(test)]
mod tests {
    use super::*;

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
        }
    }

    #[test]
    fn scanned_app_team_id_mode() {
        let (bi, pol) =
            from_scanned_app(&app(), ScanRuleType::TeamId, BinaryPolicy::Allow).unwrap();
        assert_eq!(bi.team_id.as_deref(), Some("ABCDE12345"));
        assert!(bi.signing_id.is_none() && bi.cdhash.is_none());
        assert_eq!(pol, BinaryPolicy::Allow);
    }

    #[test]
    fn auto_allow_uses_team_id_auto_deny_uses_signing_id() {
        let (allow, _) = from_scanned_app(&app(), ScanRuleType::Auto, BinaryPolicy::Allow).unwrap();
        assert_eq!(allow.team_id.as_deref(), Some("ABCDE12345"));
        assert!(
            allow.signing_id.is_none(),
            "allow must not key on SigningID alone"
        );

        let (deny, _) = from_scanned_app(&app(), ScanRuleType::Auto, BinaryPolicy::Deny).unwrap();
        assert_eq!(
            deny.signing_id.as_deref(),
            Some("ABCDE12345:com.example.app")
        );
    }

    #[test]
    fn unsigned_app_yields_no_identifier() {
        let mut a = app();
        a.team_id = None;
        a.signing_id = None;
        a.cdhash = None;
        assert!(from_scanned_app(&a, ScanRuleType::Auto, BinaryPolicy::Allow).is_none());
    }

    #[test]
    fn invalid_cdhash_is_dropped() {
        let mut a = app();
        a.cdhash = Some("not-a-hash".to_string());
        a.team_id = None;
        // Auto allow with no team id falls back to cdhash, which is invalid → None.
        assert!(from_scanned_app(&a, ScanRuleType::Cdhash, BinaryPolicy::Allow).is_none());
    }

    #[test]
    fn santa_rule_converter_maps_policy_and_type() {
        let allow = Rule::new(RuleType::TeamId, "ABCDE12345", Policy::Allowlist);
        let (bi, pol) = from_santa_rule(&allow).unwrap();
        assert_eq!(bi.team_id.as_deref(), Some("ABCDE12345"));
        assert_eq!(pol, BinaryPolicy::Allow);

        let block = Rule::new(RuleType::SigningId, "ABCDE12345:com.x", Policy::Blocklist);
        let (bi, pol) = from_santa_rule(&block).unwrap();
        assert_eq!(bi.signing_id.as_deref(), Some("ABCDE12345:com.x"));
        assert_eq!(pol, BinaryPolicy::Deny);
    }

    #[test]
    fn signing_id_pairs_team_id_for_valid_allow() {
        // A SigningID allowlist rule must become a schema-valid AllowedBinaries
        // entry: the TeamID is derived from the SigningID prefix.
        let allow = Rule::new(RuleType::SigningId, "ABCDE12345:com.x", Policy::Allowlist);
        let (bi, pol) = from_santa_rule(&allow).unwrap();
        assert_eq!(bi.team_id.as_deref(), Some("ABCDE12345"));
        assert_eq!(bi.signing_id.as_deref(), Some("ABCDE12345:com.x"));
        assert_eq!(pol, BinaryPolicy::Allow);
        // It now passes allow validation (which requires CDHash or TeamID).
        super::super::validate::validate_binary(&bi, BinaryPolicy::Allow).unwrap();
    }

    #[test]
    fn signing_id_without_valid_team_prefix_stays_signing_only() {
        // `platform:` SigningIDs have no derivable TeamID.
        let r = Rule::new(
            RuleType::SigningId,
            "platform:com.apple.x",
            Policy::Blocklist,
        );
        let (bi, _) = from_santa_rule(&r).unwrap();
        assert!(bi.team_id.is_none());
        assert_eq!(bi.signing_id.as_deref(), Some("platform:com.apple.x"));
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
