//! Where a Santa ruleset and an `app.settings` declaration disagree.
//!
//! Santa and `app.settings` are independent gates: a binary runs only when
//! neither blocks it. Run with an allowlist each, every app must be admitted
//! twice, and any drift between the two blocks it — through whichever gate the
//! operator was not looking at, with that gate's dialog rather than the one
//! they expect.
//!
//! The comparison is **coverage, not equality**. Apple: "A binary only matches
//! when all the binary identifiers match", so each entry is a conjunction of
//! constraints, and an entry naming only a TeamID admits every binary from
//! that team. A Santa `SIGNINGID TEAM:app` allow is therefore satisfied by an
//! `app.settings` `{TeamID: TEAM}` allow, though the two entries differ. A plain
//! diff would call that drift.
//!
//! What cannot be decided from rules alone is left undecided rather than
//! guessed: whether a CDHash belongs to a TeamID needs the binary, so an entry
//! is only ever covered by one whose constraints it provably satisfies.

use serde::Serialize;

use super::map::from_santa_rule;
use super::model::{BinaryIdentifier, BinaryPolicy, SigningState};
use crate::config::ClientMode;
use crate::models::{Policy, RuleSet};

/// Whether `general` admits every binary that `specific` admits.
///
/// True when every constraint `general` sets is also set, identically, in
/// `specific` — `general` then asks for a subset of what `specific` does. A
/// `PathPrefix` is satisfied by a longer prefix under it, and a `SigningState`
/// of `All` constrains nothing. An empty `general` covers nothing: an entry
/// with no identifier is invalid, and treating it as "matches everything"
/// would hide real drift behind a malformed rule.
pub fn covers(general: &BinaryIdentifier, specific: &BinaryIdentifier) -> bool {
    if general.is_empty() {
        return false;
    }

    let same =
        |g: &Option<String>, s: &Option<String>| g.as_ref().is_none_or(|g| s.as_ref() == Some(g));

    let path = general.path_prefix.as_ref().is_none_or(|p| {
        specific
            .path_prefix
            .as_ref()
            .is_some_and(|q| q.starts_with(p.as_str()))
    });

    let state = match general.signing_state {
        None | Some(SigningState::All) => true,
        Some(g) => specific.signing_state == Some(g),
    };

    same(&general.cdhash, &specific.cdhash)
        && same(&general.team_id, &specific.team_id)
        && same(&general.signing_id, &specific.signing_id)
        && path
        && state
}

/// The binary-execution half of an `app.settings` declaration.
#[derive(Debug, Clone, Default)]
pub struct DeclaredBinaries {
    /// `AllowedBinaries`, or `None` when the key is absent.
    ///
    /// Absent and empty are different: Apple's "if present, the device only
    /// allows binaries that match" makes an empty array an allowlist that
    /// admits nothing but system-critical processes.
    pub allowed: Option<Vec<BinaryIdentifier>>,
    /// `DeniedBinaries`, empty when absent.
    pub denied: Vec<BinaryIdentifier>,
    /// `AlwaysAllowManagedApps`.
    pub always_allow_managed: bool,
}

impl DeclaredBinaries {
    /// Read `Payload.Allowed` from an `app.settings` declaration.
    pub fn from_declaration(decl: &serde_json::Value) -> anyhow::Result<Self> {
        let decl_type = decl.get("Type").and_then(serde_json::Value::as_str);
        if decl_type != Some(super::APP_SETTINGS_TYPE) {
            anyhow::bail!(
                "expected a {} declaration, got {}",
                super::APP_SETTINGS_TYPE,
                decl_type.unwrap_or("no Type")
            );
        }

        let allowed_block = decl.pointer("/Payload/Allowed");
        let list = |key: &str| -> anyhow::Result<Option<Vec<BinaryIdentifier>>> {
            allowed_block
                .and_then(|a| a.get(key))
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| anyhow::anyhow!("Payload.Allowed.{key}: {e}"))
        };

        Ok(Self {
            allowed: list("AllowedBinaries")?,
            denied: list("DeniedBinaries")?.unwrap_or_default(),
            always_allow_managed: allowed_block
                .and_then(|a| a.get("AlwaysAllowManagedApps"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        })
    }
}

/// One side's entry, with a name for the operator when the rule carried one.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub identifier: BinaryIdentifier,
    /// The Santa rule's description — usually the app name. `None` for
    /// `app.settings` entries, which carry no names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// An allow on one gate that a deny on the other cancels entirely.
#[derive(Debug, Clone, Serialize)]
pub struct Nullified {
    /// The gate whose allow is cancelled: `"santa"` or `"app.settings"`.
    pub allowed_by: &'static str,
    pub allow: Entry,
    pub deny: Entry,
}

/// A Santa rule `app.settings` has no way to express.
#[derive(Debug, Clone, Serialize)]
pub struct Unmapped {
    pub rule: String,
    pub reason: String,
    /// True when this is an allow and `app.settings` is an allowlist — the
    /// app is then blocked there, with nothing to mirror the rule into.
    pub blocks: bool,
}

/// Everything that makes the two gates disagree.
#[derive(Debug, Default, Serialize)]
pub struct ParityReport {
    /// Santa allows it; no `app.settings` allow covers it.
    pub blocked_by_app_settings: Vec<Entry>,
    /// `app.settings` allows it; no Santa allow covers it.
    pub blocked_by_santa: Vec<Entry>,
    /// An allow on one gate, cancelled by a deny on the other.
    pub nullified: Vec<Nullified>,
    /// Santa rules with no `app.settings` form.
    pub no_equivalent: Vec<Unmapped>,

    /// Whether `app.settings` declares `AllowedBinaries` at all.
    pub app_settings_is_allowlist: bool,
    /// Whether Santa blocks binaries no rule allows (lockdown or standalone).
    pub santa_blocks_unknown: bool,
    /// `AlwaysAllowManagedApps` — some `blocked_by_app_settings` entries may
    /// still run as managed apps, which rules alone cannot show.
    pub always_allow_managed: bool,
    /// app.settings allows `TeamID = "*APPLE*"` and Santa blocks unknown
    /// binaries: that allow is matched by Santa's built-in platform-binary
    /// allow, not by a rule, and Apple apps outside the OS are not covered.
    pub apple_via_platform_binaries: bool,
}

impl ParityReport {
    /// Whether any finding would block an app one gate means to allow.
    pub fn has_drift(&self) -> bool {
        !self.blocked_by_app_settings.is_empty()
            || !self.blocked_by_santa.is_empty()
            || !self.nullified.is_empty()
            || self.no_equivalent.iter().any(|u| u.blocks)
    }
}

/// Compare a Santa ruleset with an `app.settings` declaration.
///
/// Findings are gated on what each side actually enforces. A Santa-only allow
/// is only blocked when `app.settings` is an allowlist; an `app.settings`-only
/// allow is only blocked when Santa blocks unknown binaries. Outside those
/// modes the other gate never refuses anything, so the difference is harmless
/// and is not reported as drift.
pub fn compare(
    rules: &RuleSet,
    declared: &DeclaredBinaries,
    santa_mode: ClientMode,
) -> ParityReport {
    let santa_blocks_unknown = !matches!(santa_mode, ClientMode::Monitor);
    let app_settings_is_allowlist = declared.allowed.is_some();

    let mut santa_allow = Vec::new();
    let mut santa_deny = Vec::new();
    let mut no_equivalent = Vec::new();

    for rule in rules {
        match from_santa_rule(rule) {
            Ok((identifier, policy)) => {
                let entry = Entry {
                    identifier,
                    label: rule.description.clone(),
                };
                match policy {
                    BinaryPolicy::Allow => santa_allow.push(entry),
                    BinaryPolicy::Deny => santa_deny.push(entry),
                }
            }
            Err(reason) => no_equivalent.push(Unmapped {
                // Lead with the rule's own description when it has one: an
                // unmappable rule is usually a SHA-256, which names nothing.
                rule: {
                    let rule_text =
                        format!("{} {} ({})", rule.rule_type, rule.identifier, rule.policy);
                    match &rule.description {
                        Some(label) => format!("{label} — {rule_text}"),
                        None => rule_text,
                    }
                },
                blocks: app_settings_is_allowlist
                    && matches!(rule.policy, Policy::Allowlist | Policy::AllowlistCompiler),
                reason,
            }),
        }
    }

    let as_entries = |ids: &[BinaryIdentifier]| -> Vec<Entry> {
        ids.iter()
            .map(|identifier| Entry {
                identifier: identifier.clone(),
                label: None,
            })
            .collect()
    };
    let declared_allow = as_entries(declared.allowed.as_deref().unwrap_or_default());
    let declared_deny = as_entries(&declared.denied);

    let covered_by = |entry: &Entry, pool: &[Entry]| {
        pool.iter()
            .any(|p| covers(&p.identifier, &entry.identifier))
    };
    let cancelled_by = |entry: &Entry, pool: &[Entry]| {
        pool.iter()
            .find(|d| covers(&d.identifier, &entry.identifier))
            .cloned()
    };

    let blocked_by_app_settings = if app_settings_is_allowlist {
        santa_allow
            .iter()
            .filter(|a| !covered_by(a, &declared_allow))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };

    // Santa allows Apple's platform binaries without a rule — `santactl
    // fileinfo /System/Applications/Calculator.app` reports `Rule: Platform
    // Binary`, `Expected Decision: Allowlist` — so an app.settings allow of
    // `TeamID = "*APPLE*"` alone is not something Santa blocks. Apple's apps
    // outside the OS (Xcode, Keynote) are not platform binaries: they carry
    // their own Team ID, Santa decides them by rule, and the report says so.
    let apple_via_platform_binaries =
        santa_blocks_unknown && declared_allow.iter().any(|a| is_apple_only(&a.identifier));
    let blocked_by_santa = if santa_blocks_unknown {
        declared_allow
            .iter()
            .filter(|a| !is_apple_only(&a.identifier) && !covered_by(a, &santa_allow))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };

    // Only a deny that covers the whole allow cancels it. A narrower deny
    // inside a broader allow — deny one app from a team the other gate allows
    // — is the ordinary way to carve out an exception, not a contradiction.
    let mut nullified = Vec::new();
    for allow in &santa_allow {
        if let Some(deny) = cancelled_by(allow, &declared_deny) {
            nullified.push(Nullified {
                allowed_by: "santa",
                allow: allow.clone(),
                deny,
            });
        }
    }
    for allow in &declared_allow {
        if let Some(deny) = cancelled_by(allow, &santa_deny) {
            nullified.push(Nullified {
                allowed_by: "app.settings",
                allow: allow.clone(),
                deny,
            });
        }
    }

    ParityReport {
        blocked_by_app_settings,
        blocked_by_santa,
        nullified,
        no_equivalent,
        app_settings_is_allowlist,
        santa_blocks_unknown,
        always_allow_managed: declared.always_allow_managed,
        apple_via_platform_binaries,
    }
}

/// `{TeamID: "*APPLE*"}` and nothing narrower: Apple's software as a whole.
fn is_apple_only(id: &BinaryIdentifier) -> bool {
    id.team_id.as_deref() == Some("*APPLE*")
        && id.signing_id.is_none()
        && id.cdhash.is_none()
        && id.path_prefix.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Rule, RuleType};

    fn team(t: &str) -> BinaryIdentifier {
        BinaryIdentifier {
            team_id: Some(t.to_string()),
            ..Default::default()
        }
    }

    fn signing(t: &str, s: &str) -> BinaryIdentifier {
        BinaryIdentifier {
            team_id: Some(t.to_string()),
            signing_id: Some(s.to_string()),
            ..Default::default()
        }
    }

    fn rules(list: &[(RuleType, &str, Policy)]) -> RuleSet {
        let mut set = RuleSet::new();
        for (rule_type, id, policy) in list {
            set.add(Rule::new(*rule_type, *id, *policy));
        }
        set
    }

    const TEAM: &str = "BJ4HAAB9B3";

    /// The `*APPLE*` entry `app-settings --from-rules` adds by default is not
    /// drift against a lockdown ruleset: Santa allows platform binaries itself.
    /// A narrower Apple entry, or any other team, is still held to the rules.
    #[test]
    fn apple_alone_is_matched_by_santas_platform_binary_allow() {
        let santa = rules(&[(RuleType::TeamId, "BJ4HAAB9B3", Policy::Allowlist)]);
        let decl = DeclaredBinaries::from_declaration(&serde_json::json!({
            "Type": "com.apple.configuration.app.settings",
            "Payload": {"Allowed": {"AllowedBinaries": [
                {"TeamID": "*APPLE*"}, {"TeamID": "BJ4HAAB9B3"}
            ]}}
        }))
        .unwrap();
        let r = compare(&santa, &decl, ClientMode::Lockdown);
        assert!(r.blocked_by_santa.is_empty(), "{:?}", r.blocked_by_santa);
        assert!(r.apple_via_platform_binaries);
        assert!(!r.has_drift());

        let r = compare(&santa, &decl, ClientMode::Monitor);
        assert!(
            !r.apple_via_platform_binaries,
            "monitor mode blocks nothing, nothing to note"
        );

        let narrow = DeclaredBinaries::from_declaration(&serde_json::json!({
            "Type": "com.apple.configuration.app.settings",
            "Payload": {"Allowed": {"AllowedBinaries": [
                {"TeamID": "*APPLE*", "SigningID": "com.apple.dt.Xcode"}
            ]}}
        }))
        .unwrap();
        let r = compare(&santa, &narrow, ClientMode::Lockdown);
        assert_eq!(
            r.blocked_by_santa.len(),
            1,
            "a narrower Apple entry is not the platform allow"
        );
    }

    #[test]
    fn a_team_allow_covers_a_signing_id_allow_from_that_team() {
        assert!(covers(&team(TEAM), &signing(TEAM, "us.zoom.xos")));
        // …but not the other way round: a SigningID asks for more.
        assert!(!covers(&signing(TEAM, "us.zoom.xos"), &team(TEAM)));
    }

    #[test]
    fn a_cdhash_never_covers_a_team_it_cannot_be_proven_to_belong_to() {
        let hash = BinaryIdentifier {
            cdhash: Some("a".repeat(40)),
            ..Default::default()
        };
        assert!(!covers(&hash, &team(TEAM)));
        assert!(!covers(&team(TEAM), &hash));
    }

    #[test]
    fn an_empty_entry_covers_nothing() {
        assert!(!covers(&BinaryIdentifier::default(), &team(TEAM)));
    }

    #[test]
    fn signing_state_all_constrains_nothing() {
        let mut general = team(TEAM);
        general.signing_state = Some(SigningState::All);
        assert!(covers(&general, &signing(TEAM, "us.zoom.xos")));
    }

    #[test]
    fn a_signing_id_allow_under_a_team_allow_is_not_drift() {
        let santa = rules(&[(
            RuleType::SigningId,
            "BJ4HAAB9B3:us.zoom.xos",
            Policy::Allowlist,
        )]);
        let declared = DeclaredBinaries {
            allowed: Some(vec![team(TEAM)]),
            ..Default::default()
        };
        let report = compare(&santa, &declared, ClientMode::Lockdown);
        assert!(report.blocked_by_app_settings.is_empty(), "{report:?}");
    }

    #[test]
    fn a_santa_allow_missing_from_the_declaration_is_blocked_there() {
        let santa = rules(&[(RuleType::TeamId, "EQHXZ8M8AV", Policy::Allowlist)]);
        let declared = DeclaredBinaries {
            allowed: Some(vec![team(TEAM)]),
            ..Default::default()
        };
        let report = compare(&santa, &declared, ClientMode::Lockdown);
        assert_eq!(report.blocked_by_app_settings.len(), 1);
        assert!(report.has_drift());
    }

    #[test]
    fn without_an_allowlist_app_settings_blocks_nothing_santa_allows() {
        let santa = rules(&[(RuleType::TeamId, "EQHXZ8M8AV", Policy::Allowlist)]);
        let declared = DeclaredBinaries::default(); // no AllowedBinaries
        let report = compare(&santa, &declared, ClientMode::Lockdown);
        assert!(!report.has_drift(), "{report:?}");
    }

    #[test]
    fn santa_in_monitor_mode_blocks_nothing_app_settings_allows() {
        let santa = RuleSet::new();
        let declared = DeclaredBinaries {
            allowed: Some(vec![team(TEAM)]),
            ..Default::default()
        };
        assert!(
            compare(&santa, &declared, ClientMode::Monitor)
                .blocked_by_santa
                .is_empty()
        );
        assert_eq!(
            compare(&santa, &declared, ClientMode::Lockdown)
                .blocked_by_santa
                .len(),
            1
        );
    }

    #[test]
    fn a_narrow_deny_carving_out_of_a_broad_allow_is_not_a_contradiction() {
        // Santa allows the whole team; app.settings denies one app from it.
        let santa = rules(&[(RuleType::TeamId, TEAM, Policy::Allowlist)]);
        let declared = DeclaredBinaries {
            allowed: Some(vec![team(TEAM)]),
            denied: vec![signing(TEAM, "us.zoom.xos")],
            ..Default::default()
        };
        assert!(
            compare(&santa, &declared, ClientMode::Lockdown)
                .nullified
                .is_empty()
        );
    }

    #[test]
    fn a_deny_covering_the_whole_allow_cancels_it() {
        let santa = rules(&[(
            RuleType::SigningId,
            "BJ4HAAB9B3:us.zoom.xos",
            Policy::Allowlist,
        )]);
        let declared = DeclaredBinaries {
            allowed: Some(vec![signing(TEAM, "us.zoom.xos")]),
            denied: vec![team(TEAM)],
            ..Default::default()
        };
        let report = compare(&santa, &declared, ClientMode::Lockdown);
        assert_eq!(report.nullified.len(), 1);
        assert_eq!(report.nullified[0].allowed_by, "santa");
    }

    #[test]
    fn a_sha256_allow_blocks_only_when_app_settings_is_an_allowlist() {
        let sha256 = "f".repeat(64);
        let santa = rules(&[(RuleType::Binary, sha256.as_str(), Policy::Allowlist)]);
        let allowlist = DeclaredBinaries {
            allowed: Some(vec![team(TEAM)]),
            ..Default::default()
        };
        let report = compare(&santa, &allowlist, ClientMode::Lockdown);
        assert_eq!(report.no_equivalent.len(), 1);
        assert!(report.no_equivalent[0].blocks && report.has_drift());

        let report = compare(&santa, &DeclaredBinaries::default(), ClientMode::Lockdown);
        assert!(!report.no_equivalent[0].blocks && !report.has_drift());
    }

    #[test]
    fn an_absent_allowlist_differs_from_an_empty_one() {
        let absent = serde_json::json!({
            "Type": "com.apple.configuration.app.settings",
            "Payload": {"Allowed": {"DeniedBinaries": [{"TeamID": TEAM}]}}
        });
        let empty = serde_json::json!({
            "Type": "com.apple.configuration.app.settings",
            "Payload": {"Allowed": {"AllowedBinaries": []}}
        });
        assert!(
            DeclaredBinaries::from_declaration(&absent)
                .unwrap()
                .allowed
                .is_none()
        );
        assert_eq!(
            DeclaredBinaries::from_declaration(&empty).unwrap().allowed,
            Some(vec![])
        );
    }

    #[test]
    fn a_declaration_of_another_type_is_refused() {
        let other = serde_json::json!({"Type": "com.apple.configuration.passcode.settings"});
        DeclaredBinaries::from_declaration(&other).unwrap_err();
    }
}
