//! Change taxonomy for `profile plan`.
//!
//! Each variant maps to a specific MDM-side behavior on enrolled
//! devices. Treat the order of the variants as authoritative: tooling
//! and CI policy compare tiers ordinally.

use serde::{Deserialize, Serialize};

/// The classification of a single payload-level delta between baseline
/// and proposed profiles.
///
/// Order matters: tools compare tiers ordinally to decide whether a
/// plan should block. `Noop` is the lowest, `Deprecated` the highest
/// in the eyes of CI policy. See
/// `sop-profile-changes.md::TIER ENUM` for the full doctrine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeTier {
    /// Canonical-form-only delta after normalize. Nothing pushed.
    Noop,
    /// Same `PayloadUUID`, same `PayloadType`; one or more values changed.
    /// Apple MDM updates the payload in place.
    InPlaceUpdate,
    /// Payload appears in proposed but not baseline.
    Add,
    /// Payload appears in baseline but not proposed.
    Remove,
    /// Same `(PayloadType, PayloadIdentifier)` pair, different `PayloadUUID`.
    /// Causes remove + reinstall on every enrolled device — destructive.
    Replace,
    /// `PayloadCertificateUUID` / `PayloadCertificateAnchorUUID` /
    /// EAP / IKEv2 reference points at a UUID that does not resolve.
    /// Payload installs but does not bind. Wired in by the REF_BROKEN slice.
    RefBroken,
    /// TCC ACL widened, `PayloadScope` widened, or a managed-domain
    /// wildcard was introduced. Wired in by the SCOPE_BROADENED slice.
    ScopeBroadened,
    /// A value's plist type does not match the consuming app's schema
    /// (Nudge, Santa, Okta Verify, Munki, ...). Silent fallback to
    /// default. Wired in by the TYPE_INVALID slice.
    TypeInvalid,
    /// Introduces a deprecated payload type or key. Will break on a
    /// future macOS. Wired in by the DEPRECATED slice.
    Deprecated,
}

impl ChangeTier {
    /// Tiers that should block a CI run by default (override with
    /// `--accept-replace` or `--accept-scope-change` where applicable).
    ///
    /// `RefBroken`, `TypeInvalid`, and `Deprecated` have no accept
    /// flag — fix the change.
    pub fn is_default_blocker(self) -> bool {
        matches!(
            self,
            ChangeTier::Replace
                | ChangeTier::RefBroken
                | ChangeTier::ScopeBroadened
                | ChangeTier::TypeInvalid
                | ChangeTier::Deprecated
        )
    }
}

/// A single payload-level change between baseline and proposed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadChange {
    /// Classification.
    pub tier: ChangeTier,
    /// Apple `PayloadType` of the affected payload (e.g. `com.apple.security.scep`).
    pub payload_type: String,
    /// Reverse-DNS `PayloadIdentifier` of the affected payload.
    pub payload_identifier: String,
    /// 0-based index of the payload in `PayloadContent` (proposed side
    /// when present, otherwise baseline).
    pub payload_index: usize,
    /// `PayloadUUID` from the baseline profile, if the payload existed there.
    pub baseline_uuid: Option<String>,
    /// `PayloadUUID` from the proposed profile, if the payload exists there.
    pub proposed_uuid: Option<String>,
    /// Names of value fields that changed (only meaningful for
    /// `InPlaceUpdate` and `Replace`). Empty otherwise.
    pub fields_changed: Vec<String>,
    /// One-line human-readable explanation. Used by the text reporter
    /// and surfaced in JSON output.
    pub evidence: String,
}

/// The complete output of [`crate::plan::plan_profiles`] for a single
/// (baseline, proposed) pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    /// One entry per detected payload-level change. Empty `changes`
    /// with `summary.noop > 0` is the all-clear signal.
    pub changes: Vec<PayloadChange>,
    /// Per-tier counts derived from `changes`.
    pub summary: PlanSummary,
}

/// Per-tier counts. Always derivable from `Plan::changes`; carried as a
/// separate field so JSON consumers don't have to compute it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlanSummary {
    pub noop: usize,
    pub in_place_update: usize,
    pub add: usize,
    pub remove: usize,
    pub replace: usize,
    pub ref_broken: usize,
    pub scope_broadened: usize,
    pub type_invalid: usize,
    pub deprecated: usize,
}

impl PlanSummary {
    /// True if any change in this plan would block a default CI run.
    pub fn has_default_blocker(&self) -> bool {
        self.replace > 0
            || self.ref_broken > 0
            || self.scope_broadened > 0
            || self.type_invalid > 0
            || self.deprecated > 0
    }
}

impl Plan {
    /// Build a `Plan` from a list of `PayloadChange`s, deriving the
    /// summary in one pass.
    pub fn from_changes(changes: Vec<PayloadChange>) -> Self {
        let mut summary = PlanSummary::default();
        for change in &changes {
            match change.tier {
                ChangeTier::Noop => summary.noop += 1,
                ChangeTier::InPlaceUpdate => summary.in_place_update += 1,
                ChangeTier::Add => summary.add += 1,
                ChangeTier::Remove => summary.remove += 1,
                ChangeTier::Replace => summary.replace += 1,
                ChangeTier::RefBroken => summary.ref_broken += 1,
                ChangeTier::ScopeBroadened => summary.scope_broadened += 1,
                ChangeTier::TypeInvalid => summary.type_invalid += 1,
                ChangeTier::Deprecated => summary.deprecated += 1,
            }
        }
        Self { changes, summary }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering_is_stable() {
        // Ordinal compare is the basis for CI policy; lock it in.
        assert!(ChangeTier::Noop < ChangeTier::InPlaceUpdate);
        assert!(ChangeTier::InPlaceUpdate < ChangeTier::Replace);
        assert!(ChangeTier::Replace < ChangeTier::RefBroken);
        assert!(ChangeTier::Deprecated > ChangeTier::Noop);
    }

    #[test]
    fn default_blockers_match_doctrine() {
        // sop-profile-changes.md::TIER ENUM defines the exit policy.
        assert!(!ChangeTier::Noop.is_default_blocker());
        assert!(!ChangeTier::InPlaceUpdate.is_default_blocker());
        assert!(!ChangeTier::Add.is_default_blocker());
        assert!(!ChangeTier::Remove.is_default_blocker());
        assert!(ChangeTier::Replace.is_default_blocker());
        assert!(ChangeTier::RefBroken.is_default_blocker());
        assert!(ChangeTier::ScopeBroadened.is_default_blocker());
        assert!(ChangeTier::TypeInvalid.is_default_blocker());
        assert!(ChangeTier::Deprecated.is_default_blocker());
    }

    #[test]
    fn plan_summary_counts_correctly() {
        let changes = vec![
            PayloadChange {
                tier: ChangeTier::Noop,
                payload_type: "x".into(),
                payload_identifier: "x".into(),
                payload_index: 0,
                baseline_uuid: None,
                proposed_uuid: None,
                fields_changed: vec![],
                evidence: String::new(),
            },
            PayloadChange {
                tier: ChangeTier::Replace,
                payload_type: "x".into(),
                payload_identifier: "x".into(),
                payload_index: 1,
                baseline_uuid: Some("A".into()),
                proposed_uuid: Some("B".into()),
                fields_changed: vec![],
                evidence: String::new(),
            },
            PayloadChange {
                tier: ChangeTier::Replace,
                payload_type: "y".into(),
                payload_identifier: "y".into(),
                payload_index: 2,
                baseline_uuid: Some("C".into()),
                proposed_uuid: Some("D".into()),
                fields_changed: vec![],
                evidence: String::new(),
            },
        ];
        let plan = Plan::from_changes(changes);
        assert_eq!(plan.summary.noop, 1);
        assert_eq!(plan.summary.replace, 2);
        assert_eq!(plan.summary.add, 0);
        assert!(plan.summary.has_default_blocker());
    }
}
