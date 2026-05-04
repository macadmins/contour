//! Profile lint checks — Apple-spec-adjacent issues that the structural
//! validator alone misses.
//!
//! These checks operate on the raw `plist::Value` tree (post-parse,
//! pre-deserialization) so they can:
//!
//! - Inspect the literal plist tag of a value (`<integer>1</integer>` vs
//!   `<real>1.0</real>`) to detect type coercion that hides spec violations
//! - Walk every nested dict to collect cross-payload state (duplicate
//!   PayloadUUIDs, deprecated PayloadType usage)
//!
//! Each finding carries a stable `check` name so callers can map back to
//! the procedural-SOP STEP 3 named checklist and so trap fixtures can
//! pin "the X check fires on the X-defect fixture, not on the clean
//! one" per-violation.
//!
//! Run by `validate_profile` after the structural validator. Defaults
//! to ON (these are spec-adjacent, not Fleet-policy). Future Phase 2
//! adds Fleet-policy checks gated behind `--strict`.

use crate::migrate::mapping::{MigrationRegistry, MigrationStatus};
use crate::uuid::is_placeholder_uuid;
use plist::Value;

/// Severity of a lint finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    /// Lint check failed in a way that should fail the validate run.
    Error,
    /// Lint check noticed something worth flagging but didn't fail.
    Warning,
}

/// One finding from the lint pass — keyed by stable check name so
/// SOP STEP 3 procedures can reference checks by ID.
#[derive(Debug, Clone)]
pub struct LintFinding {
    /// Stable identifier for the check that produced this finding
    /// (e.g. `duplicate-payload-uuid`). Used by SOP procedures and
    /// the trap suite.
    pub check: &'static str,
    pub severity: LintSeverity,
    pub message: String,
    /// Index into the top-level `PayloadContent` array if the finding
    /// is scoped to a nested payload; `None` for top-level findings.
    pub payload_index: Option<usize>,
}

impl LintFinding {
    fn error(check: &'static str, message: String) -> Self {
        Self {
            check,
            severity: LintSeverity::Error,
            message,
            payload_index: None,
        }
    }

    fn warn(check: &'static str, message: String) -> Self {
        Self {
            check,
            severity: LintSeverity::Warning,
            message,
            payload_index: None,
        }
    }

    fn with_payload(mut self, idx: usize) -> Self {
        self.payload_index = Some(idx);
        self
    }
}

/// All known lint check IDs, partitioned by tier.
///
/// Tier 1 (Apple-spec-adjacent) — fire by default, regardless of mode:
/// `duplicate-payload-uuid`, `payload-version-type`,
/// `placeholder-payload-uuid`, `deprecated-payload-type`.
///
/// Tier 2 (Fleet-policy) — gated on `LintOptions.strict` OR explicit
/// `selected_checks`:
/// `payload-identifier-reverse-dns` (warn default → error strict),
/// `payload-organization-required` (off default → error strict),
/// `payload-scope-consistency` (off default → error strict),
/// `nested-payload-identifier-prefix` (warn default → error strict).
pub const ALL_CHECKS: &[&str] = &[
    // Tier 1 — always on
    "duplicate-payload-uuid",
    "payload-version-type",
    "placeholder-payload-uuid",
    "deprecated-payload-type",
    // Tier 2 — strict / selectable
    "payload-identifier-reverse-dns",
    "payload-organization-required",
    "payload-scope-consistency",
    "nested-payload-identifier-prefix",
];

/// Selection knobs for the lint pass.
#[derive(Debug, Clone, Default)]
pub struct LintOptions {
    /// `--strict`: severity promotion (warn → error) AND fires the
    /// off-by-default Fleet-policy checks. Composed with
    /// `selected_checks`: when both are set, only the listed checks
    /// run, but at strict severity.
    pub strict: bool,
    /// `--check <list>`: opt into specific checks by name. When
    /// `Some(set)`, only checks whose name is in the set are run.
    /// `None` means "run the default set" (Tier 1 always + Tier 2's
    /// always-on members + all Tier 2 if `strict`).
    pub selected_checks: Option<std::collections::HashSet<String>>,
}

impl LintOptions {
    fn includes(&self, name: &str) -> bool {
        match &self.selected_checks {
            Some(set) => set.contains(name),
            // No explicit selection: Tier 1 always; Tier 2 only the
            // always-on members OR everything in strict mode.
            None => match name {
                // Tier 1 — always on
                "duplicate-payload-uuid"
                | "payload-version-type"
                | "placeholder-payload-uuid"
                | "deprecated-payload-type" => true,
                // Tier 2, on by default at warn severity
                "payload-identifier-reverse-dns"
                | "nested-payload-identifier-prefix" => true,
                // Tier 2, off by default — only fire in strict
                "payload-organization-required" | "payload-scope-consistency" => self.strict,
                _ => false,
            },
        }
    }

    /// Resolve the severity for a given check based on strict mode.
    ///
    /// Tier 1 checks have a fixed severity regardless of strict
    /// (the per-check function chose error vs warning at write time).
    /// Tier 2 checks promote warning → error in strict.
    fn promote_if_strict(&self, finding: LintFinding) -> LintFinding {
        if self.strict && matches!(finding.severity, LintSeverity::Warning) && is_tier_2(finding.check) {
            LintFinding {
                severity: LintSeverity::Error,
                ..finding
            }
        } else {
            finding
        }
    }
}

fn is_tier_2(check: &str) -> bool {
    matches!(
        check,
        "payload-identifier-reverse-dns"
            | "payload-organization-required"
            | "payload-scope-consistency"
            | "nested-payload-identifier-prefix"
    )
}

/// Run the default lint pass — equivalent to `lint_profile_with_options`
/// with `LintOptions::default()`. Kept for backwards compat with
/// existing callers and unit tests.
pub fn lint_profile(value: &Value, registry: &MigrationRegistry) -> Vec<LintFinding> {
    lint_profile_with_options(value, registry, &LintOptions::default())
}

/// Run lint checks with explicit options.
///
/// Filters by `options.includes(check)` and applies strict severity
/// promotion via `options.promote_if_strict`. Unknown check names in
/// `selected_checks` are silently ignored — caller is responsible for
/// validating CLI input.
pub fn lint_profile_with_options(
    value: &Value,
    registry: &MigrationRegistry,
    options: &LintOptions,
) -> Vec<LintFinding> {
    let mut all = Vec::new();
    if options.includes("duplicate-payload-uuid") {
        all.extend(check_duplicate_payload_uuids(value));
    }
    if options.includes("payload-version-type") {
        all.extend(check_payload_version_type(value));
    }
    if options.includes("placeholder-payload-uuid") {
        all.extend(check_placeholder_uuids(value));
    }
    if options.includes("deprecated-payload-type") {
        all.extend(check_deprecated_payload_types(value, registry));
    }
    if options.includes("payload-identifier-reverse-dns") {
        all.extend(check_payload_identifier_reverse_dns(value));
    }
    if options.includes("payload-organization-required") {
        all.extend(check_payload_organization_required(value));
    }
    if options.includes("payload-scope-consistency") {
        all.extend(check_payload_scope_consistency(value));
    }
    if options.includes("nested-payload-identifier-prefix") {
        all.extend(check_nested_payload_identifier_prefix(value));
    }
    all.into_iter()
        .map(|f| options.promote_if_strict(f))
        .collect()
}

// ── 1a. Duplicate PayloadUUIDs across the tree ─────────────────────────

/// Apple's spec implicitly requires PayloadUUID to identify exactly
/// one payload. Two payloads with the same UUID produce undefined
/// MDM behaviour — the server may apply one and silently drop the
/// other. Catch it at authoring time.
pub fn check_duplicate_payload_uuids(value: &Value) -> Vec<LintFinding> {
    use std::collections::HashMap;
    let mut occurrences: HashMap<String, Vec<String>> = HashMap::new();
    collect_payload_uuids(value, "Profile".to_string(), &mut occurrences);
    let mut findings = Vec::new();
    for (uuid, locations) in occurrences {
        if locations.len() > 1 {
            findings.push(LintFinding::error(
                "duplicate-payload-uuid",
                format!(
                    "PayloadUUID {uuid:?} appears in {n} locations: {locs} — \
                     each PayloadUUID must identify a single payload",
                    n = locations.len(),
                    locs = locations.join(", ")
                ),
            ));
        }
    }
    findings
}

/// Recursively walk the plist tree, recording every `PayloadUUID`
/// value alongside a human-readable location path.
fn collect_payload_uuids(
    value: &Value,
    location: String,
    occurrences: &mut std::collections::HashMap<String, Vec<String>>,
) {
    match value {
        Value::Dictionary(dict) => {
            // Record this dict's PayloadUUID if present.
            if let Some(uuid) = dict.get("PayloadUUID").and_then(Value::as_string) {
                occurrences
                    .entry(uuid.to_string())
                    .or_default()
                    .push(location.clone());
            }
            // Recurse into child arrays/dicts so nested PayloadContent
            // is covered.
            for (key, child) in dict {
                if key == "PayloadUUID" {
                    continue; // already recorded above
                }
                collect_payload_uuids(child, format!("{location}.{key}"), occurrences);
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                collect_payload_uuids(item, format!("{location}[{i}]"), occurrences);
            }
        }
        _ => {}
    }
}

// ── 1b. Type-coerced PayloadVersion ────────────────────────────────────

/// Apple's spec says PayloadVersion is `<integer>1</integer>`. The
/// `plist` crate type-coerces `<real>1.0</real>` to integer 1 silently,
/// hiding the violation. Detect by inspecting the literal plist tag
/// before deserialization.
///
/// Applies at top level + every nested payload in `PayloadContent`.
pub fn check_payload_version_type(value: &Value) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    // Top-level
    if let Value::Dictionary(dict) = value {
        check_one_payload_version(dict, None, &mut findings);
        // Each nested payload
        if let Some(Value::Array(items)) = dict.get("PayloadContent") {
            for (idx, item) in items.iter().enumerate() {
                if let Value::Dictionary(child) = item {
                    check_one_payload_version(child, Some(idx), &mut findings);
                }
            }
        }
    }
    findings
}

fn check_one_payload_version(
    dict: &plist::Dictionary,
    idx: Option<usize>,
    findings: &mut Vec<LintFinding>,
) {
    let Some(version) = dict.get("PayloadVersion") else {
        return;
    };
    if matches!(version, Value::Real(_)) {
        let scope = idx.map_or("Profile".to_string(), |i| format!("PayloadContent[{i}]"));
        let f = LintFinding::warn(
            "payload-version-type",
            format!(
                "{scope}: PayloadVersion is encoded as <real> in the plist; \
                 Apple's spec requires <integer>. Some MDMs accept this via \
                 type coercion; others reject the profile entirely."
            ),
        );
        findings.push(if let Some(i) = idx {
            f.with_payload(i)
        } else {
            f
        });
    }
}

// ── 1c. Placeholder UUIDs ──────────────────────────────────────────────

/// Catch UUIDs that are well-formed per RFC 4122 but practically
/// defective (all-zeros, repeating-digit boilerplate, etc.). Implementation
/// delegates to [`crate::uuid::is_placeholder_uuid`].
///
/// Walks every PayloadUUID in the tree (top-level + nested).
pub fn check_placeholder_uuids(value: &Value) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    walk_check_uuid(value, None, &mut findings);
    findings
}

fn walk_check_uuid(value: &Value, idx: Option<usize>, findings: &mut Vec<LintFinding>) {
    match value {
        Value::Dictionary(dict) => {
            if let Some(uuid) = dict.get("PayloadUUID").and_then(Value::as_string)
                && is_placeholder_uuid(uuid)
            {
                let scope = idx.map_or("Profile".to_string(), |i| format!("PayloadContent[{i}]"));
                let f = LintFinding::warn(
                    "placeholder-payload-uuid",
                    format!(
                        "{scope}: PayloadUUID {uuid:?} looks like a placeholder \
                         (well-formed UUID with too few distinct hex digits) — \
                         regenerate with `contour profile uuid regenerate` or a \
                         real generator before deploying."
                    ),
                );
                findings.push(if let Some(i) = idx {
                    f.with_payload(i)
                } else {
                    f
                });
            }
            // Recurse into nested PayloadContent
            if let Some(Value::Array(items)) = dict.get("PayloadContent") {
                for (i, item) in items.iter().enumerate() {
                    walk_check_uuid(item, Some(i), findings);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_check_uuid(item, idx, findings);
            }
        }
        _ => {}
    }
}

// ── 1d. Deprecated PayloadType usage ───────────────────────────────────

/// Walk every payload in the tree and warn on any PayloadType that
/// `MigrationRegistry` knows has a DDM replacement. Cites the
/// replacement so the agent can route the user to the supported path.
pub fn check_deprecated_payload_types(
    value: &Value,
    registry: &MigrationRegistry,
) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    walk_check_payload_type(value, None, registry, &mut findings);
    findings
}

fn walk_check_payload_type(
    value: &Value,
    idx: Option<usize>,
    registry: &MigrationRegistry,
    findings: &mut Vec<LintFinding>,
) {
    let Value::Dictionary(dict) = value else {
        return;
    };
    if let Some(payload_type) = dict.get("PayloadType").and_then(Value::as_string)
        && let Some(mapping) = registry.get(payload_type)
        && matches!(
            mapping.status,
            MigrationStatus::Available | MigrationStatus::Partial
        )
    {
        let scope = idx.map_or("Profile".to_string(), |i| format!("PayloadContent[{i}]"));
        let f = LintFinding::warn(
            "deprecated-payload-type",
            format!(
                "{scope}: PayloadType {pt:?} has a DDM replacement \
                 ({ddm:?}, status={status:?}); legacy payload still works on \
                 macOS \u{2264}25 but stops working on macOS 26+. {notes}",
                pt = payload_type,
                ddm = mapping.ddm_type,
                status = mapping.status,
                notes = mapping.notes,
            ),
        );
        findings.push(if let Some(i) = idx {
            f.with_payload(i)
        } else {
            f
        });
    }
    if let Some(Value::Array(items)) = dict.get("PayloadContent") {
        for (i, item) in items.iter().enumerate() {
            walk_check_payload_type(item, Some(i), registry, findings);
        }
    }
}

// ── 2a. payload-identifier-reverse-dns ─────────────────────────────────

/// Apple's spec accepts any non-empty string as PayloadIdentifier.
/// Fleet/MDM convention is reverse-DNS — `com.acme.passcode` — so a
/// bare UUID or single-segment string slips through Apple-strict but
/// will collide in any GitOps repo with multiple profiles. Default
/// severity: warning. Strict severity: error (promoted by the caller).
pub fn check_payload_identifier_reverse_dns(value: &Value) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    walk_check_identifier(value, None, &mut findings);
    findings
}

fn walk_check_identifier(value: &Value, idx: Option<usize>, findings: &mut Vec<LintFinding>) {
    let Value::Dictionary(dict) = value else {
        return;
    };
    if let Some(id) = dict.get("PayloadIdentifier").and_then(Value::as_string)
        && !is_reverse_dns(id)
    {
        let scope = idx.map_or("Profile".to_string(), |i| format!("PayloadContent[{i}]"));
        let f = LintFinding::warn(
            "payload-identifier-reverse-dns",
            format!(
                "{scope}: PayloadIdentifier {id:?} is not in reverse-DNS form \
                 (expected pattern: 'com.example.foo' — at least one '.' \
                 separator, ASCII alphanumerics + dot/hyphen/underscore). \
                 Bare strings collide across profiles in a GitOps repo."
            ),
        );
        findings.push(if let Some(i) = idx { f.with_payload(i) } else { f });
    }
    if let Some(Value::Array(items)) = dict.get("PayloadContent") {
        for (i, item) in items.iter().enumerate() {
            walk_check_identifier(item, Some(i), findings);
        }
    }
}

fn is_reverse_dns(s: &str) -> bool {
    // At least one dot, no leading/trailing dots, no empty segments,
    // each segment is ASCII alphanumerics + - + _.
    if s.is_empty() || s.starts_with('.') || s.ends_with('.') || !s.contains('.') {
        return false;
    }
    s.split('.').all(|seg| {
        !seg.is_empty()
            && seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

// ── 2b. payload-organization-required ──────────────────────────────────

/// PayloadOrganization is optional per Apple's spec, but required by
/// Fleet/audit conventions — without it, profiles can't be attributed
/// to a vendor in GitOps logs. Off by default; fires in strict.
pub fn check_payload_organization_required(value: &Value) -> Vec<LintFinding> {
    let Value::Dictionary(dict) = value else {
        return Vec::new();
    };
    let org = dict.get("PayloadOrganization").and_then(Value::as_string);
    if org.is_none_or(str::is_empty) {
        vec![LintFinding::warn(
            "payload-organization-required",
            "Profile: PayloadOrganization is missing or empty. Fleet/audit \
             convention requires it; agents should set it from the org \
             config (see `contour profile init` / CONTOUR_NAME)."
                .to_string(),
        )]
    } else {
        Vec::new()
    }
}

// ── 2c. payload-scope-consistency ──────────────────────────────────────

/// Some Apple payload types only deploy at System scope (e.g. kernel
/// extension policy, MCXFileVault2). A profile that lists one of these
/// nested under PayloadScope=User silently fails on the device — Apple
/// rejects the install with no clear authoring-time signal.
///
/// Lookup table is a small const slice. Source: Apple's Configuration
/// Profile Reference + community-confirmed system-scope-only payloads.
const SYSTEM_ONLY_PAYLOAD_TYPES: &[&str] = &[
    "com.apple.MCX",
    "com.apple.MCXFileVault2",
    "com.apple.systempolicy.kernel-extension-policy",
    "com.apple.systempolicy.system-extensions",
    "com.apple.system-extension-policy",
    "com.apple.TCC.configuration-profile-policy",
    "com.apple.servicemanagement.managed",
];

pub fn check_payload_scope_consistency(value: &Value) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    let Value::Dictionary(top) = value else {
        return findings;
    };
    // PayloadScope at top level (if any).
    let top_scope = top.get("PayloadScope").and_then(Value::as_string);
    if let Some(Value::Array(items)) = top.get("PayloadContent") {
        for (idx, item) in items.iter().enumerate() {
            let Value::Dictionary(child) = item else {
                continue;
            };
            let payload_type = child.get("PayloadType").and_then(Value::as_string);
            // Effective scope for this nested payload: nested wins, then top-level.
            let effective_scope = child
                .get("PayloadScope")
                .and_then(Value::as_string)
                .or(top_scope);
            if let (Some(pt), Some(scope)) = (payload_type, effective_scope)
                && SYSTEM_ONLY_PAYLOAD_TYPES.contains(&pt)
                && scope.eq_ignore_ascii_case("user")
            {
                findings.push(
                    LintFinding::warn(
                        "payload-scope-consistency",
                        format!(
                            "PayloadContent[{idx}]: PayloadType {pt:?} is \
                             System-scope-only per Apple's spec, but effective \
                             PayloadScope is 'User'. Apple silently rejects \
                             this combination at install time."
                        ),
                    )
                    .with_payload(idx),
                );
            }
        }
    }
    findings
}

// ── 2d. nested-payload-identifier-prefix ───────────────────────────────

/// Each nested payload's PayloadIdentifier should start with the
/// top-level PayloadIdentifier — a Fleet/audit convention that makes
/// profile attribution unambiguous and prevents PayloadIdentifier
/// collisions across profiles authored by different teams. Default
/// warning; strict error.
pub fn check_nested_payload_identifier_prefix(value: &Value) -> Vec<LintFinding> {
    let Value::Dictionary(top) = value else {
        return Vec::new();
    };
    let Some(top_id) = top.get("PayloadIdentifier").and_then(Value::as_string) else {
        return Vec::new();
    };
    let Some(Value::Array(items)) = top.get("PayloadContent") else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        let Value::Dictionary(child) = item else {
            continue;
        };
        if let Some(child_id) = child.get("PayloadIdentifier").and_then(Value::as_string)
            && !child_id.starts_with(top_id)
        {
            findings.push(
                LintFinding::warn(
                    "nested-payload-identifier-prefix",
                    format!(
                        "PayloadContent[{idx}]: nested PayloadIdentifier \
                         {child_id:?} does not start with top-level \
                         PayloadIdentifier {top_id:?}. Convention is \
                         {top_id:?}.<suffix>; mismatched prefixes break \
                         profile-attribution lookups."
                    ),
                )
                .with_payload(idx),
            );
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Dictionary;

    fn s(v: &str) -> Value {
        Value::String(v.into())
    }

    fn build_profile(payload_uuid: &str, payload_content: Vec<Value>) -> Value {
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Integer(1.into()));
        top.insert("PayloadIdentifier".into(), s("com.acme.test"));
        top.insert("PayloadUUID".into(), s(payload_uuid));
        top.insert("PayloadDisplayName".into(), s("Test"));
        top.insert("PayloadContent".into(), Value::Array(payload_content));
        Value::Dictionary(top)
    }

    fn nested(payload_type: &str, uuid: &str) -> Value {
        let mut d = Dictionary::new();
        d.insert("PayloadType".into(), s(payload_type));
        d.insert("PayloadVersion".into(), Value::Integer(1.into()));
        d.insert("PayloadIdentifier".into(), s("com.acme.test.inner"));
        d.insert("PayloadUUID".into(), s(uuid));
        Value::Dictionary(d)
    }

    // ── 1a duplicate PayloadUUIDs ──

    #[test]
    fn duplicate_uuids_across_tree_are_flagged() {
        let dup = "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D";
        let profile = build_profile(
            "11111111-2222-3333-4444-555555555555",
            vec![
                nested("com.apple.passcode", dup),
                nested("com.apple.firewall", dup),
            ],
        );
        let findings = check_duplicate_payload_uuids(&profile);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "duplicate-payload-uuid");
        assert!(findings[0].message.contains(dup));
    }

    #[test]
    fn no_duplicates_means_no_findings() {
        let profile = build_profile(
            "11111111-2222-3333-4444-555555555555",
            vec![
                nested("com.apple.passcode", "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
                nested("com.apple.firewall", "B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E"),
            ],
        );
        assert!(check_duplicate_payload_uuids(&profile).is_empty());
    }

    // ── 1b PayloadVersion type ──

    #[test]
    fn real_payload_version_is_flagged() {
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Real(1.0));
        top.insert("PayloadIdentifier".into(), s("com.acme.test"));
        top.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
        let findings = check_payload_version_type(&Value::Dictionary(top));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "payload-version-type");
        assert_eq!(findings[0].severity, LintSeverity::Warning);
    }

    #[test]
    fn integer_payload_version_passes() {
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Integer(1.into()));
        top.insert("PayloadIdentifier".into(), s("com.acme.test"));
        top.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
        assert!(check_payload_version_type(&Value::Dictionary(top)).is_empty());
    }

    #[test]
    fn nested_real_payload_version_is_flagged_with_index() {
        let mut nested_dict = Dictionary::new();
        nested_dict.insert("PayloadType".into(), s("com.apple.passcode"));
        nested_dict.insert("PayloadVersion".into(), Value::Real(1.0));
        nested_dict.insert("PayloadIdentifier".into(), s("com.acme.inner"));
        nested_dict.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
        let profile = build_profile(
            "11111111-2222-3333-4444-555555555555",
            vec![Value::Dictionary(nested_dict)],
        );
        let findings = check_payload_version_type(&profile);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].payload_index, Some(0));
    }

    // ── 1c placeholder UUIDs ──

    #[test]
    fn placeholder_uuid_at_top_level_flagged() {
        let profile = build_profile("00000000-0000-0000-0000-000000000000", vec![]);
        let findings = check_placeholder_uuids(&profile);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "placeholder-payload-uuid");
    }

    #[test]
    fn placeholder_uuid_in_nested_payload_flagged() {
        let profile = build_profile(
            "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D",
            vec![nested(
                "com.apple.passcode",
                "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            )],
        );
        let findings = check_placeholder_uuids(&profile);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].payload_index, Some(0));
    }

    // ── 1d deprecated PayloadType ──

    #[test]
    fn softwareupdate_is_flagged_as_deprecated() {
        let registry = MigrationRegistry::new();
        let profile = build_profile(
            "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D",
            vec![nested(
                "com.apple.SoftwareUpdate",
                "B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E",
            )],
        );
        let findings = check_deprecated_payload_types(&profile, &registry);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "deprecated-payload-type");
        assert!(findings[0].message.contains("softwareupdate"));
    }

    #[test]
    fn unknown_payload_type_is_not_flagged() {
        let registry = MigrationRegistry::new();
        let profile = build_profile(
            "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D",
            vec![nested(
                "com.example.private.something",
                "B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E",
            )],
        );
        assert!(check_deprecated_payload_types(&profile, &registry).is_empty());
    }

    // ── full lint pass smoke ──

    #[test]
    fn lint_profile_aggregates_all_checks() {
        let registry = MigrationRegistry::new();
        // A fixture that triggers all four checks at once.
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Real(1.0)); // 1b
        top.insert("PayloadIdentifier".into(), s("com.acme.test"));
        top.insert(
            "PayloadUUID".into(),
            s("00000000-0000-0000-0000-000000000000"), // 1c
        );
        // Two nested payloads with the same UUID + a deprecated PayloadType.
        let dup = "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D";
        let mut a = Dictionary::new();
        a.insert("PayloadType".into(), s("com.apple.SoftwareUpdate")); // 1d
        a.insert("PayloadUUID".into(), s(dup));
        let mut b = Dictionary::new();
        b.insert("PayloadType".into(), s("com.apple.firewall"));
        b.insert("PayloadUUID".into(), s(dup)); // 1a
        top.insert(
            "PayloadContent".into(),
            Value::Array(vec![Value::Dictionary(a), Value::Dictionary(b)]),
        );
        let findings = lint_profile(&Value::Dictionary(top), &registry);
        let names: std::collections::HashSet<&str> = findings.iter().map(|f| f.check).collect();
        assert!(names.contains("duplicate-payload-uuid"), "1a fired");
        assert!(names.contains("payload-version-type"), "1b fired");
        assert!(names.contains("placeholder-payload-uuid"), "1c fired");
        assert!(names.contains("deprecated-payload-type"), "1d fired");
    }

    // ── 2a payload-identifier-reverse-dns ──

    #[test]
    fn bare_uuid_payload_identifier_flagged() {
        let bare = "C1B2A3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D";
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Integer(1.into()));
        top.insert("PayloadIdentifier".into(), s(bare));
        top.insert("PayloadUUID".into(), s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"));
        let findings = check_payload_identifier_reverse_dns(&Value::Dictionary(top));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "payload-identifier-reverse-dns");
    }

    #[test]
    fn reverse_dns_identifier_passes() {
        let mut top = Dictionary::new();
        top.insert("PayloadIdentifier".into(), s("com.acme.passcode"));
        assert!(check_payload_identifier_reverse_dns(&Value::Dictionary(top)).is_empty());
    }

    // ── 2b payload-organization-required ──

    #[test]
    fn missing_payload_organization_flagged() {
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        // No PayloadOrganization
        let findings = check_payload_organization_required(&Value::Dictionary(top));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "payload-organization-required");
    }

    #[test]
    fn empty_payload_organization_flagged() {
        let mut top = Dictionary::new();
        top.insert("PayloadOrganization".into(), s(""));
        let findings = check_payload_organization_required(&Value::Dictionary(top));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn payload_organization_set_passes() {
        let mut top = Dictionary::new();
        top.insert("PayloadOrganization".into(), s("Acme"));
        assert!(check_payload_organization_required(&Value::Dictionary(top)).is_empty());
    }

    // ── 2c payload-scope-consistency ──

    #[test]
    fn system_only_payload_with_user_scope_flagged() {
        let mut child = Dictionary::new();
        child.insert("PayloadType".into(), s("com.apple.MCXFileVault2"));
        child.insert("PayloadIdentifier".into(), s("com.acme.fv"));
        child.insert("PayloadUUID".into(), s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"));
        let mut top = Dictionary::new();
        top.insert("PayloadScope".into(), s("User"));
        top.insert("PayloadIdentifier".into(), s("com.acme.test"));
        top.insert(
            "PayloadContent".into(),
            Value::Array(vec![Value::Dictionary(child)]),
        );
        let findings = check_payload_scope_consistency(&Value::Dictionary(top));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "payload-scope-consistency");
    }

    #[test]
    fn system_only_payload_with_system_scope_passes() {
        let mut child = Dictionary::new();
        child.insert("PayloadType".into(), s("com.apple.MCXFileVault2"));
        let mut top = Dictionary::new();
        top.insert("PayloadScope".into(), s("System"));
        top.insert(
            "PayloadContent".into(),
            Value::Array(vec![Value::Dictionary(child)]),
        );
        assert!(check_payload_scope_consistency(&Value::Dictionary(top)).is_empty());
    }

    // ── 2d nested-payload-identifier-prefix ──

    #[test]
    fn unrelated_nested_identifier_flagged() {
        let mut child = Dictionary::new();
        child.insert("PayloadIdentifier".into(), s("com.othervendor.mcx"));
        let mut top = Dictionary::new();
        top.insert("PayloadIdentifier".into(), s("com.acme.test"));
        top.insert(
            "PayloadContent".into(),
            Value::Array(vec![Value::Dictionary(child)]),
        );
        let findings = check_nested_payload_identifier_prefix(&Value::Dictionary(top));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "nested-payload-identifier-prefix");
    }

    #[test]
    fn prefixed_nested_identifier_passes() {
        let mut child = Dictionary::new();
        child.insert("PayloadIdentifier".into(), s("com.acme.test.passcode"));
        let mut top = Dictionary::new();
        top.insert("PayloadIdentifier".into(), s("com.acme.test"));
        top.insert(
            "PayloadContent".into(),
            Value::Array(vec![Value::Dictionary(child)]),
        );
        assert!(check_nested_payload_identifier_prefix(&Value::Dictionary(top)).is_empty());
    }

    // ── strict-mode promotion + selection ──

    #[test]
    fn strict_promotes_warnings_to_errors_on_tier_2() {
        // A profile with a bare-UUID PayloadIdentifier triggers
        // payload-identifier-reverse-dns at warn (default) → error (strict).
        let bare = "C1B2A3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D";
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Integer(1.into()));
        top.insert("PayloadIdentifier".into(), s(bare));
        top.insert("PayloadUUID".into(), s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"));
        top.insert("PayloadOrganization".into(), s("Acme"));
        let registry = MigrationRegistry::new();
        let value = Value::Dictionary(top);

        let default = lint_profile_with_options(&value, &registry, &LintOptions::default());
        let strict = lint_profile_with_options(
            &value,
            &registry,
            &LintOptions { strict: true, selected_checks: None },
        );

        let default_severity = default
            .iter()
            .find(|f| f.check == "payload-identifier-reverse-dns")
            .map(|f| f.severity);
        let strict_severity = strict
            .iter()
            .find(|f| f.check == "payload-identifier-reverse-dns")
            .map(|f| f.severity);

        assert_eq!(default_severity, Some(LintSeverity::Warning));
        assert_eq!(strict_severity, Some(LintSeverity::Error));
    }

    #[test]
    fn off_by_default_check_only_fires_in_strict() {
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Integer(1.into()));
        top.insert("PayloadIdentifier".into(), s("com.acme.test"));
        top.insert("PayloadUUID".into(), s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"));
        // No PayloadOrganization — payload-organization-required triggers.
        let registry = MigrationRegistry::new();
        let value = Value::Dictionary(top);

        let default = lint_profile_with_options(&value, &registry, &LintOptions::default());
        assert!(
            !default.iter().any(|f| f.check == "payload-organization-required"),
            "off-by-default check must NOT fire without --strict"
        );

        let strict = lint_profile_with_options(
            &value,
            &registry,
            &LintOptions { strict: true, selected_checks: None },
        );
        assert!(
            strict.iter().any(|f| f.check == "payload-organization-required"),
            "off-by-default check MUST fire in --strict"
        );
    }

    #[test]
    fn selected_checks_filters_to_named_only() {
        // Profile with multiple defects.
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Real(1.0)); // tier-1 fires
        top.insert("PayloadIdentifier".into(), s("bare"));      // tier-2 fires (default)
        top.insert("PayloadUUID".into(), s("00000000-0000-0000-0000-000000000000")); // tier-1 fires
        let registry = MigrationRegistry::new();
        let value = Value::Dictionary(top);

        let mut only = std::collections::HashSet::new();
        only.insert("placeholder-payload-uuid".to_string());

        let result = lint_profile_with_options(
            &value,
            &registry,
            &LintOptions {
                strict: false,
                selected_checks: Some(only),
            },
        );
        let names: std::collections::HashSet<&str> = result.iter().map(|f| f.check).collect();
        assert_eq!(names.len(), 1);
        assert!(names.contains("placeholder-payload-uuid"));
    }
}
