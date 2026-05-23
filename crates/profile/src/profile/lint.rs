//! Profile lint checks — Apple-spec-adjacent issues that the structural
//! validator alone misses, plus an organizational-policy tier reserved
//! for opt-in callers.
//!
//! These checks operate on the raw `plist::Value` tree (post-parse,
//! pre-deserialization) so they can:
//!
//! - Inspect the literal plist tag of a value (`<integer>1</integer>` vs
//!   `<real>1.0</real>`) to detect type coercion that hides spec violations
//! - Walk every nested dict to collect cross-payload state (duplicate
//!   PayloadUUIDs, deprecated PayloadType usage)
//!
//! Each finding carries a stable `check` name so callers can map a
//! finding back to its trap fixture and to the SOP step that triggers
//! the workflow.
//!
//! ## Tiers
//!
//! **Tier 1 (Apple-spec-adjacent, always on)**: `duplicate-payload-uuid`,
//! `payload-version-type`, `placeholder-payload-uuid`,
//! `deprecated-payload-type`. Fired by `lint_profile_with_options` and
//! surfaced through `profile validate`. These hurt any Apple-profile
//! authoring workflow,
//! regardless of vendor.
//!
//! **Tier 2 (org-policy, opt-in)**: `payload-identifier-reverse-dns`,
//! `payload-organization-required`, `payload-scope-consistency`,
//! `nested-payload-identifier-prefix`. Off by default; callers opt in
//! via `LintOptions::selected_checks` or the
//! `validate --lint-policy <names|all>` CLI flag. `--strict` promotes
//! Tier-2 warnings to errors but does NOT widen the check set —
//! `--lint-policy` is the only opt-in. Default `validate` stays
//! Apple-schema-only; organizational conventions are off the agent's
//! path until explicitly requested.

use crate::migrate::mapping::MigrationRegistry;
use crate::profile::deprecation;
use crate::schema::SchemaRegistry;
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

/// Tier-1 (Apple-spec-adjacent) check names — always fired by
/// `lint_profile_with_options` regardless of `selected_checks`.
pub const TIER_1_CHECKS: &[&str] = &[
    "duplicate-payload-uuid",
    "payload-version-type",
    "nested-missing-payload-version",
    "placeholder-payload-uuid",
    "deprecated-payload-type",
    "deprecated-key",
    "single-instance-payload-repeated",
];

/// Tier-2 (org-policy) check names — opt-in via
/// `LintOptions::selected_checks` or the `validate --lint-policy` CLI
/// flag.
pub const TIER_2_CHECKS: &[&str] = &[
    "payload-identifier-reverse-dns",
    "payload-organization-required",
    "payload-scope-consistency",
    "nested-payload-identifier-prefix",
];

/// Selection knobs for the lint pass. Tier-1 always fires; Tier-2
/// (org-policy) is opt-in via `selected_checks`.
///
/// `validate` (without `--lint-policy`) constructs a `LintOptions`
/// with `selected_checks: None` and gets Tier-1 only. Callers that
/// want Tier-2 checks construct an explicit `selected_checks` set
/// containing the Tier-2 names — `strict` is severity-only and does
/// NOT widen the check set.
#[derive(Debug, Clone, Default)]
pub struct LintOptions {
    /// Severity promotion: Tier-2 warnings become errors. Does not
    /// widen the check set — Tier-2 stays opt-in via `selected_checks`.
    pub strict: bool,
    /// Opt into specific checks by name. `Some(set)` runs only the
    /// listed checks; `None` runs the Tier-1 defaults.
    pub selected_checks: Option<std::collections::HashSet<String>>,
    /// Map of `payload_type → apply_mode` used by the
    /// `single-instance-payload-repeated` check to resolve schema
    /// constraints. Empty map = check is a no-op (no schema data
    /// available).
    pub apply_modes: std::collections::HashMap<String, String>,
}

impl LintOptions {
    fn includes(&self, name: &str) -> bool {
        match &self.selected_checks {
            Some(set) => set.contains(name),
            // No explicit selection: Tier 1 only. Tier 2 (org-policy)
            // is opt-in via `selected_checks` — callers construct the
            // set explicitly. `strict` only promotes severity; it does
            // NOT widen the check set.
            None => matches!(
                name,
                "duplicate-payload-uuid"
                    | "payload-version-type"
                    | "nested-missing-payload-version"
                    | "placeholder-payload-uuid"
                    | "deprecated-payload-type"
                    | "deprecated-key"
                    | "single-instance-payload-repeated"
            ),
        }
    }

    /// Resolve the severity for a given check based on strict mode.
    ///
    /// Tier 1 checks have a fixed severity regardless of strict
    /// (the per-check function chose error vs warning at write time).
    /// Tier 2 checks promote warning → error in strict.
    fn promote_if_strict(&self, finding: LintFinding) -> LintFinding {
        if self.strict
            && matches!(finding.severity, LintSeverity::Warning)
            && is_tier_2(finding.check)
        {
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

/// Run lint checks with explicit options.
///
/// Filters by `options.includes(check)` and applies strict severity
/// promotion via `options.promote_if_strict`. Unknown check names in
/// `selected_checks` are silently ignored — caller is responsible for
/// validating CLI input. The `validate` CLI handler does this via
/// `resolve_lint_options` in `cli/validate.rs`.
pub fn lint_profile_with_options(
    value: &Value,
    registry: &MigrationRegistry,
    schema: Option<&SchemaRegistry>,
    options: &LintOptions,
) -> Vec<LintFinding> {
    let mut all = Vec::new();
    if options.includes("duplicate-payload-uuid") {
        all.extend(check_duplicate_payload_uuids(value));
    }
    if options.includes("payload-version-type") {
        all.extend(check_payload_version_type(value));
    }
    if options.includes("nested-missing-payload-version") {
        all.extend(check_nested_missing_payload_version(value));
    }
    if options.includes("placeholder-payload-uuid") {
        all.extend(check_placeholder_uuids(value));
    }
    if options.includes("deprecated-payload-type") {
        all.extend(check_deprecated_payload_types(value, registry));
    }
    if options.includes("deprecated-key")
        && let Some(sch) = schema
    {
        all.extend(check_deprecated_keys(value, sch));
    }
    if options.includes("single-instance-payload-repeated") {
        all.extend(check_single_instance_payload_repeated(
            value,
            &options.apply_modes,
        ));
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

// ── 1b'. Nested missing PayloadVersion ─────────────────────────────────

/// Apple's spec requires `PayloadVersion` on every payload — top-level
/// AND nested. The structural validator catches a missing top-level
/// version (required-field check), but nested entries silently
/// deserialize with a default value when the key is absent, masking
/// real-world authoring drift.
///
/// We inspect the raw plist tree so absence is observable: a nested
/// dict that has `PayloadType` but lacks the literal `PayloadVersion`
/// key is flagged as an error.
pub fn check_nested_missing_payload_version(value: &Value) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    let Value::Dictionary(top) = value else {
        return findings;
    };
    let Some(Value::Array(items)) = top.get("PayloadContent") else {
        return findings;
    };
    for (idx, item) in items.iter().enumerate() {
        let Value::Dictionary(child) = item else {
            continue;
        };
        // Only meaningful for entries that look like a payload
        // (`PayloadType` present). Plain config dicts inside other
        // keys are out of scope.
        if child.get("PayloadType").is_none() {
            continue;
        }
        if child.get("PayloadVersion").is_none() {
            findings.push(
                LintFinding::error(
                    "nested-missing-payload-version",
                    format!(
                        "PayloadContent[{idx}]: required field PayloadVersion is missing. \
                         Apple's spec requires <integer>1</integer> on every payload; \
                         absent values are silently defaulted by some MDM stacks and \
                         outright rejected by others."
                    ),
                )
                .with_payload(idx),
            );
        }
    }
    findings
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
/// Lint adapter: deprecated payload types. Delegates detection to the
/// shared `deprecation` module and converts to `LintFinding`s.
pub fn check_deprecated_payload_types(
    value: &Value,
    registry: &MigrationRegistry,
) -> Vec<LintFinding> {
    deprecation::scan_payload_types(value, registry)
        .into_iter()
        .map(|f| {
            let lf = LintFinding::warn("deprecated-payload-type", f.detail);
            match f.payload_index {
                Some(i) => lf.with_payload(i),
                None => lf,
            }
        })
        .collect()
}

/// Lint adapter: deprecated keys. Delegates to the shared `deprecation`
/// module and converts to `LintFinding`s.
pub fn check_deprecated_keys(value: &Value, schema: &SchemaRegistry) -> Vec<LintFinding> {
    deprecation::scan_keys(value, schema)
        .into_iter()
        .map(|f| {
            let lf = LintFinding::warn("deprecated-key", f.detail);
            match f.payload_index {
                Some(i) => lf.with_payload(i),
                None => lf,
            }
        })
        .collect()
}

// ── 1e. Single-instance payload repeated ──────────────────────────────

/// Apple's schema declares some payload types as `apply_mode = "single"`
/// — only one instance of that type is supposed to appear in a profile.
/// A profile listing the same single-instance type twice in
/// `PayloadContent` produces undefined MDM behaviour: the server may
/// apply one and silently drop the other, or fail the install entirely.
///
/// `apply_modes` is the per-payload-type lookup map built by `validate`
/// at lint-time. An empty map turns the check into a no-op (consistent
/// with the other registry-backed checks). Currently warning severity:
/// schemas occasionally mislabel multi-instance configs as `"single"`,
/// so the agent should see the signal without being blocked.
pub fn check_single_instance_payload_repeated<S: ::std::hash::BuildHasher>(
    value: &Value,
    apply_modes: &std::collections::HashMap<String, String, S>,
) -> Vec<LintFinding> {
    use std::collections::HashMap;
    let mut findings = Vec::new();
    let Value::Dictionary(top) = value else {
        return findings;
    };
    let Some(Value::Array(items)) = top.get("PayloadContent") else {
        return findings;
    };
    // Count occurrences of each PayloadType across the nested entries.
    let mut counts: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, item) in items.iter().enumerate() {
        let Value::Dictionary(child) = item else {
            continue;
        };
        if let Some(payload_type) = child.get("PayloadType").and_then(Value::as_string) {
            counts.entry(payload_type).or_default().push(idx);
        }
    }
    for (payload_type, indices) in counts {
        if indices.len() < 2 {
            continue;
        }
        let Some(mode) = apply_modes.get(payload_type) else {
            continue; // unknown apply_mode — no signal either way
        };
        if mode != "single" {
            continue;
        }
        findings.push(LintFinding::warn(
            "single-instance-payload-repeated",
            format!(
                "PayloadType {payload_type:?} is declared apply_mode=\"single\" \
                 in Apple's schema but appears {n} times in PayloadContent \
                 (at indices {indices:?}). Single-instance payloads should \
                 only appear once; deploying multiple copies produces \
                 undefined MDM behaviour.",
                n = indices.len()
            ),
        ));
    }
    findings
}

// ── 2a. payload-identifier-reverse-dns ─────────────────────────────────

/// Apple's spec accepts any non-empty string as PayloadIdentifier.
/// Industry convention is reverse-DNS — `com.acme.passcode` — so a
/// bare UUID or single-segment string slips through Apple-strict but
/// will collide in any GitOps repo with multiple profiles. Default
/// severity: warning. Strict severity: error (promoted by the caller).
///
/// Tier-2 (org-policy). Library-only — not wired into `validate`.
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
        findings.push(if let Some(i) = idx {
            f.with_payload(i)
        } else {
            f
        });
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
/// audit conventions — without it, profiles can't be attributed to a
/// vendor in GitOps logs. Off by default; fires in strict.
///
/// Tier-2 (org-policy). Library-only — not wired into `validate`.
pub fn check_payload_organization_required(value: &Value) -> Vec<LintFinding> {
    let Value::Dictionary(dict) = value else {
        return Vec::new();
    };
    let org = dict.get("PayloadOrganization").and_then(Value::as_string);
    if org.is_none_or(str::is_empty) {
        vec![LintFinding::warn(
            "payload-organization-required",
            "Profile: PayloadOrganization is missing or empty. Audit \
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

/// Tier-2 (org-policy). Library-only — not wired into `validate`.
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
/// top-level PayloadIdentifier — an audit convention that makes
/// profile attribution unambiguous and prevents PayloadIdentifier
/// collisions across profiles authored by different teams. Default
/// warning; strict error.
///
/// Tier-2 (org-policy). Library-only — not wired into `validate`.
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

    // ── 1b' nested missing PayloadVersion ──

    #[test]
    fn nested_missing_payload_version_flagged() {
        let mut child = Dictionary::new();
        child.insert("PayloadType".into(), s("com.apple.passcode"));
        // intentionally omit PayloadVersion
        child.insert("PayloadIdentifier".into(), s("com.acme.test.passcode"));
        child.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
        let profile = build_profile(
            "11111111-2222-3333-4444-555555555555",
            vec![Value::Dictionary(child)],
        );
        let findings = check_nested_missing_payload_version(&profile);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "nested-missing-payload-version");
        assert_eq!(findings[0].severity, LintSeverity::Error);
        assert_eq!(findings[0].payload_index, Some(0));
    }

    #[test]
    fn nested_payload_version_present_passes() {
        let profile = build_profile(
            "11111111-2222-3333-4444-555555555555",
            vec![nested(
                "com.apple.passcode",
                "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D",
            )],
        );
        assert!(check_nested_missing_payload_version(&profile).is_empty());
    }

    #[test]
    fn nested_dict_without_payload_type_is_skipped() {
        // A dict without PayloadType isn't a payload — skip it rather
        // than false-positive on inner config sub-dicts.
        let mut not_a_payload = Dictionary::new();
        not_a_payload.insert("SomeConfigKey".into(), s("value"));
        let profile = build_profile(
            "11111111-2222-3333-4444-555555555555",
            vec![Value::Dictionary(not_a_payload)],
        );
        assert!(check_nested_missing_payload_version(&profile).is_empty());
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

    #[test]
    fn deprecated_key_lint_check_fires() {
        let schema = crate::schema::SchemaRegistry::embedded().expect("embedded schema");
        // Find a (payload type, key) the schema marks deprecated.
        let mut probe = None;
        for manifest in schema.all() {
            for (name, field) in &manifest.fields {
                if field.deprecated_in.is_some() {
                    probe = Some((manifest.payload_type.clone(), name.clone()));
                    break;
                }
            }
            if probe.is_some() {
                break;
            }
        }
        let Some((payload_type, key)) = probe else {
            return; // no deprecated keys in this schema build
        };
        let mut p = Dictionary::new();
        p.insert("PayloadType".into(), s(&payload_type));
        p.insert("PayloadIdentifier".into(), s("com.test.p"));
        p.insert(
            "PayloadUUID".into(),
            s("B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E"),
        );
        p.insert("PayloadVersion".into(), Value::Integer(1.into()));
        p.insert(key, Value::Boolean(true));
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert(
            "PayloadContent".into(),
            Value::Array(vec![Value::Dictionary(p)]),
        );
        let findings = check_deprecated_keys(&Value::Dictionary(top), &schema);
        assert!(findings.iter().any(|f| f.check == "deprecated-key"));
    }

    // ── 1e single-instance payload repeated ──

    #[test]
    fn single_instance_payload_repeated_flagged() {
        // Two nested payloads sharing the same single-instance PayloadType.
        let mut a = Dictionary::new();
        a.insert("PayloadType".into(), s("com.apple.demo.single"));
        a.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
        let mut b = Dictionary::new();
        b.insert("PayloadType".into(), s("com.apple.demo.single"));
        b.insert(
            "PayloadUUID".into(),
            s("B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E"),
        );
        let profile = build_profile(
            "11111111-2222-3333-4444-555555555555",
            vec![Value::Dictionary(a), Value::Dictionary(b)],
        );
        let mut apply_modes = std::collections::HashMap::new();
        apply_modes.insert("com.apple.demo.single".to_string(), "single".to_string());
        let findings = check_single_instance_payload_repeated(&profile, &apply_modes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "single-instance-payload-repeated");
        assert_eq!(findings[0].severity, LintSeverity::Warning);
    }

    #[test]
    fn multiple_apply_mode_does_not_flag_duplicates() {
        // Same shape as above but apply_mode is "multiple" — no finding.
        let mut a = Dictionary::new();
        a.insert("PayloadType".into(), s("com.apple.demo.multi"));
        a.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
        let mut b = Dictionary::new();
        b.insert("PayloadType".into(), s("com.apple.demo.multi"));
        b.insert(
            "PayloadUUID".into(),
            s("B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E"),
        );
        let profile = build_profile(
            "11111111-2222-3333-4444-555555555555",
            vec![Value::Dictionary(a), Value::Dictionary(b)],
        );
        let mut apply_modes = std::collections::HashMap::new();
        apply_modes.insert("com.apple.demo.multi".to_string(), "multiple".to_string());
        assert!(check_single_instance_payload_repeated(&profile, &apply_modes).is_empty());
    }

    #[test]
    fn missing_apply_mode_is_silent() {
        // No apply_mode entry → no signal either way.
        let mut a = Dictionary::new();
        a.insert("PayloadType".into(), s("com.apple.demo.unknown"));
        a.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
        let mut b = Dictionary::new();
        b.insert("PayloadType".into(), s("com.apple.demo.unknown"));
        b.insert(
            "PayloadUUID".into(),
            s("B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E"),
        );
        let profile = build_profile(
            "11111111-2222-3333-4444-555555555555",
            vec![Value::Dictionary(a), Value::Dictionary(b)],
        );
        let apply_modes = std::collections::HashMap::new();
        assert!(check_single_instance_payload_repeated(&profile, &apply_modes).is_empty());
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
        let findings = lint_profile_with_options(
            &Value::Dictionary(top),
            &registry,
            None,
            &LintOptions::default(),
        );
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
        top.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
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
        child.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
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
    fn strict_promotes_tier_2_warning_to_error_when_explicitly_selected() {
        // Tier-2 is opt-in via selected_checks. With opt-in + strict,
        // warning → error promotion fires.
        let bare = "C1B2A3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D";
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Integer(1.into()));
        top.insert("PayloadIdentifier".into(), s(bare));
        top.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
        top.insert("PayloadOrganization".into(), s("Acme"));
        let registry = MigrationRegistry::new();
        let value = Value::Dictionary(top);

        let mut tier_2 = std::collections::HashSet::new();
        tier_2.insert("payload-identifier-reverse-dns".to_string());

        let opted_in = lint_profile_with_options(
            &value,
            &registry,
            None,
            &LintOptions {
                strict: false,
                selected_checks: Some(tier_2.clone()),
                apply_modes: std::collections::HashMap::new(),
            },
        );
        let opted_in_strict = lint_profile_with_options(
            &value,
            &registry,
            None,
            &LintOptions {
                strict: true,
                selected_checks: Some(tier_2),
                apply_modes: std::collections::HashMap::new(),
            },
        );

        let default_severity = opted_in
            .iter()
            .find(|f| f.check == "payload-identifier-reverse-dns")
            .map(|f| f.severity);
        let strict_severity = opted_in_strict
            .iter()
            .find(|f| f.check == "payload-identifier-reverse-dns")
            .map(|f| f.severity);

        assert_eq!(default_severity, Some(LintSeverity::Warning));
        assert_eq!(strict_severity, Some(LintSeverity::Error));
    }

    #[test]
    fn tier_2_off_by_default_unless_explicitly_selected() {
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Integer(1.into()));
        top.insert("PayloadIdentifier".into(), s("com.acme.test"));
        top.insert(
            "PayloadUUID".into(),
            s("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"),
        );
        // No PayloadOrganization — payload-organization-required would
        // fire if selected.
        let registry = MigrationRegistry::new();
        let value = Value::Dictionary(top);

        // Default mode: Tier-2 silent.
        let default = lint_profile_with_options(&value, &registry, None, &LintOptions::default());
        assert!(
            !default
                .iter()
                .any(|f| f.check == "payload-organization-required"),
            "Tier-2 must NOT fire without explicit selected_checks"
        );

        // Strict alone: still silent. Strict only promotes severity, it
        // does NOT widen the check set — Tier-2 stays opt-in.
        let strict_only = lint_profile_with_options(
            &value,
            &registry,
            None,
            &LintOptions {
                strict: true,
                selected_checks: None,
                apply_modes: std::collections::HashMap::new(),
            },
        );
        assert!(
            !strict_only
                .iter()
                .any(|f| f.check == "payload-organization-required"),
            "strict alone must NOT widen the check set"
        );

        // Explicit opt-in via selected_checks fires Tier-2.
        let mut tier_2 = std::collections::HashSet::new();
        tier_2.insert("payload-organization-required".to_string());
        let opted_in = lint_profile_with_options(
            &value,
            &registry,
            None,
            &LintOptions {
                strict: false,
                selected_checks: Some(tier_2),
                apply_modes: std::collections::HashMap::new(),
            },
        );
        assert!(
            opted_in
                .iter()
                .any(|f| f.check == "payload-organization-required"),
            "explicit selected_checks MUST fire the named Tier-2 check"
        );
    }

    #[test]
    fn selected_checks_filters_to_named_only() {
        // Profile with multiple defects.
        let mut top = Dictionary::new();
        top.insert("PayloadType".into(), s("Configuration"));
        top.insert("PayloadVersion".into(), Value::Real(1.0)); // tier-1 fires
        top.insert("PayloadIdentifier".into(), s("bare")); // tier-2 fires (default)
        top.insert(
            "PayloadUUID".into(),
            s("00000000-0000-0000-0000-000000000000"),
        ); // tier-1 fires
        let registry = MigrationRegistry::new();
        let value = Value::Dictionary(top);

        let mut only = std::collections::HashSet::new();
        only.insert("placeholder-payload-uuid".to_string());

        let result = lint_profile_with_options(
            &value,
            &registry,
            None,
            &LintOptions {
                strict: false,
                selected_checks: Some(only),
                apply_modes: std::collections::HashMap::new(),
            },
        );
        let names: std::collections::HashSet<&str> = result.iter().map(|f| f.check).collect();
        assert_eq!(names.len(), 1);
        assert!(names.contains("placeholder-payload-uuid"));
    }
}
