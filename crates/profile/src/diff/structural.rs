//! Structural diff — payload by payload, key by key.
//!
//! [`diff_profiles`](super::diff_profiles) compares two profiles as text:
//! serialise both to XML, run a line diff. That is the right tool for a code
//! review and the wrong one for anything programmatic. Two profiles that
//! differ in one Wi-Fi setting also differ in every `PayloadUUID` and
//! `PayloadIdentifier` line, because those differ by construction, and the
//! result cannot say "`FilterGrade` changed while `FilterSockets` agrees" —
//! only that line 24 did.
//!
//! This module answers the second question. Payloads are paired across the
//! two profiles by `PayloadType` plus `PayloadDisplayName` — never by UUID,
//! which is exactly the thing that is expected to differ — and each pair is
//! walked to its leaves. Every leaf gets a dotted path and one of four
//! statuses. Identity keys are reported like any other, but marked, so a
//! consumer can drop them in one filter instead of pattern-matching prose.
//!
//! ## Paths
//!
//! Keys may contain dots — Apple's own managed-preference keys do
//! (`com.apple.EnergySaver.desktop.ACPower`) — so a segment's `.`, `[`, `]`
//! and `\` are backslash-escaped before joining. Array elements are addressed
//! by index: `Services.SystemPolicyAllFiles[0].Allowed`. [`split_path`]
//! inverts [`join_path`] exactly, and a test pins that.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

use crate::profile::{ConfigurationProfile, PayloadContent};

/// What happened to one leaf, or to one payload as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Added,
    Removed,
    Changed,
    Unchanged,
}

/// One leaf value, addressed by path.
#[derive(Debug, Clone, Serialize)]
pub struct FieldDiff {
    /// Escaped dotted path from the payload root; see the module docs.
    pub path: String,
    pub status: Status,
    /// `true` for the `Payload*` bookkeeping keys — UUID, identifier,
    /// version, display name and so on — which differ by construction
    /// between two independently generated profiles and are rarely what a
    /// consumer is asking about.
    pub metadata: bool,
    /// The baseline value, absent when the leaf was added.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<Json>,
    /// The proposed value, absent when the leaf was removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed: Option<Json>,
}

/// Leaf tallies for one payload, or for the whole diff.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub unchanged: usize,
}

impl Counts {
    fn record(&mut self, status: Status) {
        match status {
            Status::Added => self.added += 1,
            Status::Removed => self.removed += 1,
            Status::Changed => self.changed += 1,
            Status::Unchanged => self.unchanged += 1,
        }
    }

    fn absorb(&mut self, other: Counts) {
        self.added += other.added;
        self.removed += other.removed;
        self.changed += other.changed;
        self.unchanged += other.unchanged;
    }

    /// Anything other than unchanged leaves.
    pub fn differences(&self) -> usize {
        self.added + self.removed + self.changed
    }
}

/// One payload, paired across the two profiles or present on one side only.
#[derive(Debug, Clone, Serialize)]
pub struct PayloadDiff {
    /// `PayloadType`, then ` · ` and the display name when there is one, then
    /// `#n` when that still does not distinguish it from a sibling.
    pub identity: String,
    pub payload_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// `Added` / `Removed` for one-sided payloads; otherwise `Changed` when
    /// any leaf differs, `Unchanged` when none does.
    pub status: Status,
    pub fields: Vec<FieldDiff>,
    pub counts: Counts,
}

/// The whole comparison.
#[derive(Debug, Clone, Serialize)]
pub struct StructuralDiff {
    /// Label for the first profile, as given by the caller.
    pub baseline: String,
    /// Label for the second.
    pub proposed: String,
    /// Top-level profile keys, outside `PayloadContent`.
    pub profile: Vec<FieldDiff>,
    pub payloads: Vec<PayloadDiff>,
    pub counts: Counts,
    pub has_differences: bool,
}

impl StructuralDiff {
    /// Drop metadata leaves everywhere, keeping the tallies honest.
    ///
    /// A payload whose only differences were bookkeeping keys becomes
    /// `Unchanged` — that is the point of asking.
    pub fn settings_only(mut self) -> Self {
        self.profile.retain(|f| !f.metadata);
        for p in &mut self.payloads {
            p.fields.retain(|f| !f.metadata);
            p.counts = tally(&p.fields);
            if matches!(p.status, Status::Changed | Status::Unchanged) {
                p.status = if p.counts.differences() > 0 {
                    Status::Changed
                } else {
                    Status::Unchanged
                };
            }
        }
        self.counts = tally(&self.profile);
        for p in &self.payloads {
            self.counts.absorb(p.counts);
        }
        self.has_differences = self.counts.differences() > 0;
        self
    }
}

fn tally(fields: &[FieldDiff]) -> Counts {
    let mut c = Counts::default();
    for f in fields {
        c.record(f.status);
    }
    c
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Escape one key so it can be joined with `.` and split back unambiguously.
pub fn escape_segment(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for ch in key.chars() {
        if matches!(ch, '.' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// `parent.child`, or `child` at the root. `child` must already be escaped
/// (or be an index like `[3]`, which attaches without a dot).
pub fn join_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else if child.starts_with('[') {
        format!("{parent}{child}")
    } else {
        format!("{parent}.{child}")
    }
}

/// One step of a split path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathStep {
    Key(String),
    Index(usize),
}

/// Inverse of [`join_path`] over escaped segments.
///
/// Returns `None` if the path is malformed — an unterminated `[`, a non-digit
/// index, a trailing backslash. Anything this module produced splits cleanly.
pub fn split_path(path: &str) -> Option<Vec<PathStep>> {
    let mut steps = Vec::new();
    let mut key = String::new();
    let mut have_key = false;
    let mut chars = path.chars().peekable();

    let flush = |key: &mut String, have_key: &mut bool, steps: &mut Vec<PathStep>| {
        if *have_key {
            steps.push(PathStep::Key(std::mem::take(key)));
            *have_key = false;
        }
    };

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                key.push(chars.next()?);
                have_key = true;
            }
            '.' => flush(&mut key, &mut have_key, &mut steps),
            '[' => {
                flush(&mut key, &mut have_key, &mut steps);
                let mut digits = String::new();
                loop {
                    match chars.next()? {
                        ']' => break,
                        d if d.is_ascii_digit() => digits.push(d),
                        _ => return None,
                    }
                }
                steps.push(PathStep::Index(digits.parse().ok()?));
            }
            other => {
                key.push(other);
                have_key = true;
            }
        }
    }
    flush(&mut key, &mut have_key, &mut steps);
    Some(steps)
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Render a plist value for the report.
///
/// Binary data becomes a length and a digest, never the bytes: certificates
/// and signed blobs run to kilobytes and a consumer wanting equality gets it
/// from the digest.
fn render(v: &plist::Value) -> Json {
    match v {
        plist::Value::Boolean(b) => json!(b),
        plist::Value::Integer(i) => i
            .as_signed()
            .map(|n| json!(n))
            .or_else(|| i.as_unsigned().map(|n| json!(n)))
            .unwrap_or(Json::Null),
        plist::Value::Real(r) => json!(r),
        plist::Value::String(s) => json!(s),
        plist::Value::Date(d) => json!(d.to_xml_format()),
        plist::Value::Uid(u) => json!(u.get()),
        plist::Value::Data(bytes) => {
            use std::fmt::Write as _;
            let hex = Sha256::digest(bytes)
                .iter()
                .fold(String::with_capacity(64), |mut s, b| {
                    let _ = write!(s, "{b:02x}");
                    s
                });
            json!({ "bytes": bytes.len(), "sha256": hex })
        }
        plist::Value::Array(items) => Json::Array(items.iter().map(render).collect()),
        plist::Value::Dictionary(d) => {
            Json::Object(d.iter().map(|(k, v)| (k.clone(), render(v))).collect())
        }
        // The plist crate reserves the right to add variants.
        _ => Json::Null,
    }
}

/// Keys Apple defines on every payload dictionary, as opposed to the settings
/// the payload carries.
const METADATA_KEYS: &[&str] = &[
    "PayloadType",
    "PayloadVersion",
    "PayloadIdentifier",
    "PayloadUUID",
    "PayloadDisplayName",
    "PayloadDescription",
    "PayloadOrganization",
    "PayloadEnabled",
    "PayloadRemovalDisallowed",
    "PayloadScope",
];

fn is_metadata(path: &str) -> bool {
    // Only top-level bookkeeping counts; a payload that nests its own
    // `PayloadContent` (MCX) is settings all the way down.
    !path.contains('.') && !path.contains('[') && METADATA_KEYS.contains(&path)
}

// ---------------------------------------------------------------------------
// Walk
// ---------------------------------------------------------------------------

/// Recurse two values in parallel, emitting one [`FieldDiff`] per leaf.
///
/// A container present on one side only is still walked, so `Services` added
/// wholesale yields `Services.SystemPolicyAllFiles[0].Allowed = added` rather
/// than one opaque `Services` leaf: a consumer asking about a path gets the
/// same answer whether or not the parent existed before.
///
/// An empty container is a leaf: otherwise `Foo = {}` on both sides would
/// vanish from the report entirely, and a consumer could not tell it from a
/// key that never existed. A type change — dict on one side, scalar on the
/// other — is also a leaf, with both values rendered whole.
fn walk(path: &str, a: Option<&plist::Value>, b: Option<&plist::Value>, out: &mut Vec<FieldDiff>) {
    use plist::Value::{Array, Dictionary};

    let da = match a {
        Some(Dictionary(d)) => Some(d),
        _ => None,
    };
    let db = match b {
        Some(Dictionary(d)) => Some(d),
        _ => None,
    };
    let dict_shaped = (a.is_none() || da.is_some()) && (b.is_none() || db.is_some());
    let any_dict_content = da.is_some_and(|d| !d.is_empty()) || db.is_some_and(|d| !d.is_empty());
    if dict_shaped && any_dict_content {
        let mut keys: Vec<&str> = Vec::new();
        if let Some(d) = da {
            keys.extend(d.keys().map(String::as_str));
        }
        if let Some(d) = db {
            keys.extend(d.keys().map(String::as_str));
        }
        keys.sort_unstable();
        keys.dedup();
        for k in keys {
            let child = join_path(path, &escape_segment(k));
            walk(
                &child,
                da.and_then(|d| d.get(k)),
                db.and_then(|d| d.get(k)),
                out,
            );
        }
        return;
    }

    let xa = match a {
        Some(Array(x)) => Some(x),
        _ => None,
    };
    let xb = match b {
        Some(Array(x)) => Some(x),
        _ => None,
    };
    let array_shaped = (a.is_none() || xa.is_some()) && (b.is_none() || xb.is_some());
    let any_array_content = xa.is_some_and(|x| !x.is_empty()) || xb.is_some_and(|x| !x.is_empty());
    if array_shaped && any_array_content {
        let len = xa.map_or(0, Vec::len).max(xb.map_or(0, Vec::len));
        for i in 0..len {
            let child = join_path(path, &format!("[{i}]"));
            walk(
                &child,
                xa.and_then(|x| x.get(i)),
                xb.and_then(|x| x.get(i)),
                out,
            );
        }
        return;
    }

    match (a, b) {
        (None, None) => {}
        (Some(va), None) => out.push(leaf(path, Status::Removed, Some(va), None)),
        (None, Some(vb)) => out.push(leaf(path, Status::Added, None, Some(vb))),
        (Some(va), Some(vb)) => {
            let status = if va == vb {
                Status::Unchanged
            } else {
                Status::Changed
            };
            out.push(leaf(path, status, Some(va), Some(vb)));
        }
    }
}

fn leaf(
    path: &str,
    status: Status,
    a: Option<&plist::Value>,
    b: Option<&plist::Value>,
) -> FieldDiff {
    FieldDiff {
        path: path.to_string(),
        status,
        metadata: is_metadata(path),
        baseline: a.map(render),
        proposed: b.map(render),
    }
}

/// A payload as one flat dictionary, struct fields folded back in, so the
/// walk sees what the plist on disk has.
fn payload_dict(p: &PayloadContent) -> plist::Dictionary {
    let mut d = plist::Dictionary::new();
    d.insert("PayloadType".into(), p.payload_type.clone().into());
    d.insert(
        "PayloadVersion".into(),
        plist::Value::Integer(p.payload_version.into()),
    );
    d.insert(
        "PayloadIdentifier".into(),
        p.payload_identifier.clone().into(),
    );
    d.insert("PayloadUUID".into(), p.payload_uuid.clone().into());
    for (k, v) in &p.content {
        d.insert(k.clone(), v.clone());
    }
    d
}

/// The profile's own keys, `PayloadContent` excluded.
fn profile_dict(p: &ConfigurationProfile) -> plist::Dictionary {
    let mut d = plist::Dictionary::new();
    d.insert("PayloadType".into(), p.payload_type.clone().into());
    d.insert(
        "PayloadVersion".into(),
        plist::Value::Integer(p.payload_version.into()),
    );
    d.insert(
        "PayloadIdentifier".into(),
        p.payload_identifier.clone().into(),
    );
    d.insert("PayloadUUID".into(), p.payload_uuid.clone().into());
    d.insert(
        "PayloadDisplayName".into(),
        p.payload_display_name.clone().into(),
    );
    for (k, v) in &p.additional_fields {
        d.insert(k.clone(), v.clone());
    }
    d
}

fn diff_dicts(a: &plist::Dictionary, b: &plist::Dictionary) -> Vec<FieldDiff> {
    let mut out = Vec::new();
    walk(
        "",
        Some(&plist::Value::Dictionary(a.clone())),
        Some(&plist::Value::Dictionary(b.clone())),
        &mut out,
    );
    out
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

/// Assign each payload an identity that is stable across regeneration.
///
/// `PayloadType` alone is not enough — a profile may legitimately carry two
/// TCC payloads or two managed-preference envelopes — and `PayloadUUID` is
/// what we are trying not to key on. Type plus display name covers the
/// realistic cases; a residual collision gets `#2`, `#3` in document order,
/// which pairs positionally and says so in the name.
fn identities(payloads: &[PayloadContent]) -> Vec<(String, &PayloadContent)> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    payloads
        .iter()
        .map(|p| {
            let base = match p.payload_display_name() {
                Some(name) if !name.trim().is_empty() => format!("{} · {}", p.payload_type, name),
                _ => p.payload_type.clone(),
            };
            let n = seen.entry(base.clone()).or_insert(0);
            *n += 1;
            let id = if *n == 1 {
                base
            } else {
                format!("{base} #{n}")
            };
            (id, p)
        })
        .collect()
}

fn one_sided(id: String, p: &PayloadContent, status: Status) -> PayloadDiff {
    let dict = payload_dict(p);
    let mut fields = Vec::new();
    let value = plist::Value::Dictionary(dict);
    match status {
        Status::Removed => walk("", Some(&value), None, &mut fields),
        _ => walk("", None, Some(&value), &mut fields),
    }
    let counts = tally(&fields);
    PayloadDiff {
        identity: id,
        payload_type: p.payload_type.clone(),
        display_name: p.payload_display_name(),
        status,
        fields,
        counts,
    }
}

/// Compare two profiles structurally. Labels are echoed into the result so a
/// JSON consumer knows which file was which.
pub fn structural_diff(
    baseline: &ConfigurationProfile,
    proposed: &ConfigurationProfile,
    baseline_label: &str,
    proposed_label: &str,
) -> StructuralDiff {
    let profile = diff_dicts(&profile_dict(baseline), &profile_dict(proposed));
    let mut counts = tally(&profile);

    let base_ids = identities(&baseline.payload_content);
    let prop_ids = identities(&proposed.payload_content);
    let prop_map: BTreeMap<&str, &PayloadContent> =
        prop_ids.iter().map(|(id, p)| (id.as_str(), *p)).collect();
    let base_map: BTreeMap<&str, &PayloadContent> =
        base_ids.iter().map(|(id, p)| (id.as_str(), *p)).collect();

    let mut payloads = Vec::new();

    // Baseline order first: paired payloads and removals, as the reader of
    // the old profile would meet them.
    for (id, bp) in &base_ids {
        match prop_map.get(id.as_str()) {
            Some(pp) => {
                let fields = diff_dicts(&payload_dict(bp), &payload_dict(pp));
                let c = tally(&fields);
                payloads.push(PayloadDiff {
                    identity: id.clone(),
                    payload_type: pp.payload_type.clone(),
                    display_name: pp.payload_display_name(),
                    status: if c.differences() > 0 {
                        Status::Changed
                    } else {
                        Status::Unchanged
                    },
                    fields,
                    counts: c,
                });
            }
            None => payloads.push(one_sided(id.clone(), bp, Status::Removed)),
        }
    }
    // Then anything only the proposed profile has.
    for (id, pp) in &prop_ids {
        if !base_map.contains_key(id.as_str()) {
            payloads.push(one_sided(id.clone(), pp, Status::Added));
        }
    }

    for p in &payloads {
        counts.absorb(p.counts);
    }

    StructuralDiff {
        baseline: baseline_label.to_string(),
        proposed: proposed_label.to_string(),
        profile,
        payloads,
        has_differences: counts.differences() > 0,
        counts,
    }
}

/// Top-level keys that differ — the collapse [`crate::plan`] wants.
///
/// A change at `Services.SystemPolicyAllFiles[0].Allowed` is reported as
/// `Services`. Sorted, deduplicated.
pub fn changed_top_level_keys(
    a: &BTreeMap<String, plist::Value>,
    b: &BTreeMap<String, plist::Value>,
) -> Vec<String> {
    let mut out = Vec::new();
    walk(
        "",
        Some(&plist::Value::Dictionary(
            a.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        )),
        Some(&plist::Value::Dictionary(
            b.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        )),
        &mut out,
    );
    let mut keys: Vec<String> = out
        .iter()
        .filter(|f| f.status != Status::Unchanged)
        .filter_map(|f| match split_path(&f.path)?.into_iter().next()? {
            PathStep::Key(k) => Some(k),
            PathStep::Index(_) => None,
        })
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

// ---------------------------------------------------------------------------
// Human rendering
// ---------------------------------------------------------------------------

/// Terminal view: changes only, unchanged leaves as a count.
pub fn render_text(d: &StructuralDiff) -> String {
    use colored::Colorize;
    use std::fmt::Write as _;

    let mut s = String::new();

    let fmt_val = |v: &Option<Json>| -> String {
        match v {
            None => String::new(),
            Some(Json::String(x)) => format!("{x:?}"),
            Some(other) => other.to_string(),
        }
    };

    let write_fields = |s: &mut String, fields: &[FieldDiff]| {
        for f in fields.iter().filter(|f| f.status != Status::Unchanged) {
            let (mark, line) = match f.status {
                Status::Added => ("+".green(), fmt_val(&f.proposed)),
                Status::Removed => ("-".red(), fmt_val(&f.baseline)),
                Status::Changed => (
                    "~".yellow(),
                    format!("{} → {}", fmt_val(&f.baseline), fmt_val(&f.proposed)),
                ),
                Status::Unchanged => unreachable!("filtered above"),
            };
            let path = if f.metadata {
                f.path.dimmed().to_string()
            } else {
                f.path.clone()
            };
            let _ = writeln!(s, "    {mark} {path:<40} {line}");
        }
    };

    let _ = writeln!(s, "{} {}", "baseline:".dimmed(), d.baseline);
    let _ = writeln!(s, "{} {}", "proposed:".dimmed(), d.proposed);
    let _ = writeln!(s);

    if d.profile.iter().any(|f| f.status != Status::Unchanged) {
        let _ = writeln!(s, "  {}", "profile".bold());
        write_fields(&mut s, &d.profile);
    }

    for p in &d.payloads {
        let tag = match p.status {
            Status::Added => "added".green().to_string(),
            Status::Removed => "removed".red().to_string(),
            Status::Changed => format!("{} ({})", "changed".yellow(), p.counts.differences()),
            Status::Unchanged => "unchanged".dimmed().to_string(),
        };
        let _ = writeln!(s, "  {}  {tag}", p.identity.bold());
        if p.status != Status::Unchanged {
            write_fields(&mut s, &p.fields);
        }
    }

    let c = d.counts;
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "{} added, {} removed, {} changed, {} unchanged",
        c.added, c.removed, c.changed, c.unchanged
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(
        ty: &str,
        name: Option<&str>,
        uuid: &str,
        kvs: &[(&str, plist::Value)],
    ) -> PayloadContent {
        let mut content = BTreeMap::new();
        if let Some(n) = name {
            content.insert("PayloadDisplayName".to_string(), n.into());
        }
        for (k, v) in kvs {
            content.insert((*k).to_string(), v.clone());
        }
        PayloadContent {
            payload_type: ty.into(),
            payload_version: 1,
            payload_identifier: format!("com.acme.{uuid}"),
            payload_uuid: uuid.into(),
            content,
        }
    }

    fn profile(uuid: &str, payloads: Vec<PayloadContent>) -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".into(),
            payload_version: 1,
            payload_identifier: "com.acme.profile".into(),
            payload_uuid: uuid.into(),
            payload_display_name: "Test".into(),
            payload_content: payloads,
            additional_fields: BTreeMap::new(),
        }
    }

    fn find<'a>(fields: &'a [FieldDiff], path: &str) -> &'a FieldDiff {
        fields.iter().find(|f| f.path == path).unwrap_or_else(|| {
            panic!(
                "no leaf at {path}; have {:?}",
                fields.iter().map(|f| &f.path).collect::<Vec<_>>()
            )
        })
    }

    /// The case the text diff cannot answer: one setting changed, one agreed,
    /// and the UUIDs differ because they always do.
    #[test]
    fn reports_which_key_changed_and_which_agreed() {
        let a = profile(
            "P1",
            vec![payload(
                "com.apple.webcontent-filter",
                Some("Filter"),
                "U1",
                &[
                    ("FilterGrade", "inspector".into()),
                    ("FilterSockets", true.into()),
                ],
            )],
        );
        let b = profile(
            "P2",
            vec![payload(
                "com.apple.webcontent-filter",
                Some("Filter"),
                "U2",
                &[
                    ("FilterGrade", "firewall".into()),
                    ("FilterSockets", true.into()),
                ],
            )],
        );

        let d = structural_diff(&a, &b, "a", "b");
        assert_eq!(
            d.payloads.len(),
            1,
            "same type + name must pair, despite the UUID"
        );
        let p = &d.payloads[0];
        assert_eq!(p.status, Status::Changed);

        let grade = find(&p.fields, "FilterGrade");
        assert_eq!(grade.status, Status::Changed);
        assert_eq!(grade.baseline, Some(json!("inspector")));
        assert_eq!(grade.proposed, Some(json!("firewall")));
        assert!(!grade.metadata);

        assert_eq!(find(&p.fields, "FilterSockets").status, Status::Unchanged);

        let uuid = find(&p.fields, "PayloadUUID");
        assert_eq!(uuid.status, Status::Changed);
        assert!(uuid.metadata, "UUID churn must be filterable, not hidden");

        // Filtering bookkeeping leaves the one real change.
        let settings = d.settings_only();
        assert_eq!(settings.counts.changed, 1);
        assert!(settings.payloads[0].fields.iter().all(|f| !f.metadata));
    }

    /// A payload whose only deltas are bookkeeping is unchanged once those are
    /// filtered — otherwise `--settings-only` would still say "changed".
    #[test]
    fn settings_only_downgrades_bookkeeping_only_payloads() {
        let a = profile(
            "P1",
            vec![payload(
                "com.apple.dock",
                None,
                "U1",
                &[("tilesize", 48.into())],
            )],
        );
        let b = profile(
            "P2",
            vec![payload(
                "com.apple.dock",
                None,
                "U2",
                &[("tilesize", 48.into())],
            )],
        );
        let d = structural_diff(&a, &b, "a", "b");
        assert_eq!(d.payloads[0].status, Status::Changed, "UUID differs");
        let d = d.settings_only();
        assert_eq!(d.payloads[0].status, Status::Unchanged);
        assert!(!d.has_differences);
    }

    #[test]
    fn nested_dicts_and_arrays_get_full_paths() {
        let entry = |allowed: bool| -> plist::Value {
            let mut d = plist::Dictionary::new();
            d.insert("Identifier".into(), "com.x".into());
            d.insert("Allowed".into(), allowed.into());
            d.into()
        };
        let services = |allowed: bool| -> plist::Value {
            let mut d = plist::Dictionary::new();
            d.insert(
                "SystemPolicyAllFiles".into(),
                plist::Value::Array(vec![entry(allowed)]),
            );
            d.into()
        };
        let a = profile(
            "P",
            vec![payload(
                "com.apple.TCC.configuration-profile-policy",
                None,
                "U",
                &[("Services", services(true))],
            )],
        );
        let b = profile(
            "P",
            vec![payload(
                "com.apple.TCC.configuration-profile-policy",
                None,
                "U",
                &[("Services", services(false))],
            )],
        );

        let d = structural_diff(&a, &b, "a", "b");
        let f = find(
            &d.payloads[0].fields,
            "Services.SystemPolicyAllFiles[0].Allowed",
        );
        assert_eq!(f.status, Status::Changed);
        assert_eq!(
            find(
                &d.payloads[0].fields,
                "Services.SystemPolicyAllFiles[0].Identifier"
            )
            .status,
            Status::Unchanged
        );
        assert!(
            !f.metadata,
            "nested keys are settings even if named like bookkeeping"
        );
    }

    /// Apple's own managed-preference keys contain dots. A path that does not
    /// escape them cannot be split back, and a consumer indexing by path gets
    /// the wrong depth.
    #[test]
    fn dotted_keys_survive_the_round_trip() {
        let key = "com.apple.EnergySaver.desktop.ACPower";
        let a = profile(
            "P",
            vec![payload("com.apple.MCX", None, "U", &[(key, 1.into())])],
        );
        let b = profile(
            "P",
            vec![payload("com.apple.MCX", None, "U", &[(key, 2.into())])],
        );
        let d = structural_diff(&a, &b, "a", "b");
        let changed: Vec<&FieldDiff> = d.payloads[0]
            .fields
            .iter()
            .filter(|f| f.status == Status::Changed)
            .collect();
        assert_eq!(changed.len(), 1);
        let path = &changed[0].path;
        assert_eq!(path, r"com\.apple\.EnergySaver\.desktop\.ACPower");
        assert_eq!(split_path(path), Some(vec![PathStep::Key(key.to_string())]));
    }

    #[test]
    fn split_inverts_join_for_every_escapable_character() {
        let nasty = r"a.b[c]\d";
        let path = join_path(&join_path("", &escape_segment(nasty)), "[7]");
        let path = join_path(&path, &escape_segment("plain"));
        assert_eq!(
            split_path(&path),
            Some(vec![
                PathStep::Key(nasty.into()),
                PathStep::Index(7),
                PathStep::Key("plain".into())
            ])
        );
        assert_eq!(split_path("a[x]"), None, "non-numeric index is malformed");
        assert_eq!(split_path("a["), None, "unterminated index is malformed");
    }

    #[test]
    fn one_sided_payloads_are_added_or_removed_whole() {
        let a = profile(
            "P",
            vec![payload(
                "com.apple.dock",
                None,
                "U1",
                &[("tilesize", 48.into())],
            )],
        );
        let b = profile(
            "P",
            vec![
                payload("com.apple.dock", None, "U1", &[("tilesize", 48.into())]),
                payload(
                    "com.apple.finder",
                    None,
                    "U2",
                    &[("ShowHardDrivesOnDesktop", false.into())],
                ),
            ],
        );
        let d = structural_diff(&a, &b, "a", "b");
        assert_eq!(d.payloads.len(), 2);
        assert_eq!(d.payloads[0].status, Status::Unchanged);
        let added = &d.payloads[1];
        assert_eq!(added.status, Status::Added);
        assert!(added.fields.iter().all(|f| f.status == Status::Added));
        assert_eq!(
            find(&added.fields, "ShowHardDrivesOnDesktop").proposed,
            Some(json!(false))
        );

        let d = structural_diff(&b, &a, "b", "a");
        assert_eq!(d.payloads[1].status, Status::Removed);
    }

    /// Two payloads of one type with the same (or no) display name pair
    /// positionally, and the identity says so rather than silently merging.
    #[test]
    fn same_type_same_name_collisions_are_numbered() {
        let a = profile(
            "P",
            vec![
                payload(
                    "com.apple.ManagedClient.preferences",
                    None,
                    "U1",
                    &[("k", 1.into())],
                ),
                payload(
                    "com.apple.ManagedClient.preferences",
                    None,
                    "U2",
                    &[("k", 2.into())],
                ),
            ],
        );
        let d = structural_diff(&a, &a, "a", "a");
        let ids: Vec<&str> = d.payloads.iter().map(|p| p.identity.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "com.apple.ManagedClient.preferences",
                "com.apple.ManagedClient.preferences #2"
            ]
        );
        assert!(!d.has_differences);
    }

    #[test]
    fn binary_data_is_digested_not_dumped() {
        let blob = plist::Value::Data(vec![0u8; 4096]);
        let a = profile(
            "P",
            vec![payload(
                "com.apple.security.pkcs1",
                None,
                "U",
                &[("PayloadContent", blob.clone())],
            )],
        );
        let b = profile(
            "P",
            vec![payload(
                "com.apple.security.pkcs1",
                None,
                "U",
                &[("PayloadContent", plist::Value::Data(vec![1u8; 4096]))],
            )],
        );
        let d = structural_diff(&a, &b, "a", "b");
        let f = find(&d.payloads[0].fields, "PayloadContent");
        assert_eq!(f.status, Status::Changed);
        assert_eq!(f.baseline.as_ref().unwrap()["bytes"], 4096);
        assert_ne!(
            f.baseline.as_ref().unwrap()["sha256"],
            f.proposed.as_ref().unwrap()["sha256"]
        );
        assert!(
            serde_json::to_string(&d).unwrap().len() < 4096,
            "the blob must not be in the JSON"
        );
    }

    #[test]
    fn empty_containers_are_visible_leaves() {
        let a = profile(
            "P",
            vec![payload(
                "com.apple.x",
                None,
                "U",
                &[("Empty", plist::Dictionary::new().into())],
            )],
        );
        let d = structural_diff(&a, &a, "a", "a");
        assert_eq!(
            find(&d.payloads[0].fields, "Empty").status,
            Status::Unchanged
        );
    }

    /// The collapse `plan` uses must agree with the old top-level comparison.
    #[test]
    fn top_level_collapse_matches_plan_semantics() {
        let mut a = BTreeMap::new();
        let mut b = BTreeMap::new();
        let mut inner_a = plist::Dictionary::new();
        inner_a.insert("x".into(), 1.into());
        let mut inner_b = plist::Dictionary::new();
        inner_b.insert("x".into(), 2.into());
        a.insert("Nested".to_string(), inner_a.into());
        b.insert("Nested".to_string(), inner_b.into());
        a.insert("Same".to_string(), "v".into());
        b.insert("Same".to_string(), "v".into());
        a.insert("Gone".to_string(), true.into());
        b.insert("New".to_string(), true.into());
        b.insert("dotted.key".to_string(), 1.into());

        assert_eq!(
            changed_top_level_keys(&a, &b),
            vec!["Gone", "Nested", "New", "dotted.key"]
        );
    }
}
