//! The read-only tool catalogue.
//!
//! Every tool is shaped for a machine reader, not a human one: results are
//! JSON conforming to a declared `outputSchema`, field names are stable, and
//! nothing is decorated. Where a result implies an obvious next lookup, the
//! tool names it rather than leaving the agent to guess.
//!
//! Embedded data is decoded once per process and cached. The parquet payloads
//! are compiled into the binary and never change at runtime, so a second decode
//! could only ever produce the same answer more slowly.

use std::sync::OnceLock;

use serde_json::{Value, json};

use mdm_schema::types::Capability;
use mscp_schema::types::{BaselineEdge, RuleMeta};
use osquery_schema::types::OsqueryEntry;

/// A tool execution failure: reported as a successful JSON-RPC response whose
/// result carries `isError: true`, because models can self-correct from these.
#[derive(Debug)]
pub struct ToolError {
    pub message: String,
    /// Closest known identifiers, when the failure looks like a typo. Naming
    /// the near-misses is what turns a dead end into a retry.
    pub suggestions: Vec<String>,
}

impl ToolError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            suggestions: Vec::new(),
        }
    }

    fn with_suggestions(message: impl Into<String>, suggestions: Vec<String>) -> Self {
        Self {
            message: message.into(),
            suggestions,
        }
    }
}

/// One callable tool.
pub struct Tool {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub input_schema: fn() -> Value,
    pub output_schema: fn() -> Value,
    pub handler: fn(&Value) -> Result<Value, ToolError>,
}

impl std::fmt::Debug for Tool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tool").field("name", &self.name).finish()
    }
}

/// The catalogue, in a fixed order.
///
/// Order is deliberate and stable: the spec notes that deterministic ordering
/// lets clients cache the tool list and improves prompt-cache hit rates, and
/// this list cannot change for a given build anyway.
pub const TOOLS: &[Tool] = &[
    Tool {
        name: "contour.schema.search",
        title: "Search Apple MDM schema",
        description: "Search Apple MDM payload types and their keys by keyword. \
                      Returns matching payload types with the keys that matched. \
                      Use this first when you know what a setting does but not \
                      which payload or key name carries it.",
        input_schema: schema_search_input,
        output_schema: schema_search_output,
        handler: schema_search,
    },
    Tool {
        name: "contour.schema.key",
        title: "Apple MDM payload detail",
        description: "Full detail for one Apple MDM payload type: every key with \
                      its type and default, per-platform availability, and a \
                      ready-to-use payload snippet. Pass `key` to narrow to a \
                      single key. Use after contour.schema.search identifies the \
                      payload type.",
        input_schema: schema_key_input,
        output_schema: schema_key_output,
        handler: schema_key,
    },
    Tool {
        name: "contour.osquery.search",
        title: "Search osquery tables",
        description: "Search osquery table and column names by keyword. Returns \
                      matching tables with their platforms. Use before writing \
                      any osquery SQL to confirm the table exists.",
        input_schema: osquery_search_input,
        output_schema: osquery_search_output,
        handler: osquery_search,
    },
    Tool {
        name: "contour.osquery.table",
        title: "osquery table schema",
        description: "Full column schema for one osquery table: every column with \
                      its type and whether it is required. A misspelled table \
                      returns no rows at runtime and a Fleet policy reads no rows \
                      as compliant, so verify the table here before shipping SQL.",
        input_schema: osquery_table_input,
        output_schema: osquery_table_output,
        handler: osquery_table,
    },
    Tool {
        name: "contour.mscp.rule",
        title: "mSCP compliance rule",
        description: "Detail for one mSCP compliance rule: title, severity, \
                      discussion, whether it has a check/fix, whether it is \
                      enforceable by mobileconfig or DDM, and which baselines \
                      include it.",
        input_schema: mscp_rule_input,
        output_schema: mscp_rule_output,
        handler: mscp_rule,
    },
    Tool {
        name: "contour.mscp.baseline",
        title: "mSCP baseline contents",
        description: "The rules belonging to one mSCP baseline (CIS, STIG, 800-53 \
                      and friends), grouped by section. Call contour.mscp.rule for \
                      the detail of any rule_id returned here.",
        input_schema: mscp_baseline_input,
        output_schema: mscp_baseline_output,
        handler: mscp_baseline,
    },
    Tool {
        name: "contour.sop",
        title: "contour standard operating procedure",
        description: "The procedural SOP for a contour workflow — the same text as \
                      `contour help-ai --sop <topic>`. Pass `section` to return one \
                      heading instead of the whole document. Use when you need the \
                      command sequence for a task rather than schema data.",
        input_schema: sop_input,
        output_schema: sop_output,
        handler: sop,
    },
];

/// Look up a tool by exact name.
pub fn find(name: &str) -> Option<&'static Tool> {
    TOOLS.iter().find(|t| t.name == name)
}

/// Render the catalogue as `tools/list` entries.
pub fn list() -> Vec<Value> {
    TOOLS
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "title": t.title,
                "description": t.description,
                "inputSchema": (t.input_schema)(),
                "outputSchema": (t.output_schema)(),
                // Every tool in this build is a pure lookup over embedded data.
                // Clients are told to treat annotations as untrusted, so these
                // are a hint, not the guarantee — the guarantee is that no
                // handler in this file calls a writer. (`contour-core` is
                // linked and does have write paths; none are reached here.)
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false,
                },
            })
        })
        .collect()
}

// ── Embedded data, decoded once ──────────────────────────────────────

fn capabilities() -> &'static [Capability] {
    static CACHE: OnceLock<Vec<Capability>> = OnceLock::new();
    CACHE.get_or_init(|| {
        mdm_schema::capabilities::read(mdm_schema::embedded_capabilities()).unwrap_or_default()
    })
}

/// Microsoft's DDF v2 Windows CSP nodes.
///
/// A separate corpus, never merged into the Apple set — the same separation
/// `profile search --windows` keeps on the CLI. A Windows node and an Apple
/// payload share no namespace, and blending them would put `BitLocker`
/// beside `com.apple.security.FDERecoveryKeyEscrow` in one result list with
/// nothing saying which protocol either belongs to.
fn windows_capabilities() -> &'static [Capability] {
    static CACHE: OnceLock<Vec<Capability>> = OnceLock::new();
    CACHE.get_or_init(|| {
        mdm_schema::capabilities::read(mdm_schema::embedded_windows_capabilities())
            .unwrap_or_default()
    })
}

/// The corpus a request selected.
fn corpus(args: &Value) -> &'static [Capability] {
    if args
        .get("windows")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        windows_capabilities()
    } else {
        capabilities()
    }
}

fn osquery_entries() -> &'static [OsqueryEntry] {
    static CACHE: OnceLock<Vec<OsqueryEntry>> = OnceLock::new();
    CACHE.get_or_init(|| {
        osquery_schema::osquery::read(osquery_schema::embedded()).unwrap_or_default()
    })
}

fn rule_meta() -> &'static [RuleMeta] {
    static CACHE: OnceLock<Vec<RuleMeta>> = OnceLock::new();
    CACHE.get_or_init(|| {
        mscp_schema::rule_meta::read(mscp_schema::embedded_rule_meta()).unwrap_or_default()
    })
}

fn baseline_edges() -> &'static [BaselineEdge] {
    static CACHE: OnceLock<Vec<BaselineEdge>> = OnceLock::new();
    CACHE.get_or_init(|| {
        mscp_schema::baseline_edges::read(mscp_schema::embedded_baseline_edges())
            .unwrap_or_default()
    })
}

// ── Argument helpers ─────────────────────────────────────────────────

fn required_str(args: &Value, field: &str) -> Result<String, ToolError> {
    args.get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            ToolError::new(format!(
                "`{field}` is required and must be a non-empty string"
            ))
        })
}

fn optional_str(args: &Value, field: &str) -> Option<String> {
    args.get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
}

/// Result cap. Large result sets cost the agent context without adding
/// signal, so the search tools return the top slice plus an honest
/// `truncated` flag rather than everything. `mscp_baseline` caps its
/// sections too but emits no flag, and never goes below `DEFAULT_LIMIT`.
const DEFAULT_LIMIT: usize = 20;
const MAX_LIMIT: usize = 100;

fn limit_of(args: &Value) -> usize {
    args.get("limit")
        .and_then(Value::as_u64)
        .map_or(DEFAULT_LIMIT, |n| (n as usize).clamp(1, MAX_LIMIT))
}

/// Names within two edits of `needle`, or containing it / contained by it,
/// for "did you mean".
fn near_misses(needle: &str, haystack: impl Iterator<Item = String>) -> Vec<String> {
    let n = needle.to_lowercase();
    let mut hits: Vec<String> = haystack
        .filter(|c| {
            let c = c.to_lowercase();
            c.contains(&n) || n.contains(&c) || levenshtein_within(&c, &n, 2)
        })
        .collect();
    hits.sort();
    hits.dedup();
    hits.truncate(5);
    hits
}

/// True when `a` and `b` are within `max` edits. Bounded and allocation-light;
/// the candidate lists here are small enough that a full DP table is fine.
fn levenshtein_within(a: &str, b: &str, max: usize) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a.len().abs_diff(b.len()) > max {
        return false;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()] <= max
}

/// How well a record matched, most specific first.
///
/// A lookup tool must never answer a too-specific query with a bare empty set:
/// zero results is indistinguishable from an authoritative "not in the schema",
/// which is the worst failure mode available to it. Degrading to partial hits
/// and *saying so* lets the caller judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MatchQuality {
    /// The whole query appears verbatim.
    Phrase,
    /// Every token appears, in any order or field.
    AllTerms,
    /// Some tokens appear. Only used when nothing better matched.
    Partial,
}

impl MatchQuality {
    fn as_str(self) -> &'static str {
        match self {
            Self::Phrase => "phrase",
            Self::AllTerms => "all_terms",
            Self::Partial => "partial",
        }
    }
}

/// Rank `matcher` against a phrase and its tokens.
///
/// `Partial` is only reported when neither the phrase nor every token matched,
/// so an exact hit is never diluted by a loose one.
fn rank_match(
    query: &str,
    tokens: &[&str],
    matcher: impl Fn(&str) -> bool,
) -> Option<MatchQuality> {
    if matcher(query) {
        return Some(MatchQuality::Phrase);
    }
    if tokens.len() > 1 && tokens.iter().all(|t| matcher(t)) {
        return Some(MatchQuality::AllTerms);
    }
    if tokens.len() > 1 && tokens.iter().any(|t| matcher(t)) {
        return Some(MatchQuality::Partial);
    }
    None
}

/// Does any searchable field of this capability contain `needle`?
fn capability_contains(cap: &Capability, needle: &str) -> bool {
    cap.payload_type.to_lowercase().contains(needle)
        || cap.title.to_lowercase().contains(needle)
        || cap.description.to_lowercase().contains(needle)
        || cap
            .keys
            .iter()
            .any(|k| k.name.to_lowercase().contains(needle))
}

/// The DDM declaration that supersedes an MDM payload type, if one exists.
///
/// A deprecation version without a replacement is a dead end: the caller knows
/// the payload is going away and has to source the successor elsewhere, which
/// is exactly where a wrong answer gets invented. The registry is authoritative
/// and now lives in `mdm-schema`, so a read-only consumer can reach it.
fn superseded_by(payload_type: &str) -> Option<Value> {
    static REGISTRY: OnceLock<mdm_schema::migration::MigrationRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(mdm_schema::migration::MigrationRegistry::new);
    registry.get(payload_type).map(|m| {
        json!({
            "ddm_type": m.ddm_type,
            "status": m.status.as_str(),
            "notes": m.notes,
        })
    })
}

fn platforms_of(cap: &Capability) -> Vec<String> {
    let mut p: Vec<String> = cap
        .supported_os
        .iter()
        .map(|o| o.platform.as_str().to_string())
        .collect();
    p.sort();
    p.dedup();
    p
}

// ── contour.schema.search ────────────────────────────────────────────

fn schema_search_input() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Keyword to match against payload type, title, description and key names"},
            "platform": {"type": "string", "description": "Restrict to a platform, e.g. macOS, iOS, tvOS"},
            "windows": {"type": "boolean", "description": "Search Microsoft's Windows CSP nodes instead of Apple's payloads. The two are separate corpora and are never mixed; a Windows node has no Apple equivalent and vice versa."},
            "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "description": "Max payload types to return (default 20)"}
        },
        "required": ["query"],
        "additionalProperties": false
    })
}

fn schema_search_output() -> Value {
    json!({
        "type": "object",
        "properties": {
            "count": {"type": "integer"},
            "truncated": {"type": "boolean"},
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "payload_type": {"type": "string"},
                        "kind": {"type": "string"},
                        "title": {"type": "string"},
                        "platforms": {"type": "array", "items": {"type": "string"}},
                        "key_count": {"type": "integer"},
                        "matched_keys": {"type": "array", "items": {"type": "string"}},
                        "match_quality": {
                            "type": "string",
                            "enum": ["phrase", "all_terms", "partial"],
                            "description": "phrase = whole query matched verbatim; all_terms = every token matched in any order; partial = only some tokens matched, returned because nothing stronger did"
                        }
                    },
                    "required": ["payload_type", "kind", "title", "platforms", "key_count", "match_quality"]
                }
            }
        },
        "required": ["count", "truncated", "results"]
    })
}

fn schema_search(args: &Value) -> Result<Value, ToolError> {
    let query = required_str(args, "query")?.to_lowercase();
    let tokens: Vec<&str> = query.split_whitespace().collect();
    let platform = optional_str(args, "platform").map(|p| p.to_lowercase());
    let limit = limit_of(args);

    let mut hits: Vec<(MatchQuality, &Capability)> = corpus(args)
        .iter()
        .filter(|c| {
            platform.as_ref().is_none_or(|p| {
                c.supported_os
                    .iter()
                    .any(|o| o.platform.as_str().to_lowercase() == *p)
            })
        })
        .filter_map(|c| {
            rank_match(&query, &tokens, |needle| capability_contains(c, needle)).map(|q| (q, c))
        })
        .collect();

    // Keep only the strongest tier that matched: a phrase hit must not be
    // diluted by records sharing a single token.
    if let Some(best) = hits.iter().map(|(q, _)| *q).min() {
        hits.retain(|(q, _)| *q == best);
    }

    // Stable order within a tier: payload-name matches first, then
    // alphabetical, so the same query ranks the same way on every call.
    hits.sort_by(|(_, a), (_, b)| {
        let rank = |c: &Capability| u8::from(!c.payload_type.to_lowercase().contains(&query));
        rank(a)
            .cmp(&rank(b))
            .then(a.payload_type.cmp(&b.payload_type))
    });

    let count = hits.len();
    let truncated = count > limit;
    let results: Vec<Value> = hits
        .iter()
        .take(limit)
        .map(|(quality, c)| {
            // Match keys on any token, not the whole phrase — otherwise a
            // multi-word query reports no matched keys at all.
            let matched: Vec<String> = c
                .keys
                .iter()
                .filter(|k| {
                    let n = k.name.to_lowercase();
                    tokens.iter().any(|t| n.contains(t))
                })
                .map(|k| k.name.clone())
                .take(10)
                .collect();
            json!({
                "payload_type": c.payload_type,
                "kind": format!("{:?}", c.kind),
                "title": c.title,
                "platforms": platforms_of(c),
                "key_count": c.keys.len(),
                "matched_keys": matched,
                "match_quality": quality.as_str(),
            })
        })
        .collect();

    // An empty Apple result must not read as "contour does not know this".
    //
    // Searching the Apple corpus for `BitLocker` returned `count: 0`, which
    // is indistinguishable from contour having no such schema — and contour
    // carries 4,347 Windows CSP nodes including that one. An agent that
    // cannot tell "not here" from "not anywhere" stops looking, so a miss on
    // one corpus says whether the other has it.
    let mut out = json!({ "count": count, "truncated": truncated, "results": results });
    if count == 0 {
        let searching_windows = args
            .get("windows")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let other = if searching_windows {
            capabilities()
        } else {
            windows_capabilities()
        };
        let elsewhere = other
            .iter()
            .filter(|c| {
                rank_match(&query, &tokens, |needle| capability_contains(c, needle)).is_some()
            })
            .count();
        if elsewhere > 0 {
            let (corpus_name, hint) = if searching_windows {
                ("apple", "Re-run without `windows: true`.")
            } else {
                ("windows", "Re-run with `windows: true`.")
            };
            out["no_match_here_but"] = json!({
                "corpus": corpus_name,
                "matches": elsewhere,
                "hint": hint,
            });
        }
    }
    Ok(out)
}

// ── contour.schema.key ───────────────────────────────────────────────

fn schema_key_input() -> Value {
    json!({
        "type": "object",
        "properties": {
            "payload_type": {"type": "string", "description": "Exact payload type, e.g. com.apple.SoftwareUpdate"},
            "key": {"type": "string", "description": "Narrow the response to one key: a bare name (every key of that name, under any parent) or a dot-path such as Apps.Mail.AllowSummary (exactly that one)"},
            "windows": {"type": "boolean", "description": "Look the type up among Microsoft's Windows CSP nodes instead of Apple's payloads. The two are separate corpora; a miss in one reports whether the other has it."}
        },
        "required": ["payload_type"],
        "additionalProperties": false
    })
}

fn schema_key_output() -> Value {
    json!({
        "type": "object",
        "properties": {
            "payload_type": {"type": "string"},
            "kind": {"type": "string"},
            "title": {"type": "string"},
            "description": {"type": "string"},
            "availability": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "platform": {"type": "string"},
                    "introduced": {"type": ["string", "null"]},
                    "deprecated": {"type": ["string", "null"]},
                    "removed": {"type": ["string", "null"]}
                },
                "required": ["platform"]
            }},
            "keys": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "path": {"type": "string",
                             "description": "Where the key sits: parent dot-path and name, e.g. Apps.Mail.AllowSummary. Two keys can share a name under different parents; the path tells them apart."},
                    "parent": {"type": "string",
                               "description": "The parent dot-path, absent for a top-level key. For a Windows CSP key this is the `parent` value `profile windows generate` needs."},
                    "depth": {"type": "integer"},
                    "introduced": {"type": "object", "description": "Per platform, the OS version the key appeared in"},
                    "deprecated": {"type": "object", "description": "Per platform, the OS version Apple deprecated the key in"},
                    "removed": {"type": "object", "description": "Per platform, the OS version the key was removed in"},
                    "type": {"type": "string"},
                    "presence": {"type": "string"},
                    "default": {},
                    "allowed": {"type": "array", "items": {"type": "string"},
                                "description": "The only values this key accepts. Anything else is refused at generate time."},
                    "min": {"type": "number"},
                    "max": {"type": "number"},
                    "description": {"type": "string"}
                },
                "required": ["name", "path", "type", "presence"]
            }},
            "ambiguous": {"type": "boolean",
                          "description": "True when a bare `key` name matched keys under more than one parent. Pick one by its `path`."},
            "snippet": {"type": "object"},
            "superseded_by": {
                "type": ["object", "null"],
                "description": "The DDM declaration that replaces this payload type, when one exists. Present regardless of deprecation status — check `availability[].deprecated` for whether the move is required yet.",
                "properties": {
                    "ddm_type": {"type": "string"},
                    "status": {"type": "string"},
                    "notes": {"type": "string"}
                }
            }
        },
        "required": ["payload_type", "kind", "title", "availability", "keys"]
    })
}

/// A key's full dot-path: its parent's path and its own name.
fn key_path(k: &mdm_schema::types::PayloadKey) -> String {
    match k.parent_key.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => format!("{p}.{}", k.name),
        None => k.name.clone(),
    }
}

fn schema_key(args: &Value) -> Result<Value, ToolError> {
    let payload_type = required_str(args, "payload_type")?;
    let wanted_key = optional_str(args, "key");

    let here = corpus(args);
    let cap = here
        .iter()
        .find(|c| c.payload_type.eq_ignore_ascii_case(&payload_type))
        .ok_or_else(|| {
            let searching_windows = args
                .get("windows")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let (name, other, flag) = if searching_windows {
                ("Windows CSP", capabilities(), "without `windows: true`")
            } else {
                ("Apple", windows_capabilities(), "with `windows: true`")
            };
            // The other corpus having it is the most useful thing that can
            // be said, and saying nothing reads as "contour has no such
            // schema" — which is how an agent concludes contour cannot help
            // with Windows at all.
            if other
                .iter()
                .any(|c| c.payload_type.eq_ignore_ascii_case(&payload_type))
            {
                return ToolError::new(format!(
                    "`{payload_type}` is not in the embedded {name} schema, but the other \
                     corpus has it — re-run {flag}."
                ));
            }
            ToolError::with_suggestions(
                format!("no payload type `{payload_type}` in the embedded {name} schema"),
                near_misses(&payload_type, here.iter().map(|c| c.payload_type.clone())),
            )
        })?;

    // A dot-path names exactly one key; a bare name names every key of that
    // name, which is how an agent learns the name is shared at all.
    let keys: Vec<&mdm_schema::types::PayloadKey> = match &wanted_key {
        Some(k) => {
            let by_path = k.contains('.');
            let found: Vec<_> = cap
                .keys
                .iter()
                .filter(|pk| {
                    if by_path {
                        key_path(pk).eq_ignore_ascii_case(k)
                    } else {
                        pk.name.eq_ignore_ascii_case(k)
                    }
                })
                .collect();
            if found.is_empty() {
                let candidates: Vec<String> = if by_path {
                    cap.keys.iter().map(key_path).collect()
                } else {
                    cap.keys.iter().map(|pk| pk.name.clone()).collect()
                };
                return Err(ToolError::with_suggestions(
                    format!("payload `{}` has no key `{k}`", cap.payload_type),
                    near_misses(k, candidates.into_iter()),
                ));
            }
            found
        }
        None => cap.keys.iter().collect(),
    };
    let ambiguous = {
        let mut parents: Vec<&str> = keys
            .iter()
            .map(|k| k.parent_key.as_deref().unwrap_or_default())
            .collect();
        parents.sort_unstable();
        parents.dedup();
        wanted_key.is_some() && parents.len() > 1
    };

    let availability: Vec<Value> = cap
        .supported_os
        .iter()
        .map(|o| {
            json!({
                "platform": o.platform.as_str(),
                "introduced": o.introduced,
                "deprecated": o.deprecated,
                "removed": o.removed,
            })
        })
        .collect();

    let key_json: Vec<Value> = keys
        .iter()
        .map(|k| {
            // `allowed` and the range are what let an agent SUGGEST a value
            // rather than guess one. They were absent from this response for
            // both corpora, so an agent knew `RequireDeviceEncryption` was an
            // integer and nothing about it accepting only 0 or 1 — and a
            // guessed integer is refused at generate time, after the work.
            let mut out = json!({
                "name": k.name,
                "path": key_path(k),
                "depth": k.depth,
                "type": k.data_type,
                "presence": k.presence,
                "default": k.default_value,
            });
            if let Some(p) = k.parent_key.as_deref().filter(|p| !p.is_empty()) {
                out["parent"] = json!(p);
            }
            for (field, map) in [
                ("introduced", &k.introduced),
                ("deprecated", &k.deprecated),
                ("removed", &k.removed),
            ] {
                if !map.is_empty() {
                    let by_platform: std::collections::BTreeMap<&str, &String> =
                        map.iter().map(|(p, v)| (p.as_str(), v)).collect();
                    out[field] = json!(by_platform);
                }
            }
            if let Some(allowed) = &k.range_list
                && !allowed.is_empty()
            {
                out["allowed"] = json!(allowed);
            }
            if let Some(min) = k.range_min {
                out["min"] = json!(min);
            }
            if let Some(max) = k.range_max {
                out["max"] = json!(max);
            }
            if let Some(d) = &k.key_description
                && !d.trim().is_empty()
            {
                out["description"] = json!(d);
            }
            out
        })
        .collect();

    // A paste-ready starting point: the payload identity plus every required
    // key. Saves the agent inventing the envelope from prose.
    let mut snippet = serde_json::Map::new();
    snippet.insert("PayloadType".into(), json!(cap.payload_type));
    // Top-level keys only: a nested required key belongs inside its parent,
    // and placing it at the root writes a key Apple ignores.
    for k in keys.iter().filter(|k| k.depth == 0) {
        if k.presence.eq_ignore_ascii_case("required") {
            snippet.insert(
                k.name.clone(),
                k.default_value.clone().unwrap_or(Value::Null),
            );
        }
    }

    Ok(json!({
        "payload_type": cap.payload_type,
        "kind": format!("{:?}", cap.kind),
        "title": cap.title,
        "description": cap.description,
        "availability": availability,
        "keys": key_json,
        "ambiguous": ambiguous,
        "snippet": Value::Object(snippet),
        "superseded_by": superseded_by(&cap.payload_type),
    }))
}

// ── contour.osquery.search ───────────────────────────────────────────

fn osquery_search_input() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Keyword to match against table name, description and column names"},
            "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT}
        },
        "required": ["query"],
        "additionalProperties": false
    })
}

fn osquery_search_output() -> Value {
    json!({
        "type": "object",
        "properties": {
            "count": {"type": "integer"},
            "truncated": {"type": "boolean"},
            "results": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "table": {"type": "string"},
                    "platforms": {"type": "string"},
                    "evented": {"type": "boolean"},
                    "description": {"type": ["string", "null"]},
                    "matched_columns": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["table", "platforms", "evented"]
            }}
        },
        "required": ["count", "truncated", "results"]
    })
}

fn osquery_search(args: &Value) -> Result<Value, ToolError> {
    let query = required_str(args, "query")?.to_lowercase();
    let limit = limit_of(args);

    let mut by_table: std::collections::BTreeMap<&str, (&OsqueryEntry, Vec<String>)> =
        std::collections::BTreeMap::new();
    for e in osquery_entries() {
        let table_hit = e.table_name.to_lowercase().contains(&query)
            || e.table_description
                .as_deref()
                .is_some_and(|d| d.to_lowercase().contains(&query));
        let col_hit = e.column_name.to_lowercase().contains(&query);
        if !table_hit && !col_hit {
            continue;
        }
        let slot = by_table.entry(&e.table_name).or_insert((e, Vec::new()));
        if col_hit && slot.1.len() < 10 {
            slot.1.push(e.column_name.clone());
        }
    }

    let count = by_table.len();
    let truncated = count > limit;
    let results: Vec<Value> = by_table
        .values()
        .take(limit)
        .map(|(e, cols)| {
            json!({
                "table": e.table_name,
                "platforms": e.platforms,
                "evented": e.evented,
                "description": e.table_description,
                "matched_columns": cols,
            })
        })
        .collect();

    Ok(json!({ "count": count, "truncated": truncated, "results": results }))
}

// ── contour.osquery.table ────────────────────────────────────────────

fn osquery_table_input() -> Value {
    json!({
        "type": "object",
        "properties": {"table": {"type": "string", "description": "Exact osquery table name"}},
        "required": ["table"],
        "additionalProperties": false
    })
}

fn osquery_table_output() -> Value {
    json!({
        "type": "object",
        "properties": {
            "table": {"type": "string"},
            "platforms": {"type": "string"},
            "evented": {"type": "boolean"},
            "description": {"type": ["string", "null"]},
            "columns": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "type": {"type": "string"},
                    "required": {"type": "boolean"},
                    "hidden": {"type": "boolean"},
                    "description": {"type": ["string", "null"]}
                },
                "required": ["name", "type", "required", "hidden"]
            }}
        },
        "required": ["table", "platforms", "evented", "columns"]
    })
}

fn osquery_table(args: &Value) -> Result<Value, ToolError> {
    let table = required_str(args, "table")?;
    let rows: Vec<&OsqueryEntry> = osquery_entries()
        .iter()
        .filter(|e| e.table_name.eq_ignore_ascii_case(&table))
        .collect();

    let first = rows.first().ok_or_else(|| {
        ToolError::with_suggestions(
            format!("no osquery table `{table}` in the embedded schema"),
            near_misses(
                &table,
                osquery_entries().iter().map(|e| e.table_name.clone()),
            ),
        )
    })?;

    let mut columns: Vec<Value> = rows
        .iter()
        .map(|e| {
            json!({
                "name": e.column_name,
                "type": e.column_type,
                "required": e.required,
                "hidden": e.hidden,
                "description": e.column_description,
            })
        })
        .collect();
    columns.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    Ok(json!({
        "table": first.table_name,
        "platforms": first.platforms,
        "evented": first.evented,
        "description": first.table_description,
        "columns": columns,
    }))
}

// ── contour.mscp.rule ────────────────────────────────────────────────

fn mscp_rule_input() -> Value {
    json!({
        "type": "object",
        "properties": {"rule_id": {"type": "string", "description": "Exact mSCP rule id, e.g. os_airdrop_disable"}},
        "required": ["rule_id"],
        "additionalProperties": false
    })
}

fn mscp_rule_output() -> Value {
    json!({
        "type": "object",
        "properties": {
            "rule_id": {"type": "string"},
            "title": {"type": "string"},
            "severity": {"type": ["string", "null"]},
            "discussion": {"type": ["string", "null"]},
            "has_check": {"type": "boolean"},
            "has_fix": {"type": "boolean"},
            "enforceable_by_mobileconfig": {"type": "boolean"},
            "has_ddm": {"type": "boolean"},
            "baselines": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["rule_id", "title", "has_check", "has_fix", "enforceable_by_mobileconfig", "has_ddm", "baselines"]
    })
}

fn mscp_rule(args: &Value) -> Result<Value, ToolError> {
    let rule_id = required_str(args, "rule_id")?;
    let rule = rule_meta()
        .iter()
        .find(|r| r.rule_id.eq_ignore_ascii_case(&rule_id))
        .ok_or_else(|| {
            ToolError::with_suggestions(
                format!("no mSCP rule `{rule_id}` in the embedded data"),
                near_misses(&rule_id, rule_meta().iter().map(|r| r.rule_id.clone())),
            )
        })?;

    let mut baselines: Vec<String> = baseline_edges()
        .iter()
        .filter(|e| e.rule_id == rule.rule_id)
        .map(|e| e.baseline.clone())
        .collect();
    baselines.sort();
    baselines.dedup();

    Ok(json!({
        "rule_id": rule.rule_id,
        "title": rule.title,
        "severity": rule.severity,
        "discussion": rule.discussion,
        "has_check": rule.has_check,
        "has_fix": rule.has_fix,
        "enforceable_by_mobileconfig": rule.mobileconfig,
        "has_ddm": rule.has_ddm_info,
        "baselines": baselines,
    }))
}

// ── contour.mscp.baseline ────────────────────────────────────────────

fn mscp_baseline_input() -> Value {
    json!({
        "type": "object",
        "properties": {
            "baseline": {"type": "string", "description": "Baseline name, e.g. cis_lvl1, stig, 800-53r5_high"},
            "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "description": "Max sections to return"}
        },
        "required": ["baseline"],
        "additionalProperties": false
    })
}

fn mscp_baseline_output() -> Value {
    json!({
        "type": "object",
        "properties": {
            "baseline": {"type": "string"},
            "rule_count": {"type": "integer"},
            "sections": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "section": {"type": "string"},
                    "rules": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["section", "rules"]
            }}
        },
        "required": ["baseline", "rule_count", "sections"]
    })
}

fn mscp_baseline(args: &Value) -> Result<Value, ToolError> {
    let baseline = required_str(args, "baseline")?;
    let edges: Vec<&BaselineEdge> = baseline_edges()
        .iter()
        .filter(|e| e.baseline.eq_ignore_ascii_case(&baseline))
        .collect();

    if edges.is_empty() {
        return Err(ToolError::with_suggestions(
            format!("no mSCP baseline `{baseline}` in the embedded data"),
            near_misses(
                &baseline,
                baseline_edges().iter().map(|e| e.baseline.clone()),
            ),
        ));
    }

    let mut sections: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for e in &edges {
        sections
            .entry(e.section.clone())
            .or_default()
            .push(e.rule_id.clone());
    }
    for rules in sections.values_mut() {
        rules.sort();
        rules.dedup();
    }

    let rule_count: usize = sections.values().map(Vec::len).sum();
    let section_json: Vec<Value> = sections
        .into_iter()
        .take(limit_of(args).max(DEFAULT_LIMIT))
        .map(|(section, rules)| json!({"section": section, "rules": rules}))
        .collect();

    Ok(json!({
        "baseline": edges[0].baseline,
        "rule_count": rule_count,
        "sections": section_json,
    }))
}

// ── contour.sop ──────────────────────────────────────────────────────

fn sop_input() -> Value {
    json!({
        "type": "object",
        "properties": {
            "topic": {"type": "string", "description": "SOP topic, e.g. profile, mcx, osquery, santa, mscp, ddm, enrollment"},
            "section": {"type": "string", "description": "Return only the section whose heading contains this text"}
        },
        "required": ["topic"],
        "additionalProperties": false
    })
}

fn sop_output() -> Value {
    json!({
        "type": "object",
        "properties": {
            "topic": {"type": "string"},
            "section": {"type": ["string", "null"]},
            "markdown": {"type": "string"}
        },
        "required": ["topic", "markdown"]
    })
}

fn sop(args: &Value) -> Result<Value, ToolError> {
    let topic = required_str(args, "topic")?;
    let section = optional_str(args, "section");

    let mut buf = Vec::new();
    let outcome = match &section {
        Some(s) => contour_core::help_agents::generate_sop_section(&topic, s, &mut buf),
        None => contour_core::help_agents::generate_sop(&topic, &mut buf),
    };
    outcome.map_err(|e| ToolError::new(format!("{e:#}")))?;

    Ok(json!({
        "topic": topic,
        "section": section,
        "markdown": String::from_utf8_lossy(&buf),
    }))
}

#[cfg(test)]
mod tests {

    /// Windows CSP nodes are reachable over MCP.
    ///
    /// They were not. `contour.schema.search` read only the Apple corpus, so
    /// an agent asking about BitLocker got `count: 0` from a binary carrying
    /// 4,347 Windows nodes — and `count: 0` is indistinguishable from "this
    /// tool does not know about Windows", which is the conclusion an agent
    /// reasonably draws and then stops.
    #[test]
    fn the_windows_corpus_is_searchable() {
        let v = schema_search(&json!({"query": "BitLocker", "windows": true})).unwrap();
        assert!(
            v["count"].as_u64().unwrap() > 0,
            "no Windows CSP matched BitLocker"
        );
        let first = &v["results"][0];
        assert_eq!(first["kind"], "CspSetting");
    }

    /// The two corpora never mix.
    #[test]
    fn apple_and_windows_stay_separate() {
        let apple = schema_search(&json!({"query": "BitLocker"})).unwrap();
        assert_eq!(
            apple["count"], 0,
            "a Windows node leaked into the Apple set"
        );

        let win = schema_search(&json!({"query": "wifi", "windows": true})).unwrap();
        for r in win["results"].as_array().unwrap() {
            assert_ne!(
                r["kind"], "MdmProfile",
                "an Apple payload leaked into the Windows set"
            );
        }
    }

    /// A miss on one corpus says whether the other has it.
    ///
    /// This is the whole point: silence is what made an agent conclude
    /// contour could not help with Windows.
    #[test]
    fn an_empty_result_names_the_corpus_that_has_it() {
        let v = schema_search(&json!({"query": "BitLocker"})).unwrap();
        assert_eq!(v["count"], 0);
        let hint = &v["no_match_here_but"];
        assert_eq!(hint["corpus"], "windows");
        assert!(hint["matches"].as_u64().unwrap() > 0);
        assert!(
            hint["hint"].as_str().unwrap().contains("windows: true"),
            "the hint must name the argument to re-run with"
        );

        // And nothing is added when the query genuinely matches nowhere.
        let nowhere = schema_search(&json!({"query": "zzzznotathing"})).unwrap();
        assert_eq!(nowhere["count"], 0);
        assert!(nowhere.get("no_match_here_but").is_none());
    }

    /// A key lookup in the wrong corpus points at the right one.
    #[test]
    fn a_key_lookup_in_the_wrong_corpus_says_so() {
        let err = schema_key(&json!({"payload_type": "BitLocker"})).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("windows: true"),
            "the error must name how to reach it: {msg}"
        );
    }

    /// Keys that share a name under different parents are told apart by
    /// path, and a bare-name lookup says the name is shared.
    #[test]
    fn a_shared_key_name_is_told_apart_by_path() {
        let v = schema_key(&json!({
            "payload_type": "com.apple.configuration.intelligence.settings",
            "key": "AllowSummary"
        }))
        .unwrap();
        let paths: Vec<&str> = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["path"].as_str().unwrap())
            .collect();
        assert!(
            paths.contains(&"Apps.Mail.AllowSummary")
                && paths.contains(&"Apps.Safari.AllowSummary"),
            "{paths:?}"
        );
        assert_eq!(v["ambiguous"], true);

        let one = schema_key(&json!({
            "payload_type": "com.apple.configuration.intelligence.settings",
            "key": "Apps.Mail.AllowSummary"
        }))
        .unwrap();
        assert_eq!(one["keys"].as_array().unwrap().len(), 1);
        assert_eq!(one["keys"][0]["parent"], "Apps.Mail");
        assert_eq!(one["ambiguous"], false);
    }

    /// A Windows key's `parent` is the value `profile windows generate`
    /// needs to pick one of several same-named nodes.
    #[test]
    fn a_windows_key_reports_the_parent_generate_needs() {
        let v = schema_key(&json!({
            "payload_type": "Firewall",
            "key": "EnableFirewall",
            "windows": true
        }))
        .unwrap();
        let parents: Vec<&str> = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|k| k["parent"].as_str())
            .collect();
        assert!(parents.contains(&"MdmStore.PublicProfile"), "{parents:?}");
        assert!(parents.len() > 1);
    }

    /// Deprecation is per key, not only per payload.
    #[test]
    fn a_key_reports_its_deprecation() {
        let v = schema_key(&json!({
            "payload_type": "com.apple.configuration.intelligence.settings",
            "key": "AllowVisualIntelligenceSummary"
        }))
        .unwrap();
        assert_eq!(v["keys"][0]["deprecated"]["iOS"], "27.0");
    }

    /// An agent cannot suggest a value it is not told the key accepts.
    #[test]
    fn a_key_reports_the_values_it_accepts() {
        let v = schema_key(&json!({
            "payload_type": "BitLocker",
            "key": "RequireDeviceEncryption",
            "windows": true
        }))
        .unwrap();
        let k = &v["keys"][0];
        assert_eq!(k["name"], "RequireDeviceEncryption");
        let allowed = k["allowed"]
            .as_array()
            .expect("the node's enum must be reported");
        assert!(
            allowed.iter().any(|x| x == "0") && allowed.iter().any(|x| x == "1"),
            "expected the 0/1 enum, got {allowed:?}"
        );
    }
    use super::*;

    #[test]
    fn catalogue_names_are_unique_and_spec_legal() {
        let mut seen = std::collections::BTreeSet::new();
        for t in TOOLS {
            assert!(seen.insert(t.name), "duplicate tool name {}", t.name);
            assert!(
                t.name.len() <= 128
                    && t.name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')),
                "tool name `{}` uses characters the spec disallows",
                t.name
            );
        }
    }

    #[test]
    fn every_tool_declares_both_schemas() {
        for t in TOOLS {
            let i = (t.input_schema)();
            assert_eq!(
                i["type"], "object",
                "{} inputSchema must be an object",
                t.name
            );
            let o = (t.output_schema)();
            assert!(o.get("type").is_some(), "{} needs an outputSchema", t.name);
        }
    }

    #[test]
    fn list_marks_every_tool_read_only() {
        for entry in list() {
            assert_eq!(entry["annotations"]["readOnlyHint"], json!(true));
            assert_eq!(entry["annotations"]["destructiveHint"], json!(false));
        }
    }

    #[test]
    fn missing_required_argument_is_a_tool_error() {
        let err = schema_key(&json!({})).unwrap_err();
        assert!(err.message.contains("payload_type"), "got: {}", err.message);
    }

    #[test]
    fn unknown_osquery_table_suggests_near_misses() {
        // `process` is two edits from `processes` and a substring of it, so
        // either branch of `near_misses` names the fix.
        let err = osquery_table(&json!({"table": "process"})).unwrap_err();
        assert!(!err.suggestions.is_empty(), "expected suggestions");
    }

    #[test]
    fn osquery_table_returns_columns_for_a_real_table() {
        let v = osquery_table(&json!({"table": "processes"})).unwrap();
        assert_eq!(v["table"], "processes");
        assert!(
            v["columns"].as_array().is_some_and(|c| !c.is_empty()),
            "expected columns"
        );
    }

    #[test]
    fn search_respects_limit_and_reports_truncation() {
        let v = osquery_search(&json!({"query": "e", "limit": 2})).unwrap();
        assert!(v["results"].as_array().unwrap().len() <= 2);
        assert_eq!(v["truncated"], json!(true));
    }

    #[test]
    fn multi_token_query_matches_regardless_of_order() {
        // Tokens, not the whole phrase: substring-matching "update software"
        // would let token order decide whether the concept is found at all.
        let forward = schema_search(&json!({"query": "software update"})).unwrap();
        let reversed = schema_search(&json!({"query": "update software"})).unwrap();
        assert!(reversed["count"].as_u64().unwrap() > 0, "got: {reversed}");
        assert!(forward["count"].as_u64().unwrap() > 0, "got: {forward}");
    }

    #[test]
    fn results_are_tagged_with_match_quality() {
        let v = schema_search(&json!({"query": "software update"})).unwrap();
        let q = v["results"][0]["match_quality"].as_str().unwrap();
        assert!(
            ["phrase", "all_terms", "partial"].contains(&q),
            "unexpected quality: {q}"
        );
    }

    #[test]
    fn a_phrase_hit_is_not_diluted_by_single_token_matches() {
        // Every result must share the strongest tier that matched, so an
        // exact hit is never listed next to an incidental one.
        let v = schema_search(&json!({"query": "software update"})).unwrap();
        let qualities: std::collections::BTreeSet<&str> = v["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["match_quality"].as_str().unwrap())
            .collect();
        assert_eq!(qualities.len(), 1, "mixed tiers: {qualities:?}");
    }

    #[test]
    fn editor_metadata_keys_never_reach_a_caller() {
        // PFC_* is ProfileCreator widget state, arriving from scraped
        // manifests marked `required`. Trusting it produces fabricated
        // "missing required key" findings.
        let v = schema_key(&json!({"payload_type": "com.apple.systempreferences"})).unwrap();
        for k in v["keys"].as_array().unwrap() {
            let name = k["name"].as_str().unwrap();
            assert!(
                !name.starts_with("PFC_") && !name.starts_with("pfm_"),
                "editor artifact leaked into schema.key: {name}"
            );
        }
    }

    #[test]
    fn deprecated_payloads_name_their_successor() {
        // A deprecation version with no replacement is a dead end: the caller
        // must source the successor elsewhere, which is where wrong answers
        // get invented. The registry moved to mdm-schema so this is reachable.
        let v = schema_key(&json!({"payload_type": "com.apple.SoftwareUpdate"})).unwrap();
        let sb = &v["superseded_by"];
        assert!(sb.is_object(), "expected a successor, got: {sb}");
        assert_eq!(
            sb["ddm_type"],
            "com.apple.configuration.softwareupdate.settings"
        );
    }

    #[test]
    fn payloads_without_a_successor_report_null_not_absent() {
        // The field must always be present so a caller can distinguish
        // "no replacement" from "this server does not know".
        let v = schema_key(&json!({"payload_type": "com.apple.systempreferences"})).unwrap();
        assert!(
            v.get("superseded_by").is_some(),
            "superseded_by must always be present"
        );
    }

    #[test]
    fn levenshtein_bound_is_respected() {
        assert!(levenshtein_within("processes", "process", 2));
        assert!(!levenshtein_within("processes", "users", 2));
    }

    #[test]
    fn sop_tool_returns_markdown() {
        let v = sop(&json!({"topic": "mcx"})).unwrap();
        assert!(
            v["markdown"]
                .as_str()
                .is_some_and(|m| m.contains("mcx rename")),
            "expected the mcx SOP body"
        );
    }

    #[test]
    fn sop_unknown_topic_is_a_tool_error() {
        assert!(sop(&json!({"topic": "definitely-not-a-sop"})).is_err());
    }
}
