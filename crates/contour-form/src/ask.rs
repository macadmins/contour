//! A request in plain words to deployable documents, with a model doing only
//! the part contour cannot: reading the words.
//!
//! Two pure steps around a model call this crate never makes:
//!
//! 1. [`prepare`] finds the candidate keys for the request and writes the
//!    prompt and the schema the model's reply must fit. The reply's `key` is
//!    an enumeration of the candidates, so a model that honours the schema
//!    cannot name a key contour did not offer.
//! 2. [`resolve`] takes the reply, types and validates what it chose, and
//!    returns documents, a decline, or the message to send back for one more
//!    try.
//!
//! The caller owns the transport: an HTTP request to a local server, a
//! browser `fetch`, or an operating system's on-device model. That is what
//! lets one pipeline run in the native binary and in the wasm module.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::emit::{EmitOptions, Emitted, Refusal, Setting, emit_settings};
use crate::form::{Target, form};
use crate::formspec::{FormNode, Presence, Verdict};
use crate::types::Platform;
use crate::{SchemaRegistry, mscp_rules};

/// One key the model may choose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    /// `"<payload type> <dotted path>"`: the one string the reply names it by.
    pub key: String,
    #[serde(rename = "type")]
    pub value_type: String,
    /// Must accompany any other key of its payload type.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    /// `[min, max]`, either end open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<[Option<f64>; 2]>,
    /// The value a compliance rule matching the request sets this key to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_sets: Option<serde_json::Value>,
    pub description: String,
}

impl Candidate {
    fn split(&self) -> (&str, &str) {
        self.key.split_once(' ').unwrap_or((&self.key, ""))
    }
}

/// Everything a caller needs to ask a model.
#[derive(Debug, Clone, Serialize)]
pub struct Prepared {
    pub system: String,
    pub user: String,
    /// JSON Schema for the reply: `{reason, settings: [{key, value}]}`.
    pub schema: serde_json::Value,
    /// Hand these back to [`resolve`].
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone)]
pub struct AskOptions {
    pub platform: Option<Platform>,
    /// How many searched keys to offer; required keys and rule keys are extra.
    pub limit: usize,
    /// Say to use a declaration key where one does what was asked.
    pub prefer_declarations: bool,
}

impl Default for AskOptions {
    fn default() -> Self {
        Self {
            platform: None,
            limit: 10,
            prefer_declarations: true,
        }
    }
}

const SYSTEM: &str = "You turn an IT admin's request into Apple device management settings.\n\
You are given candidate keys found in Apple's schema, and compliance rules that match the request.\n\
- First write `reason`: for each thing the request asks for, the candidate key that controls it and the value to give it. If the candidates are about something else, say so.\n\
- Then give one setting for every key named in `reason`, including every number the request states.\n\
- `value` is text: true or false for a Boolean, digits for a number, or one of the candidate's options exactly.\n\
- Read each description for polarity: many keys are \"allow...\" and need false to turn a feature off.\n\
- Convert units to what the description states (minutes, seconds, days).\n\
- A candidate with `rule_sets` is what a matching compliance rule deploys; prefer it and its value.\n\
- A candidate marked `required` must be included whenever you use another key of the same payload type.\n\
- Set only what was asked for, plus those required keys.\n\
- A rule marked `enforced_by: script` cannot be met by any profile. If that is what was asked, return no settings.\n\
- When no candidate does what was asked, return no settings and give the reason.\n\
Reply with JSON only, no prose and no code fence, in exactly this shape:\n\
{\"reason\": \"...\", \"settings\": [{\"key\": \"<a candidate's key, copied exactly>\", \"value\": \"<text>\"}]}";

/// A type's FormSpec nodes by path, on the target platform.
fn nodes_of(reg: &SchemaRegistry, type_id: &str, target: &Target) -> BTreeMap<String, FormNode> {
    fn walk(nodes: Vec<FormNode>, out: &mut BTreeMap<String, FormNode>) {
        for mut n in nodes {
            let children = n.children.take().unwrap_or_default();
            out.insert(n.path.clone(), n);
            walk(children, out);
        }
    }
    let mut out = BTreeMap::new();
    // A type with no form on this platform contributes nothing.
    if let Ok(spec) = form(reg, type_id, target) {
        walk(spec.nodes, &mut out);
    }
    out
}

/// A key the target platform has, and that names a real key: `*` stands for
/// a key the operator names.
fn usable(n: &FormNode) -> bool {
    let unavailable = n
        .availability
        .as_ref()
        .and_then(|a| a.verdict.as_ref())
        .is_some_and(|v| matches!(v, Verdict::Unavailable | Verdict::Removed));
    !unavailable && !n.path.split('.').any(|s| s == "*")
}

fn parent(path: &str) -> &str {
    path.rsplit_once('.').map_or("", |(p, _)| p)
}

fn candidate(type_id: &str, n: &FormNode, required: bool) -> Candidate {
    let help: String = n
        .help
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    Candidate {
        key: format!("{type_id} {}", n.path),
        value_type: n.r#type.clone().unwrap_or_default(),
        required,
        options: n.options.clone().unwrap_or_default(),
        range: n.range.as_ref().map(|r| [r.min, r.max]),
        rule_sets: None,
        description: if help.chars().count() > 300 {
            format!("{}…", help.chars().take(300).collect::<String>())
        } else {
            help
        },
    }
}

/// Find the candidates for `request` and write the prompt.
pub fn prepare(reg: &SchemaRegistry, request: &str, opts: &AskOptions) -> Prepared {
    let target = Target {
        platform: opts.platform,
        os_version: None,
    };
    let mut specs: BTreeMap<String, BTreeMap<String, FormNode>> = BTreeMap::new();
    let mut nodes = |type_id: &str| -> BTreeMap<String, FormNode> {
        specs
            .entry(type_id.to_string())
            .or_insert_with(|| nodes_of(reg, type_id, &target))
            .clone()
    };

    // "block the camera and screenshots" is two searches; ranked as one
    // phrase, the second setting is outvoted by the first.
    let lower = request.to_lowercase();
    let mut parts: Vec<&str> = vec![request];
    parts.extend(
        lower
            .split([',', ';'])
            .flat_map(|p| p.split(" and "))
            .map(str::trim)
            .filter(|p| !p.is_empty() && *p != lower),
    );
    let ranked: Vec<Vec<(String, String)>> = parts
        .iter()
        .map(|p| {
            reg.rank_fields(p)
                .into_iter()
                .filter(|h| h.manifest.is_authorable())
                .take(opts.limit * 4)
                .map(|h| (h.manifest.payload_type.clone(), h.field.path.clone()))
                .filter(|(t, path)| nodes(t).get(path).is_some_and(usable))
                .collect()
        })
        .collect();

    let mut picked: Vec<Candidate> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut add = |c: Candidate, picked: &mut Vec<Candidate>| {
        if seen.insert(c.key.clone()) {
            picked.push(c);
        }
    };

    // What matching compliance rules deploy comes first: it is the one place
    // that says "Disable Siri" means `allowAssistant: false`.
    let rules = mscp_rules::matching(request, 3);
    for rule in &rules {
        for (type_id, key, value) in rule.keys() {
            let Some(m) = reg.get(&type_id).or_else(|| reg.get_by_name(&type_id)) else {
                continue;
            };
            let by_path = nodes(&m.payload_type);
            // mSCP writes a top-level key by name; the path escapes its dots.
            let node = by_path
                .values()
                .find(|n| n.depth == 0 && (n.path == key || n.key == key));
            if let Some(n) = node.filter(|n| usable(n)) {
                let mut c = candidate(&m.payload_type, n, false);
                c.rule_sets = Some(value);
                add(c, &mut picked);
            }
        }
    }

    // Round-robin across the parts, so each asked-for setting gets its share.
    let searched_from = picked.len();
    let mut i = 0;
    while picked.len() - searched_from < opts.limit && ranked.iter().any(|r| i < r.len()) {
        for r in &ranked {
            if let Some((t, path)) = r.get(i)
                && picked.len() - searched_from < opts.limit
                && let Some(n) = nodes(t).get(path)
            {
                add(candidate(t, n, false), &mut picked);
            }
        }
        i += 1;
    }

    // Required keys beside a candidate and at the top of its type, for the
    // three best-placed types only: for the rest they are noise.
    let mut leading: Vec<String> = Vec::new();
    for c in &picked {
        let t = c.split().0.to_string();
        if !leading.contains(&t) {
            leading.push(t);
        }
    }
    leading.truncate(3);
    for c in picked.clone() {
        let (t, path) = c.split();
        if !leading.iter().any(|l| l == t) {
            continue;
        }
        for n in nodes(t).values() {
            let beside = parent(&n.path).is_empty() || parent(&n.path) == parent(path);
            if n.presence == Some(Presence::Required) && beside && usable(n) {
                add(candidate(t, n, true), &mut picked);
            }
        }
    }

    let keys: Vec<&str> = picked.iter().map(|c| c.key.as_str()).collect();
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "reason": {"type": "string"},
            "settings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string", "enum": keys},
                        "value": {"type": "string"}
                    },
                    "required": ["key", "value"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["reason", "settings"],
        "additionalProperties": false
    });
    let rules_json: Vec<serde_json::Value> = rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "title": r.title,
                "enforced_by": r.enforced_by,
                "settings": r.settings,
            })
        })
        .collect();
    let user = format!(
        "Request: {request}\nPlatform: {}\n{}Compliance rules that match:\n{}\nCandidates:\n{}",
        opts.platform.map_or("any", |p| p.as_str()),
        if opts.prefer_declarations {
            "When a declaration key (payload type starting com.apple.configuration.) does what was asked, use it and not the older profile key.\n"
        } else {
            ""
        },
        serde_json::Value::Array(rules_json),
        serde_json::to_string(&picked).unwrap_or_default(),
    );
    Prepared {
        system: SYSTEM.to_string(),
        user,
        schema,
        candidates: picked,
    }
}

/// What a model's reply came to.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum Resolved {
    /// Validated and written.
    Documents {
        documents: Vec<Emitted>,
        settings: Vec<Chosen>,
    },
    /// Nothing to write: the model chose no candidate, and why.
    Declined { reason: String },
    /// The schema refused part of the choice. `message` is what to send the
    /// model as the next user turn, after its own reply.
    Retry {
        message: String,
        refused: Vec<Refusal>,
        settings: Vec<Chosen>,
    },
}

/// A setting the model chose, as it will be validated.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Chosen {
    #[serde(rename = "type")]
    pub type_id: String,
    pub path: String,
    pub value: serde_json::Value,
}

#[derive(Deserialize)]
struct Reply {
    /// Text when the reply fits the schema. A model that is not held to it
    /// sometimes writes a list here; the settings are still usable.
    #[serde(default)]
    reason: serde_json::Value,
    #[serde(default)]
    settings: Vec<ReplySetting>,
}

#[derive(Deserialize)]
struct ReplySetting {
    key: String,
    value: serde_json::Value,
}

/// Turn a model's reply into documents, a decline, or one more question.
///
/// `candidates` are the ones [`prepare`] returned. A key that is not among
/// them is dropped: a model without schema-constrained output can invent
/// one, and what it invents was never checked against the request.
pub fn resolve(
    reg: &SchemaRegistry,
    candidates: &[Candidate],
    reply: &str,
    opts: &EmitOptions,
) -> Resolved {
    // Small models wrap JSON in prose or a code fence; take the outermost object.
    let body = match (reply.find('{'), reply.rfind('}')) {
        (Some(a), Some(b)) if a < b => &reply[a..=b],
        _ => reply,
    };
    let Ok(parsed) = serde_json::from_str::<Reply>(body) else {
        return Resolved::Declined {
            reason: format!(
                "The model's reply was not the JSON asked for: {}",
                reply.chars().take(200).collect::<String>()
            ),
        };
    };

    let known: BTreeSet<&str> = candidates.iter().map(|c| c.key.as_str()).collect();
    let chosen: Vec<Chosen> = parsed
        .settings
        .into_iter()
        .filter(|s| known.contains(s.key.as_str()))
        .filter_map(|s| {
            let (t, path) = s.key.split_once(' ')?;
            Some(Chosen {
                type_id: t.to_string(),
                path: path.to_string(),
                value: s.value,
            })
        })
        .collect();
    if chosen.is_empty() {
        return Resolved::Declined {
            reason: match parsed.reason {
                serde_json::Value::String(s) if !s.trim().is_empty() => s,
                _ => "The model chose no key from the candidates.".to_string(),
            },
        };
    }

    let settings: Vec<Setting> = chosen
        .iter()
        .map(|c| Setting {
            type_id: c.type_id.clone(),
            path: c.path.clone(),
            value: c.value.clone(),
        })
        .collect();
    let outcome = emit_settings(reg, &settings, opts);
    if outcome.refused.is_empty() {
        return Resolved::Documents {
            documents: outcome.documents,
            settings: chosen,
        };
    }
    let lines: Vec<String> = outcome
        .refused
        .iter()
        .map(|r| {
            let mut line = format!("{} {}: {}", r.type_id, r.path, r.message);
            if !r.allowed.is_empty() {
                line.push_str(&format!(" Allowed: {}.", r.allowed.join(", ")));
            }
            if let Some([min, max]) = r.range {
                let end = |v: Option<f64>| v.map_or("open".to_string(), |v| v.to_string());
                line.push_str(&format!(" Range: {} to {}.", end(min), end(max)));
            }
            if let Some(d) = &r.did_you_mean {
                line.push_str(&format!(" Did you mean {d}?"));
            }
            line
        })
        .collect();
    Resolved::Retry {
        message: format!(
            "contour's validator refused these. Correct them and reply with the full JSON again:\n{}",
            lines.join("\n")
        ),
        refused: outcome.refused,
        settings: chosen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> SchemaRegistry {
        SchemaRegistry::embedded().unwrap()
    }

    fn opts() -> AskOptions {
        AskOptions {
            platform: Some(Platform::MacOS),
            ..Default::default()
        }
    }

    fn emit_opts() -> EmitOptions {
        EmitOptions {
            org: "com.acme".into(),
            platform: Some(Platform::MacOS),
            ..Default::default()
        }
    }

    #[test]
    fn the_candidate_is_offered_and_the_schema_names_only_candidates() {
        let r = reg();
        let p = prepare(&r, "turn off airdrop", &opts());
        let airdrop = "com.apple.applicationaccess allowAirDrop";
        assert!(p.candidates.iter().any(|c| c.key == airdrop), "{:?}", p.candidates);
        let allowed = &p.schema["properties"]["settings"]["items"]["properties"]["key"]["enum"];
        assert_eq!(allowed.as_array().unwrap().len(), p.candidates.len());
        assert!(p.user.contains(airdrop));
    }

    /// The schema's text never says Siri is `allowAssistant`; the rule does.
    #[test]
    fn a_compliance_rule_brings_its_key_and_value() {
        let r = reg();
        let p = prepare(&r, "disable siri", &opts());
        let c = p
            .candidates
            .iter()
            .find(|c| c.key == "com.apple.applicationaccess allowAssistant")
            .expect("allowAssistant offered");
        assert_eq!(c.rule_sets, Some(serde_json::json!(false)));
    }

    #[test]
    fn a_reply_becomes_documents_a_retry_or_a_decline() {
        let r = reg();
        let p = prepare(&r, "turn off airdrop", &opts());
        let key = "com.apple.applicationaccess allowAirDrop";

        // In a code fence, with an invented key beside the real one.
        let reply = format!(
            "```json\n{{\"reason\":\"x\",\"settings\":[{{\"key\":\"{key}\",\"value\":\"false\"}},{{\"key\":\"com.apple.applicationaccess allowMadeUp\",\"value\":\"false\"}}]}}\n```"
        );
        match resolve(&r, &p.candidates, &reply, &emit_opts()) {
            Resolved::Documents { documents, settings } => {
                assert_eq!(settings.len(), 1, "the invented key is dropped");
                assert!(documents[0].body.contains("<key>allowAirDrop</key>"));
                assert!(!documents[0].body.contains("allowMadeUp"));
            }
            other => panic!("expected documents, got {other:?}"),
        }

        // A value of the wrong type goes back with the diagnostic.
        let reply = format!("{{\"reason\":\"x\",\"settings\":[{{\"key\":\"{key}\",\"value\":\"sometimes\"}}]}}");
        match resolve(&r, &p.candidates, &reply, &emit_opts()) {
            Resolved::Retry { message, .. } => assert!(message.contains("allowAirDrop"), "{message}"),
            other => panic!("expected a retry, got {other:?}"),
        }

        let reply = r#"{"reason":"No profile can do this.","settings":[]}"#;
        match resolve(&r, &p.candidates, reply, &emit_opts()) {
            Resolved::Declined { reason } => assert_eq!(reason, "No profile can do this."),
            other => panic!("expected a decline, got {other:?}"),
        }
    }
}
