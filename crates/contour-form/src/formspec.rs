//! FormSpec v1 — the contract a form-driven authoring tool renders from.
//!
//! Two structs encode "the schema is silent" differently, and serde must follow: a
//! [`FormNode`] field is **omitted** when silent (the spec's presence counts
//! are counts of nodes carrying the field), while a [`FormSpec`] field is
//! **present and `null`**. Same `Option<T>`, opposite wire form — get it
//! backwards and the presence counts stop reproducing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Platform;
use crate::scope::ScopeClass;

/// Contract version. Changes only when a consumer would break.
pub const SPEC_VERSION: &str = "1";

/// The top-level document: one contract version, many specs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub spec_version: String,
    /// Caller-supplied; this crate does not read the clock.
    pub generated: Option<String>,
    pub specs: Vec<FormSpec>,
}

impl Document {
    pub fn new(specs: Vec<FormSpec>, generated: Option<String>) -> Self {
        Self {
            spec_version: SPEC_VERSION.to_string(),
            generated,
            specs,
        }
    }
}

/// Which table a spec came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub dataset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_ref: Option<String>,
}

/// Decides envelope, format and nesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    #[serde(rename = "ddm.configuration")]
    DdmConfiguration,
    #[serde(rename = "ddm.asset")]
    DdmAsset,
    #[serde(rename = "ddm.activation")]
    DdmActivation,
    #[serde(rename = "ddm.management")]
    DdmManagement,
    #[serde(rename = "mdm.profile")]
    MdmProfile,
    #[serde(rename = "managed-preference")]
    ManagedPreference,
}

impl Kind {
    pub fn is_declaration(self) -> bool {
        matches!(
            self,
            Kind::DdmConfiguration | Kind::DdmAsset | Kind::DdmActivation | Kind::DdmManagement
        )
    }

    /// The identifier segment for a declaration: `{org}.{segment}.{intent}`.
    pub fn identifier_segment(self) -> Option<&'static str> {
        match self {
            Kind::DdmConfiguration => Some("config"),
            Kind::DdmAsset => Some("asset"),
            Kind::DdmActivation => Some("activation"),
            Kind::DdmManagement => Some("management"),
            Kind::MdmProfile | Kind::ManagedPreference => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Apply {
    Single,
    Multiple,
    Combined,
}

impl Apply {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "single" => Some(Apply::Single),
            "multiple" => Some(Apply::Multiple),
            "combined" => Some(Apply::Combined),
            _ => None,
        }
    }
}

/// How a `.mobileconfig` carries the keys. Absent for declarations.
///
/// Both are valid deliveries for a preference domain; this is the default
/// the emitter uses, not a rule about what a device accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Nesting {
    Direct,
    McxWrapped,
}

/// The ten controls that cover every key in every source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Control {
    Text,
    Toggle,
    Number,
    List,
    Picker,
    Group,
    DictOf,
    AssetRef,
    File,
    RawAny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Presence {
    Required,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Range {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Merge {
    pub combinetype: String,
}

/// What a consumer can say about this key on a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Ok,
    RequiresOs,
    RequiresSupervision,
    Deprecated,
    Removed,
    Unavailable,
    /// The schema this key came from does not record OS availability at
    /// all, so nothing is known — which is not the same as "available".
    ///
    /// The app-schema and supplemental sources state no
    /// `introduced`/`deprecated` for anything. Apple's schema
    /// does, so a key with none there inherits the payload's availability
    /// and `Ok` is the truthful answer. Both arrive as the same nulls;
    /// only the source tells them apart, and reporting `Ok` for the second
    /// kind asserts a check nobody performed.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Availability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introduced: Option<BTreeMap<Platform, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<BTreeMap<Platform, String>>,
    /// The key's own `removed` version per platform. Apple: silently
    /// ignored on that OS and later. Absent where the source states none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<BTreeMap<Platform, String>>,
    /// Resolved against the caller's [`Target`](crate::form::Target); absent
    /// when no platform was given, because a verdict needs one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    /// Platforms of the payload on which Apple states this key does not
    /// exist (`introduced: n/a`). Absent when Apple excluded nothing — an
    /// unlisted platform inherits the payload, so this is never inferred
    /// from silence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<Vec<Platform>>,
}

/// One key. Silence is omission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormNode {
    /// Identity. Dotted. Never the leaf name. A `*` segment stands for a
    /// key the operator names (see §3.2); the markers `ANY`, `{{key}}` and
    /// `{{value}}` never appear.
    pub path: String,
    /// Leaf name, for display. `*` for an operator-named entry.
    pub key: String,
    pub depth: u8,
    pub control: Control,
    pub label: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence: Option<Presence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<Hint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merge: Option<Merge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability: Option<Availability>,
    /// Key-level scope restriction, the union across platforms — display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// Present only where the key-level scope differs by platform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_by_platform: Option<BTreeMap<Platform, Vec<String>>>,
    /// For `dict-of`: what the operator's key means.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_hint: Option<String>,
    /// For `group`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<FormNode>>,
    /// Element shape for `list` and `dict-of`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<Box<FormNode>>,
    /// What the compliance frameworks say about this key — a badge, not a
    /// rule. Top-level keys only, because that is the grain the source
    /// states. Absent unless the caller supplied [`crate::Annotations`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Vec<crate::annotations::Annotation>>,
}

/// One envelope key — the bookkeeping around the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeKey {
    pub key: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub required: bool,
    /// `apple` or `fleet`. Not decoration: `PayloadScope` exists twice with
    /// different owners, and a consumer that cannot tell them apart presents
    /// a vendor extension as Apple specification.
    pub origin: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    /// Fixed by the schema; the consumer shows it, never edits it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
    /// The key is platform-restricted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<Vec<Platform>>,
    /// On `PayloadScope` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_class_by_platform: Option<BTreeMap<Platform, ScopeClass>>,
    /// On `PayloadScope` only: top-level keys whose own scope narrows the
    /// payload's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub narrowed_by_key: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvelopeLayer {
    Declaration,
    Root,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub layer: EnvelopeLayer,
    pub keys: Vec<EnvelopeKey>,
}

/// One payload type, render-ready. Silence is `null`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormSpec {
    pub source: Source,
    pub id: String,
    pub kind: Kind,
    pub title: String,
    pub description: Option<String>,
    pub category: String,
    pub apply: Option<Apply>,
    pub platforms: Vec<Platform>,
    /// Union across platforms — **display only**, never a decision input.
    pub scopes: Vec<String>,
    /// Resolved for the target platform, or the default platform.
    pub scope_class: ScopeClass,
    /// The authority.
    pub scope_class_by_platform: BTreeMap<Platform, ScopeClass>,
    /// Raw per-platform scopes, where Apple stated them.
    pub scopes_by_platform: Option<BTreeMap<Platform, Vec<String>>>,
    pub nesting: Option<Nesting>,
    pub nodes: Vec<FormNode>,
    pub envelope: Envelope,
}
