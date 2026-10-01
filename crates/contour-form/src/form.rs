//! `form()` — a payload type projected onto the FormSpec contract.
//!
//! Four rules live here so no client re-implements them: control
//! resolution (schema type + constraints → one of ten controls),
//! availability against a target, scope per platform inherited down the
//! subtree, and identity by dotted path. Operator-named keys — Apple's
//! `ANY`, ProfileCreator's `{{key}}`/`{{value}}` — become `dict-of` with the
//! value shape re-rooted under a `*` segment, so no emitted path carries a
//! marker.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::formspec::{
    Apply, Availability, Control, Envelope, EnvelopeKey, EnvelopeLayer, FormNode, FormSpec, Hint,
    Kind, Merge, Nesting, Presence, Range, Source, Verdict,
};
use crate::scope::{self, Scope, ScopeClass};
use crate::types::{FieldDefinition, FieldType, PayloadManifest, Platform};
use crate::{SchemaRegistry, version};

/// What the caller is authoring for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Target {
    pub platform: Option<Platform>,
    /// `"26.0"` and the like. Only read when `platform` is set.
    pub os_version: Option<String>,
}

/// The right refusal for a type that is not in the registry.
fn withheld_or_unknown(registry: &SchemaRegistry, type_id: &str) -> FormError {
    match registry.why_withheld(type_id) {
        Some(why) => FormError::Withheld(why),
        None => FormError::UnknownType(type_id.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormError {
    UnknownType(String),
    /// The payload type exists, but its only description is the deprecated
    /// community corpus, which is not loaded. Carries the full explanation.
    ///
    /// Distinct from [`FormError::UnknownType`] on purpose: an agent told a
    /// type is unknown invents keys for it, while one told the source is
    /// withheld can ask for it or choose something else.
    Withheld(String),
    /// Commands, check-in messages and Apple's shared structures have
    /// schemas and are not authorable; they must not appear in a FormSpec
    /// document. `kind` is the reason, from
    /// [`mdm_schema::PayloadKind::not_authorable_reason`].
    NotAuthorable {
        id: String,
        kind: String,
    },
    UnsupportedPlatform {
        id: String,
        platform: Platform,
    },
}

impl std::fmt::Display for FormError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormError::UnknownType(id) => write!(f, "payload type '{id}' is not in the schema"),
            FormError::Withheld(why) => write!(f, "{why}"),
            FormError::NotAuthorable { id, kind } => write!(f, "'{id}' is {kind}"),
            FormError::UnsupportedPlatform { id, platform } => {
                write!(f, "'{id}' does not exist on {}", platform.as_str())
            }
        }
    }
}

impl std::error::Error for FormError {}

/// The order platforms are reported in, and the default target when the
/// caller names none.
pub const PLATFORM_ORDER: [Platform; 5] = [
    Platform::MacOS,
    Platform::Ios,
    Platform::TvOS,
    Platform::WatchOS,
    Platform::VisionOS,
];

/// Build the contract for one payload type, without annotations.
pub fn form(reg: &SchemaRegistry, type_id: &str, target: &Target) -> Result<FormSpec, FormError> {
    form_with(reg, type_id, target, None)
}

/// Build the contract, attaching what the compliance frameworks say about
/// each top-level key when `annotations` is supplied.
pub fn form_with(
    reg: &SchemaRegistry,
    type_id: &str,
    target: &Target,
    annotations: Option<&crate::annotations::Annotations>,
) -> Result<FormSpec, FormError> {
    let m = reg
        .get(type_id)
        .or_else(|| reg.get_by_name(type_id))
        .ok_or_else(|| withheld_or_unknown(reg, type_id))?;
    if !m.is_authorable() {
        return Err(FormError::NotAuthorable {
            id: m.payload_type.clone(),
            kind: m
                .kind
                .and_then(mdm_schema::PayloadKind::not_authorable_reason)
                .unwrap_or("not a document an operator authors")
                .to_string(),
        });
    }

    let platforms: Vec<Platform> = PLATFORM_ORDER
        .iter()
        .copied()
        .filter(|p| platform_flag(m, *p))
        .collect();
    if let Some(p) = target.platform
        && !platforms.is_empty()
        && !platforms.contains(&p)
    {
        return Err(FormError::UnsupportedPlatform {
            id: m.payload_type.clone(),
            platform: p,
        });
    }

    let kind = kind_of(m);

    // Scope, per platform, never unioned for a decision.
    let mut scope_class_by_platform = BTreeMap::new();
    let mut scopes_by_platform: BTreeMap<Platform, Vec<String>> = BTreeMap::new();
    let mut union: BTreeSet<Scope> = BTreeSet::new();
    for p in &platforms {
        let set = scope::payload_scopes(m, *p);
        scope_class_by_platform.insert(*p, ScopeClass::classify(set.as_ref()));
        if let Some(s) = set {
            union.extend(s.iter().copied());
            scopes_by_platform.insert(*p, s.iter().map(|x| x.to_string()).collect());
        }
    }
    let default_platform = target.platform.or_else(|| platforms.first().copied());
    let scope_class = default_platform
        .and_then(|p| scope_class_by_platform.get(&p).copied())
        .unwrap_or(ScopeClass::Unspecified);

    let mut nodes = children_of(m, None, "", target);
    if let Some(ann) = annotations {
        for n in &mut nodes {
            if let Some(a) = ann.for_key(&m.payload_type, &n.key) {
                n.annotations = Some(a.to_vec());
            }
        }
    }
    let envelope = envelope_for(reg, m, kind, &scope_class_by_platform, &nodes);

    Ok(FormSpec {
        source: {
            // The table a spec came from, and the upstream commit that table
            // was read from.
            //
            // Read off the manifest's OWN source, not its kind. Kind says
            // nothing about provenance: Santa, SAP Privileges and Defender
            // are ManagedPreferences derived from their vendors' own sources,
            // and `posture-supplemental` keys are stated by the dataset with
            // a citation. Attributing by kind would tell a consumer that
            // vendor data came from a community corpus.
            let (dataset, upstream) = match m.manifest_source.as_deref() {
                Some("profile-manifests") => ("profilecreator", "ProfileManifests"),
                // A vendor's own document. Its revision is recorded in the
                // document, not in the dataset's source table, so there is no
                // upstream ref to look up here — better absent than the wrong
                // repository's commit.
                Some(s) if s.starts_with("app-schema") => ("app-schema", ""),
                Some("posture-supplemental") => ("posture-supplemental", ""),
                Some(_) => ("capabilities", "device-management"),
                // Older datasets carry no manifest_source. Fall back to the
                // kind, which is what this did for everything.
                None => match m.kind {
                    Some(mdm_schema::PayloadKind::ManagedPreference) => {
                        ("profilecreator", "ProfileManifests")
                    }
                    _ => ("capabilities", "device-management"),
                },
            };
            Source {
                dataset: dataset.into(),
                channel: reg.channel().map(|c| c.to_string()),
                upstream_ref: (!upstream.is_empty())
                    .then(|| reg.upstream_revision(upstream).map(str::to_string))
                    .flatten(),
            }
        },
        id: m.payload_type.clone(),
        kind,
        title: if m.title.is_empty() {
            m.payload_type.clone()
        } else {
            m.title.clone()
        },
        description: (!m.description.is_empty()).then(|| m.description.clone()),
        category: m
            .category
            .strip_prefix("ddm-")
            .unwrap_or(&m.category)
            .to_string(),
        apply: m.apply_mode.as_deref().and_then(Apply::parse),
        platforms,
        scopes: union.iter().map(|s| s.to_string()).collect(),
        scope_class,
        scope_class_by_platform,
        scopes_by_platform: (!scopes_by_platform.is_empty()).then_some(scopes_by_platform),
        nesting: default_nesting(kind),
        nodes,
        envelope,
    })
}

/// Every authorable type in the registry, in a stable order.
pub fn form_all(reg: &SchemaRegistry, target: &Target) -> Vec<Result<FormSpec, FormError>> {
    form_all_with(reg, target, None)
}

/// [`form_all`], annotated.
pub fn form_all_with(
    reg: &SchemaRegistry,
    target: &Target,
    annotations: Option<&crate::annotations::Annotations>,
) -> Vec<Result<FormSpec, FormError>> {
    let mut ids: Vec<&str> = reg
        .all()
        .filter(|m| m.is_authorable())
        .map(|m| m.payload_type.as_str())
        .collect();
    ids.sort_unstable();
    ids.into_iter()
        .map(|id| form_with(reg, id, target, annotations))
        .collect()
}

fn platform_flag(m: &PayloadManifest, p: Platform) -> bool {
    match p {
        Platform::MacOS => m.platforms.macos,
        Platform::Ios => m.platforms.ios,
        Platform::TvOS => m.platforms.tvos,
        Platform::WatchOS => m.platforms.watchos,
        Platform::VisionOS => m.platforms.visionos,
        Platform::Windows => m.platforms.windows,
    }
}

/// The envelope a `.mobileconfig` for this kind uses **by default**. A
/// preference domain is MCX-wrapped; direct delivery is equally valid and
/// the emitter offers it. Declarations have no envelope of this sort.
pub fn default_nesting(kind: Kind) -> Option<Nesting> {
    match kind {
        Kind::MdmProfile => Some(Nesting::Direct),
        Kind::ManagedPreference => Some(Nesting::McxWrapped),
        _ => None,
    }
}

/// `kind` from the source's own column; the category is the fallback for
/// external schemas that carry no kind.
pub fn kind_of(m: &PayloadManifest) -> Kind {
    use mdm_schema::PayloadKind as K;
    let ddm = || match m.category.strip_prefix("ddm-") {
        Some("asset") => Kind::DdmAsset,
        Some("activation") => Kind::DdmActivation,
        Some("management") => Kind::DdmManagement,
        _ => Kind::DdmConfiguration,
    };
    match m.kind {
        Some(K::DdmDeclaration) => ddm(),
        Some(K::ManagedPreference) => Kind::ManagedPreference,
        Some(K::MdmProfile | K::CspSetting | K::AdmxPolicy) => Kind::MdmProfile,
        // All three are refused by `is_authorable` before reaching here;
        // the arm exists so the match is exhaustive, not because the mapping
        // means anything.
        Some(K::MdmCommand | K::MdmCheckin | K::SharedStructure) => Kind::MdmProfile,
        None if m.category.starts_with("ddm-") => ddm(),
        None if matches!(m.category.as_str(), "apps" | "prefs") => Kind::ManagedPreference,
        None => Kind::MdmProfile,
    }
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

/// Children of `parent` (or the top level), in declaration order, as nodes.
/// `out_prefix` is the *emitted* path of the parent — schema paths and
/// emitted paths diverge only where a marker segment became `*`.
fn children_of(
    m: &PayloadManifest,
    parent: Option<&FieldDefinition>,
    out_prefix: &str,
    target: &Target,
) -> Vec<FormNode> {
    let parent_path = parent.map(|p| p.path.as_str());
    let spec_platforms: Vec<Platform> = PLATFORM_ORDER
        .iter()
        .copied()
        .filter(|p| platform_flag(m, *p))
        .collect();
    m.fields_in_order()
        .filter(|f| f.parent_key.as_deref() == parent_path)
        .filter(|f| !f.is_placeholder())
        .map(|f| {
            node(
                m,
                f,
                &join(out_prefix, &f.name),
                &f.name,
                target,
                &spec_platforms,
            )
        })
        .collect()
}

fn join(prefix: &str, seg: &str) -> String {
    if prefix.is_empty() {
        seg.to_string()
    } else {
        format!("{prefix}.{seg}")
    }
}

fn node(
    m: &PayloadManifest,
    f: &FieldDefinition,
    out_path: &str,
    key: &str,
    target: &Target,
    spec_platforms: &[Platform],
) -> FormNode {
    let (control, children, item, key_hint) =
        resolve_control(m, f, out_path, target, spec_platforms);

    let (scopes, scopes_by_platform) = key_scopes(f);

    FormNode {
        path: out_path.to_string(),
        key: key.to_string(),
        depth: f.depth,
        control,
        label: if f.title.is_empty() || f.title == f.name {
            de_camel(key)
        } else {
            f.title.clone()
        },
        r#type: Some(f.field_type.as_str().to_string()),
        help: (!f.description.is_empty()).then(|| f.description.clone()),
        presence: Some(if f.flags.required {
            Presence::Required
        } else {
            Presence::Optional
        }),
        default: f.default.as_deref().map(|d| typed_default(f.field_type, d)),
        options: (!f.allowed_values.is_empty()).then(|| f.allowed_values.clone()),
        range: (f.range_min.is_some() || f.range_max.is_some()).then_some(Range {
            min: f.range_min,
            max: f.range_max,
        }),
        hint: hint_for(f),
        asset_types: (!f.asset_types.is_empty()).then(|| f.asset_types.clone()),
        sensitive: f.flags.sensitive.then_some(true),
        merge: f.combinetype.as_ref().map(|c| Merge {
            combinetype: c.clone(),
        }),
        availability: availability(
            f,
            m.fields_recording_availability.contains(&f.path),
            &m.os_support,
            spec_platforms,
            target,
        ),
        scopes,
        scopes_by_platform,
        key_hint,
        children,
        item,
        annotations: None,
    }
}

type Resolved = (
    Control,
    Option<Vec<FormNode>>,
    Option<Box<FormNode>>,
    Option<String>,
);

fn resolve_control(
    m: &PayloadManifest,
    f: &FieldDefinition,
    out_path: &str,
    target: &Target,
    spec_platforms: &[Platform],
) -> Resolved {
    match f.field_type {
        FieldType::Dictionary => {
            if let Some(shape) = m.dynamic_value_shape(f) {
                // Re-root the value shape under the operator's key. The
                // marker's own children keep their names; only the marker
                // segment changes.
                let item_path = join(out_path, "*");
                let item = node(m, shape, &item_path, "*", target, spec_platforms);
                let hint = if !shape.description.is_empty() {
                    shape.description.clone()
                } else if !f.description.is_empty() {
                    f.description.clone()
                } else {
                    "Each key is supplied by the operator.".to_string()
                };
                return (Control::DictOf, None, Some(Box::new(item)), Some(hint));
            }
            let kids = children_of(m, Some(f), out_path, target);
            if kids.is_empty() {
                (Control::RawAny, None, None, None)
            } else {
                (Control::Group, Some(kids), None, None)
            }
        }
        FieldType::Array => {
            let kids = children_of(m, Some(f), out_path, target);
            let item = match kids.len() {
                0 => None,
                1 => Some(Box::new(kids.into_iter().next().expect("one child"))),
                _ => Some(Box::new(FormNode {
                    path: out_path.to_string(),
                    key: f.name.clone(),
                    depth: f.depth + 1,
                    control: Control::Group,
                    label: de_camel(&f.name),
                    r#type: Some("Dictionary".into()),
                    help: None,
                    presence: None,
                    default: None,
                    options: None,
                    range: None,
                    hint: None,
                    asset_types: None,
                    sensitive: None,
                    merge: None,
                    availability: None,
                    scopes: None,
                    scopes_by_platform: None,
                    key_hint: None,
                    children: Some(kids),
                    item: None,
                    annotations: None,
                })),
            };
            (Control::List, None, item, None)
        }
        FieldType::String if !f.asset_types.is_empty() => (Control::AssetRef, None, None, None),
        FieldType::String | FieldType::Integer if !f.allowed_values.is_empty() => {
            (Control::Picker, None, None, None)
        }
        FieldType::String | FieldType::Date => (Control::Text, None, None, None),
        FieldType::Integer | FieldType::Real => (Control::Number, None, None, None),
        FieldType::Boolean => (Control::Toggle, None, None, None),
        FieldType::Data => (Control::File, None, None, None),
    }
}

fn hint_for(f: &FieldDefinition) -> Option<Hint> {
    let subtype = f
        .subtype
        .clone()
        .or_else(|| matches!(f.field_type, FieldType::Date).then(|| "date".to_string()));
    let pattern = f.format.clone();
    (subtype.is_some() || pattern.is_some()).then_some(Hint { subtype, pattern })
}

/// Typed, not stringified: `"true"` on a Boolean is `true`.
fn typed_default(ty: FieldType, raw: &str) -> serde_json::Value {
    match ty {
        FieldType::Boolean => raw.parse::<bool>().map_or_else(
            |_| serde_json::Value::String(raw.into()),
            serde_json::Value::Bool,
        ),
        FieldType::Integer => raw
            .parse::<i64>()
            .map_or_else(|_| serde_json::Value::String(raw.into()), |n| n.into()),
        FieldType::Real => raw
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map_or_else(
                || serde_json::Value::String(raw.into()),
                serde_json::Value::Number,
            ),
        _ => serde_json::Value::String(raw.to_string()),
    }
}

fn availability(
    f: &FieldDefinition,
    records_availability: bool,
    payload_os: &HashMap<Platform, crate::types::OsSupportDetail>,
    spec_platforms: &[Platform],
    target: &Target,
) -> Option<Availability> {
    let to_map = |h: &HashMap<Platform, String>| -> Option<BTreeMap<Platform, String>> {
        (!h.is_empty()).then(|| h.iter().map(|(p, v)| (*p, v.clone())).collect())
    };
    let introduced = to_map(&f.introduced_by_platform);
    let deprecated = to_map(&f.deprecated_by_platform);
    let removed = to_map(&f.removed_by_platform);

    let verdict = target.platform.map(|p| {
        if !f.platforms.is_empty() && !f.platforms.contains(&p) {
            return Verdict::Unavailable;
        }
        // The whole payload gone from this OS takes every key with it, and
        // it is Apple's statement about the payload, so it holds even for a
        // key whose own source records nothing. Checked before the Unknown
        // gate for that reason.
        if let Some(os) = target.os_version.as_deref()
            && let Some(gone) = payload_os.get(&p).and_then(|o| o.removed.as_deref())
            && version::at_least(os, gone) == Some(true)
        {
            return Verdict::Removed;
        }
        // Platform exclusion above is stated by every source. Version
        // availability is not: where the source records none, say so
        // rather than falling through to `Ok`, which would claim the key
        // is available on an OS nobody checked.
        if !records_availability {
            return Verdict::Unknown;
        }
        if let Some(os) = target.os_version.as_deref() {
            if let Some(need) = f.introduced_by_platform.get(&p)
                && version::at_least(os, need) == Some(false)
            {
                return Verdict::RequiresOs;
            }
            // Removed before Deprecated: a key deprecated at 14.0 and
            // removed at 15.0, targeted at 15.0, is removed. Reporting
            // Deprecated there says "still works, flagged" about a key the
            // device ignores. Per Apple, removed keys are silently ignored
            // on that OS and later — so this is the verdict that had never
            // once been produced, for want of the data.
            if let Some(gone) = f.removed_by_platform.get(&p)
                && version::at_least(os, gone) == Some(true)
            {
                return Verdict::Removed;
            }
            if let Some(gone) = f.deprecated_by_platform.get(&p)
                && version::at_least(os, gone) == Some(true)
            {
                return Verdict::Deprecated;
            }
        }
        if f.flags.supervised {
            return Verdict::RequiresSupervision;
        }
        Verdict::Ok
    });

    // `f.platforms` is empty unless Apple excluded the key somewhere; then it
    // is the payload's platforms minus the exclusions.
    let unavailable: Option<Vec<Platform>> = (!f.platforms.is_empty())
        .then(|| {
            spec_platforms
                .iter()
                .copied()
                .filter(|p| !f.platforms.contains(p))
                .collect::<Vec<_>>()
        })
        .filter(|u| !u.is_empty());

    (introduced.is_some()
        || deprecated.is_some()
        || removed.is_some()
        || verdict.is_some()
        || unavailable.is_some())
    .then_some(Availability {
        introduced,
        deprecated,
        removed,
        verdict,
        unavailable,
    })
}

/// The union for display, and the per-platform map only where platforms
/// disagree.
type KeyScopes = (Option<Vec<String>>, Option<BTreeMap<Platform, Vec<String>>>);

/// Key-level scopes: the union for display, and the per-platform map only
/// where platforms disagree.
fn key_scopes(f: &FieldDefinition) -> KeyScopes {
    if f.allowed_scopes.is_empty() {
        return (None, None);
    }
    let per: BTreeMap<Platform, Vec<String>> = f
        .allowed_scopes
        .iter()
        .map(|(p, v)| {
            let set: BTreeSet<Scope> = v.iter().filter_map(|s| Scope::parse(s)).collect();
            (*p, set.iter().map(|s| s.to_string()).collect())
        })
        .collect();
    let union: BTreeSet<String> = per.values().flatten().cloned().collect();
    let differs = per.values().collect::<BTreeSet<_>>().len() > 1;
    (Some(union.into_iter().collect()), differs.then_some(per))
}

/// `AllowDisablingFraudWarning` → `Allow Disabling Fraud Warning`; acronyms
/// stay together (`URL`, `PayloadUUID` → `Payload UUID`).
pub fn de_camel(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len() + 8);
    for (i, &c) in chars.iter().enumerate() {
        if i > 0 && c.is_uppercase() {
            let prev = chars[i - 1];
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if prev.is_lowercase() || prev.is_ascii_digit() || (prev.is_uppercase() && next_lower) {
                out.push(' ');
            }
        }
        out.push(if c == '_' { ' ' } else { c });
    }
    out
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

fn envelope_for(
    reg: &SchemaRegistry,
    m: &PayloadManifest,
    kind: Kind,
    scope_class_by_platform: &BTreeMap<Platform, ScopeClass>,
    nodes: &[FormNode],
) -> Envelope {
    let narrowed: Vec<String> = nodes
        .iter()
        .filter(|n| n.scopes.is_some())
        .map(|n| n.path.clone())
        .collect();

    if kind.is_declaration() {
        let key = |k: &str, ty: &str, required: bool, desc: &str| EnvelopeKey {
            key: k.into(),
            r#type: ty.into(),
            required,
            origin: "apple".into(),
            description: desc.into(),
            default: None,
            options: None,
            readonly: None,
            platforms: None,
            scope_class_by_platform: None,
            narrowed_by_key: None,
        };
        let mut ty = key("Type", "String", true, "The declaration type.");
        ty.readonly = Some(true);
        ty.default = Some(serde_json::Value::String(m.payload_type.clone()));
        let keys = vec![
            ty,
            key(
                "Identifier",
                "String",
                true,
                "Unique identifier for this declaration; `{org}.{segment}.{intent}`.",
            ),
            key(
                "ServerToken",
                "String",
                false,
                "Server-provided token for change tracking.",
            ),
            EnvelopeKey {
                key: "PayloadScope".into(),
                r#type: "String".into(),
                required: false,
                origin: "fleet".into(),
                description: "Delivery channel hint Fleet reads on macOS. Not an Apple key: \
                              Apple's DDM schema has no scope field; the channel is decided \
                              at delivery time."
                    .into(),
                default: None,
                options: Some(vec!["System".into(), "User".into()]),
                readonly: None,
                platforms: Some(vec![Platform::MacOS]),
                scope_class_by_platform: Some(scope_class_by_platform.clone()),
                narrowed_by_key: Some(narrowed),
            },
        ];
        return Envelope {
            layer: EnvelopeLayer::Declaration,
            keys,
        };
    }

    // Profiles: the root keys Apple documents in `TopLevel`.
    let mut keys = Vec::new();
    if let Some(top) = reg.get("TopLevel") {
        for f in top.fields_in_order() {
            if f.parent_key.is_some()
                || f.is_placeholder()
                || matches!(
                    f.name.as_str(),
                    "PayloadContent" | "EncryptedPayloadContent"
                )
            {
                continue;
            }
            let is_scope = f.name == "PayloadScope";
            keys.push(EnvelopeKey {
                key: f.name.clone(),
                r#type: f.field_type.as_str().into(),
                required: f.flags.required,
                origin: "apple".into(),
                description: f.description.clone(),
                default: if f.name == "PayloadType" {
                    Some(serde_json::Value::String("Configuration".into()))
                } else {
                    f.default.as_deref().map(|d| typed_default(f.field_type, d))
                },
                options: (!f.allowed_values.is_empty()).then(|| f.allowed_values.clone()),
                readonly: (f.name == "PayloadType").then_some(true),
                platforms: None,
                scope_class_by_platform: is_scope.then(|| scope_class_by_platform.clone()),
                narrowed_by_key: is_scope.then(|| narrowed.clone()),
            });
        }
    }
    Envelope {
        layer: EnvelopeLayer::Root,
        keys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict_of(spec: &FormSpec, path: &str) -> Option<Verdict> {
        let mut all = Vec::new();
        walk(&spec.nodes, &mut all);
        all.iter()
            .find(|n| n.path == path)
            .unwrap_or_else(|| panic!("no node {path}"))
            .availability
            .as_ref()
            .and_then(|a| a.verdict)
    }

    fn at(ty: &str, platform: Platform, os: &str) -> FormSpec {
        form(
            &reg(),
            ty,
            &Target {
                platform: Some(platform),
                os_version: Some(os.into()),
                ..Default::default()
            },
        )
        .unwrap()
    }

    /// `Verdict::Removed` is constructed from the key's `removed`.
    /// com.apple.mdm's ManagedAppleID is the witness Apple hands us: on
    /// macOS it is deprecated at 14.0 and removed at 15.0, so it exercises
    /// the precedence too. A key the device ignores is removed, not
    /// "deprecated but still works".
    #[test]
    fn a_key_apple_removed_reports_removed_and_it_beats_deprecated() {
        let path = "ManagedAppleID";
        assert_eq!(
            verdict_of(&at("com.apple.mdm", Platform::MacOS, "15.0"), path),
            Some(Verdict::Removed),
            "at the removal version the key is removed. If this reads Deprecated, the \
             dataset ({}) predates the key_removed column (45 columns) — republish; do not skip",
            dataset_generation()
        );
        assert_eq!(
            verdict_of(&at("com.apple.mdm", Platform::MacOS, "16.1"), path),
            Some(Verdict::Removed),
            "and it stays removed on every later OS"
        );
        assert_eq!(
            verdict_of(&at("com.apple.mdm", Platform::MacOS, "14.5"), path),
            Some(Verdict::Deprecated),
            "between deprecation and removal it is deprecated"
        );
        assert_ne!(
            verdict_of(&at("com.apple.mdm", Platform::MacOS, "13.6"), path),
            Some(Verdict::Removed),
            "before either it is not removed"
        );
    }

    /// The `removed` map itself reaches the contract, so a renderer can say
    /// which version, not just that.
    #[test]
    fn the_removed_version_is_on_the_node() {
        let spec = at("com.apple.mdm", Platform::MacOS, "15.0");
        let mut all = Vec::new();
        walk(&spec.nodes, &mut all);
        let n = all.iter().find(|n| n.path == "ManagedAppleID").unwrap();
        let removed = n
            .availability
            .as_ref()
            .unwrap()
            .removed
            .as_ref()
            .unwrap_or_else(|| {
                panic!(
                    "no removed map — the dataset ({}) predates key_removed; republish",
                    dataset_generation()
                )
            });
        assert_eq!(
            removed.get(&Platform::MacOS).map(String::as_str),
            Some("15.0")
        );
    }

    /// A payload Apple removed wholesale takes every key with it, even one
    /// whose own row says nothing. com.apple.AIM.account left macOS at 10.14.
    #[test]
    fn a_removed_payload_removes_every_key() {
        let spec = at("com.apple.AIM.account", Platform::MacOS, "10.15");
        let mut all = Vec::new();
        walk(&spec.nodes, &mut all);
        let verdicts: Vec<_> = all
            .iter()
            .filter_map(|n| n.availability.as_ref().and_then(|a| a.verdict))
            .collect();
        assert!(
            !verdicts.is_empty(),
            "the payload has keys with a target verdict"
        );
        assert!(
            verdicts.iter().all(|v| *v == Verdict::Removed),
            "every key of a payload removed at 10.14 is removed on 10.15: {verdicts:?}"
        );
    }

    /// A Windows ADMX node in a form carries its STIG rules exactly as an
    /// Apple node carries its mSCP rules — same `annotations[]`, same
    /// renderer, no Windows-shaped copy of anything.
    #[test]
    fn a_windows_admx_node_is_annotated_with_its_stig_rules() {
        let r = SchemaRegistry::embedded_windows().expect("Windows registry");
        let ann = crate::annotations::Annotations::embedded().unwrap();
        let spec = form_with(
            &r,
            "BitLocker",
            &Target {
                platform: Some(Platform::Windows),
                ..Default::default()
            },
            Some(&ann),
        )
        .expect("BitLocker forms");
        let node = spec
            .nodes
            .iter()
            .find(|n| n.key == "SystemDrivesRequireStartupAuthentication")
            .expect("the ADMX policy is a top-level node of the BitLocker area");
        let anns = node.annotations.as_ref().unwrap_or_else(|| {
            panic!(
                "unannotated — the dataset ({}) predates the Windows bridge; republish, do not skip",
                dataset_generation()
            )
        });
        assert!(anns.iter().any(|a| a.rule_id == "V-253260"), "{anns:?}");
    }

    /// The dataset's own account of what built it, for a failure that would
    /// otherwise say only "empty". A test that needs a newer dataset fails
    /// naming the one it got; it does not skip.
    fn dataset_generation() -> String {
        let v = mdm_schema::schema_versions();
        format!("{} · {}", v.generation_date, v.generation_source)
    }

    fn reg() -> SchemaRegistry {
        SchemaRegistry::embedded().expect("embedded registry")
    }

    fn walk<'a>(nodes: &'a [FormNode], out: &mut Vec<&'a FormNode>) {
        for n in nodes {
            out.push(n);
            if let Some(c) = &n.children {
                walk(c, out);
            }
            if let Some(i) = &n.item {
                walk(std::slice::from_ref(i.as_ref()), out);
            }
        }
    }

    fn is_marker(s: &str) -> bool {
        s.split('.')
            .any(|seg| matches!(seg, "ANY" | "{{key}}" | "{{value}}"))
    }

    /// The contract's one hard invariant, checked over every type.
    #[test]
    fn no_spec_carries_a_marker_as_key_or_path_segment() {
        // Sweeps every spec contour can produce, community included — the
        // widest set is the point of this test.
        let r = reg();
        let mut count = 0;
        let mut dict_of = 0;
        for spec in form_all(&r, &Target::default()) {
            let spec = spec.expect("every authorable type forms");
            let mut all = Vec::new();
            walk(&spec.nodes, &mut all);
            for n in &all {
                count += 1;
                assert!(!is_marker(&n.key), "{}: key {}", spec.id, n.key);
                assert!(!is_marker(&n.path), "{}: path {}", spec.id, n.path);
                if n.control == Control::DictOf {
                    dict_of += 1;
                    assert!(n.item.is_some(), "{}: dict-of without item", spec.id);
                    assert!(n.key_hint.is_some());
                }
            }
        }
        // The corpus shrank when ProfileCreator was removed; this is a
        // smoke threshold, not a census. `contour census` reports the real
        // figures.
        assert!(count > 3_000, "expected thousands of nodes, saw {count}");
        assert!(
            dict_of >= 20,
            "expected dozens of dict-of nodes, saw {dict_of}"
        );
    }

    /// Commands have schemas and no form.
    #[test]
    fn protocol_kinds_are_refused() {
        let r = reg();
        let err = form(&r, "DeviceLock", &Target::default()).unwrap_err();
        assert!(matches!(err, FormError::NotAuthorable { .. }), "{err}");
        assert!(
            form_all(&r, &Target::default())
                .into_iter()
                .all(|s| s.is_ok())
        );
    }

    /// §3.2's example: PermissionDefaults is keyed by app; its item is the
    /// permission dictionary, re-rooted under `*`.
    #[test]
    fn permission_defaults_is_dict_of_with_rerooted_item() {
        let r = reg();
        let spec = form(
            &r,
            "com.apple.configuration.app.settings",
            &Target::default(),
        )
        .unwrap();
        let mut all = Vec::new();
        walk(&spec.nodes, &mut all);
        let pd = all
            .iter()
            .find(|n| n.path == "Privacy.PermissionDefaults")
            .expect("PermissionDefaults");
        assert_eq!(pd.control, Control::DictOf);
        let item = pd.item.as_ref().unwrap();
        assert_eq!(item.key, "*");
        assert_eq!(item.path, "Privacy.PermissionDefaults.*");
        let kids: Vec<&str> = item
            .children
            .as_ref()
            .unwrap()
            .iter()
            .map(|c| c.key.as_str())
            .collect();
        for want in ["Camera", "Microphone", "OrganizationJustification"] {
            assert!(kids.contains(&want), "{kids:?}");
        }
        let cam = item
            .children
            .as_ref()
            .unwrap()
            .iter()
            .find(|c| c.key == "Camera")
            .unwrap();
        assert_eq!(cam.path, "Privacy.PermissionDefaults.*.Camera");
    }

    /// Scope is per platform and the platforms disagree.
    #[test]
    fn safari_settings_scope_is_user_on_macos_and_system_on_ios() {
        let r = reg();
        let spec = form(
            &r,
            "com.apple.configuration.safari.settings",
            &Target::default(),
        )
        .unwrap();
        assert_eq!(spec.kind, Kind::DdmConfiguration);
        assert_eq!(
            spec.scope_class_by_platform[&Platform::MacOS],
            ScopeClass::UserOnly
        );
        assert_eq!(
            spec.scope_class_by_platform[&Platform::Ios],
            ScopeClass::SystemOnly
        );
        assert!(
            !spec.scope_class_by_platform.contains_key(&Platform::TvOS),
            "n/a platform must be absent"
        );
        // The union is display-only and says both — true on no platform.
        assert_eq!(spec.scopes, vec!["system", "user"]);
        assert_eq!(spec.envelope.layer, EnvelopeLayer::Declaration);
        let ps = spec
            .envelope
            .keys
            .iter()
            .find(|k| k.key == "PayloadScope")
            .unwrap();
        assert_eq!(ps.origin, "fleet");
    }

    #[test]
    fn profile_envelope_comes_from_top_level_and_marks_payload_type_readonly() {
        let r = reg();
        let spec = form(&r, "com.apple.wifi.managed", &Target::default()).unwrap();
        assert_eq!(spec.kind, Kind::MdmProfile);
        assert_eq!(spec.nesting, Some(Nesting::Direct));
        assert_eq!(spec.envelope.layer, EnvelopeLayer::Root);
        let pt = spec
            .envelope
            .keys
            .iter()
            .find(|k| k.key == "PayloadType")
            .unwrap();
        assert_eq!(pt.readonly, Some(true));
        assert_eq!(pt.origin, "apple");
        assert!(spec.envelope.keys.iter().all(|k| k.key != "PayloadContent"));
        assert!(spec.envelope.keys.iter().all(|k| !is_marker(&k.key)));
    }

    /// R6's surviving clause: nesting is reported per payload type. The
    /// same helper feeds `profile info`, so the two cannot disagree.
    #[test]
    fn default_nesting_follows_kind() {
        let r = reg();
        let k = |id: &str| kind_of(r.get(id).unwrap());
        // A preference domain the DEFAULT registry serves, so this covers
        // the path an operator actually gets.
        assert_eq!(
            default_nesting(k("com.apple.Siri")),
            Some(Nesting::McxWrapped)
        );
        assert_eq!(
            default_nesting(k("com.apple.wifi.managed")),
            Some(Nesting::Direct)
        );
        assert_eq!(
            default_nesting(k("com.apple.configuration.safari.settings")),
            None
        );
    }

    /// A spec is attributed to where its schema came from, not to its kind.
    ///
    /// Santa, SAP Privileges and Defender are ManagedPreferences derived from
    /// their VENDORS' sources; labelling them by kind would call vendor data
    /// community data — the inversion the vendor documents exist to correct.
    #[test]
    fn a_spec_names_the_source_its_schema_came_from() {
        let r = reg();
        for (domain, expected) in [
            ("com.northpolesec.santa", "app-schema"),
            ("corp.sap.privileges", "app-schema"),
            ("com.microsoft.wdav", "app-schema"),
            ("com.apple.wifi.managed", "capabilities"),
        ] {
            let spec =
                form(&r, domain, &Target::default()).unwrap_or_else(|e| panic!("{domain}: {e}"));
            assert_eq!(
                spec.source.dataset, expected,
                "{domain} is attributed to the wrong dataset"
            );
        }

        // An app-schema document records its revision in the document, not in
        // the dataset's source table — so no upstream ref here beats the
        // wrong repository's commit.
        let santa = form(&r, "com.northpolesec.santa", &Target::default()).unwrap();
        assert_eq!(
            santa.source.upstream_ref, None,
            "a vendor document must not borrow another repository's revision"
        );

        // The dataset states a handful of domains itself, and labels them as
        // its own rather than borrowing another source's name.
        let okta = form(&r, "com.okta.mobile", &Target::default()).unwrap();
        assert_eq!(okta.source.dataset, "posture-supplemental");
        assert_eq!(
            okta.source.upstream_ref, None,
            "the dataset states these itself; there is no upstream to name"
        );
    }

    #[test]
    fn preference_domain_defaults_to_mcx() {
        // A preference domain the dataset states itself.
        let r = reg();
        let spec = form(&r, "com.okta.mobile", &Target::default()).unwrap();
        assert_eq!(spec.kind, Kind::ManagedPreference);
        assert_eq!(spec.nesting, Some(Nesting::McxWrapped));
        assert_eq!(spec.source.dataset, "posture-supplemental");
    }

    #[test]
    fn verdict_needs_a_platform_and_reads_the_version() {
        let r = reg();
        let none = form(
            &r,
            "com.apple.configuration.safari.settings",
            &Target::default(),
        )
        .unwrap();
        let mut all = Vec::new();
        walk(&none.nodes, &mut all);
        assert!(
            all.iter()
                .all(|n| n.availability.as_ref().is_none_or(|a| a.verdict.is_none()))
        );

        let old = form(
            &r,
            "com.apple.configuration.safari.settings",
            &Target {
                platform: Some(Platform::MacOS),
                os_version: Some("15.0".into()),
            },
        )
        .unwrap();
        let mut all = Vec::new();
        walk(&old.nodes, &mut all);
        let with_intro: Vec<&&FormNode> = all
            .iter()
            .filter(|n| {
                n.availability
                    .as_ref()
                    .is_some_and(|a| a.introduced.is_some())
            })
            .collect();
        assert!(!with_intro.is_empty());
        assert!(
            with_intro
                .iter()
                .all(|n| n.availability.as_ref().unwrap().verdict == Some(Verdict::RequiresOs))
        );
    }

    /// Annotations ride on top-level nodes only, and only when asked for.
    #[test]
    fn annotations_attach_to_top_level_keys_when_supplied() {
        let r = reg();
        let ann = crate::annotations::Annotations::embedded().unwrap();
        assert!(
            !ann.is_empty(),
            "rule_capability_links has no rows — the dataset did not carry it; do not skip"
        );
        let plain = form(&r, "com.apple.systempreferences", &Target::default()).unwrap();
        assert!(plain.nodes.iter().all(|n| n.annotations.is_none()));

        let spec = form_with(
            &r,
            "com.apple.systempreferences",
            &Target::default(),
            Some(&ann),
        )
        .unwrap();
        let dss = spec
            .nodes
            .iter()
            .find(|n| n.key == "DisabledSystemSettings")
            .expect("DisabledSystemSettings");
        let anns = dss.annotations.as_ref().expect("annotated");
        assert!(
            anns.iter()
                .any(|a| a.rule_id == "system_settings_internet_accounts_disable")
        );
        assert!(anns.iter().all(|a| !a.baselines.is_empty()));

        let annotated: usize = form_all_with(&r, &Target::default(), Some(&ann))
            .into_iter()
            .filter_map(Result::ok)
            .flat_map(|s| s.nodes)
            .filter(|n| n.annotations.is_some())
            .count();
        assert!(
            annotated > 100,
            "expected hundreds of annotated keys, saw {annotated}"
        );
    }

    /// `source.upstream_ref` is the commit the table was read from, and
    /// differs by dataset: Apple's repo for Apple kinds, ProfileManifests for
    /// preference domains. Null only when the dataset does not say.
    #[test]
    fn upstream_ref_names_the_commit_per_dataset() {
        // Names the profilecreator dataset's upstream ref.
        let r = reg();
        assert!(
            !r.provenance().is_empty(),
            "source_versions has no rows — the dataset did not carry it; do not skip"
        );
        // Apple's own schema names the device-management commit it came
        // from. This compared that against ProfileManifests' commit until
        // that corpus was removed; there is one upstream table now, so what
        // is worth pinning is that the ref is a real sha and that it is the
        // one the registry reports for device-management.
        let wifi = form(&r, "com.apple.wifi.managed", &Target::default()).unwrap();
        assert_eq!(wifi.source.channel.as_deref(), Some("stable"));
        assert_eq!(wifi.source.dataset, "capabilities");
        let apple = wifi.source.upstream_ref.expect("Apple commit");
        assert_eq!(apple.len(), 40, "a full sha, not a label: {apple}");
        assert_eq!(apple, r.upstream_revision("device-management").unwrap());

        // A domain the dataset states itself borrows no commit at all.
        let okta = form(&r, "com.okta.mobile", &Target::default()).unwrap();
        assert_eq!(okta.source.upstream_ref, None);
    }

    /// Apple writes `DeniedApps: {macOS: n/a}` and nothing else: not on
    /// macOS, inherited everywhere else. `Privacy` lists tvOS/visionOS/
    /// watchOS as n/a but not iOS — so iOS must NOT be unavailable:
    /// unlisted does not mean n/a.
    #[test]
    fn explicit_n_a_is_unavailable_and_unlisted_inherits() {
        let r = reg();
        let spec = form(
            &r,
            "com.apple.configuration.app.settings",
            &Target::default(),
        )
        .unwrap();
        let mut all = Vec::new();
        walk(&spec.nodes, &mut all);
        let un = |p: &str| -> Vec<Platform> {
            all.iter()
                .find(|n| n.path == p)
                .unwrap_or_else(|| panic!("{p}"))
                .availability
                .as_ref()
                .and_then(|a| a.unavailable.clone())
                .unwrap_or_default()
        };
        let denied = un("Allowed.DeniedApps");
        assert!(
            !denied.is_empty(),
            "Allowed.DeniedApps carries no per-key n/a — this dataset ({}) predates the \
             per-key n/a fix. Republish; do not skip",
            dataset_generation()
        );
        assert_eq!(denied, vec![Platform::MacOS], "{denied:?}");
        let privacy = un("Privacy");
        assert!(
            !privacy.contains(&Platform::Ios),
            "iOS was unlisted, so it inherits: {privacy:?}"
        );
        assert!(privacy.contains(&Platform::TvOS), "{privacy:?}");

        let mac = form(
            &r,
            "com.apple.configuration.app.settings",
            &Target {
                platform: Some(Platform::MacOS),
                os_version: None,
            },
        )
        .unwrap();
        let mut all = Vec::new();
        walk(&mac.nodes, &mut all);
        let denied = all.iter().find(|n| n.path == "Allowed.DeniedApps").unwrap();
        assert_eq!(
            denied.availability.as_ref().unwrap().verdict,
            Some(Verdict::Unavailable)
        );
        assert!(
            all.iter()
                .any(|n| n.path == "Allowed.DeniedApps.AppIdentifier"),
            "DeniedApps lost its item"
        );
        assert!(
            all.iter()
                .any(|n| n.path == "Allowed.DeniedBinaries.BinaryIdentifier.CDHash")
        );
    }

    /// TCC's 23 aliased service lists: every service must carry the same
    /// IdentityDict shape AddressBook does.
    #[test]
    fn tcc_services_all_have_children() {
        let r = reg();
        let spec = form(
            &r,
            "com.apple.TCC.configuration-profile-policy",
            &Target::default(),
        )
        .unwrap();
        let services = spec
            .nodes
            .iter()
            .find(|n| n.key == "Services")
            .expect("Services");
        let kids = services.children.as_ref().expect("service lists");
        let childless: Vec<&str> = kids
            .iter()
            .filter(|k| k.item.is_none())
            .map(|k| k.key.as_str())
            .collect();
        assert!(
            childless.len() + 1 != kids.len(),
            "every TCC service but one is childless — this dataset ({}) predates the anchor \
             fix (TCC went 7 → 289 key paths). Republish; do not skip",
            dataset_generation()
        );
        assert!(
            childless.is_empty(),
            "service lists without an item: {childless:?}"
        );
        assert!(kids.len() >= 20, "{}", kids.len());
    }

    #[test]
    fn labels_de_camel_without_splitting_acronyms() {
        assert_eq!(
            de_camel("AllowDisablingFraudWarning"),
            "Allow Disabling Fraud Warning"
        );
        assert_eq!(de_camel("PayloadUUID"), "Payload UUID");
        assert_eq!(de_camel("URL"), "URL");
        assert_eq!(
            de_camel("enableRealTimeProtection"),
            "enable Real Time Protection"
        );
    }

    /// A ProfileCreator key must not claim availability nobody checked.
    ///
    /// Community manifests record no `introduced`/`deprecated`, and a plain
    /// `Ok` would be indistinguishable from an Apple key whose silence
    /// genuinely means "inherits the payload".
    ///
    /// The subject is chosen from the dataset, not named: the test is about
    /// the CLASS — any payload carrying keys while recording no availability
    /// — so it asks the registry which payloads those are and requires the
    /// class to be non-empty first. A named payload could leave the dataset
    /// and fail the test for the wrong reason.
    #[test]
    fn a_source_without_availability_reports_unknown_not_ok() {
        let r = SchemaRegistry::embedded().unwrap();

        let mut candidates: Vec<&str> = r
            .all()
            .filter(|m| m.fields_recording_availability.is_empty())
            .filter(|m| m.platforms.macos)
            .filter(|m| !m.fields.is_empty())
            // Commands, check-ins and shared structures record no
            // availability either, but they are not documents an operator
            // authors — `form` refuses them by design, so they are not
            // subjects for a question about key verdicts.
            .filter(|m| m.kind.is_none_or(|k| k.not_authorable_reason().is_none()))
            .map(|m| m.payload_type.as_str())
            .collect();
        candidates.sort_unstable();
        assert!(
            !candidates.is_empty(),
            "no payload in the dataset records zero availability — either every \
             source now carries it (delete this test) or the field stopped being \
             populated (a bug)"
        );

        // Deterministic pick, so a failure names the same payload every run.
        let subject = candidates[0];
        let spec = form(
            &r,
            subject,
            &Target {
                platform: Some(Platform::MacOS),
                os_version: Some("15.0".into()),
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("form builds for {subject}: {e}"));
        let verdicts: Vec<_> = spec
            .nodes
            .iter()
            .filter_map(|n| n.availability.as_ref().and_then(|a| a.verdict))
            .collect();
        assert!(
            !verdicts.is_empty(),
            "expected verdicts on a targeted form for {subject}"
        );
        assert!(
            verdicts.iter().all(|v| *v != Verdict::Ok),
            "{subject} records no availability, so it must not report Ok: {verdicts:?}"
        );
        assert!(
            verdicts.contains(&Verdict::Unknown),
            "expected Unknown for {subject}, got {verdicts:?}"
        );
    }

    /// Apple's own schema still answers `Ok` — silence there means the key
    /// inherits the payload's availability, which is a real fact.
    #[test]
    fn apples_schema_still_reports_ok() {
        let r = SchemaRegistry::embedded().unwrap();
        let m = r.get("com.apple.wifi.managed").expect("wifi manifest");
        assert!(
            !m.fields_recording_availability.is_empty(),
            "Apple's schema records availability"
        );
        let spec = form(
            &r,
            "com.apple.wifi.managed",
            &Target {
                platform: Some(Platform::MacOS),
                os_version: Some("15.0".into()),
                ..Default::default()
            },
        )
        .expect("form builds");
        assert!(
            spec.nodes
                .iter()
                .filter_map(|n| n.availability.as_ref().and_then(|a| a.verdict))
                .any(|v| v == Verdict::Ok),
            "Apple keys available on macOS 15 must still read Ok"
        );
    }
}
