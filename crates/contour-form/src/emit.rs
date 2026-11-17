//! `emit()` — values back into a deployable document.
//!
//! Format and cardinality come from the schema; `EmitOptions::format` and
//! `nesting` are the only caller overrides, and cardinality has none.
//! A declaration is JSON; a profile is a `.mobileconfig`, keys directly in
//! the inner payload or wrapped in the MCX envelope for a preference domain
//! (either is a valid delivery; the caller may override the default). A
//! declaration whose keys span both delivery channels emits **two**
//! documents — `.user` and `.system` — because Apple delivers a declaration
//! on exactly one channel. Unrestricted keys ride with the system document.
//!
//! Identifiers follow `{org}.{segment}.{intent}` for declarations and
//! `{org}.{intent}` for profiles. A placeholder org is refused, not
//! defaulted. UUIDs derive from the identifier, so the same input yields the
//! same bytes.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use crate::form::{PLATFORM_ORDER, Target, kind_of};
use crate::formspec::{Kind, Nesting};
use crate::identity::{self, InvalidOrg};
use crate::scope::{self, Scope, ScopeClass};
use crate::types::{FieldDefinition, FieldType, PayloadManifest, Platform};
use crate::validate::{Diagnostic, validate_target};
use crate::{SchemaRegistry, form::FormError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EmitFormat {
    Declaration,
    MobileConfig,
}

#[derive(Debug, Clone, Default)]
pub struct EmitOptions {
    /// Reverse-DNS organization domain. Required; `com.example` is refused.
    pub org: String,
    /// The intent segment of the identifier — `passcode`, `wifi-corp`.
    pub intent: String,
    /// Override the format the kind implies. Rarely right.
    pub format: Option<EmitFormat>,
    /// Override the envelope for a `.mobileconfig`.
    pub nesting: Option<Nesting>,
    /// Platform whose scope rules decide the channel split; the type's
    /// first platform when absent.
    pub platform: Option<Platform>,
    /// OS version on that platform. With it, a key Apple removed by this
    /// version is refused instead of written into a document the device
    /// would ignore.
    pub os_version: Option<String>,
    /// `PayloadDisplayName`; the schema title when absent.
    pub display_name: Option<String>,
    /// Write what the schema does not know instead of refusing it: a key a
    /// known payload type does not document, and a whole payload type the
    /// schema does not have. For a profile someone already deploys, where an
    /// undocumented key is usually deliberate. Each one is listed in
    /// [`Outcome::kept`]. Values of keys the schema does know are still
    /// checked and refused as usual.
    pub keep_unknown: bool,
}

/// One emitted document.
#[derive(Debug, Clone, Serialize)]
pub struct Emitted {
    /// `"User channel"` / `"System channel"` on a split; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub identifier: String,
    pub filename: String,
    pub format: EmitFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    pub requirements: Requirements,
    pub body: String,
}

/// What the keys in one emitted document ask of the device and of whoever
/// delivers it. Read from the schema for exactly the keys that were set, so
/// a split declaration's two documents can differ.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Requirements {
    /// Per platform, the earliest OS on which the type and every key set
    /// exist. An older device ignores the newer keys.
    pub min_os: BTreeMap<&'static str, String>,
    /// Keys that only take effect on a supervised device.
    pub supervised: Vec<String>,
    /// Text keys that hold a credential, by schema flag or by name. Their
    /// values belong in the MDM's secret variables, not in a repository.
    pub sensitive: Vec<String>,
    /// Keys set that need a minimum version of the app that reads them,
    /// by path ("RequireBiometricAuthentication" -> "2.5"). Not an OS.
    pub app_versions: BTreeMap<String, String>,
}

// ponytail: follows dictionaries only. Keys inside an array of dictionaries
// are not looked up; add when a caller needs their requirements.
fn requirements(
    m: &PayloadManifest,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Requirements {
    let by_path: HashMap<&str, &FieldDefinition> =
        m.fields.values().map(|f| (f.path.as_str(), f)).collect();
    let mut req = Requirements::default();
    let mut raise = |platform: Platform, version: &str| {
        // `n/a` and other non-versions never compare, so they are skipped.
        let newer = match req.min_os.get(platform.as_str()) {
            Some(have) => crate::version::at_least(have, version) == Some(false),
            None => crate::version::parse(version).is_some(),
        };
        if newer {
            req.min_os.insert(platform.as_str(), version.to_string());
        }
    };
    for (platform, version) in &m.min_versions {
        raise(*platform, version);
    }

    let mut supervised = Vec::new();
    let mut sensitive = Vec::new();
    let mut stack: Vec<(String, &serde_json::Value)> =
        obj.iter().map(|(k, v)| (k.clone(), v)).collect();
    while let Some((path, value)) = stack.pop() {
        if let Some(f) = by_path.get(path.as_str()) {
            for (platform, version) in &f.introduced_by_platform {
                raise(*platform, version);
            }
            if f.flags.supervised {
                supervised.push(path.clone());
            }
            if let Some(v) = &f.facets.app_introduced {
                req.app_versions.insert(path.clone(), v.clone());
            }
        }
        // By name as well: the dataset flags credentials only where a source
        // states them, and Apple's schema states none.
        // Text only, so `allowPasswordSharing: false` is not a credential.
        let leaf = path.rsplit('.').next().unwrap_or(&path);
        if value.is_string()
            && (by_path.get(path.as_str()).is_some_and(|f| f.flags.sensitive)
                || crate::sensitive::is_known_sensitive_name(leaf))
        {
            sensitive.push(path.clone());
        }
        if let Some(children) = value.as_object() {
            stack.extend(children.iter().map(|(k, v)| (format!("{path}.{k}"), v)));
        }
    }
    supervised.sort();
    sensitive.sort();
    req.supervised = supervised;
    req.sensitive = sensitive;
    req
}

#[derive(Debug)]
pub enum EmitError {
    Form(FormError),
    Org(InvalidOrg),
    /// `validate()` found something that blocks emission.
    Invalid(Vec<Diagnostic>),
    /// One top-level key's subtree demands both channels at once.
    Unsatisfiable {
        key: String,
    },
    Serialize(String),
    /// A key the schema types `<data>` carries something that is not
    /// base64. Emitting it as a `<string>` would produce a profile that
    /// installs and does nothing, so it is refused instead.
    NotBase64 {
        path: String,
        /// The decoder's error.
        reason: String,
    },
}

impl std::fmt::Display for EmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmitError::Form(e) => write!(f, "{e}"),
            EmitError::Org(e) => write!(f, "{e}"),
            EmitError::Invalid(ds) => {
                writeln!(f, "values do not satisfy the schema:")?;
                for d in ds.iter().filter(|d| d.blocks_emit) {
                    writeln!(f, "  {d}")?;
                }
                Ok(())
            }
            EmitError::Unsatisfiable { key } => write!(
                f,
                "'{key}' contains keys restricted to the user channel and keys restricted to the \
                 system channel; no single declaration can carry both, and it cannot be split \
                 below a top-level key"
            ),
            EmitError::Serialize(e) => write!(f, "serialising the document: {e}"),
            EmitError::NotBase64 { path, reason } => write!(
                f,
                "'{path}' is typed <data> in the schema, so its value must be base64; \
                 what was supplied does not decode ({reason}). A <data> key given a <string> \
                 installs cleanly and has no effect, so this is refused rather than \
                 emitted"
            ),
        }
    }
}

impl std::error::Error for EmitError {}

impl From<FormError> for EmitError {
    fn from(e: FormError) -> Self {
        EmitError::Form(e)
    }
}

/// Emit `values` for `type_id`. See the module docs for what decides the
/// format and how many documents come back.
pub fn emit(
    reg: &SchemaRegistry,
    type_id: &str,
    values: &serde_json::Value,
    opts: &EmitOptions,
) -> Result<Vec<Emitted>, EmitError> {
    let m = reg
        .get(type_id)
        .or_else(|| reg.get_by_name(type_id))
        .ok_or_else(|| match reg.why_withheld(type_id) {
            Some(why) => FormError::Withheld(why),
            None => FormError::UnknownType(type_id.to_string()),
        })?;
    if !m.is_authorable() {
        return Err(FormError::NotAuthorable {
            id: m.payload_type.clone(),
            kind: m
                .kind
                .map_or("protocol message", |k| k.as_str())
                .to_string(),
        }
        .into());
    }
    identity::validate_org_domain(&opts.org).map_err(EmitError::Org)?;
    let diagnostics = validate_target(
        reg,
        &m.payload_type,
        values,
        &Target {
            platform: opts.platform,
            os_version: opts.os_version.clone(),
        },
    );
    // An undocumented key nested in a value is written as given when the
    // caller keeps what the schema does not know.
    if diagnostics.iter().any(|d| d.blocks_emit && !(opts.keep_unknown && d.rule == "unknown-key")) {
        return Err(EmitError::Invalid(diagnostics));
    }
    let obj = values.as_object().expect("validate() guarantees an object");

    let kind = kind_of(m);
    let format = opts.format.unwrap_or(if kind.is_declaration() {
        EmitFormat::Declaration
    } else {
        EmitFormat::MobileConfig
    });
    let platform = opts.platform.or_else(|| {
        PLATFORM_ORDER
            .iter()
            .copied()
            .find(|p| platform_flag(m, *p))
    });

    match format {
        EmitFormat::Declaration => emit_declarations(m, kind, obj, opts, platform),
        EmitFormat::MobileConfig => emit_mobileconfig(m, kind, obj, opts, platform),
    }
}

// ---------------------------------------------------------------------------
// Settings in, documents out: the entry point for a caller that is not a form
// ---------------------------------------------------------------------------

/// One thing to set: a key of a payload type, and its value.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct Setting {
    #[serde(rename = "type")]
    pub type_id: String,
    /// Dotted path of the key, as search and the FormSpec give it.
    pub path: String,
    pub value: serde_json::Value,
}

/// Why a setting, or a whole payload type, was not written, and what would
/// fix it. Meant to be handed back to whoever chose the setting.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Refusal {
    #[serde(rename = "type")]
    pub type_id: String,
    /// The key, or `""` when the payload type as a whole is refused.
    pub path: String,
    pub rule: String,
    pub message: String,
    /// The values the key accepts, when it has a fixed set.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<String>,
    /// The range the key accepts, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<[Option<f64>; 2]>,
    /// The key of this type whose name is closest, for an unknown key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_you_mean: Option<String>,
}

/// What [`emit_settings`] produced.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub documents: Vec<Emitted>,
    pub refused: Vec<Refusal>,
    /// With [`EmitOptions::keep_unknown`]: what was written as given,
    /// unchecked, because the schema does not know it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kept: Vec<Refusal>,
}

/// A short identifier segment for a payload type: `com.apple.applicationaccess`
/// gives `applicationaccess`, `com.apple.configuration.passcode.settings`
/// gives `passcode`.
fn intent_for(type_id: &str) -> String {
    let words: Vec<&str> = type_id
        .split('.')
        .filter(|w| !matches!(*w, "com" | "apple" | "configuration" | "settings" | "managed"))
        .collect();
    let slug = words.join("-").to_lowercase();
    if slug.is_empty() { "settings".into() } else { slug }
}

/// A value typed as the schema types the key. An agent or a text field sends
/// `"false"` and `"12"`; a profile needs `<false/>` and `<integer>`. Text
/// that does not read as the key's type is left alone, for validation to
/// refuse by name.
///
/// A boolean for a text key with a fixed set of values is the value of that
/// set that reads as it: YAML 1.1 reads an unquoted `On` as `true`, so mSCP's
/// `Enable: On` for FileVault arrives as `true`, and Apple's key takes `On`.
pub(crate) fn typed(field: &FieldDefinition, value: serde_json::Value) -> serde_json::Value {
    if let (serde_json::Value::Bool(b), FieldType::String) = (&value, &field.field_type) {
        let words: &[&str] = if *b { &["on", "yes", "true", "enabled"] } else { &["off", "no", "false", "disabled"] };
        return field
            .allowed_values
            .iter()
            .find(|a| words.contains(&a.to_ascii_lowercase().as_str()))
            .map_or(value, |a| a.clone().into());
    }
    let serde_json::Value::String(text) = &value else {
        return value;
    };
    let text = text.trim();
    match field.field_type {
        FieldType::Boolean => match text.to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" => true.into(),
            "false" | "no" | "off" => false.into(),
            _ => value,
        },
        FieldType::Integer => text.parse::<i64>().map_or(value.clone(), Into::into),
        FieldType::Real => text.parse::<f64>().map_or(value.clone(), Into::into),
        _ => value,
    }
}

/// Emit a flat list of settings, across payload types, in one call.
///
/// The shape an agent produces: it picked keys from a search and has a value
/// for each. Settings are grouped by type, typed from the schema, validated
/// and emitted, one document set per type. `opts.intent` names the document
/// when every setting is of one type; otherwise each type names its own.
///
/// A type with any refused setting is not written: a document missing part
/// of what was chosen is not the document that was asked for. Every refusal
/// across every type comes back together, with the allowed values, the range
/// or the nearest key name, so one correction round can fix them all.
pub fn emit_settings(reg: &SchemaRegistry, settings: &[Setting], opts: &EmitOptions) -> Outcome {
    let mut groups: BTreeMap<&str, Vec<&Setting>> = BTreeMap::default();
    for s in settings {
        groups.entry(s.type_id.as_str()).or_default().push(s);
    }
    let single = groups.len() == 1 && !opts.intent.trim().is_empty();
    let mut out = Outcome {
        documents: Vec::new(),
        refused: Vec::new(),
        kept: Vec::new(),
    };
    let refuse = |type_id: &str, path: &str, rule: &str, message: String| Refusal {
        type_id: type_id.to_string(),
        path: path.to_string(),
        rule: rule.to_string(),
        message,
        allowed: Vec::new(),
        range: None,
        did_you_mean: None,
    };

    for (type_id, group) in groups {
        let Some(m) = reg.get(type_id).or_else(|| reg.get_by_name(type_id)) else {
            if opts.keep_unknown {
                let mut values = serde_json::Map::new();
                for s in &group {
                    // ponytail: a conflicting path is skipped; no schema says which wins.
                    let _ = crate::FieldPath::parse(&s.path).insert_json(&mut values, s.value.clone());
                }
                let intent = if single { opts.intent.clone() } else { intent_for(type_id) };
                match passthrough(type_id, &values, &EmitOptions { intent, ..opts.clone() }) {
                    Ok(doc) => {
                        out.kept.push(refuse(type_id, "", "unknown-type", format!("'{type_id}' is not in the schema; its keys are written as given, unchecked")));
                        out.documents.push(doc);
                    }
                    Err(e) => out.refused.push(refuse(type_id, "", "not-emitted", e.to_string())),
                }
                continue;
            }
            out.refused.push(refuse(
                type_id,
                "",
                "unknown-type",
                format!("'{type_id}' is not a payload type in the schema"),
            ));
            continue;
        };
        let by_path: HashMap<&str, &FieldDefinition> =
            m.fields.values().map(|f| (f.path.as_str(), f)).collect();

        let mut values = serde_json::Map::new();
        // Keys the type does not document, kept aside to be written as given.
        let mut extra = serde_json::Map::new();
        let before = out.refused.len();
        for s in group {
            let Some(field) = by_path.get(s.path.as_str()) else {
                if opts.keep_unknown {
                    let _ = crate::FieldPath::parse(&s.path).insert_json(&mut extra, s.value.clone());
                    out.kept.push(refuse(&m.payload_type, &s.path, "unknown-key", format!("'{}' is not a documented key of {}; written as given, unchecked", s.path, m.payload_type)));
                    continue;
                }
                // The same key in another case, or the same leaf under another parent.
                let leaf = s.path.rsplit('.').next().unwrap_or(&s.path);
                let mut near: Vec<&str> = by_path
                    .keys()
                    .copied()
                    .filter(|p| {
                        p.eq_ignore_ascii_case(&s.path)
                            || p.rsplit('.').next().is_some_and(|l| l.eq_ignore_ascii_case(leaf))
                    })
                    .collect();
                near.sort_unstable();
                let mut r = refuse(
                    &m.payload_type,
                    &s.path,
                    "unknown-key",
                    format!("'{}' is not a key of {}", s.path, m.payload_type),
                );
                r.did_you_mean = near.first().map(|p| (*p).to_string());
                out.refused.push(r);
                continue;
            };
            if field.flags.read_only {
                out.refused.push(refuse(
                    &m.payload_type,
                    &s.path,
                    "read-only",
                    format!("'{}' is reported by the device; a profile cannot set it", s.path),
                ));
                continue;
            }
            if let Err(conflict) = crate::FieldPath::parse(&s.path)
                .insert_json(&mut values, typed(field, s.value.clone()))
            {
                out.refused.push(refuse(
                    &m.payload_type,
                    &s.path,
                    "path-conflict",
                    format!("{conflict}"),
                ));
            }
        }

        let values = serde_json::Value::Object(values);
        let target = Target {
            platform: opts.platform,
            os_version: opts.os_version.clone(),
        };
        for d in validate_target(reg, &m.payload_type, &values, &target) {
            if !d.blocks_emit {
                continue;
            }
            if opts.keep_unknown && d.rule == "unknown-key" {
                out.kept.push(refuse(&m.payload_type, &d.path, d.rule, format!("{}; written as given, unchecked", d.message)));
                continue;
            }
            let mut r = refuse(&m.payload_type, &d.path, d.rule, d.message);
            if let Some(f) = by_path.get(d.path.as_str()) {
                r.allowed = f.allowed_values.clone();
                if f.range_min.is_some() || f.range_max.is_some() {
                    r.range = Some([f.range_min, f.range_max]);
                }
            }
            out.refused.push(r);
        }
        if out.refused.len() > before {
            continue;
        }

        let opts = EmitOptions {
            intent: if single {
                opts.intent.clone()
            } else {
                intent_for(&m.payload_type)
            },
            ..opts.clone()
        };
        match emit(reg, &m.payload_type, &values, &opts).and_then(|mut docs| {
            if !extra.is_empty()
                && let Some(first) = docs.first_mut()
            {
                first.body = add_keys(&first.body, first.format, &extra)?;
            }
            Ok(docs)
        }) {
            Ok(docs) => out.documents.extend(docs),
            Err(e) => out
                .refused
                .push(refuse(&m.payload_type, "", "not-emitted", e.to_string())),
        }
    }
    out
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

// ---------------------------------------------------------------------------
// Channel resolution
// ---------------------------------------------------------------------------

/// The channel a top-level key demands on `platform`: the union of every
/// stated key-level scope in its subtree. `None` when nothing is stated.
fn subtree_channel(
    m: &PayloadManifest,
    top: &FieldDefinition,
    platform: Platform,
) -> Result<Option<Scope>, EmitError> {
    let mut set: BTreeSet<Scope> = BTreeSet::new();
    let prefix = format!("{}.", top.path);
    for f in m
        .fields
        .values()
        .filter(|f| f.path == top.path || f.path.starts_with(&prefix))
    {
        if let Some(s) = scope::key_scopes(f, platform) {
            set.extend(s);
        }
    }
    match (set.contains(&Scope::User), set.contains(&Scope::System)) {
        (true, true) => Err(EmitError::Unsatisfiable {
            key: top.name.clone(),
        }),
        (true, false) => Ok(Some(Scope::User)),
        (false, true) => Ok(Some(Scope::System)),
        (false, false) => Ok(None),
    }
}

struct Split {
    user: serde_json::Map<String, serde_json::Value>,
    system: serde_json::Map<String, serde_json::Value>,
}

fn split_by_channel(
    m: &PayloadManifest,
    obj: &serde_json::Map<String, serde_json::Value>,
    platform: Option<Platform>,
) -> Result<Split, EmitError> {
    let mut user = serde_json::Map::new();
    let mut system = serde_json::Map::new();
    for (k, v) in obj {
        let channel = match (
            platform,
            m.fields_in_order()
                .find(|f| f.parent_key.is_none() && f.name == *k),
        ) {
            (Some(p), Some(f)) => subtree_channel(m, f, p)?,
            _ => None,
        };
        match channel {
            Some(Scope::User) => user.insert(k.clone(), v.clone()),
            // Unrestricted keys ride with the system document.
            _ => system.insert(k.clone(), v.clone()),
        };
    }
    Ok(Split { user, system })
}

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

fn emit_declarations(
    m: &PayloadManifest,
    kind: Kind,
    obj: &serde_json::Map<String, serde_json::Value>,
    opts: &EmitOptions,
    platform: Option<Platform>,
) -> Result<Vec<Emitted>, EmitError> {
    let segment = kind.identifier_segment().unwrap_or("config");
    let base_id = format!("{}.{segment}.{}", opts.org.trim(), opts.intent.trim());
    let payload_class = platform
        .map(|p| ScopeClass::classify(scope::payload_scopes(m, p).as_ref()))
        .unwrap_or(ScopeClass::Unspecified);

    // A user-only payload has one channel; nothing to split.
    if payload_class == ScopeClass::UserOnly {
        return Ok(vec![declaration(
            m,
            &base_id,
            obj.clone(),
            Some(Scope::User),
            None,
        )?]);
    }

    let split = split_by_channel(m, obj, platform)?;
    if split.user.is_empty() {
        return Ok(vec![declaration(m, &base_id, split.system, None, None)?]);
    }
    if split.system.is_empty() {
        return Ok(vec![declaration(
            m,
            &base_id,
            split.user,
            Some(Scope::User),
            None,
        )?]);
    }
    Ok(vec![
        declaration(
            m,
            &format!("{base_id}.user"),
            split.user,
            Some(Scope::User),
            Some("User channel"),
        )?,
        declaration(
            m,
            &format!("{base_id}.system"),
            split.system,
            None,
            Some("System channel"),
        )?,
    ])
}

fn declaration(
    m: &PayloadManifest,
    id: &str,
    payload: serde_json::Map<String, serde_json::Value>,
    scope: Option<Scope>,
    label: Option<&str>,
) -> Result<Emitted, EmitError> {
    // Order matters for readers: Type, Identifier, then the rest.
    let mut doc = serde_json::Map::new();
    doc.insert(
        "Type".into(),
        serde_json::Value::String(m.payload_type.clone()),
    );
    doc.insert(
        "Identifier".into(),
        serde_json::Value::String(id.to_string()),
    );
    if let Some(s) = scope {
        // Fleet's delivery hint; not an Apple key. Present only when the
        // user channel is required, since the device channel is the default.
        doc.insert(
            "PayloadScope".into(),
            serde_json::Value::String(s.payload_scope_value().into()),
        );
    }
    let requirements = requirements(m, &payload);
    doc.insert("Payload".into(), serde_json::Value::Object(payload));
    // Ends with a newline, as `profile normalize` writes a declaration.
    let body = serde_json::to_string_pretty(&serde_json::Value::Object(doc))
        .map_err(|e| EmitError::Serialize(e.to_string()))?
        + "\n";
    Ok(Emitted {
        label: label.map(str::to_string),
        identifier: id.to_string(),
        filename: format!("{id}.json"),
        format: EmitFormat::Declaration,
        scope,
        requirements,
        body,
    })
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

fn emit_mobileconfig(
    m: &PayloadManifest,
    kind: Kind,
    obj: &serde_json::Map<String, serde_json::Value>,
    opts: &EmitOptions,
    platform: Option<Platform>,
) -> Result<Vec<Emitted>, EmitError> {
    let org = opts.org.trim();
    let intent = opts.intent.trim();
    let root_id = format!("{org}.{intent}");
    let payload_id = format!("{root_id}.payload");
    let display = opts.display_name.clone().unwrap_or_else(|| {
        if m.title.is_empty() {
            m.payload_type.clone()
        } else {
            m.title.clone()
        }
    });
    let nesting = opts.nesting.unwrap_or(match kind {
        Kind::ManagedPreference => Nesting::McxWrapped,
        _ => Nesting::Direct,
    });
    let scope =
        platform.and_then(
            |p| match ScopeClass::classify(scope::payload_scopes(m, p).as_ref()) {
                ScopeClass::UserOnly => Some(Scope::User),
                _ => None,
            },
        );

    let flat = json_to_plist_dict(m, None, obj)?;
    let mut inner = plist::Dictionary::new();
    match nesting {
        Nesting::Direct => {
            inner.insert("PayloadType".into(), m.payload_type.clone().into());
            for (k, v) in flat {
                inner.insert(k, v);
            }
        }
        Nesting::McxWrapped => {
            // domain → Forced → [ { mcx_preference_settings: <flat> } ]
            let mut settings = plist::Dictionary::new();
            settings.insert(
                "mcx_preference_settings".into(),
                plist::Value::Dictionary(flat),
            );
            let mut domain = plist::Dictionary::new();
            domain.insert(
                "Forced".into(),
                plist::Value::Array(vec![plist::Value::Dictionary(settings)]),
            );
            let mut content = plist::Dictionary::new();
            content.insert(m.payload_type.clone(), plist::Value::Dictionary(domain));
            inner.insert(
                "PayloadType".into(),
                "com.apple.ManagedClient.preferences".into(),
            );
            inner.insert("PayloadContent".into(), plist::Value::Dictionary(content));
        }
    }
    inner.insert("PayloadIdentifier".into(), payload_id.clone().into());
    inner.insert(
        "PayloadUUID".into(),
        identity::name_uuid(&payload_id).into(),
    );
    inner.insert("PayloadVersion".into(), plist::Value::Integer(1.into()));
    inner.insert("PayloadDisplayName".into(), display.clone().into());
    inner.insert("PayloadEnabled".into(), true.into());
    inner.insert("PayloadOrganization".into(), org.into());
    let inner = ordered(
        inner,
        &["PayloadType", "PayloadVersion", "PayloadIdentifier", "PayloadUUID"],
    );

    let mut root = plist::Dictionary::new();
    root.insert("PayloadType".into(), "Configuration".into());
    root.insert("PayloadVersion".into(), plist::Value::Integer(1.into()));
    root.insert("PayloadIdentifier".into(), root_id.clone().into());
    root.insert("PayloadUUID".into(), identity::name_uuid(&root_id).into());
    root.insert("PayloadDisplayName".into(), display.into());
    root.insert("PayloadOrganization".into(), org.into());
    root.insert(
        "PayloadScope".into(),
        scope.unwrap_or(Scope::System).payload_scope_value().into(),
    );
    root.insert(
        "PayloadContent".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(inner)]),
    );

    let root = ordered(
        root,
        &[
            "PayloadType",
            "PayloadVersion",
            "PayloadIdentifier",
            "PayloadUUID",
            "PayloadDisplayName",
            "PayloadContent",
        ],
    );

    let body = write_plist(root)?;
    Ok(vec![Emitted {
        label: None,
        identifier: root_id.clone(),
        filename: format!("{root_id}.mobileconfig"),
        format: EmitFormat::MobileConfig,
        scope,
        requirements: requirements(m, obj),
        body,
    }])
}

/// A profile as text, the way contour writes every profile.
fn write_plist(root: plist::Dictionary) -> Result<String, EmitError> {
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &plist::Value::Dictionary(root))
        .map_err(|e| EmitError::Serialize(e.to_string()))?;
    // Escape like Apple's writers (& < > only); see contour_profiles::xml.
    // Kept inline: contour-form stays free of native-only crates. Same guard
    // as there: keep the edit only if it parses to the same value.
    let text = String::from_utf8(buf).map_err(|e| EmitError::Serialize(e.to_string()))?;
    let fixed = text.replace("&quot;", "\"").replace("&apos;", "'");
    let parse = |s: &str| plist::from_bytes::<plist::Value>(s.as_bytes()).ok();
    Ok(match (parse(&fixed), parse(&text)) {
        (Some(a), Some(b)) if a == b => fixed,
        _ => text,
    })
}

/// JSON to plist with no schema to consult: strings stay strings.
fn plain_plist(v: &serde_json::Value) -> plist::Value {
    use serde_json::Value as J;
    match v {
        J::Null => plist::Value::String(String::new()),
        J::Bool(b) => plist::Value::Boolean(*b),
        J::Number(n) => n.as_i64().map_or_else(|| plist::Value::Real(n.as_f64().unwrap_or(0.0)), |i| plist::Value::Integer(i.into())),
        J::String(s) => plist::Value::String(s.clone()),
        J::Array(a) => plist::Value::Array(a.iter().map(plain_plist).collect()),
        J::Object(o) => plist::Value::Dictionary(o.iter().map(|(k, v)| (k.clone(), plain_plist(v))).collect()),
    }
}

/// Keys the schema does not document, added to an emitted document's
/// payload: the settings dictionary of a profile (inside the MCX wrapper
/// where there is one), or `Payload` of a declaration.
fn add_keys(body: &str, format: EmitFormat, extra: &serde_json::Map<String, serde_json::Value>) -> Result<String, EmitError> {
    let bad = |what: &str| EmitError::Serialize(format!("adding undocumented keys: {what}"));
    if format == EmitFormat::Declaration {
        let mut v: serde_json::Value = serde_json::from_str(body).map_err(|e| bad(&e.to_string()))?;
        let payload = v.get_mut("Payload").and_then(|p| p.as_object_mut()).ok_or_else(|| bad("no Payload"))?;
        for (k, val) in extra {
            payload.insert(k.clone(), val.clone());
        }
        let mut text = serde_json::to_string_pretty(&v).map_err(|e| bad(&e.to_string()))?;
        text.push('\n');
        return Ok(text);
    }
    let mut root: plist::Dictionary = plist::from_bytes(body.as_bytes()).map_err(|e| bad(&e.to_string()))?;
    let inner = root
        .get_mut("PayloadContent")
        .and_then(plist::Value::as_array_mut)
        .and_then(|a| a.first_mut())
        .and_then(plist::Value::as_dictionary_mut)
        .ok_or_else(|| bad("no payload"))?;
    let mcx = inner.get("PayloadType").and_then(plist::Value::as_string) == Some("com.apple.ManagedClient.preferences");
    let target = if mcx {
        inner
            .get_mut("PayloadContent")
            .and_then(plist::Value::as_dictionary_mut)
            .and_then(|d| d.values_mut().next())
            .and_then(plist::Value::as_dictionary_mut)
            .and_then(|d| d.get_mut("Forced"))
            .and_then(plist::Value::as_array_mut)
            .and_then(|a| a.first_mut())
            .and_then(plist::Value::as_dictionary_mut)
            .and_then(|d| d.get_mut("mcx_preference_settings"))
            .and_then(plist::Value::as_dictionary_mut)
            .ok_or_else(|| bad("no MCX settings"))?
    } else {
        inner
    };
    for (k, v) in extra {
        target.insert(k.clone(), plain_plist(v));
    }
    let head = ["PayloadType", "PayloadVersion", "PayloadIdentifier", "PayloadUUID"];
    if !mcx {
        let sorted = ordered(std::mem::take(target), &head);
        *target = sorted;
    } else {
        let sorted = ordered(std::mem::take(target), &[]);
        *target = sorted;
    }
    write_plist(root)
}

/// A profile for a payload type the schema does not have: its keys as
/// given, in contour's envelope.
fn passthrough(
    type_id: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
    opts: &EmitOptions,
) -> Result<Emitted, EmitError> {
    identity::validate_org_domain(&opts.org).map_err(EmitError::Org)?;
    let org = opts.org.trim();
    let root_id = format!("{org}.{}", opts.intent.trim());
    let payload_id = format!("{root_id}.payload");
    let display = opts.display_name.clone().unwrap_or_else(|| type_id.to_string());
    let mut inner: plist::Dictionary = obj.iter().map(|(k, v)| (k.clone(), plain_plist(v))).collect();
    inner.insert("PayloadType".into(), type_id.into());
    inner.insert("PayloadIdentifier".into(), payload_id.clone().into());
    inner.insert("PayloadUUID".into(), identity::name_uuid(&payload_id).into());
    inner.insert("PayloadVersion".into(), plist::Value::Integer(1.into()));
    inner.insert("PayloadDisplayName".into(), display.clone().into());
    inner.insert("PayloadEnabled".into(), true.into());
    inner.insert("PayloadOrganization".into(), org.into());
    let inner = ordered(inner, &["PayloadType", "PayloadVersion", "PayloadIdentifier", "PayloadUUID"]);
    let mut root = plist::Dictionary::new();
    root.insert("PayloadType".into(), "Configuration".into());
    root.insert("PayloadVersion".into(), plist::Value::Integer(1.into()));
    root.insert("PayloadIdentifier".into(), root_id.clone().into());
    root.insert("PayloadUUID".into(), identity::name_uuid(&root_id).into());
    root.insert("PayloadDisplayName".into(), display.into());
    root.insert("PayloadOrganization".into(), org.into());
    root.insert("PayloadScope".into(), Scope::System.payload_scope_value().into());
    root.insert("PayloadContent".into(), plist::Value::Array(vec![plist::Value::Dictionary(inner)]));
    let root = ordered(root, &["PayloadType", "PayloadVersion", "PayloadIdentifier", "PayloadUUID", "PayloadDisplayName", "PayloadContent"]);
    Ok(Emitted {
        label: None,
        identifier: root_id.clone(),
        filename: format!("{root_id}.mobileconfig"),
        format: EmitFormat::MobileConfig,
        scope: None,
        requirements: Requirements::default(),
        body: write_plist(root)?,
    })
}

/// `head` keys first in that order, then the rest sorted: the key order
/// `profile normalize` writes, so an emitted profile is already in it.
///
/// The same function as `contour_profiles::xml::ordered`, kept inline for the
/// reason the escape above is: contour-form stays free of native-only crates.
/// `every_generator_agrees_with_normalize` holds the two together.
fn ordered(dict: plist::Dictionary, head: &[&str]) -> plist::Dictionary {
    let mut rest: Vec<_> = dict.into_iter().collect();
    rest.sort_by(|a, b| {
        let rank = |k: &str| head.iter().position(|h| *h == k).unwrap_or(head.len());
        rank(&a.0).cmp(&rank(&b.0)).then_with(|| a.0.cmp(&b.0))
    });
    rest.into_iter().collect()
}

/// Convert a values object to a plist dictionary, consulting the schema.
///
/// JSON has no bytes type, so a `<data>` key arrives as a base64 string and
/// looks exactly like a `<string>` key. Converting on the JSON type alone —
/// which is what this did — emits
///
/// ```xml
/// <key>ConfigurationProfile</key>
/// <string>PD94bWwgdmVyc2lvbj0i…</string>
/// ```
///
/// for a key Apple types `<data>`. The profile installs, the key is the
/// wrong type, and the payload does nothing. 72 keys across the schema are
/// typed `<data>`, including `ESSO.ConfigurationProfile`,
/// `EraseDevice.ReturnToService.WiFiProfileData` and the pinning
/// certificates in `InstallEnterpriseApplication`.
///
/// So the schema decides, not the JSON. `parent` carries the dotted path so
/// nested keys resolve against `fields`, which is keyed by path.
fn json_to_plist_dict(
    m: &PayloadManifest,
    parent: Option<&str>,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<plist::Dictionary, EmitError> {
    let mut out = plist::Dictionary::new();
    for (k, v) in obj {
        let path = FieldDefinition::compose_path(parent, k);
        out.insert(k.clone(), json_to_plist(m, &path, v)?);
    }
    Ok(out)
}

/// The schema type at `path`, when the manifest declares one.
fn declared_type(m: &PayloadManifest, path: &str) -> Option<FieldType> {
    m.fields.get(path).map(|f| f.field_type)
}

fn json_to_plist(
    m: &PayloadManifest,
    path: &str,
    v: &serde_json::Value,
) -> Result<plist::Value, EmitError> {
    use base64::Engine as _;
    use serde_json::Value as J;
    Ok(match v {
        J::Null => plist::Value::String(String::new()),
        J::Bool(b) => plist::Value::Boolean(*b),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                plist::Value::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                plist::Value::Integer(u.into())
            } else {
                plist::Value::Real(n.as_f64().unwrap_or(0.0))
            }
        }
        J::String(s) => {
            if declared_type(m, path) == Some(FieldType::Data) {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(s.trim())
                    .map_err(|err| EmitError::NotBase64 {
                        path: path.to_string(),
                        reason: err.to_string(),
                    })?;
                plist::Value::Data(bytes)
            } else {
                plist::Value::String(s.clone())
            }
        }
        J::Array(items) => {
            // Apple names an array's element type as a child key —
            // `ManifestURLPinningCerts.ManifestURLPinningCertsItem` — so the
            // elements resolve against that path, not the array's.
            let item_path = array_item_path(m, path);
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(json_to_plist(m, item_path.as_deref().unwrap_or(path), it)?);
            }
            plist::Value::Array(out)
        }
        J::Object(o) => plist::Value::Dictionary(json_to_plist_dict(m, Some(path), o)?),
    })
}

/// The path of an array's element definition, when the schema declares
/// exactly one child under `path`. Ambiguity means we cannot tell which
/// child types the elements, so the array's own path is used and a `<data>`
/// element falls back to `<string>` — no worse than before, and never a
/// wrong guess.
fn array_item_path(m: &PayloadManifest, path: &str) -> Option<String> {
    let prefix = format!("{path}.");
    let mut children = m
        .fields
        .keys()
        .filter(|k| k.starts_with(&prefix) && !k[prefix.len()..].contains('.'));
    let first = children.next()?;
    if children.next().is_some() {
        return None;
    }
    Some(first.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reg() -> SchemaRegistry {
        SchemaRegistry::embedded().unwrap()
    }

    fn opts(intent: &str) -> EmitOptions {
        EmitOptions {
            org: "com.acme".into(),
            intent: intent.into(),
            platform: Some(Platform::MacOS),
            ..Default::default()
        }
    }

    /// The shape an agent sends: keys of two types in one list, values as text.
    #[test]
    fn settings_across_types_emit_together_and_refusals_say_how_to_fix() {
        let r = reg();
        let settings = |v: serde_json::Value| -> Vec<Setting> { serde_json::from_value(v).unwrap() };
        let o = EmitOptions {
            org: "com.acme".into(),
            platform: Some(Platform::MacOS),
            ..Default::default()
        };

        let good = emit_settings(
            &r,
            &settings(json!([
                {"type": "com.apple.applicationaccess", "path": "allowAirDrop", "value": "false"},
                {"type": "com.apple.applicationaccess", "path": "allowCamera", "value": false},
                {"type": "com.apple.configuration.passcode.settings", "path": "MinimumLength", "value": "12"},
            ])),
            &o,
        );
        assert!(good.refused.is_empty(), "{:?}", good.refused);
        assert_eq!(good.documents.len(), 2);
        let profile = good.documents.iter().find(|d| d.format == EmitFormat::MobileConfig).unwrap();
        assert!(profile.body.contains("<key>allowAirDrop</key>\n\t\t\t<false/>"), "{}", profile.body);
        let declaration = good.documents.iter().find(|d| d.format == EmitFormat::Declaration).unwrap();
        assert!(declaration.body.contains("\"MinimumLength\": 12"), "{}", declaration.body);

        // One bad key refuses its own type and leaves the other type alone.
        let mixed = emit_settings(
            &r,
            &settings(json!([
                {"type": "com.apple.applicationaccess", "path": "allowairdrop", "value": false},
                {"type": "com.apple.configuration.softwareupdate.settings", "path": "AutomaticActions.InstallOSUpdates", "value": "Always"},
                {"type": "com.apple.configuration.passcode.settings", "path": "MinimumLength", "value": 12},
            ])),
            &o,
        );
        assert_eq!(mixed.documents.len(), 1, "only the passcode declaration");
        let unknown = mixed.refused.iter().find(|x| x.rule == "unknown-key").unwrap();
        assert_eq!(unknown.did_you_mean.as_deref(), Some("allowAirDrop"));
        let not_in_enum = mixed.refused.iter().find(|x| x.path == "AutomaticActions.InstallOSUpdates").unwrap();
        assert!(not_in_enum.allowed.iter().any(|v| v == "AlwaysOn"), "{not_in_enum:?}");
    }

    /// Two Apple files describe com.apple.extensiblesso; the Kerberos one's
    /// fixed values must not bind every SSO extension.
    #[test]
    fn a_variant_does_not_narrow_what_its_payload_type_accepts() {
        let r = reg();
        let set = |p: &str, v: serde_json::Value| Setting { type_id: "com.apple.extensiblesso".into(), path: p.into(), value: v };
        let out = emit_settings(
            &r,
            &[
                set("ExtensionIdentifier", json!("com.microsoft.CompanyPortalMac.ssoextension")),
                set("TeamIdentifier", json!("UBF8T346G9")),
                set("Type", json!("Redirect")),
                set("URLs", json!(["https://login.microsoftonline.com"])),
            ],
            &opts(""),
        );
        assert!(!out.refused.iter().any(|x| x.rule == "not-in-enum"), "{:?}", out.refused);
        let bogus = emit_settings(&r, &[set("Type", json!("Sideways"))], &opts(""));
        assert!(bogus.refused.iter().any(|x| x.rule == "not-in-enum"), "Type still has a fixed set: {:?}", bogus.refused);
    }

    /// YAML 1.1 reads mSCP's `Enable: On` as `true`; FileVault's `Enable`
    /// is text that takes `On` or `Off`.
    #[test]
    fn a_boolean_for_an_on_off_text_key_is_written_as_its_word() {
        let r = reg();
        let set = |v: serde_json::Value| Setting { type_id: "com.apple.MCX.FileVault2".into(), path: "Enable".into(), value: v };
        let out = emit_settings(&r, &[set(json!(true))], &opts(""));
        assert!(!out.refused.iter().any(|x| x.rule == "type-mismatch"), "{:?}", out.refused);
        let xml = &out.documents[0].body;
        assert!(xml.contains("<string>On</string>"), "{xml}");
        let sorted = crate::intent::sort_baseline(&r, "800-171").unwrap();
        let enable = sorted.settings.iter().find(|s| s.type_id == "com.apple.MCX.FileVault2" && s.path == "Enable").unwrap();
        assert_eq!(enable.value, json!("On"), "the baseline's value reads as the page shows it");
    }

    /// Apple types each logging subsystem `<any>`; in practice it is a
    /// dictionary of options, and that must not read as a wrong type.
    #[test]
    fn an_any_typed_value_takes_a_dictionary() {
        let r = reg();
        let out = emit_settings(
            &r,
            &[Setting {
                type_id: "com.apple.system.logging".into(),
                path: "Subsystems".into(),
                value: json!({"com.apple.IPConfiguration": {"DEFAULT-OPTIONS": {"Level": {"Enable": "Info"}}}}),
            }],
            &opts(""),
        );
        assert!(!out.refused.iter().any(|x| x.rule == "type-mismatch"), "{:?}", out.refused);
    }

    /// A profile someone already deploys keeps what the schema does not
    /// know, flagged, instead of being held back for it.
    #[test]
    fn keep_unknown_writes_undocumented_keys_and_types() {
        let r = reg();
        let set = |t: &str, p: &str, v: serde_json::Value| Setting { type_id: t.into(), path: p.into(), value: v };
        let settings = [
            set("com.apple.loginwindow", "DisableLoginItemsSuppression", json!(true)),
            set("com.apple.loginwindow", "SHOWFULLNAME", json!(true)),
            set("com.acme.vendor.app", "LicenseServer", json!("lic.acme.test")),
        ];
        let strict = emit_settings(&r, &settings, &opts(""));
        assert!(strict.refused.iter().any(|x| x.rule == "unknown-key"));
        assert!(strict.refused.iter().any(|x| x.rule == "unknown-type"));

        let lenient = emit_settings(&r, &settings, &EmitOptions { keep_unknown: true, ..opts("") });
        assert!(lenient.refused.is_empty(), "{:?}", lenient.refused);
        assert_eq!(lenient.kept.len(), 2, "{:?}", lenient.kept);
        let body = |t: &str| lenient.documents.iter().find(|d| d.body.contains(t)).map(|d| d.body.clone()).unwrap();
        assert!(body("DisableLoginItemsSuppression").contains("SHOWFULLNAME"), "documented and undocumented keys in one payload");
        assert!(body("com.acme.vendor.app").contains("<string>lic.acme.test</string>"));
        // An undocumented key inside a documented dictionary is kept too.
        let nested = emit_settings(&r, &[set("com.apple.security.scep", "PayloadContent", json!({"URL": "https://scep.acme.test", "ScepProxyOption": 1}))], &EmitOptions { keep_unknown: true, ..opts("") });
        assert!(nested.refused.is_empty(), "{:?}", nested.refused);
        assert!(nested.documents[0].body.contains("ScepProxyOption"));
        assert!(nested.kept.iter().any(|k| k.path.ends_with("ScepProxyOption")), "{:?}", nested.kept);
        // A known key's value is still checked.
        let wrong = emit_settings(&r, &[set("com.apple.loginwindow", "SHOWFULLNAME", json!("maybe"))], &EmitOptions { keep_unknown: true, ..opts("") });
        assert!(!wrong.refused.is_empty());
    }

    /// The requirements are those of the keys that were set, not of the type.
    #[test]
    fn requirements_follow_the_keys_that_were_set() {
        let r = reg();
        let emit_one = |values| {
            emit(&r, "com.apple.applicationaccess", &values, &opts("restrictions")).unwrap()[0]
                .requirements
                .clone()
        };
        let airdrop = emit_one(json!({"allowAirDrop": false}));
        assert_eq!(airdrop.supervised, ["allowAirDrop"]);
        assert!(airdrop.min_os.contains_key("macOS"), "{airdrop:?}");

        let wifi = emit(
            &r,
            "com.apple.wifi.managed",
            &json!({"SSID_STR": "Acme", "EncryptionType": "WPA2", "Password": "x"}),
            &opts("wifi"),
        )
        .unwrap();
        assert_eq!(wifi[0].requirements.sensitive, ["Password"]);
        assert!(wifi[0].requirements.supervised.is_empty());
    }

    /// A key Apple types `<data>` must emit `<data>`.
    ///
    /// SCEP's CA fingerprint is a hash — binary by nature. JSON has no bytes,
    /// so it arrives as base64 and is indistinguishable from a string value
    /// unless the schema is consulted. Emitted as `<string>` the profile
    /// installs cleanly and the fingerprint is never checked.
    #[test]
    fn a_data_typed_key_emits_data_not_string() {
        let r = reg();
        let values = json!({"PayloadContent": {
            "URL": "https://scep.example.com/scep",
            "CAFingerprint": "3q2+7w==",
        }});
        let out = emit(&r, "com.apple.security.scep", &values, &opts("scep")).unwrap();
        let body = &out[0].body;
        assert!(
            body.contains("<data>"),
            "CAFingerprint is typed <data> upstream; emitted body has no <data>:\n{body}"
        );
        assert!(
            !body.contains("<string>3q2+7w==</string>"),
            "the base64 was emitted as a string:\n{body}"
        );
    }

    /// The sibling key in the same dictionary is a string and stays one —
    /// the schema decides per key, not per payload.
    #[test]
    fn a_string_key_beside_a_data_key_is_unaffected() {
        let r = reg();
        let values = json!({"PayloadContent": {
            "URL": "https://scep.example.com/scep",
            "CAFingerprint": "3q2+7w==",
        }});
        let out = emit(&r, "com.apple.security.scep", &values, &opts("scep")).unwrap();
        assert!(
            out[0]
                .body
                .contains("<string>https://scep.example.com/scep</string>"),
            "{}",
            out[0].body
        );
    }

    /// Something that is not base64 in a `<data>` key is refused.
    ///
    /// Falling back to `<string>` would be the original bug with extra
    /// steps: a profile that installs and does nothing. `validate` catches
    /// it first, with the path (`data-not-base64`); the converter's own
    /// `NotBase64` stays as the last line of defence for a caller that
    /// bypasses validation.
    #[test]
    fn a_data_key_given_non_base64_is_refused() {
        let r = reg();
        let values = json!({"PayloadContent": {
            "URL": "https://scep.example.com/scep",
            "CAFingerprint": "not base64 at all!!",
        }});
        match emit(&r, "com.apple.security.scep", &values, &opts("scep")) {
            Err(EmitError::Invalid(ds)) => assert!(
                ds.iter()
                    .any(|d| d.rule == "data-not-base64" && d.path.ends_with("CAFingerprint")),
                "{ds:?}"
            ),
            Err(EmitError::NotBase64 { path, .. }) => {
                assert!(path.ends_with("CAFingerprint"), "path was {path}");
            }
            Err(e) => panic!("wrong error: {e}"),
            Ok(_) => panic!("a <data> key given non-base64 must not emit"),
        }
    }

    /// R8's three cases on app.settings, macOS: Privacy is user-only,
    /// Allowed.* is system-only, together they are two documents.
    #[test]
    fn app_settings_splits_by_channel_only_when_it_must() {
        let r = reg();
        let ty = "com.apple.configuration.app.settings";
        // macOS target, so the key is the macOS spelling — a bare bundle ID
        // is refused there (`composed-identifier`), which is not this test.
        let privacy = json!({"Privacy": {"PermissionDefaults": {
            "us.zoom.xos {anchor apple generic}": {"Camera": "Allow", "OrganizationJustification": "Calls"}}}});
        let allowed = json!({"Allowed": {"AllowedBinaries": [
            {"TeamID": "BJ4HAAB9B3", "SigningID": "us.zoom.xos"}]}});
        let mut both = privacy.clone();
        both.as_object_mut()
            .unwrap()
            .insert("Allowed".into(), allowed["Allowed"].clone());

        let one = emit(&r, ty, &privacy, &opts("app-privacy")).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].scope, Some(Scope::User));
        assert!(
            one[0].body.contains("\"PayloadScope\": \"User\""),
            "{}",
            one[0].body
        );
        assert_eq!(one[0].identifier, "com.acme.config.app-privacy");

        let sys = emit(&r, ty, &allowed, &opts("app-privacy")).unwrap();
        assert_eq!(sys.len(), 1);
        assert_eq!(sys[0].scope, None);
        assert!(!sys[0].body.contains("PayloadScope"), "{}", sys[0].body);

        let two = emit(&r, ty, &both, &opts("app-privacy")).unwrap();
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].identifier, "com.acme.config.app-privacy.user");
        assert!(two[0].body.contains("Privacy") && !two[0].body.contains("Allowed"));
        assert_eq!(two[1].identifier, "com.acme.config.app-privacy.system");
        assert!(two[1].body.contains("Allowed") && !two[1].body.contains("Privacy"));
        assert_eq!(two[0].label.as_deref(), Some("User channel"));
    }

    #[test]
    fn placeholder_org_is_refused_not_defaulted() {
        let r = reg();
        let mut o = opts("x");
        o.org = "com.example".into();
        let err = emit(
            &r,
            "com.apple.configuration.safari.settings",
            &json!({}),
            &o,
        )
        .unwrap_err();
        assert!(matches!(err, EmitError::Org(_)), "{err}");
    }

    #[test]
    fn invalid_values_block_emission_with_paths() {
        let r = reg();
        let err = emit(
            &r,
            "com.apple.configuration.safari.settings",
            &json!({"AcceptCookies": "Sometimes"}),
            &opts("safari"),
        )
        .unwrap_err();
        match err {
            EmitError::Invalid(ds) => assert!(ds.iter().any(|d| d.path == "AcceptCookies")),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn preference_domain_is_mcx_wrapped_by_default_and_direct_on_request() {
        // com.microsoft.wdav is an app-schema preference domain, so it gets
        // the MCX envelope by default.
        let r = reg();
        let values = json!({"antivirusEngine": {"enforcementLevel": "real_time"}});
        let mcx = emit(&r, "com.microsoft.wdav", &values, &opts("defender")).unwrap();
        assert_eq!(mcx.len(), 1);
        assert_eq!(mcx[0].format, EmitFormat::MobileConfig);
        let doc: plist::Value = plist::from_bytes(mcx[0].body.as_bytes()).unwrap();
        let root = doc.as_dictionary().unwrap();
        let inner = root["PayloadContent"].as_array().unwrap()[0]
            .as_dictionary()
            .unwrap();
        assert_eq!(
            inner["PayloadType"].as_string(),
            Some("com.apple.ManagedClient.preferences")
        );
        let forced = inner["PayloadContent"].as_dictionary().unwrap()["com.microsoft.wdav"]
            .as_dictionary()
            .unwrap()["Forced"]
            .as_array()
            .unwrap();
        let settings = forced[0].as_dictionary().unwrap()["mcx_preference_settings"]
            .as_dictionary()
            .unwrap();
        assert!(settings.contains_key("antivirusEngine"));

        let mut o = opts("defender");
        o.nesting = Some(Nesting::Direct);
        let direct = emit(&r, "com.microsoft.wdav", &values, &o).unwrap();
        let doc: plist::Value = plist::from_bytes(direct[0].body.as_bytes()).unwrap();
        let inner = doc.as_dictionary().unwrap()["PayloadContent"]
            .as_array()
            .unwrap()[0]
            .as_dictionary()
            .unwrap();
        assert_eq!(inner["PayloadType"].as_string(), Some("com.microsoft.wdav"));
        assert!(inner.contains_key("antivirusEngine"));
    }

    #[test]
    fn same_input_same_bytes() {
        let registry = reg();
        // AcceptCookies is n/a on macOS — Apple states it — so this targets
        // iOS; `key-unavailable-on-platform` refuses it on macOS.
        let values = json!({"AcceptCookies": "Never"});
        let ios = EmitOptions {
            platform: Some(Platform::Ios),
            ..opts("s")
        };
        let first = emit(
            &registry,
            "com.apple.configuration.safari.settings",
            &values,
            &ios,
        )
        .unwrap();
        let second = emit(
            &registry,
            "com.apple.configuration.safari.settings",
            &values,
            &ios,
        )
        .unwrap();
        assert_eq!(first[0].body, second[0].body);
        let wifi_a = emit(
            &registry,
            "com.apple.wifi.managed",
            &json!({"SSID_STR": "corp", "EncryptionType": "WPA2"}),
            &opts("wifi"),
        )
        .unwrap();
        let wifi_b = emit(
            &registry,
            "com.apple.wifi.managed",
            &json!({"SSID_STR": "corp", "EncryptionType": "WPA2"}),
            &opts("wifi"),
        )
        .unwrap();
        assert_eq!(wifi_a[0].body, wifi_b[0].body);
        assert!(wifi_a[0].body.contains("<key>PayloadUUID</key>"));
    }
}
