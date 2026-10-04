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

use std::collections::BTreeSet;

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
    pub body: String,
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
            EmitError::NotBase64 { path } => write!(
                f,
                "'{path}' is typed <data> in the schema, so its value must be base64; \
                 what was supplied does not decode. A <data> key given a <string> \
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
            ..Default::default()
        },
    );
    if diagnostics.iter().any(|d| d.blocks_emit) {
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
    doc.insert("Payload".into(), serde_json::Value::Object(payload));
    let body = serde_json::to_string_pretty(&serde_json::Value::Object(doc))
        .map_err(|e| EmitError::Serialize(e.to_string()))?;
    Ok(Emitted {
        label: label.map(str::to_string),
        identifier: id.to_string(),
        filename: format!("{id}.json"),
        format: EmitFormat::Declaration,
        scope,
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

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &plist::Value::Dictionary(root))
        .map_err(|e| EmitError::Serialize(e.to_string()))?;
    let body = String::from_utf8(buf).map_err(|e| EmitError::Serialize(e.to_string()))?;
    Ok(vec![Emitted {
        label: None,
        identifier: root_id.clone(),
        filename: format!("{root_id}.mobileconfig"),
        format: EmitFormat::MobileConfig,
        scope,
        body,
    }])
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
                    .map_err(|_| EmitError::NotBase64 {
                        path: path.to_string(),
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
            Err(EmitError::NotBase64 { path }) => {
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
