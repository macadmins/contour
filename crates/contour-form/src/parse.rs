//! `parse()` — an existing document back into values a form can populate.
//!
//! The inverse of [`emit`](crate::emit). Accepts a JSON declaration or a
//! `.mobileconfig` (XML or binary plist) as bytes, identifies each payload's
//! type, unwraps the MCX envelope where present, and returns the values as a
//! **nested** object mirroring the document.
//!
//! ## Why nested, not flattened
//!
//! FormSpec §8 left the round trip open on one point: a `dict-of` entry whose
//! key contains dots — `Privacy.PermissionDefaults` keyed by
//! `us.zoom.xos`. Flattening to dotted paths makes
//! `Privacy.PermissionDefaults.us.zoom.xos.Camera` ambiguous, and any escaping
//! scheme leaks into the contract. The decision: **paths identify schema
//! nodes, never value locations.** An operator's key is data. A consumer
//! walks the values structurally beside the FormSpec tree and, at a
//! `dict-of` node, iterates the object's keys. Nothing is split on `.`.
//!
//! What does not round-trip losslessly: plist `<data>` comes back as a
//! base64 string and `<date>` as its XML form, because JSON has neither type;
//! `emit` then writes them as strings and `validate` says so.

use std::collections::BTreeMap;

use base64::Engine as _;
use serde::Serialize;

use crate::SchemaRegistry;
use crate::form::{FormError, Target, form};
use crate::formspec::{FormSpec, Nesting};
use crate::scope::Scope;

/// One payload, parsed.
#[derive(Debug, Clone, Serialize)]
pub struct Parsed {
    /// The payload or declaration type the values belong to.
    pub type_id: String,
    /// The contract for it, so a caller can render without a second call.
    pub spec: FormSpec,
    /// The values, nested as in the document, bookkeeping keys removed.
    pub values: serde_json::Value,
    /// The bookkeeping around the payload: `Type`/`Identifier`/`ServerToken`
    /// for a declaration; the `Payload*` keys of the inner dictionary for a
    /// profile.
    pub envelope: BTreeMap<String, serde_json::Value>,
    /// The profile-level `Payload*` keys, for a `.mobileconfig`. Absent for
    /// a declaration, whose only layer is the declaration itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<BTreeMap<String, serde_json::Value>>,
    /// How the profile carried the keys. Absent for a declaration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nesting: Option<Nesting>,
    /// `PayloadScope` as the document stated it, where it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
}

#[derive(Debug)]
pub enum ParseError {
    /// Neither JSON nor a plist.
    Unrecognised,
    Json(String),
    Plist(String),
    /// A declaration without `Type`, a payload without `PayloadType`.
    MissingType,
    /// The document parsed but its type has no form.
    Form(FormError),
    /// A profile with no `PayloadContent` array.
    NoPayloads,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Unrecognised => {
                write!(f, "document is neither a JSON declaration nor a plist")
            }
            ParseError::Json(e) => write!(f, "invalid JSON: {e}"),
            ParseError::Plist(e) => write!(f, "invalid plist: {e}"),
            ParseError::MissingType => write!(f, "document names no type (`Type` / `PayloadType`)"),
            ParseError::Form(e) => write!(f, "{e}"),
            ParseError::NoPayloads => write!(f, "profile has no PayloadContent"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<FormError> for ParseError {
    fn from(e: FormError) -> Self {
        ParseError::Form(e)
    }
}

const MCX_TYPE: &str = "com.apple.ManagedClient.preferences";

/// Parse a document. A declaration yields one [`Parsed`]; a profile yields
/// one per payload in `PayloadContent`.
pub fn parse(
    reg: &SchemaRegistry,
    document: &[u8],
    target: &Target,
) -> Result<Vec<Parsed>, ParseError> {
    let head = document
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &document[i..])
        .unwrap_or(document);
    if head.starts_with(b"{") {
        let v: serde_json::Value =
            serde_json::from_slice(head).map_err(|e| ParseError::Json(e.to_string()))?;
        return Ok(vec![parse_declaration(reg, &v, target)?]);
    }
    if head.starts_with(b"<") || head.starts_with(b"bplist") {
        let v: plist::Value =
            plist::from_bytes(head).map_err(|e| ParseError::Plist(e.to_string()))?;
        return parse_profile(reg, &v, target);
    }
    Err(ParseError::Unrecognised)
}

fn parse_declaration(
    reg: &SchemaRegistry,
    v: &serde_json::Value,
    target: &Target,
) -> Result<Parsed, ParseError> {
    let obj = v.as_object().ok_or(ParseError::Unrecognised)?;
    let type_id = obj
        .get("Type")
        .and_then(|t| t.as_str())
        .ok_or(ParseError::MissingType)?
        .to_string();
    let spec = form(reg, &type_id, target)?;
    let mut envelope = BTreeMap::new();
    for (k, val) in obj {
        if k != "Payload" {
            envelope.insert(k.clone(), val.clone());
        }
    }
    let scope = obj
        .get("PayloadScope")
        .and_then(|s| s.as_str())
        .and_then(Scope::parse);
    Ok(Parsed {
        type_id,
        spec,
        values: obj
            .get("Payload")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
        envelope,
        root: None,
        nesting: None,
        scope,
    })
}

fn parse_profile(
    reg: &SchemaRegistry,
    v: &plist::Value,
    target: &Target,
) -> Result<Vec<Parsed>, ParseError> {
    let root = v.as_dictionary().ok_or(ParseError::Unrecognised)?;
    let payloads = root
        .get("PayloadContent")
        .and_then(plist::Value::as_array)
        .ok_or(ParseError::NoPayloads)?;

    let root_meta: BTreeMap<String, serde_json::Value> = root
        .iter()
        .filter(|(k, _)| k.as_str() != "PayloadContent")
        .map(|(k, val)| (k.clone(), plist_to_json(val)))
        .collect();
    let scope = root
        .get("PayloadScope")
        .and_then(plist::Value::as_string)
        .and_then(Scope::parse);

    let mut out = Vec::new();
    for p in payloads {
        let Some(inner) = p.as_dictionary() else {
            continue;
        };
        let payload_type = inner
            .get("PayloadType")
            .and_then(plist::Value::as_string)
            .ok_or(ParseError::MissingType)?;

        let envelope: BTreeMap<String, serde_json::Value> = inner
            .iter()
            .filter(|(k, _)| is_bookkeeping(k))
            .map(|(k, val)| (k.clone(), plist_to_json(val)))
            .collect();

        if payload_type == MCX_TYPE {
            // domain → Forced → [ { mcx_preference_settings: <flat> } ]
            let Some(domains) = inner
                .get("PayloadContent")
                .and_then(plist::Value::as_dictionary)
            else {
                continue;
            };
            for (domain, d) in domains {
                let settings = d
                    .as_dictionary()
                    .and_then(|d| d.get("Forced"))
                    .and_then(plist::Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(plist::Value::as_dictionary)
                    .and_then(|f| f.get("mcx_preference_settings"))
                    .map(plist_to_json)
                    .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
                out.push(Parsed {
                    type_id: domain.clone(),
                    spec: form(reg, domain, target)?,
                    values: settings,
                    envelope: envelope.clone(),
                    root: Some(root_meta.clone()),
                    nesting: Some(Nesting::McxWrapped),
                    scope,
                });
            }
            continue;
        }

        let values: serde_json::Map<String, serde_json::Value> = inner
            .iter()
            .filter(|(k, _)| !is_bookkeeping(k))
            .map(|(k, val)| (k.clone(), plist_to_json(val)))
            .collect();
        out.push(Parsed {
            type_id: payload_type.to_string(),
            spec: form(reg, payload_type, target)?,
            values: serde_json::Value::Object(values),
            envelope,
            root: Some(root_meta.clone()),
            nesting: Some(Nesting::Direct),
            scope,
        });
    }
    Ok(out)
}

/// The keys Apple defines on every payload dictionary — the envelope, not
/// the settings. `PayloadContent` is deliberately not here: on a direct
/// payload it is a real key (SCEP, certificates), and the MCX case is
/// handled before this is consulted.
fn is_bookkeeping(k: &str) -> bool {
    matches!(
        k,
        "PayloadType"
            | "PayloadVersion"
            | "PayloadIdentifier"
            | "PayloadUUID"
            | "PayloadDisplayName"
            | "PayloadDescription"
            | "PayloadOrganization"
            | "PayloadEnabled"
    )
}

/// plist → JSON. `<data>` becomes base64, `<date>` its XML form; neither has
/// a JSON type, and a string is the honest carrier.
pub fn plist_to_json(v: &plist::Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        plist::Value::Boolean(b) => J::Bool(*b),
        plist::Value::Integer(i) => i
            .as_signed()
            .map(J::from)
            .or_else(|| i.as_unsigned().map(J::from))
            .unwrap_or(J::Null),
        plist::Value::Real(r) => serde_json::Number::from_f64(*r).map_or(J::Null, J::Number),
        plist::Value::String(s) => J::String(s.clone()),
        plist::Value::Date(d) => J::String(d.to_xml_format()),
        plist::Value::Uid(u) => J::from(u.get()),
        plist::Value::Data(bytes) => {
            J::String(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        plist::Value::Array(items) => J::Array(items.iter().map(plist_to_json).collect()),
        plist::Value::Dictionary(d) => J::Object(
            d.iter()
                .map(|(k, v)| (k.clone(), plist_to_json(v)))
                .collect(),
        ),
        _ => J::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::{EmitOptions, emit};
    use crate::types::Platform;
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

    /// The case §8 left open: an operator key with dots survives, because
    /// it is never split. The key here is the macOS composed identifier —
    /// dots, spaces and braces — which is both what the macOS target
    /// requires and a harder round trip than a bare bundle ID.
    #[test]
    fn declaration_round_trips_including_a_dotted_operator_key() {
        let r = reg();
        let key = "us.zoom.xos {anchor apple generic}";
        let values = json!({"Privacy": {"PermissionDefaults": {
            key: {"Camera": "Allow", "OrganizationJustification": "Calls"}}}});
        let docs = emit(
            &r,
            "com.apple.configuration.app.settings",
            &values,
            &opts("p"),
        )
        .unwrap();
        assert_eq!(docs.len(), 1);
        let parsed = parse(&r, docs[0].body.as_bytes(), &Target::default()).unwrap();
        assert_eq!(parsed.len(), 1);
        let p = &parsed[0];
        assert_eq!(p.type_id, "com.apple.configuration.app.settings");
        assert_eq!(p.values, values, "values must come back exactly");
        assert_eq!(
            p.values["Privacy"]["PermissionDefaults"][key]["Camera"],
            "Allow"
        );
        assert_eq!(p.envelope["Identifier"], "com.acme.config.p");
        assert_eq!(p.scope, Some(Scope::User));
        assert!(p.nesting.is_none() && p.root.is_none());
    }

    /// Both halves of a split come back as two parses of the same type; a
    /// caller can merge the `values` objects key by key.
    #[test]
    fn split_declarations_parse_to_the_same_type() {
        let r = reg();
        let values = json!({
            "Privacy": {"PermissionDefaults": {"us.zoom.xos {anchor apple generic}": {"Camera": "Allow", "OrganizationJustification": "x"}}},
            "Allowed": {"AllowedBinaries": [{"TeamID": "BJ4HAAB9B3", "SigningID": "us.zoom.xos"}]}});
        let docs = emit(
            &r,
            "com.apple.configuration.app.settings",
            &values,
            &opts("p"),
        )
        .unwrap();
        assert_eq!(docs.len(), 2);
        let mut merged = serde_json::Map::new();
        for d in &docs {
            let p = parse(&r, d.body.as_bytes(), &Target::default())
                .unwrap()
                .remove(0);
            assert_eq!(p.type_id, "com.apple.configuration.app.settings");
            merged.extend(p.values.as_object().unwrap().clone());
        }
        assert_eq!(serde_json::Value::Object(merged), values);
    }

    #[test]
    fn direct_profile_round_trips_and_separates_the_envelope() {
        let r = reg();
        let values = json!({"SSID_STR": "corp", "EncryptionType": "WPA2", "AutoJoin": true});
        let docs = emit(&r, "com.apple.wifi.managed", &values, &opts("wifi")).unwrap();
        let parsed = parse(&r, docs[0].body.as_bytes(), &Target::default()).unwrap();
        assert_eq!(parsed.len(), 1);
        let p = &parsed[0];
        assert_eq!(p.type_id, "com.apple.wifi.managed");
        assert_eq!(p.values, values);
        assert_eq!(p.nesting, Some(Nesting::Direct));
        assert_eq!(p.envelope["PayloadIdentifier"], "com.acme.wifi.payload");
        assert!(!p.values.as_object().unwrap().contains_key("PayloadUUID"));
        let root = p.root.as_ref().unwrap();
        assert_eq!(root["PayloadIdentifier"], "com.acme.wifi");
        assert_eq!(root["PayloadScope"], "System");
    }

    #[test]
    fn mcx_profile_is_unwrapped_to_its_domain() {
        // Round-trips a community-only domain.
        let r = reg();
        let values = json!({"antivirusEngine": {"enforcementLevel": "real_time"}});
        let docs = emit(&r, "com.microsoft.wdav", &values, &opts("defender")).unwrap();
        let parsed = parse(&r, docs[0].body.as_bytes(), &Target::default()).unwrap();
        assert_eq!(parsed.len(), 1);
        let p = &parsed[0];
        assert_eq!(
            p.type_id, "com.microsoft.wdav",
            "the domain, not the MCX wrapper"
        );
        assert_eq!(p.values, values);
        assert_eq!(p.nesting, Some(Nesting::McxWrapped));
        assert_eq!(p.envelope["PayloadType"], MCX_TYPE);
    }

    #[test]
    fn data_and_date_come_back_as_strings() {
        let mut d = plist::Dictionary::new();
        d.insert("blob".into(), plist::Value::Data(vec![1, 2, 3]));
        assert_eq!(plist_to_json(&plist::Value::Dictionary(d))["blob"], "AQID");
    }

    #[test]
    fn garbage_is_named_not_guessed() {
        let r = reg();
        assert!(matches!(
            parse(&r, b"hello", &Target::default()),
            Err(ParseError::Unrecognised)
        ));
        assert!(matches!(
            parse(&r, b"{\"Payload\": {}}", &Target::default()),
            Err(ParseError::MissingType)
        ));
        assert!(matches!(
            parse(
                &r,
                b"{\"Type\": \"DeviceLock\", \"Payload\": {}}",
                &Target::default()
            ),
            Err(ParseError::Form(FormError::NotAuthorable { .. }))
        ));
    }
}
