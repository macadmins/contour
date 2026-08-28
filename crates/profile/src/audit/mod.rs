//! Content/security classification of configuration-profile payloads.
//!
//! Powers `contour profile audit`: detects embedded binary blobs (fonts,
//! certs), classifies certificate payloads (root/intermediate/leaf/identity)
//! by parsing their DER, and flags secrets (schema-sensitive fields, known
//! credential field names, embedded private keys, MDM deploy-time variables,
//! and high-entropy literals).

pub mod cert;
pub mod entropy;
pub mod route;
pub mod sensitive;

use std::collections::BTreeSet;

use serde::Serialize;

use crate::mdm_vars::{self, MdmFlavour};
use crate::profile::PayloadContent;
use crate::schema::SchemaRegistry;

use cert::CertInfo;

/// Apple payload type that installs a trusted root certificate.
const PT_ROOT: &str = "com.apple.security.root";
/// Apple payload type for a PEM/DER certificate.
const PT_PEM: &str = "com.apple.security.pem";
/// Apple payload type for a DER (PKCS#1) certificate.
const PT_PKCS1: &str = "com.apple.security.pkcs1";
/// Apple payload type for a PKCS#12 identity (cert + private key).
const PT_PKCS12: &str = "com.apple.security.pkcs12";

/// Embedded binary content found in a payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryInfo {
    pub present: bool,
    /// Top-level field keys that hold (or nest) `<data>` blobs.
    pub fields: Vec<String>,
    /// Total bytes across all embedded blobs.
    pub bytes: usize,
}

/// How a secret was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// Field marked `sensitive` by the embedded schema.
    SchemaSensitive,
    /// Field name matches a well-known credential pattern.
    KnownSensitive,
    /// PKCS#12 payload carrying an embedded private key.
    PrivateKey,
    /// Value references an MDM deploy-time variable.
    DeployVar,
    /// Value looks like an embedded high-entropy literal credential.
    HighEntropyLiteral,
}

/// A single secret finding within a payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SecretFinding {
    pub field: String,
    pub kind: SecretKind,
    /// The matched deploy-time token, for [`SecretKind::DeployVar`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Shannon entropy, for [`SecretKind::HighEntropyLiteral`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
}

/// Audit result for a single payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PayloadAudit {
    pub index: usize,
    pub r#type: String,
    pub identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub binary: BinaryInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<CertInfo>,
    pub secrets: Vec<SecretFinding>,
}

impl PayloadAudit {
    /// True when this payload carries a certificate (any kind).
    pub fn is_cert(&self) -> bool {
        self.cert.is_some()
    }

    /// True when this payload has embedded binary content that is not a cert.
    pub fn is_noncert_binary(&self) -> bool {
        self.binary.present && self.cert.is_none()
    }

    /// True when this payload has any secret finding.
    pub fn has_secrets(&self) -> bool {
        !self.secrets.is_empty()
    }
}

/// Audit result for a whole profile.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProfileAudit {
    pub path: String,
    pub display_name: String,
    pub identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    pub signed: bool,
    pub payloads: Vec<PayloadAudit>,
}

impl ProfileAudit {
    /// True when any payload carries a certificate.
    pub fn has_certs(&self) -> bool {
        self.payloads.iter().any(PayloadAudit::is_cert)
    }

    /// True when any payload has a secret finding.
    pub fn has_secrets(&self) -> bool {
        self.payloads.iter().any(PayloadAudit::has_secrets)
    }

    /// True when any payload has embedded binary content that is not a cert.
    pub fn has_noncert_binary(&self) -> bool {
        self.payloads.iter().any(PayloadAudit::is_noncert_binary)
    }
}

/// Audit a single profile file, transparently unsigning a signed profile first.
///
/// # Errors
/// Returns an error if the file cannot be read or parsed as a configuration
/// profile.
pub fn audit_profile(path: &std::path::Path) -> anyhow::Result<ProfileAudit> {
    use anyhow::Context as _;

    let signed = crate::signing::is_signed_profile(path).unwrap_or(false);
    let path_str = path.to_string_lossy();
    let profile = crate::profile::parser::parse_profile_auto_unsign(&path_str)
        .with_context(|| format!("Failed to parse profile: {}", path.display()))?;
    let registry = SchemaRegistry::embedded().context("Failed to load embedded schema")?;

    let organization = profile
        .additional_fields
        .get("PayloadOrganization")
        .and_then(plist::Value::as_string)
        .map(str::to_string);

    let payloads = profile
        .payload_content
        .iter()
        .enumerate()
        .map(|(i, p)| classify_payload(i, p, &registry))
        .collect();

    Ok(ProfileAudit {
        path: path_str.into_owned(),
        display_name: profile.payload_display_name.clone(),
        identifier: profile.payload_identifier.clone(),
        organization,
        signed,
        payloads,
    })
}

/// Classify a single payload's binary content, certificate, and secrets.
pub fn classify_payload(
    index: usize,
    payload: &PayloadContent,
    registry: &SchemaRegistry,
) -> PayloadAudit {
    let ptype = payload.payload_type.as_str();

    // --- Binary blobs + string values (recursive, attributed to top-level key) ---
    let mut data_keys = BTreeSet::new();
    let mut data_bytes = 0usize;
    let mut strings: Vec<(String, String)> = Vec::new();
    for (key, value) in &payload.content {
        walk_value(key, value, &mut data_bytes, &mut data_keys, &mut strings);
    }
    let binary = BinaryInfo {
        present: !data_keys.is_empty(),
        fields: data_keys.into_iter().collect(),
        bytes: data_bytes,
    };

    // --- Certificate ---
    let cert = classify_cert_payload(ptype, &payload.content);

    // --- Secrets ---
    let mut secrets: Vec<SecretFinding> = Vec::new();
    let mut flagged_fields: BTreeSet<String> = BTreeSet::new();

    // 1. schema_sensitive — schema marks the field sensitive (0 fields today).
    if let Some(manifest) = registry.get(ptype) {
        for (name, def) in &manifest.fields {
            if def.flags.sensitive && payload.content.contains_key(name) {
                secrets.push(SecretFinding {
                    field: name.clone(),
                    kind: SecretKind::SchemaSensitive,
                    token: None,
                    entropy: None,
                });
                flagged_fields.insert(name.clone());
            }
        }
    }

    // 2. known_sensitive — well-known credential field name with a non-empty value.
    for (key, value) in &payload.content {
        if sensitive::is_known_sensitive_name(key) && value_is_non_empty(value) {
            secrets.push(SecretFinding {
                field: key.clone(),
                kind: SecretKind::KnownSensitive,
                token: None,
                entropy: None,
            });
            flagged_fields.insert(key.clone());
        }
    }

    // 3. private_key — PKCS#12 carries an embedded private key.
    if ptype == PT_PKCS12 {
        secrets.push(SecretFinding {
            field: "PayloadContent".to_string(),
            kind: SecretKind::PrivateKey,
            token: None,
            entropy: None,
        });
        flagged_fields.insert("PayloadContent".to_string());
    }

    // 4. deploy_var — value references an MDM deploy-time variable.
    for (field, value) in &strings {
        for token in deploy_tokens(value) {
            secrets.push(SecretFinding {
                field: field.clone(),
                kind: SecretKind::DeployVar,
                token: Some(token),
                entropy: None,
            });
            flagged_fields.insert(field.clone());
        }
    }

    // 5. high_entropy_literal — last resort on values nothing else claimed.
    // Skipped for public-certificate payload types: their content IS long
    // opaque base64 by design (already surfaced via the cert/binary
    // classification above), and flagging it as a secret buries real
    // findings in noise. PKCS#12 is NOT exempt — it carries a private key
    // and is claimed by check 3.
    let is_public_cert_payload = matches!(ptype, PT_ROOT | PT_PEM | PT_PKCS1);
    if !is_public_cert_payload {
        for (field, value) in &strings {
            if flagged_fields.contains(field) {
                continue;
            }
            if entropy::looks_like_secret(value) {
                secrets.push(SecretFinding {
                    field: field.clone(),
                    kind: SecretKind::HighEntropyLiteral,
                    token: None,
                    entropy: Some(entropy::shannon_entropy(value)),
                });
            }
        }
    }

    PayloadAudit {
        index,
        r#type: payload.payload_type.clone(),
        identifier: payload.payload_identifier.clone(),
        display_name: payload.payload_display_name(),
        binary,
        cert,
        secrets,
    }
}

/// Classify the certificate carried by a `com.apple.security.*` payload, if any.
fn classify_cert_payload(
    ptype: &str,
    content: &std::collections::BTreeMap<String, plist::Value>,
) -> Option<CertInfo> {
    match ptype {
        PT_PKCS12 => Some(CertInfo {
            kind: cert::CertKind::Identity,
            subject_cn: None,
            issuer_cn: None,
            self_signed: false,
            is_ca: false,
            not_after: None,
            expired: false,
            serial: String::new(),
        }),
        PT_ROOT | PT_PEM | PT_PKCS1 => {
            let der = cert_der_bytes(content)?;
            cert::classify_der(&der)
        }
        _ => None,
    }
}

/// Extract DER bytes from a cert payload's `PayloadContent`, decoding PEM armor
/// if the value is text rather than raw `<data>`.
fn cert_der_bytes(content: &std::collections::BTreeMap<String, plist::Value>) -> Option<Vec<u8>> {
    match content.get("PayloadContent")? {
        plist::Value::Data(bytes) => Some(bytes.clone()),
        plist::Value::String(s) if s.contains("-----BEGIN CERTIFICATE-----") => {
            use base64::Engine as _;
            let body: String = s
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<String>();
            base64::engine::general_purpose::STANDARD.decode(body).ok()
        }
        _ => None,
    }
}

/// Union of Fleet and Jamf deploy-time variable tokens found in `s`.
///
/// A Fleet token like `FLEET_VAR_X` also matches Jamf's `$VAR` shape as
/// `$FLEET_VAR_X`; those are deduplicated by ignoring a leading `$`/`%` sigil so
/// the same reference is reported once.
fn deploy_tokens(s: &str) -> Vec<String> {
    let strip = |t: &str| t.trim_start_matches(['$', '%']).to_string();
    let mut tokens = mdm_vars::extract_tokens(s, MdmFlavour::Fleet);
    let mut seen: BTreeSet<String> = tokens.iter().map(|t| strip(t)).collect();
    for t in mdm_vars::extract_tokens(s, MdmFlavour::Jamf) {
        if seen.insert(strip(&t)) {
            tokens.push(t);
        }
    }
    tokens
}

/// Whether a plist value carries a non-empty payload (for sensitive-field gating).
fn value_is_non_empty(v: &plist::Value) -> bool {
    match v {
        plist::Value::String(s) => !s.is_empty(),
        plist::Value::Data(d) => !d.is_empty(),
        _ => true,
    }
}

/// Recursively tally `<data>` bytes and collect string values, attributing each
/// to the top-level `key` it descends from.
fn walk_value(
    key: &str,
    value: &plist::Value,
    data_bytes: &mut usize,
    data_keys: &mut BTreeSet<String>,
    strings: &mut Vec<(String, String)>,
) {
    match value {
        plist::Value::Data(d) => {
            *data_bytes += d.len();
            data_keys.insert(key.to_string());
        }
        plist::Value::String(s) => strings.push((key.to_string(), s.clone())),
        plist::Value::Array(items) => {
            for item in items {
                walk_value(key, item, data_bytes, data_keys, strings);
            }
        }
        plist::Value::Dictionary(dict) => {
            for (_, v) in dict {
                walk_value(key, v, data_bytes, data_keys, strings);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const ROOT_DER: &[u8] = include_bytes!("../../tests/fixtures/audit/certs/root.der");

    fn registry() -> SchemaRegistry {
        SchemaRegistry::embedded().expect("embedded schema")
    }

    fn payload(payload_type: &str, content: BTreeMap<String, plist::Value>) -> PayloadContent {
        PayloadContent {
            payload_type: payload_type.to_string(),
            payload_version: 1,
            payload_identifier: format!("{payload_type}.test"),
            payload_uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            content,
        }
    }

    fn map(pairs: &[(&str, plist::Value)]) -> BTreeMap<String, plist::Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    /// Public-certificate payloads carry base64 cert material by design —
    /// flagging it as a high-entropy secret is noise that buries real
    /// findings. (Real-estate feedback: "110 secrets", mostly this.) The
    /// material is already surfaced via the cert/binary classification.
    #[test]
    fn public_cert_payload_content_is_not_a_high_entropy_secret() {
        // Base64-ish cert body as a string (some profiles store <string>,
        // not <data>): long, high-entropy, would trip looks_like_secret.
        let cert_b64 = "MIIDdzCCAl+gAwIBAgIEbXf4qzANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYQ==";
        for ptype in [
            "com.apple.security.root",
            "com.apple.security.pem",
            "com.apple.security.pkcs1",
        ] {
            let p = payload(
                ptype,
                map(&[("PayloadContent", plist::Value::String(cert_b64.into()))]),
            );
            let a = classify_payload(0, &p, &registry());
            assert!(
                !a.secrets
                    .iter()
                    .any(|s| s.kind == SecretKind::HighEntropyLiteral),
                "{ptype}: expected no high-entropy finding on cert material"
            );
        }
    }

    /// PKCS#12 still reports its private key — that finding is real.
    #[test]
    fn pkcs12_private_key_finding_is_kept() {
        let p = payload(
            "com.apple.security.pkcs12",
            map(&[("PayloadContent", plist::Value::Data(vec![1u8; 64]))]),
        );
        let a = classify_payload(0, &p, &registry());
        assert!(a.secrets.iter().any(|s| s.kind == SecretKind::PrivateKey));
    }

    /// A genuinely suspicious literal in a NON-certificate payload is still
    /// flagged — the cert exemption must not widen.
    #[test]
    fn high_entropy_literal_still_flagged_outside_cert_payloads() {
        let p = payload(
            "com.apple.wifi.managed",
            map(&[(
                "OpaqueSetting",
                plist::Value::String("a3F9b2C1d8E7460aF1029384756bcDeF01928374aa".into()),
            )]),
        );
        let a = classify_payload(0, &p, &registry());
        assert!(
            a.secrets
                .iter()
                .any(|s| s.kind == SecretKind::HighEntropyLiteral),
            "non-cert payloads keep entropy detection"
        );
    }

    #[test]
    fn detects_binary_blob() {
        let p = payload(
            "com.apple.font",
            map(&[("Font", plist::Value::Data(vec![0u8; 2048]))]),
        );
        let a = classify_payload(0, &p, &registry());
        assert!(a.binary.present);
        assert_eq!(a.binary.fields, vec!["Font".to_string()]);
        assert_eq!(a.binary.bytes, 2048);
    }

    #[test]
    fn no_binary_for_plain_payload() {
        let p = payload(
            "com.apple.wifi.managed",
            map(&[("SSID_STR", plist::Value::String("Corp".into()))]),
        );
        let a = classify_payload(0, &p, &registry());
        assert!(!a.binary.present);
        assert!(a.binary.fields.is_empty());
        assert_eq!(a.binary.bytes, 0);
    }

    #[test]
    fn classifies_root_cert_payload() {
        let p = payload(
            PT_ROOT,
            map(&[("PayloadContent", plist::Value::Data(ROOT_DER.to_vec()))]),
        );
        let a = classify_payload(0, &p, &registry());
        let cert = a.cert.expect("cert classified");
        assert_eq!(cert.kind, cert::CertKind::Root);
        assert!(a.binary.present); // the DER itself is a binary blob
    }

    #[test]
    fn pkcs12_is_identity_with_private_key() {
        let p = payload(
            PT_PKCS12,
            map(&[("PayloadContent", plist::Value::Data(vec![1, 2, 3, 4]))]),
        );
        let a = classify_payload(0, &p, &registry());
        let cert = a.cert.expect("identity classified");
        assert_eq!(cert.kind, cert::CertKind::Identity);
        assert!(
            a.secrets.iter().any(|s| s.kind == SecretKind::PrivateKey),
            "pkcs12 should flag a private key, got {:?}",
            a.secrets
        );
    }

    #[test]
    fn flags_known_sensitive_field_name() {
        let p = payload(
            "com.apple.wifi.managed",
            map(&[("Password", plist::Value::String("hunter2".into()))]),
        );
        let a = classify_payload(0, &p, &registry());
        assert!(
            a.secrets
                .iter()
                .any(|s| s.kind == SecretKind::KnownSensitive && s.field == "Password"),
            "expected known_sensitive on Password, got {:?}",
            a.secrets
        );
    }

    #[test]
    fn empty_sensitive_field_is_not_flagged() {
        let p = payload(
            "com.apple.wifi.managed",
            map(&[("Password", plist::Value::String(String::new()))]),
        );
        let a = classify_payload(0, &p, &registry());
        assert!(
            !a.secrets
                .iter()
                .any(|s| s.kind == SecretKind::KnownSensitive),
            "empty Password should not be flagged"
        );
    }

    #[test]
    fn flags_deploy_variable_reference() {
        let p = payload(
            "com.apple.wifi.managed",
            map(&[(
                "Password",
                plist::Value::String("$FLEET_VAR_NDES_SCEP_CHALLENGE".into()),
            )]),
        );
        let a = classify_payload(0, &p, &registry());
        let dv = a
            .secrets
            .iter()
            .find(|s| s.kind == SecretKind::DeployVar)
            .expect("deploy_var finding");
        assert_eq!(dv.field, "Password");
        assert_eq!(dv.token.as_deref(), Some("FLEET_VAR_NDES_SCEP_CHALLENGE"));
    }

    #[test]
    fn audits_sample_profile_end_to_end() {
        let path = std::path::Path::new("tests/fixtures/audit/sample.mobileconfig");
        let audit = audit_profile(path).expect("audit sample profile");

        assert_eq!(audit.display_name, "Audit Sample");
        assert_eq!(audit.organization.as_deref(), Some("Acme"));
        assert!(!audit.signed);
        assert_eq!(audit.payloads.len(), 3);

        // Profile-level buckets.
        assert!(audit.has_certs());
        assert!(audit.has_secrets());
        assert!(audit.has_noncert_binary()); // the font

        // Root cert payload.
        let root = &audit.payloads[0];
        assert_eq!(root.cert.as_ref().unwrap().kind, cert::CertKind::Root);
        assert!(root.binary.present);

        // Wi-Fi payload carries a deploy-var + known-sensitive Password.
        let wifi = &audit.payloads[1];
        assert!(wifi.cert.is_none());
        assert!(wifi.secrets.iter().any(|s| s.kind == SecretKind::DeployVar));
        assert!(
            wifi.secrets
                .iter()
                .any(|s| s.kind == SecretKind::KnownSensitive)
        );

        // Font payload is non-cert binary, no secrets.
        let font = &audit.payloads[2];
        assert!(font.binary.present);
        assert!(font.cert.is_none());
        assert!(font.secrets.is_empty());
    }
}
