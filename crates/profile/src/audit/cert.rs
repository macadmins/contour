//! Certificate classification by decoding the embedded DER bytes.
//!
//! Given the raw certificate bytes from a `com.apple.security.*` payload,
//! [`classify_der`] extracts subject/issuer common names, validity, CA status,
//! and serial, and decides whether the certificate is a self-signed root, an
//! intermediate CA, or a leaf.

use serde::Serialize;

/// Where a certificate sits in a PKI hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CertKind {
    /// Self-signed (subject == issuer).
    Root,
    /// A CA certificate that is not self-signed.
    Intermediate,
    /// An end-entity certificate (not a CA).
    Leaf,
    /// A PKCS#12 identity container (cert + private key); not DER-classified.
    Identity,
}

/// Decoded summary of a single certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertInfo {
    pub kind: CertKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_cn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_cn: Option<String>,
    pub self_signed: bool,
    pub is_ca: bool,
    /// Expiry as an RFC3339 timestamp, when decodable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    pub expired: bool,
    /// Serial number as uppercase colon-separated hex (e.g. `0A:1B:2C`).
    pub serial: String,
}

/// Classify a DER-encoded X.509 certificate.
///
/// Returns `None` when `der` is not a parseable certificate; callers fall back
/// to a payload-type-only classification and warn.
pub fn classify_der(der: &[u8]) -> Option<CertInfo> {
    use cms::cert::x509::Certificate;
    use cms::cert::x509::der::Decode;

    let cert = Certificate::from_der(der).ok()?;
    let tbs = &cert.tbs_certificate;

    let subject_cn = common_name(&tbs.subject);
    let issuer_cn = common_name(&tbs.issuer);
    let self_signed = tbs.subject == tbs.issuer;
    let is_ca = is_ca_cert(tbs);

    let (not_after, expired) = validity(tbs);
    let serial = colon_hex(tbs.serial_number.as_bytes());

    let kind = if self_signed {
        CertKind::Root
    } else if is_ca {
        CertKind::Intermediate
    } else {
        CertKind::Leaf
    };

    Some(CertInfo {
        kind,
        subject_cn,
        issuer_cn,
        self_signed,
        is_ca,
        not_after,
        expired,
        serial,
    })
}

/// Extract the first Common Name (OID 2.5.4.3) from a distinguished name.
fn common_name(name: &cms::cert::x509::name::Name) -> Option<String> {
    use cms::cert::x509::der::asn1::{Ia5StringRef, PrintableStringRef, Utf8StringRef};
    use cms::cert::x509::der::oid::ObjectIdentifier;

    // 2.5.4.3 = id-at-commonName.
    const CN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

    for rdn in &name.0 {
        for atv in rdn.0.iter() {
            if atv.oid != CN_OID {
                continue;
            }
            // CN can be encoded as UTF8String, PrintableString, or IA5String.
            if let Ok(s) = atv.value.decode_as::<Utf8StringRef>() {
                return Some(s.as_str().to_owned());
            }
            if let Ok(s) = atv.value.decode_as::<PrintableStringRef>() {
                return Some(s.as_str().to_owned());
            }
            if let Ok(s) = atv.value.decode_as::<Ia5StringRef>() {
                return Some(s.as_str().to_owned());
            }
        }
    }
    None
}

/// Whether the certificate's BasicConstraints extension marks it as a CA.
fn is_ca_cert(tbs: &cms::cert::x509::TbsCertificate) -> bool {
    use cms::cert::x509::der::Decode;
    use cms::cert::x509::ext::pkix::BasicConstraints;

    // 2.5.29.19 = id-ce-basicConstraints.
    const BC_OID: cms::cert::x509::der::oid::ObjectIdentifier =
        cms::cert::x509::der::oid::ObjectIdentifier::new_unwrap("2.5.29.19");

    let Some(exts) = tbs.extensions.as_ref() else {
        return false;
    };
    for ext in exts {
        if ext.extn_id == BC_OID
            && let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes())
        {
            return bc.ca;
        }
    }
    false
}

/// Returns `(not_after_rfc3339, expired)` for the certificate validity window.
fn validity(tbs: &cms::cert::x509::TbsCertificate) -> (Option<String>, bool) {
    let secs = tbs.validity.not_after.to_unix_duration().as_secs();
    match chrono::DateTime::from_timestamp(secs as i64, 0) {
        Some(dt) => {
            let expired = dt < chrono::Utc::now();
            (Some(dt.to_rfc3339()), expired)
        }
        None => (None, false),
    }
}

/// Format bytes as uppercase colon-separated hex (e.g. `0A:1B:2C`).
fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_DER: &[u8] = include_bytes!("../../tests/fixtures/audit/certs/root.der");
    const INT_DER: &[u8] = include_bytes!("../../tests/fixtures/audit/certs/int.der");
    const LEAF_DER: &[u8] = include_bytes!("../../tests/fixtures/audit/certs/leaf.der");

    #[test]
    fn self_signed_cert_is_root() {
        let info = classify_der(ROOT_DER).expect("root parses");
        assert_eq!(info.kind, CertKind::Root);
        assert!(info.self_signed);
        assert!(info.is_ca);
        assert_eq!(info.subject_cn.as_deref(), Some("Acme Root CA"));
        assert_eq!(info.issuer_cn.as_deref(), Some("Acme Root CA"));
    }

    #[test]
    fn ca_signed_ca_cert_is_intermediate() {
        let info = classify_der(INT_DER).expect("intermediate parses");
        assert_eq!(info.kind, CertKind::Intermediate);
        assert!(!info.self_signed);
        assert!(info.is_ca);
        assert_eq!(info.subject_cn.as_deref(), Some("Acme Intermediate CA"));
        assert_eq!(info.issuer_cn.as_deref(), Some("Acme Root CA"));
    }

    #[test]
    fn non_ca_cert_is_leaf() {
        let info = classify_der(LEAF_DER).expect("leaf parses");
        assert_eq!(info.kind, CertKind::Leaf);
        assert!(!info.self_signed);
        assert!(!info.is_ca);
        assert_eq!(info.subject_cn.as_deref(), Some("device.acme.example"));
    }

    #[test]
    fn fixtures_have_future_expiry() {
        // All fixtures are minted with multi-year validity.
        let info = classify_der(ROOT_DER).expect("root parses");
        assert!(!info.expired);
        assert!(info.not_after.is_some());
    }

    #[test]
    fn serial_is_colon_hex() {
        let info = classify_der(ROOT_DER).expect("root parses");
        assert!(!info.serial.is_empty());
        assert!(
            info.serial
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':'),
            "serial {} not colon-hex",
            info.serial
        );
    }

    #[test]
    fn garbage_bytes_return_none() {
        assert!(classify_der(b"not a certificate").is_none());
    }
}
