//! Bidirectional cross-reference analysis for a set of profiles.
//!
//! `link` rewrites references; this module only *reports* them, in both
//! directions:
//!
//! - **outgoing** — a Wi-Fi payload's `PayloadCertificateUUID` resolved to the
//!   SCEP/PKCS#12/root payload it names
//! - **incoming** — for a root certificate, every payload that references it
//!
//! The reverse direction is the one that is hard to see by eye: a cert
//! payload's own content says nothing about who depends on it, so deleting or
//! re-identifying it silently breaks the referrer.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::profile::ConfigurationProfile;

use super::extractor::extract_references;

/// One resolved (or dangling) cross-reference.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ResolvedLink {
    /// File holding the payload that carries the reference.
    pub from_file: String,
    /// UUID of the referring payload.
    pub from_payload_uuid: String,
    /// The field the reference lives in (`PayloadCertificateUUID`, …).
    pub field: String,
    /// The referenced UUID.
    pub to_uuid: String,
    /// Payload type of the target, when it resolves.
    pub to_payload_type: Option<String>,
    /// File holding the target, when it resolves.
    pub to_file: Option<String>,
}

impl ResolvedLink {
    /// True when the referenced UUID matches no payload in the scanned set.
    pub fn is_dangling(&self) -> bool {
        self.to_payload_type.is_none()
    }
}

/// What references a given referenceable payload (the reverse index).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IncomingLinks {
    /// UUID of the referenced payload (a cert/identity).
    pub payload_uuid: String,
    /// Its payload type.
    pub payload_type: String,
    /// File it lives in.
    pub file: String,
    /// Referring payload UUIDs, with the field that names them.
    pub referenced_by: Vec<(String, String)>,
}

/// Both directions of the reference graph across a scanned profile set.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LinkAnalysis {
    /// Every reference found, resolved where possible.
    pub links: Vec<ResolvedLink>,
    /// Referenceable payloads and who points at them. Includes entries with
    /// no referrers — an unreferenced cert is worth seeing too.
    pub incoming: Vec<IncomingLinks>,
}

impl LinkAnalysis {
    /// True when nothing in the set references anything.
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// References whose target is not present in the scanned set.
    pub fn dangling(&self) -> Vec<&ResolvedLink> {
        self.links.iter().filter(|l| l.is_dangling()).collect()
    }

    /// Referenceable payloads nothing points at.
    pub fn unreferenced(&self) -> Vec<&IncomingLinks> {
        self.incoming
            .iter()
            .filter(|i| i.referenced_by.is_empty())
            .collect()
    }
}

/// Build the bidirectional reference graph for a set of parsed profiles.
pub fn analyze_links(profiles: &[(PathBuf, ConfigurationProfile)]) -> LinkAnalysis {
    let (references, referenceables) = extract_references(profiles);

    // uuid → (payload_type, file)
    let targets: BTreeMap<&str, (&str, String)> = referenceables
        .iter()
        .map(|r| {
            (
                r.payload_uuid.as_str(),
                (
                    r.payload_type.as_str(),
                    r.source_profile.display().to_string(),
                ),
            )
        })
        .collect();

    let links: Vec<ResolvedLink> = references
        .iter()
        .map(|r| {
            let target = targets.get(r.referenced_uuid.as_str());
            ResolvedLink {
                from_file: r.source_profile.display().to_string(),
                from_payload_uuid: r.source_payload_uuid.clone(),
                field: r.field_name.clone(),
                to_uuid: r.referenced_uuid.clone(),
                to_payload_type: target.map(|(t, _)| (*t).to_string()),
                to_file: target.map(|(_, f)| f.clone()),
            }
        })
        .collect();

    let incoming: Vec<IncomingLinks> = referenceables
        .iter()
        .map(|target| IncomingLinks {
            payload_uuid: target.payload_uuid.clone(),
            payload_type: target.payload_type.clone(),
            file: target.source_profile.display().to_string(),
            referenced_by: references
                .iter()
                .filter(|r| r.referenced_uuid == target.payload_uuid)
                .map(|r| (r.source_payload_uuid.clone(), r.field_name.clone()))
                .collect(),
        })
        .collect();

    LinkAnalysis { links, incoming }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::PayloadContent;
    use std::collections::BTreeMap as Map;

    fn payload(ptype: &str, uuid: &str, content: Map<String, plist::Value>) -> PayloadContent {
        PayloadContent {
            payload_type: ptype.to_string(),
            payload_version: 1,
            payload_identifier: format!("{ptype}.id"),
            payload_uuid: uuid.to_string(),
            content,
        }
    }

    fn profile(name: &str, payloads: Vec<PayloadContent>) -> (PathBuf, ConfigurationProfile) {
        (
            PathBuf::from(name),
            ConfigurationProfile {
                payload_type: "Configuration".to_string(),
                payload_version: 1,
                payload_identifier: "com.acme.p".to_string(),
                payload_uuid: format!("{name}-ENVELOPE"),
                payload_display_name: name.to_string(),
                payload_content: payloads,
                additional_fields: Map::new(),
            },
        )
    }

    /// A Wi-Fi payload naming a root certificate must be reported in BOTH
    /// directions: outgoing from the Wi-Fi payload, and incoming on the cert.
    #[test]
    fn reports_both_directions_for_a_root_certificate() {
        let cert = payload("com.apple.security.root", "CERT-UUID", Map::new());
        let mut wifi_content = Map::new();
        wifi_content.insert(
            "PayloadCertificateAnchorUUID".to_string(),
            plist::Value::Array(vec![plist::Value::String("CERT-UUID".into())]),
        );
        let wifi = payload("com.apple.wifi.managed", "WIFI-UUID", wifi_content);

        let analysis = analyze_links(&[profile("corp.mobileconfig", vec![cert, wifi])]);

        // Outgoing: Wi-Fi → cert, resolved to the target's type.
        let link = analysis
            .links
            .iter()
            .find(|l| l.from_payload_uuid == "WIFI-UUID")
            .expect("outgoing link from the Wi-Fi payload");
        assert_eq!(link.to_uuid, "CERT-UUID");
        assert_eq!(
            link.to_payload_type.as_deref(),
            Some("com.apple.security.root")
        );
        assert_eq!(link.field, "PayloadCertificateAnchorUUID");
        assert!(!link.is_dangling());

        // Incoming: the cert knows who depends on it — the direction you
        // cannot see by reading the cert payload itself.
        let inc = analysis
            .incoming
            .iter()
            .find(|i| i.payload_uuid == "CERT-UUID")
            .expect("incoming entry for the certificate");
        assert_eq!(inc.payload_type, "com.apple.security.root");
        assert_eq!(inc.referenced_by.len(), 1);
        assert_eq!(inc.referenced_by[0].0, "WIFI-UUID");
        assert!(analysis.unreferenced().is_empty());
    }

    /// Links spanning two files resolve across the scanned set — the case
    /// that matters when certs live in their own profile.
    #[test]
    fn resolves_links_across_files() {
        let cert = payload("com.apple.security.pkcs12", "ID-UUID", Map::new());
        let mut vpn_content = Map::new();
        vpn_content.insert(
            "PayloadCertificateUUID".to_string(),
            plist::Value::String("ID-UUID".into()),
        );
        let vpn = payload("com.apple.vpn.managed", "VPN-UUID", vpn_content);

        let analysis = analyze_links(&[
            profile("certs.mobileconfig", vec![cert]),
            profile("vpn.mobileconfig", vec![vpn]),
        ]);

        let link = &analysis.links[0];
        assert_eq!(link.from_file, "vpn.mobileconfig");
        assert_eq!(link.to_file.as_deref(), Some("certs.mobileconfig"));
        assert!(!link.is_dangling());
    }

    /// A reference to a UUID nothing provides is the silent-failure case —
    /// the profile installs and never authenticates.
    #[test]
    fn flags_dangling_references() {
        let mut wifi_content = Map::new();
        wifi_content.insert(
            "PayloadCertificateUUID".to_string(),
            plist::Value::String("MISSING-UUID".into()),
        );
        let wifi = payload("com.apple.wifi.managed", "WIFI-UUID", wifi_content);

        let analysis = analyze_links(&[profile("wifi.mobileconfig", vec![wifi])]);
        assert_eq!(analysis.dangling().len(), 1);
        assert_eq!(analysis.dangling()[0].to_uuid, "MISSING-UUID");
        assert!(analysis.dangling()[0].to_payload_type.is_none());
    }

    /// A certificate nothing references is surfaced too — often a leftover,
    /// or a sign the referrer lives outside the scanned set.
    #[test]
    fn reports_unreferenced_certificates() {
        let cert = payload("com.apple.security.root", "LONELY", Map::new());
        let analysis = analyze_links(&[profile("certs.mobileconfig", vec![cert])]);
        assert!(analysis.is_empty(), "no references at all");
        assert_eq!(analysis.unreferenced().len(), 1);
        assert_eq!(analysis.unreferenced()[0].payload_uuid, "LONELY");
    }
}
