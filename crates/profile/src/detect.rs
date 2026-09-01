//! Configuration-format detection.
//!
//! A caller handed a mixed list of device-management files — an MDM server
//! returns mobileconfigs, DDM declarations, Windows CSP documents and Android
//! configs in one collection — cannot route on the file extension: an Android
//! config and a DDM declaration are both `.json`. Only content tells them
//! apart, so contour answers the question itself rather than making every
//! integrator reimplement the sniffing.
//!
//! The detected format drives two things: automatic routing to the right
//! validator, and a refusal that *names the format* instead of leaking a
//! parser's internal error.

use std::path::Path;

/// A recognised (or explicitly unrecognised) configuration format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    /// Apple configuration profile — XML or binary plist.
    Mobileconfig,
    /// Apple DDM declaration — JSON with `Type` + `Identifier` + `Payload`.
    DdmDeclaration,
    /// Windows CSP document — SyncML XML (`<Replace>`, `<Add>`, `<LocURI>`).
    WindowsCspSyncMl,
    /// JSON that is not a DDM declaration (an Android managed config, a
    /// vendor payload, …).
    OtherJson,
    /// XML that is neither a profile nor SyncML.
    OtherXml,
    /// Nothing recognisable.
    Unknown,
}

impl ConfigFormat {
    /// True when contour can parse and validate this format.
    pub fn is_supported(self) -> bool {
        matches!(
            self,
            ConfigFormat::Mobileconfig | ConfigFormat::DdmDeclaration
        )
    }

    /// Human-readable format name, for messages that must say *what this is*.
    pub fn describe(self) -> &'static str {
        match self {
            ConfigFormat::Mobileconfig => "Apple configuration profile (plist)",
            ConfigFormat::DdmDeclaration => "Apple DDM declaration (JSON)",
            ConfigFormat::WindowsCspSyncMl => "Windows CSP document (SyncML XML)",
            ConfigFormat::OtherJson => "JSON, but not a DDM declaration",
            ConfigFormat::OtherXml => "XML, but not an Apple configuration profile",
            ConfigFormat::Unknown => "unrecognised format",
        }
    }

    /// A refusal that names the format and says what to do — never a leaked
    /// parser error. Returns `None` for supported formats.
    pub fn refusal(self) -> Option<String> {
        if self.is_supported() {
            return None;
        }
        Some(match self {
            ConfigFormat::WindowsCspSyncMl => format!(
                "{} — contour reads the Windows CSP *schema* (`profile search --windows`) \
                 but does not parse or validate SyncML documents",
                self.describe()
            ),
            ConfigFormat::OtherJson => format!(
                "{} — a DDM declaration needs Type, Identifier and Payload. Android and \
                 vendor configs are out of scope",
                self.describe()
            ),
            other => format!("{} — contour cannot validate this file", other.describe()),
        })
    }
}

/// Detect the format of `bytes`, using `path` only as a tie-breaker.
///
/// Content wins over extension throughout: an Android managed config and a
/// DDM declaration are both `.json`, and a `.mobileconfig` may be a signed
/// (DER/CMS) blob rather than XML.
pub fn detect_bytes(bytes: &[u8], path: Option<&Path>) -> ConfigFormat {
    // Binary plist and CMS-signed profiles are byte-sniffable.
    if bytes.starts_with(b"bplist00") {
        return ConfigFormat::Mobileconfig;
    }
    // DER SEQUENCE — a signed profile (CMS). Only trust it with the extension.
    if bytes.first() == Some(&0x30)
        && path.is_some_and(|p| p.extension().is_some_and(|e| e == "mobileconfig"))
    {
        return ConfigFormat::Mobileconfig;
    }

    let text = String::from_utf8_lossy(bytes);
    let head: String = text.chars().take(4096).collect();
    let trimmed = head.trim_start();

    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return detect_json(&text);
    }

    if trimmed.starts_with("<?xml") || trimmed.starts_with('<') {
        // SyncML/CSP: LocURI is the giveaway; the verbs alone are too generic.
        let syncml = head.contains("<LocURI>")
            || head.contains("syncml:metinf")
            || (head.contains("<Replace>") && head.contains("<Target>"));
        if syncml {
            return ConfigFormat::WindowsCspSyncMl;
        }
        if head.contains("<!DOCTYPE plist") || head.contains("<plist") {
            return ConfigFormat::Mobileconfig;
        }
        return ConfigFormat::OtherXml;
    }

    ConfigFormat::Unknown
}

/// JSON discrimination: a DDM declaration carries `Type` + `Identifier`
/// (+ usually `Payload`). Anything else is out of scope.
fn detect_json(text: &str) -> ConfigFormat {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return ConfigFormat::OtherJson;
    };
    let Some(obj) = value.as_object() else {
        return ConfigFormat::OtherJson;
    };
    if obj.contains_key("Type") && obj.contains_key("Identifier") {
        ConfigFormat::DdmDeclaration
    } else {
        ConfigFormat::OtherJson
    }
}

/// Detect the format of a file on disk.
///
/// # Errors
/// When the file cannot be read.
pub fn detect_file(path: &Path) -> std::io::Result<ConfigFormat> {
    let bytes = std::fs::read(path)?;
    Ok(detect_bytes(&bytes, Some(path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_xml_mobileconfig() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>PayloadType</key><string>Configuration</string></dict></plist>"#;
        assert_eq!(detect_bytes(xml, None), ConfigFormat::Mobileconfig);
    }

    #[test]
    fn detects_binary_plist() {
        assert_eq!(
            detect_bytes(b"bplist00\x00\x01\x02", None),
            ConfigFormat::Mobileconfig
        );
    }

    /// The integration case: a DDM declaration is `.json`, and must route to
    /// the DDM validator rather than the plist parser.
    #[test]
    fn detects_ddm_declaration() {
        let json = br#"{"Type":"com.apple.configuration.softwareupdate.settings",
                        "Identifier":"com.acme.settings","Payload":{}}"#;
        assert_eq!(detect_bytes(json, None), ConfigFormat::DdmDeclaration);
        assert!(ConfigFormat::DdmDeclaration.is_supported());
    }

    /// The near-miss that extension-based routing gets wrong: an Android
    /// managed config is also `.json`, and must NOT be treated as DDM.
    #[test]
    fn android_style_json_is_not_a_ddm_declaration() {
        let json = br#"{"managedProperty":[{"key":"server_url","valueString":"https://x"}]}"#;
        let format = detect_bytes(json, None);
        assert_eq!(format, ConfigFormat::OtherJson);
        assert!(!format.is_supported());
        let refusal = format.refusal().expect("unsupported formats explain why");
        assert!(refusal.contains("DDM declaration"), "{refusal}");
    }

    /// Windows CSP SyncML — named, not leaked as a serde error.
    #[test]
    fn detects_windows_csp_syncml() {
        let xml = br#"<Replace>
  <Item>
    <Meta><Format xmlns="syncml:metinf">int</Format></Meta>
    <Target><LocURI>./Device/Vendor/MSFT/Policy/Config/Update/X</LocURI></Target>
    <Data>7</Data>
  </Item>
</Replace>"#;
        let format = detect_bytes(xml, None);
        assert_eq!(format, ConfigFormat::WindowsCspSyncMl);
        let refusal = format.refusal().expect("unsupported formats explain why");
        assert!(refusal.contains("Windows CSP"), "{refusal}");
        assert!(
            refusal.contains("--windows"),
            "point at the schema surface that does exist: {refusal}"
        );
    }

    #[test]
    fn malformed_json_is_reported_as_json_not_unknown() {
        assert_eq!(
            detect_bytes(b"{ not really json", None),
            ConfigFormat::OtherJson
        );
    }

    #[test]
    fn supported_formats_have_no_refusal() {
        assert!(ConfigFormat::Mobileconfig.refusal().is_none());
        assert!(ConfigFormat::DdmDeclaration.refusal().is_none());
    }

    #[test]
    fn unknown_content_is_unknown() {
        assert_eq!(detect_bytes(b"just some text", None), ConfigFormat::Unknown);
    }
}
