//! Profile normalization utilities
#![allow(dead_code, reason = "module under development")]

use super::{ConfigurationProfile, PayloadContent};
use anyhow::Result;
use std::sync::LazyLock;

#[derive(Debug)]
pub struct NormalizerConfig {
    pub org_domain: Option<String>,
    pub org_name: Option<String>,
    pub naming_convention: NamingConvention,
}

#[derive(Debug)]
pub enum NamingConvention {
    OrgDomainPrefix,
    Custom(String),
}

pub fn normalize_profile(
    profile: &mut ConfigurationProfile,
    config: &NormalizerConfig,
) -> Result<()> {
    if let Some(org_domain) = &config.org_domain {
        normalize_identifier(&mut profile.payload_identifier, org_domain);

        for content in &mut profile.payload_content {
            normalize_payload_content(content, org_domain)?;
        }
    }

    // Normalize PayloadOrganization if org_name is provided
    if let Some(org_name) = &config.org_name {
        profile.set_payload_organization(Some(org_name.clone()));

        for content in &mut profile.payload_content {
            content.set_payload_organization(Some(org_name.clone()));
        }
    }

    sanitize_display_name(&mut profile.payload_display_name);

    Ok(())
}

fn normalize_identifier(identifier: &mut String, org_domain: &str) {
    if !identifier.starts_with(org_domain) {
        let clean_identifier = extract_identifier_name(identifier);
        *identifier = format!("{org_domain}.{clean_identifier}");
    }
}

fn normalize_payload_content(content: &mut PayloadContent, org_domain: &str) -> Result<()> {
    normalize_identifier(&mut content.payload_identifier, org_domain);
    Ok(())
}

fn extract_identifier_name(identifier: &str) -> String {
    let parts: Vec<&str> = identifier.rsplitn(2, '.').collect();
    let name = if parts.len() > 1 {
        parts[0].to_string()
    } else {
        identifier.to_string()
    };
    sanitize_identifier_name(&name)
}

/// Sanitize an identifier name to be valid for PayloadIdentifier.
/// Removes spaces and special characters, keeping only alphanumeric, hyphen, underscore.
fn sanitize_identifier_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

fn sanitize_display_name(name: &mut String) {
    static RE_INVALID_CHARS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"[^a-zA-Z0-9\s\-_.]").expect("invariant: hardcoded regex is valid")
    });
    static RE_MULTI_SPACES: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"\s+").expect("invariant: hardcoded regex is valid"));

    *name = RE_INVALID_CHARS.replace_all(name, "").to_string();

    *name = name.trim().to_string();

    *name = RE_MULTI_SPACES.replace_all(name, " ").to_string();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_identifier_name() {
        assert_eq!(extract_identifier_name("com.example.profile"), "profile");
        assert_eq!(extract_identifier_name("profile"), "profile");
        // Spaces should be removed
        assert_eq!(
            extract_identifier_name("com.example.Block AirDrop"),
            "BlockAirDrop"
        );
        assert_eq!(extract_identifier_name("new.Block AirDrop"), "BlockAirDrop");
    }

    #[test]
    fn test_sanitize_identifier_name() {
        assert_eq!(sanitize_identifier_name("BlockAirDrop"), "BlockAirDrop");
        assert_eq!(sanitize_identifier_name("Block AirDrop"), "BlockAirDrop");
        assert_eq!(sanitize_identifier_name("Block-AirDrop"), "Block-AirDrop");
        assert_eq!(sanitize_identifier_name("Block_AirDrop"), "Block_AirDrop");
        assert_eq!(sanitize_identifier_name("Block!@#AirDrop"), "BlockAirDrop");
    }

    #[test]
    fn test_sanitize_display_name() {
        let mut name = "Test Profile!@#$%".to_string();
        sanitize_display_name(&mut name);
        assert_eq!(name, "Test Profile");
    }

    /// Byte-stable serialization is the contract that `profile plan`
    /// relies on: re-running normalize on already-normalized output must
    /// produce byte-identical XML. If it doesn't, plan can't tell a
    /// real change from `BTreeMap`/HashMap iteration noise.
    ///
    /// This guards the BTreeMap swap on `additional_fields` and `content`.
    /// Any future field added to ConfigurationProfile or PayloadContent
    /// that uses HashMap will break this test on the first iteration.
    #[test]
    fn normalize_is_byte_deterministic_round_trip() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>com.acme.test</string>
    <key>PayloadUUID</key>
    <string>11111111-2222-3333-4444-555555555555</string>
    <key>PayloadDisplayName</key>
    <string>Test</string>
    <key>PayloadOrganization</key>
    <string>Acme</string>
    <key>PayloadDescription</key>
    <string>desc</string>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.applicationaccess</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.acme.test.access</string>
            <key>PayloadUUID</key>
            <string>AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE</string>
            <key>allowAirDrop</key>
            <false/>
            <key>allowAssistant</key>
            <true/>
            <key>allowBookstore</key>
            <true/>
            <key>allowExplicitContent</key>
            <false/>
        </dict>
    </array>
</dict>
</plist>
"#;
        let cfg = NormalizerConfig {
            org_domain: Some("com.acme".to_string()),
            org_name: Some("Acme".to_string()),
            naming_convention: NamingConvention::OrgDomainPrefix,
        };

        // Parse → normalize → serialize → parse → normalize → serialize.
        // The two serializations must be byte-identical.
        let mut prof_a: ConfigurationProfile = plist::from_bytes(xml.as_bytes()).expect("parse 1");
        normalize_profile(&mut prof_a, &cfg).expect("normalize 1");
        let mut buf_a = Vec::new();
        plist::to_writer_xml(&mut buf_a, &prof_a).expect("serialize 1");

        let mut prof_b: ConfigurationProfile = plist::from_bytes(&buf_a).expect("parse 2");
        normalize_profile(&mut prof_b, &cfg).expect("normalize 2");
        let mut buf_b = Vec::new();
        plist::to_writer_xml(&mut buf_b, &prof_b).expect("serialize 2");

        assert_eq!(
            buf_a, buf_b,
            "normalize must be byte-deterministic: a profile that has \
                 already been normalized must serialize identically on a \
                 second pass. If this fails, plan/diff cannot trust round-trip \
                 stability — usually means a HashMap leaked into a payload \
                 field somewhere."
        );

        // Run a third time to catch any second-iteration drift.
        let mut prof_c: ConfigurationProfile = plist::from_bytes(&buf_b).expect("parse 3");
        normalize_profile(&mut prof_c, &cfg).expect("normalize 3");
        let mut buf_c = Vec::new();
        plist::to_writer_xml(&mut buf_c, &prof_c).expect("serialize 3");
        assert_eq!(buf_b, buf_c, "third pass must also be stable");

        // Stronger check: assert keys in `additional_fields` and inner
        // `content` actually come out alphabetically. HashMap-iteration
        // order is *stable within a process*, so the round-trip check
        // alone wouldn't catch a regression that keeps HashMap. This
        // explicit ordering check would.
        let xml_str = String::from_utf8(buf_a.clone()).expect("utf-8");
        // PayloadOrganization appears twice in the output (inner content
        // + outer additional_fields); rfind grabs the outer one.
        let desc_pos = xml_str
            .rfind("<key>PayloadDescription</key>")
            .expect("desc key present");
        let org_pos = xml_str
            .rfind("<key>PayloadOrganization</key>")
            .expect("org key present");
        assert!(
            desc_pos < org_pos,
            "additional_fields must serialize alphabetically — \
                 expected PayloadDescription before PayloadOrganization. \
                 If this fails, the field switched back to HashMap."
        );

        let aa = xml_str.find("<key>allowAirDrop</key>").expect("aa");
        let ab = xml_str.find("<key>allowAssistant</key>").expect("ab");
        let ac = xml_str.find("<key>allowBookstore</key>").expect("ac");
        let ad = xml_str.find("<key>allowExplicitContent</key>").expect("ad");
        assert!(
            aa < ab && ab < ac && ac < ad,
            "PayloadContent[0].content must serialize alphabetically"
        );
    }
}
