use super::ConfigurationProfile;
use anyhow::{Context, Result};
use regex::Regex;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use std::process::Command;

/// MDM placeholder pattern: $VAR_NAME, {{var}}, %Var%, {VarName}
/// Matches common patterns across Fleet, Jamf, Mosyle, WS1, Kandji.
fn placeholder_regex() -> Regex {
    Regex::new(r"\$[A-Z][A-Z0-9_]*|\{\{[^}]+\}\}|%[A-Za-z][A-Za-z0-9_]*%|\{[A-Z][A-Za-z0-9_]*\}")
        .expect("invalid placeholder regex")
}

/// Result of scanning and substituting placeholders in profile XML.
#[derive(Debug)]
pub struct PlaceholderResult {
    /// The XML with placeholders replaced by dummy values.
    pub substituted: Vec<u8>,
    /// List of placeholder strings found.
    pub placeholders: Vec<String>,
}

/// Scan XML bytes for MDM placeholders and replace with dummy values.
/// Placeholders inside `<data>` tags get valid base64, others get "PLACEHOLDER".
pub fn substitute_placeholders(xml: &[u8]) -> PlaceholderResult {
    let text = String::from_utf8_lossy(xml);
    let re = placeholder_regex();
    let mut placeholders = Vec::new();

    for m in re.find_iter(&text) {
        let p = m.as_str().to_string();
        if !placeholders.contains(&p) {
            placeholders.push(p);
        }
    }

    if placeholders.is_empty() {
        return PlaceholderResult {
            substituted: xml.to_vec(),
            placeholders,
        };
    }

    // Replace placeholders: inside <data> tags use valid base64, elsewhere use string
    let mut result = text.to_string();
    // First handle <data>PLACEHOLDER</data> — need valid base64
    for p in &placeholders {
        let data_pattern = format!("<data>{p}</data>");
        if result.contains(&data_pattern) {
            result = result.replace(&data_pattern, "<data>UExBQ0VIT0xERVI=</data>");
        }
        // Replace remaining occurrences (in <string> etc.) with text
        result = result.replace(p, "PLACEHOLDER");
    }

    PlaceholderResult {
        substituted: result.into_bytes(),
        placeholders,
    }
}

/// Plist format detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "reserved for future use")]
pub enum PlistFormat {
    Xml,
    Binary,
}

#[allow(dead_code, reason = "reserved for future use")]
impl PlistFormat {
    /// Detect plist format from file
    pub fn detect(path: &str) -> Result<Self> {
        let mut file = File::open(path).with_context(|| format!("Failed to open file: {path}"))?;

        let mut magic = [0u8; 8];
        let bytes_read = file.read(&mut magic)?;

        if bytes_read < 8 {
            anyhow::bail!("File too small to detect format");
        }

        if magic.starts_with(b"bplist") {
            Ok(PlistFormat::Binary)
        } else if magic.starts_with(b"<?xml") || magic.starts_with(b"<plist") {
            Ok(PlistFormat::Xml)
        } else {
            // Check for XML with whitespace/BOM at start
            let content_start = std::str::from_utf8(&magic).unwrap_or("");
            if content_start.trim_start().starts_with('<') {
                Ok(PlistFormat::Xml)
            } else {
                anyhow::bail!("Unknown plist format")
            }
        }
    }
}

pub fn parse_profile(path: &str) -> Result<ConfigurationProfile> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open configuration profile: {path}"))?;

    let reader = BufReader::new(file);

    // plist crate auto-detects binary vs XML format
    let value: plist::Value =
        plist::from_reader(reader).with_context(|| "Failed to parse plist (XML or binary)")?;

    // Try to deserialize, and if it fails, provide detailed error with context
    match plist::from_value(&value) {
        Ok(profile) => Ok(profile),
        Err(e) => {
            let detailed_error = diagnose_profile_structure(&value, &e.to_string());
            anyhow::bail!("{detailed_error}")
        }
    }
}

pub fn write_profile(profile: &ConfigurationProfile, path: &Path) -> Result<()> {
    write_profile_xml(profile, path)
}

/// Write profile as XML plist (default)
pub fn write_profile_xml(profile: &ConfigurationProfile, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create output file: {}", path.display()))?;

    plist::to_writer_xml(file, profile)
        .with_context(|| "Failed to write XML configuration profile")?;

    Ok(())
}

/// Write profile as binary plist
#[allow(dead_code, reason = "reserved for future use")]
pub fn write_profile_binary(profile: &ConfigurationProfile, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create output file: {}", path.display()))?;

    plist::to_writer_binary(file, profile)
        .with_context(|| "Failed to write binary configuration profile")?;

    Ok(())
}

/// Parse profile with format detection, returning the detected format
#[allow(dead_code, reason = "reserved for future use")]
pub fn parse_profile_with_format(path: &str) -> Result<(ConfigurationProfile, PlistFormat)> {
    let format = PlistFormat::detect(path)?;
    let profile = parse_profile(path)?;
    Ok((profile, format))
}

/// Convert profile to XML string
#[allow(dead_code, reason = "reserved for future use")]
pub fn profile_to_xml_string(profile: &ConfigurationProfile) -> Result<String> {
    let mut buffer = Vec::new();
    plist::to_writer_xml(&mut buffer, profile)
        .with_context(|| "Failed to serialize profile to XML")?;
    String::from_utf8(buffer).with_context(|| "Invalid UTF-8 in XML output")
}

/// Convert profile to binary plist bytes
#[allow(dead_code, reason = "reserved for future use")]
pub fn profile_to_binary(profile: &ConfigurationProfile) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    plist::to_writer_binary(&mut buffer, profile)
        .with_context(|| "Failed to serialize profile to binary")?;
    Ok(buffer)
}

/// Parse profile, auto-unsigning if it's a signed PKCS#7 profile
pub fn parse_profile_auto_unsign(path: &str) -> Result<ConfigurationProfile> {
    // Read file data
    let data = fs::read(path).with_context(|| format!("Failed to read file: {path}"))?;

    // Check if it's already an unsigned profile (XML or binary plist)
    if is_xml_profile(&data) || is_binary_plist(&data) {
        return parse_profile(path);
    }

    // Check if it's a signed profile
    if is_signed_profile(&data) {
        // Try to unsign using security cms (macOS)
        if cfg!(target_os = "macos")
            && let Ok(unsigned_data) = unsign_with_security_cms(path)
        {
            return parse_profile_from_bytes(&unsigned_data);
        }

        // Fallback: extract XML manually from PKCS#7 envelope
        let unsigned_data = extract_xml_from_pkcs7(&data)?;
        return parse_profile_from_bytes(&unsigned_data);
    }

    // Unknown format - try parsing anyway for better error message
    parse_profile(path)
}

// ==================== Lenient parsing for normalize ====================

/// Result of lenient parsing: the profile plus any fixups/placeholders that were applied.
#[derive(Debug)]
pub struct FixupResult {
    pub profile: ConfigurationProfile,
    /// Human-readable descriptions of value-level fixups applied (e.g. "added missing PayloadVersion").
    pub fixups: Vec<String>,
    /// MDM placeholder strings that were substituted with dummy values.
    pub placeholders: Vec<String>,
}

/// Fix common issues in a raw `plist::Value` profile tree before deserialization.
///
/// Handles:
/// - Missing `PayloadVersion` in top-level or PayloadContent dicts → insert `Integer(1)`
/// - `PayloadVersion` as `Real` → convert to `Integer`
///
/// Returns a list of human-readable fixup descriptions.
fn fixup_profile_value(value: &mut plist::Value) -> Vec<String> {
    let mut fixups = Vec::new();
    let Some(dict) = value.as_dictionary_mut() else {
        return fixups;
    };

    // Auto-wrap bare payloads (PayloadType != "Configuration") into a Configuration envelope.
    // These are MCX/PPPC payload fragments that MDM servers normally wrap on upload.
    if needs_configuration_wrap(dict) {
        wrap_bare_payload(dict, &mut fixups);
    }

    // Fix top-level PayloadVersion
    fixup_payload_version(dict, "profile level", &mut fixups);

    // Fix top-level PayloadScope
    fixup_payload_scope(dict, "profile level", &mut fixups);

    // Fix PayloadContent items
    if let Some(plist::Value::Array(items)) = dict.get_mut("PayloadContent") {
        for (i, item) in items.iter_mut().enumerate() {
            if let Some(item_dict) = item.as_dictionary_mut() {
                let payload_type = item_dict
                    .get("PayloadType")
                    .and_then(plist::Value::as_string)
                    .unwrap_or("unknown");
                let context = format!("PayloadContent[{i}] ({payload_type})");
                fixup_payload_version(item_dict, &context, &mut fixups);
                fixup_missing_identity(item_dict, &context, &mut fixups);
                fixup_payload_scope(item_dict, &context, &mut fixups);
            }
        }
    }

    fixups
}

/// Check if the top-level dict is a bare payload that needs wrapping.
fn needs_configuration_wrap(dict: &plist::Dictionary) -> bool {
    match dict.get("PayloadType").and_then(plist::Value::as_string) {
        Some("Configuration") => false, // already a proper profile
        Some(_) => true, // bare payload (e.g., com.apple.TCC.configuration-profile-policy)
        None => false,   // missing type — let other fixups handle it
    }
}

/// Wrap a bare payload dict into a Configuration profile envelope.
/// Moves the current dict contents into PayloadContent[0] and creates
/// proper top-level Configuration keys.
fn wrap_bare_payload(dict: &mut plist::Dictionary, fixups: &mut Vec<String>) {
    let payload_type = dict
        .get("PayloadType")
        .and_then(plist::Value::as_string)
        .unwrap_or("unknown")
        .to_string();

    // Derive display name from the payload or use the type
    let display_name = dict
        .get("PayloadDisplayName")
        .and_then(plist::Value::as_string)
        .unwrap_or(&payload_type)
        .to_string();

    // Derive identifier — use existing or generate from type
    let payload_identifier = dict
        .get("PayloadIdentifier")
        .and_then(plist::Value::as_string)
        .unwrap_or(&payload_type)
        .to_string();

    // Preserve PayloadScope if present at the bare-payload level
    let scope = dict.get("PayloadScope").cloned();

    // Take all current contents as the inner payload
    let inner_payload = plist::Value::Dictionary(dict.clone());

    // Clear and rebuild as a Configuration envelope
    dict.clear();
    dict.insert(
        "PayloadType".to_string(),
        plist::Value::String("Configuration".to_string()),
    );
    dict.insert(
        "PayloadVersion".to_string(),
        plist::Value::Integer(1.into()),
    );
    dict.insert(
        "PayloadIdentifier".to_string(),
        plist::Value::String(format!("{payload_identifier}.wrapper")),
    );
    dict.insert(
        "PayloadUUID".to_string(),
        plist::Value::String(uuid::Uuid::new_v4().to_string().to_uppercase()),
    );
    dict.insert(
        "PayloadDisplayName".to_string(),
        plist::Value::String(display_name),
    );
    dict.insert(
        "PayloadContent".to_string(),
        plist::Value::Array(vec![inner_payload]),
    );
    if let Some(s) = scope {
        dict.insert("PayloadScope".to_string(), s);
    }

    fixups.push(format!(
        "wrapped bare payload ({payload_type}) in Configuration envelope"
    ));
}

/// Fix PayloadScope case: "system" → "System", "user" → "User".
fn fixup_payload_scope(dict: &mut plist::Dictionary, context: &str, fixups: &mut Vec<String>) {
    let needs_fix = match dict.get("PayloadScope").and_then(plist::Value::as_string) {
        Some("system") => Some(("system", "System")),
        Some("user") => Some(("user", "User")),
        _ => None,
    };

    if let Some((old, new)) = needs_fix {
        dict.insert(
            "PayloadScope".to_string(),
            plist::Value::String(new.to_string()),
        );
        fixups.push(format!("{context}: fixed PayloadScope '{old}' → '{new}'"));
    }
}

/// Fix PayloadVersion in a single dictionary: add if missing, convert Real→Integer.
fn fixup_payload_version(dict: &mut plist::Dictionary, context: &str, fixups: &mut Vec<String>) {
    // Check what kind of fixup is needed (borrowing immutably first)
    enum VersionFixup {
        Missing,
        RealToInt(f64, i64),
        None,
    }

    let fixup = match dict.get("PayloadVersion") {
        Option::None => VersionFixup::Missing,
        Some(plist::Value::Real(f)) => VersionFixup::RealToInt(*f, *f as i64),
        _ => VersionFixup::None,
    };

    match fixup {
        VersionFixup::Missing => {
            dict.insert(
                "PayloadVersion".to_string(),
                plist::Value::Integer(1.into()),
            );
            fixups.push(format!("{context}: added missing PayloadVersion=1"));
        }
        VersionFixup::RealToInt(f, i) => {
            dict.insert(
                "PayloadVersion".to_string(),
                plist::Value::Integer(i.into()),
            );
            fixups.push(format!(
                "{context}: converted PayloadVersion from real({f}) to integer({i})"
            ));
        }
        VersionFixup::None => {}
    }
}

/// Fix missing PayloadIdentifier and PayloadUUID in a payload dictionary.
fn fixup_missing_identity(dict: &mut plist::Dictionary, context: &str, fixups: &mut Vec<String>) {
    if !dict.contains_key("PayloadIdentifier") {
        // Generate a placeholder identifier from PayloadType if available
        let identifier = dict
            .get("PayloadType")
            .and_then(plist::Value::as_string)
            .unwrap_or("unknown")
            .to_string();
        dict.insert(
            "PayloadIdentifier".to_string(),
            plist::Value::String(identifier.clone()),
        );
        fixups.push(format!(
            "{context}: added missing PayloadIdentifier='{identifier}'"
        ));
    }

    if !dict.contains_key("PayloadUUID") {
        let new_uuid = uuid::Uuid::new_v4().to_string().to_uppercase();
        dict.insert(
            "PayloadUUID".to_string(),
            plist::Value::String(new_uuid.clone()),
        );
        fixups.push(format!("{context}: added missing PayloadUUID='{new_uuid}'"));
    }
}

/// Parse a profile leniently from a file path — applies fixups and placeholder substitution.
/// Used by the normalize command to handle real-world profiles with common issues.
pub fn parse_profile_lenient(path: &str) -> Result<FixupResult> {
    let data = fs::read(path).with_context(|| format!("Failed to read file: {path}"))?;

    // Auto-unsign if needed
    let working_data = unsign_if_needed(path, &data)?;

    parse_profile_lenient_from_bytes(&working_data)
}

/// Extract unsigned profile bytes, reusing the same logic as `parse_profile_auto_unsign`.
fn unsign_if_needed(path: &str, data: &[u8]) -> Result<Vec<u8>> {
    if is_xml_profile(data) || is_binary_plist(data) {
        return Ok(data.to_vec());
    }

    if is_signed_profile(data) {
        if cfg!(target_os = "macos") {
            if let Ok(unsigned_data) = unsign_with_security_cms(path) {
                return Ok(unsigned_data);
            }
        }
        return extract_xml_from_pkcs7(data);
    }

    // Unknown format — return as-is, let the plist parser produce the error
    Ok(data.to_vec())
}

/// Parse a profile leniently from raw bytes — applies fixups and placeholder substitution.
pub fn parse_profile_lenient_from_bytes(data: &[u8]) -> Result<FixupResult> {
    // Step 1: Try parsing raw bytes as plist Value
    let (mut value, placeholders) = match plist::from_bytes::<plist::Value>(data) {
        Ok(v) => (v, vec![]),
        Err(initial_err) => {
            // Step 2: plist parse failed — try placeholder substitution and retry
            let placeholder_result = substitute_placeholders(data);
            if placeholder_result.placeholders.is_empty() {
                // No placeholders found, the error is genuine
                return Err(
                    anyhow::anyhow!(initial_err).context("Failed to parse plist (XML or binary)")
                );
            }
            let value = plist::from_bytes::<plist::Value>(&placeholder_result.substituted)
                .context("Failed to parse plist even after placeholder substitution")?;
            (value, placeholder_result.placeholders)
        }
    };

    // Step 3: Apply value-level fixups
    let fixups = fixup_profile_value(&mut value);

    // Step 4: Deserialize into ConfigurationProfile
    let profile = match plist::from_value(&value) {
        Ok(p) => p,
        Err(e) => {
            let detailed_error = diagnose_profile_structure(&value, &e.to_string());
            anyhow::bail!("{detailed_error}")
        }
    };

    Ok(FixupResult {
        profile,
        fixups,
        placeholders,
    })
}

/// Read raw bytes from the macOS pasteboard.
pub fn read_pasteboard_bytes() -> Result<Vec<u8>> {
    if cfg!(not(target_os = "macos")) {
        anyhow::bail!("Pasteboard access requires macOS (uses `pbpaste` command)");
    }
    let output = Command::new("pbpaste")
        .output()
        .context("Failed to run pbpaste")?;
    if !output.status.success() {
        anyhow::bail!("pbpaste failed");
    }
    if output.stdout.is_empty() {
        anyhow::bail!("Pasteboard is empty");
    }
    Ok(output.stdout)
}

/// Read a configuration profile from the macOS pasteboard (clipboard).
/// Shells out to `pbpaste` and parses the result as plist.
#[allow(
    dead_code,
    reason = "utility for interactive macOS clipboard parsing, not yet wired into CLI"
)]
pub fn parse_profile_from_pasteboard() -> Result<ConfigurationProfile> {
    if cfg!(not(target_os = "macos")) {
        anyhow::bail!("Pasteboard access requires macOS (uses `pbpaste` command)");
    }
    let output = Command::new("pbpaste")
        .output()
        .context("Failed to run pbpaste")?;
    if !output.status.success() {
        anyhow::bail!("pbpaste failed");
    }
    if output.stdout.is_empty() {
        anyhow::bail!("Pasteboard is empty");
    }
    parse_profile_from_bytes(&output.stdout)
}

/// Parse profile from raw bytes
pub fn parse_profile_from_bytes(data: &[u8]) -> Result<ConfigurationProfile> {
    let value: plist::Value =
        plist::from_bytes(data).with_context(|| "Failed to parse plist data")?;

    // Try to deserialize, and if it fails, provide detailed error with context
    match plist::from_value(&value) {
        Ok(profile) => Ok(profile),
        Err(e) => {
            let detailed_error = diagnose_profile_structure(&value, &e.to_string());
            anyhow::bail!("{detailed_error}")
        }
    }
}

/// Diagnose profile structure issues and provide detailed error messages
fn diagnose_profile_structure(value: &plist::Value, serde_error: &str) -> String {
    let mut issues = Vec::new();

    let Some(dict) = value.as_dictionary() else {
        return format!("Profile is not a dictionary: {serde_error}");
    };

    // Check top-level required fields
    let top_level_required = [
        "PayloadType",
        "PayloadVersion",
        "PayloadIdentifier",
        "PayloadUUID",
        "PayloadDisplayName",
        "PayloadContent",
    ];
    for field in top_level_required {
        if !dict.contains_key(field) {
            issues.push(format!("Missing required field '{field}' at profile level"));
        }
    }

    // Check PayloadContent array
    if let Some(content) = dict.get("PayloadContent") {
        if let Some(payloads) = content.as_array() {
            let payload_required = [
                "PayloadType",
                "PayloadVersion",
                "PayloadIdentifier",
                "PayloadUUID",
            ];

            for (idx, payload) in payloads.iter().enumerate() {
                if let Some(payload_dict) = payload.as_dictionary() {
                    let payload_type = payload_dict.get("PayloadType").and_then(|v| v.as_string());

                    let payload_id = payload_dict
                        .get("PayloadIdentifier")
                        .and_then(|v| v.as_string());

                    let payload_name = payload_dict
                        .get("PayloadDisplayName")
                        .and_then(|v| v.as_string());

                    for field in payload_required {
                        if !payload_dict.contains_key(field) {
                            let location = format_payload_location(
                                idx,
                                payload_type,
                                payload_id,
                                payload_name,
                            );
                            issues.push(format!("{location}: missing '{field}'"));
                        }
                    }
                } else {
                    issues.push(format!("PayloadContent[{idx}]: not a dictionary"));
                }
            }
        } else {
            issues.push("PayloadContent is not an array".to_string());
        }
    }

    if issues.is_empty() {
        // No obvious issues found, return the original error
        format!("Failed to deserialize profile: {serde_error}")
    } else {
        format!("Profile structure errors:\n  - {}", issues.join("\n  - "))
    }
}

/// Format a human-readable payload location string
fn format_payload_location(
    index: usize,
    payload_type: Option<&str>,
    payload_id: Option<&str>,
    payload_name: Option<&str>,
) -> String {
    let mut parts = vec![format!("PayloadContent[{}]", index)];

    if let Some(name) = payload_name {
        parts.push(format!("\"{name}\""));
    }

    if let Some(ptype) = payload_type {
        parts.push(format!("({ptype})"));
    }

    if let Some(pid) = payload_id {
        // Only show identifier if different from type
        if payload_type != Some(pid) {
            parts.push(format!("[{pid}]"));
        }
    }

    parts.join(" ")
}

/// Check if data is an XML plist
fn is_xml_profile(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    data.starts_with(b"<?xml") || data.starts_with(b"<plist")
}

/// Check if data is a binary plist
fn is_binary_plist(data: &[u8]) -> bool {
    data.len() >= 6 && &data[0..6] == b"bplist"
}

/// Check if data is a signed PKCS#7 profile
fn is_signed_profile(data: &[u8]) -> bool {
    // PKCS#7/CMS signed data starts with ASN.1 SEQUENCE (0x30)
    // followed by length encoding (0x80 for indefinite, or other values)
    if data.len() < 10 {
        return false;
    }
    data[0] == 0x30 && (data[1] == 0x80 || data[1] == 0x82 || data[1] == 0x83)
}

/// Unsign profile using macOS security cms command
fn unsign_with_security_cms(path: &str) -> Result<Vec<u8>> {
    let output = Command::new("security")
        .args(["cms", "-D", "-i", path])
        .output()
        .with_context(|| "Failed to execute security cms")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("security cms failed: {stderr}");
    }

    Ok(output.stdout)
}

/// Extract XML content from PKCS#7 signed envelope (fallback method)
fn extract_xml_from_pkcs7(data: &[u8]) -> Result<Vec<u8>> {
    // Find XML start marker
    let xml_marker = b"<?xml";
    let mut xml_start = None;

    for i in 0..data.len().saturating_sub(xml_marker.len()) {
        if &data[i..i + xml_marker.len()] == xml_marker {
            xml_start = Some(i);
            break;
        }
    }

    let start = xml_start.context("No XML content found in signed profile")?;

    // Find XML end marker
    let end_marker = b"</plist>";
    let mut end = data.len();

    for i in start..data.len().saturating_sub(end_marker.len()) {
        if &data[i..i + end_marker.len()] == end_marker {
            end = i + end_marker.len();
            break;
        }
    }

    if end > start {
        let mut xml_data = data[start..end].to_vec();
        // Remove null bytes that may be present in the PKCS#7 structure
        xml_data.retain(|&b| b != 0);

        if !xml_data.is_empty()
            && (xml_data.starts_with(b"<?xml") || xml_data.starts_with(b"<plist"))
        {
            return Ok(xml_data);
        }
    }

    anyhow::bail!("Failed to extract valid XML from PKCS#7 envelope")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::PayloadContent;
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ========== Test Fixtures ==========

    fn minimal_xml_profile() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>com.test.profile</string>
    <key>PayloadUUID</key>
    <string>12345678-1234-1234-1234-123456789012</string>
    <key>PayloadDisplayName</key>
    <string>Test Profile</string>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.wifi.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.test.wifi</string>
            <key>PayloadUUID</key>
            <string>87654321-4321-4321-4321-210987654321</string>
        </dict>
    </array>
</dict>
</plist>"#
    }

    fn create_test_profile() -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "12345678-1234-1234-1234-123456789012".to_string(),
            payload_display_name: "Test Profile".to_string(),
            payload_content: vec![PayloadContent {
                payload_type: "com.apple.wifi.managed".to_string(),
                payload_version: 1,
                payload_identifier: "com.test.wifi".to_string(),
                payload_uuid: "87654321-4321-4321-4321-210987654321".to_string(),
                content: HashMap::new(),
            }],
            additional_fields: HashMap::new(),
        }
    }

    // ========== PlistFormat Detection Tests ==========

    #[test]
    fn test_detect_xml_format() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(minimal_xml_profile().as_bytes()).unwrap();

        let format = PlistFormat::detect(file.path().to_str().unwrap()).unwrap();
        assert_eq!(format, PlistFormat::Xml);
    }

    #[test]
    fn test_detect_binary_format() {
        let mut file = NamedTempFile::new().unwrap();
        let profile = create_test_profile();
        plist::to_writer_binary(&mut file, &profile).unwrap();

        let format = PlistFormat::detect(file.path().to_str().unwrap()).unwrap();
        assert_eq!(format, PlistFormat::Binary);
    }

    #[test]
    fn test_detect_format_file_not_found() {
        let result = PlistFormat::detect("/nonexistent/file.mobileconfig");
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_format_too_small_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"short").unwrap();

        let result = PlistFormat::detect(file.path().to_str().unwrap());
        assert!(result.is_err()); // Less than 8 bytes
    }

    // ========== parse_profile Tests ==========

    #[test]
    fn test_parse_profile_xml() {
        let mut file = NamedTempFile::with_suffix(".mobileconfig").unwrap();
        file.write_all(minimal_xml_profile().as_bytes()).unwrap();

        let profile = parse_profile(file.path().to_str().unwrap()).unwrap();

        assert_eq!(profile.payload_type, "Configuration");
        assert_eq!(profile.payload_version, 1);
        assert_eq!(profile.payload_identifier, "com.test.profile");
        assert_eq!(profile.payload_content.len(), 1);
        assert_eq!(
            profile.payload_content[0].payload_type,
            "com.apple.wifi.managed"
        );
    }

    #[test]
    fn test_parse_profile_binary() {
        let file = NamedTempFile::with_suffix(".mobileconfig").unwrap();
        let profile = create_test_profile();
        plist::to_file_binary(file.path(), &profile).unwrap();

        let parsed = parse_profile(file.path().to_str().unwrap()).unwrap();

        assert_eq!(parsed.payload_type, profile.payload_type);
        assert_eq!(parsed.payload_identifier, profile.payload_identifier);
    }

    #[test]
    fn test_parse_profile_file_not_found() {
        let result = parse_profile("/nonexistent/file.mobileconfig");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to open"));
    }

    #[test]
    fn test_parse_profile_invalid_plist() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not a valid plist").unwrap();

        let result = parse_profile(file.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_profile_missing_required_fields() {
        let incomplete_plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>PayloadType</key>
    <string>Configuration</string>
</dict>
</plist>"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(incomplete_plist.as_bytes()).unwrap();

        let result = parse_profile(file.path().to_str().unwrap());
        assert!(result.is_err()); // Missing required fields
    }

    // ========== parse_profile_with_format Tests ==========

    #[test]
    fn test_parse_profile_with_format_xml() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(minimal_xml_profile().as_bytes()).unwrap();

        let (profile, format) = parse_profile_with_format(file.path().to_str().unwrap()).unwrap();

        assert_eq!(format, PlistFormat::Xml);
        assert_eq!(profile.payload_type, "Configuration");
    }

    #[test]
    fn test_parse_profile_with_format_binary() {
        let file = NamedTempFile::new().unwrap();
        let profile = create_test_profile();
        plist::to_file_binary(file.path(), &profile).unwrap();

        let (parsed, format) = parse_profile_with_format(file.path().to_str().unwrap()).unwrap();

        assert_eq!(format, PlistFormat::Binary);
        assert_eq!(parsed.payload_identifier, profile.payload_identifier);
    }

    // ========== Write Profile Tests ==========

    #[test]
    fn test_write_profile_xml() {
        let profile = create_test_profile();
        let file = NamedTempFile::new().unwrap();

        write_profile_xml(&profile, file.path()).unwrap();

        // Read back and verify
        let content = std::fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("<?xml"));
        assert!(content.contains("com.test.profile"));
    }

    #[test]
    fn test_write_profile_binary() {
        let profile = create_test_profile();
        let file = NamedTempFile::new().unwrap();

        write_profile_binary(&profile, file.path()).unwrap();

        // Read back magic bytes
        let content = std::fs::read(file.path()).unwrap();
        assert!(content.starts_with(b"bplist"));
    }

    #[test]
    fn test_write_profile_roundtrip_xml() {
        let original = create_test_profile();
        let file = NamedTempFile::new().unwrap();

        write_profile_xml(&original, file.path()).unwrap();
        let parsed = parse_profile(file.path().to_str().unwrap()).unwrap();

        assert_eq!(parsed.payload_type, original.payload_type);
        assert_eq!(parsed.payload_identifier, original.payload_identifier);
        assert_eq!(parsed.payload_uuid, original.payload_uuid);
        assert_eq!(parsed.payload_display_name, original.payload_display_name);
    }

    #[test]
    fn test_write_profile_roundtrip_binary() {
        let original = create_test_profile();
        let file = NamedTempFile::new().unwrap();

        write_profile_binary(&original, file.path()).unwrap();
        let parsed = parse_profile(file.path().to_str().unwrap()).unwrap();

        assert_eq!(parsed.payload_type, original.payload_type);
        assert_eq!(parsed.payload_identifier, original.payload_identifier);
    }

    #[test]
    fn test_write_profile_default_is_xml() {
        let profile = create_test_profile();
        let file = NamedTempFile::new().unwrap();

        write_profile(&profile, file.path()).unwrap();

        // Verify it's XML format
        let content = std::fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("<?xml"));
    }

    // ========== String/Bytes Conversion Tests ==========

    #[test]
    fn test_profile_to_xml_string() {
        let profile = create_test_profile();

        let xml = profile_to_xml_string(&profile).unwrap();

        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("com.test.profile"));
        assert!(xml.contains("</plist>"));
    }

    #[test]
    fn test_profile_to_binary() {
        let profile = create_test_profile();

        let binary = profile_to_binary(&profile).unwrap();

        assert!(binary.starts_with(b"bplist"));
    }

    // ========== Format Detection Helper Tests ==========

    #[test]
    fn test_is_xml_profile_with_xml_declaration() {
        assert!(is_xml_profile(b"<?xml version=\"1.0\"?>"));
    }

    #[test]
    fn test_is_xml_profile_with_plist_tag() {
        assert!(is_xml_profile(b"<plist version=\"1.0\">"));
    }

    #[test]
    fn test_is_xml_profile_false_for_binary() {
        assert!(!is_xml_profile(b"bplist00"));
    }

    #[test]
    fn test_is_xml_profile_false_for_short_data() {
        assert!(!is_xml_profile(b"<?x"));
    }

    #[test]
    fn test_is_binary_plist_true() {
        assert!(is_binary_plist(b"bplist00data"));
    }

    #[test]
    fn test_is_binary_plist_false_for_xml() {
        assert!(!is_binary_plist(b"<?xml version"));
    }

    #[test]
    fn test_is_binary_plist_false_for_short() {
        assert!(!is_binary_plist(b"bpli"));
    }

    // ========== Signed Profile Detection Tests ==========

    #[test]
    fn test_is_signed_profile_true_indefinite_length() {
        // ASN.1 SEQUENCE with 0x80 indefinite length
        let signed_data = [0x30, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(is_signed_profile(&signed_data));
    }

    #[test]
    fn test_is_signed_profile_true_definite_length() {
        // ASN.1 SEQUENCE with 0x82 (2-byte length)
        let signed_data = [0x30, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(is_signed_profile(&signed_data));
    }

    #[test]
    fn test_is_signed_profile_false_for_xml() {
        assert!(!is_signed_profile(b"<?xml version=\"1.0\"?>"));
    }

    #[test]
    fn test_is_signed_profile_false_for_short() {
        assert!(!is_signed_profile(b"short"));
    }

    #[test]
    fn test_is_signed_profile_false_for_binary_plist() {
        assert!(!is_signed_profile(b"bplist00data"));
    }

    // ========== parse_profile_from_bytes Tests ==========

    #[test]
    fn test_parse_profile_from_bytes_xml() {
        let bytes = minimal_xml_profile().as_bytes();

        let profile = parse_profile_from_bytes(bytes).unwrap();

        assert_eq!(profile.payload_type, "Configuration");
        assert_eq!(profile.payload_content.len(), 1);
    }

    #[test]
    fn test_parse_profile_from_bytes_binary() {
        let profile = create_test_profile();
        let binary = profile_to_binary(&profile).unwrap();

        let parsed = parse_profile_from_bytes(&binary).unwrap();

        assert_eq!(parsed.payload_identifier, profile.payload_identifier);
    }

    #[test]
    fn test_parse_profile_from_bytes_invalid() {
        let result = parse_profile_from_bytes(b"invalid data");
        assert!(result.is_err());
    }

    // ========== extract_xml_from_pkcs7 Tests ==========

    #[test]
    fn test_extract_xml_from_pkcs7_success() {
        // Simulate PKCS#7 envelope with embedded XML
        let mut data = Vec::new();
        data.extend_from_slice(&[0x30, 0x82, 0x00, 0x50]); // ASN.1 header
        data.extend_from_slice(b"some binary data before");
        data.extend_from_slice(minimal_xml_profile().as_bytes());
        data.extend_from_slice(b"some binary data after");

        let extracted = extract_xml_from_pkcs7(&data).unwrap();

        assert!(extracted.starts_with(b"<?xml"));
        assert!(extracted.ends_with(b"</plist>"));
    }

    #[test]
    fn test_extract_xml_from_pkcs7_no_xml() {
        let data = [0x30, 0x82, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00];

        let result = extract_xml_from_pkcs7(&data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No XML content found")
        );
    }

    #[test]
    fn test_extract_xml_from_pkcs7_incomplete_xml() {
        // Function extracts from <?xml to </plist>, if </plist> is missing it fails
        // Test with data that has no plist end tag
        let mut data = Vec::new();
        data.extend_from_slice(&[0x30, 0x82]);
        data.extend_from_slice(b"<?xml version=\"1.0\"?><plist>incomplete data here");

        let result = extract_xml_from_pkcs7(&data);
        // The function will extract the data (it finds <?xml start but no </plist>)
        // The result includes everything from <?xml to end of data
        // This tests that even incomplete XML is extracted if it starts with valid marker
        assert!(result.is_ok());
        let extracted = result.unwrap();
        assert!(extracted.starts_with(b"<?xml"));
    }

    // ========== parse_profile_auto_unsign Tests ==========

    #[test]
    fn test_parse_profile_auto_unsign_xml() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(minimal_xml_profile().as_bytes()).unwrap();

        let profile = parse_profile_auto_unsign(file.path().to_str().unwrap()).unwrap();

        assert_eq!(profile.payload_type, "Configuration");
    }

    #[test]
    fn test_parse_profile_auto_unsign_binary() {
        let file = NamedTempFile::new().unwrap();
        let profile = create_test_profile();
        plist::to_file_binary(file.path(), &profile).unwrap();

        let parsed = parse_profile_auto_unsign(file.path().to_str().unwrap()).unwrap();

        assert_eq!(parsed.payload_identifier, profile.payload_identifier);
    }

    #[test]
    fn test_parse_profile_auto_unsign_file_not_found() {
        let result = parse_profile_auto_unsign("/nonexistent/file.mobileconfig");
        assert!(result.is_err());
    }

    // ========== Profile with PayloadContent Tests ==========

    #[test]
    fn test_parse_profile_preserves_payload_content() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(minimal_xml_profile().as_bytes()).unwrap();

        let profile = parse_profile(file.path().to_str().unwrap()).unwrap();

        assert_eq!(profile.payload_content.len(), 1);
        let payload = &profile.payload_content[0];
        assert_eq!(payload.payload_type, "com.apple.wifi.managed");
        assert_eq!(payload.payload_identifier, "com.test.wifi");
        assert_eq!(payload.payload_uuid, "87654321-4321-4321-4321-210987654321");
    }

    #[test]
    fn test_roundtrip_preserves_all_fields() {
        let mut additional_fields = HashMap::new();
        additional_fields.insert(
            "PayloadDescription".to_string(),
            plist::Value::String("A description".to_string()),
        );
        additional_fields.insert(
            "PayloadOrganization".to_string(),
            plist::Value::String("Test Org".to_string()),
        );

        let mut content = HashMap::new();
        content.insert(
            "PayloadDisplayName".to_string(),
            plist::Value::String("Login Window".to_string()),
        );

        let original = ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_identifier: "com.example.test".to_string(),
            payload_uuid: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".to_string(),
            payload_display_name: "Full Test Profile".to_string(),
            payload_content: vec![PayloadContent {
                payload_type: "com.apple.loginwindow".to_string(),
                payload_version: 1,
                payload_identifier: "com.example.loginwindow".to_string(),
                payload_uuid: "11111111-2222-3333-4444-555555555555".to_string(),
                content,
            }],
            additional_fields,
        };

        let file = NamedTempFile::new().unwrap();
        write_profile_xml(&original, file.path()).unwrap();
        let parsed = parse_profile(file.path().to_str().unwrap()).unwrap();

        assert_eq!(parsed.payload_type, original.payload_type);
        assert_eq!(parsed.payload_version, original.payload_version);
        assert_eq!(parsed.payload_identifier, original.payload_identifier);
        assert_eq!(parsed.payload_uuid, original.payload_uuid);
        assert_eq!(parsed.payload_display_name, original.payload_display_name);
        assert_eq!(parsed.payload_description(), original.payload_description());
        assert_eq!(
            parsed.payload_organization(),
            original.payload_organization()
        );
        assert_eq!(parsed.payload_content.len(), original.payload_content.len());
    }

    // ========== Lenient Parsing / Fixup Tests ==========

    fn xml_profile_missing_payload_version() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>com.test.profile</string>
    <key>PayloadUUID</key>
    <string>12345678-1234-1234-1234-123456789012</string>
    <key>PayloadDisplayName</key>
    <string>Test Profile</string>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.SoftwareUpdate</string>
            <key>PayloadIdentifier</key>
            <string>com.test.softwareupdate</string>
            <key>PayloadUUID</key>
            <string>87654321-4321-4321-4321-210987654321</string>
        </dict>
    </array>
</dict>
</plist>"#
    }

    fn xml_profile_real_payload_version() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <real>1</real>
    <key>PayloadIdentifier</key>
    <string>com.test.profile</string>
    <key>PayloadUUID</key>
    <string>12345678-1234-1234-1234-123456789012</string>
    <key>PayloadDisplayName</key>
    <string>Test Profile</string>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.wifi.managed</string>
            <key>PayloadVersion</key>
            <real>1</real>
            <key>PayloadIdentifier</key>
            <string>com.test.wifi</string>
            <key>PayloadUUID</key>
            <string>87654321-4321-4321-4321-210987654321</string>
        </dict>
    </array>
</dict>
</plist>"#
    }

    #[test]
    fn test_fixup_missing_payload_version() {
        let xml = xml_profile_missing_payload_version();
        let mut value: plist::Value = plist::from_bytes(xml.as_bytes()).unwrap();

        let fixups = fixup_profile_value(&mut value);

        assert_eq!(fixups.len(), 1);
        assert!(fixups[0].contains("added missing PayloadVersion"));
        assert!(fixups[0].contains("PayloadContent[0]"));

        // Should now deserialize successfully
        let profile: ConfigurationProfile = plist::from_value(&value).unwrap();
        assert_eq!(profile.payload_content[0].payload_version, 1);
    }

    #[test]
    fn test_fixup_real_payload_version() {
        let xml = xml_profile_real_payload_version();
        let mut value: plist::Value = plist::from_bytes(xml.as_bytes()).unwrap();

        let fixups = fixup_profile_value(&mut value);

        assert_eq!(fixups.len(), 2); // top-level + PayloadContent[0]
        assert!(
            fixups
                .iter()
                .all(|f| f.contains("converted PayloadVersion"))
        );

        let profile: ConfigurationProfile = plist::from_value(&value).unwrap();
        assert_eq!(profile.payload_version, 1);
        assert_eq!(profile.payload_content[0].payload_version, 1);
    }

    #[test]
    fn test_fixup_valid_profile_no_fixups() {
        let xml = minimal_xml_profile();
        let mut value: plist::Value = plist::from_bytes(xml.as_bytes()).unwrap();

        let fixups = fixup_profile_value(&mut value);

        assert!(fixups.is_empty());
    }

    #[test]
    fn test_parse_lenient_missing_payload_version() {
        let xml = xml_profile_missing_payload_version();
        let result = parse_profile_lenient_from_bytes(xml.as_bytes()).unwrap();

        assert_eq!(result.profile.payload_content[0].payload_version, 1);
        assert_eq!(result.fixups.len(), 1);
        assert!(result.placeholders.is_empty());
    }

    #[test]
    fn test_parse_lenient_with_placeholders() {
        // Placeholder inside <data> breaks plist parsing — triggers substitution path
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>com.test.profile</string>
    <key>PayloadUUID</key>
    <string>12345678-1234-1234-1234-123456789012</string>
    <key>PayloadDisplayName</key>
    <string>Test Profile</string>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.wifi.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.test.wifi</string>
            <key>PayloadUUID</key>
            <string>87654321-4321-4321-4321-210987654321</string>
            <key>CertData</key>
            <data>$FLEET_SECRET_CERT</data>
        </dict>
    </array>
</dict>
</plist>"#;

        let result = parse_profile_lenient_from_bytes(xml.as_bytes()).unwrap();

        assert!(!result.placeholders.is_empty());
        assert!(
            result
                .placeholders
                .contains(&"$FLEET_SECRET_CERT".to_string())
        );
    }

    #[test]
    fn test_parse_lenient_truly_broken_still_fails() {
        let result = parse_profile_lenient_from_bytes(b"not a plist at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_lenient_valid_profile_no_fixups() {
        let xml = minimal_xml_profile();
        let result = parse_profile_lenient_from_bytes(xml.as_bytes()).unwrap();

        assert!(result.fixups.is_empty());
        assert!(result.placeholders.is_empty());
        assert_eq!(result.profile.payload_type, "Configuration");
    }
}
