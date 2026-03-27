use crate::models::{Policy, Rule, RuleSet, RuleType};
use anyhow::{Context, Result};
use plist::Value;
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

/// Generator options
#[derive(Debug, Clone)]
pub struct GeneratorOptions {
    /// Organization identifier prefix
    pub org: String,
    /// Profile identifier
    pub identifier: String,
    /// Profile display name
    pub display_name: String,
    /// Profile description
    pub description: String,
    /// Use deterministic UUIDs
    pub deterministic_uuids: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            org: "com.example".to_string(),
            identifier: "santa.rules".to_string(),
            display_name: "Santa Rules".to_string(),
            description: "Santa binary authorization rules".to_string(),
            deterministic_uuids: false,
        }
    }
}

impl GeneratorOptions {
    pub fn new(org: &str) -> Self {
        Self {
            org: org.to_string(),
            identifier: format!("{org}.santa.rules"),
            display_name: "Santa Rules".to_string(),
            description: "Santa binary authorization rules".to_string(),
            deterministic_uuids: false,
        }
    }

    pub fn with_identifier(mut self, identifier: &str) -> Self {
        self.identifier = identifier.to_string();
        self
    }

    pub fn with_display_name(mut self, name: &str) -> Self {
        self.display_name = name.to_string();
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_deterministic_uuids(mut self, deterministic: bool) -> Self {
        self.deterministic_uuids = deterministic;
        self
    }
}

/// Generate mobileconfig from rules
pub fn generate(rules: &RuleSet, options: &GeneratorOptions) -> Result<Vec<u8>> {
    let profile_uuid = generate_uuid(options.deterministic_uuids, &options.identifier);
    let payload_uuid = generate_uuid(
        options.deterministic_uuids,
        &format!("{}.payload", options.identifier),
    );

    // Build Santa rules array
    let santa_rules: Vec<Value> = rules.rules().iter().map(rule_to_plist).collect();

    // Build payload content
    let mut payload_content: HashMap<String, Value> = HashMap::new();
    payload_content.insert("Rules".to_string(), Value::Array(santa_rules));

    // Build payload
    let mut payload: HashMap<String, Value> = HashMap::new();
    payload.insert(
        "PayloadType".to_string(),
        Value::String("com.northpolesec.santa".to_string()),
    );
    payload.insert(
        "PayloadIdentifier".to_string(),
        Value::String(format!("{}.santa", options.identifier)),
    );
    payload.insert(
        "PayloadUUID".to_string(),
        Value::String(payload_uuid.to_string().to_uppercase()),
    );
    payload.insert("PayloadVersion".to_string(), Value::Integer(1.into()));
    payload.insert(
        "PayloadDisplayName".to_string(),
        Value::String("Santa Rules".to_string()),
    );
    payload.insert(
        "PayloadContent".to_string(),
        Value::Dictionary(payload_content.into_iter().collect()),
    );

    // Build profile
    let mut profile: HashMap<String, Value> = HashMap::new();
    profile.insert("PayloadVersion".to_string(), Value::Integer(1.into()));
    profile.insert(
        "PayloadType".to_string(),
        Value::String("Configuration".to_string()),
    );
    profile.insert(
        "PayloadIdentifier".to_string(),
        Value::String(options.identifier.clone()),
    );
    profile.insert(
        "PayloadUUID".to_string(),
        Value::String(profile_uuid.to_string().to_uppercase()),
    );
    profile.insert(
        "PayloadDisplayName".to_string(),
        Value::String(options.display_name.clone()),
    );
    profile.insert(
        "PayloadDescription".to_string(),
        Value::String(options.description.clone()),
    );
    profile.insert(
        "PayloadOrganization".to_string(),
        Value::String(options.org.clone()),
    );
    profile.insert(
        "PayloadScope".to_string(),
        Value::String("System".to_string()),
    );
    profile.insert(
        "PayloadContent".to_string(),
        Value::Array(vec![Value::Dictionary(payload.into_iter().collect())]),
    );

    // Serialize to XML plist
    let mut buffer = Vec::new();
    plist::to_writer_xml(
        &mut buffer,
        &Value::Dictionary(profile.into_iter().collect()),
    )
    .context("Failed to serialize mobileconfig")?;

    Ok(buffer)
}

/// Write mobileconfig to file
pub fn write_to_file(rules: &RuleSet, options: &GeneratorOptions, path: &Path) -> Result<()> {
    let content = generate(rules, options)?;
    std::fs::write(path, content)
        .with_context(|| format!("Failed to write mobileconfig: {}", path.display()))?;
    Ok(())
}

/// Output format for generated profiles
#[derive(Debug, Clone, Copy, Default)]
pub enum Format {
    /// Standard Apple mobileconfig format
    #[default]
    Mobileconfig,
    /// Plist payload without XML header (WS1 compatible)
    Plist,
    /// Plist payload with full XML header (Jamf custom schema)
    PlistFull,
}

/// Generate output in the specified format
pub fn generate_format(
    rules: &RuleSet,
    options: &GeneratorOptions,
    format: Format,
) -> Result<Vec<u8>> {
    match format {
        Format::Mobileconfig => generate(rules, options),
        Format::Plist => generate_plist_stripped(rules, options),
        Format::PlistFull => generate_payload_plist(rules, options),
    }
}

/// Generate just the Santa payload as a plist (no profile wrapper)
pub fn generate_payload_plist(rules: &RuleSet, options: &GeneratorOptions) -> Result<Vec<u8>> {
    let payload_uuid = generate_uuid(
        options.deterministic_uuids,
        &format!("{}.payload", options.identifier),
    );

    // Build Santa rules array
    let santa_rules: Vec<Value> = rules.rules().iter().map(rule_to_plist).collect();

    // Build payload content
    let mut payload_content: HashMap<String, Value> = HashMap::new();
    payload_content.insert("Rules".to_string(), Value::Array(santa_rules));

    // Build payload
    let mut payload: HashMap<String, Value> = HashMap::new();
    payload.insert(
        "PayloadType".to_string(),
        Value::String("com.northpolesec.santa".to_string()),
    );
    payload.insert(
        "PayloadIdentifier".to_string(),
        Value::String(format!("{}.santa", options.identifier)),
    );
    payload.insert(
        "PayloadUUID".to_string(),
        Value::String(payload_uuid.to_string().to_uppercase()),
    );
    payload.insert("PayloadVersion".to_string(), Value::Integer(1.into()));
    payload.insert(
        "PayloadDisplayName".to_string(),
        Value::String(options.display_name.clone()),
    );
    payload.insert(
        "PayloadContent".to_string(),
        Value::Dictionary(payload_content.into_iter().collect()),
    );

    let mut buffer = Vec::new();
    plist::to_writer_xml(
        &mut buffer,
        &Value::Dictionary(payload.into_iter().collect()),
    )
    .context("Failed to serialize plist payload")?;

    Ok(buffer)
}

/// Generate plist without XML header - WS1/Workspace ONE compatible
pub fn generate_plist_stripped(rules: &RuleSet, options: &GeneratorOptions) -> Result<Vec<u8>> {
    let plist_content = generate_payload_plist(rules, options)?;
    let xml_str = String::from_utf8(plist_content)?;

    // Strip the XML declaration, DOCTYPE, and <plist> wrapper
    let dict_start = xml_str
        .find("<dict>")
        .ok_or_else(|| anyhow::anyhow!("No <dict> tag found in plist"))?;
    let dict_end = xml_str
        .rfind("</dict>")
        .ok_or_else(|| anyhow::anyhow!("No </dict> tag found in plist"))?;

    let dict_content = &xml_str[dict_start..dict_end + 7]; // 7 = len("</dict>")
    Ok(dict_content.as_bytes().to_vec())
}

/// Write output in the specified format
pub fn write_to_file_format(
    rules: &RuleSet,
    options: &GeneratorOptions,
    path: &Path,
    format: Format,
) -> Result<()> {
    let content = generate_format(rules, options, format)?;
    std::fs::write(path, content)
        .with_context(|| format!("Failed to write output: {}", path.display()))?;
    Ok(())
}

fn rule_to_plist(rule: &Rule) -> Value {
    let mut dict: HashMap<String, Value> = HashMap::new();

    dict.insert(
        "rule_type".to_string(),
        Value::String(rule_type_to_santa(&rule.rule_type)),
    );
    dict.insert(
        "identifier".to_string(),
        Value::String(rule.identifier.clone()),
    );
    dict.insert(
        "policy".to_string(),
        Value::String(policy_to_santa(&rule.policy)),
    );

    if let Some(ref cel) = rule.cel_expression {
        dict.insert("cel_expression".to_string(), Value::String(cel.clone()));
    }
    if let Some(ref msg) = rule.custom_msg {
        dict.insert("custom_msg".to_string(), Value::String(msg.clone()));
    }
    if let Some(ref url) = rule.custom_url {
        dict.insert("custom_url".to_string(), Value::String(url.clone()));
    }

    Value::Dictionary(dict.into_iter().collect())
}

fn rule_type_to_santa(rt: &RuleType) -> String {
    match rt {
        RuleType::Binary => "BINARY",
        RuleType::Certificate => "CERTIFICATE",
        RuleType::TeamId => "TEAMID",
        RuleType::SigningId => "SIGNINGID",
        RuleType::Cdhash => "CDHASH",
    }
    .to_string()
}

fn policy_to_santa(p: &Policy) -> String {
    match p {
        Policy::Allowlist => "ALLOWLIST",
        Policy::AllowlistCompiler => "ALLOWLIST_COMPILER",
        Policy::Blocklist => "BLOCKLIST",
        Policy::SilentBlocklist => "SILENT_BLOCKLIST",
        Policy::Remove => "REMOVE",
        Policy::Cel => "CEL",
    }
    .to_string()
}

fn generate_uuid(deterministic: bool, seed: &str) -> Uuid {
    if deterministic {
        // UUID v5 with DNS namespace
        Uuid::new_v5(&Uuid::NAMESPACE_DNS, seed.as_bytes())
    } else {
        Uuid::new_v4()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_empty_rules() {
        let rules = RuleSet::new();
        let options = GeneratorOptions::default();
        let result = generate(&rules, &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_with_rules() {
        let mut rules = RuleSet::new();
        rules.add(Rule::new(RuleType::TeamId, "EQHXZ8M8AV", Policy::Allowlist));

        let options = GeneratorOptions::new("com.example");
        let result = generate(&rules, &options).unwrap();

        let content = String::from_utf8(result).unwrap();
        assert!(content.contains("EQHXZ8M8AV"));
        assert!(content.contains("TEAMID"));
        assert!(content.contains("ALLOWLIST"));
    }

    #[test]
    fn test_deterministic_uuid() {
        let uuid1 = generate_uuid(true, "test.seed");
        let uuid2 = generate_uuid(true, "test.seed");
        assert_eq!(uuid1, uuid2);
    }

    #[test]
    fn test_random_uuid() {
        let uuid1 = generate_uuid(false, "test.seed");
        let uuid2 = generate_uuid(false, "test.seed");
        assert_ne!(uuid1, uuid2);
    }
}
