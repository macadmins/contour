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
}
