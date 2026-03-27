//! Configuration profile types and operations.
//!
//! Core types for Apple configuration profiles including parsing, validation,
//! and normalization of .mobileconfig files.

pub mod normalizer;
pub mod parser;
pub mod validator;

pub use parser::PlistFormat;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Deserialize PayloadVersion accepting both `<integer>` and `<real>` plist types.
/// Apple specifies integer but some profiles use `<real>1</real>` which macOS accepts.
fn deserialize_version<'de, D: serde::Deserializer<'de>>(d: D) -> Result<i32, D::Error> {
    let v = plist::Value::deserialize(d)?;
    match &v {
        plist::Value::Integer(i) => i
            .as_signed()
            .and_then(|n| i32::try_from(n).ok())
            .ok_or_else(|| serde::de::Error::custom("PayloadVersion integer out of range")),
        plist::Value::Real(f) => Ok(*f as i32),
        _ => Err(serde::de::Error::custom(format!(
            "PayloadVersion: expected integer or real, got {v:?}"
        ))),
    }
}

/// Serialize PayloadVersion always as integer (even if it was parsed from real).
fn serialize_version<S: serde::Serializer>(v: &i32, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_i32(*v)
}

/// Detect plist format from file path
#[allow(dead_code, reason = "reserved for future use")]
pub fn detect_format(path: &Path) -> anyhow::Result<PlistFormat> {
    PlistFormat::detect(path.to_str().unwrap_or(""))
}

/// Apple configuration profile (.mobileconfig).
///
/// Represents a complete configuration profile with one or more payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationProfile {
    /// Profile type, always "Configuration".
    #[serde(rename = "PayloadType")]
    pub payload_type: String,

    /// Profile version, always 1. Accepts both `<integer>` and `<real>` from plist.
    #[serde(
        rename = "PayloadVersion",
        deserialize_with = "deserialize_version",
        serialize_with = "serialize_version"
    )]
    pub payload_version: i32,

    /// Unique reverse-DNS identifier for this profile.
    #[serde(rename = "PayloadIdentifier")]
    pub payload_identifier: String,

    /// Unique identifier (UUID) for this profile.
    #[serde(rename = "PayloadUUID")]
    pub payload_uuid: String,

    /// Human-readable name shown in Settings.
    #[serde(rename = "PayloadDisplayName")]
    pub payload_display_name: String,

    /// Array of payload content dictionaries.
    #[serde(rename = "PayloadContent")]
    pub payload_content: Vec<PayloadContent>,

    /// Additional fields including PayloadDescription, PayloadOrganization, etc.
    /// Note: plist crate has issues with Option<String> + flatten, so these are captured here
    #[serde(flatten)]
    pub additional_fields: HashMap<String, plist::Value>,
}

impl ConfigurationProfile {
    /// Get PayloadDescription if present
    pub fn payload_description(&self) -> Option<String> {
        self.additional_fields
            .get("PayloadDescription")
            .and_then(|v| v.as_string().map(std::string::ToString::to_string))
    }

    /// Set PayloadDescription
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn set_payload_description(&mut self, desc: Option<String>) {
        if let Some(d) = desc {
            self.additional_fields
                .insert("PayloadDescription".to_string(), plist::Value::String(d));
        } else {
            self.additional_fields.remove("PayloadDescription");
        }
    }

    /// Get PayloadOrganization if present
    pub fn payload_organization(&self) -> Option<String> {
        self.additional_fields
            .get("PayloadOrganization")
            .and_then(|v| v.as_string().map(std::string::ToString::to_string))
    }

    /// Set PayloadOrganization
    pub fn set_payload_organization(&mut self, org: Option<String>) {
        if let Some(o) = org {
            self.additional_fields
                .insert("PayloadOrganization".to_string(), plist::Value::String(o));
        } else {
            self.additional_fields.remove("PayloadOrganization");
        }
    }

    /// Convert to plist Value for serialization
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn to_plist_value(&self) -> plist::Value {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "PayloadType".to_string(),
            plist::Value::String(self.payload_type.clone()),
        );
        dict.insert(
            "PayloadVersion".to_string(),
            plist::Value::Integer(self.payload_version.into()),
        );
        dict.insert(
            "PayloadIdentifier".to_string(),
            plist::Value::String(self.payload_identifier.clone()),
        );
        dict.insert(
            "PayloadUUID".to_string(),
            plist::Value::String(self.payload_uuid.clone()),
        );
        dict.insert(
            "PayloadDisplayName".to_string(),
            plist::Value::String(self.payload_display_name.clone()),
        );

        // Add payload content array
        let content_array: Vec<plist::Value> = self
            .payload_content
            .iter()
            .map(PayloadContent::to_plist_value)
            .collect();
        dict.insert(
            "PayloadContent".to_string(),
            plist::Value::Array(content_array),
        );

        // Add additional fields
        for (key, value) in &self.additional_fields {
            dict.insert(key.clone(), value.clone());
        }

        plist::Value::Dictionary(dict)
    }
}

/// Individual payload within a configuration profile.
///
/// Each payload configures a specific system feature (WiFi, VPN, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadContent {
    /// Payload type identifier (e.g., "com.apple.wifi.managed").
    #[serde(rename = "PayloadType")]
    pub payload_type: String,

    /// Payload version, always 1. Accepts both `<integer>` and `<real>` from plist.
    #[serde(
        rename = "PayloadVersion",
        deserialize_with = "deserialize_version",
        serialize_with = "serialize_version"
    )]
    pub payload_version: i32,

    /// Unique reverse-DNS identifier for this payload.
    #[serde(rename = "PayloadIdentifier")]
    pub payload_identifier: String,

    /// Unique identifier (UUID) for this payload.
    #[serde(rename = "PayloadUUID")]
    pub payload_uuid: String,

    /// Payload-specific configuration fields.
    #[serde(flatten)]
    pub content: HashMap<String, plist::Value>,
}

impl PayloadContent {
    /// Get PayloadDisplayName if present
    pub fn payload_display_name(&self) -> Option<String> {
        self.content
            .get("PayloadDisplayName")
            .and_then(|v| v.as_string().map(std::string::ToString::to_string))
    }

    /// Set PayloadOrganization
    pub fn set_payload_organization(&mut self, org: Option<String>) {
        if let Some(o) = org {
            self.content
                .insert("PayloadOrganization".to_string(), plist::Value::String(o));
        } else {
            self.content.remove("PayloadOrganization");
        }
    }

    /// Convert to plist Value for serialization
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn to_plist_value(&self) -> plist::Value {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "PayloadType".to_string(),
            plist::Value::String(self.payload_type.clone()),
        );
        dict.insert(
            "PayloadVersion".to_string(),
            plist::Value::Integer(self.payload_version.into()),
        );
        dict.insert(
            "PayloadIdentifier".to_string(),
            plist::Value::String(self.payload_identifier.clone()),
        );
        dict.insert(
            "PayloadUUID".to_string(),
            plist::Value::String(self.payload_uuid.clone()),
        );

        // Add all content fields
        for (key, value) in &self.content {
            dict.insert(key.clone(), value.clone());
        }

        plist::Value::Dictionary(dict)
    }
}
