use anyhow::{Context, Result};
use plist::Value;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Extract basic information from a mobileconfig file
pub fn extract_basic_info(path: &Path) -> Result<(Option<String>, Option<String>)> {
    let file = File::open(path).context("Failed to open mobileconfig file")?;
    let reader = BufReader::new(file);

    let plist: Value = plist::from_reader(reader).context("Failed to parse mobileconfig plist")?;

    let payload_identifier = extract_string_value(&plist, "PayloadIdentifier");
    let payload_type = extract_string_value(&plist, "PayloadType");

    Ok((payload_identifier, payload_type))
}

/// Extract a string value from a plist Value
fn extract_string_value(plist: &Value, key: &str) -> Option<String> {
    if let Value::Dictionary(dict) = plist {
        dict.get(key).and_then(|v| {
            if let Value::String(s) = v {
                Some(s.clone())
            } else {
                None
            }
        })
    } else {
        None
    }
}

/// Parse full mobileconfig content (detailed extraction)
#[allow(dead_code, reason = "reserved for future use")]
pub fn parse_mobileconfig(path: &Path) -> Result<crate::models::MobileConfigContent> {
    let file = File::open(path).context("Failed to open mobileconfig file")?;
    let reader = BufReader::new(file);

    let plist: Value = plist::from_reader(reader).context("Failed to parse mobileconfig plist")?;

    if let Value::Dictionary(dict) = plist {
        let payload_identifier =
            extract_string_value(&Value::Dictionary(dict.clone()), "PayloadIdentifier")
                .unwrap_or_else(|| "unknown".to_string());
        let payload_type = extract_string_value(&Value::Dictionary(dict.clone()), "PayloadType")
            .unwrap_or_else(|| "Configuration".to_string());
        let payload_uuid = extract_string_value(&Value::Dictionary(dict.clone()), "PayloadUUID")
            .unwrap_or_else(|| "unknown".to_string());
        let payload_display_name =
            extract_string_value(&Value::Dictionary(dict.clone()), "PayloadDisplayName");
        let payload_description =
            extract_string_value(&Value::Dictionary(dict.clone()), "PayloadDescription");
        let payload_organization =
            extract_string_value(&Value::Dictionary(dict.clone()), "PayloadOrganization");

        // Extract PayloadContent array
        let payload_content = if let Some(Value::Array(content)) = dict.get("PayloadContent") {
            content.iter().filter_map(parse_payload_item).collect()
        } else {
            Vec::new()
        };

        Ok(crate::models::MobileConfigContent {
            payload_identifier,
            payload_type,
            payload_uuid,
            payload_display_name,
            payload_description,
            payload_organization,
            payload_content,
        })
    } else {
        anyhow::bail!("Invalid mobileconfig format: root is not a dictionary");
    }
}

/// Parse a single payload item
#[allow(dead_code, reason = "reserved for future use")]
fn parse_payload_item(value: &Value) -> Option<crate::models::PayloadItem> {
    if let Value::Dictionary(dict) = value {
        let payload_type = extract_string_value(&Value::Dictionary(dict.clone()), "PayloadType")?;
        let payload_identifier =
            extract_string_value(&Value::Dictionary(dict.clone()), "PayloadIdentifier")?;
        let payload_uuid = extract_string_value(&Value::Dictionary(dict.clone()), "PayloadUUID")?;
        let payload_display_name =
            extract_string_value(&Value::Dictionary(dict.clone()), "PayloadDisplayName");

        // Convert the entire dict to JSON for easy storage
        let payload_content = plist_to_json(value);

        Some(crate::models::PayloadItem {
            payload_type,
            payload_identifier,
            payload_uuid,
            payload_display_name,
            payload_content,
        })
    } else {
        None
    }
}

/// Convert plist Value to `serde_json::Value`
#[allow(dead_code, reason = "reserved for future use")]
fn plist_to_json(plist: &Value) -> serde_json::Value {
    match plist {
        Value::Boolean(b) => serde_json::Value::Bool(*b),
        Value::Integer(i) => {
            if let Some(signed) = i.as_signed() {
                serde_json::Value::Number(signed.into())
            } else if let Some(unsigned) = i.as_unsigned() {
                serde_json::Value::Number(unsigned.into())
            } else {
                serde_json::Value::Null
            }
        }
        Value::Real(f) => serde_json::Number::from_f64(*f)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Array(arr) => serde_json::Value::Array(arr.iter().map(plist_to_json).collect()),
        Value::Dictionary(dict) => {
            let map: serde_json::Map<String, serde_json::Value> = dict
                .iter()
                .map(|(k, v)| (k.clone(), plist_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        }
        Value::Data(data) => {
            // Convert data to base64 string
            serde_json::Value::String(base64_encode(data))
        }
        Value::Date(date) => serde_json::Value::String(format!("{date:?}")),
        _ => serde_json::Value::Null,
    }
}

/// Simple base64 encoding
#[allow(dead_code, reason = "reserved for future use")]
fn base64_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::new();
    for byte in data {
        write!(&mut result, "{byte:02x}").unwrap();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plist_to_json() {
        let plist = Value::Boolean(true);
        let json = plist_to_json(&plist);
        assert_eq!(json, serde_json::Value::Bool(true));
    }
}
