//! JSON Schema Draft 2020-12 export for payload schemas
//!
//! Converts Form PayloadManifest definitions to JSON Schema format
//! for use in documentation, validation tools, and IDE autocomplete.

use crate::schema::{FieldDefinition, FieldType, PayloadManifest, SchemaRegistry};
use anyhow::Result;
use serde_json::{Map, Value, json};
use std::fs;
use std::path::Path;

/// Export schemas as JSON Schema Draft 2020-12
///
/// # Arguments
/// * `registry` - The schema registry to export from
/// * `output` - Output path (file for bundle, directory for split)
/// * `bundle` - If true, create single bundled file; if false, individual files
/// * `include_ddm` - Include DDM declaration schemas
/// * `category` - Optional category filter
///
/// # Returns
/// Number of schemas exported
pub fn export_json_schemas(
    registry: &SchemaRegistry,
    output: &Path,
    bundle: bool,
    include_ddm: bool,
    category: Option<&str>,
) -> Result<usize> {
    let manifests: Vec<_> = registry
        .all()
        .filter(|m| {
            // Filter by category if specified
            if let Some(cat) = category {
                if cat.starts_with("ddm-") {
                    m.category == cat
                } else if cat == "ddm" {
                    m.category.starts_with("ddm-")
                } else {
                    m.category == cat
                }
            } else {
                // By default, include DDM only if explicitly requested
                if m.category.starts_with("ddm-") {
                    include_ddm
                } else {
                    true
                }
            }
        })
        .collect();

    if bundle {
        // Create bundled schema with all definitions
        let bundled = create_bundled_schema(&manifests);
        fs::write(output, serde_json::to_string_pretty(&bundled)?)?;
        Ok(manifests.len())
    } else {
        // Create individual schema files
        fs::create_dir_all(output)?;

        for manifest in &manifests {
            let schema = manifest_to_json_schema(manifest);
            let filename = format!("{}.json", manifest.payload_type.replace('.', "-"));
            fs::write(
                output.join(&filename),
                serde_json::to_string_pretty(&schema)?,
            )?;
        }

        // Create index file
        let index = create_schema_index(&manifests);
        fs::write(
            output.join("index.json"),
            serde_json::to_string_pretty(&index)?,
        )?;

        Ok(manifests.len())
    }
}

/// Convert a PayloadManifest to JSON Schema
fn manifest_to_json_schema(manifest: &PayloadManifest) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();

    // Add standard payload fields
    properties.insert(
        "PayloadType".to_string(),
        json!({
            "type": "string",
            "const": manifest.payload_type,
            "description": "The payload type identifier"
        }),
    );
    required.push("PayloadType".to_string());

    properties.insert(
        "PayloadVersion".to_string(),
        json!({
            "type": "integer",
            "minimum": 1,
            "default": 1,
            "description": "The payload version number"
        }),
    );
    required.push("PayloadVersion".to_string());

    properties.insert(
        "PayloadIdentifier".to_string(),
        json!({
            "type": "string",
            "description": "A unique identifier for the payload (reverse DNS style)"
        }),
    );
    required.push("PayloadIdentifier".to_string());

    properties.insert(
        "PayloadUUID".to_string(),
        json!({
            "type": "string",
            "format": "uuid",
            "description": "A globally unique identifier for the payload"
        }),
    );
    required.push("PayloadUUID".to_string());

    properties.insert(
        "PayloadDisplayName".to_string(),
        json!({
            "type": "string",
            "description": "A human-readable name for the payload"
        }),
    );

    properties.insert(
        "PayloadDescription".to_string(),
        json!({
            "type": "string",
            "description": "A human-readable description of the payload"
        }),
    );

    properties.insert(
        "PayloadOrganization".to_string(),
        json!({
            "type": "string",
            "description": "The organization that created the payload"
        }),
    );

    // Add payload-specific fields
    for field_name in &manifest.field_order {
        if let Some(field) = manifest.fields.get(field_name) {
            // Skip deeply nested fields for top-level schema
            if field.depth > 0 {
                continue;
            }

            let field_schema = field_to_json_schema(field);
            properties.insert(field_name.clone(), field_schema);

            if field.flags.required {
                required.push(field_name.clone());
            }
        }
    }

    // Build the schema
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("https://apple.com/schemas/{}", manifest.payload_type),
        "title": manifest.title,
        "description": manifest.description,
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": true
    });

    // Add Apple-specific extensions
    let extensions = json!({
        "x-apple-payload-type": manifest.payload_type,
        "x-apple-category": manifest.category,
        "x-apple-platforms": manifest.platforms.to_vec(),
    });

    if let Some(obj) = schema.as_object_mut() {
        for (k, v) in extensions.as_object().unwrap() {
            obj.insert(k.clone(), v.clone());
        }
    }

    schema
}

/// Convert a FieldDefinition to JSON Schema property
fn field_to_json_schema(field: &FieldDefinition) -> Value {
    let mut schema = Map::new();

    // Map field type to JSON Schema type
    let (type_val, format) = match field.field_type {
        FieldType::String => (json!("string"), None),
        FieldType::Integer => (json!("integer"), None),
        FieldType::Boolean => (json!("boolean"), None),
        FieldType::Real => (json!("number"), None),
        FieldType::Array => (json!("array"), None),
        FieldType::Dictionary => (json!("object"), None),
        FieldType::Data => (json!("string"), Some("base64")),
        FieldType::Date => (json!("string"), Some("date-time")),
    };

    schema.insert("type".to_string(), type_val);

    if let Some(fmt) = format {
        if field.field_type == FieldType::Data {
            schema.insert("contentEncoding".to_string(), json!(fmt));
        } else {
            schema.insert("format".to_string(), json!(fmt));
        }
    }

    // Add description
    if !field.description.is_empty() {
        schema.insert("description".to_string(), json!(field.description));
    }

    // Add default value
    if let Some(ref default) = field.default {
        // Try to parse as appropriate type
        let default_val = match field.field_type {
            FieldType::Integer => default.parse::<i64>().ok().map(|v| json!(v)),
            FieldType::Real => default.parse::<f64>().ok().map(|v| json!(v)),
            FieldType::Boolean => match default.to_lowercase().as_str() {
                "true" | "yes" | "1" => Some(json!(true)),
                "false" | "no" | "0" => Some(json!(false)),
                _ => None,
            },
            _ => Some(json!(default)),
        };
        if let Some(val) = default_val {
            schema.insert("default".to_string(), val);
        }
    }

    // Add enum for allowed values
    if !field.allowed_values.is_empty() {
        schema.insert("enum".to_string(), json!(field.allowed_values));
    }

    // Add Apple-specific extensions
    if field.flags.sensitive {
        schema.insert("x-apple-sensitive".to_string(), json!(true));
    }
    if field.flags.supervised {
        schema.insert("x-apple-supervised".to_string(), json!(true));
    }
    if let Some(ref min_ver) = field.min_version {
        schema.insert("x-apple-min-version".to_string(), json!(min_ver));
    }
    if !field.platforms.is_empty() {
        let platforms: Vec<_> = field
            .platforms
            .iter()
            .map(super::types::Platform::as_str)
            .collect();
        schema.insert("x-apple-platforms".to_string(), json!(platforms));
    }

    Value::Object(schema)
}

/// Create a bundled schema with all definitions
fn create_bundled_schema(manifests: &[&PayloadManifest]) -> Value {
    let mut defs = Map::new();

    for manifest in manifests {
        let schema = manifest_to_json_schema(manifest);
        // Remove $schema and $id from individual schemas in bundle
        let mut schema_obj = schema.as_object().unwrap().clone();
        schema_obj.remove("$schema");
        schema_obj.remove("$id");

        let def_name = manifest.payload_type.replace('.', "_");
        defs.insert(def_name, Value::Object(schema_obj));
    }

    // Group by category for organization
    let categories: Vec<_> = manifests
        .iter()
        .map(|m| m.category.as_str())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://apple.com/schemas/configuration-profiles",
        "title": "Apple Configuration Profile Schemas",
        "description": format!("JSON Schema definitions for {} Apple configuration profile payload types", manifests.len()),
        "$defs": defs,
        "x-apple-schema-version": "1.0.0",
        "x-apple-categories": categories,
        "x-apple-total-schemas": manifests.len()
    })
}

/// Create an index file listing all schemas
fn create_schema_index(manifests: &[&PayloadManifest]) -> Value {
    let schemas: Vec<_> = manifests
        .iter()
        .map(|m| {
            json!({
                "payload_type": m.payload_type,
                "title": m.title,
                "category": m.category,
                "file": format!("{}.json", m.payload_type.replace('.', "-")),
                "platforms": m.platforms.to_vec(),
                "field_count": m.fields.len()
            })
        })
        .collect();

    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Apple Configuration Profile Schema Index",
        "description": format!("Index of {} JSON Schema files for Apple configuration profiles", manifests.len()),
        "schemas": schemas,
        "generated": chrono::Utc::now().to_rfc3339()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_manifest_to_json_schema() {
        let registry = SchemaRegistry::embedded().unwrap();
        let wifi = registry.get("com.apple.wifi.managed").unwrap();
        let schema = manifest_to_json_schema(wifi);

        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["title"], "Wi-Fi");
        assert!(schema["properties"]["PayloadType"].is_object());
        assert!(schema["properties"]["SSID_STR"].is_object());
    }

    #[test]
    fn test_export_individual_files() {
        let registry = SchemaRegistry::embedded().unwrap();
        let dir = tempdir().unwrap();

        let count = export_json_schemas(
            &registry,
            dir.path(),
            false, // not bundled
            false, // no DDM
            Some("apple"),
        )
        .unwrap();

        assert!(count > 0);
        assert!(dir.path().join("index.json").exists());
        assert!(dir.path().join("com-apple-wifi-managed.json").exists());
    }

    #[test]
    fn test_export_bundled() {
        let registry = SchemaRegistry::embedded().unwrap();
        let dir = tempdir().unwrap();
        let output = dir.path().join("all.json");

        let count = export_json_schemas(
            &registry, &output, true,  // bundled
            false, // no DDM
            None,
        )
        .unwrap();

        assert!(count > 0);
        assert!(output.exists());

        let content = fs::read_to_string(&output).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        assert!(parsed["$defs"].is_object());
    }

    #[test]
    fn test_field_type_mapping() {
        use crate::schema::types::FieldFlags;

        // Test string field
        let string_field = FieldDefinition {
            name: "TestString".to_string(),
            field_type: FieldType::String,
            flags: FieldFlags::default(),
            title: "Test".to_string(),
            description: "A test field".to_string(),
            default: Some("default".to_string()),
            allowed_values: vec![],
            depth: 0,
            parent_key: None,
            platforms: vec![],
            min_version: None,
        };
        let schema = field_to_json_schema(&string_field);
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["default"], "default");

        // Test data field (base64)
        let data_field = FieldDefinition {
            name: "TestData".to_string(),
            field_type: FieldType::Data,
            flags: FieldFlags::default(),
            title: "Test".to_string(),
            description: "Binary data".to_string(),
            default: None,
            allowed_values: vec![],
            depth: 0,
            parent_key: None,
            platforms: vec![],
            min_version: None,
        };
        let schema = field_to_json_schema(&data_field);
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["contentEncoding"], "base64");

        // Test date field
        let date_field = FieldDefinition {
            name: "TestDate".to_string(),
            field_type: FieldType::Date,
            flags: FieldFlags::default(),
            title: "Test".to_string(),
            description: "A date".to_string(),
            default: None,
            allowed_values: vec![],
            depth: 0,
            parent_key: None,
            platforms: vec![],
            min_version: None,
        };
        let schema = field_to_json_schema(&date_field);
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["format"], "date-time");
    }
}
