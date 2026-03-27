//! DDM declaration parser
//!
//! Parse and write DDM declarations in JSON format.

use super::types::Declaration;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Parse a DDM declaration from JSON string
pub fn parse_declaration(json: &str) -> Result<Declaration> {
    serde_json::from_str(json).context("Failed to parse DDM declaration JSON")
}

/// Parse a DDM declaration from a file
pub fn parse_declaration_file(path: &Path) -> Result<Declaration> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read DDM file: {}", path.display()))?;

    parse_declaration(&contents)
}

/// Write a DDM declaration to JSON string
pub fn write_declaration(decl: &Declaration) -> Result<String> {
    serde_json::to_string_pretty(decl).context("Failed to serialize DDM declaration")
}

/// Write a DDM declaration to a file
pub fn write_declaration_file(decl: &Declaration, path: &Path) -> Result<()> {
    let json = write_declaration(decl)?;
    fs::write(path, json).with_context(|| format!("Failed to write DDM file: {}", path.display()))
}

/// Parse multiple declarations from a JSON array
pub fn parse_declarations(json: &str) -> Result<Vec<Declaration>> {
    serde_json::from_str(json).context("Failed to parse DDM declarations array")
}

/// Check if a file is likely a DDM declaration (JSON with Type field)
pub fn is_ddm_file(path: &Path) -> bool {
    if let Ok(contents) = fs::read_to_string(path) {
        // Quick check for DDM-like structure
        contents.contains("\"Type\"")
            && contents.contains("\"Identifier\"")
            && contents.contains("\"Payload\"")
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ========== Parse Declaration Tests ==========

    #[test]
    fn test_parse_declaration() {
        let json = r#"{
            "Type": "com.apple.configuration.passcode.settings",
            "Identifier": "com.example.passcode",
            "Payload": {
                "RequirePasscode": true,
                "MinimumLength": 8
            }
        }"#;

        let decl = parse_declaration(json).unwrap();
        assert_eq!(
            decl.declaration_type,
            "com.apple.configuration.passcode.settings"
        );
        assert_eq!(decl.identifier, "com.example.passcode");
        assert!(decl.payload.get("RequirePasscode").is_some());
    }

    #[test]
    fn test_parse_declaration_minimal() {
        let json = r#"{
            "Type": "com.apple.configuration.test",
            "Identifier": "minimal",
            "Payload": {}
        }"#;

        let decl = parse_declaration(json).unwrap();
        assert_eq!(decl.declaration_type, "com.apple.configuration.test");
        assert!(decl.payload.is_empty());
    }

    #[test]
    fn test_parse_declaration_with_server_token() {
        let json = r#"{
            "Type": "com.apple.configuration.test",
            "Identifier": "test",
            "ServerToken": "token123",
            "Payload": {}
        }"#;

        let decl = parse_declaration(json).unwrap();
        assert_eq!(decl.server_token, Some("token123".to_string()));
    }

    #[test]
    fn test_parse_declaration_invalid_json() {
        let result = parse_declaration("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_declaration_missing_type() {
        let json = r#"{
            "Identifier": "test",
            "Payload": {}
        }"#;
        let result = parse_declaration(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_declaration_missing_identifier() {
        let json = r#"{
            "Type": "com.apple.configuration.test",
            "Payload": {}
        }"#;
        let result = parse_declaration(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_declaration_missing_payload() {
        let json = r#"{
            "Type": "com.apple.configuration.test",
            "Identifier": "test"
        }"#;
        let result = parse_declaration(json);
        assert!(result.is_err());
    }

    // ========== Write Declaration Tests ==========

    #[test]
    fn test_write_declaration() {
        let mut decl = Declaration::new(
            "com.apple.configuration.passcode.settings",
            "com.example.passcode",
        );
        decl.payload
            .insert("RequirePasscode".to_string(), serde_json::json!(true));
        decl.payload
            .insert("MinimumLength".to_string(), serde_json::json!(8));

        let json = write_declaration(&decl).unwrap();
        assert!(json.contains("com.apple.configuration.passcode.settings"));
        assert!(json.contains("RequirePasscode"));
    }

    #[test]
    fn test_write_declaration_pretty_formatted() {
        let decl = Declaration::new("com.apple.configuration.test", "test.id");
        let json = write_declaration(&decl).unwrap();

        // Pretty format should have newlines
        assert!(json.contains('\n'));
    }

    #[test]
    fn test_write_declaration_empty_payload() {
        let decl = Declaration::new("com.apple.configuration.test", "test.id");
        let json = write_declaration(&decl).unwrap();
        assert!(json.contains("\"Payload\": {}"));
    }

    // ========== Roundtrip Tests ==========

    #[test]
    fn test_roundtrip() {
        let original = r#"{
            "Type": "com.apple.configuration.passcode.settings",
            "Identifier": "test.id",
            "ServerToken": "abc123",
            "Payload": {
                "RequirePasscode": true,
                "MinimumLength": 10,
                "MaximumFailedAttempts": 5
            }
        }"#;

        let decl = parse_declaration(original).unwrap();
        let output = write_declaration(&decl).unwrap();
        let reparsed = parse_declaration(&output).unwrap();

        assert_eq!(decl.declaration_type, reparsed.declaration_type);
        assert_eq!(decl.identifier, reparsed.identifier);
        assert_eq!(decl.server_token, reparsed.server_token);
    }

    #[test]
    fn test_roundtrip_complex_payload() {
        let mut decl = Declaration::new("com.apple.configuration.wifi", "wifi.config");
        decl.payload
            .insert("SSID".to_string(), serde_json::json!("MyNetwork"));
        decl.payload
            .insert("AutoJoin".to_string(), serde_json::json!(true));
        decl.payload
            .insert("EncryptionType".to_string(), serde_json::json!("WPA2"));
        decl.payload.insert(
            "ProxySettings".to_string(),
            serde_json::json!({
                "ProxyType": "Auto",
                "ProxyPACURL": "http://proxy.example.com/proxy.pac"
            }),
        );

        let json = write_declaration(&decl).unwrap();
        let reparsed = parse_declaration(&json).unwrap();

        assert_eq!(
            reparsed.payload.get("SSID"),
            Some(&serde_json::json!("MyNetwork"))
        );
        assert!(reparsed.payload.get("ProxySettings").is_some());
    }

    // ========== File Operations Tests ==========

    #[test]
    fn test_parse_declaration_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.json");

        let json = r#"{
            "Type": "com.apple.configuration.test",
            "Identifier": "file.test",
            "Payload": {"Key": "Value"}
        }"#;
        std::fs::write(&file_path, json).unwrap();

        let decl = parse_declaration_file(&file_path).unwrap();
        assert_eq!(decl.identifier, "file.test");
    }

    #[test]
    fn test_parse_declaration_file_not_found() {
        let result = parse_declaration_file(Path::new("/nonexistent/path/file.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_write_declaration_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("output.json");

        let decl = Declaration::new("com.apple.configuration.test", "write.test");
        write_declaration_file(&decl, &file_path).unwrap();

        // Read back and verify
        let contents = std::fs::read_to_string(&file_path).unwrap();
        assert!(contents.contains("com.apple.configuration.test"));
        assert!(contents.contains("write.test"));
    }

    // ========== Multiple Declarations Tests ==========

    #[test]
    fn test_parse_declarations_array() {
        let json = r#"[
            {
                "Type": "com.apple.configuration.test1",
                "Identifier": "first",
                "Payload": {}
            },
            {
                "Type": "com.apple.configuration.test2",
                "Identifier": "second",
                "Payload": {}
            }
        ]"#;

        let declarations = parse_declarations(json).unwrap();
        assert_eq!(declarations.len(), 2);
        assert_eq!(declarations[0].identifier, "first");
        assert_eq!(declarations[1].identifier, "second");
    }

    #[test]
    fn test_parse_declarations_empty_array() {
        let json = "[]";
        let declarations = parse_declarations(json).unwrap();
        assert!(declarations.is_empty());
    }

    #[test]
    fn test_parse_declarations_invalid() {
        let result = parse_declarations("not an array");
        assert!(result.is_err());
    }

    // ========== DDM File Detection Tests ==========

    #[test]
    fn test_is_ddm_file_valid() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("valid.json");

        let json = r#"{
            "Type": "com.apple.configuration.test",
            "Identifier": "test",
            "Payload": {}
        }"#;
        std::fs::write(&file_path, json).unwrap();

        assert!(is_ddm_file(&file_path));
    }

    #[test]
    fn test_is_ddm_file_missing_type() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("no_type.json");

        let json = r#"{
            "Identifier": "test",
            "Payload": {}
        }"#;
        std::fs::write(&file_path, json).unwrap();

        assert!(!is_ddm_file(&file_path));
    }

    #[test]
    fn test_is_ddm_file_missing_identifier() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("no_id.json");

        let json = r#"{
            "Type": "com.apple.configuration.test",
            "Payload": {}
        }"#;
        std::fs::write(&file_path, json).unwrap();

        assert!(!is_ddm_file(&file_path));
    }

    #[test]
    fn test_is_ddm_file_nonexistent() {
        assert!(!is_ddm_file(Path::new("/nonexistent/file.json")));
    }

    #[test]
    fn test_is_ddm_file_not_json() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("not_json.txt");

        std::fs::write(&file_path, "This is not JSON").unwrap();

        assert!(!is_ddm_file(&file_path));
    }
}
