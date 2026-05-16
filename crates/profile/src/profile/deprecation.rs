//! Deprecation scanning — the single detection path for deprecated
//! payload types and deprecated keys. Shared by `profile scan`, the
//! `lint` module, and `plan`.
//!
//! Detection walks the parsed `plist::Value` tree (same shape the
//! `lint` module uses) and produces structured `DeprecationFinding`s.
//! Two sources:
//!   - payload types: `MigrationRegistry` (legacy MDM type with a DDM
//!     replacement — breaks on macOS 26+)
//!   - keys: `SchemaRegistry` `FieldDefinition.deprecated_in` (Apple
//!     deprecated the key; it still works)

use crate::migrate::mapping::{MigrationRegistry, MigrationStatus};
use crate::schema::SchemaRegistry;
use plist::Value;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Whether a finding is about a whole payload type or a single key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DeprecationKind {
    PayloadType,
    Key,
}

/// Severity of a deprecation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DeprecationSeverity {
    /// Stops working on a future OS (deprecated payload type).
    Critical,
    /// Still works; Apple flagged it for eventual removal.
    Warning,
}

/// One deprecated element found in a profile.
#[derive(Debug, Clone, Serialize)]
pub struct DeprecationFinding {
    pub kind: DeprecationKind,
    /// Index into the outer `PayloadContent`; `None` for the envelope.
    pub payload_index: Option<usize>,
    pub payload_type: String,
    /// `com.apple.softwareupdate` or `com.apple.foo.SomeKey`.
    pub locator: String,
    /// OS version the element was deprecated in, when known.
    pub deprecated_in: Option<String>,
    /// DDM replacement type or successor key, when known.
    pub replacement: Option<String>,
    pub detail: String,
    pub severity: DeprecationSeverity,
}

/// Scan a parsed profile tree for deprecated payload types only.
/// No schema needed — `lint`'s `deprecated-payload-type` check and
/// `plan` reuse this directly.
pub fn scan_payload_types(value: &Value, migration: &MigrationRegistry) -> Vec<DeprecationFinding> {
    let mut findings = Vec::new();
    walk_payload_types(value, None, migration, &mut findings);
    findings
}

fn walk_payload_types(
    value: &Value,
    idx: Option<usize>,
    migration: &MigrationRegistry,
    out: &mut Vec<DeprecationFinding>,
) {
    let Value::Dictionary(dict) = value else {
        return;
    };
    if let Some(pt) = dict.get("PayloadType").and_then(Value::as_string)
        && let Some(mapping) = migration.get(pt)
        && matches!(
            mapping.status,
            MigrationStatus::Available | MigrationStatus::Partial
        )
    {
        let scope = idx.map_or("Profile".to_string(), |i| format!("PayloadContent[{i}]"));
        out.push(DeprecationFinding {
            kind: DeprecationKind::PayloadType,
            payload_index: idx,
            payload_type: pt.to_string(),
            locator: pt.to_string(),
            deprecated_in: Some("macOS 26".to_string()),
            replacement: Some(mapping.ddm_type.to_string()),
            detail: format!(
                "{scope}: PayloadType {pt:?} has a DDM replacement \
                 ({ddm:?}, status={status:?}); legacy payload still works on \
                 macOS \u{2264}25 but stops working on macOS 26+. {notes}",
                ddm = mapping.ddm_type,
                status = mapping.status,
                notes = mapping.notes,
            ),
            severity: DeprecationSeverity::Critical,
        });
    }
    if let Some(Value::Array(items)) = dict.get("PayloadContent") {
        for (i, item) in items.iter().enumerate() {
            walk_payload_types(item, Some(i), migration, out);
        }
    }
}

/// Scan a parsed profile tree for deprecated keys. A key is deprecated
/// when its `FieldDefinition` in the payload's schema manifest carries
/// a `deprecated_in` version.
pub fn scan_keys(value: &Value, schema: &SchemaRegistry) -> Vec<DeprecationFinding> {
    let mut findings = Vec::new();
    walk_keys(value, None, schema, &mut findings);
    findings
}

fn walk_keys(
    value: &Value,
    idx: Option<usize>,
    schema: &SchemaRegistry,
    out: &mut Vec<DeprecationFinding>,
) {
    let Value::Dictionary(dict) = value else {
        return;
    };
    if let Some(pt) = dict.get("PayloadType").and_then(Value::as_string)
        && let Some(manifest) = schema.get(pt)
    {
        let scope = idx.map_or("Profile".to_string(), |i| format!("PayloadContent[{i}]"));
        for key in dict.keys() {
            if let Some(field) = manifest.fields.get(key)
                && let Some(dep) = &field.deprecated_in
            {
                out.push(DeprecationFinding {
                    kind: DeprecationKind::Key,
                    payload_index: idx,
                    payload_type: pt.to_string(),
                    locator: format!("{pt}.{key}"),
                    deprecated_in: Some(dep.clone()),
                    replacement: None,
                    detail: format!(
                        "{scope}: key {key:?} in {pt:?} was deprecated by Apple \
                         in {dep}; it still works but is scheduled for removal."
                    ),
                    severity: DeprecationSeverity::Warning,
                });
            }
        }
    }
    if let Some(Value::Array(items)) = dict.get("PayloadContent") {
        for (i, item) in items.iter().enumerate() {
            walk_keys(item, Some(i), schema, out);
        }
    }
}

/// All deprecation findings for a single profile file.
#[derive(Debug, Clone, Serialize)]
pub struct DeprecationReport {
    pub path: PathBuf,
    pub findings: Vec<DeprecationFinding>,
}

impl DeprecationReport {
    pub fn for_file(path: &Path, findings: Vec<DeprecationFinding>) -> Self {
        Self {
            path: path.to_path_buf(),
            findings,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn critical_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == DeprecationSeverity::Critical)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == DeprecationSeverity::Warning)
            .count()
    }
}

/// Scan a profile for every known deprecation — payload types and keys —
/// and wrap the findings in a `DeprecationReport` for `path`. This is the
/// entry point `profile scan` uses.
pub fn scan_deprecations(
    value: &Value,
    path: &Path,
    migration: &MigrationRegistry,
    schema: &SchemaRegistry,
) -> DeprecationReport {
    let mut findings = scan_payload_types(value, migration);
    findings.extend(scan_keys(value, schema));
    DeprecationReport::for_file(path, findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(payload_type: &str) -> Value {
        let mut p = plist::Dictionary::new();
        p.insert("PayloadType".into(), Value::String(payload_type.into()));
        p.insert(
            "PayloadIdentifier".into(),
            Value::String("com.test.p".into()),
        );
        p.insert(
            "PayloadUUID".into(),
            Value::String("B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E".into()),
        );
        p.insert("PayloadVersion".into(), Value::Integer(1.into()));
        Value::Dictionary(p)
    }

    fn payload_with_key(payload_type: &str, key: &str) -> Value {
        let Value::Dictionary(mut p) = payload(payload_type) else {
            unreachable!()
        };
        p.insert(key.into(), Value::Boolean(true));
        Value::Dictionary(p)
    }

    fn profile(payloads: Vec<Value>) -> Value {
        let mut d = plist::Dictionary::new();
        d.insert("PayloadType".into(), Value::String("Configuration".into()));
        d.insert("PayloadContent".into(), Value::Array(payloads));
        Value::Dictionary(d)
    }

    /// Resolve a (payload_type, key) pair the embedded schema marks
    /// deprecated, so tests are not pinned to a specific Apple key.
    fn first_deprecated_key() -> Option<(String, String)> {
        let schema = SchemaRegistry::embedded().ok()?;
        for manifest in schema.all() {
            for (name, field) in &manifest.fields {
                if field.deprecated_in.is_some() {
                    return Some((manifest.payload_type.clone(), name.clone()));
                }
            }
        }
        None
    }

    #[test]
    fn deprecated_payload_type_is_flagged_critical() {
        let migration = MigrationRegistry::new();
        let v = profile(vec![payload("com.apple.SoftwareUpdate")]);
        let findings = scan_payload_types(&v, &migration);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, DeprecationKind::PayloadType);
        assert_eq!(findings[0].severity, DeprecationSeverity::Critical);
        assert_eq!(findings[0].payload_index, Some(0));
    }

    #[test]
    fn unknown_payload_type_is_not_flagged() {
        let migration = MigrationRegistry::new();
        let v = profile(vec![payload("com.example.private.thing")]);
        assert!(scan_payload_types(&v, &migration).is_empty());
    }

    #[test]
    fn deprecated_key_is_flagged_warning() {
        let schema = SchemaRegistry::embedded().expect("embedded schema");
        let Some((payload_type, key)) = first_deprecated_key() else {
            return; // no deprecated keys in schema build — nothing to assert
        };
        let v = profile(vec![payload_with_key(&payload_type, &key)]);
        let findings = scan_keys(&v, &schema);
        let hit = findings
            .iter()
            .find(|f| f.locator == format!("{payload_type}.{key}"))
            .expect("deprecated key should be flagged");
        assert_eq!(hit.kind, DeprecationKind::Key);
        assert_eq!(hit.severity, DeprecationSeverity::Warning);
        assert_eq!(hit.payload_index, Some(0));
    }

    #[test]
    fn clean_profile_has_no_findings() {
        // A payload type unknown to both registries — guaranteed no
        // payload-type finding and no schema manifest, so no key findings.
        let migration = MigrationRegistry::new();
        let schema = SchemaRegistry::embedded().expect("embedded schema");
        let v = profile(vec![payload("com.example.private.thing")]);
        assert!(scan_payload_types(&v, &migration).is_empty());
        assert!(scan_keys(&v, &schema).is_empty());
    }
}
