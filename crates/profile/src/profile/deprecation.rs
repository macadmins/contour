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
use crate::schema::{Platform, SchemaRegistry};
use plist::Value;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Whether a finding is about a whole payload type or a single key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DeprecationKind {
    PayloadType,
    Key,
    /// Payload type hard-removed on a target OS — it no longer installs.
    /// Sourced from `os_support[macOS].removed`, populated by the
    /// posture-ingest pipeline for the seed/beta schema.
    RemovedPayloadType,
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
    /// OS version the element was *removed* in (no longer installs), when known.
    /// Set only for [`DeprecationKind::RemovedPayloadType`].
    pub removed_in: Option<String>,
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
            removed_in: None,
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
                    removed_in: None,
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

/// Scan a parsed profile tree for payload types the schema marks as **removed**
/// on macOS — i.e. the type no longer installs (stronger than deprecation, which
/// still works). The signal is `os_support[macOS].removed`, populated by the
/// posture-ingest pipeline for the seed/beta schema. With the released (stable)
/// schema this returns nothing; pass a beta registry to detect seed removals.
pub fn scan_removed_payload_types(
    value: &Value,
    schema: &SchemaRegistry,
) -> Vec<DeprecationFinding> {
    let mut findings = Vec::new();
    walk_removed(value, None, schema, &mut findings);
    findings
}

fn walk_removed(
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
        && let Some(removed) = manifest
            .os_support
            .get(&Platform::MacOS)
            .and_then(|d| d.removed.as_ref())
    {
        let scope = idx.map_or("Profile".to_string(), |i| format!("PayloadContent[{i}]"));
        out.push(DeprecationFinding {
            kind: DeprecationKind::RemovedPayloadType,
            payload_index: idx,
            payload_type: pt.to_string(),
            locator: pt.to_string(),
            deprecated_in: None,
            removed_in: Some(removed.clone()),
            replacement: None,
            detail: format!(
                "{scope}: PayloadType {pt:?} was REMOVED in {removed} — it no longer \
                 installs on that OS or later. Migrate off this payload before upgrading."
            ),
            severity: DeprecationSeverity::Critical,
        });
    }
    if let Some(Value::Array(items)) = dict.get("PayloadContent") {
        for (i, item) in items.iter().enumerate() {
            walk_removed(item, Some(i), schema, out);
        }
    }
}

/// Scan a parsed profile tree for payload types the schema marks **deprecated**
/// on any platform (`os_support[*].deprecated`). Deprecated payloads still
/// install but Apple has flagged them for removal — weaker than
/// [`scan_removed_payload_types`]. Works on both channels: the stable schema
/// carries existing deprecations (e.g. iOS-era payloads); a beta registry adds
/// the seed/OS-27 ones (e.g. `AssetCache.managed` deprecated 27.0).
pub fn scan_deprecated_payload_types(
    value: &Value,
    schema: &SchemaRegistry,
) -> Vec<DeprecationFinding> {
    let mut findings = Vec::new();
    walk_deprecated(value, None, schema, &mut findings);
    findings
}

fn walk_deprecated(
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
        // Collect every platform that carries a deprecation marker, in a
        // deterministic order (HashMap iteration order is otherwise unstable).
        let mut deps: Vec<(String, String)> = manifest
            .os_support
            .iter()
            .filter_map(|(p, d)| d.deprecated.as_ref().map(|v| (format!("{p:?}"), v.clone())))
            .collect();
        deps.sort();
        if !deps.is_empty() {
            let scope = idx.map_or("Profile".to_string(), |i| format!("PayloadContent[{i}]"));
            let platforms = deps
                .iter()
                .map(|(p, v)| format!("{p} {v}"))
                .collect::<Vec<_>>()
                .join(", ");
            let earliest = deps.iter().map(|(_, v)| v.clone()).min();
            out.push(DeprecationFinding {
                kind: DeprecationKind::PayloadType,
                payload_index: idx,
                payload_type: pt.to_string(),
                locator: pt.to_string(),
                deprecated_in: earliest,
                removed_in: None,
                replacement: None,
                detail: format!(
                    "{scope}: PayloadType {pt:?} is deprecated by Apple ({platforms}); \
                     it still installs but is scheduled for removal."
                ),
                severity: DeprecationSeverity::Warning,
            });
        }
    }
    if let Some(Value::Array(items)) = dict.get("PayloadContent") {
        for (i, item) in items.iter().enumerate() {
            walk_deprecated(item, Some(i), schema, out);
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
    // Three payload-type-level sources can flag the same payload: the migration
    // registry (legacy→DDM), the schema's `removed` marker, and the schema's
    // `deprecated` marker. Collect all, then keep the strongest signal per
    // payload so a single payload isn't reported two or three times.
    let mut payload_level = scan_payload_types(value, migration);
    payload_level.extend(scan_removed_payload_types(value, schema));
    payload_level.extend(scan_deprecated_payload_types(value, schema));

    let mut findings = dedup_payload_findings(payload_level);
    findings.extend(scan_keys(value, schema));
    DeprecationReport::for_file(path, findings)
}

/// Keep one payload-type-level finding per `(payload_index, payload_type)`,
/// preferring the strongest signal: removed > migration (critical) > schema
/// deprecation (warning). Key findings are handled separately and untouched.
fn dedup_payload_findings(findings: Vec<DeprecationFinding>) -> Vec<DeprecationFinding> {
    fn rank(f: &DeprecationFinding) -> u8 {
        match (f.kind, f.severity) {
            (DeprecationKind::RemovedPayloadType, _) => 3,
            (DeprecationKind::PayloadType, DeprecationSeverity::Critical) => 2,
            (DeprecationKind::PayloadType, DeprecationSeverity::Warning) => 1,
            _ => 0,
        }
    }
    let mut best: Vec<DeprecationFinding> = Vec::new();
    for f in findings {
        if let Some(existing) = best
            .iter_mut()
            .find(|e| e.payload_index == f.payload_index && e.payload_type == f.payload_type)
        {
            if rank(&f) > rank(existing) {
                *existing = f;
            }
        } else {
            best.push(f);
        }
    }
    best
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

    /// Build a one-payload registry whose macOS `removed` slot is populated —
    /// mirrors what posture-ingest will emit for a seed-removed payload type.
    fn registry_with_removed(payload_type: &str, removed_ver: &str) -> SchemaRegistry {
        use crate::schema::types::{OsSupportDetail, PayloadManifest, Platforms};
        let mut os_support = std::collections::HashMap::new();
        os_support.insert(
            Platform::MacOS,
            OsSupportDetail {
                removed: Some(removed_ver.to_string()),
                ..Default::default()
            },
        );
        let manifest = PayloadManifest {
            payload_type: payload_type.to_string(),
            title: payload_type.to_string(),
            description: String::new(),
            platforms: Platforms::parse("*"),
            min_versions: std::collections::HashMap::new(),
            os_support,
            apply_mode: None,
            category: "apple".to_string(),
            fields: std::collections::HashMap::new(),
            field_order: vec![],
            segments: vec![],
        };
        SchemaRegistry::from_manifests_for_test(vec![manifest])
    }

    #[test]
    fn removed_payload_type_is_flagged() {
        let schema = registry_with_removed("com.apple.system.logging", "26.0");
        let v = profile(vec![payload("com.apple.system.logging")]);
        let findings = scan_removed_payload_types(&v, &schema);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, DeprecationKind::RemovedPayloadType);
        assert_eq!(findings[0].severity, DeprecationSeverity::Critical);
        assert_eq!(findings[0].removed_in.as_deref(), Some("26.0"));
        assert_eq!(findings[0].payload_index, Some(0));
    }

    /// One-payload registry whose macOS `deprecated` slot is populated.
    fn registry_with_deprecated(payload_type: &str, dep_ver: &str) -> SchemaRegistry {
        use crate::schema::types::{OsSupportDetail, PayloadManifest, Platforms};
        let mut os_support = std::collections::HashMap::new();
        os_support.insert(
            Platform::MacOS,
            OsSupportDetail {
                deprecated: Some(dep_ver.to_string()),
                ..Default::default()
            },
        );
        let manifest = PayloadManifest {
            payload_type: payload_type.to_string(),
            title: payload_type.to_string(),
            description: String::new(),
            platforms: Platforms::parse("*"),
            min_versions: std::collections::HashMap::new(),
            os_support,
            apply_mode: None,
            category: "apple".to_string(),
            fields: std::collections::HashMap::new(),
            field_order: vec![],
            segments: vec![],
        };
        SchemaRegistry::from_manifests_for_test(vec![manifest])
    }

    #[test]
    fn deprecated_payload_type_is_flagged_warning() {
        let schema = registry_with_deprecated("com.apple.AssetCache.managed", "27.0");
        let v = profile(vec![payload("com.apple.AssetCache.managed")]);
        let findings = scan_deprecated_payload_types(&v, &schema);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, DeprecationKind::PayloadType);
        assert_eq!(findings[0].severity, DeprecationSeverity::Warning);
        assert_eq!(findings[0].deprecated_in.as_deref(), Some("27.0"));
        assert_eq!(findings[0].payload_index, Some(0));
    }

    #[test]
    fn removed_wins_over_deprecated_for_same_payload() {
        // A payload marked BOTH removed and deprecated should yield ONE finding
        // (the stronger "removed"), not two.
        use crate::schema::types::{OsSupportDetail, PayloadManifest, Platforms};
        let mut os_support = std::collections::HashMap::new();
        os_support.insert(
            Platform::MacOS,
            OsSupportDetail {
                deprecated: Some("26.0".to_string()),
                removed: Some("27.0".to_string()),
                ..Default::default()
            },
        );
        let schema = SchemaRegistry::from_manifests_for_test(vec![PayloadManifest {
            payload_type: "com.apple.SoftwareUpdate".to_string(),
            title: "SoftwareUpdate".to_string(),
            description: String::new(),
            platforms: Platforms::parse("*"),
            min_versions: std::collections::HashMap::new(),
            os_support,
            apply_mode: None,
            category: "apple".to_string(),
            fields: std::collections::HashMap::new(),
            field_order: vec![],
            segments: vec![],
        }]);
        let v = profile(vec![payload("com.apple.SoftwareUpdate")]);
        let report = scan_deprecations(
            &v,
            Path::new("t.mobileconfig"),
            &MigrationRegistry::new(),
            &schema,
        );
        let pt: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.payload_type == "com.apple.SoftwareUpdate")
            .collect();
        assert_eq!(pt.len(), 1, "one payload-level finding, not two");
        assert_eq!(pt[0].kind, DeprecationKind::RemovedPayloadType);
    }

    #[test]
    fn payload_not_marked_removed_is_clean() {
        // Same type, but the schema carries no `removed` marker → no finding.
        let schema = SchemaRegistry::embedded().unwrap();
        let v = profile(vec![payload("com.apple.system.logging")]);
        assert!(scan_removed_payload_types(&v, &schema).is_empty());
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
