# Deprecation Scan Implementation Plan

> Implement this plan task-by-task, in order. Run each task's tests and `scripts/ci-check.sh` before committing. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deprecation scan to `contour profile scan` that reports deprecated payload types and keys, with human/JSON/Markdown output and an opt-in CI gate.

**Architecture:** A new `profile/deprecation.rs` module is the single detection path. It walks the parsed `plist::Value` tree producing `DeprecationFinding`s from two sources — `MigrationRegistry` (payload types) and `SchemaRegistry` field metadata (keys). `scan`, `lint`, and `plan` all consume this one module.

**Tech Stack:** Rust (stable), `plist` crate, `serde`, `clap`, `anyhow`, `colored`.

**Spec:** `docs/specs/2026-05-16-deprecation-scan-design.md`

**Signature note:** The detection functions take `&plist::Value` (not `&ConfigurationProfile` as the spec sketched). This matches the existing `lint` module's tree-walk and lets `lint` reuse the module with zero conversion; `scan` converts its profile via `plist::to_value` (as `plan/deprecated.rs` already does).

**Verification:** This repo's CI uses `RUSTFLAGS=-D warnings`. After each task run `scripts/ci-check.sh` from the repo root before committing; fix all warnings.

---

## Task 1: Deprecation module — data structures + payload-type detection

**Files:**
- Create: `crates/profile/src/profile/deprecation.rs`
- Modify: `crates/profile/src/profile/mod.rs:6` (module list)

- [ ] **Step 1: Register the module**

In `crates/profile/src/profile/mod.rs`, the module list currently reads:

```rust
pub mod lint;
pub mod normalizer;
pub mod parser;
pub mod validator;
```

Change it to:

```rust
pub mod deprecation;
pub mod lint;
pub mod normalizer;
pub mod parser;
pub mod validator;
```

- [ ] **Step 2: Create `deprecation.rs` with structures and payload-type detection**

Create `crates/profile/src/profile/deprecation.rs`:

```rust
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

/// Scan a parsed profile tree for deprecated payload types only.
/// No schema needed — `lint`'s `deprecated-payload-type` check and
/// `plan` reuse this directly.
pub fn scan_payload_types(
    value: &Value,
    migration: &MigrationRegistry,
) -> Vec<DeprecationFinding> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(payload_type: &str) -> Value {
        let mut p = plist::Dictionary::new();
        p.insert("PayloadType".into(), Value::String(payload_type.into()));
        p.insert("PayloadIdentifier".into(), Value::String("com.test.p".into()));
        p.insert(
            "PayloadUUID".into(),
            Value::String("B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E".into()),
        );
        p.insert("PayloadVersion".into(), Value::Integer(1.into()));
        Value::Dictionary(p)
    }

    fn profile(payloads: Vec<Value>) -> Value {
        let mut d = plist::Dictionary::new();
        d.insert("PayloadType".into(), Value::String("Configuration".into()));
        d.insert("PayloadContent".into(), Value::Array(payloads));
        Value::Dictionary(d)
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
}
```

This task is self-contained: the file compiles, payload-type detection
works, and its tests pass. `scan_keys` and `scan_deprecations` are added
in Task 2.

- [ ] **Step 3: Run the payload-type tests**

Run: `cargo test -p profile profile::deprecation -- --nocapture`
Expected: PASS — `deprecated_payload_type_is_flagged_critical`,
`unknown_payload_type_is_not_flagged`.

- [ ] **Step 4: CI-parity check and commit**

Run: `scripts/ci-check.sh`
Expected: `all CI-parity checks passed`

```bash
git add crates/profile/src/profile/deprecation.rs crates/profile/src/profile/mod.rs
git commit -m "Add deprecation detection module: payload types"
```

---

## Task 2: Deprecation module — key detection

**Files:**
- Modify: `crates/profile/src/profile/deprecation.rs`

- [ ] **Step 1: Add the key-detection test**

Add to the `tests` module in `deprecation.rs` (the test fixtures from Task 1 build payloads without extra keys; this test adds a deprecated key). Append inside `mod tests`:

```rust
    fn payload_with_key(payload_type: &str, key: &str) -> Value {
        let Value::Dictionary(mut p) = payload(payload_type) else {
            unreachable!()
        };
        p.insert(key.into(), Value::Boolean(true));
        Value::Dictionary(p)
    }

    /// Resolve a (payload_type, key) pair that the embedded schema marks
    /// deprecated, so the test is not pinned to a specific Apple key.
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
    fn deprecated_key_is_flagged_warning() {
        let schema = SchemaRegistry::embedded().expect("embedded schema");
        let Some((payload_type, key)) = first_deprecated_key() else {
            return; // no deprecated keys in schema build — nothing to assert
        };
        let v = profile(vec![payload_with_key(&payload_type, &key)]);
        let findings = scan_keys(&v, &schema);
        let hit = findings
            .iter()
            .find(|f| f.locator == format!("{payload_type}.{key}"));
        let hit = hit.expect("deprecated key should be flagged");
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
        let report = scan_deprecations(
            &v,
            std::path::Path::new("clean.mobileconfig"),
            &migration,
            &schema,
        );
        assert!(report.is_empty());
    }
```

This test requires `SchemaRegistry::all()` — an existing method returning `impl Iterator<Item = &PayloadManifest>` (`crates/profile/src/schema/mod.rs:227`).

- [ ] **Step 2: Add the `SchemaRegistry` import, `scan_keys`, and `scan_deprecations`**

In `deprecation.rs`, add to the imports below `use crate::migrate::mapping::...`:

```rust
use crate::schema::SchemaRegistry;
```

Add after `walk_payload_types` (before the `#[cfg(test)]` module):

```rust
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
```

- [ ] **Step 3: Run the deprecation module tests**

Run: `cargo test -p profile profile::deprecation -- --nocapture`
Expected: PASS — `deprecated_payload_type_is_flagged_critical`, `unknown_payload_type_is_not_flagged`, `deprecated_key_is_flagged_warning`, `clean_profile_has_no_findings`.

- [ ] **Step 4: CI-parity check and commit**

Run: `scripts/ci-check.sh`
Expected: `all CI-parity checks passed`

```bash
git add crates/profile/src/profile/deprecation.rs
git commit -m "Add deprecation detection module: keys and report"
```

---

## Task 3: Refactor lint to reuse the deprecation module

**Files:**
- Modify: `crates/profile/src/profile/lint.rs:36` (imports), `:91-98` (`TIER_1_CHECKS`), `:190-216` (`lint_profile_with_options`), `:449-498` (`check_deprecated_payload_types` / `walk_check_payload_type`)
- Modify: `crates/profile/src/cli/validate.rs:515`, `:721` (caller signature)

- [ ] **Step 1: Replace the imports and detection in `lint.rs`**

In `crates/profile/src/profile/lint.rs`, the import line 36 reads:

```rust
use crate::migrate::mapping::{MigrationRegistry, MigrationStatus};
```

Change it to:

```rust
use crate::migrate::mapping::MigrationRegistry;
use crate::profile::deprecation;
use crate::schema::SchemaRegistry;
```

(`MigrationStatus` is no longer used in `lint.rs` once the walk moves out.)

Delete the entire `check_deprecated_payload_types` function and its helper `walk_check_payload_type` (lines 449-498, from `pub fn check_deprecated_payload_types` through the closing brace of `walk_check_payload_type`). Replace them with:

```rust
/// Lint adapter: deprecated payload types. Delegates detection to the
/// shared `deprecation` module and converts to `LintFinding`s.
pub fn check_deprecated_payload_types(
    value: &Value,
    registry: &MigrationRegistry,
) -> Vec<LintFinding> {
    deprecation::scan_payload_types(value, registry)
        .into_iter()
        .map(|f| {
            let lf = LintFinding::warn("deprecated-payload-type", f.detail);
            match f.payload_index {
                Some(i) => lf.with_payload(i),
                None => lf,
            }
        })
        .collect()
}

/// Lint adapter: deprecated keys. Delegates to the shared `deprecation`
/// module and converts to `LintFinding`s.
pub fn check_deprecated_keys(value: &Value, schema: &SchemaRegistry) -> Vec<LintFinding> {
    deprecation::scan_keys(value, schema)
        .into_iter()
        .map(|f| {
            let lf = LintFinding::warn("deprecated-key", f.detail);
            match f.payload_index {
                Some(i) => lf.with_payload(i),
                None => lf,
            }
        })
        .collect()
}
```

- [ ] **Step 2: Add `deprecated-key` to `TIER_1_CHECKS`**

`TIER_1_CHECKS` at lines 91-98 reads:

```rust
pub const TIER_1_CHECKS: &[&str] = &[
    "duplicate-payload-uuid",
    "payload-version-type",
    "nested-missing-payload-version",
    "placeholder-payload-uuid",
    "deprecated-payload-type",
    "single-instance-payload-repeated",
];
```

Add `"deprecated-key"`:

```rust
pub const TIER_1_CHECKS: &[&str] = &[
    "duplicate-payload-uuid",
    "payload-version-type",
    "nested-missing-payload-version",
    "placeholder-payload-uuid",
    "deprecated-payload-type",
    "deprecated-key",
    "single-instance-payload-repeated",
];
```

- [ ] **Step 3: Thread schema through `lint_profile_with_options`**

The signature at line 190 reads:

```rust
pub fn lint_profile_with_options(
    value: &Value,
    registry: &MigrationRegistry,
    options: &LintOptions,
) -> Vec<LintFinding> {
```

Change it to:

```rust
pub fn lint_profile_with_options(
    value: &Value,
    registry: &MigrationRegistry,
    schema: Option<&SchemaRegistry>,
    options: &LintOptions,
) -> Vec<LintFinding> {
```

Immediately after the existing `deprecated-payload-type` block (lines 208-210):

```rust
    if options.includes("deprecated-payload-type") {
        all.extend(check_deprecated_payload_types(value, registry));
    }
```

add:

```rust
    if options.includes("deprecated-key")
        && let Some(sch) = schema
    {
        all.extend(check_deprecated_keys(value, sch));
    }
```

- [ ] **Step 4: Update `lint_profile_with_options` call sites**

In `crates/profile/src/cli/validate.rs`, both calls (line ~515 and ~721) pass `&registry` and `&options`. `validate.rs` already constructs a `SchemaRegistry` for schema validation in scope as `registry` is the `MigrationRegistry`; locate the `SchemaRegistry` value in each function (it is used for the schema-validation pass) and pass it as `Some(&schema_registry)`. If a function has no `SchemaRegistry` in scope, construct one at the top of that function: `let schema_registry = crate::schema::SchemaRegistry::embedded()?;` and pass `Some(&schema_registry)`.

Each call changes from:

```rust
lint::lint_profile_with_options(&value, &migration_registry, &lint_options)
```

to:

```rust
lint::lint_profile_with_options(&value, &migration_registry, Some(&schema_registry), &lint_options)
```

(Use the actual variable names present in `validate.rs`.)

In `crates/profile/src/profile/lint.rs` test module, every `lint_profile_with_options(...)` call (lines ~1064, ~1212, ~1221, ~1260, ~1270, ~1289, ~1323) gains a `None` argument in the new third position. Example — line ~1064:

```rust
lint_profile_with_options(&Value::Dictionary(top), &registry, &LintOptions::default())
```

becomes:

```rust
lint_profile_with_options(&Value::Dictionary(top), &registry, None, &LintOptions::default())
```

Apply the same `None` insertion to every other test call site.

- [ ] **Step 5: Add a `deprecated-key` lint test**

In the `lint.rs` `tests` module, after `unknown_payload_type_is_not_flagged` (line ~959), add:

```rust
    #[test]
    fn deprecated_key_lint_check_fires() {
        let schema = crate::schema::SchemaRegistry::embedded().expect("embedded schema");
        // Find a (payload type, key) the schema marks deprecated.
        let mut probe = None;
        for manifest in schema.all() {
            for (name, field) in &manifest.fields {
                if field.deprecated_in.is_some() {
                    probe = Some((manifest.payload_type.clone(), name.clone()));
                    break;
                }
            }
            if probe.is_some() {
                break;
            }
        }
        let Some((payload_type, key)) = probe else {
            return; // no deprecated keys in this schema build
        };
        let mut p = plist::Dictionary::new();
        p.insert("PayloadType".into(), Value::String(payload_type));
        p.insert("PayloadIdentifier".into(), Value::String("com.test.p".into()));
        p.insert(
            "PayloadUUID".into(),
            Value::String("B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E".into()),
        );
        p.insert("PayloadVersion".into(), Value::Integer(1.into()));
        p.insert(key, Value::Boolean(true));
        let mut top = plist::Dictionary::new();
        top.insert("PayloadType".into(), Value::String("Configuration".into()));
        top.insert("PayloadContent".into(), Value::Array(vec![Value::Dictionary(p)]));
        let findings = check_deprecated_keys(&Value::Dictionary(top), &schema);
        assert!(findings.iter().any(|f| f.check == "deprecated-key"));
    }
```

- [ ] **Step 6: Run lint tests**

Run: `cargo test -p profile profile::lint -- --nocapture`
Expected: PASS — including the existing `softwareupdate_is_flagged_as_deprecated` and the new `deprecated_key_lint_check_fires`.

- [ ] **Step 7: CI-parity check and commit**

Run: `scripts/ci-check.sh`
Expected: `all CI-parity checks passed`

```bash
git add crates/profile/src/profile/lint.rs crates/profile/src/cli/validate.rs
git commit -m "Reuse deprecation module from lint, add deprecated-key check"
```

---

## Task 4: Config — `[validation].fail_on_deprecations`

**Files:**
- Modify: `crates/contour-core/src/config.rs` (`ValidationConfig` struct + `Default` impl)

- [ ] **Step 1: Add a config round-trip test**

In `crates/contour-core/src/config.rs`, find the `tests` module. Add:

```rust
    #[test]
    fn validation_config_defaults_fail_on_deprecations_false() {
        let v = ValidationConfig::default();
        assert!(v.fail_on_errors);
        assert!(!v.fail_on_warnings);
        assert!(!v.fail_on_deprecations);
    }

    #[test]
    fn validation_config_parses_fail_on_deprecations() {
        let toml = "fail_on_deprecations = true\n";
        let v: ValidationConfig = toml::from_str(toml).unwrap();
        assert!(v.fail_on_deprecations);
        assert!(v.fail_on_errors); // serde default still applies
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p contour-core validation_config -- --nocapture`
Expected: FAIL — `no field 'fail_on_deprecations'`.

- [ ] **Step 3: Add the field**

The `ValidationConfig` struct currently reads:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationConfig {
    #[serde(default = "default_true")]
    pub fail_on_errors: bool,
    #[serde(default)]
    pub fail_on_warnings: bool,
}
```

Change it to:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationConfig {
    #[serde(default = "default_true")]
    pub fail_on_errors: bool,
    #[serde(default)]
    pub fail_on_warnings: bool,
    /// When true, `profile scan --deprecations` exits non-zero if any
    /// deprecation is found. CLI `--fail-on-deprecations` overrides this.
    #[serde(default)]
    pub fail_on_deprecations: bool,
}
```

And the `Default` impl currently reads:

```rust
impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            fail_on_errors: true,
            fail_on_warnings: false,
        }
    }
}
```

Change it to:

```rust
impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            fail_on_errors: true,
            fail_on_warnings: false,
            fail_on_deprecations: false,
        }
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p contour-core validation_config -- --nocapture`
Expected: PASS.

- [ ] **Step 5: CI-parity check and commit**

Run: `scripts/ci-check.sh`
Expected: `all CI-parity checks passed`

```bash
git add crates/contour-core/src/config.rs
git commit -m "Add [validation].fail_on_deprecations config key"
```

---

## Task 5: `scan` command — flag plumbing

**Files:**
- Modify: `crates/profile/src/cli/mod.rs:304-326` (`Scan` command)
- Modify: `crates/profile/src/main.rs` (`Commands::Scan` arm)
- Modify: `crates/contour/src/dispatch.rs` (`Commands::Scan` arm)
- Modify: `crates/profile/src/cli/scan.rs:55-64` (`handle_scan` signature)

This task adds the flags and threads them to `handle_scan` without using them yet — it must compile and leave `scan` behaviour unchanged.

- [ ] **Step 1: Add the flags to the `Scan` command**

In `crates/profile/src/cli/mod.rs`, the `Scan` command ends with the `no_parallel` arg and a closing `},`. Add three flags before the closing brace:

```rust
        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,

        #[arg(long, help = "Scan for deprecated payload types and keys")]
        deprecations: bool,

        #[arg(
            long,
            value_name = "PATH",
            help = "Write a Markdown deprecation report to this path (implies --deprecations)"
        )]
        md_report: Option<String>,

        #[arg(
            long,
            help = "Exit non-zero if any deprecation is found (overrides [validation].fail_on_deprecations)"
        )]
        fail_on_deprecations: bool,
    },
```

- [ ] **Step 2: Update `handle_scan` signature**

In `crates/profile/src/cli/scan.rs`, the signature reads:

```rust
pub fn handle_scan(
    paths: &[String],
    simulate: bool,
    domain: Option<&str>,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
```

Change it to:

```rust
pub fn handle_scan(
    paths: &[String],
    simulate: bool,
    domain: Option<&str>,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    deprecations: bool,
    md_report: Option<&str>,
    fail_on_deprecations: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    // `--md-report` implies `--deprecations`.
    let deprecations = deprecations || md_report.is_some();
    let _ = (deprecations, md_report, fail_on_deprecations); // wired in Tasks 6-8
```

(The `let _ = ...` line is removed in Task 6; it prevents unused-variable warnings under `-D warnings` for this intermediate task.)

- [ ] **Step 3: Update the `main.rs` dispatch**

In `crates/profile/src/main.rs`, find the `Commands::Scan { ... }` arm. It destructures the scan fields and calls `cli::scan::handle_scan(...)`. Add the three new fields to the destructure and pass them. The destructure gains:

```rust
        Commands::Scan {
            paths,
            simulate,
            org,
            recursive,
            max_depth,
            no_parallel,
            deprecations,
            md_report,
            fail_on_deprecations,
        } => {
```

and the call becomes:

```rust
            cli::scan::handle_scan(
                &paths,
                simulate,
                org.as_deref(),
                recursive,
                max_depth,
                !no_parallel,
                deprecations,
                md_report.as_deref(),
                fail_on_deprecations,
                config.as_ref(),
                output_mode,
            )?;
```

(Match the existing argument order/names already present in the arm; only `deprecations`, `md_report`, `fail_on_deprecations` are new.)

- [ ] **Step 4: Update the `dispatch.rs` dispatch**

In `crates/contour/src/dispatch.rs`, apply the identical change to its `Commands::Scan { ... }` arm: add `deprecations`, `md_report`, `fail_on_deprecations` to the destructure and pass them to `profile::cli::scan::handle_scan` in the same positions as Step 3.

- [ ] **Step 5: Verify build**

Run: `scripts/ci-check.sh`
Expected: `all CI-parity checks passed`

- [ ] **Step 6: Commit**

```bash
git add crates/profile/src/cli/mod.rs crates/profile/src/main.rs crates/contour/src/dispatch.rs crates/profile/src/cli/scan.rs
git commit -m "Add scan deprecation flags (plumbing)"
```

---

## Task 6: `scan` — detection, human + JSON output

**Files:**
- Modify: `crates/profile/src/cli/scan.rs`
- Test: `crates/profile/tests/` (new integration test file)

- [ ] **Step 1: Wire detection into `ScanResult` and the scan functions**

In `crates/profile/src/cli/scan.rs`, add imports near the top:

```rust
use crate::migrate::mapping::MigrationRegistry;
use crate::profile::deprecation::{
    self, DeprecationFinding, DeprecationReport, DeprecationSeverity,
};
use crate::schema::SchemaRegistry;
```

Add a field to `ScanResult` (after `simulation`):

```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    deprecations: Option<DeprecationReport>,
```

`scan_single_file` gains an optional registries parameter. Change its signature:

```rust
fn scan_single_file(
    path: &Path,
    simulate: bool,
    sim_domain: &str,
    registries: Option<(&MigrationRegistry, &SchemaRegistry)>,
) -> Result<ScanResult> {
```

Just before the final `Ok(ScanResult { ... })`, add:

```rust
    let deprecations = registries.map(|(migration, schema)| {
        let value = profile.to_plist_value();
        deprecation::scan_deprecations(&value, path, migration, schema)
    });
```

and add `deprecations,` to the `ScanResult { ... }` literal.

`scan_files` gains the same parameter and forwards it. Change its signature:

```rust
fn scan_files(
    files: &[std::path::PathBuf],
    simulate: bool,
    sim_domain: &str,
    parallel: bool,
    registries: Option<(&MigrationRegistry, &SchemaRegistry)>,
) -> Vec<ScanResult> {
```

In both the `par_iter` and sequential branches, pass `registries` through to `scan_single_file`. `MigrationRegistry` and `SchemaRegistry` are `Sync`, so `registries` (a `Copy` tuple of references) can be captured by the rayon closure directly.

- [ ] **Step 2: Build the registries in `handle_scan` and pass them down**

In `handle_scan`, remove the `let _ = (deprecations, md_report, fail_on_deprecations);` line from Task 5. After the `sim_domain` resolution block, add:

```rust
    let registries = if deprecations {
        let migration = MigrationRegistry::new();
        let schema = SchemaRegistry::embedded()
            .context("Failed to load embedded schema for deprecation scan")?;
        Some((migration, schema))
    } else {
        None
    };
    let registry_refs = registries
        .as_ref()
        .map(|(m, s)| (m, s));
```

Update the two call sites in `handle_scan` to pass `registry_refs`:
- `scan_files(&files, simulate, &sim_domain, parallel, registry_refs)`
- `scan_single_file(path, simulate, &sim_domain, registry_refs)`

- [ ] **Step 3: Render the deprecation section (human output)**

Add a helper to `scan.rs`:

```rust
/// Print the deprecation findings for one scanned profile.
fn print_deprecations(findings: &[DeprecationFinding]) {
    if findings.is_empty() {
        println!("  {} {}", "Deprecations".white().bold(), "none".green());
        return;
    }
    println!(
        "  {} ({})",
        "Deprecations".white().bold(),
        findings.len()
    );
    for f in findings {
        let (marker, sev) = match f.severity {
            DeprecationSeverity::Critical => ("✗".red(), "critical".red()),
            DeprecationSeverity::Warning => ("⚠".yellow(), "warning".yellow()),
        };
        let since = f
            .deprecated_in
            .as_deref()
            .map(|d| format!(" (deprecated {d})"))
            .unwrap_or_default();
        let repl = f
            .replacement
            .as_deref()
            .map(|r| format!(" → {r}"))
            .unwrap_or_default();
        println!(
            "    {} [{}] {}{}{}",
            marker,
            sev,
            f.locator.cyan(),
            since.dimmed(),
            repl.green()
        );
    }
}
```

In `print_scan_result_human`, just before the final `println!();`, add:

```rust
    if let Some(report) = &result.deprecations {
        println!();
        print_deprecations(&report.findings);
    }
```

In `output_scan_results`, after the existing `Payloads:` summary line, add a deprecation summary:

```rust
        let dep_total: usize = results
            .iter()
            .filter_map(|r| r.deprecations.as_ref())
            .map(|r| r.findings.len())
            .sum();
        if results.iter().any(|r| r.deprecations.is_some()) {
            println!("  {} {} deprecations", "Deprecated:".cyan(), dep_total);
        }
```

JSON output needs no extra code: `ScanResult` already derives `Serialize` and the new `deprecations` field flows through `output_scan_result` / `output_scan_results` automatically.

- [ ] **Step 4: Write the integration test**

Create `crates/profile/tests/scan_deprecations.rs`:

```rust
//! Integration: `profile scan --deprecations`.

use std::process::Command;

fn contour() -> Command {
    Command::new(env!("CARGO_BIN_EXE_profile"))
}

const DEPRECATED_PROFILE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.test.dep</string>
  <key>PayloadUUID</key><string>1AE33410-88E1-40DE-B41E-08BCD69B6238</string>
  <key>PayloadDisplayName</key><string>Dep Test</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.SoftwareUpdate</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.test.dep.su</string>
      <key>PayloadUUID</key><string>B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E</string>
    </dict>
  </array>
</dict>
</plist>
"#;

#[test]
fn scan_deprecations_flags_deprecated_payload_type() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("dep.mobileconfig");
    std::fs::write(&file, DEPRECATED_PROFILE).unwrap();

    let out = contour()
        .args(["scan", file.to_str().unwrap(), "--deprecations", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "scan should succeed without the gate");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"deprecations\""),
        "JSON should carry a deprecations field: {stdout}"
    );
    assert!(
        stdout.contains("com.apple.SoftwareUpdate"),
        "deprecated payload type should appear: {stdout}"
    );
}

#[test]
fn scan_without_flag_has_no_deprecation_field() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("dep.mobileconfig");
    std::fs::write(&file, DEPRECATED_PROFILE).unwrap();

    let out = contour()
        .args(["scan", file.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("\"deprecations\""),
        "default scan must not include deprecations: {stdout}"
    );
}
```

This test invokes the `profile` binary (`CARGO_BIN_EXE_profile`). `tempfile` is already a dev-dependency of the `profile` crate (used by existing tests such as `sop_traps`).

- [ ] **Step 5: Run the integration test**

Run: `cargo test -p profile --test scan_deprecations -- --nocapture`
Expected: PASS — both tests.

- [ ] **Step 6: CI-parity check and commit**

Run: `scripts/ci-check.sh`
Expected: `all CI-parity checks passed`

```bash
git add crates/profile/src/cli/scan.rs crates/profile/tests/scan_deprecations.rs
git commit -m "Add deprecation detection and reporting to profile scan"
```

---

## Task 7: `scan` — Markdown report

**Files:**
- Modify: `crates/profile/src/cli/scan.rs`
- Modify: `crates/profile/tests/scan_deprecations.rs`

- [ ] **Step 1: Write the Markdown renderer**

Add to `crates/profile/src/cli/scan.rs`:

```rust
/// Render a Markdown deprecation report for the scanned profiles.
fn render_markdown_report(results: &[ScanResult]) -> String {
    use std::fmt::Write as _;

    let mut md = String::new();
    md.push_str("# Deprecation Report\n\n");

    let scanned: Vec<&ScanResult> = results
        .iter()
        .filter(|r| r.deprecations.is_some())
        .collect();
    let with_findings: Vec<&ScanResult> = scanned
        .iter()
        .copied()
        .filter(|r| r.deprecations.as_ref().is_some_and(|d| !d.is_empty()))
        .collect();

    let _ = writeln!(
        md,
        "{} profile(s) scanned, {} with deprecations.\n",
        scanned.len(),
        with_findings.len()
    );

    md.push_str("| Profile | Critical | Warning |\n");
    md.push_str("|---|---|---|\n");
    for r in &scanned {
        let report = r.deprecations.as_ref().unwrap();
        let _ = writeln!(
            md,
            "| {} | {} | {} |",
            r.path,
            report.critical_count(),
            report.warning_count()
        );
    }
    md.push('\n');

    for r in &with_findings {
        let report = r.deprecations.as_ref().unwrap();
        let _ = writeln!(md, "## {}\n", r.path);
        for sev in [DeprecationSeverity::Critical, DeprecationSeverity::Warning] {
            let group: Vec<&DeprecationFinding> =
                report.findings.iter().filter(|f| f.severity == sev).collect();
            if group.is_empty() {
                continue;
            }
            let label = match sev {
                DeprecationSeverity::Critical => "Critical",
                DeprecationSeverity::Warning => "Warning",
            };
            let _ = writeln!(md, "### {label}\n");
            for f in group {
                let since = f
                    .deprecated_in
                    .as_deref()
                    .map(|d| format!(" (deprecated {d})"))
                    .unwrap_or_default();
                let repl = f
                    .replacement
                    .as_deref()
                    .map(|r| format!(" → `{r}`"))
                    .unwrap_or_default();
                let _ = writeln!(md, "- `{}`{}{}", f.locator, since, repl);
                let _ = writeln!(md, "  - {}", f.detail);
            }
            md.push('\n');
        }
    }
    md
}
```

- [ ] **Step 2: Write the report file in `handle_scan`**

`handle_scan` currently returns after producing output in both the batch and single-file branches. Refactor so both branches keep their `results: Vec<ScanResult>` available, then after output, before `Ok(())`, add:

```rust
    if let Some(md_path) = md_report {
        let md = render_markdown_report(&all_results);
        std::fs::write(md_path, md)
            .with_context(|| format!("Failed to write Markdown report to {md_path}"))?;
        if output_mode == OutputMode::Human {
            println!("  {} Markdown report → {}", "→".green(), md_path);
        }
    }
```

To make `all_results` available in both branches: in the batch branch capture `let results = scan_files(...);` (already named `results`); in the single-file branch capture `let result = scan_single_file(...)?; let results = vec![result];`. Normalize both branches to bind a `Vec<ScanResult>` named `all_results` before the output call, call `output_scan_results`/`output_scan_result` as before, then run the Markdown block above. Do not early-`return` from the branches — fall through to the shared Markdown + gate code.

- [ ] **Step 3: Add a Markdown test**

Append to `crates/profile/tests/scan_deprecations.rs`:

```rust
#[test]
fn scan_md_report_writes_markdown_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("dep.mobileconfig");
    std::fs::write(&file, DEPRECATED_PROFILE).unwrap();
    let report = dir.path().join("report.md");

    let out = contour()
        .args([
            "scan",
            file.to_str().unwrap(),
            "--md-report",
            report.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let md = std::fs::read_to_string(&report).expect("report file written");
    assert!(md.contains("# Deprecation Report"), "md: {md}");
    assert!(md.contains("com.apple.SoftwareUpdate"), "md: {md}");
    assert!(md.contains("### Critical"), "md: {md}");
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p profile --test scan_deprecations -- --nocapture`
Expected: PASS — all three tests.

- [ ] **Step 5: CI-parity check and commit**

Run: `scripts/ci-check.sh`
Expected: `all CI-parity checks passed`

```bash
git add crates/profile/src/cli/scan.rs crates/profile/tests/scan_deprecations.rs
git commit -m "Add Markdown deprecation report to profile scan"
```

---

## Task 8: `scan` — `--fail-on-deprecations` gate

**Files:**
- Modify: `crates/profile/src/cli/scan.rs`
- Modify: `crates/profile/tests/scan_deprecations.rs`

- [ ] **Step 1: Implement the gate in `handle_scan`**

At the very end of `handle_scan`, after the Markdown block and before `Ok(())`, add:

```rust
    if deprecations {
        let total: usize = all_results
            .iter()
            .filter_map(|r| r.deprecations.as_ref())
            .map(|r| r.findings.len())
            .sum();
        let gate = fail_on_deprecations
            || contour_core::config::resolve_validation_with_anchor(None).fail_on_deprecations;
        if gate && total > 0 {
            anyhow::bail!(
                "deprecation scan failed: {total} deprecation(s) found \
                 (--fail-on-deprecations / [validation].fail_on_deprecations)"
            );
        }
    }
```

The gate runs *after* all output and the Markdown write, so the operator sees the full report before the non-zero exit. `resolve_validation_with_anchor(None)` walks `.contour/config.toml` from CWD and returns defaults when none is found.

- [ ] **Step 2: Add gate exit-code tests**

Append to `crates/profile/tests/scan_deprecations.rs`:

```rust
const CLEAN_PROFILE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.test.clean</string>
  <key>PayloadUUID</key><string>1AE33410-88E1-40DE-B41E-08BCD69B6239</string>
  <key>PayloadDisplayName</key><string>Clean</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.dock</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.test.clean.dock</string>
      <key>PayloadUUID</key><string>C2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D70</string>
    </dict>
  </array>
</dict>
</plist>
"#;

#[test]
fn fail_on_deprecations_exits_nonzero_when_found() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("dep.mobileconfig");
    std::fs::write(&file, DEPRECATED_PROFILE).unwrap();

    let out = contour()
        .args([
            "scan",
            file.to_str().unwrap(),
            "--deprecations",
            "--fail-on-deprecations",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "gate should fail the run when a deprecation is present"
    );
}

#[test]
fn fail_on_deprecations_exits_zero_when_clean() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("clean.mobileconfig");
    std::fs::write(&file, CLEAN_PROFILE).unwrap();

    let out = contour()
        .args([
            "scan",
            file.to_str().unwrap(),
            "--deprecations",
            "--fail-on-deprecations",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "gate should pass when no deprecations are present"
    );
}
```

`.current_dir(dir.path())` ensures `resolve_validation_with_anchor` does not pick up a developer's real `.contour/config.toml`.

- [ ] **Step 3: Run the tests**

Run: `cargo test -p profile --test scan_deprecations -- --nocapture`
Expected: PASS — all five tests.

- [ ] **Step 4: CI-parity check and commit**

Run: `scripts/ci-check.sh`
Expected: `all CI-parity checks passed`

```bash
git add crates/profile/src/cli/scan.rs crates/profile/tests/scan_deprecations.rs
git commit -m "Add --fail-on-deprecations gate to profile scan"
```

---

## Final verification

- [ ] **Run the whole suite**

Run: `cargo test --workspace`
Expected: 0 failed.

- [ ] **Stress-test against the reference set**

Run:
```bash
cargo run -q -p contour --bin contour -- profile scan \
  /Users/henry/Downloads/profiles-main-ref --recursive \
  --deprecations --md-report /tmp/dep-report.md
```
Expected: scans 73 profiles, prints a deprecation section per file, writes `/tmp/dep-report.md`. Review the report.
