# Deprecation Scan — Design

Date: 2026-05-16
Status: Approved (pending spec review)

## Problem

contour can detect deprecated payload types as a *change-based* check inside
`profile plan` (`plan/deprecated.rs` → `check_new_deprecations`): it only flags
deprecations a proposed profile newly introduces versus a baseline. There is no
way to scan a profile or a folder of profiles and get a standalone report of
*every* deprecated element it already contains.

Operators auditing a profile library (e.g. a 73-profile reference set) need a
deprecation report as part of normal reporting — both for human review and for
CI gating.

## Goals

- Scan one or more profiles and report every known-deprecated element.
- Cover two element kinds: deprecated **payload types** and deprecated **keys**.
- Surface the report through the existing `profile scan` command.
- Emit human, JSON, and Markdown output.
- Be informational by default, with an opt-in gate that fails CI runs.
- Make the new detection logic the single source of truth, reused by `lint`
  (and therefore transitively by `plan`).

## Non-goals

- Detecting deprecation of payload types or keys that are *unknown* to
  contour's schema/registry. `com.apple.screensaver.ByHost` is reported by
  `validate` as an unknown payload type; expanding schema/registry coverage is
  a separate data-coverage effort.
- Auto-migrating or rewriting deprecated profiles.
- Wiring deprecation gating into commands other than `scan`.

## Data sources (verified present)

| Source | Data | Coverage |
|---|---|---|
| `MigrationRegistry` (`migrate/mapping.rs`) | legacy MDM payload type → DDM replacement + `MigrationStatus` | payload types |
| `SchemaRegistry` `FieldDefinition.deprecated_macos` (from ProfileCreator `pfm_macos_deprecated`) | per-key macOS deprecation version | ~94 keys in `profilecreator.parquet` |

Payload-type deprecation = "legacy payload still works on macOS ≤25 but stops
working on macOS 26+". Key deprecation = "Apple deprecated the key; it still
functions".

## Architecture

### New module: `crates/profile/src/profile/deprecation.rs`

The single detection path. Pure functions over a parsed `ConfigurationProfile`
plus the two registries; no I/O.

```rust
pub enum DeprecationKind { PayloadType, Key }

pub enum DeprecationSeverity { Critical, Warning }

pub struct DeprecationFinding {
    pub kind: DeprecationKind,
    pub payload_index: Option<usize>,   // None = outer profile envelope
    pub payload_type: String,
    pub locator: String,                // "com.apple.softwareupdate"
                                        // or "com.apple.foo.SomeKey"
    pub deprecated_in: Option<String>,  // "macOS 26", "14.0"
    pub replacement: Option<String>,    // DDM type or successor key, if known
    pub detail: String,                 // human-readable explanation
    pub severity: DeprecationSeverity,
}

pub struct DeprecationReport {
    pub path: PathBuf,
    pub findings: Vec<DeprecationFinding>,
}

impl DeprecationReport {
    pub fn is_empty(&self) -> bool;
    pub fn critical_count(&self) -> usize;
    pub fn warning_count(&self) -> usize;
}

pub fn scan_deprecations(
    profile: &ConfigurationProfile,
    path: &Path,
    migration: &MigrationRegistry,
    schema: &SchemaRegistry,
) -> DeprecationReport;
```

`DeprecationFinding` and `DeprecationReport` derive `Serialize` for JSON output.

### Detection rules

- **Payload types** — for each payload (and the outer envelope), look up
  `PayloadType` in `MigrationRegistry`. A mapping with status
  `Available` or `Partial` produces a `Critical` finding with `replacement`
  set to the DDM type. This is the logic currently in
  `lint::check_deprecated_payload_types`, relocated into this module.
- **Keys** — for each payload, resolve its `PayloadManifest` from
  `SchemaRegistry`. For every key present in the payload whose
  `FieldDefinition` carries a `deprecated_macos` value, produce a `Warning`
  finding with `deprecated_in` set to that version.

### Severity

- Payload-type findings → `Critical` (breaks on macOS 26+).
- Key findings → `Warning` (deprecated but still functional).

## `scan` command integration

`profile scan` gains:

- `--deprecations` — adds a deprecation section to the scan output. Without the
  flag, `scan` behaves exactly as today (metadata only).
- `--md-report <PATH>` — writes a standalone Markdown deprecation report to
  the given path. Implies `--deprecations`.
- `--fail-on-deprecations` — process exits non-zero when any finding exists.
  The default for this gate is read from a new config key
  `[validation].fail_on_deprecations` (default `false`); the CLI flag overrides
  the config value.

`[validation]` already exists in `ContourConfig`; `fail_on_deprecations: bool`
is added there with `#[serde(default)]`.

## Output formats

One `DeprecationReport` per file feeds three renderers:

- **Human** — per-file "Deprecations" section. Each finding on one line:
  `✗`/`⚠` + `locator` + `deprecated_in` + `→ replacement` (when known).
  A trailing summary line: counts of deprecated payload types and keys across
  N profiles.
- **JSON** — under the global `--json`, the serialized reports as a
  `deprecations` array (one entry per file).
- **Markdown** — `--md-report` writes: a title, a summary table
  (profile · critical · warning counts), then per-profile sections listing
  findings grouped by severity. Suitable for posting to a PR or wiki.

## lint reuse

`lint::check_deprecated_payload_types` is refactored into a thin adapter:
it calls `deprecation::scan_deprecations` and converts the `PayloadType`
findings into `LintFinding`s (check id `deprecated-payload-type`, unchanged).
A new adapter produces `deprecated-key` `LintFinding`s from the `Key` findings,
registered in `lint_profile_with_options` alongside the existing checks.

`plan/deprecated.rs::check_new_deprecations` calls
`check_deprecated_payload_types` and therefore rides on the same detection path
without modification.

Net result: one detection implementation, three consumers — `scan`, `lint`,
`plan`.

## Testing

- Unit tests in `deprecation.rs`:
  - profile with a known deprecated payload type → exactly one `Critical`
    finding with the expected `replacement`.
  - profile with a deprecated key → exactly one `Warning` finding with the
    expected `deprecated_in`.
  - clean profile → empty report.
- `scan` integration tests:
  - `scan --deprecations` against a fixture shows the section.
  - `scan --fail-on-deprecations` exits non-zero on a deprecated fixture,
    zero on a clean one.
  - `--md-report` writes a Markdown file with the expected headings.
- Regression: existing `lint` deprecation tests
  (`softwareupdate_is_flagged_as_deprecated`) still pass after the refactor.

## Files touched

- New: `crates/profile/src/profile/deprecation.rs`
- New: `crates/profile/src/profile/mod.rs` — module registration
- Modified: `crates/profile/src/profile/lint.rs` — delegate to new module,
  add `deprecated-key` check
- Modified: `crates/profile/src/cli/scan.rs` — flags, deprecation section,
  Markdown renderer, gate
- Modified: `crates/profile/src/cli/mod.rs` — new `scan` flags
- Modified: `crates/profile/src/main.rs`, `crates/contour/src/dispatch.rs` —
  thread new flags
- Modified: `crates/contour-core/src/config.rs` — `[validation].fail_on_deprecations`
