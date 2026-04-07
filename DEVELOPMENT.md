# Development Guide

This document covers development workflows for contributors to the Contour project.

## Prerequisites

- Rust 1.85+ (stable) via `rust-toolchain.toml`
- `uv` for Python (mSCP generation pipeline)

## Workspace Structure

```
contour/
├── Cargo.toml              # Workspace manifest with shared dependencies + lints
├── Cargo.lock              # Committed lockfile for reproducible builds
├── rust-toolchain.toml     # Rust stable + rustfmt, clippy
├── crates/
│   ├── contour/            # Unified CLI dispatcher (binary)
│   ├── contour-core/       # Shared library (output, logging, fragments, FleetLayout, help-ai)
│   ├── mscp-schema/        # mSCP compliance data (embedded parquet, 10 datasets)
│   ├── profile/            # Apple configuration profile toolkit
│   ├── pppc/               # Privacy/TCC profile generator
│   ├── btm/                # Background Task Management profiles
│   ├── notifications/      # Notification settings profiles
│   ├── support/            # Root3 Support App profiles
│   ├── santa/              # Santa allowlist/blocklist toolkit (CEL, FAA, rings)
│   └── mscp/               # mSCP baseline transformer (Fleet, Jamf, Munki)
├── pkg/contour/            # munkipkg project for signed .pkg installer
├── scripts/
│   ├── build-release.sh    # Build, sign, notarize, pkg (--op for 1Password)
└── .github/workflows/
    ├── ci.yml              # PR checks: fmt, clippy, test, audit
    └── release.yml         # Tag-triggered builds (v* tags)
```

## Building

```bash
# Build the unified contour binary (default member)
cargo build

# Build all crates
cargo build --workspace

# Build release
cargo build --release

# Build for Apple Silicon (release, cross-target)
cargo build --release --target aarch64-apple-darwin -p contour

# Run a specific tool directly
cargo run -p profile -- --help
cargo run -p santa -- cel fields --json
```

## Testing

```bash
# Run all tests
cargo test --workspace

# Run tests for specific crate
cargo test -p contour-core
cargo test -p profile
cargo test -p mscp
cargo test -p santa
cargo test -p mscp-schema

# Run a specific test
cargo test -p santa -- cel::validate::tests::test_validate_unknown_field

# Run tests with output
cargo test -- --nocapture
```

## Linting and Formatting
Lints are configured at workspace level in `Cargo.toml`:
- `[workspace.lints.rust]` — 7 compiler lints
- `[workspace.lints.clippy]` — all major categories + 19 restriction lints

```bash
# Check formatting
cargo fmt --check

# Apply formatting
cargo fmt

# Run clippy (workspace lints apply automatically)
cargo clippy --workspace

# Run clippy with warnings as errors (CI mode)
cargo clippy --workspace -- -D warnings
```

### Lint Override Rules

- Use `#[expect(lint, reason = "...")]` for non-dead-code suppressions
- Use `#[allow(dead_code, reason = "...")]` for forward-declared items
- Every `#[allow]` must include a `reason` parameter

## Fleet GitOps Layout

All Fleet output uses `FleetLayout` from `contour-core`. Default is v4.83 (definitive structure from `fleetctl new`):

```
platforms/
├── all/{icons,policies,reports}/
├── macos/{configuration-profiles,declaration-profiles,commands,enrollment-profiles,policies,reports,scripts,software}/
├── ios/{configuration-profiles,declaration-profiles}/
├── ipados/{configuration-profiles,declaration-profiles}/
├── windows/{configuration-profiles,policies,reports,scripts,software}/
├── linux/{policies,reports,scripts,software}/
└── android/{configuration-profiles,managed-app-configurations}/
fleets/                       # fleet YAML files (glob paths: *.mobileconfig)
labels/                       # one .yml per label
```

Key v4.83 changes: `declaration-profiles/` separated from `configuration-profiles/`, glob `paths:` patterns, `apple_settings` key.

Versions: `FleetLayout::v4_83()` (default), `FleetLayout::v4_82()`, `FleetLayout::legacy()`.

## Jamf Import

Import profiles from Jamf backup YAML ([jamf-cli](https://github.com/Jamf-Concepts/jamf-cli) export format):

```bash
# Step 1: Export profiles from Jamf Pro using jamf-cli
jamf-cli pro backup --output ./jamf-backup --resources profiles

# Step 2: Import, normalize, and validate with contour
contour profile import --jamf ./jamf-backup/profiles/macos/ --all -o output/ --org com.yourco

# Dry run (preview without writing)
contour profile import --jamf ./jamf-backup/profiles/macos/ --all --dry-run
```

The Jamf YAML `payloads: |-` field contains minified mobileconfig XML. The import pipeline:
1. Parses YAML, extracts `general.payloads` plist
2. Writes as properly formatted `.mobileconfig`
3. Normalizes identifiers under `--org` namespace
4. Regenerates deterministic UUIDs
5. Validates against embedded Apple schema

## Managed Preferences Import

Synthesize mobileconfigs from deployed managed preference plists:

```bash
contour profile synthesize /Library/Managed\ Preferences/ -o profiles/ --org com.yourco --validate
```

## Adding Dependencies

Dependencies are managed at workspace level:

```toml
# In root Cargo.toml
[workspace.dependencies]
new-crate = "1.0"

# In crate's Cargo.toml
[dependencies]
new-crate.workspace = true
```

## Versioning

All crates currently at v0.1.3. Release via `v*` tags:

```bash
# Bump version in crates/contour/Cargo.toml
# Tag and push
git tag v0.1.3
git push origin v0.1.3
# GitHub Actions builds Linux + macOS artifacts
```

## Release (macOS)

```bash
# Full pipeline: build → sign → notarize binary → pkg → notarize pkg → staple
./scripts/build-release.sh --op

# Skip build (reuse existing binary)
./scripts/build-release.sh --op --skip-build --install

# Skip pkg creation
./scripts/build-release.sh --op --skip-pkg

# Upload to GitHub Release
./scripts/release-macos.sh contour
```

## Reproducible Builds

All CLIs support reproducible builds via `SOURCE_DATE_EPOCH`:

```bash
SOURCE_DATE_EPOCH=1706500000 cargo build --release
```

Build timestamps round to 10-minute intervals for cache efficiency.

## Architecture

### Output Modes

All commands support `--json` for machine-readable output:

```rust
use contour_core::{CommandResult, OutputMode};

pub fn handle_info(mode: OutputMode) -> Result<()> {
    match mode {
        OutputMode::Human => print_info("..."),
        OutputMode::Json => print_json(&serde_json::json!({...}))?,
    }
    Ok(())
}
```

### Agent SOPs

Agent-facing workflows are documented in `help-ai`:

```bash
contour help-ai                    # command index + SOP pointers
contour help-ai --sop profile     # profile generation workflow
contour help-ai --sop mscp        # mSCP compliance workflow
contour help-ai --sop santa       # Santa allowlist workflow
contour help-ai --command santa.cel.compile  # specific command detail
contour help-json profile.validate # JSON schema for a command
```

## CI/CD

### GitHub Actions

- `ci.yml` — on push/PR to main: fmt → clippy → test → build → audit
- `release.yml` — on `v*` tags: build Linux + macOS, create GitHub Release

### Local CI Check

```bash
cargo fmt --check && \
cargo clippy --workspace -- -D warnings && \
cargo test --workspace
```

## Resources

- [Microsoft Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Fleet GitOps Docs](https://fleetdm.com/docs/configuration/yaml-files)
- [Apple Device Management](https://github.com/apple/device-management)
- [NIST mSCP](https://github.com/usnistgov/macos_security)
