# SOP: Embedded Schema Data Management

contour ships precomputed parquet datasets at compile time for the
Apple device-management schema, mSCP rules, and osquery tables. This
SOP is for **contour developers** — it documents what's embedded, the
three-layer versioning, and the steps to refresh the data from the
upstream `posture` pipeline.

This is a **hybrid SOP**: a developer reference (data inventory,
versioning model) plus one thin `update_schema_data` procedure for the
happy-path refresh. Forced into pure procedural form, the inventory
becomes useless; forced into pure prose, the refresh loses its
explicit preconditions.

If you're not refreshing schema data — i.e. you're a contour user, not
a contour contributor — this SOP isn't for you. Use the data via the
existing CLI (`contour profile search`, `contour profile ddm list`,
`contour mscp baseline list`, `contour osquery search`).

---

## What's embedded (data inventory)

### `crates/mdm-schema/data/`

| File | Rows (approx) | Purpose |
|---|---|---|
| `capabilities.parquet` | 13,500+ | Apple MDM profile payloads, DDM declarations, MDM commands |
| `profilecreator.parquet` | 8,900+ | Community ProfileManifests (third-party app profile schemas) |
| `skip_keys.parquet` | 71 | Setup Assistant skip keys per platform/OS |

Consumers: `crates/profile/` (search, ddm list, generate, validate),
`crates/contour/help-ai`.

### `crates/mscp-schema/data/`

| File | Rows | Purpose |
|---|---|---|
| `rules_versioned.parquet` | 540 | mSCP security rules with enforcement metadata |
| `rule_payloads.parquet` | 463 | Check/fix scripts, mobileconfig_info, DDM details per rule |
| `baseline_edges.parquet` | 4,400+ | Rule-to-baseline membership |
| `baseline_meta.parquet` | 14 | Baseline names, titles, authors |
| `rule_meta.parquet` | 463 | Rule title, discussion, severity |
| `control_tiers.parquet` | 728 | NIST 800-53 control tiers |
| `sections.parquet` | 11 | mSCP section definitions |
| `envelope_patterns.parquet` | 4 | XML nesting templates |
| `envelope_meta_keys.parquet` | 20 | Envelope metadata key definitions |

Consumers: `crates/mscp/` (baseline list, schema rules, generate).

### `crates/osquery-schema/`

osquery table schema is also embedded (parquet); same versioning and
update flow applies.

---

## Three-layer versioning

The data carries three independent stability signals so consumers can
diagnose what changed without diffing parquet binaries.

### Layer 1 — Schema version (CalVer)

Every JSON Schema in posture's `out/schemas/` has:

```yaml
x-schema-version: "2026.04.02.1"   # YYYY.MM.DD.MICRO
```

Bumps **only when the type structure changes** (fields added/removed,
type changes). Same version across regenerations = safe to drop in
new parquet files without code changes.

### Layer 2 — Data hash (SHA-256)

Every schema also carries:

```yaml
x-data-file: "skip_keys.parquet"
x-data-sha256: "7227c5b9a67c..."
```

Verify after copying:

```bash
shasum -a 256 crates/mdm-schema/data/skip_keys.parquet
# Compare against x-data-sha256 from posture's schema
```

### Layer 3 — Manifest

`out/manifest.json` (in posture's output) lists every file with
filename, sha256, row count, byte size, and column inventory. Diff old
vs new manifest to see exactly what changed without parsing parquet.

---

## PROCEDURE update_schema_data(posture_root)

```
SCHEMA_TOOL: posture compat-check --contour {contour_crates_root}
             posture validate
             posture data-report

INPUT:
  posture_root  : path to a fresh posture pipeline output (must contain
                   out/, out/schemas/, out/manifest.json)

PRECONDITIONS:
  ASSERT posture_root/out/manifest.json exists
    HALT "posture output is stale or incomplete; re-run the pipeline"
  ASSERT contour working tree is clean
    HALT "commit or stash local changes before refreshing data"
  ASSERT cargo test -p mdm-schema -p mscp-schema -p osquery-schema currently passes
    HALT "tests are red on current data — fix before refreshing"

STEP 1 — Compatibility check:
  result = posture compat-check --contour {contour_crates_root}
  # Reports per-schema status:
  #   EXACT       — same shape, safe to drop in
  #   COMPATIBLE  — new nullable columns added; existing readers OK
  #   BREAKING    — column renames/removals/type changes; needs code
  if any schema reports BREAKING:
    REQUIRE human approval before continuing
    # Note which fields broke — STEP 5 walks the code update.

STEP 2 — Copy parquet files:
  cp {posture_root}/out/capabilities.parquet  crates/mdm-schema/data/
  cp {posture_root}/out/profilecreator.parquet crates/mdm-schema/data/
  cp {posture_root}/out/skip_keys.parquet     crates/mdm-schema/data/
  cp {posture_root}/out/{baseline_meta,baseline_edges,control_tiers}.parquet \
                                              crates/mscp-schema/data/
  cp {posture_root}/out/{rule_meta,rules_versioned,rule_payloads}.parquet \
                                              crates/mscp-schema/data/
  cp {posture_root}/out/{sections,envelope_patterns,envelope_meta_keys}.parquet \
                                              crates/mscp-schema/data/

STEP 3 — Verify integrity:
  posture validate
    # Runs sha256 verification on every emitted file against manifest.

  # Manual sanity check (optional):
  shasum -a 256 crates/mdm-schema/data/*.parquet
  shasum -a 256 crates/mscp-schema/data/*.parquet
  ASSERT every hash matches the corresponding x-data-sha256 in
         posture's schemas
    HALT "hash mismatch on {file}; copy was incomplete or corrupted"

STEP 4 — Run schema-crate tests:
  cargo test -p mdm-schema -p mscp-schema -p osquery-schema
  # Tests assert minimum row counts and column-presence invariants.
  # If data is empty / column missing / shape drift, tests fail.
  if tests fail:
    if STEP 1 reported only EXACT/COMPATIBLE:
      HALT "tests fail on COMPATIBLE data — investigate; this is unexpected"
    else:
      proceed to STEP 5

STEP 5 — (BREAKING only) Update Rust readers:
  for each BREAKING schema reported by STEP 1:
    schema_file = posture_root/out/schemas/{name}.schema.yaml
    reader     = crates/mscp-schema/src/{name}.rs    # or mdm-schema/src/...

    # Compare Arrow schemas:
    pqrs schema crates/{crate}-schema/data/{name}.parquet
    yq '.properties' {schema_file}

    # Sync the reader:
    # - Update col() calls for renamed columns
    # - Add new fields to types.rs
    # - Update derive()s if new column types

  cargo test -p {crate}-schema   # iterate until green

INVARIANTS:
  # source_versions.parquet and platform_validity.parquet change on
  # EVERY posture regeneration even when no real data changed (they
  # carry the timestamp of the run). Don't include them in the
  # consumer-side hash check.
  WARN if validating against full manifest:
    "use --exclude source_versions,platform_validity to filter
     volatile-by-design files"

POSTCONDITIONS:
  RETURN {
    files_updated:  list of parquet files that changed,
    breaking_count: count of schemas that required code changes,
    posture_version: posture's pipeline version string,
  }

  # Commit the data + reader changes together; don't ship a parquet
  # update without the matching code update if STEP 5 ran.
```

---

## Operational notes

### Selective copies

If only one dataset changed (e.g. just mSCP rules), you don't have to
re-copy everything. Use `posture compat-check` to identify which files
actually changed since the last copy:

```bash
posture compat-check --contour /Users/henry/Projects/GitHub/contour/crates/ --json \
  | jq -r '.files[] | select(.changed) | .filename'
```

Copy only those.

### Generated tests catch missing data

Each schema crate has test files under `tests/` that assert minimum
row counts (e.g. `assert!(baselines.len() >= 10)`). If a posture
regeneration accidentally drops data, these tests fail loudly. Don't
disable them.

### Volatile files (skip during validation)

`source_versions.parquet` and `platform_validity.parquet` change on
every posture regeneration even when nothing semantic changed. They're
valid data but produce noise in hash diffs:

```bash
posture validate --exclude source_versions,platform_validity
```

### Versioning policy

Bumping `x-schema-version` (Layer 1) without a real shape change is
discouraged — it forces all consumers (contour, third parties) to
re-test, and dilutes the signal. Bump only when:
- Adding/removing fields
- Changing field types
- Renaming fields

Pure data refreshes (more rules, updated values) leave Layer 1 at the
same version; consumers see Layer 2 (sha256) and Layer 3 (manifest)
flip but no code-level coordination is required.

---

## Reference

- Posture consumer guide — `CONSUMER_GUIDE.md` in the posture pipeline output
- Posture CLI repo — `github.com/headmin/posture`
- Posture commands:
  - `posture validate` — verify all hashes match the manifest
  - `posture compat-check --contour <crates-root>` — check schema compatibility against a contour checkout
  - `posture data-report` — generate manifest.json
- Reader modules in contour:
  - `crates/mdm-schema/src/lib.rs` (capabilities, profilecreator, skip_keys)
  - `crates/mscp-schema/src/{baseline_meta,rule_meta,rule_payloads,...}.rs`
  - `crates/osquery-schema/src/lib.rs`

## Why this SOP is hybrid

The data inventory and versioning model are reference material — they
describe what exists, not what to do. Locking them into a procedural
shape would force every reader to mentally execute the procedure to
extract the inventory.

The refresh flow IS procedural: clear preconditions (clean tree, green
tests), explicit steps (compat-check → copy → validate → test → maybe
update readers), and a typed branch on `BREAKING` to gate human
approval. So that part is a real PROCEDURE.

The two halves split cleanly along this seam.
