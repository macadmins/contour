# SOP: embedded schema data (contour developers)

This SOP is for people building contour, not for operators. It describes
where the datasets compiled into the binary come from and how a build
decides which one it embeds.

## What is embedded

Five crates embed Parquet tables at compile time with `include_bytes!`:

| Crate | Archive | What it carries |
|---|---|---|
| `mdm-schema` | `mdm-schema.zip` | Apple payloads, declarations, commands, skip keys, App Schema facts |
| `mscp-schema` | `mscp-schema.zip` | mSCP rules, baselines, sections, links; Fleet's GitOps JSON Schema |
| `osquery-schema` | `osquery-schema.zip` | osquery and Fleet table schemas |
| `windows-schema` | `windows-schema.zip` | Windows CSP nodes, ADMX policies, app templates, STIG corpus |
| `app-policy-schema` | `app-policy-schema.zip` | AI-tool managed-configuration policies |

`crates/*/data/` is gitignored. `schema-data.toml` at the workspace root is
what says which dataset a build carries.

## How a build resolves `data/`

`build-support/schema_data.rs` runs in each crate's build script:

1. `CONTOUR_SCHEMA_SRC` set — copy the crate's files from that directory (a
   local dataset build) and stamp `data/` as `local <path>`. Development
   only; the build warns.
2. `data/.dataset-pin` matches what `schema-data.toml` asks for and every
   required file is present — use it, no network.
3. Otherwise fetch the crate's archive for `zip_release` from the host in
   `CONTOUR_SCHEMA_ZIP_BASE`, check it against `sha256_<crate>`, and replace
   `data/` whole. The host is not in the tree: CI reads the repository
   secret of the same name, a developer exports it once.

`CONTOUR_SCHEMA_SKIP_DOWNLOAD` keeps a mismatched `data/` and warns that the
binary does not embed the pin. `CONTOUR_*_SCHEMA_URL` fetches one crate's
archive from another URL, unverified.

## The OS seed: `mdm-schema-beta.zip` → `data-beta/`

When a release carries Apple's pre-release seed, it ships one more archive,
`mdm-schema-beta.zip`, and `schema-data.toml` records `sha256_mdm-schema-beta`.
`mdm-schema`'s build script then fills `crates/mdm-schema/data-beta/` the same
way (local `CONTOUR_SCHEMA_BETA_SRC`, the stamp, or the pinned archive, or
`CONTOUR_MDM_SCHEMA_BETA_URL`) and the `*_beta` accessors embed it. It sits
beside `data/`, not inside it, because a stable refetch replaces `data/` whole.

Without that hash the seed is not carried: `data-beta/` is removed and every
`--beta` surface refuses. Dropping the line when the seed's OS ships is the
whole retirement.

## PROCEDURE update_schema_data

```
PRECONDITIONS:
  - a new dataset release is published at CONTOUR_SCHEMA_ZIP_BASE
  - its per-archive sha256 values are known

STEPS:
  1. Edit schema-data.toml: set zip_release, and each sha256_<crate>
     (sha256_mdm-schema-beta only when the release carries a seed).
  2. cargo build — every crate whose stamp differs fetches, verifies and
     re-stamps its data/. A hash mismatch fails the build and says so.
  3. cargo test --workspace.
  4. contour census — the embedded counts come from the new data.

POSTCONDITIONS:
  - each crates/<crate>/data/.dataset-pin reads
    `release <zip_release> sha256 <hash>`
```

A table a crate embeds but the release does not carry gets a zero-length
placeholder so the build compiles; `no_embedded_table_is_an_empty_placeholder`
fails on it, so an incomplete release is loud.
