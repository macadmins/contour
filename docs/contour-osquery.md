# contour osquery -- osquery Schema Reference

> **Status: Preview** — feature-complete for core workflows, APIs and flags may still change before 1.0.

`contour osquery` is a fast, offline reference for the osquery schema. It
queries an embedded snapshot of every osquery table and column — 283
tables and 2,581 columns — so you can look up table layouts, find the
right column for a query, and check platform support without an osquery
install or a network connection.

Aimed at Mac admins and detection engineers writing osquery / Fleet
queries who need quick schema lookups while authoring policies — and at
**AI agents**, which should use it as the ground-truth schema check
before emitting any osquery query (see [For AI agents](#for-ai-agents)).

## Quick Start

```bash
# Find tables and columns mentioning a keyword
contour osquery search filevault

# Show the full schema for one table
contour osquery table disk_encryption

# Embedded schema statistics
contour osquery stats
```

## Commands

### `osquery search`

Search table names, column names, and descriptions for a keyword.
Results are grouped by table.

```
contour osquery search <QUERY> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<QUERY>` | Search term — matches table names, column names, and descriptions | **required** |
| `--platform <OS>` | Restrict to one platform: `darwin`, `linux`, `windows` | all platforms |
| `--json` | Emit JSON instead of human-readable output | `false` |

```bash
contour osquery search certificate --platform darwin
contour osquery search alf --json
```

### `osquery table`

Show the complete schema for a single table — description, platforms,
the evented flag, and every column with its type, required/hidden flags,
and description.

```
contour osquery table <TABLE_NAME> [--json]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<TABLE_NAME>` | Table name (e.g., `preferences`, `alf`, `disk_encryption`) | **required** |
| `--json` | Emit JSON instead of human-readable output | `false` |

```bash
contour osquery table preferences
```

### `osquery stats`

Print embedded-schema statistics — total tables and columns, and the
per-platform table counts (darwin / linux / windows).

```
contour osquery stats [--json]
```

```bash
contour osquery stats
```

## For AI agents

`contour osquery` exists largely so that an LLM or coding agent writing
osquery or Fleet queries can **verify the schema instead of guessing
it**. Table and column names are a common hallucination source — this
command is the ground-truth check.

**Always pass `--json`.** Every subcommand emits structured JSON for
reliable parsing.

Recommended agent workflow:

1. `contour osquery search <keyword> --json` — discover candidate
   tables and columns for the data you need.
2. `contour osquery table <table_name> --json` — confirm the **exact**
   column names, types, `required` flags, and platform support *before*
   emitting a query. Do not reference a column you have not confirmed
   here.
3. `contour osquery stats --json` — sanity-check coverage (per-platform
   table counts).

Why this is safe to rely on:

- **Offline and deterministic** — the schema is embedded at build time.
  No osquery install and no network access; a given contour version
  always returns the same schema.
- **Authoritative** — it is the real osquery schema (283 tables, 2,581
  columns), not a paraphrase.

**If a table or column does not appear in `contour osquery`, treat it as
not available** — do not emit a query that depends on it.

## Notes

- The schema is **embedded at build time** — no osquery install or
  network access is needed.
- `--platform` (`darwin` / `linux` / `windows`) narrows `search` results
  to one OS — useful when authoring platform-specific queries.
