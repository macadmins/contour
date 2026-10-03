# contour osquery -- osquery Schema Reference

> **Status: Preview** — feature-complete for core workflows, APIs and flags may still change before 1.0.

`contour osquery` is a fast, offline reference for the osquery schema.

Two schemas are embedded in the binary: upstream osquery's 286 tables and 2,624 columns, and Fleet's schema for the same tables plus 91 Fleet-only agent tables, with Fleet's worked examples, notes and docs links. Look up a table layout, find the right column for a query, check platform support, and validate the SQL contour or you wrote. No osquery install, no network round-trip.

**What you get:** the ground-truth osquery schema as a local CLI.

- **No install needed.** The schema lives in the contour binary. Nothing to `apt-get`, `brew install`, or `pip install` on the build host.
- **No network round-trips.** Faster than reading docs, faster than spinning up osquery itself. Works offline and in CI.
- **Agent-safe.** AI agents should use this before emitting any osquery query, so the query references columns that actually exist, and `osquery validate` afterwards, so a typo never ships. See [For AI agents](#for-ai-agents).
- **Provenance on every hit.** A table is `both`, `osquery` (not in Fleet's schema) or `fleet` (needs Fleet's agent; plain osqueryd returns nothing). Nothing is merged silently.

## Quick Start

```bash
# Find tables and columns mentioning a keyword
contour osquery search filevault

# Show the full schema for one table
contour osquery table disk_encryption

# Embedded schema statistics
contour osquery stats

# Check every query in a Fleet GitOps repo against both schemas
contour osquery validate -r ./fleet-gitops
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
| `--platform <OS>` | Restrict to one platform: `darwin`, `linux`, `windows`. Applies to Fleet-only hits too | all platforms |
| `--json` | Emit JSON instead of human-readable output | `false` |

Fleet-only tables are listed after the upstream hits and labelled. In JSON every entry carries `source`: `osquery` or `fleet`.

```bash
contour osquery search certificate --platform darwin
contour osquery search alf --json
```

### `osquery table`

Show the complete schema for a single table — description, platforms,
the evented flag, and every column with its type, required/hidden flags,
and description. Where Fleet documents the table, its docs link, notes
and worked example follow; in JSON they sit under `fleet`. A Fleet-only
table is answered the same way, with `source: fleet` and a note that it
needs Fleet's agent.

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

Print embedded-schema statistics — total tables and columns, the
per-platform table counts (darwin / linux / windows), and which tables
each schema has (`sources` in JSON).

```
contour osquery stats [--json]
```

```bash
contour osquery stats
```

### `osquery validate`

Check every osquery query in Fleet GitOps YAML against both embedded
schemas, offline. Reads `policies:` and `queries:` collections wherever
they appear, `labels:` with a query, and the flat lists contour writes
(`*.policies.yml`, `*.reports.yml`, `*.labels.yml`).

```
contour osquery validate <PATH> [-r] [--json]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATH>` | A GitOps repo, directory, or single YAML file | **required** |
| `-r, --recursive` | Recurse into directories | top level only |
| `--json` | Emit `{success, files_scanned, queries_checked, findings, warnings, unreadable}` | `false` |

What fails (exit 1): a table in neither schema (with did-you-mean
suggestions), a column the table does not have (single-table queries), a
`platform:` the table does not exist on, a `required` column left
unconstrained in `WHERE`. What warns: a Fleet-only table (real under
Fleet's agent, empty under plain osqueryd), a query over a table that is
not on every platform with no `platform:` declared, and an osquery
extension table neither schema lists.

```bash
contour osquery validate -r ./fleet-gitops
contour osquery validate platforms/macos/reports/security-posture.reports.yml --json
```

### `osquery verify`

Render every generated query under a path as copy-pasteable commands for
both host kinds: `osqueryi --json "<sql>"` for a dev machine or CI, and
`sudo orbit shell -- --json "<sql>"` for a Fleet-managed host. Nothing is
executed.

```
contour osquery verify <PATH> [-o FILE] [--json]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATH>` | A GitOps repo, directory, or single `*.policies.yml` / `*.reports.yml` | **required** |
| `-o, --output <FILE>` | Write the commands as Markdown to this file | print |
| `--json` | Emit `{count, osqueryi, orbit, queries[{name, source, query, osqueryi_cmd, orbit_cmd}]}` | `false` |

## Worked example: building a Santa allowlist from osquery output

The schema commands above tell you what tables exist; this section shows the
canonical query for the Santa allowlist workflow. It joins `apps` (the
installed-app inventory) with `signature` (code-signing metadata) on `path`,
pre-computes the SigningID composite at SQL time, and exposes the CDHash for
the most-specific rule variant.

```sql
SELECT DISTINCT
    a.name,
    a.bundle_identifier,
    a.bundle_version,
    s.team_identifier,
    s.team_identifier || ':' || a.bundle_identifier AS signing_id,
    s.cdhash
FROM apps AS a
JOIN signature AS s ON a.path = s.path
WHERE s.signed = 1
    AND s.hash_resources = 0
    AND s.hash_executable = 0
    AND a.path LIKE '/Applications/%'
ORDER BY a.name;
```

Run it through Fleet (or local `osqueryi`), export as CSV, and feed it to
`contour santa allow`:

```bash
# Vendor-level (one rule per TeamID — fewest rules, lowest churn)
contour santa allow --input fleet-export.csv --rule-type team-id --org com.acme -o santa.mobileconfig

# App-level (one rule per signing_id — uses the precomputed column)
contour santa allow --input fleet-export.csv --rule-type signing-id --org com.acme -o santa.mobileconfig

# Binary-level (one rule per exact build — most specific, requires the cdhash column)
contour santa allow --input fleet-export.csv --rule-type cdhash --org com.acme -o santa.mobileconfig

# Auto (signing-id when derivable, team-id fallback per row)
contour santa allow --input fleet-export.csv --rule-type auto --org com.acme -o santa.mobileconfig
```

**Why `s.team_identifier || ':' || a.bundle_identifier`?** osquery's
`signature` table doesn't expose a composite `signing_id` column. Pre-computing
the SQL-side concatenation gives `contour santa allow --rule-type signing-id`
a column to consume directly, instead of relying on `--rule-type auto` to
synthesize it row-by-row. Mind the spelling — `signing_id`, not `signning_id`;
contour's CSV parser looks for `signing_id` / `signingid` / `signing_identifier`.

The full Santa-side toolkit is documented
in [contour-santa.md](contour-santa.md).

## For AI agents

`contour osquery` exists largely so that an LLM or coding agent writing
osquery or Fleet queries can **verify the schema instead of guessing
it**. Table and column names are a common hallucination source — this
command is the ground-truth check.

**Always pass `--json`.** Every subcommand emits structured JSON for
reliable parsing.

Recommended agent workflow:

1. `contour osquery search <keyword> --json` — discover candidate
   tables and columns for the data you need. Check `source`: `fleet`
   means the query needs Fleet's agent.
2. `contour osquery table <table_name> --json` — confirm the **exact**
   column names, types, `required` flags, and platform support *before*
   emitting a query. Do not reference a column you have not confirmed
   here. Start from Fleet's `examples` where present.
3. `contour osquery validate <file> --json` — check the YAML you wrote
   before deploying it. `findings` must be empty.

Why this is safe to rely on:

- **Offline and deterministic** — the schema is embedded at build time.
  No osquery install and no network access; a given contour version
  always returns the same schema.
- **Authoritative** — it is the real osquery schema (286 upstream tables,
  2,624 columns) and Fleet's real schema (91 more tables), not a paraphrase.

**If a table or column does not appear in `contour osquery`, treat it as
not available** — do not emit a query that depends on it.

## Notes

- The schema is **embedded at build time** — no osquery install or
  network access is needed.
- `--platform` (`darwin` / `linux` / `windows`) narrows `search` results
  to one OS, Fleet-only hits included — useful when authoring
  platform-specific queries.
- The same checks run inside contour: every query `mscp generate` writes
  is validated before the file is, and `mscp validate` re-checks a repo.
