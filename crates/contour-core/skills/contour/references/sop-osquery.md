# SOP: osquery Schema Lookup + Policy Patterns

This SOP covers two distinct concerns, both centred on osquery:
1. **Schema lookup** (procedural) — finding the right table and columns to
   query, given a keyword or compliance requirement.
2. **Idiomatic policy patterns** (reference cookbook) — battle-tested SQL
   templates drawn from real-world deployments (Fleet's `it-and-security`
   repo is the source for many; the patterns generalize to any osquery
   consumer). Agents should reuse these patterns; inventing new query
   structures is a common source of false-negatives (queries that work
   locally but fail across host versions).

The lookup half is procedural. The patterns half is a cookbook —
agents pick a pattern, fill in the table/column, and validate against the
schema before deploying. Both halves use the same `contour osquery` CLI,
just with different shapes of result.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/profile/tests/sop_traps.rs`

## ERROR-CODE ENUM

```
INVALID_FORMAT         malformed --json input
SCHEMA_VIOLATION       query references nonexistent table or column
IO_ERROR               schema data missing / unreadable
UNKNOWN                unmatched (e.g. unknown table name)
```

Failure-path JSON envelope (since contour ≥0.2.1):

```json
{ "success": false, "error": "...", "error_code": "UNKNOWN" }
```

---

## PROCEDURE find_query_table(keyword, platform)

```
SCHEMA_SOURCE: osquery/osquery (via contour's embedded snapshot)
SCHEMA_TOOL:   contour osquery search <keyword> --json
               contour osquery table <name> --json
               contour osquery stats --json

INPUT:
  keyword   : a noun describing the compliance check or data point
              (e.g. "disk_encryption", "filevault", "preferences")
  platform  : optional platform filter ("darwin", "linux", "windows")
              — narrows results when the same keyword applies to multiple OS

PRECONDITIONS:
  ASSERT keyword is non-empty
    HALT "keyword required; got empty string"

STEP 1 — Search:
  matches = contour osquery search {keyword} [--platform {platform}] --json
  # Returns a JSON ARRAY of column-level matches:
  #   [ { "table_name", "table_description", "platforms",
  #       "evented", "column_name", "column_description",
  #       "column_type", "required", "hidden" }, ... ]
  # NB: each entry is one matching COLUMN (so a single matching table
  #     with 8 matching columns produces 8 entries).
  # Empty array (no match) exits 0 — agents MUST check len(), not exit.

  ASSERT len(matches) > 0
    HALT "no osquery columns match '{keyword}'; try `contour osquery stats` \
          to see registered tables, or broaden the keyword"

STEP 2 — Reduce to candidate tables:
  tables = unique(matches.map(m -> m.table_name))
  if len(tables) == 1:
    candidate = tables[0]
  else:
    REQUIRE human approval to pick from {tables} (or relax platform filter)

STEP 3 — Inspect the chosen table:
  schema = contour osquery table {candidate} --json
  # Returns one OBJECT:
  #   { "table_name", "table_description", "platforms",
  #     "evented", "columns": [ { "column_name", "column_type",
  #                                "column_description",
  #                                "required", "hidden" }, ... ] }
  # NB: column fields are prefixed (column_name, column_type,
  #     column_description) — NOT bare name/type. Same prefix used
  #     by `osquery search` results.

  if schema.exit_code != 0:
    # Unknown table — emits {success:false, error_code:"UNKNOWN"} on stderr.
    HALT "{schema.error_code}: {schema.error}"

POSTCONDITIONS:
  ASSERT platform in schema.platforms (if platform was specified)
    HALT "{candidate} not available on {platform}; platforms: {schema.platforms}"

  RETURN {
    table: candidate,
    platforms: schema.platforms,
    columns: schema.columns,
    matched_columns: matches.filter(m -> m.table_name == candidate)
                            .map(m -> m.column_name),
  }
```

---

## PROCEDURE write_policy_query(intent, table_info)

```
INPUT:
  intent      : one of {is_setting_enabled, is_app_installed,
                        check_app_version, check_disk_space,
                        check_software_updates, check_mdm_profile,
                        snapshot_data, complex_multi_condition}
  table_info  : output of find_query_table — table name, columns, platforms

PRECONDITIONS:
  ASSERT intent in known intents (see "Idiomatic policy patterns" below)
    HALT "{intent} is not a known query pattern; pick from list or add to SOP"

EXECUTION:
  # Pick the matching SQL template (see cookbook below).
  template = get_template(intent, table_info.platforms)

  # Substitute identifiers from table_info — never interpolate user strings
  # directly (sql-injection avoided because we control the template).
  query = template.fill({
    table:    table_info.table,
    column:   chosen column from table_info.columns,
    value:    user-provided literal (escape per template rules),
  })

INVARIANTS:
  # Version comparison MUST use osquery's version_compare() function, not
  # string comparison. String comparison fails on mixed-format versions
  # ("4.48.100" > "4.5.1" is false lexicographically, but true semantically).
  if intent == check_app_version:
    ASSERT query contains "version_compare("
      HALT "version checks must use version_compare(); string comparison \
            produces wrong results across version formats"

  # Prefer bundle_identifier over name for app checks — name varies by
  # locale and macOS version; bundle_identifier is stable.
  if intent == is_app_installed and platform == darwin:
    ASSERT query references bundle_identifier OR
           "WHERE name =" appears with REQUIRE human approval
      WARN "policy uses `name` instead of `bundle_identifier`; \
            name can vary by locale and major version"

POSTCONDITIONS:
  RETURN { query, references_table: table_info.table, intent }
```

---

## Idiomatic policy patterns (reference cookbook)

Battle-tested patterns drawn from real-world osquery deployments
(Fleet's public `it-and-security` repo is the source for several below).
**Reuse these
verbatim; do not invent new query structures** — agents that synthesize
queries from scratch produce false-negatives that look like compliant
hosts but are actually unmonitored.

### `is_setting_enabled` — boolean check

```sql
-- Disk encryption (macOS)
SELECT 1 FROM filevault_status WHERE status LIKE '%on%';

-- Disk encryption (Linux)
SELECT 1 FROM mounts m, disk_encryption d
WHERE m.device_alias = d.name AND d.encrypted = 1 AND m.path = '/';

-- Disk encryption (Windows)
SELECT 1 FROM bitlocker_info WHERE protection_status = 1;

-- Firewall enabled (macOS)
SELECT 1 FROM alf WHERE global_state >= 1;
```

### `is_app_installed` — app presence check

```sql
-- macOS — bundle_identifier preferred (stable across versions)
SELECT 1 FROM apps WHERE bundle_identifier = 'com.1password.1password';

-- Windows
SELECT 1 FROM programs WHERE name = '1Password';
```

### `check_app_version` — version comparison via NOT EXISTS

```sql
-- Fail-if-outdated pattern (NOT EXISTS returns 1 only if no compliant app found)
SELECT 1 WHERE NOT EXISTS (
  SELECT 1 FROM apps
  WHERE name = 'Slack.app'
    AND version_compare(bundle_short_version, '4.48.100') < 0
);

-- Multi-OS version check
SELECT 1 FROM os_version
WHERE version >= '26.4' OR version >= '15.7.5';
```

### `check_disk_space` — free-space ratio

```sql
-- macOS / Linux (>10% free)
SELECT 1 FROM mounts
WHERE path = '/' AND CAST(blocks_available AS REAL) / blocks > 0.10;

-- Windows
SELECT 1 WHERE (
  SELECT CAST(SUM(free_space) AS REAL) / SUM(size)
  FROM logical_drives WHERE file_system = 'NTFS'
) > 0.10;
```

### `check_software_updates`

```sql
SELECT 1 FROM software_update WHERE software_update_required = 0;
```

### `check_mdm_profile` — MDM-profile presence

```sql
SELECT 1 FROM macos_profiles WHERE identifier = 'com.fleetdm.nudge.managed';
```

### `snapshot_data` — collect raw rows (not boolean policy)

```sql
-- Apple Intelligence opt-in detection
SELECT * FROM plist
WHERE path LIKE '/Users/%/Library/Preferences/com.apple.CloudSubscriptionFeatures.optIn.plist';

-- XProtect reports
SELECT * FROM xprotect_reports;
```

### `complex_multi_condition` — combined checks

```sql
-- App installed + profile present + package receipt
SELECT 1 WHERE
  EXISTS (SELECT 1 FROM macos_profiles WHERE identifier = 'com.fleetdm.nudge.managed')
  AND EXISTS (SELECT 1 FROM apps
              WHERE bundle_identifier = 'com.github.macadmins.Nudge'
                AND bundle_short_version LIKE '2.%')
  AND EXISTS (SELECT 1 FROM package_receipts WHERE package_id = 'com.fleetdm.Nudge.assets');
```

---

## Software-assignment patterns (Fleet shown; generalizes to any policy engine)

These are not osquery patterns, but agents writing osquery policies often
need them as the next step. Fleet's policy engine is the example shown
below — when a policy query returns no rows, Fleet's `install_software`
wires an auto-install. Other policy engines that consume osquery
results have analogous hooks; the SQL patterns are portable.

### Custom package YAML

```yaml
# platforms/macos/software/1password.yml
url: https://downloads.1password.com/mac/1Password.pkg
```

### Policy with auto-install

```yaml
- name: macOS - 1Password installed
  query: SELECT 1 FROM apps WHERE bundle_identifier = 'com.1password.1password';
  install_software:
    package_path: ../software/1password.yml
  platform: darwin
```

When the policy fails (no row returned), Fleet auto-installs the package.

### Software in fleet YAML (self-service, categories, labels)

```yaml
software:
  packages:
    - path: ../platforms/macos/software/1password.yml
      self_service: true
      setup_experience: true        # install during first-time setup
      categories:
        - Security
    - path: ../platforms/macos/software/firefox.yml
      self_service: true
      labels_include_any:           # only install on matching hosts
        - "Macs with Firefox needed"
      categories:
        - Browsers
  fleet_maintained_apps:
    - slug: slack/darwin
      self_service: true
      categories:
        - Communication
```

---

## Other operations (prose)

### Statistics on the embedded osquery schema

```
contour osquery stats --json
# Returns: {total_tables, total_columns, darwin_tables, linux_tables,
#           windows_tables}
# As of contour 0.2.x: 283 tables, 2581 columns total.
```

### Verify generated queries against a host (osqueryi / orbit)

```
# Render every generated *.policies.yml / *.reports.yml query as a path-resolved,
# copy-pasteable command. contour NEVER executes them — you run them on the host.
contour osquery verify ./output                  # scan a GitOps repo (or a dir/file), print commands
contour osquery verify ./output -o verify.md     # write a Markdown reference instead of printing
#
# Each query is emitted in BOTH host forms (one doc works everywhere):
#   dev / CI:            osqueryi --json "<sql>"
#   Fleet-managed host:  sudo orbit shell -- --json "<sql>"   (no osqueryi there; needs root)
# Binary paths are resolved (PATH, then the standard install location).
# Non-osquery policies (e.g. Fleet `type: patch` software/FMA policies) are skipped — they have no query.

# Same thing inline, right after generating:
contour mscp generate ... --osquery --verify-queries
# → writes <output>/osquery/verify-commands.md
```

### Generated osquery artifacts (--osquery bridge)

```
# `contour mscp generate ... --osquery` (Fleet output) emits, per baseline:
#   osquery/<baseline>/<baseline>.policies.yml          — pass/fail Fleet policies (native query or plist read)
#   osquery/<baseline>/<baseline>-audit.sh              — Tier-2 audit script (writes /Library/Preferences/<org>.<baseline>.audit.plist)
#   osquery/<baseline>/<baseline>.osquery-coverage.md   — Tier-1/Tier-2/uncovered coverage report
#   platforms/macos/reports/<baseline>-compliance.reports.yml  — scheduled query over the audit plist
#   platforms/macos/reports/security-posture.reports.yml       — baseline-independent posture pack (overridable; see --sop mscp)
```
