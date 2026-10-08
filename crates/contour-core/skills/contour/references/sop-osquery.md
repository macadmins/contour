# SOP: osquery Schema Lookup + Policy Patterns

Two halves, both via `contour osquery`: **schema lookup** (find the table
and columns for a requirement) and a **policy-pattern cookbook** (reuse its
SQL; validate against the schema before deploying).

## ERROR-CODE ENUM

```
INVALID_FORMAT         malformed --json input
SCHEMA_VIOLATION       query names a nonexistent table (columns checked on single-table queries)
IO_ERROR               schema data missing / unreadable
UNKNOWN                unmatched (e.g. unknown table name)
```

Failure-path JSON envelope:

```json
{ "success": false, "error": "...", "error_code": "UNKNOWN" }
```


## PROCEDURE find_query_table(keyword, platform)

```
SCHEMA_SOURCE: osquery/osquery + Fleet's schema (fleetdm.com/tables), both embedded
SCHEMA_TOOL:   contour osquery search <keyword> --json
               contour osquery table <name> --json
               contour osquery stats --json
               contour osquery validate <yaml> --json     # before deploying what you wrote

INPUT:
  keyword   : noun for the check or data point ("filevault", "preferences")
  platform  : optional filter ("darwin", "linux", "windows")

PRECONDITIONS:
  ASSERT keyword is non-empty
    HALT "keyword required; got empty string"

STEP 1 — Search:
  matches = contour osquery search {keyword} [--platform {platform}] --json
  # JSON ARRAY, one entry per matching COLUMN:
  #   [ { "table_name", "table_description", "platforms", "evented",
  #       "column_name", "column_description", "column_type",
  #       "required", "hidden", "source" }, ... ]
  # NB: "source" is "osquery" or "fleet". A "fleet" table needs Fleet's
  #     agent (fleetd); plain osqueryd returns no rows for it.
  # Empty array (no match) exits 0 — agents MUST check len(), not exit.

  ASSERT len(matches) > 0
    HALT "no osquery columns match '{keyword}'; broaden it or check `contour osquery stats`"

STEP 2 — Reduce to candidate tables:
  tables = unique(matches.map(m -> m.table_name))
  if len(tables) == 1:
    candidate = tables[0]
  else:
    REQUIRE human approval to pick from {tables} (or relax platform filter)

STEP 3 — Inspect the chosen table:
  schema = contour osquery table {candidate} --json
  # One OBJECT: { "table_name", "table_description", "platforms", "evented",
  #   "columns": [ { "column_name", "column_type", "column_description",
  #                  "required", "hidden" } ],
  #   "fleet": { "examples", "notes", "url" },   # when Fleet documents it
  #   "source", "note" }                         # on a Fleet-only table
  # Start from fleet.examples where present.
  # NB: column fields are prefixed (column_name, …) — NOT bare name/type.

  if schema.exit_code != 0:
    # Unknown table → {success:false, error_code:"UNKNOWN"} on stderr.
    HALT "{schema.error_code}: {schema.error}"

POSTCONDITIONS:
  ASSERT platform in schema.platforms (if platform was specified)
    HALT "{candidate} not available on {platform}; platforms: {schema.platforms}"

  RETURN { table: candidate, platforms, columns,
           matched_columns: matching column_names in candidate }
```


## PROCEDURE write_policy_query(intent, table_info)

```
INPUT:
  intent      : one of {is_setting_enabled, is_app_installed,
                        check_app_version, check_disk_space,
                        check_software_updates, check_mdm_profile,
                        snapshot_data, complex_multi_condition}
  table_info  : output of find_query_table

PRECONDITIONS:
  ASSERT intent in known intents (see "Idiomatic policy patterns" below)
    HALT "{intent} is not a known query pattern; pick from list or add to SOP"

EXECUTION:
  template = cookbook pattern for {intent} and table_info.platforms
  query = template.fill(table, column from table_info; value = escaped literal)
  # Identifiers come from table_info — never interpolate user strings.

INVARIANTS:
  # Version comparison MUST use version_compare(), not string comparison
  # ("4.48.100" > "4.5.1" is false lexicographically).
  if intent == check_app_version:
    ASSERT query contains "version_compare("
      HALT "version checks must use version_compare(), not string comparison"

  # Prefer bundle_identifier over name (name varies by locale and version).
  if intent == is_app_installed and platform == darwin:
    ASSERT query references bundle_identifier OR
           "WHERE name =" appears with REQUIRE human approval
      WARN "policy uses `name` instead of `bundle_identifier`"

POSTCONDITIONS:
  RETURN { query, references_table: table_info.table, intent }
```


## Idiomatic policy patterns (reference cookbook)

**Reuse these verbatim; do not invent new query structures** — synthesized
queries produce false negatives that look like compliant hosts.

Every `sql` block below is schema-checked by a test (`trap_97`). Fleet agent
tables (`filevault_status`, `software_update`, `macos_profiles`, `mdm_bridge`)
show `source: fleet` and return nothing under plain osqueryd: ship those only
to Fleet-managed hosts.

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
-- macOS — bundle_identifier preferred
SELECT 1 FROM apps WHERE bundle_identifier = 'com.1password.1password';

-- Windows
SELECT 1 FROM programs WHERE name = '1Password';
```

### `check_app_version` — version comparison via NOT EXISTS

```sql
-- Fail if outdated
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

### `snapshot_data` — raw rows, not a boolean policy

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


## Software-assignment patterns (Fleet shown; generalizes to any policy engine)

Fleet: when a policy query returns no rows, `install_software` auto-installs.

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

### Software in fleet YAML (self-service, categories, labels)

```yaml
software:
  packages:
    - path: ../platforms/macos/software/1password.yml
      self_service: true
      setup_experience: true        # install during first-time setup
      categories: [Security]
    - path: ../platforms/macos/software/firefox.yml
      self_service: true
      labels_include_any:           # only install on matching hosts
        - "Macs with Firefox needed"
      categories: [Browsers]
  fleet_maintained_apps:
    - slug: slack/darwin
      self_service: true
      categories: [Communication]
```


## PROCEDURE resolve_app_identifier(app_name)

Use when an artifact is keyed by **bundle identifier** or **Team ID** — PPPC,
`com.apple.configuration.app.settings` privacy defaults, BTM, Santa rules.

**Naming an app that is not installed is not an error.** The artifact is
schema-valid, installs, reports Verified, and grants nothing — silently and
indefinitely. Identifier accuracy is the whole job.

### IDENTIFIER_TRUST_HIERARCHY

Use the highest-ranked source available.

| Rank | Source | Trust |
|---|---|---|
| 1 | `apps` + `signature` on the device | Authoritative. |
| 2 | `codesign -dr -` on an installed copy | Authoritative for that one machine. |
| 3 | An existing profile's `Identifier` + `CodeRequirement` | Was true when written; may be stale. |
| 4 | Vendor docs / community lists | Often a different edition. |
| 5 | **Installer metadata** (pkg/dmg receipt id) | **Not a bundle identifier at all.** |

**Rank 5 is the common trap**: a pkg receipt id is not the app's
`CFBundleIdentifier`, yet looks right (`com.vendor.product.updater` vs
`com.vendor.Product`). Take only the **Team ID** from installer metadata.

```
SCHEMA_TOOL: contour osquery table apps
             contour osquery table signature

PRECONDITIONS:
  ASSERT the target table is `signature`, NOT `codesign`
    HALT "codesign is a Fleet extension table, absent from vanilla osqueryd.
          Use signature — it is core osquery and works in both."
    # `osquery validate` warns: 'codesign' is a Fleet extension table

  ASSERT the query constrains signature.path
    # REQUIRED column; unconstrained returns nothing. JOIN on apps.path supplies it.

STEP 1 — Enumerate installed apps with their signing identity:
  SELECT DISTINCT
    a.name, a.bundle_identifier, a.bundle_short_version AS version,
    a.path, s.team_identifier, s.authority
  FROM apps a
  JOIN signature s ON s.path = a.path
  WHERE a.path LIKE '/Applications/%.app'
    AND a.path NOT LIKE '%/Contents/%'
    AND a.bundle_identifier <> ''
    AND s.hash_resources = 0
    AND s.hash_executable = 0
  ORDER BY a.name;

  # Keep every clause:
  #  DISTINCT                — one signature row per architecture otherwise.
  #  NOT LIKE '%/Contents/%' — drops nested helper bundles (Helper, WebView…).
  #  bundle_identifier <> '' — some bundles carry no CFBundleIdentifier.
  #  hash_* = 0              — TABLE PARAMETERS (default 1), not predicates;
  #                            omitting them hashes every binary on the box.

STEP 2 — Validate before deploying the query:
  contour osquery validate <gitops.yml>
  # Offline; a Fleet-only table such as codesign is a warning.

POSTCONDITIONS:
  ASSERT the identifier came from rank 1-3, never rank 5
  RETURN { bundle_identifier, team_identifier, path }
```

### Helper binaries are invisible to `apps`

`apps` returns `.app` bundles only; daemons, XPC services and system
extensions never appear. **PPPC and Santa grants are made per signed
component, not per app**, so audit them via `signature` (`LIKE` on `path`):

```sql
SELECT DISTINCT identifier, team_identifier
FROM signature
WHERE (   path LIKE '/Applications/<App>.app/Contents/MacOS/%'
       OR path LIKE '/Applications/<App>.app/Contents/Library/SystemExtensions/%/Contents/MacOS/%')
  AND signed = 1 AND hash_resources = 0 AND hash_executable = 0;
```

Both patterns are required (helpers vs system extensions); a security
agent often ships 6-8 signed components.

### Reading drift results without false positives

Only one pattern is real drift: **the app is installed, under a different
bundle ID than the profile names.** Exclude first:

- **Not installed** on that machine — only a fleet-wide run tells this apart.
- **Legitimate sub-bundles** — a profile for `com.vendor.app.daemon` while
  `com.vendor.app` is installed is normally correct (PPPC targets the daemon).
- **Fuzzy name matching** — match on bundle identifier, never display name
  (`ms-office` vs "starts with Microsoft" pairs it with Teams).

### Scope limit

This yields *identity*, not *entitlement*. DDM covers only Camera,
Microphone, Accessibility, Dictation, Bluetooth, LocalNetwork, Location and
LocationAccuracy; Full Disk Access, ScreenCapture, AppleEvents, Calendar,
AddressBook and folder policies stay in PPPC. See `--sop app-privacy`.


## Other operations (prose)

### Statistics on the embedded osquery schema

```
contour osquery stats --json
# {total_tables, total_columns, <os>_tables, sources: {osquery, fleet, both, fleet_only[], osquery_only[]}}
```

### Verify generated queries against a host (osqueryi / orbit)

```
# Renders every *.policies.yml / *.reports.yml query as a copy-pasteable command.
# contour NEVER executes them — you run them on the host.
contour osquery verify ./output                  # GitOps repo, dir or file; print commands
contour osquery verify ./output -o verify.md     # write Markdown instead
contour osquery verify ./output --json           # {count, queries[{name, source, query, osqueryi_cmd, orbit_cmd}]}
#
# Each query is emitted in BOTH forms:
#   dev / CI:            osqueryi --json "<sql>"
#   Fleet-managed host:  sudo orbit shell -- --json "<sql>"   (no osqueryi there; needs root)
# Fleet `type: patch` policies are skipped — they have no query.

# Same thing inline, right after generating:
contour mscp generate ... --osquery --verify-queries
# → writes <output>/osquery/verify-commands.md
```

### Generated osquery artifacts (--osquery bridge)

```
# `contour mscp generate ... --osquery` (Fleet output) emits, per baseline:
#   osquery/<baseline>/<baseline>.policies.yml, <baseline>-audit.sh,
#   <baseline>.osquery-coverage.md, and under platforms/macos/reports/
#   <baseline>-compliance.reports.yml + security-posture.reports.yml.
# Details: --sop mscp-osquery (tiers, audit plist), --sop mscp (posture pack).
```
