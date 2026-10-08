# SOP: Profile Generation & Validation

Follow the PROCEDURE blocks deterministically.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/profile/tests/sop_traps.rs`

## Finding a command

`contour profile find <term>` fuzzy-searches profile commands and prints
invocations plus a `help-ai --command` pointer. E.g. `contour profile find "rename org"` →
`normalize`.

## ERROR-CODE ENUM

Agents MUST switch on `error_code`, not substring-match `error`.

```
INVALID_IDENTIFIER     identifier syntax issue (spaces, invalid chars)
INVALID_FORMAT         not a valid plist / corrupted / not a profile
MISSING_PAYLOAD_TYPE   required PayloadType field absent
SCHEMA_VIOLATION       failed Apple-schema validation
IO_ERROR               file not found, permission denied, disk full
INVALID_ORG            org domain malformed
UNKNOWN                unmatched — treat as fatal, do NOT auto-retry
```

A failed top-level call in `--json` mode emits on stderr:

```json
{ "success": false, "error": "...", "error_code": "INVALID_ORG" }
```

## PROCEDURE generate_profile(payload_key, org, output_file)

```
INPUT:
  payload_key  : Apple PayloadType (e.g. com.apple.mobiledevice.passwordpolicy)
  org          : reverse-domain identifier (com.acme, NOT com.example)
  output_file  : explicit .mobileconfig path  ←  NB: file path, not directory
                 (passing a directory fails with "Is a directory (os error 21)")

PRECONDITIONS:
  ASSERT org matches /^[a-z0-9-]+(\.[a-z0-9-]+)+$/
    HALT "org must be reverse-domain; got '{org}'"
  ASSERT org != "com.example"
    HALT "refusing default 'com.example' — produces non-deployable PayloadIdentifier"
    # also covers org resolved via profile.toml or .contour/config.toml
  ASSERT parent(output_file) exists OR can be created
    AUTO_FIX: mkdir -p {parent(output_file)}

STEP 1 — Schema lookup:
  schema = contour profile search {payload_key} --json
  # Exit code is always 0 — agents MUST check array length, not exit.
  ASSERT len(schema) > 0
    HALT "unknown payload: {payload_key}. Run `contour profile search <keyword>` to discover."
  exact = filter(schema, fn entry: entry.payload_type == {payload_key})
  if len(exact) == 0:
    WARN "no exact match for {payload_key}; closest: {schema[0..3].payload_type}"
    REQUIRE human approval before proceeding with closest match

STEP 2 — Generation:
  result = contour profile generate {payload_key} --full --org {org} \
           -o {output_file} --json
  # Success: { "success": true, "output": path, "payload_type", "title",
  #            "format": "mobileconfig" | "plist", "fields": "all" | "required" }
  if result.exit_code != 0:
    HALT "{result.error_code}: {result.error}"   # JSON on stderr

STEP 3 — Post-generation validation (always):
  CALL normalize_profile({result.output}, {org})
  validation = contour profile validate {result.output} --json
  # { "valid": bool, "errors": [string], "warnings": [string],
  #   "schema_validation": { "valid", "errors", "warnings" },
  #   "profile": { "identifier", "uuid", "organization", ... } }
  ASSERT validation.valid AND validation.schema_validation.valid
    HALT "generated profile failed validation: {validation.errors}"

POSTCONDITIONS:
  RETURN { file_path: result.output,
           payload_identifier: validation.profile.identifier,
           payload_uuid: validation.profile.uuid,
           validation_status: "valid" }
```

## PROCEDURE normalize_profile(path, org)

```
INPUT:
  path  : .mobileconfig file path OR directory containing them
  org   : reverse-domain identifier (e.g. com.acme)

PRECONDITIONS:
  ASSERT org matches /^[a-z0-9-]+(\.[a-z0-9-]+)+$/
    HALT "org must be reverse-domain; got '{org}'"
  ASSERT path exists
    HALT "path not found: {path}"
  ASSERT org != "com.example"
    HALT "refusing default org 'com.example'"

EXECUTION:
  result = contour profile normalize {path} -r --org {org} --json
  # Single-file and batch both emit BatchResult:
  #   { "operation": "normalize", "success": bool, "total", "succeeded",
  #     "failed", "skipped", "with_warnings": int,
  #     "failure_categories": [ { "category", "count", "hint",
  #        "files": [{"file", "error" (prose), "error_code" (ENUM)}] } ],
  #     "warnings": [{"file", "warnings": [string]}],
  #     "files": [{"input", "output", "identifier", "uuid"}] }  ← single-file only

POSTCONDITIONS:
  ASSERT result.success
    for each entry in result.failure_categories[*].files:
      HALT "{entry.file}: {entry.error_code}: {entry.error}"   # every code is fatal here
    HALT "normalize failed for {result.failed}/{result.total} files"
  ASSERT result.total > 0
    WARN "no .mobileconfig files found at {path}"
  RETURN { succeeded: result.succeeded, total: result.total, files: result.files OR [] }

INVARIANTS:
  # Re-running normalize with identical inputs MUST produce identical output.
  # If `diff orig.mobileconfig <(normalize ... | normalize again)` differs, it's a bug.
```

**What normalize does:** rewrites PayloadIdentifier under `--org` (top-level
AND child payloads); regenerates UUIDs (deterministic); fixes PayloadVersion,
PayloadScope, display names; preserves MDM placeholders (`$FLEET_VAR_*`,
`%HardwareUUID%`, `{{var}}`) and XML comments.

**What normalize does NOT do:** fix name-segment typos
(`com.old.zscaler-cofing → com.yourco.zscaler-cofing`). Use
`contour profile duplicate --name 'correct-name' --org com.yourco`.

## PROCEDURE import_jamf_backup(backup_dir, org, output_dir)

```
INPUT:
  backup_dir : directory of jamf-cli profile YAML files
               (jamf-cli backup --resources profiles dumps these)
  org        : reverse-domain identifier (e.g. com.acme)
  output_dir : where to write normalized .mobileconfig files

PRECONDITIONS:
  ASSERT backup_dir exists and contains *.yaml files
    HALT "{backup_dir} contains no .yaml files"
  ASSERT org is set
    HALT "--org is required for Jamf imports (the CLI enforces this)"

EXECUTION:
  result = contour profile import --jamf {backup_dir} --all \
           -o {output_dir} --org {org} --json
  # Two response shapes — agents MUST branch on field presence.

EMPTY-SOURCE shape (no .yaml files match the Jamf envelope):
  { "success": false, "total_found": 0, "message": "No .yaml files found" }
  # `total_found` present ⇒ empty-source path; no BatchResult fields.

BATCH-RESULT shape (at least one Jamf YAML discovered):
  { "operation": "jamf_import", "success": bool,
    "total": int,    ← counts only Jamf-envelope files; other YAML is silently filtered
    "succeeded": int, "failed": int,
    "failure_categories": [ { "category", "count", "hint",
       "files": [{"file", "error", "error_code": ENUM}] } ],
    "warnings": [{"file", "warnings": [string]}] }

POSTCONDITIONS:
  if "total_found" in result:
    HALT "no Jamf YAML files in {backup_dir}; check the path or jamf-cli output"
  ASSERT result.success
    for each category in result.failure_categories:
      for each entry in category.files:
        # every code WARNs and continues — partial failures are tolerable
        WARN "[{category.category}] {entry.file}: {entry.error_code}: {entry.error}"
    if result.succeeded == 0:
      HALT "all imports failed ({result.failed}/{result.total})"
    WARN "{result.failed} of {result.total} profiles failed; {result.succeeded} imported"
  ASSERT result.total > 0
    HALT "no Jamf-format profiles discovered in {backup_dir}"
  RETURN { imported: result.succeeded, failed: result.failed,
           failure_summary: result.failure_categories }
```

## Other operations (prose recipes; not yet migrated to the procedural format)

### Generate from a recipe (multi-profile bundle)

```
1. contour profile generate --list-recipes --json
2. contour profile generate --recipe <name> --set KEY=VALUE -o <dir>
   # Secrets: op:// (1Password), env:VAR, or file:/path
   # Exit 1 if a --set key matches no {{KEY}} (typo) or any {{KEY}} is
   # unfilled; files are written either way. --allow-placeholders exits 0
   # to edit by hand — a file with a literal {{KEY}} is not deployable.
```

### Create a custom recipe

```
1. contour profile generate --create-recipe <name> <type1> <type2> ...
2. Edit the generated TOML (field values, placeholders)
3. contour profile generate --recipe <name> --recipe-path ./recipes/
```

### Validate existing profiles

```
1. contour profile validate <file_or_dir> --json    # schema validation
2. contour profile validate <dir> --recursive --report report.md
```

### Generate as a GitOps fragment (Fleet v4.83 layout)

A `fragment.toml` manifest plus Fleet's v4.83 layout, to merge into a GitOps
repo; entries go under `controls.apple_settings.configuration_profiles`.
Refuses what Fleet refuses at upload (FileVault payloads, status-subscription
declarations, an activation naming more than one configuration); leaves a
plain activation for Fleet to make.

```
contour profile generate --recipe hardening-macos-baseline --org <ORG> --fragment -o fragment/
contour {btm|pppc|notifications|support} generate <tool>.toml --fragment -o fragment/
contour santa generate rules.yaml --fragment -o fragment/
```

### Synthesize mobileconfigs from managed preferences

```
1. contour profile synthesize /Library/Managed\ Preferences/ --dry-run --json
2. contour profile synthesize /Library/Managed\ Preferences/ \
     -o profiles/ --org com.yourco --validate
3. contour profile validate profiles/ --recursive --json
```

### Duplicate / re-identity a profile

```
contour profile duplicate <source> --name 'New Name' --org com.yourco \
  -o fixed.mobileconfig
```

New PayloadDisplayName, PayloadIdentifier and UUIDs.

### Generate MDM command payloads (.plist)

```
1. contour profile command list --json
2. contour profile command info <command> --json      # keys, types, descriptions
3. contour profile command generate <command> -o cmd.plist
   --set KEY=VALUE    # command parameters
   --uuid             # add CommandUUID for tracking
   --base64           # base64 string (Fleet API)
   --json             # includes the base64 field
```

#### Common MDM commands

```
contour profile command generate DeviceLock --set PIN=123456 \
  --set Message='Locked by IT' --uuid -o lock.plist
contour profile command generate ScheduleOSUpdate --set InstallAction=InstallASAP -o update.plist
```

Also: `RestartDevice`, `RemoveProfile` (`--set Identifier=…`),
`ShutDownDevice`, `EraseDevice`, `EnableRemoteDesktop`, `RotateFileVaultKey`.

#### Send via your MDM (Fleet shown as the worked example)

```
fleetctl mdm run-command --host <hostname> --payload cmd.plist
fleetctl get mdm-command-results --id=<CommandUUID>    # verify
```

Fleet API: `POST /api/v1/fleet/commands/run` with `command` (the `--base64`
string) and `host_uuids` (array). Other MDMs take the same .plist or base64.

### Generate DEP enrollment profiles

See `--sop enrollment` (`contour profile enrollment generate --platform macOS
--skip … | --skip-list … | --interactive -o enrollment.dep.json`). `--skip-all`
never skips `FileVault` or `SoftwareUpdate` (NEVER_SKIP); naming either in
`--skip` or a skip list is refused.

## What contour refuses, and why

Both families are deliberate; do not retry or work around them.

### Not authorable at all

`form spec` / `form emit` refuse these kinds with `not-authorable`:

| Kind | Why it is refused |
|---|---|
| `MdmCommand` | protocol traffic a server sends to a device |
| `MdmCheckin` | protocol traffic a device sends to a server |
| `SharedStructure` | a shape another document carries, or a protocol body (Apple's `other/` directory) |

A `SharedStructure` looks authorable but is the *shape of a key* another
declaration embeds — go back to `profile search` for the declaration that
carries it.

### Available, but not on the target you named

Pass `--os` and `--os-version`: **without a target, neither surface below
can judge anything.**

TWO surfaces, DIFFERENT vocabularies — do not expect one to produce the
other's words.

**1. `form spec` — a `verdict` per key, in `availability`.**

```bash
contour profile form spec com.apple.applicationaccess --os macos --os-version 27.0 --json
```

Each node's `availability`: per-platform `introduced` / `deprecated` /
`removed`, an `unavailable` list, and one `verdict`:

| `verdict` | Means |
|---|---|
| `ok` | available on the target |
| `deprecated` | deprecated at or before the target; it still applies |
| `removed` | removed at or before the target; the device ignores it |
| `unavailable` | Apple marks it `n/a` on this platform — it never existed here |
| `requires-os` | exists, but needs a newer OS than the target |
| `requires-supervision` | available, but only on a supervised device |
| `unknown` | the source records no availability — see below |

**2. `form emit` (and `profile validate`) — diagnostics with rule names.**

Errors, the device will ignore what you wrote:

| Rule | Means |
|---|---|
| `not-authorable` | the payload type is a command, check-in or shared structure |
| `payload-removed-on-target` | the whole payload was removed at or before your target; nothing below it matters |
| `key-removed-on-target` | this key was removed at or before your target |
| `key-unavailable-on-platform` | Apple marks the key `n/a` on this platform |

Warnings, still emitted:

| Rule | Means |
|---|---|
| `key-deprecated-on-target` | deprecated at or before your target; it still applies |
| `key-removed` / `payload-removed` | removed *somewhere*; with no OS version named, contour cannot say whether it affects you |
| `key-deprecated` | deprecated somewhere, same caveat |

Bare (non-`-on-target`) rules: name a target to learn whether they matter.

**Where Apple names a replacement, `key-removed-on-target` repeats it** as
`Apple says: …`. Use that sentence — do not infer a replacement from the
key's name.

### Unknown is not OK

A source that records no availability (e.g. ProfileCreator community
manifests) reports `Unknown`, never `Ok`: nobody checked. Do not read
`Unknown` as approval. (Silence in Apple's schema means the key inherits its
payload's availability.)

## Key flags

- `--full` — all fields, not just required
- `--interactive` — pick segments and set values interactively
- `--format plist` — raw payload dict (for Workspace ONE)
- `--org com.yourcompany` — organization identifier (REQUIRED for generate/normalize/import)
- `--json` — structured output
- `--fragment` — composable fragment (Fleet v4.83 GitOps layout)
