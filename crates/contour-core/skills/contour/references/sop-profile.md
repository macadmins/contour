# SOP: Profile Generation & Validation

This SOP uses **procedural pseudocode** for piloted operations (generate,
normalize, jamf import) and **prose recipes** for ops not yet migrated.
Pseudocode procedures specify INPUT, PRECONDITIONS, EXECUTION, POSTCONDITIONS,
and INVARIANTS — agents follow them deterministically. The prose sections
are progressively being migrated as each operation is end-to-end traced.

Format spec: `crates/contour-core/skills/contour/references/sop-pseudocode-pilot.md`
Drift detector: `crates/profile/tests/sop_traps.rs`

## ERROR-CODE ENUM

All procedures return failures with a stable typed `error_code` from this enum.
Agents MUST switch on these codes — substring-matching the prose `error` field
is fragile and discouraged.

```
INVALID_IDENTIFIER     identifier syntax issue (spaces, invalid chars)
INVALID_FORMAT         not a valid plist / corrupted / not a profile
MISSING_PAYLOAD_TYPE   required PayloadType field absent
SCHEMA_VIOLATION       failed Apple-schema validation
IO_ERROR               file not found, permission denied, disk full
INVALID_ORG            org domain malformed
UNKNOWN                unmatched — treat as fatal, do NOT auto-retry
```

When a top-level call fails (e.g. precondition rejected by the CLI), `--json`
mode emits the envelope on stderr:

```json
{ "success": false, "error": "...", "error_code": "INVALID_ORG" }
```

---

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
    # CLI also enforces this since contour ≥0.2.1; ASSERT is defence-in-depth
    # for callers that resolve org through profile.toml or .contour/config.toml.
  ASSERT parent(output_file) exists OR can be created
    AUTO_FIX: mkdir -p {parent(output_file)}

STEP 1 — Schema lookup:
  schema = contour profile search {payload_key} --json
  # Returns a JSON array. Empty array means no match.
  # NB: exit code is always 0 — agents MUST check array length, not exit.

  ASSERT len(schema) > 0
    HALT "unknown payload: {payload_key}. Run `contour profile search <keyword>` to discover."

  exact = filter(schema, fn entry: entry.payload_type == {payload_key})
  if len(exact) == 0:
    suggestions = schema[0..3].map(fn e: e.payload_type)
    WARN "no exact match for {payload_key}; closest: {suggestions}"
    REQUIRE human approval before proceeding with closest match

STEP 2 — Generation:
  result = contour profile generate {payload_key} --full --org {org} \
           -o {output_file} --json

  # Success-path JSON shape:
  #   { "success":      true,
  #     "output":       string,        # file path written
  #     "payload_type": string,
  #     "title":        string,
  #     "format":       "mobileconfig" | "plist",
  #     "fields":       "all" | "required" }

  if result.exit_code != 0:
    # B3: failure path emits JSON on stderr with error_code
    HALT "{result.error_code}: {result.error}"

STEP 3 — Post-generation validation (always):
  CALL normalize_profile({result.output}, {org})
  validation = contour profile validate {result.output} --json

  # Validation JSON shape:
  #   { "valid": bool,                       ← top-level pass/fail
  #     "errors": [string],
  #     "warnings": [string],
  #     "schema_validation": { "valid": bool, "errors": [], "warnings": [] },
  #     "profile": { "identifier", "uuid", "organization", ... } }

  ASSERT validation.valid AND validation.schema_validation.valid
    HALT "generated profile failed validation: {validation.errors}"

POSTCONDITIONS:
  RETURN {
    file_path: result.output,
    payload_identifier: validation.profile.identifier,
    payload_uuid: validation.profile.uuid,
    validation_status: "valid",
  }
```

---

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
  # Both single-file and batch modes emit the same BatchResult shape:
  #   { "operation":   "normalize",
  #     "success":     bool,
  #     "total":       int,
  #     "succeeded":   int,
  #     "failed":      int,
  #     "skipped":     int,
  #     "with_warnings": int,
  #     "failure_categories": [
  #       { "category": string,                ← human-readable bucket
  #         "count":    int,
  #         "hint":     string,
  #         "files":    [{"file": path,
  #                       "error": message,    ← prose for humans
  #                       "error_code": ENUM}] ← typed for agents
  #       } ],
  #     "warnings":  [{"file": path, "warnings": [string]}],
  #     "files":     [{"input": path, "output": path,            ← single-file only
  #                    "identifier": str, "uuid": str}] }

POSTCONDITIONS:
  ASSERT result.success
    for each category in result.failure_categories:
      for each entry in category.files:
        SWITCH entry.error_code:
          CASE INVALID_IDENTIFIER:
            HALT "{entry.file}: identifier has spaces or invalid chars"
          CASE INVALID_FORMAT:
            HALT "{entry.file}: not a valid mobileconfig"
          CASE MISSING_PAYLOAD_TYPE:
            HALT "{entry.file}: missing required field"
          CASE SCHEMA_VIOLATION:
            HALT "{entry.file}: schema validation: {entry.error}"
          CASE IO_ERROR:
            HALT "{entry.file}: I/O: {entry.error}"
          CASE UNKNOWN:
            HALT "{entry.file}: {entry.error}"
    HALT "normalize failed for {result.failed}/{result.total} files"

  ASSERT result.total > 0
    WARN "no .mobileconfig files found at {path}"
  RETURN {
    succeeded: result.succeeded,
    total: result.total,
    files: result.files OR [],
  }

INVARIANTS:
  # Re-running normalize with identical inputs MUST produce identical output.
  # If `diff orig.mobileconfig <(normalize ... | normalize again)` differs, it's a bug.
```

**What normalize does:**
- Rewrites PayloadIdentifier under `--org` namespace (top-level AND child payloads)
- Regenerates UUIDs (deterministic from identifier)
- Fixes PayloadVersion, PayloadScope, display names
- Preserves MDM placeholders (`$FLEET_VAR_*`, `%HardwareUUID%`, `{{var}}`)
- Preserves XML comments

**What normalize does NOT do:**
- Does not fix typos in the name segment of identifiers (e.g.
  `com.old.zscaler-cofing → com.yourco.zscaler-cofing` — prefix fixed, typo preserved).
- To fix a name typo: use `contour profile duplicate --name 'correct-name' --org com.yourco`.

---

## PROCEDURE import_jamf_backup(backup_dir, org, output_dir)

```
INPUT:
  backup_dir : directory containing jamf-cli profile YAML files
               (jamf-cli backup --resources profiles dumps these)
  org        : reverse-domain identifier (e.g. com.acme)
  output_dir : where to write normalized .mobileconfig files

PRECONDITIONS:
  ASSERT backup_dir exists and contains *.yaml files
    HALT "{backup_dir} contains no .yaml files"
  ASSERT org is set
    HALT "--org is required for Jamf imports (CLI enforces this since contour ≥0.2.1)"

EXECUTION:
  result = contour profile import --jamf {backup_dir} --all \
           -o {output_dir} --org {org} --json

  # Two distinct response shapes — agents MUST branch on field presence.

EMPTY-SOURCE shape (no .yaml files match the Jamf envelope):
  {
    "success":     false,
    "total_found": 0,
    "message":     "No .yaml files found"
  }
  # Branch detection: presence of `total_found` ⇒ empty-source path.
  # Lacks the BatchResult fields entirely.

BATCH-RESULT shape (at least one Jamf YAML discovered):
  {
    "operation": "jamf_import",
    "success":   bool,
    "total":     int,    ← only counts files matching Jamf envelope;
                           non-Jamf YAML in dir is silently filtered
    "succeeded": int,
    "failed":    int,
    "failure_categories": [
      { "category": string, "count": int, "hint": string,
        "files": [{"file": path,
                   "error": message,
                   "error_code": ENUM}] }
    ],
    "warnings":  [{"file": path, "warnings": [string]}]
  }

POSTCONDITIONS:
  if "total_found" in result:
    HALT "no Jamf YAML files in {backup_dir}; check the path or jamf-cli output"

  ASSERT result.success
    for each category in result.failure_categories:
      for each entry in category.files:
        SWITCH entry.error_code:
          CASE INVALID_FORMAT:
            WARN "{entry.file}: not a valid Jamf profile YAML (skipping)"
            # continue — partial failures are tolerable for batch import
          CASE INVALID_IDENTIFIER, MISSING_PAYLOAD_TYPE, SCHEMA_VIOLATION:
            WARN "{entry.file}: {entry.error_code}: {entry.error}"
          CASE IO_ERROR:
            WARN "{entry.file}: I/O: {entry.error}"
          CASE UNKNOWN:
            WARN "[{category.category}] {entry.file}: {entry.error}"
    if result.succeeded == 0:
      HALT "all imports failed ({result.failed}/{result.total})"
    WARN "{result.failed} of {result.total} profiles failed; {result.succeeded} imported"

  ASSERT result.total > 0
    HALT "no Jamf-format profiles discovered in {backup_dir}"
  RETURN {
    imported: result.succeeded,
    failed: result.failed,
    failure_summary: result.failure_categories,
  }
```

---

## Other operations (prose recipes; not yet migrated to pseudocode)

These operations work with the existing prose recipes. They will be migrated
once each one has been end-to-end traced and added to the `sop_traps` suite.

### Generate from a recipe (multi-profile bundle)

```
1. contour profile generate --list-recipes --json   # list available recipes
2. contour profile generate --recipe <name> --set KEY=VALUE -o <dir>
   # Secrets: use op:// (1Password), env:VAR, or file:/path
```

### Create a custom recipe

```
1. contour profile generate --create-recipe <name> <type1> <type2> ...
   # Creates a TOML recipe template from payload types
2. Edit the TOML to set field values and placeholders
3. contour profile generate --recipe <name> --recipe-path ./recipes/
```

### Validate existing profiles

```
1. contour profile validate <file_or_dir> --json    # schema validation
2. contour profile validate <dir> --recursive --report report.md
```

### Generate for Fleet (fragment mode)

```
contour profile generate <payload_type> --full --fragment -o fragment/
# Creates a composable fragment that merges into existing Fleet GitOps repos.
# Output: fragment.toml + platforms/macos/configuration-profiles/*.mobileconfig
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

Creates a copy with new PayloadDisplayName, PayloadIdentifier, and UUIDs.
Use this to fix identifier typos or create variants of an existing profile.

### Generate MDM command payloads (.plist for Fleet/MDM)

```
1. contour profile command list --json                # list all 65 MDM commands
2. contour profile command info <command> --json      # show keys, types, descriptions
3. contour profile command generate <command> -o cmd.plist
   --set KEY=VALUE    # set command parameters
   --uuid             # add CommandUUID for tracking
   --base64           # output as base64 string (ready for Fleet API)
   --json             # JSON output includes base64 field automatically
```

#### Common MDM commands

```
contour profile command generate RestartDevice -o restart.plist
contour profile command generate ShutDownDevice -o shutdown.plist
contour profile command generate DeviceLock --set PIN=123456 \
  --set Message='Locked by IT' --uuid -o lock.plist
contour profile command generate EraseDevice --set PIN=123456 --uuid -o erase.plist
contour profile command generate RemoveProfile --set Identifier=com.example.wifi -o remove.plist
contour profile command generate ScheduleOSUpdate --set InstallAction=InstallASAP -o update.plist
contour profile command generate EnableRemoteDesktop -o remote.plist
contour profile command generate RotateFileVaultKey -o rotate-fvkey.plist
```

#### Send via Fleet CLI

```
fleetctl mdm run-command --host <hostname> --payload cmd.plist
```

#### Send via Fleet API (base64)

```
# Get base64 directly:
contour profile command generate RestartDevice --uuid --base64

# Or from JSON (base64 field included automatically):
contour profile command generate RestartDevice --uuid --json
# JSON output includes 'base64' field ready for Fleet API

# Use base64 value in Fleet API POST to /api/v1/fleet/commands/run
# Payload keys: command (base64 string), host_uuids (array of host UUIDs)

# Verify result:
# fleetctl get mdm-command-results --id=<CommandUUID>
```

### Generate DEP enrollment profiles

```
contour profile enrollment list --platform macOS --json
contour profile enrollment generate --platform macOS --skip-all -o enrollment.dep.json
contour profile enrollment generate --platform macOS --interactive -o enrollment.dep.json
```

---

## Key flags

- `--full` — include all fields, not just required
- `--interactive` — pick segments and set values interactively
- `--format plist` — raw payload dict (for Workspace ONE)
- `--org com.yourcompany` — set organization identifier (REQUIRED for generate/normalize/import)
- `--json` — structured output for programmatic consumption
- `--fragment` — generate composable fragment for Fleet GitOps
