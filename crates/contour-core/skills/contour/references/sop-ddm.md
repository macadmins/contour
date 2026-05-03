# SOP: DDM Declaration Generation

This SOP covers Apple Declarative Device Management (DDM). Unlike profile
generation, DDM declarations form a **dependency DAG** — agents that emit
declarations in the wrong order, or whose identifier references don't match,
produce configurations that fail at deploy time without any authoring-time
signal. The procedural format here makes that DAG explicit.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/profile/tests/sop_traps.rs`

## ERROR-CODE ENUM

All procedures emit failures with a stable typed `error_code` from this enum.
Agents MUST switch on these codes — substring-matching the prose `error` field
is fragile and discouraged.

```
INVALID_IDENTIFIER     identifier syntax issue (spaces, invalid chars)
INVALID_FORMAT         not a valid declaration / corrupted JSON
MISSING_PAYLOAD_TYPE   required Type field absent
SCHEMA_VIOLATION       failed Apple-schema validation
IO_ERROR               file not found, permission denied, disk full
INVALID_ORG            org domain malformed or absent
UNKNOWN                unmatched — treat as fatal, do NOT auto-retry
```

When a top-level call fails (e.g. precondition rejected), `--json` mode emits
on stderr:

```json
{ "success": false, "error": "...", "error_code": "INVALID_ORG" }
```

---

## DEPRECATED_LIST (DDM replaces these legacy payloads)

Apple is deprecating profile-payload-based device management in favor of DDM.
**macOS Tahoe (26 / 27) removes** software update management via the legacy
`com.apple.SoftwareUpdate` profile payload. Agents that keep generating it
will produce broken deployments on the next macOS release.

```
DEPRECATED_PAYLOADS = [
  "com.apple.SoftwareUpdate"
    -> use DDM: com.apple.configuration.softwareupdate.settings
              + com.apple.configuration.softwareupdate.enforcement.specific
]
```

The PRECONDITIONS block of every DDM procedure MUST check this list and
redirect agents to the supported DDM type before generation runs.

---

## DDM dependency DAG

```
ASSET (optional)
  └─ referenced by → CONFIGURATION (com.apple.configuration.*)
                        └─ referenced by → ACTIVATION (com.apple.activation.*)
                                              └─ Predicate may query → STATUS items
                                                  (subscribed via management.status-subscriptions)
```

Build order is **bottom-up** (asset → configuration → activation). Writing
the activation before the configuration produces a dangling
`StandardConfigurations[]` reference; writing the configuration before the
asset produces a dangling asset reference inside the configuration payload.

---

## PROCEDURE create_ddm_config(intent, org_prefix, output_dir)

```
SCHEMA_SOURCE: apple/device-management (release branch)
SCHEMA_TOOL:   contour profile ddm list --json
               contour profile ddm info <type> --json

INPUT:
  intent      : human description of the desired configuration (e.g. "enforce
                passcode policy with conditional rollout to compliant Macs")
  org_prefix  : reverse-domain identifier (e.g. com.acme); required because
                the CLI builds Identifier as `{org_prefix}.{type-tail}` and
                refuses to default to com.example.
  output_dir  : where to write the declaration files

PRECONDITIONS:
  ASSERT org_prefix matches /^[a-z0-9-]+(\.[a-z0-9-]+)+$/
    HALT "org_prefix must be reverse-domain; got '{org_prefix}'"
  ASSERT org_prefix != "com.example"
    HALT "refusing default 'com.example'"
  ASSERT output_dir exists OR can be created
    AUTO_FIX: mkdir -p {output_dir}

  # DEPRECATED_LIST check — redirect before any work happens.
  classified = classify_ddm_intent(intent)
  if classified.candidate_type in DEPRECATED_PAYLOADS:
    replacement = DEPRECATED_PAYLOADS[classified.candidate_type]
    WARN "intent maps to deprecated payload {classified.candidate_type};
          using DDM replacement {replacement} (mandatory by macOS 26)"
    classified.candidate_type = replacement

STEP 1 — Schema lookup (always live, never speculate):
  types = contour profile ddm list --json
  ASSERT len(types) > 0
    HALT "no DDM types registered; run `contour profile ddm list` to debug"

  if classified.has_asset:
    ASSERT classified.asset_type in types
      HALT "unknown asset type {classified.asset_type}; closest: {suggestions}"
  ASSERT classified.config_type in types
    HALT "unknown config type {classified.config_type}"
  if classified.needs_activation:
    # Activation type is always com.apple.activation.simple unless agent
    # has a documented reason for a different one.
    activation_type = "com.apple.activation.simple"

STEP 2 — Choose identifiers (everything else references these):
  # NB: `contour profile ddm generate` builds Identifier as
  # `{org_prefix}.{last_segment_of_type}`. For types ending in a generic
  # tail (".settings", ".simple"), this produces collisions across
  # configurations — TWO `*.settings` types generate the same Identifier.
  # Agents MUST rename emitted identifiers to type-unique values.
  ids = {
    asset:         "{org_prefix}.asset.{intent_name}"        if classified.has_asset
    configuration: "{org_prefix}.config.{intent_name}"
    activation:    "{org_prefix}.activation.{intent_name}"   if classified.needs_activation
  }
  ASSERT every id matches /^[a-z0-9.-]+$/
    HALT "computed identifier {id} contains invalid characters"

BUILD ORDER (each step's output is referenced by the next; do NOT reorder):
  STEP 3a — Emit asset (if present):
    if classified.has_asset:
      contour profile ddm generate {classified.asset_type} \
        -o {output_dir}/asset.json --full --json
      EDIT {output_dir}/asset.json: set "Identifier" to ids.asset

  STEP 3b — Emit configuration:
    contour profile ddm generate {classified.config_type} \
      -o {output_dir}/configuration.json --full --json
    EDIT {output_dir}/configuration.json:
      set "Identifier" to ids.configuration
      if classified.has_asset:
        set Payload's asset reference to ids.asset
        ASSERT exact-match: the reference string == ids.asset

  STEP 3c — Emit activation (if requested):
    if classified.needs_activation:
      contour profile ddm generate {activation_type} \
        -o {output_dir}/activation.json --full --json
      EDIT {output_dir}/activation.json:
        set "Identifier" to ids.activation
        set Payload.StandardConfigurations to [ids.configuration]
        if classified.predicate:
          ASSERT predicate uses @status() or @property() syntax
          ASSERT a status-subscription declaration covers any @status() keys
          set Payload.Predicate to classified.predicate

STEP 4 — Validate the full set:
  for each declaration_file in {asset, configuration, activation}:
    contour profile ddm validate {declaration_file} --json
    if exit != 0:
      HALT "{file}: failed schema validation; see stderr for error_code"

CROSS-FILE INVARIANT (after STEP 4):
  if classified.has_asset:
    ASSERT configuration.Payload references ids.asset (exact string match)
      HALT "configuration's asset reference does not match emitted asset.Identifier"
  if classified.needs_activation:
    ASSERT activation.Payload.StandardConfigurations contains ids.configuration
      HALT "activation does not reference the emitted configuration"

INVARIANTS:
  # ServerToken is a server-managed field. Agents MUST NOT populate it; the
  # MDM server adds it deterministically at push time. Authoring it manually
  # causes collision on re-deploy.
  for each declaration_file:
    ASSERT "ServerToken" key absent from declaration JSON
      HALT "{file}: ServerToken must be added by the MDM server, not authored"

POSTCONDITIONS:
  RETURN {
    files: [asset?, configuration, activation?],
    identifiers: ids,
    deploy_order: same as BUILD ORDER above
      # The MDM server applies declarations in this order; out-of-order push
      # produces transient unresolved-reference errors that resolve once all
      # are applied. Pushing in build order avoids that flap.
  }
```

---

## Other operations (prose recipes; not yet migrated to the procedural format)

These DDM CLI operations work with the existing prose recipes; they will be
migrated as each one is end-to-end traced.

### List available declaration types

```
contour profile ddm list --json
# 47 types embedded as of contour 0.2.x; covers asset, configuration,
# activation, management, and status categories.
```

### Show schema for a specific type

```
contour profile ddm info com.apple.configuration.passcode.settings --json
# Returns full field schema: types, descriptions, requiredness, defaults.
```

### Generate a single declaration directly (advanced)

```
# Requires organization.domain in profile.toml or .contour/config.toml.
contour profile ddm generate <type> -o <file>.json --full --json
```

Note: this emits ONE declaration in isolation. For multi-component setups
(asset + configuration + activation with cross-references), use the
`create_ddm_config` PROCEDURE above — it orchestrates the full DAG and
enforces the invariants the CLI alone can't.

### Parse + validate existing declarations

```
contour profile ddm parse <file>.json --json     # show structure
contour profile ddm validate <file>.json --json  # schema-validate
```

---

## Key flags

- `--full` — include all fields, not just required (useful for surfacing
  optional knobs to humans; agents typically populate only what intent needs)
- `--json` — structured output for programmatic consumption
- `-o <path>` — output file path (DDM `generate` emits one declaration per call)
- `--schema-path <dir>` — point at an external `apple/device-management`
  checkout to override the embedded schema (useful for trying unreleased
  declaration types from main)
