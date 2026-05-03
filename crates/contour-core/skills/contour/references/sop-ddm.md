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

STEP 2 — Author the bundle TOML, then compose:
  # `contour profile ddm compose` takes a single TOML input describing the
  # full DDM intent and emits asset.json + configuration.json + activation.json
  # with identifiers and cross-references already wired by construction.
  # Replaces the multi-step generate-and-edit-by-hand orchestration that
  # earlier revisions of this SOP documented (asset → configuration →
  # activation, with manual identifier overrides and asset-reference edits).

  bundle = author bundle.toml describing the intent (see DDM_BUNDLE_FORMAT
                                                       below)

  result = contour profile ddm compose {bundle.toml} \
                -o {output_dir} \
                [--allow-orphans]      # only when intentionally authoring
                                       # a partial set
                --json

  if result.exit_code != 0:
    HALT "{result.error_code}: {result.error}"

  RETURN {
    files: result.files.map(f -> f.path),
    identifiers: { kind -> result.files[kind].identifier },
    deploy_order: [asset?, configuration, activation?]
      # The MDM server applies declarations in this order; out-of-order push
      # produces transient unresolved-reference errors that resolve once all
      # are applied. Pushing in build order avoids that flap.
  }

CROSS-FILE INVARIANT:
  Compose enforces this by construction — it builds the dependency DAG
  in memory, writes files atomically (no files on disk on error), and
  refuses to emit dangling references or orphan assets in strict mode.
  No post-hoc verification step required.

INVARIANTS:
  Compose never authors `ServerToken` (the MDM server adds it at push
  time). Pinned by trap_34. Direct hand-edits afterwards must preserve
  this.
```

### DDM_BUNDLE_FORMAT (the input to `compose`)

```toml
intent_name = "exchange-account"           # used in computed identifiers
                                            # → {org}.{kind}.{intent_name}

[asset]                                     # OPTIONAL section
type = "com.apple.asset.credential.userpassword"
# identifier = "{override}"                 # OPTIONAL — defaults to {org}.asset.{intent_name}
[asset.payload]
Username = "user@example.com"
Password = "..."

[configuration]                             # REQUIRED section
type = "com.apple.configuration.account.exchange"
# identifier = "{override}"
asset_ref_field = "AuthenticationCredentialsAssetReference"
                                            # REQUIRED only when the schema
                                            # has multiple *AssetReference
                                            # fields (Mail, Exchange, etc.).
                                            # Single-field schemas auto-resolve.
[configuration.payload]
HostName = "outlook.example.com"
EmailAddress = "user@example.com"

[activation]                                # OPTIONAL section
# type = "com.apple.activation.simple"      # default when omitted
# identifier = "{override}"
predicate = "@status('passcode.is-compliant') == TRUE"
# references = [ "...override..." ]         # default = [{configuration.identifier}]

[subscriptions]                             # REQUIRED if predicate uses @status(...)
keys = ["passcode.is-compliant"]            # status keys the device should subscribe to
# identifier = "{override}"                 # default {org}.subscriptions.{intent_name}
```

Override hatches (rare; defaults are correct for most intents):
- `asset.identifier`, `configuration.identifier`, `activation.identifier`,
  `subscriptions.identifier` — explicit identifier; bypasses the
  `{org}.{kind}.{intent_name}` default.
- `configuration.asset_ref_field` — disambiguate when a configuration's
  schema has multiple `*AssetReference` fields.
- `activation.references` — explicit `StandardConfigurations[]` array.

### Predicate ↔ status-subscription invariant

Apple's DDM spec defines two distinct predicate failure modes:
- `Error.PredicateFailed` — predicate cleanly evaluated to `false`
  (intentional gating; activation simply doesn't install).
- `Error.UnableToEvaluatePredicate` — predicate could not evaluate
  (syntax error, type mismatch, OR a referenced `@status('key')` isn't
  subscribed). This is an **authoring bug** that ships clean and
  surfaces at deploy time.

The CLI prevents the unsubscribed-key class at authoring time:

- **`compose` PRECONDITION**: parses the activation predicate's
  `@status(...)` references and asserts every referenced key is in
  `[subscriptions].keys`. Missing key → `SCHEMA_VIOLATION /
  UnsubscribedStatusKey`. When `[subscriptions]` is present, compose
  emits a fourth declaration file `status-subscriptions.json`
  (`com.apple.configuration.management.status-subscriptions`).
- **`ddm verify <dir>`**: walks all `*.json` declarations in a
  directory and applies the same cross-check across files (useful for
  hand-authored or externally-sourced sets — see below).

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
(asset + configuration + activation with cross-references), use
`compose` (above) — it enforces the cross-file invariants the per-file
generate cannot.

### Compose a bundle (asset + configuration + activation in one shot)

```
contour profile ddm compose <bundle.toml> -o <output_dir> --json
contour profile ddm compose <bundle.toml> -o <output_dir> --allow-orphans --json
```

The canonical multi-component path. See DDM_BUNDLE_FORMAT above for the
TOML schema and `docs/examples/ddm-exchange-bundle.toml` for a worked
example. Strict by default — declared assets that aren't wired into the
configuration trigger `SCHEMA_VIOLATION`. Pass `--allow-orphans` for
incremental authoring.

### Verify a directory of declarations

```
contour profile ddm verify <dir> --json
contour profile ddm verify <dir> --recursive --json
contour profile ddm verify <dir> --strict --json   # warnings → errors
```

Walks all `*.json` declarations in `<dir>` and reports:

| Class | Errors (exit 1) | Warnings (exit 0; `--strict` upgrades) |
|---|---|---|
| Reference DAG | `DanglingAssetReference`, `DanglingConfigurationReference` | `OrphanAsset`, `OrphanConfiguration` |
| Predicate gating | `UnsubscribedStatusKey` | `UnusedSubscriptionKey` |
| Authoring | `ServerTokenAuthored` | — |

Pure cross-reference check; per-file schema validation lives in
`ddm validate`. Use both as a CI gate.

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
