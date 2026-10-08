# SOP: DDM Declaration Generation

Apple Declarative Device Management (DDM). Declarations form a **dependency
DAG**: wrong order or mismatched identifier references fail at deploy time
with no authoring-time signal.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/profile/tests/sop_traps.rs`

## ERROR-CODE ENUM

Agents MUST switch on these `error_code` values — never substring-match the
prose `error` field.

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

## DEPRECATED_LIST (DDM replaces these legacy payloads)

**macOS Tahoe (26 / 27) removes** software update management via the legacy
`com.apple.SoftwareUpdate` profile payload; generating it produces broken
deployments.

```
DEPRECATED_PAYLOADS = [
  "com.apple.SoftwareUpdate"
    -> use DDM: com.apple.configuration.softwareupdate.settings
              + com.apple.configuration.softwareupdate.enforcement.specific
]
```

The PRECONDITIONS block of every DDM procedure MUST check this list and
redirect agents to the supported DDM type before generation runs.

## DDM dependency DAG

```
ASSET (optional)
  └─ referenced by → CONFIGURATION (com.apple.configuration.*)
                        └─ referenced by → ACTIVATION (com.apple.activation.*)
                                              └─ Predicate may query → STATUS items
                                                  (subscribed via management.status-subscriptions)
```

Build order is **bottom-up** (asset → configuration → activation); any other
order leaves a dangling `StandardConfigurations[]` or asset reference.

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
  # compose takes one TOML describing the intent and emits asset.json +
  # configuration.json + activation.json, identifiers and references wired.

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
      # push in this order; out-of-order push flaps with transient
      # unresolved-reference errors.
  }

CROSS-FILE INVARIANT:
  Compose enforces this by construction: atomic writes (no files on error),
  refuses dangling references or orphan assets in strict mode.

INVARIANTS:
  Compose never authors `ServerToken` (the MDM server adds it at push
  time). Hand-edits afterwards must preserve this.
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
                                            # REQUIRED only when the schema has
                                            # multiple *AssetReference fields
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

The commented `identifier` / `references` keys are rare overrides; the
defaults are correct for most intents.

### DATA_ASSET_ZIP_WORKFLOW (`com.apple.asset.data` — hosting a file)

Point `[asset]` at the local `.zip` the device downloads; contour hashes it
(never paste a SHA-256 by hand) and fills the `Reference`:

```toml
[asset]
type = "com.apple.asset.data"
zip  = "payload.zip"                  # relative to the bundle file; hashed (SHA-256)
url  = "https://files.example.com/payload-1.0.zip"   # → Reference.DataURL
auth = "none"                         # Authentication.Type — see below
[configuration]
type = "com.apple.configuration.services.configuration-files"
[configuration.payload]
ServiceType = "com.apple.sshd"        # DataAssetReference is auto-wired
[activation]
```

- **`url` omitted** → a `https://REPLACE-WITH-HOSTED-URL/...` placeholder is
  emitted. Host the zip (S3 / Cloudflare R2 / any HTTPS), then replace the URL.
- **`auth`** is Apple's `Authentication.Type`, two values only — there is
  **no username/password field**; host credentials are NEVER embedded:
  - `none` — plain GET: public URLs or **presigned / tokened URLs**.
  - `mdm` — device authenticates with its MDM identity certificate.
  - Anything else (rotating secrets, basic auth): front it with a presigned
    URL (`none`) or an MDM-cert-auth proxy (`mdm`).
- `[asset.authentication]` is an advanced override for the full dictionary.

### Predicate ↔ status-subscription invariant

`Error.PredicateFailed` is intentional gating (predicate evaluated `false`).
`Error.UnableToEvaluatePredicate` is an **authoring bug** that surfaces only at
deploy time — syntax error, type mismatch, or an unsubscribed `@status('key')`.
The CLI catches the unsubscribed-key class at authoring time:

- **`compose` PRECONDITION**: parses the activation predicate's
  `@status(...)` references and asserts every referenced key is in
  `[subscriptions].keys`. Missing key → `SCHEMA_VIOLATION /
  UnsubscribedStatusKey`. When `[subscriptions]` is present, compose
  emits a fourth declaration file `status-subscriptions.json`
  (`com.apple.configuration.management.status-subscriptions`).
- **`ddm verify <dir>`**: walks all `*.json` declarations in a
  directory and applies the same cross-check across files. A directory with
  no declarations in it fails with `IO_ERROR`; when they sit in
  subdirectories the error says so — pass `-r/--recursive`.

## Other operations (prose recipes; not yet migrated to the procedural format)

### Start from a preset

```
contour profile ddm compose --list-presets --json
# Embedded bundles for common intents (passcode, software update, Safari,
# Apple Intelligence off, Platform SSO scenarios, …). Compose one by name:
contour profile ddm compose --preset passcode-settings --org {org} -o {dir} --json
# Platform SSO has its own SOP with the four presets and their rules:
#   contour help-ai --sop platform-sso
```

### List available declaration types

```
contour profile ddm list --json
# asset, configuration, activation, management and status types
```

### Show schema for a specific type

```
contour profile ddm info com.apple.configuration.passcode.settings --json
# --full expands nested keys as a tree; --json carries depth/parent/path per field
contour profile ddm info network.vpn.ikev2 --beta --full
```

### Map a legacy profile payload type to its DDM equivalent

```
contour profile ddm map com.apple.mail.managed --json
# Per-key migration detail: direct_keys (same name), transformed_keys
# (old → new dotted DDM path, e.g. IncomingMailServerUsername →
# IncomingServer.AuthenticationCredentialsAssetReference), unsupported_keys
# (no DDM equivalent). With no <type>: the whole table + coverage stats.
```

### Report DDM migration coverage (what is declarative vs. still legacy)

```
contour profile ddm coverage --json
# status per type (available/partial/legacy/none), native-DDM coverage %,
# types still needing legacy profiles. --channel beta counts seed types.
```

### Populate `app.settings` allow/deny from a signing catalog

`com.apple.configuration.app.settings` (OS 27.0) gates apps by
`AllowedBinaries`/`DeniedBinaries` keyed on `{CDHash, SigningID, TeamID}`. Emit
it from the **fleet-maintained-apps** catalog instead of hand-writing entries:

```
# Catalog: https://github.com/allenhouchins/fleet-maintained-apps-growth-tracker/blob/main/data/app_security_info.json
curl -sSL <raw-url> -o app_security_info.json

# Emit the DDM app.settings declaration (and a matching Santa profile):
contour santa fetch fleet-apps app_security_info.json --org com.yourco --emit ddm -o out/
#   → out/app-settings.json   (AllowedBinaries: {SigningID, TeamID} per app)
contour profile ddm validate out/app-settings.json

# --match signingid|teamid|cdhash · --policy allow|deny · --emit santa,ddm,rules
```
See `--sop santa` (Recipe 5.5) for the full Santa+DDM workflow.

### Generate a single declaration directly (advanced)

```
# Requires organization.domain in profile.toml or .contour/config.toml.
contour profile ddm generate <type> -o <file>.json --full --json

# --payload fills the Payload from a JSON/TOML file (merged over the schema
# skeleton). The standalone path for management declarations:
echo '{"hello":"world"}' > props.json
contour profile ddm generate com.apple.management.properties \
  --org io.macadmins --payload props.json -o props.json
# → {"Type":"com.apple.management.properties","Identifier":"io.macadmins.properties",
#    "Payload":{"hello":"world"}}
```

This emits ONE declaration; for cross-referenced sets use `compose`, which
enforces the cross-file invariants.

Both `generate` and `compose` are **fail-closed**: a schema-invalid
declaration is NOT written — `SCHEMA_VIOLATION` lists what's wrong. `compose`
also refuses an **unknown field** (e.g. `Mail` at the intelligence payload
root, where Apple nests it under `Apps`) because the device ignores it;
`ddm validate` reports it as a warning.

Platform checks run only when told: a bundle's `platforms = ["macOS"]`, or
`--platform <OS>` on `compose` (refuses) and `validate` (warns) — then a key
Apple does not offer there (`AllowImageWand` on macOS) is reported.
`ddm validate`/`verify` remain the gate for hand-edited or external declarations.

### Compose a bundle (asset + configuration + activation in one shot)

```
contour profile ddm compose <bundle.toml> -o <output_dir> --json
contour profile ddm compose <bundle.toml> -o <output_dir> --allow-orphans --json
```

Format: DDM_BUNDLE_FORMAT above; example `docs/examples/ddm-exchange-bundle.toml`.
Strict by default — unwired assets trigger `SCHEMA_VIOLATION`; `--allow-orphans`
for incremental authoring.

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

## Key flags

- `--full` — include all fields, not just required
- `--json` — structured output for programmatic consumption
- `-o <path>` — output file path (DDM `generate` emits one declaration per call)
- `--schema-path <dir>` — use an external `apple/device-management` checkout
  instead of the embedded schema
