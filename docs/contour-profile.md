# contour profile -- Configuration Profile Toolkit

> **Status: Preview** — feature-complete for core workflows, APIs and flags may still change before 1.0.

`contour profile` is a CLI toolkit for managing Apple configuration profiles (`.mobileconfig`). It handles normalization, validation, signing, UUID management, payload inspection, and documentation generation for Apple device management.

contour turns intent into valid `.mobileconfig` profiles and Declarative Device Management (DDM) declarations for macOS, iOS, iPadOS, tvOS, watchOS, and visionOS — every one checked against Apple's official device-management schema, so an agent can't ship config that won't apply.

Aimed at Mac admins who manage profiles across MDM solutions, GitOps repositories, or local development workflows.

## Quick Start

```bash
# Set up a new project with org defaults
contour profile init --org com.yourorg --name "Your Org"

# Import vendor profiles from a directory
contour profile import ~/Downloads/vendor-profiles -o ./profiles

# Standardize everything (identifiers, UUIDs, filenames)
contour profile normalize ./profiles -r --org com.yourorg
```

## Configuration

### profile.toml

Created by `profile init`. Place it at the root of your profile project. Commands walk up the directory tree to find it.

```toml
[organization]
domain = "com.yourorg"       # Reverse domain (required)
name = "Your Org"            # Sets PayloadOrganization

[renaming]
scheme = "display-name"      # "identifier", "display-name", or "template"
template = "{org}-{type}-{name}"  # Only used with scheme = "template"

[uuid]
predictable = false          # Use deterministic v5 UUIDs
uppercase = true             # Uppercase UUID output

[output]
directory = "./output"       # Default output directory
unsigned_suffix = "-unsigned"

[processing]
validate_on_export = true
parallel_batch = true
max_threads = 4
```

### .contour/config.toml

Repo-level, cross-tool defaults — created by `contour init` and read by
every contour subcommand. Sections:

| Section | Purpose |
|---|---|
| `[organization]` | Org name + reverse-DNS domain (identifier prefix) |
| `[defaults]` | Platforms, deterministic UUIDs, default library path |
| `[vars]` | Static `{{PLACEHOLDER}}` substitutions for recipes |
| `[signing]` | Code-signing identity + team ID for `profile sign` |
| `[validation]` | Schema-validation policy (`fail_on_errors`/`warnings`/`deprecations`) |
| `[secrets]` | Secret reference catalogue — see [Secrets](#secrets) |
| `[mdm_variables]` | MDM deploy-time variable pool — see [MDM variables](#mdm-variables) |

See **[`contour-config.md`](contour-config.md)** for the full reference
with every key, type, and default. The discovery walk and CWD-over-anchor
precedence are described there.

### Precedence

CLI flags > `profile.toml` > `.contour/config.toml` > built-in defaults.

---

## Secrets

Recipes are meant to be committed and shared, so a recipe field should
hold a **reference** to a secret, never the secret itself. contour
resolves references at generate time.

### Reference prefixes

A recipe `[profile.fields]` value (or a `--set KEY=VALUE`) is treated as
a secret reference when it starts with one of:

| Prefix | Resolves to | Example |
|---|---|---|
| `op://` | a 1Password item field via the `op` CLI | `op://Corp/WiFi/password` |
| `env:` | an environment variable, then a `.env` file | `env:WIFI_PASSWORD` |
| `file:` | the contents of a file (emitted as binary `Data`) | `file:/etc/scep/cert.p12` |
| `secret:` | a named entry in the config `[secrets.refs]` catalogue | `secret:WIFI_PASSWORD` |

`op://` is the canonical 1Password form — `op://<vault>/<item>/<field>`.

### Import redaction

`contour profile library import` never writes a real credential into a
recipe. When a captured field is sensitive (the Apple schema `X` flag,
or a name containing `password`/`secret`/`psk`/`passphrase`/`privatekey`),
its value is replaced with a `TODO: <KEY>` placeholder, the field name is
recorded in `[recipe] secrets`, and the `.meaning.md` sidecar gets a
`## Secrets` section. Replace each `TODO:` with a real reference before
generating.

### `.env` files

`env:NAME` is resolved from the process environment first, then a `.env`
file — searched in the recipe-anchor directory, then the current
directory (CWD wins), then a `[secrets].dotenv` path if configured.
The file is plain `KEY=VALUE` (with `#` comments and optional `export`).

**Add `.env` to `.gitignore` — never commit it.**

### Config `[secrets]` catalogue

`.contour/config.toml` can declare a reusable catalogue so recipes
reference a name instead of repeating `op://…`:

```toml
[secrets]
dotenv  = ".env"          # default .env path (optional)
op_vault = "Corp"         # default 1Password vault (reserved)

[secrets.refs]
WIFI_PASSWORD  = "op://Corp/WiFi/password"
SCEP_CHALLENGE = "env:SCEP_CHALLENGE"
```

A recipe field `Password = "secret:WIFI_PASSWORD"` then resolves through
the catalogue to the underlying `op://…` reference.

### GitHub Actions

GitHub secrets work today with no extra wiring — expose them as env vars
in the workflow and reference them with `env:`:

```yaml
- name: Generate profiles
  env:
    WIFI_PASSWORD: ${{ secrets.WIFI_PASSWORD }}
  run: contour profile generate --recipe wifi --org com.acme -o build
```

### `--sanitize`

`contour profile generate --sanitize` leaves every secret reference
**unresolved** in the output `.mobileconfig` — the `op://…` / `env:…` /
`secret:…` literal stays in place. The profile is then safe to share or
commit for review, but is not deployable until regenerated without
`--sanitize`. Default generation resolves the real values.

### End-to-end example

```bash
# Import a Wi-Fi profile — the password is redacted automatically.
contour profile library import ./wifi.mobileconfig --into ./presets
# → presets/recipes/wifi.toml contains:  Password = "TODO: PASSWORD"

# Edit the recipe to reference the secret instead of a literal:
#   Password = "secret:WIFI_PASSWORD"
# and add WIFI_PASSWORD to [secrets.refs] in .contour/config.toml.

# Generate the real, deployable profile:
contour profile generate --recipe wifi --recipe-path ./presets/recipes --org com.acme -o build

# Or generate a shareable, sanitized copy:
contour profile generate --recipe wifi --recipe-path ./presets/recipes --org com.acme -o review --sanitize
```

---

## MDM variables

MDM **deploy-time variables** — Jamf's `$USERNAME`, Fleet's
`FLEET_VAR_NDES_SCEP_CHALLENGE`, and similar — are substituted by the
**MDM server on the device at deploy time**, not by contour. contour
passes them through untouched. They differ from secrets (resolved by
contour at generate time) and from `[vars]` (`{{PLACEHOLDER}}`
substitution, also at generate time):

| Kind | Config | Example | Substituted by | When |
|---|---|---|---|---|
| Static var | `[vars]` | `{{OKTA_DOMAIN}}` | contour | generate |
| Secret | `[secrets]` | `op://…`, `env:…` | contour | generate |
| MDM variable | `[mdm_variables]` | `$USERNAME`, `FLEET_VAR_*` | the MDM server | deploy |

### The `[mdm_variables]` pool

Declare the MDM tokens you use in `.contour/config.toml` — a friendly
name mapped to a token (composable with static text):

```toml
[mdm_variables]
mdm = "fleet"                                    # fleet | jamf | apple

[mdm_variables.pool]
SCEP_CHALLENGE = "FLEET_VAR_NDES_SCEP_CHALLENGE"
USER_EMAIL     = "$USERNAME@acme.com"
```

A recipe field `Challenge = "var:SCEP_CHALLENGE"` resolves through the
pool to the token, which is emitted **verbatim** for the MDM to
substitute on-device. The `mdm` flavour selects the built-in catalogue
used for validation.

### Reuse from secrets

A `[secrets.refs]` entry can target a pooled variable, so a token like
the NDES SCEP challenge is defined once and reachable as a secret:

```toml
[secrets.refs]
NDES = "var:SCEP_CHALLENGE"
```

`Challenge = "secret:NDES"` then resolves `secret:` → `var:` → the
`FLEET_VAR_…` token.

### Validation

`generate` warns on any MDM token in a recipe that is not in the active
flavour's built-in catalogue **and** not in the pool — typo-catching
(`FLEET_VAR_HOST_UUDI` is flagged). It is advisory and never fails the run.

### Listing the catalogue

```bash
contour profile variables --mdm fleet     # built-in Fleet catalogue + your pool
contour profile variables                 # all flavours when none is configured
```

contour ships catalogues for **Fleet** (exact + prefix variables like
`FLEET_VAR_DIGICERT_DATA_<CA>`), **Jamf** (`$VARIABLE` payload variables, Jamf Pro), and
**Apple** (minimal — Apple defines few literal in-profile tokens; extend
via the pool).

---

## Commands

### Getting Started

#### `profile info`

Without arguments, show Profile CLI version, configuration, and schema
statistics — use this to verify your setup. With a `<PAYLOAD_TYPE>`
argument, dump the full Apple schema for that payload (title,
description, platforms, every field's type, plist tag, required flag,
default, and allowed values). This mirrors `profile ddm info <name>`.

```
contour profile info [PAYLOAD_TYPE] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `[PAYLOAD_TYPE]` | Payload type for schema lookup. Omit to show CLI metadata. | — |
| `--full` | Include all fields, not just required + top-level | `false` |
| `--os <NAME>` | Restrict output to one OS; fails fast if the payload is unsupported there. Accepts (case-insensitive): `macOS`/`mac`, `iOS`/`ipad`/`ipados`, `tvOS`/`tv`, `watchOS`/`watch`, `visionOS`/`vision` | all platforms |
| `--schema-path <DIR>` | External schema directory (overrides embedded) | embedded schemas |
| `--json` | Emit JSON instead of human-readable output | `false` |

```bash
contour profile info
contour profile info com.apple.applicationaccess --json
contour profile info com.apple.applicationaccess --full --os macOS
```

#### `profile init`

Initialize a new `profile.toml` configuration file. Run this once at the root of your profile project.

```
contour profile init [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--org <DOMAIN>` | Organization reverse domain (e.g., `com.yourorg`) | interactive prompt |
| `--name <NAME>` | Organization name | interactive prompt |
| `-o, --output <PATH>` | Output file path | `./profile.toml` |
| `-f, --force` | Overwrite existing config | `false` |

```bash
contour profile init --org com.acme --name "Acme Corp" --force
```

---

### Import & Normalize

#### `profile import`

Import `.mobileconfig` files from a directory. Presents an interactive picker unless `--all` is used. Normalizes and optionally validates imported profiles.

```
contour profile import <SOURCE> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<SOURCE>` | Source directory containing `.mobileconfig` files | **required** |
| `-o, --output <DIR>` | Output directory for imported profiles | current directory |
| `--org <DOMAIN>` | Organization reverse domain | from `profile.toml` |
| `--name <NAME>` | Organization name (sets PayloadOrganization) | from `profile.toml` |
| `--all` | Import all profiles without interactive selection | `false` |
| `--no-validate` | Skip validation after normalization | `false` |
| `--no-uuid` | Skip UUID regeneration | `false` |
| `--max-depth <N>` | Maximum directory depth for recursive search | unlimited |
| `--dry-run` | Preview without writing files | `false` |
| `--strict` | Reject profiles with auto-fixable defects instead of repairing them | `false` |
| `--jamf` | Import from Jamf backup YAML (jamf-cli export format) | `false` |

```bash
# Import vendor profiles, normalize with org identity
contour profile import ~/vendor-profiles -o ./profiles --org com.acme --all
```

By default, import is **tolerant** — a profile missing a required field
that has a known default (e.g. `PayloadVersion`) or a bare payload
needing a `Configuration` wrapper is repaired on the fly with a warning,
rather than being dropped. `--strict` turns those repairs back into hard
rejections. The same tolerant parse path backs `profile library import`.

##### Jamf Pro backup workflow (`--jamf`)

`--jamf` makes `profile import` read the YAML tree produced by
[`jamf-cli`](https://github.com/Jamf-Concepts/jamf-cli), Jamf Concepts'
open-source companion CLI for Jamf Pro. contour walks the backup,
unwraps each embedded `.mobileconfig`, runs the same tolerant parse as a
regular import, normalizes to your org identity, and writes one
`.mobileconfig` per profile under `-o`. `--strict`, `--dry-run`,
`--no-validate`, and `--no-uuid` work the same way they do for a
directory import.

End-to-end recipe (backup → import → validate → sign):
[Common Workflows → Onboarding from a Jamf Pro tenant](#onboarding-from-a-jamf-pro-tenant).

#### `profile normalize`

Standardize identifiers, display names, filenames, and optionally UUIDs across one or more profiles. The core command for ensuring consistency.

```
contour profile normalize <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to normalize | **required** (unless `--pasteboard`) |
| `--pasteboard` | Read profile from macOS pasteboard | `false` |
| `-o, --output <PATH>` | Output file or directory | in-place |
| `--org <DOMAIN>` | Organization reverse domain | from `profile.toml` |
| `--name <NAME>` | Organization name (sets PayloadOrganization) | from `profile.toml` |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-validate` | Skip validation | `false` |
| `--no-uuid` | Skip UUID regeneration | `false` |
| `--no-parallel` | Disable parallel processing | `false` |
| `--dry-run` | Preview without writing files | `false` |
| `--report <PATH>` | Write a Markdown normalize report to this path | — |

```bash
# Normalize all profiles in a directory tree
contour profile normalize ./profiles -r --org com.acme --name "Acme Corp"
```

#### `profile duplicate`

Clone a profile with a new identity -- new name, identifier, and UUIDs. Useful for creating variants (e.g., staging vs. production).

```
contour profile duplicate <SOURCE> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<SOURCE>` | Source `.mobileconfig` file | **required** |
| `--name <NAME>` | New PayloadDisplayName | interactive prompt |
| `-o, --output <PATH>` | Output file path | auto-generated |
| `--org <DOMAIN>` | Organization reverse domain | from `profile.toml` |
| `--predictable` | Use deterministic v5 UUIDs based on new identifier | `false` |
| `--dry-run` | Preview without writing files | `false` |

```bash
contour profile duplicate wifi-corp.mobileconfig --name "WiFi Guest" -o wifi-guest.mobileconfig
```

#### `profile uuid`

Regenerate UUIDs without changing other profile properties. Supports both random (v4) and predictable (v5) modes.

```
contour profile uuid <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to process | **required** |
| `-o, --output <PATH>` | Output file or directory | in-place |
| `--org <DOMAIN>` | Organization reverse domain (for predictable UUIDs) | from `profile.toml` |
| `-p, --predictable` | Generate deterministic v5 UUIDs | `false` |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |
| `--dry-run` | Preview without writing files | `false` |

```bash
# Regenerate UUIDs predictably for GitOps reproducibility
contour profile uuid ./profiles -r -p --org com.acme
```

---

### Inspect & Validate

#### `profile scan`

Preview profile metadata without modifying anything. Shows identifiers, UUIDs, payload types, and optionally simulates what normalize would change.

```
contour profile scan <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to scan | **required** |
| `--simulate` | Simulate normalize with configured domain | `false` |
| `--org <DOMAIN>` | Organization reverse domain for simulation | from `profile.toml` |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |
| `--deprecations` | Scan for deprecated payload types and keys | `false` |
| `--md-report <PATH>` | Write a Markdown deprecation report (implies `--deprecations`) | — |
| `--fail-on-deprecations` | Exit non-zero if any deprecation is found | `[validation].fail_on_deprecations` |

```bash
# Audit all profiles in a directory
contour profile scan ./profiles -r --json
```

##### Deprecation scanning

`--deprecations` flags two kinds of obsolescence: **deprecated payload
types** (legacy MDM payloads with a DDM replacement — they stop working
on macOS 26+) and **deprecated keys** (fields Apple's schema marks
superseded). It reuses the same detection as `profile plan` and the
`deprecated-payload-type` / `deprecated-key` lint checks.

```bash
# Human + per-profile findings
contour profile scan ./profiles -r --deprecations

# Markdown report for a PR or wiki
contour profile scan ./profiles -r --md-report deprecations.md

# CI gate — non-zero exit when anything is deprecated
contour profile scan ./profiles -r --deprecations --fail-on-deprecations
```

The gate defaults to the `[validation].fail_on_deprecations` config key;
the CLI flag overrides it.

#### `profile validate`

Validate profiles against Apple's payload schemas. Reports missing required keys, incorrect types, and unknown fields.

```
contour profile validate <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to validate | **required** |
| `--no-schema` | Skip schema-based validation of payload fields | `false` |
| `--schema-path <DIR>` | Path to external schema directory (ProfileManifests, Apple YAML) | embedded schemas |
| `--lookup <PATH>` | Path to a ProfileManifests repo for third-party identifier lookup | — |
| `--strict` | Treat warnings as errors | `false` |
| `--lint-policy <NAMES>` | Opt into org-policy lint checks — comma-separated names, or `all` | schema checks only |
| `--no-placeholders` | Reject MDM template placeholders (`$VAR`, `{{VAR}}`, `%VAR%`); by default they are accepted with warnings | `false` |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |
| `--report <PATH>` | Write a Markdown validation report to this path | — |

```bash
# Strict validation against embedded Apple schemas
contour profile validate ./profiles -r --strict
```

By default `validate` runs Apple-schema checks only. `--lint-policy`
adds Tier-2 authoring-convention checks on top: pass `all`, or a
comma-separated subset of `payload-identifier-reverse-dns`,
`payload-organization-required`, `payload-scope-consistency`,
`nested-payload-identifier-prefix`. When combined with `--strict`,
Tier-2 warnings are promoted to errors.

#### `profile diff`

Compare two configuration profiles side-by-side. Shows added, removed, and changed keys across all payloads.

```
contour profile diff <FILE1> <FILE2> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE1>` | First configuration profile | **required** |
| `<FILE2>` | Second configuration profile | **required** |
| `-o, --output <PATH>` | Output diff to file | stdout |

```bash
contour profile diff baseline.mobileconfig updated.mobileconfig
```

#### `profile plan`

Classify changes between a baseline profile and a proposed one into a
*change taxonomy* that maps to MDM behavior on enrolled devices —
`terraform plan` for `.mobileconfig` files. Exits non-zero on blocking
tiers so CI can gate destructive PRs.

```
contour profile plan <BASELINE> <PROPOSED> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<BASELINE>` | Baseline profile (file or directory) | **required** |
| `<PROPOSED>` | Proposed profile (file or directory) | **required** |
| `-r, --recursive` | Walk directory pairs recursively | `false` |
| `--org <DOMAIN>` | Organization reverse domain (used with `--predictable`) | none |
| `--predictable` | Normalize both sides with v5 UUIDs derived from `(org, identifier)` before classifying. Collapses cosmetic UUID churn so `REPLACE` only fires on real `PayloadIdentifier` renames | `false` |
| `--format <text\|json>` | Output format | `text` |
| `--accept-replace` | Treat `REPLACE` as a warning instead of a blocker | `false` |
| `--accept-scope-change` | Treat `SCOPE_BROADENED` as a warning | `false` |
| `--fleet-size <N>` | Multiplier for the blast-radius narrative on `REPLACE` | none |

##### Change tiers (the taxonomy)

Each payload-level delta is classified into exactly one tier. The
order of the table is also the CI severity order — top is benign,
bottom is fatal.

| Tier | Trigger | Device behavior | Default exit |
|---|---|---|---|
| `NOOP` | Canonical-form-only delta after normalize | nothing pushed | 0 |
| `IN_PLACE_UPDATE` | Same `PayloadUUID`, same `PayloadType`; values changed | in-place update | 0 |
| `ADD` | Payload exists in proposed but not baseline | new payload installed | 0 |
| `REMOVE` | Payload exists in baseline but not proposed | payload removed | 0 |
| `REPLACE` | Same `(PayloadType, PayloadIdentifier)`, different `PayloadUUID` | **remove + reinstall** | non-zero unless `--accept-replace` |
| `REF_BROKEN` | `PayloadCertificateUUID` / EAP / IKEv2 ref points at a missing UUID | payload installs but does not bind | non-zero (always) |
| `SCOPE_BROADENED` | TCC `BundleIdentifier`→`BundleIdentifierPrefix`, `PayloadScope` widened, etc. | access surface increased | non-zero unless `--accept-scope-change` |
| `TYPE_INVALID` | Plist value type does not match the consuming-app schema | silent fallback to default | non-zero (always) |
| `DEPRECATED` | Newly introduces a deprecated `PayloadType` | will break on a future macOS | non-zero (always) |

```bash
# Full GitOps PR review against `git` HEAD
contour profile plan ./baseline ./proposed --recursive --predictable --org com.acme

# Treat the regenerated UUIDs as accepted, just verify nothing else broke
contour profile plan baseline.mobileconfig proposed.mobileconfig --accept-replace

# CI: emit JSON so a downstream job can render the verdict
contour profile plan ./baseline ./proposed -r --format json | jq '.summary'
```

For the operational doctrine and the `review_bulk_profile_pr` decision
tree (when to plan, when to rollback, when to forward-fix), see
`contour help-ai --sop profile-changes`.

#### `profile rollback`

Cherry-pick UUID restore — the inverse of `plan`. When a PR has
regenerated `PayloadUUID` values (and possibly forgotten to rewrite
their cross-references), `rollback` walks the proposed profiles, pulls
the baseline UUIDs back in, and rewrites every cross-reference that
pointed at the new UUID so it resolves to the restored one. Fail-closed:
a rollback that would orphan a `PayloadCertificateUUID` aborts before
any file is written.

```
contour profile rollback <BASELINE> <CURRENT> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<BASELINE>` | Baseline profile (file or directory) | **required** |
| `<CURRENT>` | Current profile (file or directory) to repair | **required** |
| `-r, --recursive` | Walk directory pairs recursively | `false` |
| `--uuids-only` | Restore `PayloadUUID` values only — leave content untouched | `false` |
| `--payload-type <T>` | Restore only payloads of these types (repeatable) | none |
| `--refs-only` | Restore only payloads referenced by another payload (certs, identities) | `false` |
| `--no-rewrite-refs` | Skip the cross-reference rewrite pass | rewrite enabled |
| `--dry-run` | Print the rollback plan; do not write | `false` |
| `--output <PATH>` | Write restored profiles here | in-place |

```bash
# PR is churn-only — undo every PayloadUUID change in one shot
contour profile rollback HEAD~1 . -r --uuids-only

# Undo only SCEP/identity-preference UUID churn (the high-blast-radius set)
contour profile rollback baseline/ proposed/ -r \
    --uuids-only --payload-type com.apple.security.scep \
                 --payload-type com.apple.security.identity

# Cross-reference rewrite pass: undo SCEP UUID and rewrite the
# PayloadCertificateUUID that pointed at the new SCEP UUID
contour profile rollback baseline/ proposed/ --uuids-only

# Confirm the round-trip is clean
contour profile plan baseline/ proposed/ -r --predictable --org com.acme
# → 0 REPLACE, 0 REF_BROKEN  → plan exits 0
```

#### `profile payload list`

List all payloads in a profile, showing type, display name, and UUID for each.

```
contour profile payload list <FILE>
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE>` | Path to the configuration profile | **required** |

```bash
contour profile payload list corp-settings.mobileconfig --json
```

#### `profile payload read`

Read a specific value from a payload by type and key.

```
contour profile payload read <FILE> --type <TYPE> --key <KEY> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE>` | Path to the configuration profile | **required** |
| `-t, --type <TYPE>` | Payload type (e.g., `wifi`, `com.apple.wifi.managed`) | **required** |
| `-k, --key <KEY>` | Key to read | **required** |
| `--index <N>` | Payload index if multiple of same type (0-based) | `0` |

```bash
contour profile payload read wifi.mobileconfig --type com.apple.wifi.managed --key SSID_STR
```

#### `profile payload extract`

Extract specific payload types from a profile into a new, standalone profile.

```
contour profile payload extract <FILE> --type <TYPE>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE>` | Path to the configuration profile | **required** |
| `-t, --type <TYPE>...` | Payload type(s) to extract | **required** |
| `-o, --output <PATH>` | Output file path | stdout |

```bash
# Extract just the VPN payload from a multi-payload profile
contour profile payload extract all-settings.mobileconfig --type com.apple.vpn.managed -o vpn-only.mobileconfig
```

---

### Signing

#### `profile identities`

List available signing identities (certificates) from your Keychain. Use to find the identity name or SHA-1 for `profile sign`.

```
contour profile identities [--json]
```

No additional flags.

```bash
contour profile identities
```

#### `profile sign`

Sign profiles with a Developer ID or MDM signing certificate.

```
contour profile sign <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to sign | **required** |
| `-o, --output <PATH>` | Output file or directory | in-place |
| `-i, --identity <ID>` | Signing identity (certificate name or SHA-1) | interactive prompt |
| `-k, --keychain <PATH>` | Keychain path | default keychain |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |
| `--dry-run` | Preview without writing files | `false` |

```bash
contour profile sign ./profiles -r -i "Developer ID Application: Acme Corp"
```

#### `profile verify`

Verify that a profile's signature is valid and the certificate chain is trusted.

```
contour profile verify <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to verify | **required** |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |

```bash
contour profile verify ./signed-profiles -r
```

#### `profile unsign`

Strip signatures from signed profiles, returning them to unsigned XML plist format. Useful before editing or re-normalizing.

```
contour profile unsign <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to unsign | **required** |
| `-o, --output <PATH>` | Output file or directory | in-place |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |
| `--dry-run` | Preview without writing files | `false` |

```bash
contour profile unsign vendor-signed.mobileconfig -o vendor-unsigned.mobileconfig
```

---

### Linking

#### `profile link`

Cross-reference UUIDs between profiles. When profiles reference each other (e.g., a certificate profile referenced by a WiFi profile), this command updates the UUID references to match. Optionally merges multiple profiles into one.

```
contour profile link <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to link | **required** |
| `-o, --output <PATH>` | Output file (merged) or directory (separate) | in-place |
| `--org <DOMAIN>` | Organization reverse domain | from `profile.toml` |
| `-p, --predictable` | Generate deterministic v5 UUIDs | `false` |
| `--merge` | Merge all profiles into a single output profile | `false` |
| `--no-validate` | Skip validation of cross-references | `false` |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--dry-run` | Preview changes without writing files | `false` |

```bash
# Link cert + WiFi profiles and merge into one
contour profile link cert.mobileconfig wifi.mobileconfig --merge -o corp-wifi.mobileconfig
```

---

### Documentation Generation

#### `profile docs generate`

Generate markdown documentation from embedded payload schemas.

```
contour profile docs generate -o <DIR> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <DIR>` | Output directory | **required** unless `--stdout` |
| `--stdout` | Print markdown to stdout instead of writing files | `false` |
| `--payload <TYPE>` | Specific payload type (generates one file) | all payloads |
| `-c, --category <CAT>` | Filter by category: `apple`, `apps`, `prefs` | all categories |
| `--schema-path <DIR>` | External schema directory | embedded schemas |

```bash
contour profile docs generate -o ./docs --category apple
contour profile docs generate --payload com.apple.wifi.managed --stdout
```

#### `profile docs list`

List available payloads for documentation generation.

```
contour profile docs list [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --category <CAT>` | Filter by category: `apple`, `apps`, `prefs` | all categories |
| `--schema-path <DIR>` | External schema directory | embedded schemas |

```bash
contour profile docs list --category apps --json
```

#### `profile docs from-profile`

Generate documentation from an existing profile, showing which keys are configured vs. available.

```
contour profile docs from-profile <FILE> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE>` | Path to the configuration profile | **required** |
| `-o, --output <PATH>` | Output file path | stdout |

```bash
contour profile docs from-profile wifi.mobileconfig -o wifi-docs.md
```

#### `profile docs ddm`

Generate markdown documentation for DDM declaration schemas.

```
contour profile docs ddm -o <DIR> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <DIR>` | Output directory | **required** |
| `--declaration <TYPE>` | Specific declaration type | all types |
| `-c, --category <CAT>` | Filter: `configuration`, `activation`, `asset`, `management` | all categories |

```bash
contour profile docs ddm -o ./ddm-docs --category configuration
```

---

### DDM (Declarative Device Management)

#### `profile ddm parse`

Parse and display DDM declaration JSON files. Shows the declaration type, identifier, and payload contents.

```
contour profile ddm parse <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | DDM JSON file(s) or directory | **required** |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |

```bash
contour profile ddm parse ./declarations -r --json
```

#### `profile ddm validate`

Validate DDM declarations against Apple's device-management schemas.

```
contour profile ddm validate <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | DDM JSON file(s) or directory | **required** |
| `-p, --schema-path <DIR>` | Path to Apple device-management repo | embedded schemas |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |

```bash
contour profile ddm validate ./declarations -r
```

#### `profile ddm list`

List available DDM declaration types (42 embedded).

```
contour profile ddm list [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --category <CAT>` | Filter: `configuration`, `activation`, `asset`, `management` | all types |
| `-p, --schema-path <DIR>` | Path to external Apple device-management repo | embedded schemas |

```bash
contour profile ddm list --category configuration --json
```

#### `profile ddm info`

Show detailed schema information for a specific DDM declaration type.

```
contour profile ddm info <NAME> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<NAME>` | Declaration type name | **required** |
| `-p, --schema-path <DIR>` | Path to external Apple device-management repo | embedded schemas |

```bash
contour profile ddm info passcode.settings
```

#### `profile ddm generate`

Generate a DDM declaration JSON skeleton from the schema. Useful for bootstrapping new declarations.

```
contour profile ddm generate <NAME> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<NAME>` | Declaration type (e.g., `passcode.settings`) | **required** |
| `-o, --output <PATH>` | Output file path | stdout |
| `--full` | Include all fields, not just required | `false` |
| `-p, --schema-path <DIR>` | Path to external Apple device-management repo | embedded schemas |

```bash
contour profile ddm generate passcode.settings -o passcode.json --full
```

#### `profile ddm compose`

*status: experimemtal*

Compose a complete DDM bundle — asset, configuration, and activation —
from a single TOML input describing one DDM intent. Identifiers are
computed from the org domain plus the intent name, the asset reference
is auto-wired into the configuration's `*AssetReference` field, and the
three `.json` declarations are written in build order. Dangling
references and identifier collisions become impossible by construction.

```
contour profile ddm compose <BUNDLE> -o <DIR> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<BUNDLE>` | Bundle TOML file describing a DDM intent. Required unless `--preset`/`--list-presets`. | — |
| `-o, --output <DIR>` | Output directory for the emitted `.json` declarations | **required** unless `--list-presets` |
| `--org <ORG>` | Organization reverse-DNS (overrides `CONTOUR_ORG` / `profile.toml`) | from config |
| `--preset <NAME>` | Compose an embedded or external preset by name instead of a bundle path | — |
| `--preset-path <DIR_OR_FILE>` | External preset library — a directory of `.toml` bundles or a single file | — |
| `--list-presets` | List presets available via `--preset` (embedded + external) | `false` |
| `--allow-orphans` | Allow assets that are declared but not referenced by the configuration | `false` |
| `-p, --schema-path <DIR>` | External Apple device-management repo (overrides embedded schema) | embedded schemas |

```bash
contour profile ddm compose ./intent.toml -o ./out --org com.acme
contour profile ddm compose --preset disable-apple-intelligence-macos --org com.acme -o ./out
contour profile ddm compose --list-presets
```

Preset resolution order: `--preset-path` → `~/.contour/presets/` →
embedded; external presets win on name collisions. The bundle format is
documented in `sop-ddm.md`.

#### `profile ddm verify`

Walk every `.json` declaration in a directory and verify cross-references:
the reference DAG (configurations resolve to assets, activations resolve
to configurations), predicate gating (every `@status('key')` in an
activation predicate is covered by a status-subscriptions declaration),
and `ServerToken` absence. Exits non-zero on any error; warnings (orphan
assets/configurations, unused subscription keys) only fail with `--strict`.

```
contour profile ddm verify <DIRECTORY> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<DIRECTORY>` | Directory containing DDM `.json` declaration files | **required** |
| `-r, --recursive` | Recurse into subdirectories | `false` |
| `--strict` | Treat warnings as errors (orphans, unused subscriptions) | `false` |

```bash
contour profile ddm verify ./declarations -r
contour profile ddm verify ./declarations -r --strict
```

---

### Search & Generate

#### `profile search`

Search the embedded payload schemas. Runs in one of three modes:

- **Substring search** (default) — matches `<QUERY>` against payload
  type, title, description, and field names; returns matching payloads.
- **`--field <NAME>`** — exact field-name lookup across every payload.
  Returns each match with its `payload_type` plus full field detail
  (type, plist tag, required, default, allowed values). The one-call
  answer to "what type does Apple expect for this key?".
- **`--include-fields`** — polymorphic mode. Substring-matches across
  payload-level *and* field-level metadata, returning categorized
  output with `payload_matches[]` and `field_matches[]` arrays.

```
contour profile search [QUERY] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `[QUERY]` | Substring search term (e.g., `passcode`, `wifi`). Required unless `--field` is given; conflicts with `--field`. | — |
| `--field <NAME>` | Exact field-name lookup across all payloads; conflicts with `<QUERY>` and `--include-fields` | — |
| `--include-fields` | Polymorphic mode — also walk field metadata. Requires `<QUERY>`; conflicts with `--field`. | `false` |
| `--schema-path <DIR>` | External schema directory | embedded schemas |

```bash
contour profile search wifi --json
contour profile search --field safariAcceptCookies --json
contour profile search cookie --include-fields --json
```

#### `profile generate`

Generate a `.mobileconfig` from an embedded payload schema, a recipe, or interactively. Supports plist output for Workspace ONE.

```
contour profile generate <PAYLOAD_TYPE>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PAYLOAD_TYPE>...` | Payload type(s); multiple only with `--create-recipe` | required unless `--list-recipes` / `--recipe` |
| `-o, --output <PATH>` | Output file or directory | stdout |
| `--org <DOMAIN>` | Organization reverse domain | from `profile.toml` |
| `--full` | Include all fields, not just required | `false` |
| `--schema-path <DIR>` | External schema directory | embedded schemas |
| `--recipe <NAME>` | Generate from a named recipe (produces a multi-profile bundle) | none |
| `--recipe-path <DIR>` | Path to a recipe file or directory | built-in recipes |
| `--list-recipes` | List available recipes | `false` |
| `--set KEY=VALUE` | Set a placeholder value (repeat for multiple). Secrets: `op://`, `env:VAR`, `file:/path` | none |
| `--create-recipe <NAME>` | Scaffold a recipe TOML from the given payload types | none |
| `--interactive` | Pick payload segments and set field values interactively | `false` |
| `--format <FMT>` | Output format: `mobileconfig` (default) or `plist` (raw payload dict, for WS1) | `mobileconfig` |

```bash
# Single payload, all fields included
contour profile generate com.apple.mobiledevice.passwordpolicy --full --org com.acme

# From a recipe with placeholder values
contour profile generate --recipe okta-sso --set OKTA_DOMAIN=acme.okta.com -o profiles/

# Scaffold a custom recipe from multiple payload types
contour profile generate --create-recipe m365 com.microsoft.Edge com.microsoft.Outlook

# Interactive segment picker
contour profile generate com.apple.mobiledevice.passwordpolicy --interactive --org com.acme

# Raw payload dict for Workspace ONE
contour profile generate com.apple.wifi.managed --format plist --full -o wifi-payload.plist
```

##### Workspace ONE Custom Settings (`--format plist`)

Workspace ONE's **Custom Settings** payload accepts the raw payload `<dict>` directly — without the surrounding `PayloadType: Configuration` / `PayloadContent` wrapper that a full `.mobileconfig` carries. `--format plist` emits exactly that shape: a valid `<plist><dict>…</dict></plist>` containing the payload's keys, suitable for pasting into the WS1 Custom XML field.

```bash
# Generate a raw payload dict for WS1 Custom Settings
contour profile generate com.apple.wifi.managed --format plist --full --org com.acme -o wifi.plist

# Works with recipes too — emits one .plist per [[profile]] in the recipe
contour profile generate --recipe restrictions --format plist --org com.acme -o ws1-out/
```

What you get:

- **A bare `<dict>` of payload keys.** No `PayloadType`, no `PayloadContent` array, no UUIDs to hand-edit — only the keys WS1 expects. Verify with `plutil -lint <file>.plist`.
- **The same schema validation as `.mobileconfig` output.** contour refuses to write a `--format plist` file that doesn't match the embedded Apple schema, so an agent or a copy-paste cannot smuggle invented keys past WS1.
- **A recipe-driven path.** Combine `--format plist` with `--recipe <name>` to render a vendor preset (Okta, CrowdStrike, etc.) into WS1-ready dicts. Recipes resolve secrets at generate time the same way they do for `.mobileconfig` output.

Paste the resulting `.plist` content into a WS1 "Custom Settings" profile; WS1 wraps it server-side into a proper installable profile when it pushes to devices.

---

### Library & Recipes

A **recipe** is a TOML file describing one or more profiles to generate.
A **library** is a directory of recipes (`recipes/`) and DDM bundles
(`ddm/`) — a shareable, version-controlled preset collection. `profile
generate --recipe` consumes them; the `library` subcommands manage them.

#### `profile library new`

Scaffold a fresh library directory (`recipes/`, `ddm/`, `README.md`,
`.github/`).

```bash
contour profile library new ./contour-presets
```

#### `profile library import`

Convert an existing `.mobileconfig` (or a directory of them) into recipe
TOMLs at `<INTO>/recipes/<name>.toml`, each with a `.meaning.md` sidecar.
Uses the same tolerant parse as `profile import`. **Sensitive fields are
redacted** — a captured `Password` becomes `Password = "TODO: PASSWORD"`,
recorded in `[recipe] secrets` (see [Secrets](#secrets)). Refuses to
overwrite unless `--force`.

```bash
contour profile library import ./vendor-profiles --into ./contour-presets
```

#### `profile library validate` / `normalize` / `diff`

Validate every recipe in a library, restyle recipe TOML (`--style
flat|nested`, default `nested`), or diff two recipe files.

```bash
contour profile library validate ./contour-presets
contour profile library diff old.toml new.toml
```

#### Generating from a recipe

```bash
contour profile generate --recipe wifi --recipe-path ./contour-presets/recipes --org com.acme -o build
```

- `--recipe <NAME|PATH>` — a bare name (resolved via `--recipe-path` →
  `~/.contour/recipes/` → embedded) or a direct `.toml` path. Repeatable.
- `--recipe-path <DIR>` — recipe search directory; falls back to
  `defaults.library_path` in `.contour/config.toml`.
- `--combined` / `--no-combined` — bundle every `[[profile]]` into one
  `.mobileconfig`, or emit one per payload (overrides `[recipe.output]`).
- `--sanitize` — leave secret references unresolved (see
  [`--sanitize`](#--sanitize)).
- `[odv]` defaults in the recipe fill `"$ODV"` placeholders;
  `{{PLACEHOLDER}}` tokens come from `--set`, `[vars]`, or recipe
  `variables`.

Recipe field values may reference secrets and MDM variables — see
[Secrets](#secrets) and [MDM variables](#mdm-variables).

#### `profile variables`

List the MDM deploy-time variable catalogues and the configured pool.

```bash
contour profile variables --mdm fleet     # built-in catalogue + your pool
contour profile variables                 # all flavours when none configured
```

---

### MDM Commands

Generate Apple MDM command payloads (`.plist`) from 65 embedded command schemas — ready to send via `fleetctl mdm run-command` or the Fleet API (with `--base64`).

#### `profile command list`

List all available MDM command types.

```
contour profile command list [--json]
```

#### `profile command info`

Show the schema (keys, types, descriptions) for a specific command.

```
contour profile command info <COMMAND_TYPE>
```

| Flag | Description | Default |
|------|-------------|---------|
| `<COMMAND_TYPE>` | Command name (e.g., `DeviceLock`, `RestartDevice`) | **required** |

#### `profile command generate`

Generate an MDM command `.plist` payload.

```
contour profile command generate [<COMMAND_TYPE>] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<COMMAND_TYPE>` | Command name (required unless `--interactive`) | none |
| `-o, --output <PATH>` | Output file path | stdout |
| `--set KEY=VALUE` | Command parameter (repeat for multiple) | none |
| `--uuid` | Add a `CommandUUID` for tracking | `false` |
| `--base64` | Output as a base64-encoded string (ready for Fleet API) | `false` |
| `--interactive` | Search, select command, and configure params interactively | `false` |

```bash
# Simple command
contour profile command generate RestartDevice --uuid -o restart.plist

# Command with parameters
contour profile command generate DeviceLock --set PIN=123456 --set Message='Locked by IT' --uuid -o lock.plist

# Base64 for Fleet API
contour profile command generate DeviceLock --set PIN=123456 --uuid --base64

# Interactive (search + select)
contour profile command generate --interactive
```

#### `profile command decode`

Decode an MDM `InstallProfile` command back into its inner `.mobileconfig` —
the inverse of wrapping a profile for delivery. Unwraps the CMS/PKCS#7
`<data>` payload and emits the profile inside.

```
contour profile command decode <INPUT> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUT>` | MDM command plist file, or `-` to read from stdin | **required** |
| `-o, --output <PATH>` | Write the inner profile to this file | stdout |

```bash
# Decode an InstallProfile command to its inner profile
contour profile command decode install-profile.plist -o inner.mobileconfig

# From stdin
pbpaste | contour profile command decode - -o inner.mobileconfig
```

---

### DEP/ADE Enrollment

Generate Setup Assistant enrollment profiles from 71 embedded skip-key definitions (platform- and OS-version-gated).

#### `profile enrollment list`

List available skip keys for a platform and optional OS version.

```
contour profile enrollment list [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--platform <PLATFORM>` | `macOS`, `iOS`, `iPadOS`, `tvOS`, `visionOS` | `macOS` |
| `--os-version <VERSION>` | Only show keys available for this OS version | all versions |

```bash
contour profile enrollment list --platform macOS --json
contour profile enrollment list --platform iOS --os-version 17 --json
```

#### `profile enrollment generate`

Generate a DEP/ADE enrollment profile JSON.

```
contour profile enrollment generate [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--platform <PLATFORM>` | Target platform | `macOS` |
| `--os-version <VERSION>` | Target OS version | all |
| `--skip <LIST>` | Comma-separated list of skip keys; unions with `--skip-list` when both are given | none |
| `--skip-list <PATH>` | Reusable skip-list TOML file (`platform`, `os_version`, `profile_name`, `skip[]`) | none |
| `--skip-all` | Skip every available setup item — **rejected by the NEVER_SKIP guardrail** (includes `FileVault` / `SoftwareUpdate`); use `--skip` or `--skip-list` instead | `false` |
| `--profile-name <NAME>` | Profile display name (overridden by `--skip-list`'s value if both set) | `Automatic enrollment profile` |
| `-o, --output <PATH>` | Output file path | stdout |
| `--interactive` | Pick skip items interactively (conflicts with `--skip-list`, `--skip-all`) | `false` |

```bash
contour profile enrollment generate --platform macOS --interactive -o enrollment.dep.json
contour profile enrollment generate --platform iOS --skip TOS,Siri,Privacy -o ios-enrollment.dep.json
contour profile enrollment generate --skip-list skip-list.toml -o enrollment.dep.json
```

Example `skip-list.toml`:

```toml
version = 1
platform = "macOS"
profile_name = "Acme Onboarding"
skip = ["Appearance", "Siri", "Diagnostics", "Privacy", "TOS"]
```

> **Security guardrail**: `FileVault` and `SoftwareUpdate` are rejected in any source (`--skip`, `--skip-list`, `--skip-all`). Skipping the Setup Assistant panes for these undermines disk encryption and OS-update hygiene. Enforced in code as of 0.3.0-beta.5; documented in `--sop enrollment`.

---

### Synthesize

#### `profile synthesize`

Reverse-engineer managed preference plists (typically from `/Library/Managed Preferences/`) into validated `.mobileconfig` profiles. Matches keys against the Apple schema.

```
contour profile synthesize <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Plist file(s) or a directory of managed preferences | **required** |
| `-o, --output <DIR>` | Output directory for generated mobileconfigs | current directory |
| `--org <DOMAIN>` | Organization reverse domain | from `profile.toml` |
| `--validate` | Validate keys against the Apple schema | `false` |
| `--interactive` | Select which plists to synthesize | `false` |
| `--dry-run` | Preview without writing files | `false` |

```bash
# Preview
contour profile synthesize /Library/Managed\ Preferences/ --dry-run --json

# Synthesize and validate
contour profile synthesize /Library/Managed\ Preferences/ \
  -o profiles/ --org com.acme --validate
```

---

## Common Workflows

### Onboarding vendor profiles

Import profiles from a vendor, normalize to your org identity, validate, and sign:

```bash
contour profile import ~/Downloads/vendor/ -o ./profiles --org com.acme --all
contour profile validate ./profiles -r --strict
contour profile sign ./profiles -r -i "Developer ID Application: Acme Corp"
```

### Onboarding from a Jamf Pro tenant

Pull every configuration profile out of a Jamf Pro instance using
[`jamf-cli`](https://github.com/Jamf-Concepts/jamf-cli), then convert and
normalize so everything lands as schema-valid `.mobileconfig` under
your org identifier — ready for a GitOps repo or re-deployment via any MDM.

```bash
# 1. Back up the tenant. jamf-cli credentials are configured once
#    (see its README); the output directory holds the full YAML tree.
./jamf-cli pro backup --output ./jamf-backup

# 2. Import every profile through contour with --jamf.
#    Identifiers are rewritten under --org, PayloadOrganization is set
#    from --name, UUIDs are regenerated, and each profile is validated
#    against Apple's embedded schema.
contour profile import ./jamf-backup --jamf -o ./profiles \
    --org com.acme --name "Acme Corp" --all

# 3. Validate against Apple's schema before committing. --strict promotes
#    warnings to errors, so anything questionable surfaces in CI.
contour profile validate ./profiles -r --strict

# 4. (Optional) sign with your Developer ID for offline-verifiable distribution.
contour profile sign ./profiles -r -i "Developer ID Application: Acme Corp"
```

`--strict` on the import step (step 2) refuses to silently repair
defects in the Jamf export; pair it with `--dry-run` first if you want
to preview the conversion before touching disk. To produce
byte-stable diffs for a GitOps repo, add `contour profile uuid ./profiles
-r -p --org com.acme` between step 3 and step 4 — predictable v5 UUIDs
derived from `(org, identifier)` mean re-imports don't churn the diff.

### GitOps-ready profiles

Initialize a project, normalize with predictable UUIDs for reproducible diffs, then commit:

```bash
contour profile init --org com.acme --name "Acme Corp"
contour profile normalize ./profiles -r
contour profile uuid ./profiles -r -p --org com.acme
git add profiles/ profile.toml && git commit -m "Normalize profiles"
```

### Audit a directory of profiles

Scan metadata and validate without modifying anything:

```bash
contour profile scan ./profiles -r --json > audit-scan.json
contour profile validate ./profiles -r --strict --json > audit-validate.json
```

### Split and merge payloads

Extract specific payloads from a multi-payload profile, then link and merge:

```bash
contour profile payload extract all-in-one.mobileconfig --type com.apple.wifi.managed -o wifi.mobileconfig
contour profile payload extract all-in-one.mobileconfig --type com.apple.security.pkcs12 -o cert.mobileconfig
contour profile link wifi.mobileconfig cert.mobileconfig --merge -o corp-wifi-bundle.mobileconfig
```

### Generate for Workspace ONE Custom Settings

Render the raw payload `<dict>` WS1 expects, validated against the embedded Apple schema:

```bash
# Single payload, all fields populated
contour profile generate com.apple.mobiledevice.passwordpolicy \
    --format plist --full --org com.acme -o passcode.plist

# Recipe → one .plist per [[profile]] entry, with secrets resolved
contour profile generate --recipe restrictions \
    --format plist --org com.acme -o ws1-restrictions/

# Confirm the output is a valid plist before pasting
plutil -lint passcode.plist
```

Paste the resulting `.plist` content into a WS1 Custom Settings payload field. The schema-validation pass and (optional) secret resolution work identically to `.mobileconfig` generation, so the same recipes serve Jamf, Fleet, and WS1 with no per-MDM divergence.

### Unsign, edit, re-sign

```bash
contour profile unsign signed.mobileconfig -o unsigned.mobileconfig
# Edit unsigned.mobileconfig in your editor
contour profile normalize unsigned.mobileconfig
contour profile sign unsigned.mobileconfig -i "Developer ID Application: Acme Corp" -o signed.mobileconfig
```

---

## Global Flags

These flags work with all commands:

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format (for CI/CD pipelines and scripting) |
| `-v, --verbose` | Enable verbose logging |
| `--version` | Show version, build timestamp, and license |
| `--help` | Show help for any command |

## Output Modes

- **Human** (default) -- Formatted tables and colored output for terminal use.
- **JSON** (`--json`) -- Structured JSON for piping into `jq`, CI/CD systems, or other tools.

```bash
# Human output
contour profile scan wifi.mobileconfig

# JSON output for scripting
contour profile scan wifi.mobileconfig --json | jq '.payloads[].type'
```
