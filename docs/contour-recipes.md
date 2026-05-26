# contour recipes & presets -- Reusable Profile and DDM Bundles

> **Status: Preview** — feature-complete for core workflows, APIs and flags may still change before 1.0.

A **recipe** turns a tested set of payload settings into a single, shareable
TOML file that anyone can render into `.mobileconfig` profiles (and DDM
declarations) with one command — no hand-editing XML, no copy-pasting UUIDs.
A **preset** is the DDM-only sibling: a declarative-management intent bundle
composed the same way. A **library** is a versioned directory of recipes and
presets your team owns.

Aimed at Mac admins who want to capture vendor onboarding (Okta, CrowdStrike,
Entra, Santa…) or compliance baselines once and reproduce them reliably across
orgs, fleets, and MDMs.

## Quick Start

```bash
# See what ships in the box (19 recipes)
contour profile generate --list-recipes

# Render a built-in recipe — fill placeholders, set your org, write profiles
contour profile generate --recipe okta \
  --set OKTA_DOMAIN=acme.okta.com \
  --set SCEP_CHALLENGE="op://vault/okta-scep/credential" \
  --set REGISTRATION_TOKEN="op://vault/okta-psso/credential" \
  --org com.acme -o ./profiles/

# Compose a DDM preset
contour profile ddm compose --preset disable-apple-intelligence-macos \
  --org com.acme -o ./declarations/

# Aggregate an mSCP baseline into a recipe you can edit and re-render
contour mscp recipe -r ./macos_security -k cis_lvl1 -o ./recipes/cis_lvl1.toml --org com.acme
```

## Recipe vs Preset vs Library

Three related concepts — keep them straight:

| Term | What it is | Format | Rendered with |
|------|-----------|--------|---------------|
| **Recipe** | A mobileconfig-focused bundle: one or more `[[profile]]` blocks (+ optional `[[ddm]]` blocks) | `<name>.toml` | `contour profile generate --recipe <name>` |
| **Preset** | A DDM-only intent bundle (one declaration: configuration + activation) | `<name>.toml` | `contour profile ddm compose --preset <name>` |
| **Library** | A directory holding recipes (`recipes/`) and presets (`ddm/`), each with a `.meaning.md` sidecar | directory | scaffolded with `contour profile library new` |

Both recipes and presets resolve by the same **3-tier lookup**: an explicit
path (`--recipe-path` / `--preset-path`) wins, then `~/.contour/recipes/` /
`~/.contour/presets/`, then the embedded built-ins. An external file with the
same name **overrides** the built-in (listings flag it with `(overrides
embedded)`). A recipe that carries `[[ddm]]` blocks emits mobileconfig **and**
DDM together — so you only reach for a standalone preset when the bundle is
purely declarative.

## Recipe TOML reference

A recipe is plain TOML. Minimal shape (one payload, no placeholders):

```toml
[recipe]
name = "disable-mac-app-store"
description = "Disable Mac App Store"

[[profile]]
filename = "disable-mac-app-store.mobileconfig"
payload_type = "com.apple.applicationaccess"
display_name = "Disable Mac App Store"
description = "Blocks the Mac App Store app"

[profile.fields]
allowAppInstallation = false
```

Full surface, drawn from the built-in `okta` recipe:

```toml
[recipe]
name = "okta"                              # machine name (file stem need not match)
description = "Okta Verify with Platform SSO, SCEP, Associated Domains"
vendor = "Okta"                            # optional, shown in --list-recipes
variables = ["OKTA_DOMAIN", "SCEP_CHALLENGE", "REGISTRATION_TOKEN"]  # required {{placeholders}}
secrets = ["SCEP_CHALLENGE", "REGISTRATION_TOKEN"]   # advisory: which vars are sensitive

[recipe.output]
combined = false                           # one .mobileconfig per profile (default)
combined_filename = "okta-bundle.mobileconfig"   # used only when combined = true

[odv]                                      # operator-editable defaults for $ODV placeholders
MaximumFailedAttempts = 5

[[profile]]                                # repeat per payload type
filename = "okta-sso-extension.mobileconfig"
payload_type = "com.apple.extensiblesso"
display_name = "Okta SSO Extension"
description = "Okta Extensible SSO with Platform SSO"
removal_disallowed = true                  # set PayloadRemovalDisallowed
# mcx_domain = "com.apple.ManagedClient.preferences"  # unwrap an MCX-wrapped payload

[profile.fields]                           # schema-known payload keys
Type = "Redirect"
TeamIdentifier = "B7F62B65BN"
URLs = ["https://{{OKTA_DOMAIN}}"]

[profile.extra_fields]                     # vendor/non-schema keys, dot-notation for nesting
"PlatformSSO.AuthenticationMethod" = "UserSecureEnclaveKey"
"PlatformSSO.RegistrationToken" = "{{REGISTRATION_TOKEN}}"

[[ddm]]                                    # optional DDM bundle(s) alongside profiles
intent_name = "okta-software-update"
[ddm.configuration]
type = "com.apple.configuration.softwareupdate.settings"
[ddm.configuration.payload]
AutomaticActions = { Download = "AlwaysOn" }
[ddm.activation]
type = "com.apple.activation.simple"
```

| Key | Where | Meaning |
|-----|-------|---------|
| `name`, `description` | `[recipe]` | Required. Identity + one-line summary. |
| `vendor` | `[recipe]` | Optional vendor label shown in `--list-recipes`. |
| `variables` | `[recipe]` | Declares the `{{PLACEHOLDER}}` names the recipe expects. |
| `secrets` | `[recipe]` | Marks which variables are sensitive (hinted in listings; redacted on import). |
| `combined` / `combined_filename` | `[recipe.output]` | Bundle all profiles into one `.mobileconfig` (default: one file each). |
| `[odv]` | top-level | Default values that replace `$ODV` placeholders at render time. |
| `filename`, `payload_type`, `display_name`, `description` | `[[profile]]` | Output filename + the Apple `PayloadType` and identity. |
| `removal_disallowed` | `[[profile]]` | Sets `PayloadRemovalDisallowed = true`. |
| `mcx_domain` | `[[profile]]` | Unwrap an MCX-wrapped preference domain into a flat payload. |
| `[profile.fields]` | per profile | Schema-known payload keys. |
| `[profile.extra_fields]` | per profile | Vendor/non-schema keys; dot-notation builds nested dicts. |
| `[[ddm]]` | top-level | DDM bundle(s): `intent_name`, `[ddm.configuration]` (type + payload), `[ddm.activation]`. |

## `{{placeholders}}` vs `$ODV`

Two substitution mechanisms — they solve different problems:

- **`{{PLACEHOLDER}}`** — values you supply *per render* (often per customer or
  per environment). Filled from `--set KEY=VALUE` on the command line, a
  `[vars]` table in `.contour/config.toml`, or left to fail if a declared
  `variables` entry is missing. Use for domains, tokens, team IDs.
- **`$ODV`** (Organizational Defined Value) — a value with a *sensible default*
  baked into the recipe's `[odv]` table that an operator edits *once in the
  file*. Resolved at load time. Use for compliance knobs (password length,
  lock timeout) where the recipe ships a reasonable default. The
  `contour mscp recipe` aggregator emits mSCP rule defaults into `[odv]` for
  exactly this.

```bash
# {{placeholder}} — supplied at render time
contour profile generate --recipe okta --set OKTA_DOMAIN=acme.okta.com --org com.acme -o ./out

# $ODV — edit the recipe's [odv] table, then render with no --set needed
$EDITOR ./recipes/cis_lvl1.toml      # change values under [odv]
contour profile generate --recipe ./recipes/cis_lvl1.toml --org com.acme -o ./out
```

## Secrets

Placeholder values can be **secret references** that resolve at render time
rather than living in the recipe: `op://vault/item/field` (1Password),
`env:VAR`, `file:/path`, or `secret:NAME` (the config secret catalogue). Pass
`--sanitize` to leave those references *unresolved* in the output so the file
is safe to commit or share. See the **Secrets** section of
[contour-profile.md](contour-profile.md) for the full reference, `.env`
support, and CI patterns.

```bash
# Resolve secrets at render time
contour profile generate --recipe okta \
  --set SCEP_CHALLENGE="op://vault/okta/scep" --org com.acme -o ./out

# Keep references unresolved — safe to commit
contour profile generate --recipe okta \
  --set SCEP_CHALLENGE="op://vault/okta/scep" --sanitize --org com.acme -o ./out
```

## Rendering recipes — `profile generate`

```
contour profile generate --recipe <NAME|PATH> [--recipe <…>] --org <DOMAIN> -o <DIR> [flags]
```

| Flag | Description |
|------|-------------|
| `--recipe <NAME\|PATH>` | Recipe to render: a bare name (3-tier lookup) or a `.toml` path. Repeatable; shell globs work (`--recipe ./recipes/crowdstrike-*.toml`). |
| `--recipe-path <DIR\|FILE>` | Where to look up bare names (falls back to `defaults.library_path` in config). |
| `--list-recipes` | List every available recipe (embedded + external) and exit. |
| `--set <KEY=VALUE>` | Fill a `{{PLACEHOLDER}}` (repeatable). Values may be secret references. |
| `--combined` / `--no-combined` | Override `[recipe.output.combined]` for this run. |
| `--sanitize` | Leave `op://`/`env:`/`file:`/`secret:` references unresolved. |
| `--org <DOMAIN>` | Reverse-domain prefix for `PayloadIdentifier` (required unless set in config). |
| `--create-recipe <NAME>` | Scaffold a new recipe TOML named `<NAME>` instead of rendering. The payload types go in the **positional** `[PAYLOAD_TYPE]…` slot, e.g. `--create-recipe m365 com.microsoft.Edge com.microsoft.Outlook`. |

## Building recipes from mSCP — `mscp recipe`

`contour mscp recipe` reads an mSCP baseline's rule YAML **directly** (no
Python build) and aggregates every `mobileconfig` rule by payload type into
`[[profile]]` blocks, plus every `ddm_info` rule into `[[ddm]]` blocks.

```
contour mscp recipe -r <MSCP_REPO> -k <KEYWORD> -o <OUT.toml> [--org <VENDOR>] [--odv <FILE>] [--odv-mode variable|inline]
```

- `--odv-mode variable` (default) keeps `"$ODV"` in each field and writes the
  resolved per-rule defaults into a top-level `[odv]` table — edit once,
  re-render. `--odv-mode inline` bakes the resolved default straight into the
  field (no editable surface).
- `--odv <FILE>` seeds the `[odv]` table (or inline values) from an operator
  override file: any rule with a `custom_value` in
  `odv_<keyword>.yaml` (from `mscp odv init`) lands its value instead of the
  rule default. Auto-detected as `odv_<keyword>.yaml` in the working directory
  when omitted — so you don't have to hand-edit `[odv]` if you already tuned
  the override file.
- `--mscp-version`, `--os`, `--os-version` mirror `mscp generate` for 2.0
  layouts (see [contour-mscp.md](contour-mscp.md)).
- Baseline selection is `--keyword` / `-k` (the older `--baseline` / `-b` still
  works as an alias).

```bash
# Aggregate, hand-tuning [odv] afterward
contour mscp recipe -r ./macos_security -k cis_lvl1 -o ./recipes/cis_lvl1.toml --org com.acme
$EDITOR ./recipes/cis_lvl1.toml      # tune [odv] values
contour profile generate --recipe ./recipes/cis_lvl1.toml --org com.acme -o ./profiles/

# …or tune the override file once and let it seed every recipe + build
contour mscp odv init -m ./macos_security -k cis_lvl1   # writes odv_cis_lvl1.yaml
$EDITOR odv_cis_lvl1.yaml                                # set custom_value for the ODVs you care about
contour mscp recipe -r ./macos_security -k cis_lvl1 -o ./recipes/cis_lvl1.toml --org com.acme
# (--odv auto-detected; [odv] now carries your custom values)
```

## The library workflow — `profile library`

A library is a directory you own and version-control. Scaffold one, fill it
(by hand or by importing existing profiles), lint it, and point
`--recipe-path` at it.

```
contour profile library new <PATH> [--no-presets] [--no-recipes] [-f]
contour profile library import <INPUT…> --into <DIR> [--name <N>] [--combine] [-f]
contour profile library validate [PATH] [--json]
contour profile library normalize [PATH] --style <flat|nested>   # default: nested
contour profile library diff <A.toml> <B.toml> [--json]
```

`new` scaffolds the structure and copies in every built-in recipe and DDM
preset (skip with `--no-recipes` / `--no-presets`):

```
contour-presets/
├── README.md
├── recipes/                 # one <name>.toml + <name>.meaning.md per recipe
│   ├── okta.toml
│   ├── okta.meaning.md
│   └── …
├── ddm/                     # DDM presets
│   ├── siri-settings.toml
│   └── …
└── .github/workflows/validate.yml
```

`import` converts existing `.mobileconfig` (or DDM `.json`) into recipes with
schema-enriched `.meaning.md` sidecars. Sensitive fields (passwords, PSKs,
private keys, schema-marked secrets) are **redacted** to `TODO:` placeholders
and listed under `[recipe] secrets`. `--combine` folds multiple inputs into
one recipe with several `[[profile]]` blocks.

```bash
contour profile library new ./contour-presets
contour profile library import ~/Downloads/vendor-profiles --into ./contour-presets
contour profile library validate ./contour-presets
contour profile generate --recipe okta --recipe-path ./contour-presets/recipes \
  --set OKTA_DOMAIN=acme.okta.com --org com.acme -o ./profiles/
```

## DDM presets — `ddm compose`

Presets are standalone declarative-management bundles. Six ship built-in:

| Preset | Effect |
|--------|--------|
| `disable-apple-intelligence-macos` | Disable Apple Intelligence on macOS |
| `disable-apple-intelligence-ios` | Disable Apple Intelligence on iOS / iPadOS |
| `external-intelligence-settings` | Disable/scope third-party external intelligence |
| `keyboard-settings` | Managed keyboard settings (typing aids, dictation) |
| `siri-settings` | Managed Siri settings (restrict or disable) |
| `managed-migration-assistant` | Run Migration Assistant under managed control |

```
contour profile ddm compose --preset <NAME> --org <DOMAIN> -o <DIR>
contour profile ddm compose --list-presets
```

```bash
contour profile ddm compose --list-presets
contour profile ddm compose --preset siri-settings --org com.acme -o ./declarations/
# external preset library
contour profile ddm compose --preset my-preset --preset-path ./contour-presets/ddm \
  --org com.acme -o ./declarations/
```

Each composes to a `configuration.json` (the declaration) plus an
`activation.json`. The activation has no predicate by default — scope it via
your MDM's group/team assignment.

## End-to-end worked examples

### A. List, then render a built-in

```bash
contour profile generate --list-recipes
contour profile generate --recipe crowdstrike --org com.acme -o ./profiles/
```

### B. mSCP baseline → edit ODV → render

```bash
contour mscp recipe -r ./macos_security -k cis_lvl1 -o ./recipes/cis_lvl1.toml --org com.acme
$EDITOR ./recipes/cis_lvl1.toml      # adjust [odv]: password length, lock timeout, …
contour profile generate --recipe ./recipes/cis_lvl1.toml --org com.acme -o ./profiles/
```

### C. Build a team library

```bash
contour profile library new ./contour-presets
contour profile library import ~/vendor-profiles --into ./contour-presets
contour profile library validate ./contour-presets
contour profile library normalize ./contour-presets --style nested   # tidy for CI
git add ./contour-presets && git commit -m "Add vendor recipe library"
```

### D. Combine several profiles into one recipe

```bash
contour profile library import okta.mobileconfig airwatch.mobileconfig \
  --into ./contour-presets --name enterprise-sso --combine
contour profile generate --recipe enterprise-sso --recipe-path ./contour-presets/recipes \
  --combined --org com.acme -o ./profiles/
```

### E. Compose a DDM preset

```bash
contour profile ddm compose --preset disable-apple-intelligence-macos \
  --org com.acme -o ./declarations/
```

## See also

- [contour-profile.md](contour-profile.md) — the full `profile` toolkit,
  including the Secrets reference and `profile variables` catalogues.
- [contour-mscp.md](contour-mscp.md) — `mscp recipe` in the context of the
  whole mSCP baseline pipeline.
- [contour-config.md](contour-config.md) — `defaults.library_path`, `[vars]`,
  and the secret catalogue in `.contour/config.toml`.
