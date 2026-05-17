# contour mscp -- mSCP Baseline Transformation Toolkit

> **Status: Preview** — feature-complete for core workflows, APIs and flags may still change before 1.0.

`contour mscp` transforms [macOS Security Compliance Project (mSCP)](https://github.com/usnistgov/macos_security) baselines into MDM-ready configurations for Fleet, Jamf Pro, and Munki. It handles generation, post-processing, deduplication, constraints, ODV customization, versioning, and GitOps repository management.

Aimed at Mac admins deploying security compliance baselines across Apple platforms (macOS, iOS, visionOS).

## Quick Start

```bash
# Initialize a project with Fleet mode
contour mscp init --org com.yourorg --name "Your Org" --fleet --sync

# Generate a baseline - for Fleet with DDM declarations
contour mscp generate -m ./macos_security -b cis_lvl1 -o ./output --fleet-mode --generate-ddm --remove-consent-text 

# Generate a baseline - for Jamf with consent text removed
contour mscp generate -m ./macos_security -b cis_lvl1 -o ./output --jamf-mode --remove-consent-text

# Or generate all configured baselines at once
contour mscp generate-all -c mscp.toml
```

## Configuration

### mscp.toml

Created by [`mscp init`](#mscp-init) and placed at the root of your mSCP
project. Every command that accepts `--config` (`info`, `generate-all`)
loads it automatically. CLI flags override config values — see
[Precedence](#precedence).

The file has four top-level tables: **`[settings]`** (global generation
options, with `jamf` / `fleet` / `munki` sub-tables), **`[[baselines]]`**
(one per baseline to generate), **`[output]`** (directory layout), and
**`[validation]`**. A representative file:

```toml
[settings]
mscp_repo = "./macos_security"   # Path to the mSCP repository checkout
output_dir = "./output"          # Where generated config is written
python_method = "auto"           # auto | uv | python3
generate_ddm = false             # Pass -D to the mSCP build script

[settings.organization]
domain = "com.yourorg"           # Reverse-domain identifier prefix
name = "Your Org"                # Sets PayloadOrganization

[settings.fleet]
enabled = true
no_labels = false

[settings.jamf]
enabled = false
deterministic_uuids = false
identical_payload_uuid = false
no_creation_date = false
exclude_conflicts = false
remove_consent_text = false

[settings.munki]
compliance_flags = false
script_nopkg = false

[[baselines]]
name = "cis_lvl1"
enabled = true
branch = "origin/tahoe"          # Git branch — determines platform/OS

[[baselines]]
name = "800-53r5_moderate"
enabled = true
branch = "origin/tahoe"
excluded_rules = []
[baselines.labels]
include_any = ["compliance-moderate"]

[output]
structure = "pluggable"          # pluggable (Fleet) | flat (Jamf) | nested (Munki)
separate_baselines = true
generate_diffs = true
versions_to_keep = 5

[validation]
strict = false
check_conflicts = true
```

#### `[settings]`

Global generation settings shared by every baseline.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mscp_repo` | path | `./macos_security` | The mSCP repository checkout (the directory containing `rules/`, `baselines/`). |
| `output_dir` | path | `./output` | Directory generated config is written to. Any path works; `mscp init` scaffolds `./output`. |
| `python_method` | string | `auto` | How to run the mSCP build script: `auto`, `uv`, or `python3`. |
| `verbose` | bool | `false` | Verbose logging. |
| `generate_ddm` | bool | `false` | Pass `-D` to the mSCP script so it also emits DDM declarations. |

#### `[settings.organization]`

Identity stamped into every generated profile.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `domain` | string | `com.example` | Reverse-domain identifier — the `PayloadIdentifier` prefix. |
| `name` | string | `Example Organization` | Display name — sets `PayloadOrganization`. |

#### `[settings.jamf]`

Jamf Pro post-processing. Auto-enabled when `output.structure = "flat"`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable Jamf Pro mode. |
| `deterministic_uuids` | bool | `false` | Derive UUIDs from `PayloadType` (stable across runs). |
| `no_creation_date` | bool | `false` | Strip creation dates from `PayloadDescription`. |
| `identical_payload_uuid` | bool | `false` | Use one UUID for both `PayloadIdentifier` and `PayloadUUID`. |
| `exclude_conflicts` | bool | `false` | Drop profiles that conflict with Jamf Pro native settings. |
| `remove_consent_text` | bool | `false` | Remove `ConsentText` from profiles. |
| `consent_text` | string | — | Custom `ConsentText` (overrides `remove_consent_text`). |
| `description_format` | string | — | Custom `PayloadDescription` format string. |

#### `[settings.fleet]`

Fleet GitOps options. Auto-enabled when `output.structure = "pluggable"`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable Fleet conflict filtering. |
| `no_labels` | bool | `false` | Skip generating Fleet label definitions. |

#### `[settings.munki]`

Munki integration. Auto-enabled when `output.structure = "nested"`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `compliance_flags` | bool | `false` | Emit a Munki `nopkg` item that writes compliance flags. |
| `compliance_path` | path | `/Library/Managed Preferences/mscp_compliance.plist` | Where the compliance plist is written on target devices. |
| `flag_prefix` | string | `mscp_` | Prefix for compliance flag keys. |
| `script_nopkg` | bool | `false` | Emit Munki `nopkg` items from script rules. |
| `catalog` | string | `production` | Munki catalog for script `nopkg` items. |
| `category` | string | `mSCP Compliance` | Munki category for script `nopkg` items. |
| `separate_postinstall` | bool | `false` | Use a separate postinstall instead of embedding the fix in installcheck. |

#### `[[baselines]]`

One table per baseline to generate. Repeat the `[[baselines]]` header for each.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | **required** | Baseline name (e.g. `cis_lvl1`, `800-53r5_high`). |
| `enabled` | bool | `true` | Whether `generate-all` processes this baseline. |
| `branch` | string | current branch | Git branch to check out — determines platform and OS version (e.g. `origin/sequoia`, `origin/ios_18`). |
| `fleet` | string | — | Fleet name override for this baseline. |
| `excluded_rules` | string[] | `[]` | Rule IDs to drop from this baseline. |
| `metadata` | table | `{}` | Free-form key/value metadata. |

#### `[baselines.labels]`

Fleet label targeting for a baseline (one `[baselines.labels]` per `[[baselines]]`).

| Key | Type | Description |
|-----|------|-------------|
| `include_all` | string[] | Host must carry **all** of these labels. |
| `include_any` | string[] | Host must carry **at least one** of these labels. |
| `exclude_any` | string[] | Host must carry **none** of these labels. |

#### `[baselines.gitops_glob]`

Advanced. Per-section glob decisions for Fleet GitOps output — which of
`profiles`, `scripts`, `labels`, `policies`, `reports` collapse into a
single `paths:` glob and which items stay as literal `path:` exceptions.
Normally written by `mscp process --interactive` or implied by
`generate --glob`, not edited by hand. Each section sub-table accepts
`enabled`, `drop_labels`, and an `exceptions` list.

#### `[output]`

Directory layout of the generated output.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `structure` | string | `pluggable` | `pluggable` (Fleet GitOps), `flat` (Jamf), or `nested` (Munki) — see [Output Structure](#output-structure). |
| `separate_baselines` | bool | `true` | Give each baseline its own subdirectory. |
| `generate_diffs` | bool | `false` | Write diff reports against the previous generation. |
| `versions_to_keep` | int | `5` | How many prior versions to retain for version tracking. |

#### `[validation]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `schemas_path` | path | embedded | External JSON schema directory (overrides the embedded schemas). |
| `strict` | bool | `false` | Treat validation warnings as errors. |
| `check_conflicts` | bool | `true` | Check for conflicting keys across baselines. |
| `validate_paths` | bool | `true` | Verify referenced files exist on disk. |

### Precedence

CLI flags > `mscp.toml` > built-in defaults.

For output layout specifically: `--jamf-mode` / `--fleet-mode` CLI flags override `output.structure` from config. When using `generate-all -c mscp.toml`, the config's `output.structure` drives everything — no CLI flags needed.

---

## Available Baselines

24 baselines across 3 platforms. Each baseline maps to a security framework and produces a different set of rules (mobileconfig profiles, scripts, DDM declarations).

### macOS

| Baseline | Framework | Rules |
|----------|-----------|-------|
| `cis_lvl1` | CIS Apple macOS Benchmark (Level 1) | ~100 |
| `cis_lvl2` | CIS Apple macOS Benchmark (Level 2) | ~120 |
| `800-53r5_low` | NIST SP 800-53 Rev 5 Low Impact | ~160 |
| `800-53r5_moderate` | NIST SP 800-53 Rev 5 Moderate Impact | ~210 |
| `800-53r5_high` | NIST SP 800-53 Rev 5 High Impact | ~220 |
| `800-171` | NIST 800-171 Rev 3 | ~175 |
| `cmmc_lvl1` | US CMMC 2.0 Level 1 | ~90 |
| `cmmc_lvl2` | US CMMC 2.0 Level 2 | ~215 |
| `cnssi-1253_low` | CNSSI No. 1253 (Low) | ~250 |
| `cnssi-1253_moderate` | CNSSI No. 1253 (Moderate) | ~260 |
| `cnssi-1253_high` | CNSSI No. 1253 (High) | ~270 |
| `stig` | Apple macOS STIG | ~165 |
| `cisv8` | CIS Controls Version 8 | ~175 |
| `nlmapgov_base` | NLMAPGOV (base) | ~40 |
| `nlmapgov_plus` | NLMAPGOV (plus) | ~90 |

### iOS

| Baseline | Framework | Rules |
|----------|-----------|-------|
| `indigo_base` | BSI indigo Base Configuration | ~80 |
| `indigo_high` | BSI indigo High Configuration | ~125 |
| `ios_stig` | Apple iOS/iPadOS STIG | ~85 |
| `cis_lvl1_byod` | CIS Apple iOS Benchmark (Level 1) - BYOD | ~25 |
| `cis_lvl1_enterprise` | CIS Apple iOS Benchmark (Level 1) - Enterprise | ~35 |
| `cis_lvl2_byod` | CIS Apple iOS Benchmark (Level 2) - BYOD | ~30 |
| `cis_lvl2_enterprise` | CIS Apple iOS Benchmark (Level 2) - Enterprise | ~45 |

### visionOS

| Baseline | Framework | Rules |
|----------|-----------|-------|
| `visionos_stig` | Apple visionOS STIG | ~38 |

Cross-platform baselines (`800-53r5_*`, `cisv8`, `all_rules`) have different rule sets per platform. Use `--branch` to select the platform during generation.

---

## mSCP repository layout — 1.x vs 2.0

The macOS Security Compliance Project currently ships in **two coexisting
shapes**, and contour detects which one `--mscp-repo` points at:

| Layout | Branch | Rule schema |
|--------|--------|-------------|
| **2.0** — current | `dev_2.0` | Multi-OS — `platforms.{macOS,iOS,visionOS}.<version>`, nested `enforcement_info`, array-shaped `mobileconfig_info`, `references.{vendor}…`; baselines are derived from rule metadata. |
| **1.x** — legacy | `tahoe` and earlier release branches | Flat — top-level `tags`, `check`, `fix`, `result`; dict-shaped `mobileconfig_info`; baselines are explicit files under `baselines/`. |

contour treats **2.0 as the standard layout**. 1.x repositories remain
fully supported — detection is automatic, so existing 1.x workflows keep
working unchanged — but 1.x is the older schema and the focus of new
work is 2.0.

**Auto-detection.** For commands that read mSCP rule YAML *directly*,
contour sniffs the first rule file: a top-level `platforms:` key ⇒ 2.0;
an `id:` without `platforms:` ⇒ 1.x. The `dev_2.0` branch keeps the
`rules/` and `baselines/` symlinks in place, so path-based access still
works — only the schema underneath differs. A 2.0 rule can describe
several OSes at once, and contour adapts it to the normalized internal
rule model per selected platform.

**`generate` / `generate-all`.** These shell out to the mSCP project's
own Python toolchain to *build* the baseline. `generate` resolves the
baseline file for whichever layout the repo uses —
`baselines/<name>.yaml` (1.x) or
`baselines/<os>/<name>_<os>_<version>.yaml` (2.0) — and reads the build
output from `build/<name>` or `build/<name>_<os>_<version>` accordingly.
`generate-all` always auto-detects the layout and targets macOS.

mSCP 2.0 is verified on both build paths and produces an identical
Fleet GitOps structure either way:
- a local `dev_2.0` checkout built with `--use-uv` / `--use-python3` —
  point `--mscp-repo` at it and run `generate`;
- the `--use-container` route against the default mSCP 2.0 image
  `ghcr.io/brodjieski/mscp_2.0:latest` (the image checks the project
  out at `/mscp`, which contour mounts the host `build/` directory
  into).

**Layout flags.** `generate` and `recipe` both accept:

| Flag | Description | Default |
|------|-------------|---------|
| `--mscp-version <VER>` | Repository layout: `auto`, `1.x`, or `2.0` | `auto` (sniff the rule schema) |
| `--os <OS>` | OS target for 2.0 layouts: `macos`, `ios`, `visionos` (ignored for 1.x) | `macos` |
| `--os-version <VER>` | OS version for 2.0 layouts (e.g. `26.0`, `15.0`) | highest version available |

Pass `--mscp-version 1.x` or `2.0` to skip detection when the heuristic
cannot decide (e.g. an empty or non-standard checkout). With a 2.0 repo,
`generate -b 800-53r5_high --os macos` builds
`baselines/macos/800-53r5_high_macos_26.0.yaml` (newest version) — no
need to know the exact filename.

> **mSCP 2.0 toolchain note:** the 2.0 Python build pulls a heavier
> dependency set (pandas, lxml, Pillow). Pillow has no Python 3.14 wheel
> yet, so a fresh 2.0 build under the newest Python can fail to compile
> it. If you hit this, build with Python 3.13 — e.g. pre-create the
> environment with `uv venv --python 3.13` in the mSCP repo, or install
> the `libjpeg` headers.

---

## Commands

### Getting Started

#### `mscp info`

Show project configuration, mSCP repository status, and baseline counts.

```
contour mscp info [--config <CONFIG>] [--json]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config <CONFIG>` | Path to configuration file | `mscp.toml` |

```bash
contour mscp info
```

#### `mscp init`

Initialize a new `mscp.toml` configuration file with optional mSCP repository sync.

```
contour mscp init [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <DIR>` | Output directory for config files | `.` |
| `--org <DOMAIN>` | Organization reverse-domain identifier | interactive prompt |
| `-n, --name <NAME>` | Organization display name | interactive prompt |
| `--fleet` | Enable Fleet GitOps mode (sets `output.structure = "pluggable"`) | `false` |
| `--jamf` | Enable Jamf Pro mode (sets `output.structure = "flat"`) | `false` |
| `--munki` | Enable Munki integration (sets `output.structure = "nested"`) | `false` |
| `--sync` | Clone/sync mSCP repository | `false` |
| `--branch <BRANCH>` | mSCP branch to clone | `tahoe` |
| `--baselines <BASELINES>` | Baselines to enable (comma-separated, used with `--sync`) | none |
| `--force` | Overwrite existing configuration | `false` |

```bash
# Full setup: init config, clone mSCP, enable baselines
contour mscp init --org com.acme --name "Acme Corp" --fleet --sync --baselines cis_lvl1,cis_lvl2
```

#### `mscp list-baselines`

List available baselines from an mSCP repository.

```
contour mscp list-baselines [--mscp-repo <PATH>] [--json]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-m, --mscp-repo <PATH>` | Path to mSCP repository | `./macos_security` |

```bash
contour mscp list-baselines -m ./macos_security
```

---

### Generate & Process

#### `mscp generate`

Generate a baseline using the mSCP Python script, then transform the output into MDM-ready configurations. This is the recommended command for most users.

```
contour mscp generate [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-m, --mscp-repo <PATH>` | Path to mSCP repository | **required** |
| `-b, --baseline <NAME>` | Baseline name (e.g., `cis_lvl1`) | **required** |
| `-o, --output <DIR>` | Output directory | **required** |
| `--branch <BRANCH>` | Git branch (determines platform/OS) | repo default |
| `--mscp-version <VER>` | mSCP layout: `auto`, `1.x`, or `2.0` (see [mSCP repository layout](#mscp-repository-layout--1x-vs-20)) | `auto` |
| `--os <OS>` | OS target for 2.0 layouts: `macos`, `ios`, `visionos` (ignored for 1.x) | `macos` |
| `--os-version <VER>` | OS version for 2.0 layouts (e.g. `26.0`); highest available if unset | auto |
| `--dry-run` | Preview without writing files | `false` |

**Organization options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--org <DOMAIN>` | Reverse-domain identifier for PayloadIdentifier prefix | none |
| `--org-name <NAME>` | Organization display name for PayloadOrganization | none |

**Profile options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--deterministic-uuids` | Use deterministic UUIDs based on PayloadType | `false` |
| `--remove-consent-text` | Remove ConsentText from profiles | `false` |
| `--consent-text <TEXT>` | Custom ConsentText (overrides `--remove-consent-text`) | none |

**mSCP options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--generate-ddm` | Generate DDM declarations (pass `-D` to mSCP) | `false` |
| `--use-uv` | Use `uv run` instead of `python3` | auto-detected |
| `--use-python3` | Force `python3` | auto-detected |
| `--use-container` | Run mSCP in a container | `false` |
| `--container-image <IMAGE>` | Container image | `ghcr.io/brodjieski/mscp_2.0:latest` |

**Jamf Pro options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--jamf-mode` | Enable Jamf Pro mode | `false` |
| `--no-creation-date` | Remove creation dates from descriptions | `false` |
| `--identical-payload-uuid` | Same UUID for PayloadIdentifier and PayloadUUID | `false` |
| `--jamf-exclude-conflicts` | Exclude profiles conflicting with Jamf native capabilities | `false` |
| `--description-format <FMT>` | Custom PayloadDescription format | none |

**Fleet options (experimental):**

| Flag | Description | Default |
|------|-------------|---------|
| `--fleet-mode` | Enable Fleet conflict filtering | `false` |
| `--no-labels` | Skip generating Fleet label definitions | `false` |
| `--fleets <FLEETS>` | Fleets to add the baseline to (comma-separated) | none |
| `--glob` | With `--fleets`, attach the baseline as one `*.mobileconfig` glob entry instead of one entry per profile | `false` |
| `--script-mode <MODE>` | `combined`, `granular`, `bundled`, or `both` | `bundled` |
| `--fragment` | Generate Fleet fragment directory | `false` |

`--fleets` appends the baseline into each named fleet file: profiles go
into `controls.apple_settings.configuration_profiles` (current Fleet
GitOps schema), scripts into `controls.scripts`, and the baseline's label
into `default.yml`. The named fleet files must already exist. Edits are
comment- and formatting-preserving, and **fail-closed** — if an edit
would produce invalid YAML the fleet file is left byte-for-byte untouched
and the run errors, so an existing fleet file is never corrupted.

`--glob` emits a single `- paths: …/<baseline>/*.mobileconfig` entry
(Fleet's glob form — note `paths:`, not `path:`) instead of one `- path:`
entry per profile. The glob is scoped to the baseline's own profile
directory, so it never matches profiles belonging to other baselines or
the operator's existing entries.

**Munki options (experimental):**

| Flag | Description | Default |
|------|-------------|---------|
| `--munki-compliance-flags` | Generate Munki compliance flags nopkg item | `false` |
| `--munki-compliance-path <PATH>` | Target path for compliance plist | `/Library/Managed Preferences/mscp_compliance.plist` |
| `--munki-flag-prefix <PREFIX>` | Prefix for compliance flags | `mscp_` |
| `--munki-script-nopkg` | Generate Munki script nopkg items | `false` |
| `--munki-script-catalog <CAT>` | Munki catalog for scripts | `production` |
| `--munki-script-category <CAT>` | Munki category for scripts | `mSCP Compliance` |
| `--munki-script-separate-postinstall` | Use separate postinstall instead of installcheck | `false` |

**ODV and exclusion options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--odv <PATH>` | ODV override file | auto-detected as `odv_<baseline>.yaml` |
| `--exclude <CATEGORIES>` | Exclude rule categories (comma-separated) | none |

```bash
# Generate CIS Level 1 for Fleet with DDM
contour mscp generate -m ./macos_security -b cis_lvl1 -o ./output \
  --fleet-mode --generate-ddm --org com.acme --fleets "Engineering,Security"

# Generate 800-53 High and attach it to existing fleet files as a glob
contour mscp generate -m ./macos_security -b 800-53r5_high -o ./output \
  --fleet-mode --fleets "workstations,servers" --glob

# Generate STIG for Jamf Pro
contour mscp generate -m ./macos_security -b stig -o ./output \
  --jamf-mode --deterministic-uuids --jamf-exclude-conflicts
```

#### `mscp generate-all`

Generate multiple baselines from configuration file or CLI flags.

```
contour mscp generate-all [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config <CONFIG>` | Path to configuration file | none |
| `-m, --mscp-repo <PATH>` | Path to mSCP repository (ignored if `--config`) | none |
| `-b, --baselines <NAMES>` | Baselines to generate (comma-separated, ignored if `--config`) | none |
| `-o, --output <DIR>` | Output directory (ignored if `--config`) | none |
| `--no-parallel` | Disable parallel processing | `false` |
| `--dry-run` | Preview without writing files | `false` |

Also accepts: `--generate-ddm`, `--deterministic-uuids`, `--jamf-mode`, `--no-creation-date`, `--identical-payload-uuid`, `--jamf-exclude-conflicts`, `--fleet-mode`, `--script-mode`, `--fragment`, `--munki-compliance-flags`, `--munki-script-nopkg`.

```bash
# Generate all baselines from config
contour mscp generate-all -c mscp.toml

# Or specify baselines directly
contour mscp generate-all -m ./macos_security -b cis_lvl1,cis_lvl2,stig -o ./output --fleet-mode
```

#### `mscp process`

Post-process already-generated mSCP output. Use this when you've already run the mSCP Python script separately and want to transform the build output into MDM configurations.

Most users should use `generate` instead.

```
contour mscp process [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input <PATH>` | Path to mSCP build output directory (e.g., `./macos_security/build/cis_lvl1`) | **required** |
| `-o, --output <DIR>` | Output directory | **required** |
| `-b, --baseline <NAME>` | Baseline name | **required** |
| `-m, --mscp-repo <PATH>` | Path to mSCP repository (for Git version tracking) | none |
| `--dry-run` | Preview without writing files | `false` |

Also accepts all profile options (`--deterministic-uuids`, `--org`, `--org-name`, `--remove-consent-text`, `--consent-text`), Jamf options (`--jamf-mode`, `--no-creation-date`, `--identical-payload-uuid`, `--jamf-exclude-conflicts`, `--description-format`), Fleet options (`--fleet-mode`, `--no-labels`, `--script-mode`, `--fragment`), Munki options (`--munki-compliance-flags`, `--munki-compliance-path`, `--munki-flag-prefix`, `--munki-script-nopkg`, `--munki-script-catalog`, `--munki-script-category`, `--munki-script-separate-postinstall`), and exclusion options (`--exclude`).

```bash
# Process pre-built output
contour mscp process -i ./macos_security/build/cis_lvl1 -o ./output -b cis_lvl1 --fleet-mode
```

#### `mscp recipe`

Aggregate a baseline's rules into a single contour recipe TOML, ready to
drop into a recipe library and render with `contour profile generate
--recipe`. The recipe carries two kinds of block:

- **`[[profile]]`** — one per payload type (firewall, screensaver, …),
  built from the baseline's `mobileconfig` rules with every rule's keys
  merged in.
- **`[[ddm]]`** — one per DDM configuration, built from rules that carry
  a `ddm_info:` block (Declarative Device Management settings). A fully
  declarative baseline can therefore produce a DDM-only recipe with no
  `[[profile]]` blocks at all.

`recipe` reads rule YAML **directly** from the mSCP repository — it does
**not** run the mSCP Python build script, so it is fast and needs no
Python toolchain.

```
contour mscp recipe -r <MSCP_REPO> -b <BASELINE> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-r, --mscp-repo <PATH>` | Path to the mSCP repository (the directory containing `rules/`) | **required** |
| `-b, --baseline <NAME>` | Baseline name (e.g., `cis_lvl1`, `800-53r5_high`) | **required** |
| `-o, --output <PATH>` | Output recipe TOML path | `<baseline>.toml` |
| `--org <VENDOR>` | Organization vendor string written to the recipe header | none |
| `--odv-mode <MODE>` | How to render `$ODV` placeholders: `variable` or `inline` | `variable` |
| `--mscp-version <VER>` | Repository layout: `auto`, `1.x`, or `2.0` | `auto` |
| `--os <OS>` | OS target for 2.0 layouts: `macos`, `ios`, `visionos` (ignored for 1.x) | `macos` |
| `--os-version <VER>` | OS version for 2.0 layouts (e.g. `26.0`); highest available if unset | auto |

`--odv-mode variable` (default) keeps the literal `"$ODV"` placeholder
in each field and emits the resolved per-baseline defaults into a
top-level `[odv]` table — operators edit `[odv]` once and every
reference picks it up; `profile generate --recipe` substitutes at load
time. `--odv-mode inline` bakes the resolved default straight into the
field (e.g. `timeServer = "time.apple.com"`) — handy for one-shot
recipes that need no editable surface.

```bash
# Build a recipe from the CIS Level 1 baseline, then render it
contour mscp recipe -r ./macos_security -b cis_lvl1 -o ./recipes/cis_lvl1.toml --org com.acme
contour profile generate --recipe ./recipes/cis_lvl1.toml --org com.acme -o build
```

---

### Inspect & Validate

#### `mscp list`

List all baselines in an output directory.

```
contour mscp list --output <DIR> [--json]
```

```bash
contour mscp list -o ./output --json
```

#### `mscp validate`

Validate Fleet GitOps output against schemas.

```
contour mscp validate [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <DIR>` | Output directory to validate | **required** |
| `-s, --schemas <DIR>` | Path to JSON schema directory | none |
| `--strict` | Fail on warnings | `false` |

```bash
contour mscp validate -o ./output --strict
```

#### `mscp diff`

Compare baseline versions and generate a diff report. Tracks changes across regenerations.

```
contour mscp diff [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <DIR>` | Output directory containing GitOps structure | **required** |
| `-b, --baseline <NAME>` | Filter to specific baseline | all baselines |
| `-f, --format <FORMAT>` | `console` or `markdown` | `console` |

```bash
# Show what changed since last generation
contour mscp diff -o ./output -f markdown

# Diff a specific baseline
contour mscp diff -o ./output -b cis_lvl1
```

#### `mscp verify`

Verify GitOps repository for orphaned baseline references, missing labels, and structural integrity.

```
contour mscp verify [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <DIR>` | Output directory containing GitOps structure | **required** |
| `--fix` | Automatically fix orphaned references | `false` |

```bash
# Check for issues
contour mscp verify -o ./output

# Auto-fix orphaned references
contour mscp verify -o ./output --fix
```

---

### Baseline Management

#### `mscp deduplicate`

Find identical profiles across baselines and create a shared library. Reduces duplication when deploying multiple baselines.

```
contour mscp deduplicate [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <DIR>` | Output directory containing GitOps structure | **required** |
| `-b, --baselines <NAMES>` | Baselines to deduplicate (comma-separated) | all baselines |
| `-p, --platform <PLATFORM>` | Platform (`macOS`, `iOS`, `visionOS`) | `macOS` |
| `--jamf-mode` | Also emit Jamf Smart Group scoping templates (the Jamf counterpart to Fleet labels) for the deduplicated baselines | `false` |
| `--dry-run` | Preview without making changes | `false` |

```bash
# Deduplicate all baselines
contour mscp deduplicate -o ./output --dry-run

# Deduplicate specific baselines
contour mscp deduplicate -o ./output -b cis_lvl1,cis_lvl2
```

#### `mscp clean`

Remove a baseline and all associated files from the output directory.

```
contour mscp clean [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-b, --baseline <NAME>` | Baseline name to remove | **required** |
| `-o, --output <DIR>` | Output directory | **required** |
| `-f, --force` | Force removal even if referenced by fleet files | `false` |

```bash
contour mscp clean -b cis_lvl1 -o ./output
```

#### `mscp migrate`

Update fleet file references when moving from one baseline to another.

```
contour mscp migrate [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--from <NAME>` | Baseline to migrate from | **required** |
| `--to <NAME>` | Baseline to migrate to | **required** |
| `-f, --fleet <FLEET>` | Fleet file to migrate | **required** |
| `-o, --output <DIR>` | Output directory | **required** |
| `--no-backup` | Skip creating backup file | `false` |

```bash
# Migrate a fleet from CIS Level 1 to Level 2
contour mscp migrate --from cis_lvl1 --to cis_lvl2 -f engineering -o ./output
```

---

### Constraints

Constraints define MDM-native settings that conflict with mSCP-generated profiles. They prevent deploying profiles that would clash with your MDM's built-in capabilities.

Three constraint types: `fleet`, `jamf`, `munki`. Each generates its own constraint file (`fleet-constraints.yml`, `jamf-constraints.yml`, `munki-constraints.yml`).

#### `mscp constraints add`

Interactively add profiles to the exclusion list via fuzzy search.

```
contour mscp constraints add [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --type <TYPE>` | Constraint type: `fleet`, `jamf`, `munki` | `fleet` |
| `-c, --constraints <PATH>` | Path to constraints file | auto-detected |
| `-m, --mscp-repo <PATH>` | Path to mSCP repository for profile discovery | none |
| `-b, --baseline <NAME>` | Baseline to scan for profiles | all baselines |

```bash
contour mscp constraints add -t fleet -m ./macos_security -b cis_lvl1
```

#### `mscp constraints add-categories`

Exclude entire categories of rules (e.g., skip all audit or smartcard rules).

```
contour mscp constraints add-categories [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-b, --baseline <NAME>` | Baseline to resolve categories against | **required** |
| `-e, --exclude <CATEGORIES>` | Categories to exclude (comma-separated, skips interactive picker) | interactive |
| `-t, --type <TYPE>` | Constraint type: `fleet`, `jamf`, `munki` | `fleet` |
| `-c, --constraints <PATH>` | Path to constraints file | auto-detected |
| `-m, --mscp-repo <PATH>` | Path to mSCP repository | none |

```bash
# Interactive category picker
contour mscp constraints add-categories -b cis_lvl1 -m ./macos_security

# Direct exclusion
contour mscp constraints add-categories -b cis_lvl1 -e audit,smartcard
```

#### `mscp constraints add-script`

Interactively add scripts to the exclusion list.

```
contour mscp constraints add-script [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --type <TYPE>` | Constraint type: `fleet`, `jamf`, `munki` | `jamf` |
| `-c, --constraints <PATH>` | Path to constraints file | auto-detected |
| `-m, --mscp-repo <PATH>` | Path to mSCP repository | none |
| `-b, --baseline <NAME>` | Baseline to scan | all baselines |

#### `mscp constraints list` / `mscp constraints list-scripts`

List currently excluded profiles or scripts.

```bash
contour mscp constraints list -t fleet
contour mscp constraints list-scripts -t jamf
```

#### `mscp constraints remove` / `mscp constraints remove-script`

Interactively remove exclusions.

```bash
contour mscp constraints remove -t fleet
contour mscp constraints remove-script -t jamf
```

---

### ODVs (Organizational Defined Values)

mSCP rules can have parameterized values (e.g., minimum password length, screen lock timeout). ODVs let you customize these per organization without forking the mSCP repository.

Each rule with an ODV defines a `hint` (what it controls) and a `recommended` default. You create an override file to set organization-specific values.

#### `mscp odv init`

Create an ODV override file for a baseline. Scans all rules and generates a template with defaults.

```
contour mscp odv init [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-m, --mscp-repo <PATH>` | Path to mSCP repository | **required** |
| `-b, --baseline <NAME>` | Baseline name | **required** |
| `-o, --output <DIR>` | Output directory for override file | `.` |

```bash
contour mscp odv init -m ./macos_security -b cis_lvl1
# Creates: odv_cis_lvl1.yaml
```

#### `mscp odv list`

Show all ODVs for a baseline with their defaults and any overrides.

```
contour mscp odv list [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-m, --mscp-repo <PATH>` | Path to mSCP repository | **required** |
| `-b, --baseline <NAME>` | Baseline name | **required** |
| `-O, --overrides <PATH>` | ODV override file | auto-detected as `odv_<baseline>.yaml` |

```bash
contour mscp odv list -m ./macos_security -b cis_lvl1
```

#### `mscp odv edit`

Open ODV override file in `$EDITOR`.

```
contour mscp odv edit --overrides <PATH>
```

```bash
contour mscp odv edit --overrides odv_cis_lvl1.yaml
```

---

### Script Extraction

#### `mscp extract-scripts`

Extract remediation scripts from mSCP rules into standalone shell scripts. These are fix scripts only (not detection/audit).

```
contour mscp extract-scripts [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-m, --mscp-repo <PATH>` | Path to mSCP repository | **required** |
| `-b, --baseline <NAME>` | Baseline name | **required** |
| `-o, --output <DIR>` | Output directory for scripts | **required** |
| `--flat` | Flat output (no category subdirectories) | `false` |
| `--constraints <PATH>` | Constraints file for script exclusions | none |
| `--odv <PATH>` | ODV override file for value substitution | auto-detected |
| `--dry-run` | Preview without writing files | `false` |

```bash
# Extract with category organization
contour mscp extract-scripts -m ./macos_security -b cis_lvl1 -o ./scripts

# Flat output with ODV overrides
contour mscp extract-scripts -m ./macos_security -b stig -o ./scripts --flat --odv odv_stig.yaml
```

---

### Container Support

Run mSCP in a container (Docker or Apple containerization) when you don't want to install Python dependencies locally.

#### `mscp container init`

Initialize a local mSCP container. Creates a Dockerfile and optionally builds the image.

```
contour mscp container init [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-m, --mscp-repo <PATH>` | Path to mSCP repository | `./macos_security` |
| `--branch <BRANCH>` | Git branch to use | `tahoe` |
| `-t, --tag <TAG>` | Custom image name/tag | `mscp:local` |
| `--no-build` | Only create Dockerfile, don't build | `false` |
| `--docker` | Force Docker runtime | auto-detect |

```bash
contour mscp container init -m ./macos_security --branch tahoe
```

#### `mscp container pull`

Pull the mSCP container image from a registry.

```
contour mscp container pull [--image <IMAGE>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --image <IMAGE>` | Container image to pull | `ghcr.io/brodjieski/mscp_2.0:latest` |

#### `mscp container status`

Check if a container runtime (Docker, Podman, or Apple containerization) is available.

```bash
contour mscp container status
```

#### `mscp container test`

Test the container by running a simple command.

```
contour mscp container test [--image <IMAGE>]
```

---

### Schema Query (Embedded Dataset)

Query the embedded mSCP dataset (baselines, rules, statistics) directly — no mSCP repo clone required. All commands support `--json` for programmatic consumption.

#### `mscp schema baselines`

List every baseline in the embedded dataset.

```
contour mscp schema baselines [--json]
```

```bash
contour mscp schema baselines --json
```

#### `mscp schema rules`

List rules in a specific baseline (and optional platform).

```
contour mscp schema rules --baseline <NAME> [--platform <PLATFORM>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-b, --baseline <NAME>` | Baseline name (e.g., `cis_lvl1`, `800-53r5_high`) | **required** |
| `-p, --platform <PLATFORM>` | Platform: `macOS`, `iOS`, `visionOS` | `macOS` |

```bash
contour mscp schema rules --baseline cis_lvl1 --json
```

#### `mscp schema stats`

Show dataset statistics (rule counts per baseline, platform coverage, ODV rules, etc.).

```
contour mscp schema stats [--json]
```

#### `mscp schema compare`

Compare the embedded parquet data against a local mSCP repo's YAML files. Useful when refreshing the embedded dataset.

```
contour mscp schema compare <MSCP_REPO> <BASELINE> [--platform <PLATFORM>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<MSCP_REPO>` | Path to local mSCP repo | **required** |
| `<BASELINE>` | Baseline to compare | **required** |
| `--platform <PLATFORM>` | Platform filter | `macOS` |

#### `mscp schema search`

Search rules by keyword (matches against `rule_id`, title, and tags).

```
contour mscp schema search <QUERY> [--platform <PLATFORM>]
```

```bash
contour mscp schema search airdrop --json
contour mscp schema search filevault --platform macOS --json
```

#### `mscp schema rule`

Show full detail for a specific rule — including `has_odv`, `odv_options`, `mobileconfig_info`, `check_script`, and `enforcement_type`.

```
contour mscp schema rule <RULE_ID> [--json]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<RULE_ID>` | Rule ID (e.g., `os_airdrop_disable`) | **required** |

```bash
contour mscp schema rule os_airdrop_disable --json
```

---

## Common Workflows

### Single baseline for Fleet

Generate one baseline, add it to a fleet, and verify:

```bash
contour mscp init --org com.acme --fleet --sync
contour mscp generate -m ./macos_security -b cis_lvl1 -o ./output \
  --fleet-mode --fleets "Engineering" --org com.acme
contour mscp verify -o ./output
```

### Multiple baselines with deduplication

Generate several baselines, then deduplicate shared profiles:

```bash
contour mscp generate -m ./macos_security -b cis_lvl1 -o ./output --fleet-mode
contour mscp generate -m ./macos_security -b cis_lvl2 -o ./output --fleet-mode
contour mscp generate -m ./macos_security -b stig -o ./output --fleet-mode
contour mscp deduplicate -o ./output
```

### Jamf Pro deployment

Generate with Jamf-specific CLI flags (one-off use):

```bash
contour mscp generate -m ./macos_security -b 800-53r5_moderate -o ./output \
  --jamf-mode --deterministic-uuids --jamf-exclude-conflicts \
  --org com.acme --org-name "Acme Corp"
```

Or set `output.structure = "flat"` and `[settings.jamf]` in `mscp.toml` to avoid repeating flags.

### Config-driven workflow

Define everything in `mscp.toml` and generate all at once. The `output.structure` setting drives the layout — no need for `--fleet-mode` or `--jamf-mode` flags:

```bash
contour mscp init --org com.acme --fleet --sync --baselines cis_lvl1,cis_lvl2,stig
# Edit mscp.toml to customize settings (output.structure = "pluggable" set by --fleet)
contour mscp generate-all -c mscp.toml
contour mscp deduplicate -o ./output
contour mscp verify -o ./output
```

For Jamf Pro, init with `--jamf` sets `output.structure = "flat"` and enables Jamf postprocessing:

```bash
contour mscp init --org com.acme --jamf --sync --baselines cis_lvl1,stig
contour mscp generate-all -c mscp.toml
```

### Customizing with ODVs

Override default parameter values for your organization:

```bash
# Create ODV template
contour mscp odv init -m ./macos_security -b cis_lvl1

# Edit values (e.g., set minimum password length to 14)
contour mscp odv edit --overrides odv_cis_lvl1.yaml

# Generate with overrides applied
contour mscp generate -m ./macos_security -b cis_lvl1 -o ./output \
  --fleet-mode --odv odv_cis_lvl1.yaml
```

### Excluding categories

Skip audit or smartcard rules that don't apply to your environment:

```bash
# Interactive category picker
contour mscp constraints add-categories -b cis_lvl1 -m ./macos_security

# Or direct exclusion during generation
contour mscp generate -m ./macos_security -b cis_lvl1 -o ./output \
  --fleet-mode --exclude audit,smartcard
```

### Standalone remediation scripts

Extract fix scripts for manual deployment (e.g., via Munki or standalone):

```bash
contour mscp extract-scripts -m ./macos_security -b stig -o ./scripts
contour mscp extract-scripts -m ./macos_security -b stig -o ./scripts-flat --flat
```

### Version tracking

Track changes across regenerations:

```bash
# Generate (version info is tracked automatically)
contour mscp generate -m ./macos_security -b cis_lvl1 -o ./output --fleet-mode

# Later, regenerate and see what changed
contour mscp generate -m ./macos_security -b cis_lvl1 -o ./output --fleet-mode
contour mscp diff -o ./output -b cis_lvl1 -f markdown
```

### Baseline migration

Move a fleet from one baseline to another:

```bash
contour mscp migrate --from cis_lvl1 --to cis_lvl2 -f engineering -o ./output
contour mscp verify -o ./output
```

---

## Output Structure

The `output.structure` setting in `mscp.toml` (or `--fleet-mode` / `--jamf-mode` CLI flags) determines the directory layout. Three structures are available:

### `pluggable` — Fleet GitOps

Default structure. Produces a full Fleet GitOps repository (Fleet v4.83+
layout) with fleet YAMLs, labels, policies, and a `default.yml` entry
point.

```
output/
  default.yml                                   # Default fleet (labels, agent options)
  fleets/
    cis_lvl1.yml                                # Fleet YAML referencing profiles/scripts
    unassigned.yml                              # Unassigned hosts
  labels/
    mscp-cis_lvl1.labels.yml                    # Label definitions for targeting
  mscp/
    cis_lvl1/
      baseline.toml                             # Baseline metadata
    versions/
      manifest.json                             # Version tracking
  platforms/
    all/
      agent-options.yml
    macos/
      configuration-profiles/
        cis_lvl1/                               # .mobileconfig files
      scripts/
        cis_lvl1/                               # Remediation scripts (bundled by category)
      policies/
        cis_lvl1/                               # Fleet policies (YAML)
      declaration-profiles/
        cis_lvl1/                               # DDM declarations (if --generate-ddm)
```

Set via: `output.structure = "pluggable"`, `--fleet` during init, or `--fleet-mode` CLI flag.

### `flat` — Jamf Pro

Simple directory per baseline. No Fleet artifacts. Jamf postprocessing (deterministic UUIDs, identifier rewriting, conflict exclusion) is auto-enabled from `[settings.jamf]` in config.

```
output/
  cis_lvl1/
    profiles/                        # .mobileconfig files (Jamf-ready)
    scripts/                         # Remediation scripts
    declarative/                     # DDM declarations (if --generate-ddm)
```

Set via: `output.structure = "flat"`, `--jamf` during init, or `--jamf-mode` CLI flag.

### `nested` — Munki

Flat layout plus Munki-specific nopkg items. Munki compliance flags and script nopkg generation are auto-enabled from `[settings.munki]` in config.

```
output/
  cis_lvl1/
    profiles/                        # .mobileconfig files
    scripts/                         # Remediation scripts
    munki/
      compliance_flags.plist         # Munki compliance flags nopkg
      <rule_id>.plist                # Per-rule script nopkg items
```

Set via: `output.structure = "nested"`, `--munki` during init, or `--munki-*` CLI flags.

### Script Modes (Fleet)

| Mode | Description |
|------|-------------|
| `combined` | One combined script with all rules |
| `granular` | Individual script per rule |
| `bundled` | Scripts grouped by category prefix (e.g., `audit_*`, `os_*`) |
| `both` | Both granular and bundled |

---

## Global Flags

These flags work with all commands:

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format (for CI/CD pipelines and scripting) |
| `-v, --verbose` | Enable verbose logging |
| `--help` | Show help for any command |
