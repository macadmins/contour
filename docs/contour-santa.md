# contour santa -- Santa Binary Authorization Toolkit

> **Status: Preview** — feature-complete for core workflows, APIs and flags may still change before 1.0.

`contour santa` manages [Google Santa](https://santa.dev) rules and generates `.mobileconfig` profiles for MDM deployment. It handles rule ingestion from multiple sources (Fleet CSV exports, `santactl`, osquery, Installomator, existing mobileconfigs), rule management (add, remove, filter, merge, snip), profile generation in multiple formats (mobileconfig, plist, WS1), and prerequisite profile generation.

Aimed at Mac admins deploying Santa for binary authorization — building allowlists, managing rules across environments, and generating MDM-ready profiles.

## Quick Start

```bash
# Scan local apps and generate a mobileconfig directly
contour santa scan --output-format mobileconfig --output santa-rules.mobileconfig --org com.acme

# Or: scan → rules → profile (two-step)
contour santa scan -o apps.csv
contour santa allow --input apps.csv --org com.acme -o santa-rules.mobileconfig

# Generate prerequisite profiles (deploy before Santa rules)
contour santa prep --org com.acme -o ./santa-prep
```

## Workflow

```
Local scan path:
  scan → CSV → allow → mobileconfig (simple allowlist)
  scan → rules.yaml → generate → mobileconfig (two-step)
  scan → mobileconfig (one-shot)

Existing rules path:
  fetch (osquery/santactl/mobileconfig/installomator) → rules.yaml
  rules.yaml → generate → mobileconfig
```

---

## Rule Files

Rules are stored in YAML (preferred), JSON, or CSV format. YAML example:

```yaml
- rule_type: TEAM_ID
  identifier: 2BUA8C4S2C
  policy: ALLOWLIST
  description: "AgileBits (1Password)"
  group: "vendors"

- rule_type: SIGNING_ID
  identifier: "EQHXZ8M8AV:com.google.Chrome"
  policy: ALLOWLIST
  description: "Google Chrome"

- rule_type: BINARY
  identifier: "abc123def456..."
  policy: BLOCKLIST
  custom_msg: "This application is not allowed"
  custom_url: "https://wiki.example.com/security"
```

### Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `rule_type` | yes | `TEAM_ID`, `SIGNING_ID`, `BINARY`, `CERTIFICATE`, or `CDHASH` (aliases `TEAMID`/`SIGNINGID` also accepted) |
| `identifier` | yes | Rule identifier (TeamID, SigningID, SHA-256 hash, or CDHash) |
| `policy` | yes | `ALLOWLIST`, `ALLOWLIST_COMPILER`, `BLOCKLIST`, `SILENT_BLOCKLIST`, `REMOVE`, or `CEL` |
| `description` | no | Human-readable description (e.g., app or vendor name) |
| `custom_msg` | no | Custom block message shown to the user |
| `custom_url` | no | URL shown in block notifications |
| `group` | no | Logical group for organizing rules |
| `labels` | no | Fleet labels for targeting |
| `cel_expression` | no | CEL expression (when `policy = CEL`) |

### Rule Types

| Type | CLI value | Description |
|------|-----------|-------------|
| TeamID | `team-id` | Vendor-level — allows all apps from a vendor. Fewest rules, lowest maintenance. |
| SigningID | `signing-id` | App-level — allows a specific app by signing identity. Balanced. |
| Binary | `binary` | Binary-level — allows a specific binary by SHA-256 hash. Most specific, highest churn. |
| Certificate | `certificate` | Certificate-level — allows by certificate hash. |
| CDHash | `cdhash` | Code Directory Hash — most specific, tied to exact binary version. |

### Policies

| Policy | Description |
|--------|-------------|
| `ALLOWLIST` | Allow execution |
| `ALLOWLIST_COMPILER` | Allow execution and allow this binary to compile other binaries |
| `BLOCKLIST` | Block execution (shows notification) |
| `SILENT_BLOCKLIST` | Block execution silently (no notification) |
| `REMOVE` | Remove a previously deployed rule |
| `CEL` | Dynamic rule using Common Expression Language |

---

## santa.toml

Project configuration file created by `santa init`. Commands walk up the directory tree to find it.

```toml
[organization]
name = "Acme Corp"
domain = "com.acme"
# security_email = "security@acme.com"    # optional

[profiles]
prefix = "santa"
deterministic_uuids = true
max_rules_per_profile = 0     # 0 = unlimited
output_directory = "profiles"

[validation]
strict = false
require_descriptions = false
validate_team_id_format = true
```

---

## Commands

### Getting Started

#### `santa init`

Initialize a new `santa.toml` configuration file.

```
contour santa init [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <FILE>` | Output file path | `santa.toml` |
| `--org <ORG>` | Organization identifier | interactive prompt |
| `--name <NAME>` | Organization name | interactive prompt |
| `--force` | Overwrite existing configuration | `false` |

```bash
contour santa init --org com.acme --name "Acme Corp"
```

#### `santa prep`

Generate the prerequisite profiles required for Santa to function properly. Deploy these via MDM **before** deploying Santa rules.

Generates:
- System Extension Policy (allow Santa's endpoint security extension)
- Service Management (managed login items)
- TCC/PPPC (Full Disk Access for Santa components)
- Notification Settings (enable Santa notifications)
- Santa Configuration (client mode defaults)

```
contour santa prep [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output-dir <DIR>` | Output directory | `./santa-prep` |
| `--org <ORG>` | Organization identifier prefix | `com.example` |
| `--dry-run` | Preview without writing files | `false` |

```bash
contour santa prep --org com.acme -o ./santa-prep
```

---

### Scan & Discover

#### `santa scan`

Scan local applications using `santactl` and generate output in various formats. Requires Santa to be installed (`santactl` must be available).

```
contour santa scan [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --path <PATH>` | Directory to scan | `/Applications` |
| `-o, --output <FILE>` | Output file | stdout |
| `-f, --output-format <FMT>` | Output format: `csv`, `bundles`, `rules`, `mobileconfig` | `csv` |
| `--include-unsigned` | Include unsigned applications | `false` |
| `--org <ORG>` | Organization identifier (required for `mobileconfig` format) | `com.example` |
| `--rule-type <TYPE>` | Rule type: `team-id` or `signing-id` | `team-id` |
| `--merge <FILES>` | Merge multiple scan CSVs into one | none |

```bash
# Scan to CSV (for downstream commands)
contour santa scan -o apps.csv

# Scan directly to mobileconfig
contour santa scan --output-format mobileconfig --org com.acme -o santa.mobileconfig

# Scan to bundles.toml (groups by TeamID)
contour santa scan --output-format bundles -o bundles.toml

# Scan to rules.yaml
contour santa scan --output-format rules -o rules.yaml --rule-type signing-id
```

---

### Generate & Transform

#### `santa generate`

Generate `.mobileconfig` profiles from rule files. Accepts YAML, JSON, or CSV input.

```
contour santa generate <INPUTS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUTS>...` | Input rule files | **required** |
| `-o, --output <FILE>` | Output file path | stdout |
| `--org <ORG>` | Organization identifier prefix | `com.example` |
| `--identifier <ID>` | Profile identifier | `{org}.santa.rules` |
| `--display-name <NAME>` | Profile display name | auto-generated |
| `--deterministic-uuids` | Use deterministic UUIDs for reproducible builds | `false` |
| `--format <FMT>` | Output format: `mobileconfig`, `plist`, `plist-full` | `mobileconfig` |
| `--fragment` | Generate Fleet GitOps fragment directory | `false` |
| `--dry-run` | Preview without writing | `false` |

**Output formats:**

| Format | Description |
|--------|-------------|
| `mobileconfig` | Standard Apple mobileconfig (MDM profile) |
| `plist` | Plist payload without XML header (Workspace ONE compatible) |
| `plist-full` | Plist payload with XML header (Jamf custom schema compatible) |

```bash
# Generate mobileconfig from rules
contour santa generate rules.yaml -o santa-rules.mobileconfig --org com.acme

# Generate with deterministic UUIDs for GitOps
contour santa generate rules.yaml -o santa.mobileconfig --org com.acme --deterministic-uuids

# Generate WS1-compatible plist
contour santa generate rules.yaml --format plist -o santa.plist

# Generate Fleet fragment
contour santa generate rules.yaml --fragment -o santa-fragment --org com.acme
```

#### `santa allow`

Convert a CSV directly to a Santa allowlist mobileconfig — no bundle definitions needed. The simplest path from scan data to a deployable profile.

```
contour santa allow [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input <FILE>` | Input CSV file | **required** |
| `-o, --output <FILE>` | Output file path | auto-generated |
| `--rule-type <TYPE>` | Rule type: `team-id` or `signing-id` | `signing-id` |
| `--org <ORG>` | Organization identifier prefix | `com.example` |
| `--name <NAME>` | Profile display name | auto-generated |
| `--no-deterministic-uuids` | Disable deterministic UUIDs | `false` (deterministic by default) |
| `--dry-run` | Preview without writing | `false` |

```bash
contour santa allow --input apps.csv --org com.acme
contour santa allow --input fleet-export.csv --rule-type team-id -o vendor-allowlist.mobileconfig
```

#### `santa config`

Generate a Santa configuration profile (client mode, sync server, USB blocking — not rules).

```
contour santa config [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <FILE>` | Output file path | stdout |
| `--mode <MODE>` | Client mode: `monitor` or `lockdown` | `monitor` |
| `--sync-url <URL>` | Sync server URL | none |
| `--machine-owner-plist <PATH>` | Machine owner plist path | none |
| `--block-usb` | Block USB mass storage | `false` |
| `--dry-run` | Preview without writing | `false` |

```bash
contour santa config -o santa-config.mobileconfig --mode monitor
contour santa config -o santa-config.mobileconfig --mode lockdown --sync-url https://santa.example.com --block-usb
```

---

### Rule Management

#### `santa add`

Add a rule to an existing rules file. Designed for use with Installomator posthooks or `santactl` output.

```
contour santa add [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --file <FILE>` | Rules file to update (YAML) | **required** |
| `--teamid <ID>` | TeamID to add (10-character identifier) | none |
| `--binary <HASH>` | Binary hash (SHA-256) | none |
| `--certificate <HASH>` | Certificate hash (SHA-256) | none |
| `--signingid <ID>` | Signing ID (TeamID:BundleID) | none |
| `--cdhash <HASH>` | CDHash (40-character hash) | none |
| `--policy <POLICY>` | Policy for the rule | `allowlist` |
| `-d, --description <DESC>` | Rule description | none |
| `-g, --group <GROUP>` | Group for organizing rules | none |
| `--regenerate <FILE>` | Regenerate mobileconfig after adding | none |
| `--org <ORG>` | Organization identifier for regenerated profile | none |
| `-i, --interactive` | Interactive mode: guided rule type selection | `false` |

```bash
# Add a TeamID rule
contour santa add --file rules.yaml --teamid EQHXZ8M8AV --description "Google"

# Add from santactl output
santactl fileinfo /path/to/app | contour santa add --file rules.yaml --from-stdin

# Add and regenerate profile
contour santa add --file rules.yaml --teamid EQHXZ8M8AV -d "Google" --regenerate santa.mobileconfig --org com.acme
```

#### `santa remove`

Delete rules from a file. Rules are discarded. See also `snip`, which moves rules between files instead of deleting them.

```
contour santa remove <IDENTIFIER> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<IDENTIFIER>` | Identifier to remove | **required** |
| `-f, --file <FILE>` | Rules file to update | **required** |
| `--rule-type <TYPE>` | Rule type (to disambiguate) | none |
| `--dry-run` | Preview without writing | `false` |

```bash
contour santa remove EQHXZ8M8AV --file rules.yaml
contour santa remove "EQHXZ8M8AV:com.google.Chrome" --file rules.yaml --rule-type signing-id
```

#### `santa snip`

Move matching rules from one file into another. Matched rules are removed from the source and appended to the destination (created if missing). Useful for splitting large rule files or extracting rules for a specific vendor. See also `remove`, which deletes rules instead of moving them.

```
contour santa snip [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-s, --source <FILE>` | Source rules file | **required** |
| `-d, --dest <FILE>` | Destination file (created if missing, appended if exists) | **required** |
| `--identifier <PATTERN>` | Snip rules matching this identifier substring | none |
| `--rule-type <TYPE>` | Snip rules of this type | none |
| `--policy <POLICY>` | Snip rules with this policy | none |
| `--group <GROUP>` | Snip rules in this group | none |
| `--dry-run` | Preview without writing | `false` |

```bash
# Extract all Google rules to a separate file
contour santa snip --source rules.yaml --dest google-rules.yaml --identifier EQHXZ8M8AV

# Extract all blocklist rules
contour santa snip --source rules.yaml --dest blocklist.yaml --policy blocklist
```

#### `santa merge`

Combine multiple rule sources into one file.

```
contour santa merge <INPUTS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUTS>...` | Input rule files to merge | **required** |
| `-o, --output <FILE>` | Output file path | stdout |
| `--strategy <STRATEGY>` | Conflict resolution: `first`, `last`, `strict` | `last` |
| `--dry-run` | Preview without writing | `false` |

```bash
contour santa merge vendors.yaml internal.yaml -o combined.yaml
contour santa merge vendors.yaml overrides.yaml --strategy last -o merged.yaml
```

#### `santa filter`

Filter rules by various criteria.

```
contour santa filter <INPUTS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUTS>...` | Input rule files | **required** |
| `-o, --output <FILE>` | Output file | stdout |
| `--rule-type <TYPE>` | Filter by type: `binary`, `certificate`, `team-id`, `signing-id`, `cdhash` | none |
| `--policy <POLICY>` | Filter by policy | none |
| `--group <GROUP>` | Filter by group | none |
| `--has-description <BOOL>` | Filter by description presence | none |
| `--identifier-contains <PAT>` | Filter by identifier substring | none |
| `--description-contains <PAT>` | Filter by description substring | none |

```bash
# Show only TeamID rules
contour santa filter rules.yaml --rule-type team-id

# Show blocklist rules
contour santa filter rules.yaml --policy blocklist

# Find rules for a specific vendor
contour santa filter rules.yaml --identifier-contains EQHXZ8M8AV
```

---

### Inspect & Validate

#### `santa validate`

Validate rule files for structural issues.

```
contour santa validate <INPUTS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUTS>...` | Input rule files to validate | **required** |
| `--strict` | Treat warnings as errors | `false` |
| `--warn-groups` | Warn about rules without group assignment | `false` |

```bash
contour santa validate rules.yaml
contour santa validate rules.yaml --strict --warn-groups
```

#### `santa diff`

Compare two rule sets. Shows added, removed, and changed rules.

```
contour santa diff <FILE1> <FILE2>
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE1>` | First rule file | **required** |
| `<FILE2>` | Second rule file | **required** |

```bash
contour santa diff rules-v1.yaml rules-v2.yaml
contour santa diff rules-v1.yaml rules-v2.yaml --json
```

#### `santa stats`

Show statistics about rules — counts by type, policy, group, etc.

```
contour santa stats <INPUTS>...
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUTS>...` | Input rule files | **required** |

```bash
contour santa stats rules.yaml
contour santa stats rules.yaml --json
```

---

### Fetch (Import from External Sources)

#### `santa fetch osquery`

Parse osquery `santa_rules` JSON output into rules.

```
contour santa fetch osquery <INPUT> [-o <OUTPUT>]
```

#### `santa fetch mobileconfig`

Extract rules from an existing mobileconfig profile.

```
contour santa fetch mobileconfig <INPUT> [-o <OUTPUT>]
```

#### `santa fetch santactl`

Parse `santactl fileinfo` output into rules.

```
contour santa fetch santactl <INPUT> [-o <OUTPUT>]
```

#### `santa fetch installomator`

Extract TeamIDs from Installomator labels.

```
contour santa fetch installomator <INPUT> [-o <OUTPUT>]
```

#### `santa fetch fleet-csv`

Extract rules from Fleet software CSV export. Supports flexible column names: `team_identifier`/`team_id`/`teamid`, `name`/`software_name`/`app_name`, `bundle_identifier`/`bundleid`/`bundle_id`.

```
contour santa fetch fleet-csv <INPUT> [-o <OUTPUT>]
```

```bash
contour santa fetch osquery santa-rules.json -o rules.yaml
contour santa fetch mobileconfig existing-santa.mobileconfig -o rules.yaml
contour santa fetch installomator Installomator.sh -o installomator-rules.yaml
contour santa fetch fleet-csv fleet-software.csv -o fleet-rules.yaml
```

---

### Pipeline

#### `santa pipeline` (alias: `pipe`)

Run the full Fleet CSV → bundles → profiles pipeline in one deterministic step. Combines discovery, classification, and rule generation.

```
contour santa pipeline --input <CSV> --bundles <TOML> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input <CSV>` | Input Fleet software CSV | **required** |
| `-b, --bundles <TOML>` | Bundle definitions file | **required** |
| `-o, --output-dir <DIR>` | Output directory for generated profiles | `./profiles` |
| `--org <DOMAIN>` | Organization identifier prefix | `com.example` |
| `--dedup-level <LEVEL>` | Deduplication across devices | `signing-id` |
| `--rule-type <STRATEGY>` | `team-id`, `prefer-signing-id`, `signing-id`, `bundle`, `binary-only` | `prefer-signing-id` |
| `--orphan-policy <POLICY>` | Apps that match no bundle: `catch-all`, `warn`, `error`, `skip` | `catch-all` |
| `--conflict-policy <POLICY>` | Apps that match multiple bundles: `first-match`, `most-specific`, `priority`, `error` | `most-specific` |
| `--deterministic` | Sort rules and reproduce UUIDs | `true` |
| `--layer-stage` | Emit a Layer × Stage matrix of profiles | `false` |
| `--stages <N>` | With `--layer-stage`: `2`, `3`, or `5` | `3` |
| `--dry-run` | Preview without writing files | `false` |

```bash
# Basic pipeline
contour santa pipeline -i fleet.csv -b bundles.toml --org com.acme -o profiles/

# Layer × Stage matrix (staged rollout)
contour santa pipeline -i fleet.csv -b bundles.toml --org com.acme --layer-stage --stages 3
```

---

## Common Workflows

### Simple local allowlist

Scan local apps and generate a profile in one step:

```bash
contour santa scan --output-format mobileconfig --org com.acme -o santa-rules.mobileconfig
```

### Two-step local allowlist

Scan to CSV, then convert:

```bash
contour santa scan -o apps.csv
contour santa allow --input apps.csv --org com.acme -o santa-rules.mobileconfig
```

### Fleet CSV to profile

From a Fleet software export:

```bash
contour santa fetch fleet-csv fleet-export.csv -o rules.yaml
contour santa generate rules.yaml -o santa-rules.mobileconfig --org com.acme
```

### Managing rules over time

```bash
# Add a new vendor
contour santa add --file rules.yaml --teamid EQHXZ8M8AV -d "Google"

# Remove a rule
contour santa remove EQHXZ8M8AV --file rules.yaml

# Merge vendor and internal rules
contour santa merge vendors.yaml internal.yaml -o combined.yaml

# Extract Google rules for separate management
contour santa snip --source combined.yaml --dest google.yaml --identifier EQHXZ8M8AV

# Regenerate profile
contour santa generate combined.yaml -o santa.mobileconfig --org com.acme --deterministic-uuids
```

### Deploying Santa from scratch

```bash
# 1. Generate prerequisite profiles (includes system extension, PPPC, login items,
#    notifications, and a default Santa configuration profile)
contour santa prep --org com.acme -o ./santa-prep

# 2. Deploy prerequisites via MDM

# 3. Scan apps and generate rules
contour santa scan -o apps.csv
contour santa allow --input apps.csv --org com.acme -o santa-rules.mobileconfig

# 4. Deploy santa-rules.mobileconfig via MDM
```

### CI/CD pipeline

```bash
contour santa validate rules.yaml --strict
contour santa generate rules.yaml -o santa.mobileconfig --org com.acme --deterministic-uuids --json
```

---

## Output Structure

### Default (single profile)

```
santa-rules.mobileconfig
```

### Fragment mode (`--fragment`)

```
santa-fragment/
  lib/
    macos/
      configuration-profiles/
        santa-rules.mobileconfig
  fleets/
    reference-team.yml
  fragment.toml
```

### Prerequisite profiles (`prep`)

```
santa-prep/
  santa-system-extension.mobileconfig
  santa-service-management.mobileconfig
  santa-tcc.mobileconfig
  santa-notifications.mobileconfig
  santa-config.mobileconfig
```

---

## Global Flags

These flags work with all commands:

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format (for CI/CD pipelines and scripting) |
| `-v, --verbose` | Enable verbose logging |
| `--help` | Show help for any command |

---

## Organization Resolution

The `--org` flag defaults to `com.example` when not specified. Set a project-wide default with `santa init`:

```bash
contour santa init --org com.acme --name "Acme Corp"
```

Or set `.contour/config.toml` for cross-toolkit defaults:

```bash
mkdir -p .contour
cat > .contour/config.toml << 'EOF'
[organization]
domain = "com.yourorg"
name = "Your Org"
EOF
```
