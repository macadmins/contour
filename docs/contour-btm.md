# contour btm -- Background Task Management Toolkit

> **Status: Preview** — feature-complete for core workflows, APIs and flags may still change before 1.0.

`contour btm` generates Service Management mobileconfig profiles and DDM declarations from macOS launch items. It scans LaunchDaemons, LaunchAgents, and app bundles for background tasks, produces a human-editable `btm.toml` policy file, and generates `.mobileconfig` or DDM JSON declarations ready for MDM deployment.

Aimed at Mac admins who need to pre-approve managed login items and background tasks (macOS 13+ Service Management framework) for managed applications.

## Quick Start

```bash
# Two-step GitOps workflow (recommended)
contour btm scan --mode launch-items --org com.acme -o btm.toml
contour btm generate btm.toml -o ./profiles

# One-shot mode (scan + generate in one step)
contour btm --org com.acme --mode launch-items -o ./profiles
```

## Workflow

### GitOps (recommended)

The two-step workflow separates discovery from generation, producing a version-controllable TOML file that can be reviewed, edited, and committed to Git before any profiles are created.

```
1. init         → btm.toml                    (create blank policy file)
2. scan         → btm.toml                    (discover launch items, extract team IDs)
3. validate     → pass/fail                   (check policy file for issues)
4. generate     → *.mobileconfig or *.json    (produce MDM-ready profiles or DDM declarations)
```

### One-shot

For quick, non-versioned use: scan launch items and generate profiles in one step, without an intermediate TOML file.

```bash
contour btm --org com.acme --mode launch-items -o ./profiles
contour btm --org com.acme --mode apps --path /Applications -I
```

---

## btm.toml

The policy file produced by `scan` and consumed by `generate`. Place it under version control.

```toml
[settings]
org = "com.yourorg"
display_name = "Your Org"     # optional

[[apps]]
name = "Zoom"
bundle_id = "us.zoom.xos"
team_id = "BJ4HAAB9B3"
code_requirement = 'identifier "us.zoom.xos" and certificate leaf[subject.OU] = "BJ4HAAB9B3"'

[[apps.rules]]
rule_type = "Label"
rule_value = "us.zoom.xos.rtc"
comment = "Zoom RTC daemon"

[[apps.rules]]
rule_type = "TeamIdentifier"
rule_value = "BJ4HAAB9B3"
comment = "Zoom team ID"

[[apps]]
name = "1Password"
bundle_id = "com.1password.1password"
team_id = "2BUA8C4S2C"

[[apps.rules]]
rule_type = "BundleIdentifier"
rule_value = "com.1password.1password"
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `settings.org` | yes | Reverse-domain identifier (e.g., `com.yourorg`). Used in `PayloadIdentifier`. |
| `settings.display_name` | no | Friendly name for generated profiles. |
| `apps[].name` | yes | Human-readable app name. |
| `apps[].bundle_id` | yes | Bundle identifier (e.g., `us.zoom.xos`). |
| `apps[].team_id` | no | Developer team ID from code signature. Used as fallback when no explicit rules are defined. |
| `apps[].code_requirement` | no | Full code signing requirement string. |
| `apps[].rules` | no | Array of BTM rules for this app. If empty and `team_id` is set, a `TeamIdentifier` rule is generated automatically. |

### Rule types

Each rule specifies what background tasks to allow for an application.

| Rule type | Purpose | Example value |
|-----------|---------|---------------|
| `TeamIdentifier` | Match by developer team ID | `BJ4HAAB9B3` |
| `BundleIdentifier` | Match exact bundle ID | `us.zoom.xos` |
| `BundleIdentifierPrefix` | Match bundle ID prefix | `us.zoom` |
| `Label` | Match exact launchd label | `us.zoom.xos.rtc` |
| `LabelPrefix` | Match launchd label prefix | `us.zoom` |

### Rule fields

| Field | Required | Description |
|-------|----------|-------------|
| `rule_type` | yes | One of the five rule types above. |
| `rule_value` | yes | Value to match (must be non-empty). |
| `comment` | no | Description or note about this rule. |

---

## Commands

### `btm init`

Create a blank `btm.toml` policy file.

```
contour btm init [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <FILE>` | Output file path | `btm.toml` |
| `--org <ORG>` | Organization identifier | `com.example` |
| `--name <NAME>` | Organization name (sets profile display name) | none |
| `--force` | Overwrite existing file | `false` |

```bash
contour btm init --org com.acme --name "Acme Corp"
contour btm init --org com.acme --output policy.toml --force
```

### `btm scan`

Discover LaunchDaemons, LaunchAgents, or app bundles and merge results into a `btm.toml`.

```
contour btm scan [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--mode <MODE>` | Scan mode: `launch-items` or `apps` | `launch-items` |
| `-p, --path <PATH>` | Directories to scan (repeatable) | see below |
| `-o, --output <FILE>` | Output policy file | `btm.toml` |
| `--org <ORG>` | Organization identifier | `.contour/config.toml` |
| `-I, --interactive` | Interactive multi-select picker | `false` |

**Default scan paths by mode:**
- `launch-items`: `/Library/LaunchDaemons`, `/Library/LaunchAgents`
- `apps`: `/Applications`

```bash
# Scan system launch items
contour btm scan --mode launch-items --org com.acme -o btm.toml

# Scan app bundles
contour btm scan --mode apps --path /Applications --org com.acme

# Interactive mode: choose which items to include
contour btm scan --mode launch-items --org com.acme -I
```

**Scan workflow:**
1. Discovers `.plist` files (launch items) or `.app` bundles
2. Parses each plist to extract: label, executable path, associated bundle identifiers
3. Resolves team ID from the executable via `codesign`
4. Suggests rules: `Label` + `TeamIdentifier` (if signed) + `BundleIdentifier` (for each associated bundle)
5. If interactive mode: presents a multi-select picker to filter results
6. Loads or creates the target config, merges results, deduplicates rules
7. Saves to `btm.toml`

Apps that fail scanning (unsigned, missing info) are skipped with a summary. Duplicate rules are deduplicated by `(rule_type, rule_value)` pair.

### `btm generate`

Generate mobileconfig profiles or DDM declarations from a `btm.toml`.

```
contour btm generate <INPUT> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUT>` | Input `btm.toml` | **required** |
| `-o, --output <PATH>` | Output directory | same dir as input |
| `--dry-run` | Preview without writing | `false` |
| `--ddm` | Generate DDM declarations (JSON) instead of mobileconfig | `false` |
| `--per-app` | Generate one profile per app instead of combined | `false` |
| `--fragment` | Generate Fleet GitOps fragment directory | `false` |

```bash
# Generate combined service management profile (default)
contour btm generate btm.toml -o ./profiles

# Generate one profile per app
contour btm generate btm.toml --per-app -o ./profiles

# Generate DDM declarations (macOS 15+)
contour btm generate btm.toml --ddm -o ./ddm

# Generate Fleet fragment for splice
contour btm generate btm.toml --fragment -o btm-fragment

# Preview what would be generated
contour btm generate btm.toml --dry-run
```

**Combined mode** (default): Creates a single `service-management.mobileconfig` with rules from all apps.

**Per-app mode** (`--per-app`): Creates one `{app-name}-service-management.mobileconfig` per app.

**DDM mode** (`--ddm`): Generates JSON declarations (type `com.apple.configuration.services.background-tasks`) instead of mobileconfig. One declaration per app. Only `Label`-type rules are included (as `LaunchdConfigurations`). Requires macOS 15+.

**Fragment mode** (`--fragment`): Produces a fragment directory with profiles under `lib/macos/configuration-profiles/`, a `fleets/reference-team.yml`, and a `fragment.toml` for merging into a Fleet GitOps repository. Default output dir: `btm-fragment/`.

### `btm validate`

Validate a `btm.toml` for structural issues.

```
contour btm validate [INPUT] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUT>` | Input policy file | `btm.toml` |
| `--strict` | Treat warnings as errors | `false` |

```bash
contour btm validate btm.toml
contour btm validate btm.toml --strict
```

**Checks:**
- TOML parses successfully
- Each rule has a valid `rule_type` (one of the five types)
- Each rule has a non-empty `rule_value`
- No duplicate rules within the same app
- Apps with no rules AND no `team_id` produce a warning

### `btm diff`

Compare BTM rules between two policy files. Matches apps by `bundle_id`.

```
contour btm diff <FILE1> <FILE2>
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE1>` | Old policy file | **required** |
| `<FILE2>` | New policy file | **required** |

```bash
contour btm diff btm-old.toml btm-new.toml
contour btm diff btm-old.toml btm-new.toml --json
```

Shows added apps (`+`), removed apps (`-`), and modified apps (`~` — rule count or team ID changes).

### `btm merge`

Merge BTM rules from a source policy into a target policy. Matches apps by `bundle_id`.

```
contour btm merge <SOURCE> <TARGET>
```

| Flag | Description | Default |
|------|-------------|---------|
| `<SOURCE>` | Source policy file | **required** |
| `<TARGET>` | Target policy file (modified in place) | **required** |

```bash
contour btm merge machine-a.toml central.toml
contour btm merge remote-scan.toml btm.toml
```

For each source app, finds the matching target app by `bundle_id` and adds rules (avoiding duplicates). Apps without a match in the target are skipped with a warning.

### `btm info`

Display toolkit version, scan modes, rule types, and summary of any `btm.toml` in the current directory.

```
contour btm info [--json]
```

---

## One-Shot Mode

When invoked without a subcommand, `contour btm` runs in one-shot mode: scan + generate in a single step.

```
contour btm [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--mode <MODE>` | Scan mode: `launch-items` or `apps` | `launch-items` |
| `-p, --path <PATH>` | Directories to scan (repeatable) | `/Applications` (see note) |
| `-o, --output <PATH>` | Output directory | current directory |
| `--org <ORG>` | Organization identifier | `.contour/config.toml` |
| `-I, --interactive` | Interactive launch-item selection | `false` |
| `--ddm` | Generate DDM declarations instead of mobileconfig | `false` |
| `--dry-run` | Preview without writing | `false` |

```bash
# Scan /Library/LaunchDaemons + /Library/LaunchAgents and generate in one step
contour btm --org com.acme --mode launch-items \
  -p /Library/LaunchDaemons -p /Library/LaunchAgents -o ./profiles

# Interactive one-shot over /Applications (apps mode matches the default --path)
contour btm --org com.acme --mode apps -I

# DDM one-shot
contour btm --org com.acme --ddm -o ./ddm
```

> **Note on `--path`**: the clap default is `/Applications`, which is the natural match for `--mode apps`. For `--mode launch-items` (the default), pass `-p /Library/LaunchDaemons -p /Library/LaunchAgents` explicitly — the one-shot entry point does not re-default to the system LaunchDaemon/Agent directories the way the `btm scan` subcommand does when no paths are given.

Produces profiles directly without creating an intermediate `.toml` file.

---

## Common Workflows

### Standard GitOps workflow

```bash
# 1. Initialize a policy file
contour btm init --org com.acme --name "Acme Corp"

# 2. Scan for launch items
contour btm scan --mode launch-items --org com.acme

# 3. Validate the policy
contour btm validate btm.toml

# 4. Generate profiles
contour btm generate btm.toml -o ./profiles

# 5. Commit to Git
git add btm.toml
git commit -m "Add BTM policy"
```

### DDM deployment (macOS 15+)

```bash
contour btm scan --mode launch-items --org com.acme
contour btm generate btm.toml --ddm -o ./ddm
# Deploy ./ddm/*.json via MDM
```

### Multi-machine merge

Aggregate scans from multiple machines into a single policy:

```bash
# On machine A
contour btm scan --mode launch-items --org com.acme -o machine-a.toml

# On machine B
contour btm scan --mode launch-items --org com.acme -o machine-b.toml

# Merge into a central policy
contour btm merge machine-a.toml central.toml
contour btm merge machine-b.toml central.toml
contour btm generate central.toml -o ./profiles
```

### Fleet GitOps integration

Generate a fragment directory for Fleet splice:

```bash
contour btm scan --mode launch-items --org com.acme
contour btm generate btm.toml --fragment -o btm-fragment
# Merge the fragment into your Fleet GitOps repo
```

### Tracking changes

```bash
cp btm.toml btm-old.toml
contour btm scan --mode launch-items --org com.acme
contour btm diff btm-old.toml btm.toml
```

---

## Output Structure

### Combined mode (default)

```
profiles/
  service-management.mobileconfig
```

### Per-app mode (`--per-app`)

```
profiles/
  Zoom-service-management.mobileconfig
  1Password-service-management.mobileconfig
  Slack-service-management.mobileconfig
```

### DDM mode (`--ddm`)

```
ddm/
  zoom-btm.json
  1password-btm.json
  slack-btm.json
```

### Fragment mode (`--fragment`)

```
btm-fragment/
  lib/
    macos/
      configuration-profiles/
        Zoom-service-management.mobileconfig
        1Password-service-management.mobileconfig
  fleets/
    reference-team.yml
  fragment.toml
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

The `--org` flag follows this precedence:

1. Explicit `--org` CLI flag
2. `.contour/config.toml` (nearest ancestor directory)
3. Default `com.example` (for `init` only)

Set a project-wide default with:

```bash
mkdir -p .contour
cat > .contour/config.toml << 'EOF'
[organization]
domain = "com.yourorg"
name = "Your Org"
EOF
```
