# contour notifications -- Notification Settings Toolkit

`contour notifications` generates notification settings mobileconfig profiles for macOS MDM deployment. It scans installed applications, produces a human-editable `notifications.toml` policy file, and generates `.mobileconfig` profiles that control per-app notification behavior (alerts, badges, sounds, lock screen, critical alerts).

Aimed at Mac admins who need to manage notification settings across managed applications — suppressing noisy alerts, enabling critical notifications, or standardizing notification behavior fleet-wide.

## Quick Start

```bash
# Two-step GitOps workflow (recommended)
contour notifications scan -p /Applications -o notifications.toml --org com.acme
contour notifications configure notifications.toml
contour notifications generate notifications.toml -o ./profiles

# One-shot mode (scan + generate in one step)
contour notifications -p /Applications --org com.acme -o ./profiles
```

## Workflow

### GitOps (recommended)

The two-step workflow separates discovery from generation, producing a version-controllable TOML file that can be reviewed, edited, and committed to Git before any profiles are created.

```
1. init         → notifications.toml        (create blank policy file)
2. scan         → notifications.toml        (discover apps)
3. configure    → notifications.toml        (interactively set per-app notification preferences)
4. validate     → pass/fail                 (check policy file for issues)
5. generate     → *.mobileconfig            (produce MDM-ready profiles)
```

### One-shot

For quick, non-versioned use: scan apps and generate profiles in one step, without an intermediate TOML file.

```bash
contour notifications -p /Applications --org com.acme -o ./profiles
contour notifications -p /Applications --org com.acme --combined -o notifications.mobileconfig
```

---

## notifications.toml

The policy file produced by `scan` and consumed by `generate`. Place it under version control.

```toml
[settings]
org = "com.yourorg"
display_name = "Your Org"     # optional

[[apps]]
name = "Slack"
bundle_id = "com.tinyspeck.slackmacgap"
alerts_enabled = true
alert_type = 1
badges_enabled = true
critical_alerts = true
lock_screen = true
notification_center = true
sounds_enabled = false

[[apps]]
name = "Zoom"
bundle_id = "us.zoom.xos"
alerts_enabled = true
alert_type = 2
badges_enabled = true
critical_alerts = false
lock_screen = false
notification_center = true
sounds_enabled = false
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `settings.org` | yes | Reverse-domain identifier (e.g., `com.yourorg`). Used in `PayloadIdentifier`. |
| `settings.display_name` | no | Friendly name for generated profiles. |
| `apps[].name` | yes | Human-readable app name. |
| `apps[].bundle_id` | yes | Bundle identifier (e.g., `com.tinyspeck.slackmacgap`). |

### Notification settings

Per-app notification preferences. All are optional with sensible defaults.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `alerts_enabled` | bool | `true` | Master toggle — enable or disable all notifications for the app. |
| `alert_type` | integer | `1` | Alert style: `0` = None, `1` = Temporary Banner, `2` = Persistent Banner. |
| `badges_enabled` | bool | `true` | Show red badge count on the app icon. |
| `critical_alerts` | bool | `true` | Allow critical alerts that bypass Do Not Disturb and mute. |
| `lock_screen` | bool | `true` | Show notifications on the lock screen. |
| `notification_center` | bool | `true` | Show notifications in Notification Center. |
| `sounds_enabled` | bool | `false` | Play a sound when a notification arrives. |

---

## Commands

### `notifications init`

Create a blank `notifications.toml` policy file.

```
contour notifications init [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <FILE>` | Output file path | `notifications.toml` |
| `--org <ORG>` | Organization identifier | `com.example` |
| `--name <NAME>` | Organization name (sets profile display name) | none |
| `--force` | Overwrite existing file | `false` |

```bash
contour notifications init --org com.acme --name "Acme Corp"
```

### `notifications scan`

Discover installed applications and add them to a `notifications.toml`.

```
contour notifications scan [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --path <PATH>` | Directory or `.app` bundle to scan (repeatable) | `/Applications` |
| `-o, --output <FILE>` | Output policy file | `notifications.toml` |
| `--org <ORG>` | Organization identifier | `.contour/config.toml` |
| `-I, --interactive` | Interactive multi-select picker | `false` |

```bash
# Scan /Applications
contour notifications scan -o notifications.toml --org com.acme

# Scan specific apps
contour notifications scan -p /Applications/Slack.app -p /Applications/Zoom.app -o notifications.toml

# Interactive mode: choose which apps to include
contour notifications scan -p /Applications -o notifications.toml -I
```

Scanned apps are added with default notification settings (all enabled except sounds). Duplicate bundle IDs are skipped when merging into an existing config.

### `notifications configure`

Interactively walk through each app and set notification preferences.

```
contour notifications configure [INPUT]
```

| Flag | Description | Default |
|------|-------------|---------|
| `[INPUT]` | Input `notifications.toml` (modified in-place) | `notifications.toml` |

```bash
contour notifications configure notifications.toml
```

For each app, prompts for:
1. Alerts enabled?
2. Alert type (None / Temporary Banner / Persistent Banner)
3. Badges enabled?
4. Critical alerts?
5. Show on lock screen?
6. Show in Notification Center?
7. Sounds enabled?

Settings are saved after each app.

### `notifications generate`

Generate `.mobileconfig` profiles from a `notifications.toml`.

```
contour notifications generate <INPUT> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUT>` | Input `notifications.toml` | **required** |
| `-o, --output <PATH>` | Output directory or file path | same dir as input |
| `--combined` | Merge all apps into a single profile | `false` |
| `--dry-run` | Preview profiles without writing | `false` |

```bash
# Generate per-app profiles (one .mobileconfig per app)
contour notifications generate notifications.toml -o ./profiles

# Generate a single combined profile
contour notifications generate notifications.toml --combined -o notifications.mobileconfig

# Preview what would be generated
contour notifications generate notifications.toml --dry-run
```

**Per-app mode** (default): Creates one `{app-name}-notifications.mobileconfig` per app. Profile identifier: `{org}.notifications.{bundle-id}`.

**Combined mode** (`--combined`): Merges all notification settings into a single profile.

### `notifications validate`

Validate a `notifications.toml` for structural issues.

```
contour notifications validate [INPUT] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `[INPUT]` | Input policy file | `notifications.toml` |
| `--strict` | Treat warnings as errors | `false` |

```bash
contour notifications validate notifications.toml
contour notifications validate notifications.toml --strict
```

### `notifications diff`

Compare notification settings between two policy files. Matches apps by `bundle_id`.

```
contour notifications diff <FILE1> <FILE2>
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE1>` | Old policy file | **required** |
| `<FILE2>` | New policy file | **required** |

```bash
contour notifications diff notifications-old.toml notifications-new.toml
```

Shows added apps (`+`), removed apps (`-`), and modified apps (`~` — setting changes).

---

## One-Shot Mode

When invoked without a subcommand, `contour notifications` runs in one-shot mode: scan + generate in a single step.

```
contour notifications [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --path <PATH>` | Directory or `.app` to scan (repeatable) | `/Applications` |
| `-o, --output <PATH>` | Output directory | current directory |
| `--org <ORG>` | Organization identifier | `.contour/config.toml` |
| `-I, --interactive` | Interactive app selection | `false` |
| `--combined` | Generate a single combined profile | `false` |
| `--dry-run` | Preview without writing | `false` |

```bash
# Scan and generate in one step
contour notifications -p /Applications --org com.acme -o ./profiles

# Interactive one-shot with combined output
contour notifications -p /Applications --org com.acme -I --combined
```

Produces profiles directly without creating an intermediate `.toml` file. All apps get default notification settings (all enabled except sounds).

---

## Common Workflows

### Standard GitOps workflow

```bash
# 1. Initialize a policy file
contour notifications init --org com.acme --name "Acme Corp"

# 2. Scan for applications
contour notifications scan -p /Applications --org com.acme

# 3. Configure notification preferences per app
contour notifications configure notifications.toml

# 4. Validate before generating
contour notifications validate notifications.toml

# 5. Generate profiles
contour notifications generate notifications.toml -o ./profiles

# 6. Commit to Git
git add notifications.toml
git commit -m "Add notification settings policy"
```

### Tracking changes

```bash
cp notifications.toml notifications-old.toml
contour notifications scan -p /Applications --org com.acme
contour notifications diff notifications-old.toml notifications.toml
```

### CI/CD pipeline

```bash
contour notifications scan -p /Applications --org com.acme -o notifications.toml
contour notifications validate notifications.toml
contour notifications generate notifications.toml -o ./profiles --json
```

---

## Output Structure

### Per-app mode (default)

```
profiles/
  Slack-notifications.mobileconfig
  Zoom-notifications.mobileconfig
  Chrome-notifications.mobileconfig
```

### Combined mode (`--combined`)

```
notifications.mobileconfig    # Single profile with all apps
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
