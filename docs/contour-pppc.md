# contour pppc -- Privacy Preferences Policy Control Toolkit

`contour pppc` generates TCC (Transparency, Consent, and Control) mobileconfig profiles from app bundles. It scans applications for code signing requirements, produces a human-editable `pppc.toml` policy file, and generates `.mobileconfig` profiles ready for MDM deployment via Fleet, Jamf Pro, or any MDM that supports custom configuration profiles.

Aimed at Mac admins who need to pre-approve Privacy Preferences (Full Disk Access, Screen Capture, Accessibility, etc.) for managed applications.

## Quick Start

```bash
# Two-step GitOps workflow (recommended)
contour pppc scan -p /Applications -o pppc.toml
contour pppc configure pppc.toml
contour pppc generate pppc.toml -o ./profiles

# One-shot mode (scan + generate in one step)
contour pppc -p /Applications -o pppc.mobileconfig --service fda
```

## Workflow

### GitOps (recommended)

The two-step workflow separates discovery from generation, producing a version-controllable TOML file that can be reviewed, edited, and committed to Git before any profiles are created.

```
1. scan       → pppc.toml        (discover apps, extract code requirements)
2. configure  → pppc.toml        (interactively assign TCC services)
   or batch   → pppc.toml        (non-interactive bulk edits)
3. generate   → *.mobileconfig   (produce MDM-ready profiles)
```

### One-shot

For quick, non-versioned use: scan apps and generate a combined profile in one step, without an intermediate TOML file.

```bash
contour pppc -p /Applications --service fda --service screen-capture -o pppc.mobileconfig
```

---

## pppc.toml

The policy file produced by `scan` and consumed by `generate`. Place it under version control.

```toml
[config]
org = "com.yourorg"

[[apps]]
name = "Google Chrome"
bundle_id = "com.google.Chrome"
code_requirement = 'identifier "com.google.Chrome" and anchor apple generic and ...'
services = ["fda", "screen-capture"]

[[apps]]
name = "Slack"
bundle_id = "com.tinyspeck.slackmacgap"
code_requirement = 'identifier "com.tinyspeck.slackmacgap" and anchor apple generic and ...'
services = ["accessibility", "microphone", "camera"]
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `config.org` | yes | Reverse-domain identifier (e.g., `com.yourorg`). Used in `PayloadIdentifier`. |
| `config.display_name` | no | Optional display name for the profile. |
| `apps[].name` | yes | Human-readable app name. |
| `apps[].bundle_id` | yes | Bundle identifier (e.g., `com.google.Chrome`). |
| `apps[].code_requirement` | yes | Code signing requirement (extracted by `scan`). |
| `apps[].identifier_type` | no | `bundleID` (default) or `path`. |
| `apps[].path` | no | Executable path (used when `identifier_type = "path"`). |
| `apps[].services` | yes | List of TCC services to authorize. Empty `[]` = app is skipped during generation. |

---

## TCC Services

24 services are supported. Each maps to an Apple TCC policy key.

| Service name | Apple TCC key | Authorization |
|-------------|---------------|---------------|
| `fda` | `SystemPolicyAllFiles` | Allow |
| `documents` | `SystemPolicyDocumentsFolder` | Allow |
| `desktop` | `SystemPolicyDesktopFolder` | Allow |
| `downloads` | `SystemPolicyDownloadsFolder` | Allow |
| `network-volumes` | `SystemPolicyNetworkVolumes` | Allow |
| `removable-volumes` | `SystemPolicyRemovableVolumes` | Allow |
| `sysadmin-files` | `SystemPolicySysAdminFiles` | Allow |
| `app-management` | `SystemPolicyAppBundles` | Allow (macOS 13+) |
| `app-data` | `SystemPolicyAppData` | Allow (macOS 14+) |
| `camera` | `Camera` | Deny only |
| `microphone` | `Microphone` | Deny only |
| `screen-capture` | `ScreenCapture` | Allow (standard user settable) |
| `accessibility` | `Accessibility` | Allow |
| `contacts` | `AddressBook` | Allow |
| `calendar` | `Calendar` | Allow |
| `photos` | `Photos` | Allow |
| `reminders` | `Reminders` | Allow |
| `apple-events` | `AppleEvents` | Allow |
| `post-event` | `PostEvent` | Allow |
| `listen-event` | `ListenEvent` | Allow (standard user settable) |
| `speech-recognition` | `SpeechRecognition` | Allow |
| `media-library` | `MediaLibrary` | Allow |
| `file-provider` | `FileProviderPresence` | Allow |
| `bluetooth` | `BluetoothAlways` | Allow (macOS 11+) |

**Authorization types:**
- **Allow** — Profile grants access. Most services.
- **Deny only** — Camera and Microphone cannot be granted via profile; the profile can only deny access. Apple's TCC requires user consent for these.
- **Standard user settable** — ScreenCapture and ListenEvent use `AllowStandardUserToSetSystemService`, letting standard users toggle the setting.

---

## Commands

### `pppc scan`

Discover app bundles and extract code signing requirements into a `pppc.toml`.

```
contour pppc scan [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --path <PATH>` | Directory to scan or single `.app` bundle (repeatable) | `/Applications` |
| `--from-csv <FILE>` | CSV file with app paths (mutually exclusive with `--path`) | none |
| `-o, --output <FILE>` | Output TOML file | `pppc.toml` |
| `--org <ORG>` | Organization identifier | `.contour/config.toml` |
| `-I, --interactive` | Interactive app and service selection | `false` |

```bash
# Scan /Applications
contour pppc scan -o pppc.toml

# Scan specific directories
contour pppc scan -p /Applications -p /usr/local/bin -o pppc.toml

# Scan a single app
contour pppc scan -p /Applications/Slack.app -o pppc.toml

# Scan from a CSV file
contour pppc scan --from-csv apps.csv -o pppc.toml

# Interactive mode: choose apps and services
contour pppc scan -p /Applications -o pppc.toml --interactive
```

The CSV file must have a `path` or `app_path` column header, or paths in the first or second column.

Apps that fail scanning (unsigned, missing Info.plist, empty bundles) are skipped with a grouped summary. Duplicate bundle IDs (common with Adobe CC symlinks) are deduplicated automatically.

### `pppc generate`

Generate `.mobileconfig` profiles from a `pppc.toml`.

```
contour pppc generate <INPUT> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUT>` | Input `pppc.toml` | **required** |
| `-o, --output <PATH>` | Output directory or file path | same dir as input |
| `--combined` | Merge all apps into a single profile | `false` |
| `--fragment` | Generate Fleet GitOps fragment directory | `false` |
| `--dry-run` | Preview profiles without writing | `false` |

```bash
# Generate per-app profiles (one .mobileconfig per app)
contour pppc generate pppc.toml -o ./profiles

# Generate a single combined profile
contour pppc generate pppc.toml --combined -o pppc.mobileconfig

# Preview what would be generated
contour pppc generate pppc.toml --dry-run

# Generate Fleet fragment for splice
contour pppc generate pppc.toml --fragment -o pppc-fragment
```

**Per-app mode** (default): Creates one `.mobileconfig` per app. Filename: `{app-name}-pppc.mobileconfig`. Profile identifier: `{org}.pppc.{bundle-id}`.

**Combined mode** (`--combined`): Merges all TCC entries into a single profile. Profile identifier: `{org}.pppc`.

**Fleet mode** (`--fragment`): Produces a fragment directory with profiles under `lib/macos/configuration-profiles/`, a `fleets/reference-team.yml`, and a `fragment.toml` for merging into a Fleet GitOps repository.

Apps with empty `services = []` are skipped during generation.

### `pppc configure`

Interactively walk through each app in a `pppc.toml` and assign TCC services.

```
contour pppc configure <INPUT> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUT>` | Input `pppc.toml` (modified in-place) | **required** |
| `--skip-configured` | Skip apps that already have services assigned | `false` |

```bash
# Configure all apps
contour pppc configure pppc.toml

# Resume configuration (skip already-configured apps)
contour pppc configure pppc.toml --skip-configured
```

For each app, shows current services and presents a multi-select prompt with all 24 TCC services. Services are annotated with `[deny only]` (Camera, Microphone) and `[standard user settable]` (ScreenCapture, ListenEvent).

Progress is saved after each app — an interrupted session can be resumed with `--skip-configured`.

### `pppc batch`

Non-interactive bulk editing of services in a `pppc.toml`.

```
contour pppc batch <INPUT> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUT>` | Input `pppc.toml` (modified in-place) | **required** |
| `--add-services <SVC,...>` | Add services to apps | none |
| `--remove-services <SVC,...>` | Remove services from apps | none |
| `--set-services <SVC,...>` | Replace all services on apps | none |
| `--apps <NAME,...>` | Filter to specific apps (case-insensitive substring match) | all apps |
| `--dry-run` | Preview changes without writing | `false` |

```bash
# Grant FDA to all apps
contour pppc batch pppc.toml --add-services fda

# Grant screen capture to Chrome and Zoom
contour pppc batch pppc.toml --add-services screen-capture --apps "Chrome,Zoom"

# Remove camera from all apps
contour pppc batch pppc.toml --remove-services camera

# Set exact services for Slack
contour pppc batch pppc.toml --set-services accessibility,microphone --apps Slack

# Preview changes
contour pppc batch pppc.toml --add-services fda --dry-run
```

Exactly one of `--add-services`, `--remove-services`, or `--set-services` must be provided.

### `pppc validate`

Validate a `pppc.toml` for structural issues without generating profiles.

```
contour pppc validate [INPUT] [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<INPUT>` | Input `pppc.toml` | `pppc.toml` |
| `--strict` | Treat warnings as errors | `false` |

```bash
contour pppc validate pppc.toml
contour pppc validate pppc.toml --strict
```

**Checks:**
- TOML parses successfully
- `config.org` is non-empty (error)
- Each app has non-empty `bundle_id` (error)
- Each app has non-empty `code_requirement` (warning)
- Each app has non-empty `name` (warning)
- No duplicate `bundle_id` values (warning)

### `pppc diff`

Semantic diff between two `pppc.toml` files. Compares by `bundle_id`.

```
contour pppc diff <FILE1> <FILE2>
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE1>` | Old policy file | **required** |
| `<FILE2>` | New policy file | **required** |

```bash
contour pppc diff pppc-v1.toml pppc-v2.toml
contour pppc diff pppc-v1.toml pppc-v2.toml --json
```

Shows added apps, removed apps, and modified apps (service changes shown as `+service` / `-service`).

### `pppc init`

Create a blank `pppc.toml`.

```
contour pppc init [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <FILE>` | Output file path | `pppc.toml` |
| `--org <ORG>` | Organization identifier | `.contour/config.toml` |
| `--name <NAME>` | Organization name (sets profile display name) | none |
| `--force` | Overwrite existing file | `false` |

```bash
contour pppc init --org com.acme --name "Acme Corp"
```

### `pppc info`

Display toolkit version, available TCC services, and summary of any `pppc.toml` in the current directory.

```
contour pppc info [--json]
```

---

## One-Shot Mode

When invoked without a subcommand, `contour pppc` runs in one-shot mode: scan + generate in a single step.

```
contour pppc [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --path <PATH>` | Directory or `.app` to scan (repeatable) | `/Applications` |
| `-o, --output <FILE>` | Output `.mobileconfig` path | none |
| `--org <ORG>` | Organization identifier | `.contour/config.toml` |
| `--service <SVC>` | TCC service to grant (repeatable) | `fda` |
| `-I, --interactive` | Interactive app and service selection | `false` |
| `--dry-run` | Preview without writing | `false` |

```bash
# Grant FDA to all apps in /Applications
contour pppc -p /Applications --service fda -o pppc.mobileconfig

# Grant multiple services
contour pppc --service fda --service screen-capture --service accessibility

# Interactive selection
contour pppc -p /Applications --interactive
```

Produces a single combined `.mobileconfig` with all discovered apps.

---

## Common Workflows

### Standard GitOps workflow

```bash
# 1. Scan applications
contour pppc scan -p /Applications -o pppc.toml --org com.acme

# 2. Interactively assign services
contour pppc configure pppc.toml

# 3. Validate before generating
contour pppc validate pppc.toml

# 4. Generate profiles
contour pppc generate pppc.toml -o ./profiles

# 5. Commit pppc.toml to Git
git add pppc.toml
git commit -m "Add PPPC policy"
```

### Fleet GitOps integration

Generate a fragment directory for Fleet splice:

```bash
contour pppc scan -p /Applications -o pppc.toml --org com.acme
contour pppc configure pppc.toml
contour pppc generate pppc.toml --fragment -o pppc-fragment
# Merge the fragment into your Fleet GitOps repo
```

### Jamf Pro deployment

Generate a single combined profile for upload to Jamf Pro:

```bash
contour pppc scan -p /Applications -o pppc.toml --org com.acme
contour pppc batch pppc.toml --add-services fda,accessibility
contour pppc generate pppc.toml --combined -o pppc.mobileconfig
# Upload pppc.mobileconfig to Jamf Pro
```

### CI/CD pipeline

Non-interactive scan and generate for automation:

```bash
contour pppc scan -p /Applications -o pppc.toml --org com.acme
contour pppc batch pppc.toml --set-services fda,screen-capture
contour pppc validate pppc.toml --strict
contour pppc generate pppc.toml -o ./profiles --json
```

### Tracking changes

```bash
# After updating apps or services
cp pppc.toml pppc-old.toml
contour pppc scan -p /Applications -o pppc.toml --org com.acme
contour pppc diff pppc-old.toml pppc.toml
```

### Bulk service management

```bash
# Add FDA to all apps
contour pppc batch pppc.toml --add-services fda

# Add screen capture to specific apps only
contour pppc batch pppc.toml --add-services screen-capture --apps "Chrome,Zoom,Teams"

# Remove a service from all apps
contour pppc batch pppc.toml --remove-services camera
```

---

## Output Structure

### Per-app mode (default)

```
profiles/
  Google-Chrome-pppc.mobileconfig
  Slack-pppc.mobileconfig
  Zoom-pppc.mobileconfig
```

### Combined mode (`--combined`)

```
pppc.mobileconfig    # Single profile with all apps
```

### Fleet fragment mode (`--fragment`)

```
pppc-fragment/
  lib/
    macos/
      configuration-profiles/
        Google-Chrome-pppc.mobileconfig
        Slack-pppc.mobileconfig
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
3. Error (if not resolvable)

Set a project-wide default with:

```bash
mkdir -p .contour
cat > .contour/config.toml << 'EOF'
[organization]
domain = "com.yourorg"
name = "Your Org"
EOF
```
