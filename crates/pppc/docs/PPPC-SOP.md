# contour pppc — Standard Operating Procedures

Step-by-step procedures for generating PPPC (Privacy Preferences Policy
Control) profiles with `contour pppc`.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Supported Services](#supported-services)
4. [SOP 1: Quick Start (Scan, Grant, Generate)](#sop-1-quick-start-scan-grant-generate)
5. [SOP 2: GitOps Workflow (Scan, Edit, Generate)](#sop-2-gitops-workflow-scan-edit-generate)
6. [SOP 3: Interactive Scan](#sop-3-interactive-scan)
7. [SOP 4: Configure Command (Post-Scan Walkthrough)](#sop-4-configure-command-post-scan-walkthrough)
8. [SOP 5: Batch Command (Non-Interactive Edits)](#sop-5-batch-command-non-interactive-edits)
9. [SOP 6: CSV-Based App Selection](#sop-6-csv-based-app-selection)
10. [SOP 7: Path-Based Binaries (Non-.app Executables)](#sop-7-path-based-binaries-non-app-executables)
11. [SOP 8: Two-Machine Workflow (Test Computer to Admin Workstation)](#sop-8-two-machine-workflow-test-computer-to-admin-workstation)
12. [SOP 9: Per-App vs Combined Profile Generation](#sop-9-per-app-vs-combined-profile-generation)
13. [SOP 10: Fleet GitOps Fragments and Recipes](#sop-10-fleet-gitops-fragments-and-recipes)
14. [Notifications and Service Management](#notifications-and-service-management)
15. [Command Reference](#command-reference)
16. [pppc.toml Format Reference](#pppctoml-format-reference)
17. [Troubleshooting](#troubleshooting)

---

## Overview

PPPC profiles let MDM administrators pre-authorize applications for macOS
privacy permissions (TCC), removing user prompts for Full Disk Access,
Screen Recording, Accessibility and more.

### Key Capabilities

- Scans `.app` bundles and signed bare binaries, extracting code requirements automatically
- Path-based identifiers for non-bundled binaries (e.g. Munki, osquery)
- All 24 Apple TCC services
- Per-app profiles (default) or one combined profile
- Interactive (`configure`) and non-interactive (`batch`) service editing
- Fleet GitOps fragment and recipe output

### Workflows

| Workflow | Commands | Use Case |
|----------|----------|----------|
| **Quick start** | `contour pppc scan` + `batch` + `generate` | Grant a service to a set of apps without hand-editing |
| **GitOps** | `contour pppc scan` + edit + `generate` | Version-controlled, reviewed policy |
| **Two-machine** | `scan` on a test computer, `generate` on the admin workstation | Scan a reference fleet, generate centrally |

### Profile Type Generated

| Profile Type | Payload Type | Purpose |
|--------------|--------------|---------|
| **PPPC/TCC** | `com.apple.TCC.configuration-profile-policy` | Privacy permission grants |

Notification and service-management profiles come from `contour notifications`
and `contour btm` — see [Notifications and Service Management](#notifications-and-service-management).

---

## Prerequisites

### Required Tools

- macOS (code requirements are read from the code signature)
- `contour` installed (`contour --version`)
- Signed application bundles (.app) or signed binaries

### Permissions

- Read access to application bundles / binaries
- Write access to the output directory

### Inputs

| Input | Description | Source |
|-------|-------------|--------|
| Application paths | Directories, .app bundles or binary paths | Local filesystem |
| Organization ID | Identifier prefix (e.g. `com.yourcompany`) | Your organization, or `.contour/config.toml` |
| (Optional) CSV file | App names and paths | Manual or exported |

---

## Supported Services

`contour pppc` supports all 24 Apple TCC services. The CLI name is what
`batch` takes and what `pppc.toml` stores:

| CLI / TOML Name | Apple Key | Display Name |
|-----------------|-----------|--------------|
| `fda` | `SystemPolicyAllFiles` | Full Disk Access |
| `documents` | `SystemPolicyDocumentsFolder` | Documents Folder |
| `desktop` | `SystemPolicyDesktopFolder` | Desktop Folder |
| `downloads` | `SystemPolicyDownloadsFolder` | Downloads Folder |
| `network-volumes` | `SystemPolicyNetworkVolumes` | Network Volumes |
| `removable-volumes` | `SystemPolicyRemovableVolumes` | Removable Volumes |
| `sysadmin-files` | `SystemPolicySysAdminFiles` | SysAdmin Files |
| `app-management` | `SystemPolicyAppBundles` | App Management (macOS 13+) |
| `app-data` | `SystemPolicyAppData` | App Data Access (macOS 14+) |
| `camera` | `Camera` | Camera |
| `microphone` | `Microphone` | Microphone |
| `screen-capture` | `ScreenCapture` | Screen Recording |
| `accessibility` | `Accessibility` | Accessibility |
| `contacts` | `AddressBook` | Contacts |
| `calendar` | `Calendar` | Calendar |
| `photos` | `Photos` | Photos |
| `reminders` | `Reminders` | Reminders |
| `apple-events` | `AppleEvents` | Apple Events / Automation |
| `post-event` | `PostEvent` | CoreGraphics Event Posting |
| `listen-event` | `ListenEvent` | CoreGraphics Event Listening |
| `speech-recognition` | `SpeechRecognition` | Speech Recognition |
| `media-library` | `MediaLibrary` | Apple Music / Media Library |
| `file-provider` | `FileProviderPresence` | File Provider |
| `bluetooth` | `BluetoothAlways` | Bluetooth (macOS 11+) |

### TCC Authorization Behavior (macOS 11+)

Profiles use the `Authorization` string key, not the legacy `Allowed`
boolean, per the `com.apple.TCC.configuration-profile-policy` spec. What a
profile can do depends on the service:

| Category | Services | Authorization Value | Notes |
|----------|----------|-------------------|-------|
| **Allowable** | SystemPolicyAllFiles, Accessibility, AddressBook, Calendar, Photos, SystemPolicyDocumentsFolder, SystemPolicyDesktopFolder, SystemPolicyDownloadsFolder, SystemPolicyNetworkVolumes, SystemPolicyRemovableVolumes, SystemPolicySysAdminFiles, SystemPolicyAppBundles, SystemPolicyAppData, AppleEvents, PostEvent, SpeechRecognition, MediaLibrary, FileProviderPresence, BluetoothAlways, Reminders | `Allow` | Profile can grant access |
| **Standard-user-settable** | ScreenCapture, ListenEvent | `AllowStandardUserToSetSystemService` | Profile can't grant access; it lets standard users toggle it |
| **Deny-only** | Camera, Microphone | `Deny` | Profile can only deny access, not grant it |

`generate` picks the right value per service. Camera or Microphone produce a
`Deny` entry; `configure` warns about this when you select them.

### Service Aliases

`batch` also accepts these aliases:

| Alias | Resolves To |
|-------|-------------|
| `full-disk-access` | `fda` |
| `mic` | `microphone` |
| `screen` | `screen-capture` |
| `addressbook` | `contacts` |
| `docs` | `documents` |
| `automation` | `apple-events` |
| `app-bundles` | `app-management` |

---

## SOP 1: Quick Start (Scan, Grant, Generate)

**Use Case**: Grant services to a set of apps without editing the TOML by hand.
There is no single-command mode: `scan` writes `pppc.toml`, `batch` sets
services in it, and `generate` turns it into profiles.

### Grant Full Disk Access to One App

```bash
contour pppc scan --path /Applications/YourApp.app --org com.yourcompany -o yourapp.toml
contour pppc batch yourapp.toml --add-services fda
contour pppc generate yourapp.toml -o ./profiles/
```

### Grant a Service to Every App in a Directory

```bash
contour pppc scan --path /Applications --org com.yourcompany -o pppc.toml
contour pppc batch pppc.toml --add-services fda
contour pppc generate pppc.toml -o ./profiles/
```

### Multiple Services, Selected Apps

```bash
# --apps matches app names, case-insensitive substring, comma-separated
contour pppc batch pppc.toml --add-services screen-capture,accessibility --apps "Zoom,Slack"
```

### Multiple Paths

```bash
# Repeat --path, or give a comma-separated list
contour pppc scan \
  --path /Applications \
  --path ~/Applications \
  --path /opt/tools \
  --org com.yourcompany \
  -o pppc.toml
```

### Dry Run (Preview)

```bash
contour pppc batch pppc.toml --add-services fda --dry-run   # preview the TOML change
contour pppc generate pppc.toml --dry-run                   # preview the profiles
```

### Validate

```bash
contour pppc validate pppc.toml            # the policy file
plutil -lint ./profiles/*.mobileconfig     # the generated profiles
```

---

## SOP 2: GitOps Workflow (Scan, Edit, Generate)

**Use Case**: Version-controlled PPPC management with human review.

### Workflow Overview

```
Step 1: Scan
  contour pppc scan --path /Applications --org com.example -o pppc.toml
  - Extracts bundle IDs and code requirements
           |
           v
Step 2: Edit (Human Review)
  Set services = ["fda", "screen-capture"] per app
  (by hand, `contour pppc configure`, or `contour pppc batch`)
  Commit to version control
           |
           v
Step 3: Generate
  contour pppc generate pppc.toml -o ./profiles/
  - One TCC profile per app (default)
           |
           v
Step 4: Deploy
  Upload profiles to MDM (Fleet, Jamf, Kandji, Mosyle, ...)
```

### Step 1: Scan Applications

```bash
contour pppc scan \
  --path /Applications \
  --org com.yourcompany \
  -o pppc.toml
```

**Output:**
```
ℹ Scanning applications for PPPC policy generation...
  Organization: com.yourcompany
  Paths: /Applications
  Apps found: 67

✓ PPPC policy written to pppc.toml

ℹ Next steps:
  1. Edit pppc.toml to configure services per app
  2. Run: contour pppc generate pppc.toml --output pppc.mobileconfig
```

Apps that can't be read are listed as skipped, with the reason (see
[Troubleshooting](#problem-skipped-apps-emptystub-bundle)).

### Step 2: Edit pppc.toml

```bash
$EDITOR pppc.toml
```

**Example after editing:**
```toml
[config]
org = "com.yourcompany"
display_name = "Company PPPC Profile"

[[apps]]
name = "Google Chrome"
bundle_id = "com.google.Chrome"
code_requirement = 'identifier "com.google.Chrome" and anchor apple generic...'
path = "/Applications/Google Chrome.app"
services = ["fda", "screen-capture"]

[[apps]]
name = "Zoom"
bundle_id = "us.zoom.xos"
code_requirement = 'identifier "us.zoom.xos" and anchor apple generic...'
path = "/Applications/zoom.us.app"
services = ["screen-capture", "accessibility"]
```

Check the edit before generating:

```bash
contour pppc validate pppc.toml
```

### Step 3: Generate Profiles

```bash
contour pppc generate pppc.toml -o ./profiles/
```

**Output:**
```
ℹ Loading PPPC policy from pppc.toml...
  Organization: com.yourcompany
  Apps in policy: 2
  Mode: per-app (individual profiles)
  Apps with TCC services: 2
  Total TCC entries: 4

✓ Generated 2 profile(s)

ℹ Profiles created:
    Google Chrome PPPC: ./profiles/google-chrome-pppc.mobileconfig
    Zoom PPPC: ./profiles/zoom-pppc.mobileconfig

ℹ Next steps:
  1. Validate: plutil -lint <profile>.mobileconfig
  2. Deploy via MDM to grant permissions automatically
```

### Step 4: Validate and Deploy

```bash
for f in ./profiles/*.mobileconfig; do
  plutil -lint "$f"
done

# Deploy via MDM (example: Fleet GitOps)
cp ./profiles/*.mobileconfig /path/to/fleet-repo/profiles/
```

To compare two versions of a policy file before committing:

```bash
contour pppc diff pppc.toml pppc-proposed.toml
```

---

## SOP 3: Interactive Scan

**Use Case**: Pick apps and permissions during the scan.

```bash
contour pppc scan \
  --path /Applications \
  --org com.yourcompany \
  --interactive \
  -o pppc.toml
```

The scan lists the apps it found for selection, then offers to configure
services for each selected app; anything left unset can be edited in the
TOML afterwards.

---

## SOP 4: Configure Command (Post-Scan Walkthrough)

**Use Case**: Interactively set services in an existing pppc.toml — after a
non-interactive scan, or on a TOML transferred from another machine.

```bash
contour pppc configure pppc.toml
```

`configure`:
- Walks the apps one at a time, showing each app's current services
- Pre-selects the services already enabled
- Warns when Camera or Microphone are chosen (the profile will deny, not grant)
- Saves the TOML in place

Resume an interrupted session without revisiting finished apps:

```bash
contour pppc configure pppc.toml --skip-configured
```

---

## SOP 5: Batch Command (Non-Interactive Edits)

**Use Case**: Change services for many apps in one command — scripts, CI, or
large inventories.

```bash
# Add services to every app
contour pppc batch pppc.toml --add-services desktop,documents,downloads

# Add services to selected apps only
contour pppc batch pppc.toml --add-services fda --apps "Slack,Chrome"

# Replace an app's services entirely
contour pppc batch pppc.toml --set-services fda,camera --apps "Zoom"

# Remove a service everywhere, previewing first
contour pppc batch pppc.toml --remove-services downloads --dry-run
```

`--add-services` never duplicates a service already present.
`--set-services` cannot be combined with `--add-services` or
`--remove-services`. Without `--apps`, every app in the file is updated.

---

## SOP 6: CSV-Based App Selection

**Use Case**: Scan a predefined list of apps, including custom locations.

### CSV Format

```csv
name,path
"osquery","/opt/osquery/osquery.app"
"Zoom","/Applications/zoom.us.app"
"Slack","/Applications/Slack.app"
"Custom Tool","/usr/local/apps/CustomTool.app"
```

### Scan from CSV

```bash
contour pppc scan \
  --from-csv apps.csv \
  --org com.yourcompany \
  -o pppc.toml
```

---

## SOP 7: Path-Based Binaries (Non-.app Executables)

**Use Case**: PPPC for signed binaries that are not `.app` bundles (Munki,
osquery, command-line agents).

### Background

Some tools install as standalone binaries:
- `/usr/local/munki/managedsoftwareupdate`
- `/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd`
- `/usr/local/bin/some-agent`

These need `IdentifierType: path` instead of `IdentifierType: bundleID` in
the TCC profile.

### Scan the Binary

`scan` accepts a binary path like any other path, and writes a path-based entry:

```bash
contour pppc scan \
  --path /Applications \
  --path /usr/local/munki/managedsoftwareupdate \
  --org com.yourcompany \
  -o pppc.toml
```

The binary's entry:

```toml
[[apps]]
name = "managedsoftwareupdate"
code_requirement = 'identifier managedsoftwareupdate and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = T4SK8ZXCXG'
identifier_type = "path"
path = "/usr/local/munki/managedsoftwareupdate"
services = []
```

Key differences from app bundle entries:
- `identifier_type = "path"` (defaults to `"bundleID"` when omitted)
- `path` carries the identifier; there is no `bundle_id`
- `code_requirement` may use a bare identifier (no quotes) when the binary isn't a bundle

Then grant services as for any app:

```bash
contour pppc batch pppc.toml --add-services fda --apps managedsoftwareupdate
```

### Entering a Binary by Hand

To write the entry yourself, read the code requirement from the signature:

```bash
codesign -d -r - /usr/local/munki/managedsoftwareupdate
```

### Generated Profile Output

```xml
<dict>
  <key>Identifier</key>
  <string>/usr/local/munki/managedsoftwareupdate</string>
  <key>IdentifierType</key>
  <string>path</string>
  <key>CodeRequirement</key>
  <string>identifier managedsoftwareupdate and anchor apple generic...</string>
  <key>StaticCode</key>
  <false/>
  <key>Authorization</key>
  <string>Allow</string>
</dict>
```

---

## SOP 8: Two-Machine Workflow (Test Computer to Admin Workstation)

**Use Case**: Scan the standard app set on test or reference computers, then
transfer the TOML to a central admin workstation to configure, generate and
deploy.

### Workflow Overview

```
TEST COMPUTER                          ADMIN WORKSTATION
=============                          =================

1. contour pppc scan                   3. Receive pppc-<host>.toml
   - Scans /Applications               4. contour pppc configure (or batch)
   - Adds path-based binaries          5. contour pppc generate
                                          -o ./profiles/
2. Transfer pppc-<host>.toml           6. Upload profiles to MDM
```

Both machines run `contour`; install the same pkg on the test computer.

### Step 1: Scan on the Test Computer

```bash
contour pppc scan \
  --path /Applications \
  --path /Applications/Utilities \
  --path /usr/local/munki/managedsoftwareupdate \
  --org com.yourcompany \
  -o "pppc-$(hostname -s).toml"
```

Add `--interactive` to pick apps while scanning. Naming the file after the
host keeps scans from several machines apart.

### Step 2: Transfer to the Admin Workstation

```bash
# SCP
scp "pppc-$(hostname -s).toml" admin@workstation:/path/to/pppc/

# rsync
rsync -av pppc-*.toml admin@workstation:/path/to/pppc/

# USB / shared drive
cp pppc-*.toml /Volumes/SharedDrive/pppc-scans/
```

### Step 3: Configure Services on the Admin Workstation

```bash
# Interactive walkthrough
contour pppc configure pppc-macbook-pro-01.toml

# Non-interactive
contour pppc batch pppc-macbook-pro-01.toml --add-services fda --apps "managedsoftwareupdate"

# Or edit by hand
$EDITOR pppc-macbook-pro-01.toml
```

### Step 4: Generate Profiles

```bash
contour pppc generate pppc-macbook-pro-01.toml -o ./profiles/
```

### Step 5: Validate and Deploy

```bash
for f in ./profiles/*.mobileconfig; do
  plutil -lint "$f"
done

cp ./profiles/*.mobileconfig /path/to/mdm-repo/profiles/
```

### Multi-Machine Scanning

For fleets with different app sets per machine type:

```bash
# On each test machine:
contour pppc scan --path /Applications --org com.yourcompany -o "pppc-$(hostname -s).toml"

# On the admin workstation, after transfer:
contour pppc configure pppc-engineering-mac.toml
contour pppc generate pppc-engineering-mac.toml -o ./profiles/engineering/

contour pppc configure pppc-design-mac.toml
contour pppc generate pppc-design-mac.toml -o ./profiles/design/
```

---

## SOP 9: Per-App vs Combined Profile Generation

**Use Case**: One profile per app (default) or a single combined profile.

### Per-App Mode (Default)

```bash
contour pppc generate pppc.toml -o ./profiles/
```

One TCC profile per app, each with its own identifiers:

```
./profiles/
  google-chrome-pppc.mobileconfig      # com.example.pppc.com_google_Chrome
  zoom-pppc.mobileconfig               # com.example.pppc.us_zoom_xos
```

Each profile has a unique `PayloadIdentifier` and `PayloadUUID`, so they can
be deployed and updated independently.

### Combined Mode

```bash
contour pppc generate pppc.toml --combined -o ./profiles/
```

All TCC entries in one profile:

```
./profiles/
  pppc-pppc.mobileconfig               # com.example.pppc (all apps)
```

### When to Use Each Mode

| Mode | Advantages | Use Case |
|------|-----------|----------|
| **Per-app** (default) | Update one app without touching others; clear ownership | Large fleets, frequent app changes |
| **Combined** | Fewer profiles to manage in MDM | Small deployments, simple setups |

### Dry Run Preview

```bash
contour pppc generate pppc.toml --dry-run              # per-app
contour pppc generate pppc.toml --combined --dry-run   # combined
```

The dry run lists each profile and a **TCC Service Breakdown** of how many
apps use each service:

```
Dry Run - Profile Preview
==================================================

TCC/PPPC (3 individual profiles):
  • Google Chrome (com.google.Chrome)
    - Full Disk Access
    - Screen Recording
    → google-chrome-pppc.mobileconfig
  • Zoom (us.zoom.xos)
    - Screen Recording
    → zoom-pppc.mobileconfig
  • managedsoftwareupdate (/usr/local/munki/managedsoftwareupdate)
    - Full Disk Access
    → managedsoftwareupdate-pppc.mobileconfig

TCC Service Breakdown:
        Full Disk Access     2  ██████████████████████████████
        Screen Recording     2  ██████████████████████████████

--------------------------------------------------
Total profiles to generate: 3
```

The most-used service gets the longest bar (30 characters); the others scale
to it.

If two entries share a `bundle_id` (for example from scanning Adobe CC
framework symlinks), `generate` warns that they will produce colliding
profiles:

```
! 6 duplicate bundle ID(s) detected (will produce colliding profiles):
    · com.adobe.Photoshop (2x)
    · com.adobe.Illustrator (2x)
```

Remove the duplicate entries from pppc.toml, or re-scan with narrower
`--path` values. `contour pppc validate` reports duplicates too.

---

## SOP 10: Fleet GitOps Fragments and Recipes

`generate` can write other shapes than plain `.mobileconfig` files:

```bash
# A Fleet GitOps fragment: a directory with a fragment.toml manifest and lib/
# structure, for merging into a Fleet GitOps repository
contour pppc generate pppc.toml --fragment -o ./pppc-fragment/

# A single combined recipe TOML for a `contour profile library`
contour pppc generate pppc.toml --format recipe -o pppc-recipe.toml
```

`--format` takes `mobileconfig` (the default) or `recipe`.

---

## Notifications and Service Management

`contour pppc` writes TCC profiles only. The other two per-app profiles have
their own tools:

| Profile | Payload Type | Tool |
|---------|--------------|------|
| Notifications | `com.apple.notificationsettings` | `contour notifications` (scan, generate) |
| Managed login items | `com.apple.servicemanagement` | `contour btm` (scan, generate) |

```bash
contour notifications scan --path /Applications --org com.yourcompany -o notifications.toml
contour btm generate btm.toml -o ./profiles/
```

pppc.toml keys named `notifications`, `service_management` or `team_id` are
not part of its format: `validate`, `generate` and every other command refuse
the file, naming each such key and the tool that makes that profile.

---

## Command Reference

| Command | Description |
|---------|-------------|
| `contour pppc scan` | Scan applications and create a policy file (pppc.toml) |
| `contour pppc generate` | Generate mobileconfig profiles from a policy file |
| `contour pppc configure` | Interactively configure services in an existing policy file |
| `contour pppc batch` | Batch-update TCC services for apps |
| `contour pppc validate` | Validate a pppc.toml policy file |
| `contour pppc diff` | Compare two pppc.toml policy files |
| `contour pppc init` | Initialize a new pppc.toml policy file |
| `contour pppc info` | Show toolkit info, available services, and local config summary |

`contour <command> --help` is authoritative for every option; the summaries
below cover the common ones.

### scan

```
contour pppc scan [OPTIONS]

  -p, --path <PATH>           Directories, app bundles or binaries to scan
                              (repeat, or comma-separate) [default: /Applications]
      --from-csv <FROM_CSV>   CSV file with app names/paths (columns: name, path)
  -o, --output <OUTPUT>       Output TOML file [default: pppc.toml]
      --org <ORG>             Organization identifier
                              (reads .contour/config.toml if not given)
  -I, --interactive           Select apps and permissions interactively
```

### generate

```
contour pppc generate [OPTIONS] <INPUT>

  <INPUT>                     Input policy file (pppc.toml)
  -o, --output <OUTPUT>       Output .mobileconfig file or directory
      --combined              One profile for all TCC entries
      --dry-run               Preview without writing
      --fragment              Write a Fleet GitOps fragment directory
      --format <FORMAT>       mobileconfig (default) or recipe
```

### configure

```
contour pppc configure [OPTIONS] <INPUT>

  <INPUT>                     Input policy file (pppc.toml)
      --skip-configured       Skip apps that already have services
```

### batch

```
contour pppc batch [OPTIONS] <INPUT>

  <INPUT>                           Input policy file (pppc.toml)
      --add-services <SERVICES>     Append services (no duplicates)
      --remove-services <SERVICES>  Remove services
      --set-services <SERVICES>     Replace services entirely
      --apps <APPS>                 Apps by name (case-insensitive substring); omit = all
      --dry-run                     Preview without writing
```

### validate, diff, init

```
contour pppc validate [INPUT] [--strict]       # [default: pppc.toml]; --strict fails on warnings
contour pppc diff <FILE1> <FILE2>
contour pppc init [-o pppc.toml] [--org <ORG>] [--name <NAME>] [--force]
```

### Global Options

```
  -v, --verbose               Verbose logging
      --json                  JSON output (for CI/CD)
```

---

## pppc.toml Format Reference

### Complete Schema

```toml
[config]
org = "com.yourcompany"           # Required: organization identifier
display_name = "My PPPC Profile"  # Optional: profile display name

[[apps]]
name = "App Name"                 # Required: display name
bundle_id = "com.example.app"     # bundleID entries: the bundle identifier
code_requirement = '...'          # Required: code requirement string
identifier_type = "path"          # Optional: "bundleID" (default) or "path"
path = "/Applications/App.app"    # Required for "path" entries; a reference otherwise
services = ["fda", "camera"]      # Optional: TCC services to grant
```

### Field Details

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `config.org` | string | Yes | Organization identifier (e.g. `com.yourcompany`) |
| `config.display_name` | string | No | Human-readable profile name |
| `apps[].name` | string | Yes | Application display name |
| `apps[].bundle_id` | string | bundleID entries | Reverse-DNS bundle identifier; absent for path entries |
| `apps[].code_requirement` | string | Yes | Output of `codesign -d -r -` |
| `apps[].identifier_type` | string | No | `"bundleID"` (default) or `"path"` |
| `apps[].path` | string | path entries | Absolute path; the identifier for path entries |
| `apps[].services` | array | No | TCC services to grant |

A path entry that still carries the path in `bundle_id` (the older
hand-written form) is read as before.

### Example: App Bundle Entry

```toml
[[apps]]
name = "Zoom"
bundle_id = "us.zoom.xos"
code_requirement = 'identifier "us.zoom.xos" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "BJ4HAAB9B3"'
path = "/Applications/zoom.us.app"
services = ["screen-capture", "accessibility"]
```

### Example: Path-Based Binary Entry

```toml
[[apps]]
name = "managedsoftwareupdate"
code_requirement = 'identifier managedsoftwareupdate and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = T4SK8ZXCXG'
identifier_type = "path"
path = "/usr/local/munki/managedsoftwareupdate"
services = ["fda"]
```

---

## Troubleshooting

### Problem: "No applications found"

```
No applications found to scan
```

**Causes:**
1. Path doesn't exist
2. Path contains no .app bundles or signed binaries
3. No read permission

**Solutions:**
```bash
ls -la /Applications
contour pppc scan --path /Applications --org com.test
```

### Problem: Skipped apps (Empty/stub bundle)

```
! Skipped 4 app(s):
  > Empty/stub bundle (no Contents directory) (4)
```

**Cause:** Some apps (especially Microsoft 365 via the Mac App Store)
install as stub bundles that download their content on first launch.

**Solution:** Launch the app once so it downloads its full bundle, then re-scan.

### Problem: Permissions not applied after MDM deployment

**Causes:**
1. Profile not installed (check System Settings > Profiles)
2. Code requirement mismatch (app updated, new signature)
3. Bundle ID mismatch
4. The service is deny-only (Camera, Microphone) or standard-user-settable
   (Screen Recording) — see [TCC Authorization Behavior](#tcc-authorization-behavior-macos-11)

**Solutions:**
```bash
# Verify installed profiles
sudo profiles list

# Check the app's current code requirement
codesign -d -r - /Applications/App.app

# Re-scan to pick up the updated code requirement
contour pppc scan --path /Applications/App.app --org com.test -o updated.toml
```

### Debug: View a Generated Profile

```bash
# Pretty-print
plutil -p profile.mobileconfig

# Validate XML structure
plutil -lint profile.mobileconfig

# Extract the Services dictionary
plutil -extract PayloadContent.0.Services xml1 -o - profile.mobileconfig
```

---

## Appendix: Profile Payload

### PPPC/TCC Profile

**Payload Type:** `com.apple.TCC.configuration-profile-policy`

```xml
<dict>
  <key>Services</key>
  <dict>
    <key>SystemPolicyAllFiles</key>
    <array>
      <dict>
        <key>Identifier</key>
        <string>com.example.app</string>
        <key>IdentifierType</key>
        <string>bundleID</string>
        <key>CodeRequirement</key>
        <string>identifier "com.example.app" and anchor apple generic...</string>
        <key>StaticCode</key>
        <false/>
        <key>Authorization</key>
        <string>Allow</string>
      </dict>
    </array>
  </dict>
</dict>
```

### Path-Based TCC Entry

```xml
<dict>
  <key>Identifier</key>
  <string>/usr/local/munki/managedsoftwareupdate</string>
  <key>IdentifierType</key>
  <string>path</string>
  <key>CodeRequirement</key>
  <string>identifier managedsoftwareupdate and anchor apple generic...</string>
  <key>StaticCode</key>
  <false/>
  <key>Authorization</key>
  <string>Allow</string>
</dict>
```
