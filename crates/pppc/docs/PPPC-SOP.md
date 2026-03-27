# Mould PPPC Standard Operating Procedures

This document provides step-by-step procedures for generating PPPC (Privacy Preferences Policy Control) profiles using mould.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Supported Services](#supported-services)
4. [SOP 1: One-Shot PPPC Generation](#sop-1-one-shot-pppc-generation)
5. [SOP 2: GitOps Workflow (Scan, Edit, Generate)](#sop-2-gitops-workflow-scan-edit-generate)
6. [SOP 3: Interactive PPPC Configuration](#sop-3-interactive-pppc-configuration)
7. [SOP 4: Configure Command (Post-Scan Walkthrough)](#sop-4-configure-command-post-scan-walkthrough)
8. [SOP 5: CSV-Based App Selection](#sop-5-csv-based-app-selection)
9. [SOP 6: Path-Based Binaries (Non-.app Executables)](#sop-6-path-based-binaries-non-app-executables)
10. [SOP 7: Two-Machine Workflow (Test Computer to Admin Workstation)](#sop-7-two-machine-workflow-test-computer-to-admin-workstation)
11. [SOP 8: Generating Notification Profiles](#sop-8-generating-notification-profiles)
12. [SOP 9: Generating Service Management Profiles](#sop-9-generating-service-management-profiles)
13. [SOP 10: Per-App vs Combined Profile Generation](#sop-10-per-app-vs-combined-profile-generation)
14. [Configuration Reference](#configuration-reference)
15. [pppc.toml Format Reference](#pppctoml-format-reference)
16. [Troubleshooting](#troubleshooting)

---

## Overview

PPPC (Privacy Preferences Policy Control) profiles allow MDM administrators to pre-authorize applications for macOS privacy permissions (TCC). This eliminates user prompts for permissions like Full Disk Access, Camera, Microphone, Screen Recording, and more.

### Key Capabilities

- Scans `.app` bundles and extracts code requirements automatically
- Supports path-based identifiers for non-bundled binaries (e.g., Munki, osquery)
- All 24 Apple TCC services supported
- Per-app individual profiles (default) or combined profiles
- Notification and service management profiles
- Interactive walkthrough for configuring services
- Two-machine workflow: scan on test computers, generate on admin workstation

### Workflows

| Workflow | Commands | Use Case |
|----------|----------|----------|
| **One-Shot** | `mould --org ...` | Quick generation, simple deployments |
| **GitOps** | `mould scan` + `mould generate` | Version-controlled, auditable, team workflows |
| **Two-Machine** | `mould-scan.sh` + `mould generate` | Scan test fleet, generate profiles centrally |

### Profile Types Generated

| Profile Type | Payload Type | Purpose |
|--------------|--------------|---------|
| **PPPC/TCC** | `com.apple.TCC.configuration-profile-policy` | Privacy permission grants |
| **Notifications** | `com.apple.notificationsettings` | Notification settings |
| **Service Management** | `com.apple.servicemanagement` | Managed login items |

---

## Prerequisites

### Required Tools

- macOS (for code requirement extraction via `codesign`)
- `mould` binary (part of the Contour CLI toolkit)
- Signed application bundles (.app) or signed binaries

### Permissions

- Read access to application bundles / binaries
- Write access to output directory

### Inputs Required

| Input | Description | Source |
|-------|-------------|--------|
| Application paths | Directory, .app bundles, or binary paths | Local filesystem |
| Organization ID | Identifier prefix (e.g., `com.yourcompany`) | Your organization |
| (Optional) CSV file | App names and paths | Manual or exported |

---

## Supported Services

Mould supports all 24 Apple TCC services:

| CLI Name | TOML Name | Apple Key | Display Name |
|----------|-----------|-----------|--------------|
| `fda` | `fda` | `SystemPolicyAllFiles` | Full Disk Access |
| `documents` | `documents` | `SystemPolicyDocumentsFolder` | Documents Folder |
| `desktop` | `desktop` | `SystemPolicyDesktopFolder` | Desktop Folder |
| `downloads` | `downloads` | `SystemPolicyDownloadsFolder` | Downloads Folder |
| `network-volumes` | `network-volumes` | `SystemPolicyNetworkVolumes` | Network Volumes |
| `removable-volumes` | `removable-volumes` | `SystemPolicyRemovableVolumes` | Removable Volumes |
| `sysadmin-files` | `sysadmin-files` | `SystemPolicySysAdminFiles` | SysAdmin Files |
| `app-management` | `app-management` | `SystemPolicyAppBundles` | App Management (macOS 13+) |
| `app-data` | `app-data` | `SystemPolicyAppData` | App Data Access (macOS 14+) |
| `camera` | `camera` | `Camera` | Camera |
| `microphone` | `microphone` | `Microphone` | Microphone |
| `screen-capture` | `screen-capture` | `ScreenCapture` | Screen Recording |
| `accessibility` | `accessibility` | `Accessibility` | Accessibility |
| `contacts` | `contacts` | `AddressBook` | Contacts |
| `calendar` | `calendar` | `Calendar` | Calendar |
| `photos` | `photos` | `Photos` | Photos |
| `reminders` | `reminders` | `Reminders` | Reminders |
| `apple-events` | `apple-events` | `AppleEvents` | Apple Events / Automation |
| `post-event` | `post-event` | `PostEvent` | CoreGraphics Event Posting |
| `listen-event` | `listen-event` | `ListenEvent` | CoreGraphics Event Listening |
| `speech-recognition` | `speech-recognition` | `SpeechRecognition` | Speech Recognition |
| `media-library` | `media-library` | `MediaLibrary` | Apple Music / Media Library |
| `file-provider` | `file-provider` | `FileProviderPresence` | File Provider |
| `bluetooth` | `bluetooth` | `BluetoothAlways` | Bluetooth (macOS 11+) |

### TCC Authorization Behavior (macOS 11+)

Mould uses the modern `Authorization` string key instead of the legacy `Allowed` boolean, per the `com.apple.TCC.configuration-profile-policy` Apple spec. Not all services can be granted via profile — the behavior depends on the service category:

| Category | Services | Authorization Value | Notes |
|----------|----------|-------------------|-------|
| **Allowable** | SystemPolicyAllFiles, Accessibility, AddressBook, Calendar, Photos, SystemPolicyDocumentsFolder, SystemPolicyDesktopFolder, SystemPolicyDownloadsFolder, SystemPolicyNetworkVolumes, SystemPolicyRemovableVolumes, SystemPolicySysAdminFiles, SystemPolicyAppBundles, SystemPolicyAppData, AppleEvents, PostEvent, SpeechRecognition, MediaLibrary, FileProviderPresence, BluetoothAlways, Reminders | `Allow` | Profile can grant access |
| **Standard-user-settable** | ScreenCapture, ListenEvent | `AllowStandardUserToSetSystemService` | Profile can't directly grant access; it can allow standard users to toggle |
| **Deny-only** | Camera, Microphone | `Deny` | Profile can only deny access, not grant it |

When generating profiles, mould automatically selects the correct authorization value for each service. If Camera or Microphone are included, a warning is shown during configuration because the resulting profile will deny (not grant) access.

### Service Aliases (CLI only)

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

## SOP 1: One-Shot PPPC Generation

**Use Case**: Quick PPPC profile generation without intermediate files.

### Basic Usage

```bash
# Grant Full Disk Access to a single app
mould \
  --org com.yourcompany \
  --service fda \
  --path /Applications/YourApp.app \
  --output yourapp-pppc.mobileconfig
```

### Scanning a Directory

```bash
# Scan /Applications and grant FDA to all signed apps
mould \
  --org com.yourcompany \
  --service fda \
  --path /Applications \
  --output all-apps-fda.mobileconfig
```

### Multiple Services

```bash
# Grant camera and microphone to Zoom
mould \
  --org com.yourcompany \
  --service camera \
  --service microphone \
  --path "/Applications/zoom.us.app" \
  --output zoom-pppc.mobileconfig
```

### Multiple Paths

```bash
# Scan multiple directories
mould \
  --org com.yourcompany \
  --service fda \
  --path /Applications \
  --path ~/Applications \
  --path /opt/tools \
  --output company-pppc.mobileconfig
```

### Dry Run (Preview)

```bash
# Preview what would be generated without writing
mould \
  --org com.yourcompany \
  --service fda \
  --path /Applications \
  --dry-run
```

### Validate Output

```bash
# Validate the generated profile
plutil -lint yourapp-pppc.mobileconfig

# View profile contents
plutil -p yourapp-pppc.mobileconfig
```

---

## SOP 2: GitOps Workflow (Scan, Edit, Generate)

**Use Case**: Version-controlled PPPC management with human review.

### Workflow Overview

```
Step 1: Scan
  mould scan --path /Applications --org com.example --output pppc.toml
  - Extracts bundle IDs, code requirements, Team IDs
           |
           v
Step 2: Edit (Human Review)
  Edit pppc.toml:
  - services = ["fda", "camera"]
  - notifications = true
  - service_management = true
  Commit to version control
           |
           v
Step 3: Generate
  mould generate pppc.toml --output ./profiles/
  - Per-app TCC profiles (default)
  - Per-app notification profiles
  - Per-app service management profiles
           |
           v
Step 4: Deploy
  Upload profiles to MDM (Jamf, Kandji, Mosyle, Fleet, etc.)
```

### Step 1: Scan Applications

```bash
mould scan \
  --path /Applications \
  --org com.yourcompany \
  --output pppc.toml
```

**Output:**
```
Scanning applications for PPPC policy generation...
  Organization: com.yourcompany
  Paths: /Applications
  Apps found: 67

! Skipped 4 app(s):
  > Empty/stub bundle (no Contents directory) (4)
    . Excel
    . Microsoft PowerPoint
    . Microsoft Teams
    . Slack

✓ PPPC policy written to pppc.toml

Next steps:
  1. Edit pppc.toml to configure services per app
  2. Run: mould generate pppc.toml --output pppc.mobileconfig
```

### Step 2: Edit pppc.toml

Open the file and configure services for each app:

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
notifications = false
service_management = false
team_id = "EQHXZ8M8AV"

[[apps]]
name = "Zoom"
bundle_id = "us.zoom.xos"
code_requirement = 'identifier "us.zoom.xos" and anchor apple generic...'
path = "/Applications/zoom.us.app"
services = ["camera", "microphone", "screen-capture"]
notifications = true
service_management = true
team_id = "BJ4HAAB9B3"
```

### Step 3: Generate Profiles

```bash
mould generate pppc.toml --output ./profiles/
```

**Output:**
```
Loading PPPC policy from pppc.toml...
  Organization: com.yourcompany
  Apps in policy: 2
  Mode: per-app (individual profiles)
  Apps with TCC services: 2
  Total TCC entries: 5
  Apps with notifications: 1
  Apps with service management: 1

✓ Generated 4 profile(s)

Profiles created:
    Google Chrome PPPC: ./profiles/google-chrome-pppc.mobileconfig
    Zoom PPPC: ./profiles/zoom-pppc.mobileconfig
    Zoom Notifications: ./profiles/zoom-notifications.mobileconfig
    Zoom Service Management: ./profiles/zoom-service-management.mobileconfig

Next steps:
  1. Validate: plutil -lint <profile>.mobileconfig
  2. Deploy via MDM to grant permissions automatically
```

### Step 4: Validate and Deploy

```bash
# Validate all generated profiles
for f in ./profiles/*.mobileconfig; do
  echo "Validating: $f"
  plutil -lint "$f"
done

# Deploy via MDM (example: Fleet GitOps)
cp ./profiles/*.mobileconfig /path/to/fleet-repo/profiles/
```

---

## SOP 3: Interactive PPPC Configuration

**Use Case**: Guided selection of apps and permissions during scan.

### Interactive Scan

```bash
mould scan \
  --path /Applications \
  --org com.yourcompany \
  --interactive \
  --output pppc.toml
```

**Interactive Flow:**

```
PPPC Scan - Application Selection
==================================================

Select which applications to include in your PPPC policy.
You can configure services now or edit the TOML file later.

? Select applications to include:
  [ ] 1Password for Safari (com.1password.safari)
  [x] Google Chrome (com.google.Chrome)
  [x] Slack (com.tinyspeck.slackmacgap)
  [x] zoom.us (us.zoom.xos)
  [ ] Visual Studio Code (com.microsoft.VSCode)
  ...

[Space to select, Enter to confirm]

? Configure services for each app now? (Y/n)

Configuring: Google Chrome
  Bundle ID: com.google.Chrome
? Select permissions for Google Chrome:
  [x] Full Disk Access
  [ ] Documents Folder
  [ ] Desktop Folder
  [ ] Downloads Folder
  ...
  [ ] Camera
  [ ] Microphone
  [x] Screen Recording
  [ ] Accessibility

  ✓ Selected 2 permission(s)

? Enable notifications profile for Google Chrome? No
? Enable service management (background tasks) for Google Chrome? No

Configuring: Zoom
  ...
```

### Interactive One-Shot

```bash
mould \
  --org com.yourcompany \
  --path /Applications \
  --interactive \
  --output company-pppc.mobileconfig
```

---

## SOP 4: Configure Command (Post-Scan Walkthrough)

**Use Case**: Interactively configure services in an existing pppc.toml after scanning.

This is useful when you scan without `--interactive` and want to toggle services later, or when editing a TOML transferred from another machine.

### Usage

```bash
mould configure pppc.toml
```

**Interactive Flow:**

```
Loading PPPC policy from pppc.toml...
Apps: 63 | Org: com.example

App 1/63: Google Chrome
  Bundle ID: com.google.Chrome
  Services: (none)
  Notifications: false
  Service Management: false

? Configure Google Chrome? (y/N) y

? Select services for Google Chrome:
  [x] Full Disk Access
  [ ] Documents Folder
  ...
  [ ] Screen Recording

? Enable notifications for Google Chrome? No
? Enable service management for Google Chrome? No

App 2/63: Slack
  Bundle ID: com.tinyspeck.slackmacgap
  Services: (none)
  ...

? Configure Slack? (y/N) n

...

✓ Configuration saved to pppc.toml
```

The configure command:
- Shows current state for each app (services, notifications, service_management)
- Defaults to "No" for the "Configure?" prompt — press Enter to skip unchanged apps
- Pre-selects currently enabled services in the multi-select
- Saves the updated TOML in place

---

## SOP 5: CSV-Based App Selection

**Use Case**: Scan specific apps from a predefined list, including custom paths.

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
mould scan \
  --from-csv apps.csv \
  --org com.yourcompany \
  --output pppc.toml
```

---

## SOP 6: Path-Based Binaries (Non-.app Executables)

**Use Case**: Generate PPPC profiles for binaries that are not `.app` bundles (e.g., Munki, osquery, command-line daemons).

### Background

Some tools install as standalone binaries rather than `.app` bundles. Examples:
- `/usr/local/munki/managedsoftwareupdate`
- `/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd`
- `/usr/local/bin/some-agent`

These require `IdentifierType: path` instead of `IdentifierType: bundleID` in the TCC profile.

### Manual TOML Entry

Add a path-based entry directly to pppc.toml:

```toml
[[apps]]
name = "managedsoftwareupdate"
bundle_id = "/usr/local/munki/managedsoftwareupdate"
code_requirement = 'identifier managedsoftwareupdate and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = T4SK8ZXCXG'
identifier_type = "path"
services = ["fda"]
notifications = false
service_management = false
team_id = "T4SK8ZXCXG"
```

Key differences from app bundle entries:
- `bundle_id` contains the full filesystem path, not a reverse-DNS identifier
- `identifier_type = "path"` must be set (defaults to `"bundleID"` if omitted)
- `code_requirement` uses a bare identifier (no quotes) when the binary isn't a bundle

### Extracting Code Requirements from Binaries

```bash
# Get code requirement
codesign -d -r - /usr/local/munki/managedsoftwareupdate

# Get Team ID
codesign -dv /usr/local/munki/managedsoftwareupdate 2>&1 | grep TeamIdentifier
```

### Generated Profile Output

The resulting mobileconfig uses `IdentifierType: path`:

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

### Using mould-scan.sh for Automatic Binary Scanning

The `mould-scan.sh` script (see [SOP 7](#sop-7-two-machine-workflow-test-computer-to-admin-workstation)) automates binary scanning with the `--binaries` flag.

---

## SOP 7: Two-Machine Workflow (Test Computer to Admin Workstation)

**Use Case**: Scan applications on test/reference computers, then transfer the TOML inventory to a central admin workstation to generate and deploy profiles.

This is the recommended workflow for fleet management where you:
1. Have one or more reference machines with the standard app set installed
2. Want to centrally manage profile generation and MDM deployment

### Workflow Overview

```
TEST COMPUTER                          ADMIN WORKSTATION
=============                          =================

1. Run mould-scan.sh                   3. Receive pppc.toml
   - Scans /Applications               4. mould configure pppc.toml
   - Adds path-based binaries              (interactive service selection)
   - Records machine metadata           5. mould generate pppc.toml
                                            --output ./profiles/
2. Transfer ./mould-export/            6. Upload profiles to MDM
   to admin workstation
```

### Script Location

```
scripts/mould-scan.sh
```

### Step 1: Run the Scan Script on a Test Computer

#### Basic Scan

```bash
./scripts/mould-scan.sh --org com.yourcompany
```

This scans `/Applications`, writes to `./mould-export/pppc.toml`.

#### Scan with Path-Based Binaries

```bash
./scripts/mould-scan.sh \
  --org com.yourcompany \
  --binaries "/usr/local/munki/managedsoftwareupdate"
```

The script:
- Runs `mould scan` for `.app` bundles in `/Applications`
- Extracts code requirements from each specified binary via `codesign`
- Appends path-based entries with `identifier_type = "path"` to the TOML

#### Scan Multiple Directories

```bash
./scripts/mould-scan.sh \
  --org com.yourcompany \
  --scan-paths "/Applications,/Applications/Utilities,/opt/tools" \
  --binaries "/usr/local/munki/managedsoftwareupdate,/usr/local/bin/osqueryd"
```

#### Include Hostname in Filename

Useful when scanning multiple machines:

```bash
./scripts/mould-scan.sh \
  --org com.yourcompany \
  --hostname
```

Output: `./mould-export/pppc-macbook-pro-01.toml`

#### Interactive Mode

```bash
./scripts/mould-scan.sh \
  --org com.yourcompany \
  --interactive \
  --hostname
```

### Script Options Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--org <id>` | Organization identifier (required) | - |
| `--output-dir <dir>` | Output directory | `./mould-export` |
| `--scan-paths <paths>` | Comma-separated directories to scan | `/Applications` |
| `--binaries <paths>` | Comma-separated non-bundled binary paths | - |
| `--interactive` | Enable interactive app/service selection | off |
| `--hostname` | Include hostname in output filename | off |

### Output File

The generated TOML includes machine metadata as comments:

```toml
# PPPC Policy Definitions
# Generated by: mould-scan.sh
# Hostname: macbook-pro-01
# Serial: C02X12345
# macOS: 15.2
# Scan date: 2025-01-15T10:30:00Z
#
# Transfer this file to your admin workstation and run:
#   mould configure pppc-macbook-pro-01.toml
#   mould generate pppc-macbook-pro-01.toml --output ./profiles/

[config]
org = "com.yourcompany"

[[apps]]
name = "Google Chrome"
bundle_id = "com.google.Chrome"
code_requirement = 'identifier "com.google.Chrome" and anchor apple generic...'
path = "/Applications/Google Chrome.app"
services = []
notifications = false
service_management = false
team_id = "EQHXZ8M8AV"

[[apps]]
name = "managedsoftwareupdate"
bundle_id = "/usr/local/munki/managedsoftwareupdate"
code_requirement = 'identifier managedsoftwareupdate and anchor apple generic...'
identifier_type = "path"
services = []
notifications = false
service_management = false
team_id = "T4SK8ZXCXG"
```

### Step 2: Transfer to Admin Workstation

```bash
# SCP
scp -r ./mould-export/ admin@workstation:/path/to/profiles/

# rsync
rsync -av ./mould-export/ admin@workstation:/path/to/profiles/

# USB / Shared drive
cp -r ./mould-export/ /Volumes/SharedDrive/pppc-scans/
```

### Step 3: Configure Services on Admin Workstation

```bash
# Interactive walkthrough
mould configure pppc-macbook-pro-01.toml

# Or edit manually
$EDITOR pppc-macbook-pro-01.toml
```

### Step 4: Generate Profiles

```bash
mould generate pppc-macbook-pro-01.toml --output ./profiles/
```

### Step 5: Validate and Deploy

```bash
# Validate
for f in ./profiles/*.mobileconfig; do
  plutil -lint "$f"
done

# Deploy to MDM
cp ./profiles/*.mobileconfig /path/to/mdm-repo/profiles/
```

### Multi-Machine Scanning

For fleets with different app sets on different machine types:

```bash
# On each test machine:
./scripts/mould-scan.sh --org com.yourcompany --hostname

# Produces:
#   ./mould-export/pppc-engineering-mac.toml
#   ./mould-export/pppc-design-mac.toml
#   ./mould-export/pppc-exec-mac.toml

# On admin workstation, after transfer:
mould configure pppc-engineering-mac.toml
mould generate pppc-engineering-mac.toml --output ./profiles/engineering/

mould configure pppc-design-mac.toml
mould generate pppc-design-mac.toml --output ./profiles/design/
```

---

## SOP 8: Generating Notification Profiles

**Use Case**: Pre-configure notification settings for applications.

### Enable in pppc.toml

```toml
[[apps]]
name = "Slack"
bundle_id = "com.tinyspeck.slackmacgap"
code_requirement = '...'
services = []
notifications = true
service_management = false
team_id = "BQR82RBBHL"
```

### Generated Profile Settings

| Setting | Value | Description |
|---------|-------|-------------|
| `NotificationsEnabled` | `true` | Enables notifications |
| `AlertType` | `1` | Temporary Banner style |
| `BadgesEnabled` | `true` | Shows badge counts |
| `CriticalAlertEnabled` | `true` | Allows critical alerts |
| `ShowInLockScreen` | `true` | Shows on lock screen |
| `ShowInNotificationCenter` | `true` | Shows in notification center |
| `SoundsEnabled` | `false` | Sound disabled by default |

### Output

```
./profiles/
  slack-notifications.mobileconfig
```

### Payload Type

`com.apple.notificationsettings`

---

## SOP 9: Generating Service Management Profiles

**Use Case**: Configure managed login items (background services, launch agents).

### Requirements

Service management profiles require a **Team ID**. This is:
1. Automatically extracted from the code requirement (if present)
2. Manually specified via the `team_id` field

### Enable in pppc.toml

```toml
[[apps]]
name = "Zoom"
bundle_id = "us.zoom.xos"
code_requirement = 'identifier "us.zoom.xos" and certificate leaf[subject.OU] = "BJ4HAAB9B3"'
services = ["camera", "microphone"]
notifications = false
service_management = true
team_id = "BJ4HAAB9B3"
```

### Team ID Extraction

The Team ID is extracted from code requirements matching:
```
certificate leaf[subject.OU] = "TEAMID"
certificate leaf[subject.OU] = TEAMID
```

If extraction fails and no `team_id` is specified, an error is shown:
```
! Skipping service management for AppName: Team ID required...
```

Find the Team ID manually:
```bash
codesign -dv /Applications/App.app 2>&1 | grep TeamIdentifier
```

### Output

```
./profiles/
  zoom-service-management.mobileconfig
```

### Payload Type

`com.apple.servicemanagement`

---

## SOP 10: Per-App vs Combined Profile Generation

**Use Case**: Choose between individual profiles per app (default) or a single combined profile.

### Per-App Mode (Default)

```bash
mould generate pppc.toml --output ./profiles/
```

Generates one TCC profile per app with unique identifiers:

```
./profiles/
  google-chrome-pppc.mobileconfig      # com.example.pppc.com_google_Chrome
  zoom-pppc.mobileconfig               # com.example.pppc.us_zoom_xos
  zoom-notifications.mobileconfig
  zoom-service-management.mobileconfig
```

Each profile has a unique `PayloadIdentifier` and `PayloadUUID`, so they can be deployed independently.

### Combined Mode

```bash
mould generate pppc.toml --combined --output ./profiles/
```

Merges all TCC entries into a single profile:

```
./profiles/
  pppc-pppc.mobileconfig               # com.example.pppc (all apps)
  zoom-notifications.mobileconfig      # still per-app
  zoom-service-management.mobileconfig # still per-app
```

### When to Use Each Mode

| Mode | Advantages | Use Case |
|------|-----------|----------|
| **Per-app** (default) | Update one app without touching others; clear ownership | Large fleets, frequent app changes |
| **Combined** | Fewer profiles to manage in MDM | Small deployments, simple setups |

Note: Notification and service management profiles are always per-app regardless of mode.

### Dry Run Preview

```bash
# Per-app mode
mould generate pppc.toml --dry-run

# Combined mode
mould generate pppc.toml --combined --dry-run
```

The dry-run output includes a **TCC Service Breakdown** bar chart showing how many apps use each service, and a **duplicate bundle ID warning** if any are detected:

```
Dry Run - Profile Preview
==================================================

TCC/PPPC (36 individual profiles):
  • Google Chrome (com.google.Chrome)
    - Full Disk Access
    - Screen Recording
    → google-chrome-pppc.mobileconfig
  • Zoom (us.zoom.xos)
    - Camera
    - Microphone
    → zoom-pppc.mobileconfig
  ...

Notification Profiles:
  • Zoom → zoom-notifications.mobileconfig
  ...

Service Management Profiles:
  • Zoom [Team: BJ4HAAB9B3] → zoom-service-management.mobileconfig
  ...

TCC Service Breakdown:
      Full Disk Access    28  ██████████████████████████████
       Screen Recording   15  ████████████████
              Camera    12  █████████████
          Microphone     9  ██████████
    Accessibility     7  ████████
       Files & Folders    5  ██████
         Listen Event     3  ████
    Post Event        2  ███

--------------------------------------------------
Total profiles to generate: 107
```

The bar chart is proportionally scaled — the most-used service gets the longest bar (30 chars), with others scaled relative to it. This provides a quick visual summary of your fleet's privacy permission needs.

If duplicate `bundle_id` entries exist (e.g., from scanning Adobe CC framework symlinks), a warning appears in the summary header:

```
! 6 duplicate bundle ID(s) detected (will produce colliding profiles):
    · com.adobe.Photoshop (2x)
    · com.adobe.Illustrator (2x)
    · com.adobe.Premiere (2x)
```

Use `mould scan --deduplicate` or re-scan to remove duplicates before generating.

---

## Configuration Reference

### Command Summary

| Command | Description |
|---------|-------------|
| `mould scan` | Scan apps and create pppc.toml |
| `mould generate` | Generate mobileconfig profiles from pppc.toml |
| `mould configure` | Interactively edit services in existing pppc.toml |
| `mould` (no subcommand) | One-shot scan + generate |

### Scan Command Reference

```
mould scan [OPTIONS] --org <ORG>

Options:
  -p, --path <PATH>           Directories or .app bundles to scan
                              [default: /Applications]
      --from-csv <CSV>        CSV file with app names/paths
  -o, --output <OUTPUT>       Output TOML file [default: pppc.toml]
      --org <ORG>             Organization identifier (required)
  -I, --interactive           Interactive mode
```

### Generate Command Reference

```
mould generate [OPTIONS] <INPUT>

Arguments:
  <INPUT>                     Input policy file (pppc.toml)

Options:
  -o, --output <OUTPUT>       Output directory or .mobileconfig path
      --combined              Merge all TCC into one profile
      --dry-run               Preview without writing
```

### Configure Command Reference

```
mould configure <INPUT>

Arguments:
  <INPUT>                     Input policy file (pppc.toml)
```

### Global Options

```
  -v, --verbose               Enable verbose output
      --json                  Output in JSON format (for CI/CD)
```

---

## pppc.toml Format Reference

### Complete Schema

```toml
[config]
org = "com.yourcompany"           # Required: Organization identifier
display_name = "My PPPC Profile"  # Optional: Profile display name

[[apps]]
name = "App Name"                 # Required: Display name
bundle_id = "com.example.app"     # Required: Bundle identifier or binary path
code_requirement = '...'          # Required: Code requirement string
identifier_type = "path"          # Optional: "bundleID" (default) or "path"
path = "/Applications/App.app"    # Optional: Path for reference
services = ["fda", "camera"]      # Optional: TCC services to grant
notifications = false             # Always present: notification profile toggle
service_management = false        # Always present: service mgmt profile toggle
team_id = "ABCD1234EF"           # Optional: Team ID (auto-extracted if possible)
```

### Field Details

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `config.org` | string | Yes | Organization identifier (e.g., `com.yourcompany`) |
| `config.display_name` | string | No | Human-readable profile name |
| `apps[].name` | string | Yes | Application display name |
| `apps[].bundle_id` | string | Yes | Bundle ID or binary path for path-based entries |
| `apps[].code_requirement` | string | Yes | Output of `codesign -d -r -` |
| `apps[].identifier_type` | string | No | `"bundleID"` (default) or `"path"` |
| `apps[].path` | string | No | Path to .app bundle (for reference) |
| `apps[].services` | array | No | List of TCC services to grant |
| `apps[].notifications` | bool | No | Generate notification profile (default: false) |
| `apps[].service_management` | bool | No | Generate service mgmt profile (default: false) |
| `apps[].team_id` | string | No | Team ID for service management |

### Example: App Bundle Entry

```toml
[[apps]]
name = "Zoom"
bundle_id = "us.zoom.xos"
code_requirement = 'identifier "us.zoom.xos" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "BJ4HAAB9B3"'
path = "/Applications/zoom.us.app"
services = ["camera", "microphone", "screen-capture"]
notifications = true
service_management = true
team_id = "BJ4HAAB9B3"
```

### Example: Path-Based Binary Entry

```toml
[[apps]]
name = "managedsoftwareupdate"
bundle_id = "/usr/local/munki/managedsoftwareupdate"
code_requirement = 'identifier managedsoftwareupdate and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = T4SK8ZXCXG'
identifier_type = "path"
services = ["fda"]
notifications = false
service_management = false
team_id = "T4SK8ZXCXG"
```

---

## Troubleshooting

### Problem: "No applications found"

```
No applications found to scan
```

**Causes:**
1. Path doesn't exist
2. Path contains no .app bundles
3. No read permission

**Solutions:**
```bash
ls -la /Applications
mould scan --path /Applications --org com.test
```

### Problem: Skipped apps (Empty/stub bundle)

```
! Skipped 4 app(s):
  > Empty/stub bundle (no Contents directory) (4)
```

**Cause:** Some apps (especially Microsoft 365 via Mac App Store) install as stub bundles that download their content on first launch.

**Solution:** Launch the app once so it downloads its full bundle, then re-scan.

### Problem: "Team ID required for service management profile"

```
! Skipping service management for AppName: Team ID required...
```

**Solutions:**

Add `team_id` manually:
```toml
[[apps]]
name = "App"
service_management = true
team_id = "ABCD1234EF"
```

Find Team ID:
```bash
codesign -dv /Applications/App.app 2>&1 | grep TeamIdentifier
```

### Problem: Per-app profiles have identical UUIDs

This was fixed in the current version. Per-app mode generates unique `PayloadIdentifier` and `PayloadUUID` values using a suffix derived from each app's bundle ID.

### Problem: Permissions not applied after MDM deployment

**Causes:**
1. Profile not installed (check System Settings > Profiles)
2. Code requirement mismatch (app updated, new signature)
3. Bundle ID mismatch

**Solutions:**
```bash
# Verify installed profiles
sudo profiles list

# Check app's current code requirement
codesign -d -r - /Applications/App.app

# Regenerate with updated code requirement
mould scan --path /Applications/App.app --org com.test --output updated.toml
```

### Debug: View Generated Profile

```bash
# Pretty-print profile
plutil -p profile.mobileconfig

# Validate XML structure
plutil -lint profile.mobileconfig

# Extract Services dictionary
plutil -extract PayloadContent.0.Services xml1 -o - profile.mobileconfig
```

---

## Appendix: Profile Payload Types

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

### Notification Profile

**Payload Type:** `com.apple.notificationsettings`

```xml
<dict>
  <key>NotificationSettings</key>
  <array>
    <dict>
      <key>BundleIdentifier</key>
      <string>com.example.app</string>
      <key>NotificationsEnabled</key>
      <true/>
      <key>AlertType</key>
      <integer>1</integer>
      <key>BadgesEnabled</key>
      <true/>
      <key>CriticalAlertEnabled</key>
      <true/>
      <key>ShowInLockScreen</key>
      <true/>
      <key>ShowInNotificationCenter</key>
      <true/>
      <key>SoundsEnabled</key>
      <false/>
    </dict>
  </array>
</dict>
```

### Service Management Profile

**Payload Type:** `com.apple.servicemanagement`

```xml
<dict>
  <key>Rules</key>
  <array>
    <dict>
      <key>RuleType</key>
      <string>TeamIdentifier</string>
      <key>RuleValue</key>
      <string>ABCD1234EF</string>
      <key>Comment</key>
      <string>com.example.app</string>
    </dict>
  </array>
</dict>
```
