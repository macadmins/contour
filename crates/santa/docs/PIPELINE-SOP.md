# Sleigh Pipeline Standard Operating Procedures

This document provides step-by-step procedures for common contour santa pipeline workflows.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Workflow Overview](#workflow-overview)
4. [SOP 1: Basic Pipeline (Single Profile per Bundle)](#sop-1-basic-pipeline-single-profile-per-bundle)
5. [SOP 2: Layer × Stage Matrix (Multi-Audience Rollout)](#sop-2-layer--stage-matrix-multi-audience-rollout)
6. [SOP 3: Interactive App Selection](#sop-3-interactive-app-selection)
7. [SOP 4: Bundle Discovery from Fleet Data](#sop-4-bundle-discovery-from-fleet-data)
8. [SOP 5: Local Scanning (Without Fleet)](#sop-5-local-scanning-without-fleet)
9. [SOP 6: GitOps Workflow Integration](#sop-6-gitops-workflow-integration)
10. [Configuration Reference](#configuration-reference)
11. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Inputs

You need **app inventory data** in CSV format. Two collection methods:

| Method | Requirements | Best For |
|--------|--------------|----------|
| **Fleet/osquery** | Fleet deployed | Enterprises with existing Fleet |
| **Local scan** | Santa installed | Small fleets, POCs, no Fleet |

### Option A: Fleet/osquery Export (Recommended for Enterprise)

```sql
-- Fleet query to export app data
SELECT
  name,
  bundle_version as version,
  team_id,
  signing_id,
  computer_name as device_name
FROM apps
WHERE team_id != ''
```

Export as CSV: `fleet-export.csv`

### Option B: Local Scanning with santactl (No Fleet Required)

```bash
# Scan local machine - generates CSV in same format as Fleet
contour santa scan --output local-apps.csv

# Scan multiple directories
contour santa scan --path /Applications --path ~/Applications --output local-apps.csv

# Skip the discover step - generate bundles.toml directly
contour santa scan --output-format bundles --output bundles.toml

# Skip discover AND pipeline - generate rules directly
contour santa scan --output-format rules --output rules.yaml

# Fully automatic - generate deployable mobileconfig
contour santa scan --output-format mobileconfig --output santa.mobileconfig --org com.yourcompany
```

For multi-machine collection without Fleet, see [SOP 5: Local Scanning](#sop-5-local-scanning-without-fleet).

### Both methods produce the same CSV format:

```csv
name,version,team_id,signing_id,sha256,device_name
Google Chrome,120.0,EQHXZ8M8AV,EQHXZ8M8AV:com.google.Chrome,abc123...,device1
Slack,4.35,BQR82RBBHL,BQR82RBBHL:com.tinyspeck.slackmacgap,def456...,device1
```

This CSV feeds into `contour santa discover` → `contour santa pipeline`.

---

## Quick Start

```bash
# 1. Export app data from Fleet (see Prerequisites for SQL query)
#    Save as fleet-export.csv

# 2. Discover vendors and generate bundle definitions from your fleet data
contour santa discover --input fleet-export.csv --output bundles.toml --interactive

# 3. Review bundles.toml - remove unwanted vendors, add layer/stage assignments
$EDITOR bundles.toml

# 4. Run pipeline to generate profiles
contour santa pipeline --input fleet-export.csv --bundles bundles.toml --output-dir ./profiles --org com.yourcompany

# 5. Deploy profiles via MDM
```

**Key Point**: You never manually write TeamIDs or CEL expressions. The `discover` command analyzes your fleet data and generates everything automatically. Your job is to review and approve.

---

## Workflow Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: Data Collection                                       │
│  Export app inventory from Fleet/osquery → fleet-export.csv     │
│  (Your fleet data contains all the TeamIDs, SigningIDs, etc.)   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2: Discovery (REQUIRED for first run)                    │
│  contour santa discover → auto-generates bundles.toml from fleet data  │
│  - Groups apps by vendor (TeamID)                               │
│  - Calculates device coverage                                   │
│  - Suggests CEL expressions                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3: Human Review                                          │
│  Edit bundles.toml:                                             │
│  - Remove vendors you don't want to allow                       │
│  - Add layer/stage assignments                                  │
│  - Adjust priorities if needed                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4: Pipeline Execution                                    │
│  contour santa pipeline → generates mobileconfig profiles              │
│  - Classifies apps against bundles                              │
│  - Generates Santa rules                                        │
│  - Creates profiles (per-bundle or Layer×Stage matrix)          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 5: Deployment                                            │
│  Deploy via MDM (Fleet GitOps, Jamf, etc.)                      │
└─────────────────────────────────────────────────────────────────┘
```

**The key insight**: Your fleet data already contains the information needed to create bundles. Discovery extracts patterns from your actual app inventory - you don't need to know TeamIDs in advance.

---

## SOP 1: Basic Pipeline (Single Profile per Bundle)

**Use Case**: Generate one mobileconfig per vendor/bundle for simple deployments.

### Procedure

#### Step 1: Discover Bundles from Fleet Data

Run discovery to auto-generate bundle definitions from your scanned app inventory:

```bash
contour santa discover \
  --input fleet-export.csv \
  --output bundles.toml \
  --threshold 0.05 \
  --min-apps 2
```

This analyzes your fleet data and generates `bundles.toml` with entries like:

```toml
# Auto-generated from fleet-export.csv
# Discovered 15 vendors across 1,000 devices

[[bundles]]
name = "microsoft"
description = "Microsoft Corporation (auto-discovered)"
cel = 'has(app.team_id) && app.team_id == "UBF8T346G9"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
device_coverage = 847
app_count = 12
confidence = 0.92

[[bundles]]
name = "google"
description = "Google LLC (auto-discovered)"
cel = 'has(app.team_id) && app.team_id == "EQHXZ8M8AV"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
device_coverage = 823
app_count = 8
confidence = 0.95

[[bundles]]
name = "zoom"
description = "Zoom Video Communications (auto-discovered)"
cel = 'has(app.team_id) && app.team_id == "BJ4HAAB9B3"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
device_coverage = 756
app_count = 3
confidence = 0.98
```

#### Step 2: Review and Adjust (Human Review)

Open `bundles.toml` and review the auto-generated bundles:

1. **Remove unwanted vendors** - Delete bundles for apps you don't want to allow
2. **Change policies** - Set `policy = "BLOCKLIST"` for vendors you want to block
3. **Adjust priorities** - Set `priority` values for conflict resolution
4. **Add layer/stage** - Optionally assign `layer` and `stage` for matrix output

```bash
# Edit the file
$EDITOR bundles.toml
```

#### Step 3: Run Pipeline

```bash
contour santa pipeline \
  --input fleet-export.csv \
  --bundles bundles.toml \
  --output-dir ./profiles \
  --org com.yourcompany \
  --orphan-policy catch-all \
  --conflict-policy most-specific \
  --deterministic
```

#### Step 3: Verify Output

The pipeline summary includes **By Rule Type** and **By Bundle** bar chart breakdowns showing the distribution of generated rules:

```
Pipeline Summary
==================================================

Input apps:               1247
After dedup:              983
Rules generated:          142
Bundles used:             15
Coverage:                 94.2%

By Rule Type:
    TEAMID   98  ██████████████████████████████
  SIGNINGID   32  ██████████
     BINARY   12  ████

By Bundle:
       microsoft   24  ██████████████████████████████
          google   18  ███████████████████████
           adobe   15  ███████████████████
            zoom    8  ██████████
         docker    6  ████████
          slack    5  ███████
  uncategorized   12  ███████████████

Changes from previous run
----------------------------------------
  Added: 8 rules
  Changed: 2 rules

✓ Pipeline complete! 18 files written to ./profiles
```

The bar charts are proportionally scaled — the largest category gets the full 30-character bar. This makes it easy to spot the composition of your ruleset at a glance.

Output files:

```bash
ls -la ./profiles/
# Expected output:
# santa-microsoft.mobileconfig
# santa-google.mobileconfig
# santa-zoom.mobileconfig
# santa-uncategorized.mobileconfig  (if orphan-policy=catch-all)
# rules.yaml
# coverage-report.yaml
# santa.lock
```

#### Step 4: Deploy via MDM

Upload profiles to your MDM solution:
- Fleet GitOps: Copy to `profiles/` directory in your Fleet repo
- Jamf: Upload via Configuration Profiles
- Workspace ONE: Import as Custom Profile

### Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `--org` | `com.example` | Organization identifier prefix |
| `--dedup-level` | `signing-id` | How to deduplicate apps across devices |
| `--rule-type` | `prefer-signing-id` | Rule type to generate |
| `--orphan-policy` | `error` | How to handle unmatched apps |
| `--conflict-policy` | `most-specific` | How to resolve multi-bundle matches |
| `--deterministic` | `true` | Reproducible output for GitOps |

---

## SOP 2: Layer × Stage Matrix (Multi-Audience Rollout)

**Use Case**: Different app allowlists for different teams (layers) with staged rollout (alpha → beta → prod).

### Concept

```
                    Stages (Rollout Phases)
                    ───────────────────────────────
                    │  Alpha  │  Beta   │  Prod   │
Layers    ──────────┼─────────┼─────────┼─────────┤
(Audience)│  Core   │ 150     │ 120     │ 100     │  ← Rules count
          │─────────┼─────────┼─────────┼─────────┤
          │ Devs    │ 200     │ 170     │ 150     │  ← Inherits Core
          │─────────┼─────────┼─────────┼─────────┤
          │ Finance │ 160     │ 130     │ 110     │  ← Inherits Core
          └─────────┴─────────┴─────────┴─────────┘
```

**Key Concepts**:
- **Layers**: Audience groups (Core = all, Developers = devs + core, Finance = finance + core)
- **Stages**: Rollout phases with cascading (Alpha gets Alpha + Beta + Prod rules)
- **Inheritance**: Developers layer inherits all Core rules
- **Cascading**: Alpha stage includes rules from Beta and Prod stages

### Procedure

#### Step 1: Discover Bundles from Fleet Data

```bash
contour santa discover \
  --input fleet-export.csv \
  --output bundles.toml \
  --threshold 0.05 \
  --interactive
```

Interactive mode lets you review each discovered vendor before saving.

#### Step 2: Add Layer and Stage Assignments (Human Review)

Open `bundles.toml` and add layer/stage assignments based on your organization:

```bash
$EDITOR bundles.toml
```

**Layer Assignment Guidelines:**
- `layer = "core"` - Apps needed by all employees (Office, browsers, Zoom)
- `layer = "developers"` - Dev tools (Docker, IDEs, Git clients)
- `layer = "finance"` - Finance apps (accounting software, ERP clients)
- `layer = "security"` - Security tools (only for security team)

**Stage Assignment Guidelines:**
- `stage = "prod"` - Stable, tested apps (default)
- `stage = "beta"` - Apps being rolled out to early adopters
- `stage = "alpha"` - New apps in limited testing

**Example after adding layer/stage:**

```toml
# Core apps (all machines) - discovered from fleet data
[[bundles]]
name = "microsoft"
description = "Microsoft Corporation (auto-discovered)"
cel = 'has(app.team_id) && app.team_id == "UBF8T346G9"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
layer = "core"      # Added: Available to all
stage = "prod"      # Added: Production-ready
device_coverage = 847
app_count = 12

[[bundles]]
name = "google"
description = "Google LLC (auto-discovered)"
cel = 'has(app.team_id) && app.team_id == "EQHXZ8M8AV"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
layer = "core"
stage = "prod"
device_coverage = 823
app_count = 8

# Developer tools - discovered, assigned to developers layer
[[bundles]]
name = "docker"
description = "Docker Inc (auto-discovered)"
cel = 'has(app.team_id) && app.team_id == "9BNSXJN65R"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
layer = "developers"  # Added: Only for dev machines
stage = "prod"
device_coverage = 234
app_count = 2

[[bundles]]
name = "jetbrains"
description = "JetBrains s.r.o. (auto-discovered)"
cel = 'has(app.team_id) && app.team_id == "2ZEFAR8TH3"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
layer = "developers"
stage = "beta"        # Added: Still in beta rollout
device_coverage = 189
app_count = 5
```

#### Step 3: Run Layer × Stage Pipeline

```bash
contour santa pipeline \
  --input fleet-export.csv \
  --bundles bundles.toml \
  --output-dir ./profiles \
  --org com.yourcompany \
  --layer-stage \
  --stages 3 \
  --orphan-policy catch-all \
  --verbose
```

#### Step 3: Verify Matrix Output

The Layer x Stage summary includes the same **By Rule Type** and **By Bundle** bar charts as the standard pipeline, plus the matrix table when `--verbose` is used:

```
Layer × Stage Pipeline Summary
==================================================

Input apps:               1247
After dedup:              983
Base rules:               142

Layers:                   ["core", "developers", "finance"]
Stages:                   ["alpha", "beta", "prod"]
Profiles:                 9

Profile Matrix (rules per Layer × Stage):
               alpha       beta        prod
-----------------------------------------------
core           142         120         100
developers     200         170         150
finance        160         130         110

Coverage:                 94.2%

By Rule Type:
    TEAMID   98  ██████████████████████████████
  SIGNINGID   32  ██████████
     BINARY   12  ████

By Bundle:
       microsoft   24  ██████████████████████████████
          google   18  ███████████████████████
           adobe   15  ███████████████████
            zoom    8  ██████████
         docker    6  ████████
```

Output files:

```bash
ls -la ./profiles/
# Expected output (3 layers × 3 stages = 9 profiles):
#
# Core layer:
# santa-core-prod.mobileconfig      (Core + Prod rules only)
# santa-core-beta.mobileconfig      (Core + Prod + Beta rules)
# santa-core-alpha.mobileconfig     (Core + Prod + Beta + Alpha rules)
#
# Developers layer (inherits Core):
# santa-developers-prod.mobileconfig
# santa-developers-beta.mobileconfig
# santa-developers-alpha.mobileconfig
#
# Finance layer (inherits Core):
# santa-finance-prod.mobileconfig
# santa-finance-beta.mobileconfig
# santa-finance-alpha.mobileconfig
#
# Metadata:
# fleet-manifest.yaml               (Fleet GitOps labels)
# rules.yaml
# coverage-report.yaml
# santa.lock
```

#### Step 4: Understanding the Output

**santa-core-prod.mobileconfig** contains:
- Microsoft (core, prod)
- Google (core, prod)

**santa-core-alpha.mobileconfig** contains:
- Microsoft (core, prod) ← cascaded from prod
- Google (core, prod) ← cascaded from prod
- NewApp (core, alpha) ← alpha-specific

**santa-developers-prod.mobileconfig** contains:
- Microsoft (core, prod) ← inherited from core
- Google (core, prod) ← inherited from core
- Docker (developers, prod)

**santa-developers-beta.mobileconfig** contains:
- Everything from developers-prod
- JetBrains (developers, beta) ← beta-specific

#### Step 5: Deploy with Fleet Labels

The `fleet-manifest.yaml` contains targeting labels:

```yaml
profiles:
  - name: santa-core-prod
    identifier: com.yourcompany.santa.core.prod
    file: santa-core-prod.mobileconfig
    rules: 100
    labels:
      - santa-layer:core
      - santa-stage:prod

  - name: santa-developers-alpha
    identifier: com.yourcompany.santa.developers.alpha
    file: santa-developers-alpha.mobileconfig
    rules: 200
    labels:
      - santa-layer:developers
      - santa-stage:alpha
```

In Fleet, assign labels to hosts:
- All machines: `santa-layer:core`
- Developer machines: `santa-layer:developers`
- Alpha testers: `santa-stage:alpha`
- Beta testers: `santa-stage:beta`
- Production: `santa-stage:prod`

### Stage Configurations

| `--stages` | Stages | Use Case |
|------------|--------|----------|
| `2` | test, prod | Simple testing before production |
| `3` | alpha, beta, prod | Standard 3-phase rollout |
| `5` | canary, alpha, beta, early, prod | Large organization gradual rollout |

---

## SOP 3: Interactive App Selection

**Use Case**: Manually review and select which apps to allow.

### Procedure

```bash
contour santa select \
  --input fleet-export.csv \
  --output rules.yaml \
  --rule-type signing-id
```

### Interactive Flow

```
How would you like to select apps?
  ● By vendor (TeamID) - Review apps grouped by developer
  ○ By individual app (SigningID) - Review each app separately

───────────────────────────────────────────────────────────────

[1/15] Microsoft Corporation (UBF8T346G9)
Apps: Microsoft Word, Microsoft Excel, Microsoft PowerPoint, ...
Seen on: 847 devices

What would you like to do?
  ● Allow all apps from this vendor (TEAMID rule)
  ○ Review individual apps from this vendor
  ○ Skip this vendor
  ○ Block this vendor

───────────────────────────────────────────────────────────────
```

### With Profile Splitting

```bash
contour santa select \
  --input fleet-export.csv \
  --output-dir ./profiles \
  --split 3 \
  --org com.yourcompany \
  --prefix santa-allowlist
```

Output:
- `santa-allowlist-1.mobileconfig`
- `santa-allowlist-2.mobileconfig`
- `santa-allowlist-3.mobileconfig`

---

## SOP 4: Bundle Discovery from Fleet Data

**Use Case**: Auto-generate bundle suggestions from fleet data.

### Procedure

#### Step 1: Run Discovery

```bash
contour santa discover \
  --input fleet-export.csv \
  --output bundles-suggested.toml \
  --threshold 0.05 \
  --min-apps 2 \
  --interactive
```

#### Step 2: Review Suggestions

Discovery output:

```toml
# Auto-generated bundle suggestions
# Review and edit before using

[[bundles]]
name = "microsoft"
description = "Microsoft Corporation (auto-discovered)"
cel = 'has(app.team_id) && app.team_id == "UBF8T346G9"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
device_coverage = 847    # Seen on 847 devices
app_count = 12           # 12 different apps
confidence = 0.92        # 92% confidence

[[bundles]]
name = "zoom"
description = "Zoom Video Communications (auto-discovered)"
cel = 'has(app.team_id) && app.team_id == "BJ4HAAB9B3"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
device_coverage = 823
app_count = 14
confidence = 0.95
```

#### Step 3: Edit and Refine

1. Remove unwanted vendors
2. Add layer/stage assignments
3. Adjust priorities
4. Add descriptions

#### Step 4: Run Pipeline

```bash
contour santa pipeline --input fleet-export.csv --bundles bundles-suggested.toml --output-dir ./profiles
```

### Discovery Options

| Option | Default | Description |
|--------|---------|-------------|
| `--threshold` | `0.05` | Minimum device coverage (5% of fleet) |
| `--min-apps` | `2` | Minimum apps per vendor to suggest |
| `--interactive` | `false` | Review bundles interactively |

---

## SOP 5: Local Scanning (Without Fleet)

**Use Case**: You don't have Fleet/osquery but want to generate Santa profiles from local applications.

### Overview

Two data collection methods are supported:

| Method | Tool | Use Case |
|--------|------|----------|
| **Fleet/osquery** | `contour santa discover` | Enterprise with Fleet deployed |
| **Local scanning** | `contour santa scan` | Single machine or small fleet without Fleet |

### Output Format Options

The `contour santa scan` command supports multiple output formats for different workflows:

| Format | Output | Next Step | Human Review |
|--------|--------|-----------|--------------|
| `csv` (default) | CSV file | `contour santa discover` | Yes (at discover) |
| `bundles` | bundles.toml | `contour santa pipeline` | Yes (edit bundles) |
| `rules` | rules.yaml | `contour santa generate` | Optional |
| `mobileconfig` | .mobileconfig | Deploy via MDM | No |

### Single Machine Workflow

Choose the workflow that matches your needs:

#### Workflow A: Full Pipeline (CSV → Discover → Pipeline)

Best for: Multi-machine aggregation, maximum control

```bash
# Step 1: Scan to CSV
contour santa scan --output local-apps.csv

# Step 2: Discover bundles
contour santa discover --input local-apps.csv --output bundles.toml --interactive

# Step 3: Review and edit bundles
$EDITOR bundles.toml

# Step 4: Generate profiles
contour santa pipeline \
  --input local-apps.csv \
  --bundles bundles.toml \
  --output-dir ./profiles \
  --org com.yourcompany
```

#### Workflow B: Bundles with Review (Grouped by Vendor)

Best for: Review vendor groupings before generating profiles

```bash
# Step 1: Scan to generate bundle definitions (grouped by TeamID)
contour santa scan --output-format bundles --output bundles.toml

# Step 2: Review and edit bundles (remove unwanted vendors, adjust settings)
$EDITOR bundles.toml

# Step 3: Generate mobileconfig from bundles
contour santa generate bundles.toml --output santa-rules.mobileconfig --org com.yourcompany
```

The bundles.toml file groups apps by TeamID and includes the identifier, so you can directly generate profiles from it.

#### Workflow C: Skip to Rules (Direct Santa Rules)

Best for: Quick testing, simple deployments

```bash
# Generate rules.yaml directly (TeamID rules by default)
contour santa scan --output-format rules --output rules.yaml

# Or use SigningID rules for more granular control
contour santa scan --output-format rules --rule-type signing-id --output rules.yaml

# Review rules (optional)
$EDITOR rules.yaml

# Generate mobileconfig from rules
contour santa generate rules.yaml --output santa-rules.mobileconfig --org com.yourcompany
```

#### Workflow D: Fully Automatic (Direct to Mobileconfig)

Best for: Quick POC, single machine deployment, no human review needed

```bash
# Generate deployable mobileconfig in one step
contour santa scan --output-format mobileconfig --output santa-rules.mobileconfig --org com.yourcompany

# Or use SigningID rules for more specific allowlisting
contour santa scan --output-format mobileconfig --rule-type signing-id --output santa-rules.mobileconfig --org com.yourcompany

# Deploy via MDM or install manually
sudo profiles install -path santa-rules.mobileconfig
```

### Detailed Examples

#### Scan with Default CSV Output

```bash
contour santa scan --output local-apps.csv
```

Output:
```
Scanning local applications with santactl...
  Device: my-macbook.local
  Paths: /Applications
  Output format: csv
  Apps found: 127

✓ Scan complete! 98 apps written to local-apps.csv
  Unsigned skipped: 25
  Errors: 4

Next steps:
  1. contour santa discover --input local-apps.csv --output bundles.toml
  2. Review and edit bundles.toml
  3. contour santa pipeline --input local-apps.csv --bundles bundles.toml --output-dir ./profiles
```

#### Scan with Bundles Output

```bash
contour santa scan --output-format bundles --output bundles.toml
```

Output:
```
Scanning local applications with santactl...
  Device: my-macbook.local
  Paths: /Applications
  Output format: bundles
  Apps found: 127

✓ Scan complete! 98 apps written to bundles.toml
  Unsigned skipped: 25
  Errors: 4

Next steps:
  1. Review and edit bundles.toml
  2. contour santa generate bundles.toml --output santa-rules.mobileconfig
```

The generated `bundles.toml` groups apps by TeamID:

```toml
[[bundles]]
name = "google"
cel = 'has(app.team_id) && app.team_id == "EQHXZ8M8AV"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
app_count = 8

[[bundles]]
name = "microsoft"
cel = 'has(app.team_id) && app.team_id == "UBF8T346G9"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
app_count = 12
```

#### Scan with Rules Output

```bash
contour santa scan --output-format rules --output rules.yaml
```

The generated `rules.yaml` contains direct Santa rules:

```yaml
- rule_type: TEAMID
  identifier: EQHXZ8M8AV
  policy: ALLOWLIST
  description: Google Chrome

- rule_type: TEAMID
  identifier: UBF8T346G9
  policy: ALLOWLIST
  description: Microsoft Word
```

For more granular rules, use SigningID:

```bash
contour santa scan --output-format rules --rule-type signing-id --output rules.yaml
```

```yaml
- rule_type: SIGNINGID
  identifier: "EQHXZ8M8AV:com.google.Chrome"
  policy: ALLOWLIST
  description: Google Chrome

- rule_type: SIGNINGID
  identifier: "UBF8T346G9:com.microsoft.Word"
  policy: ALLOWLIST
  description: Microsoft Word
```

#### Scan with Mobileconfig Output

```bash
contour santa scan --output-format mobileconfig --output santa-rules.mobileconfig --org com.yourcompany
```

Output:
```
Scanning local applications with santactl...
  Device: my-macbook.local
  Paths: /Applications
  Output format: mobileconfig
  Apps found: 127

✓ Scan complete! 98 apps written to santa-rules.mobileconfig
  Unsigned skipped: 25
  Errors: 4

Next steps:
  1. Review the generated profile
  2. Deploy santa-rules.mobileconfig via MDM
```

### Scan Command Reference

```bash
contour santa scan [OPTIONS]

Options:
  -p, --path <PATH>           Directories to scan [default: /Applications]
  -o, --output <OUTPUT>       Output file (auto-named if not specified)
  -f, --output-format <FMT>   Output format [csv|bundles|rules|mobileconfig]
      --org <ORG>             Organization identifier (for mobileconfig)
      --rule-type <TYPE>      Rule type [team-id|signing-id]
      --include-unsigned      Include unsigned applications
      --merge <FILES>         Merge multiple scan CSVs
```

### Multi-Machine Workflow (Without Fleet)

For organizations without Fleet, aggregate scans from multiple machines.

**Note**: Multi-machine aggregation requires CSV format. The `bundles`, `rules`, and `mobileconfig` formats are best for single-machine workflows.

#### Step 1: Scan Each Machine

On each Mac, run:
```bash
contour santa scan --output $(hostname)-apps.csv
```

#### Step 2: Collect and Merge CSVs

Collect all CSVs to a central location, then merge:
```bash
# Merge multiple scans into one
contour santa scan --merge machine1-apps.csv machine2-apps.csv machine3-apps.csv --output fleet-combined.csv
```

#### Step 3: Run Discovery and Pipeline

```bash
contour santa discover --input fleet-combined.csv --output bundles.toml
contour santa pipeline --input fleet-combined.csv --bundles bundles.toml --output-dir ./profiles
```

### Scripted Collection (Small Fleet)

For automated collection from multiple machines:

```bash
#!/bin/bash
# collect-apps.sh - Run on each machine via SSH/MDM

HOSTNAME=$(hostname)
OUTPUT_DIR="/path/to/shared/drive/scans"

# Scan and save (CSV format for aggregation)
contour santa scan --output "${OUTPUT_DIR}/${HOSTNAME}-apps.csv"
```

Deploy via MDM script, then merge centrally:
```bash
# On admin machine
contour santa scan --merge /path/to/shared/drive/scans/*.csv --output combined-fleet.csv
contour santa discover --input combined-fleet.csv --output bundles.toml
```

### CSV Format

The `contour santa scan --output-format csv` output is compatible with `contour santa discover`:

```csv
name,version,team_id,signing_id,sha256,device_name,bundle_id,path
Google Chrome,120.0.6099.129,EQHXZ8M8AV,EQHXZ8M8AV:com.google.Chrome,abc123...,my-mac,com.google.Chrome,/Applications/Google Chrome.app
Slack,4.35.126,BQR82RBBHL,BQR82RBBHL:com.tinyspeck.slackmacgap,def456...,my-mac,com.tinyspeck.slackmacgap,/Applications/Slack.app
```

### Requirements

- **Santa must be installed** - `santactl` is used for scanning
- **Admin access** - Required to read application signatures
- **macOS only** - santactl is macOS-specific

### When to Use Each Output Format

| Scenario | Recommended Format | Workflow |
|----------|-------------------|----------|
| Multi-machine aggregation | `csv` | scan → merge → discover → pipeline |
| Single machine, want control | `bundles` | scan → review → pipeline |
| Quick testing | `rules` | scan → generate |
| Fast POC, no review needed | `mobileconfig` | scan → deploy |
| Already have Fleet | N/A | Use Fleet CSV export (SOP 1/2) |

### When to Use Local Scanning vs Fleet

| Scenario | Recommendation |
|----------|----------------|
| 1-10 machines | Local scan + merge (CSV format) |
| 10-100 machines | Consider Fleet, or scripted scan collection |
| 100+ machines | Fleet/osquery strongly recommended |
| Already have Fleet | Use Fleet CSV export (SOP 1/2) |
| Testing/POC | Local scan with `mobileconfig` format |

---

## SOP 6: GitOps Workflow Integration

**Use Case**: Automated, version-controlled profile management with Fleet.

### Directory Structure

```
santa-profiles/
├── bundles.toml           # Bundle definitions (source of truth)
├── profiles/              # Generated profiles (gitignored)
│   ├── santa-core-prod.mobileconfig
│   ├── santa-core-beta.mobileconfig
│   └── ...
├── fleet-manifest.yaml    # Fleet targeting configuration
├── santa.lock            # Lock file for tracking changes
└── .github/
    └── workflows/
        └── generate-profiles.yml
```

### GitHub Actions Workflow

`.github/workflows/generate-profiles.yml`:

```yaml
name: Generate Santa Profiles

on:
  push:
    paths:
      - 'bundles.toml'
  workflow_dispatch:
    inputs:
      fleet_csv_url:
        description: 'URL to Fleet CSV export'
        required: true

jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download Fleet data
        run: |
          curl -o fleet-export.csv "${{ inputs.fleet_csv_url }}"

      - name: Install contour
        run: |
          cargo install --path crates/santa

      - name: Generate profiles
        run: |
          contour santa pipeline \
            --input fleet-export.csv \
            --bundles bundles.toml \
            --output-dir ./profiles \
            --org com.yourcompany \
            --layer-stage \
            --deterministic

      - name: Commit changes
        run: |
          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add profiles/ santa.lock fleet-manifest.yaml
          git commit -m "Update Santa profiles" || echo "No changes"
          git push
```

### Lock File Tracking

The `santa.lock` file tracks all rules:

```yaml
version: 1
generated: 2024-01-15T10:30:00Z
rules:
  TEAMID:UBF8T346G9:
    rule_type: TEAMID
    identifier: UBF8T346G9
    policy: ALLOWLIST
    bundle: microsoft
    description: Microsoft Corporation
    first_seen: 2024-01-10T08:00:00Z
```

Benefits:
- Track when rules were added
- Detect removed rules
- Audit trail for compliance
- Deterministic diffs in git

---

## Configuration Reference

### Deduplication Levels (`--dedup-level`)

| Level | Description | Best For |
|-------|-------------|----------|
| `team-id` | One rule per vendor | Low maintenance, trust vendor |
| `signing-id` | One rule per app | Balanced approach |
| `binary` | One rule per binary hash | High security, high churn |
| `adaptive` | Highest available identifier | Automatic selection |

### Orphan Policies (`--orphan-policy`)

| Policy | Behavior | Recommended For |
|--------|----------|-----------------|
| `error` | Fail if any app unmatched | Production (forces explicit decisions) |
| `warn` | Log warning, continue | Development/testing |
| `catch-all` | Create "uncategorized" bundle | Initial rollout |
| `ignore` | Silently skip | Partial deployments |

### Conflict Policies (`--conflict-policy`)

| Policy | Resolution | Notes |
|--------|------------|-------|
| `most-specific` | SigningID > TeamID > pattern | Default, usually correct |
| `priority` | Highest priority number wins | Use bundle priority field |
| `first-match` | First bundle in file wins | Order matters |
| `error` | Fail on any conflict | Strict mode |

### Rule Type Strategies (`--rule-type`)

| Strategy | Description | Security Level |
|----------|-------------|----------------|
| `bundle` | Use type from bundle definition | Flexible |
| `prefer-team-id` | Always use TeamID if available | Lower (trusts vendor) |
| `prefer-signing-id` | Always use SigningID if available | Medium (trusts app) |
| `binary-only` | Always use binary hash | Highest (trusts exact binary) |

---

## Troubleshooting

### Problem: "No bundles defined"

```
Error: No bundles defined. Run 'contour santa discover' first.
```

**Solution**: Create or specify a bundles.toml file:
```bash
contour santa discover --input fleet.csv --output bundles.toml
```

### Problem: "Orphan apps detected"

```
Error: 15 apps matched no bundle
```

**Solutions**:
1. Add bundles for the unmatched apps
2. Use `--orphan-policy catch-all` to create uncategorized bundle
3. Use `--orphan-policy warn` to continue with warning

### Problem: "Conflict detected"

```
Error: App "Slack" matches bundles: slack, messaging-apps
```

**Solutions**:
1. Set bundle priorities: `priority = 10` on preferred bundle
2. Use `--conflict-policy priority`
3. Make CEL expressions more specific

### Problem: Empty profiles generated

**Causes**:
1. No apps match bundle CEL expressions
2. Dedup level too aggressive
3. Layer/stage assignment incorrect

**Debug**:
```bash
contour santa classify --input fleet.csv --bundles bundles.toml --verbose
```

### Problem: Too many rules in profile

MDM has profile size limits (~1MB for mobileconfig).

**Solutions**:
1. Use `--dedup-level team-id` for fewer rules
2. Split into multiple bundles
3. Use Layer × Stage to distribute rules

---

## Appendix: Bundle File Format

### How Bundles Are Created

**99% of bundles are auto-generated** by `contour santa discover` from your fleet data. You only manually write bundles when:

1. **Blocking a vendor** - Add a bundle with `policy = "BLOCKLIST"` for malware/unwanted apps
2. **Complex matching** - Apps that need custom CEL logic beyond simple TeamID matching
3. **Pre-emptive rules** - Allow an app before it appears in fleet data

### Auto-Generated Bundle (from discovery)

```toml
# This was generated by: contour santa discover --input fleet.csv --output bundles.toml
[[bundles]]
name = "microsoft"
description = "Microsoft Corporation (auto-discovered)"
cel = 'has(app.team_id) && app.team_id == "UBF8T346G9"'
rule_type = "TEAMID"
policy = "ALLOWLIST"
device_coverage = 847    # Seen on 847 devices
app_count = 12           # 12 different apps discovered
confidence = 0.92        # Discovery confidence score

# Human additions after discovery:
layer = "core"           # Added during review
stage = "prod"           # Added during review
priority = 10            # Added during review
```

### Manually Written Bundle (rare cases)

```toml
# Manually written to block known malware
[[bundles]]
name = "blocked-malware"
description = "Known malicious software - BLOCK"
cel = 'has(app.team_id) && app.team_id in ["MALWARE1", "MALWARE2"]'
rule_type = "TEAMID"
policy = "BLOCKLIST"
priority = 1000  # High priority to win conflicts

# Manually written for complex matching
[[bundles]]
name = "homebrew-casks"
description = "Apps installed via Homebrew Cask"
cel = '''
has(app.signing_id) && (
  app.signing_id.startsWith("EQHXZ8M8AV:") ||
  app.signing_id.startsWith("BJ4HAAB9B3:")
)
'''
rule_type = "SIGNINGID"
policy = "ALLOWLIST"
layer = "developers"
stage = "beta"
```

### CEL Expression Examples

```toml
# Match by TeamID
cel = 'has(app.team_id) && app.team_id == "UBF8T346G9"'

# Match by SigningID
cel = 'has(app.signing_id) && app.signing_id == "EQHXZ8M8AV:com.google.Chrome"'

# Match by app name pattern
cel = 'has(app.app_name) && app.app_name.contains("Microsoft")'

# Match multiple TeamIDs
cel = 'has(app.team_id) && app.team_id in ["UBF8T346G9", "EQHXZ8M8AV"]'

# Complex expression
cel = '''
has(app.team_id) && app.team_id == "UBF8T346G9" &&
has(app.signing_id) && !app.signing_id.contains("Teams")
'''
```
