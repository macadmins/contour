//! Generate machine-readable CLI reference for AI agents.
//!
//! Three output modes for progressive discovery:
//! - **Index** (default): Agent guide + command index (~120 lines)
//! - **Command**: Full detail for a single command by dotted path
//! - **Full**: Complete CLI reference (all commands, all flags)

use std::fmt::Write as _;
use std::io::Write;

use anyhow::{Result, bail};

/// Global flags that are documented once in the header and skipped in subcommands.
const GLOBAL_FLAGS: &[&str] = &["verbose", "json"];

/// Built-in subcommands to skip.
const SKIP_SUBCOMMANDS: &[&str] = &["help", "completions"];

// ── Index mode (default) ─────────────────────────────────────────────

/// Generate the agent guide and command index.
pub fn generate_index(cmd: &clap::Command, writer: &mut impl Write) -> Result<()> {
    let mut buf = String::with_capacity(4 * 1024);
    let name = cmd.get_name();

    // Agent guide
    writeln!(buf, "# {name} — macOS MDM configuration toolkit")?;
    writeln!(buf)?;
    writeln!(buf, "## Agent guide")?;
    writeln!(buf)?;
    writeln!(
        buf,
        "{name} is a CLI toolkit for generating and managing macOS MDM configuration profiles."
    )?;
    writeln!(buf)?;
    writeln!(buf, "**Discovery workflow:**")?;
    writeln!(
        buf,
        "1. Read the command index below to find relevant commands"
    )?;
    writeln!(
        buf,
        "2. Run `{name} help-ai --command <dotted.path>` for full flags and usage of a specific command"
    )?;
    writeln!(
        buf,
        "3. Run `{name} help-ai --section <name>` for a full tool section (profile, pppc, santa, mscp, btm, notifications)"
    )?;
    writeln!(
        buf,
        "4. Run `{name} help-ai --full` for the complete reference (large output)"
    )?;
    writeln!(buf)?;
    writeln!(buf, "**JSON schema (for structured parsing):**")?;
    writeln!(buf, "- `{name} help-json` — full CLI schema as JSON")?;
    writeln!(
        buf,
        "- `{name} help-json <dotted.path>` — scoped subtree, globals stripped"
    )?;
    writeln!(buf, "- Example: `{name} help-json profile.validate`")?;
    writeln!(buf)?;
    writeln!(
        buf,
        "**Command naming:** Commands use SPACES: `{name} profile ddm info`, `{name} santa cel check`"
    )?;
    writeln!(
        buf,
        "IMPORTANT: The index below uses dots (ddm.info) for readability only. When RUNNING commands, always use spaces."
    )?;
    writeln!(
        buf,
        "Dots are ONLY for --command lookup: `{name} help-ai --command profile.ddm.info`"
    )?;
    writeln!(buf)?;
    writeln!(buf, "**Common patterns:**")?;
    writeln!(buf, "- Most tools follow: init → scan → generate")?;
    writeln!(buf, "- `--json` on any command for machine-readable output")?;
    writeln!(
        buf,
        "- `--dry-run` to preview changes without writing files"
    )?;
    writeln!(
        buf,
        "- `--org` sets the organization identifier (or use .contour/config.toml)"
    )?;
    writeln!(buf)?;
    writeln!(
        buf,
        "**When to use which SOP (match user intent to the right SOP):**"
    )?;
    writeln!(
        buf,
        "- write/create/add a Fleet policy, osquery query, compliance check, detection → `--sop osquery`"
    )?;
    writeln!(
        buf,
        "- install software, auto-install, self-service, app deployment, package → `--sop osquery`"
    )?;
    writeln!(
        buf,
        "- generate/create/validate a mobileconfig, configuration profile, payload → `--sop profile`"
    )?;
    writeln!(
        buf,
        "- generate/send an MDM command (restart, lock, erase, remote desktop) → `--sop profile`"
    )?;
    writeln!(
        buf,
        "- mSCP, CIS, STIG, 800-53, compliance baseline, security rules → `--sop mscp`"
    )?;
    writeln!(
        buf,
        "- DEP, ADE, enrollment, Setup Assistant, skip keys, onboarding → `--sop enrollment`"
    )?;
    writeln!(
        buf,
        "- migrate, restructure, move from lib/ to platforms/, update GitOps → `--sop fleet-migrate`"
    )?;
    writeln!(
        buf,
        "- Santa, allowlist, blocklist, CEL, FAA, ring deployment → `--sop santa`"
    )?;
    writeln!(
        buf,
        "- DDM, declarative management, declaration, activation → `--sop ddm`"
    )?;
    writeln!(
        buf,
        "- GitHub Actions, CI, env vars, CONTOUR_ORG, workflow setup → `--sop ci`"
    )?;
    writeln!(buf)?;

    // SOP pointer (keep index compact)
    writeln!(
        buf,
        "**SOPs:** Run `{name} help-ai --sop <tool>` for step-by-step workflows:"
    )?;
    writeln!(
        buf,
        "- `--sop profile` — generate/validate mobileconfig profiles + MDM command payloads"
    )?;
    writeln!(
        buf,
        "- `--sop mscp` — query baselines, rules, ODVs, generate compliance artifacts"
    )?;
    writeln!(buf, "- `--sop ddm` — generate DDM declarations")?;
    writeln!(
        buf,
        "- `--sop santa` — Santa allowlist generation + Fleet ring deployment"
    )?;
    writeln!(buf, "- `--sop pppc` — PPPC/TCC profile generation")?;
    writeln!(buf, "- `--sop btm` — Background Task Management profiles")?;
    writeln!(
        buf,
        "- `--sop notifications` — Notification settings profiles"
    )?;
    writeln!(buf, "- `--sop support` — Root3 Support App profiles")?;
    writeln!(
        buf,
        "- `--sop osquery` — osquery schema lookup + Fleet policy query patterns + software assignment"
    )?;
    writeln!(
        buf,
        "- `--sop fleet-migrate` — migrate Fleet GitOps repo from legacy/v4.82 to v4.83 structure\n\
         - `--sop enrollment` — DEP/ADE enrollment profiles (Setup Assistant skip keys)\n\
         - `--sop ci` — GitHub Actions setup, env vars (CONTOUR_ORG, CONTOUR_NAME), workflow config\n\
         - `--sop schema-data` — embedded parquet data: verify, update, track schema versions"
    )?;
    writeln!(buf)?;

    // Command index
    writeln!(buf, "## Command index")?;
    writeln!(buf)?;

    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() || SKIP_SUBCOMMANDS.contains(&sub.get_name()) {
            continue;
        }
        write_index_group(&mut buf, sub, name)?;
    }

    writer.write_all(buf.as_bytes())?;
    Ok(())
}

// ── SOP mode ─────────────────────────────────────────────────────────

/// Generate standard operating procedures for a specific tool.
pub fn generate_sop(tool: &str, writer: &mut impl Write) -> Result<()> {
    let sop = match tool.to_lowercase().as_str() {
        "profile" => SOP_PROFILE,
        "mscp" => SOP_MSCP,
        "ddm" => SOP_DDM,
        "santa" => SOP_SANTA,
        "pppc" => SOP_PPPC,
        "btm" => SOP_BTM,
        "notifications" => SOP_NOTIFICATIONS,
        "support" => SOP_SUPPORT,
        "fleet-migrate" | "migrate" | "fleet" => SOP_FLEET_MIGRATE,
        "ci" | "github-actions" | "actions" | "env" | "workflow" => SOP_CI,
        "schema-data" | "schema" | "data" | "parquet" => SOP_SCHEMA_DATA,
        "enrollment" | "dep" | "ade" | "setup-assistant" => SOP_ENROLLMENT,
        "osquery" => SOP_OSQUERY,
        _ => bail!(
            "Unknown SOP tool: '{tool}'. Available: profile, mscp, ddm, santa, pppc, btm, notifications, support, osquery"
        ),
    };
    writer.write_all(sop.as_bytes())?;
    Ok(())
}

const SOP_PROFILE: &str = r"# SOP: Profile Generation & Validation

## Generate a mobileconfig profile
```
1. contour profile search <keyword> --json          # find payload type by keyword
2. contour profile generate <payload_type> --full   # generate with all fields
3. contour profile validate <file> --json           # validate against Apple schema
```

## Generate from a recipe (multi-profile bundle)
```
1. contour profile generate --list-recipes --json   # list available recipes
2. contour profile generate --recipe <name> --set KEY=VALUE -o <dir>
   # Secrets: use op:// (1Password), env:VAR, or file:/path
```

## Create a custom recipe
```
1. contour profile generate --create-recipe <name> <type1> <type2> ...
   # Creates a TOML recipe template from payload types
2. Edit the TOML to set field values and placeholders
3. contour profile generate --recipe <name> --recipe-path ./recipes/
```

## Validate existing profiles
```
1. contour profile validate <file_or_dir> --json    # schema validation
2. contour profile validate <dir> --recursive --report report.md
```

## Generate for Fleet (fragment mode)
```
contour profile generate <payload_type> --full --fragment -o fragment/
# Creates a composable fragment that merges into existing Fleet GitOps repos
# Output: fragment.toml + platforms/macos/configuration-profiles/*.mobileconfig
```

## Synthesize mobileconfigs from managed preferences
```
1. contour profile synthesize /Library/Managed\ Preferences/ --dry-run --json  # preview
2. contour profile synthesize /Library/Managed\ Preferences/ -o profiles/ --org com.yourco --validate
3. contour profile validate profiles/ --recursive --json  # verify output
```

## Key flags
- `--full` — include all fields, not just required
- `--interactive` — pick segments and set values interactively
- `--format plist` — raw payload dict (for Workspace ONE)
- `--org com.yourcompany` — set organization identifier
- `--json` — structured output for programmatic consumption
- `--fragment` — generate composable fragment for Fleet GitOps

## Normalize existing profiles
```
contour profile normalize <file_or_dir> --org com.yourco -o output/
contour profile normalize <dir> --recursive --org com.yourco --report report.md
```

What normalize does:
- Rewrites PayloadIdentifier under --org namespace (top-level AND child payloads)
- Regenerates UUIDs (deterministic from identifier)
- Fixes PayloadVersion, PayloadScope, display names
- Preserves MDM placeholders ($FLEET_VAR_*, %HardwareUUID%, {{var}})
- Preserves XML comments (<!-- ... -->)

What normalize does NOT do:
- Does not fix typos in the name segment of identifiers
  e.g., com.old.zscaler-cofing -> com.yourco.zscaler-cofing (prefix fixed, typo preserved)
- To fix a name typo: use contour profile duplicate --name 'correct-name' --org com.yourco

## Duplicate/re-identity a profile
```
contour profile duplicate <source> --name 'New Name' --org com.yourco -o fixed.mobileconfig
```
Creates a copy with new PayloadDisplayName, PayloadIdentifier, and UUIDs.
Use this to fix identifier typos or create variants of an existing profile.

## Synthesize mobileconfigs from managed preferences
```
1. contour profile synthesize /Library/Managed\ Preferences/ --dry-run --json  # preview
2. contour profile synthesize /Library/Managed\ Preferences/ -o profiles/ --org com.yourco --validate
3. contour profile validate profiles/ --recursive --json  # verify output
```

## Generate MDM command payloads (.plist for Fleet/MDM)
```
1. contour profile command list --json                  # list all 65 MDM commands
2. contour profile command info <command> --json         # show keys, types, descriptions
3. contour profile command generate <command> -o cmd.plist  # generate plist payload
   --set KEY=VALUE    # set command parameters
   --uuid             # add CommandUUID for tracking
   --base64           # output as base64 string (ready for Fleet API)
   --json             # JSON output includes base64 field automatically
```

### Common MDM commands
```
contour profile command generate RestartDevice -o restart.plist
contour profile command generate ShutDownDevice -o shutdown.plist
contour profile command generate DeviceLock --set PIN=123456 --set Message='Locked by IT' --uuid -o lock.plist
contour profile command generate EraseDevice --set PIN=123456 --uuid -o erase.plist
contour profile command generate RemoveProfile --set Identifier=com.example.wifi -o remove.plist
contour profile command generate ScheduleOSUpdate --set InstallAction=InstallASAP -o update.plist
contour profile command generate EnableRemoteDesktop -o remote.plist
contour profile command generate RotateFileVaultKey -o rotate-fvkey.plist
```

### Send via Fleet CLI
```
fleetctl mdm run-command --host <hostname> --payload cmd.plist
```

### Send via Fleet API (base64)
```
# Get base64 directly:
contour profile command generate RestartDevice --uuid --base64

# Or from JSON (base64 field included automatically):
contour profile command generate RestartDevice --uuid --json
# JSON output includes 'base64' field ready for Fleet API

# Use base64 value in Fleet API POST to /api/v1/fleet/commands/run
# Payload keys: command (base64 string), host_uuids (array of host UUIDs)

# Verify result:
# fleetctl get mdm-command-results --id=<CommandUUID>
```

## Import and normalize Jamf data
```
# Export profiles from Jamf Pro (requires jamf-cli)
jamf-cli pro backup --output ./jamf-backup --resources profiles

# Import, normalize, and validate (extract + format + validate in one step)
contour profile import --jamf ./jamf-backup/profiles/macos/ --all -o normalized/ --org com.yourco
```
Single file: `contour profile import --jamf backup.yaml -o output/ --org com.yourco`
Dry run: add `--dry-run` to preview without writing
Output goes to the specified directory — copy to Fleet GitOps as needed.

## Generate DEP enrollment profiles
```
contour profile enrollment list --platform macOS --json           # list skip keys
contour profile enrollment generate --platform macOS --skip-all -o enrollment.dep.json
contour profile enrollment generate --platform macOS --interactive -o enrollment.dep.json
```
";

const SOP_MSCP: &str = r#"# SOP: mSCP Security Compliance

## List baselines and rules
```
1. contour mscp schema baselines --json                        # list all baselines (14+)
2. contour mscp schema rules --baseline <name> --json          # list rules in baseline
3. contour mscp schema search <keyword> --json                 # search rules by keyword
4. contour mscp schema rule <rule_id> --json                   # full rule detail + payload
```

## Handle ODV (Organization Defined Values)
```
When a rule has "has_odv": true in JSON output:
1. contour mscp schema rule <rule_id> --json
2. Read payload.odv_options — per-baseline recommendations:
   {"cis_lvl1": 1200, "stig": 900, "recommended": 1200, "hint": "seconds"}
3. Ask user: "This rule requires an organization-defined value.
   Default: <odv_default>. Baseline options: <from odv_options>. Which value?"
4. Use the chosen value when generating artifacts
```

## Generate compliance artifacts (requires mSCP repo)
```
1. contour mscp generate --baseline <name> --output <dir> --mscp-repo <path>
   # Generates mobileconfigs via NIST's Python pipeline
2. contour mscp generate --baseline <name> --output <dir> --fleet-mode
   # Fleet GitOps output with policies, scripts, labels
```

## Compare embedded data vs mSCP repo
```
contour mscp schema compare <mscp_repo_path> --baseline <name> --json
```

## Key JSON fields for agents
- `has_odv` — true if rule needs an organization-defined value (MUST ask user)
- `odv_default` — default value if user doesn't specify
- `mobileconfig` — true if enforceable via MDM profile
- `has_ddm_info` — true if enforceable via DDM declaration
- `enforcement_type` — how the rule is enforced
- `payload.mobileconfig_info` — JSON array of {payload_type, keys} for profile generation
- `payload.check_script` — shell script to verify compliance
- `payload.odv_options` — JSON with per-baseline recommended values

## Validate osquery tables referenced by mSCP rules
When a rule has `osquery_checkable: true`, validate the referenced table:
```
contour osquery table <osquery_table_from_rule> --json
```
"#;

const SOP_DDM: &str = r#"# SOP: DDM Declaration Generation

## Before generating: ask for org domain
ALWAYS ask the user for their organization reverse-domain (e.g., com.acme)
before generating. The Identifier field in DDM declarations defaults to
com.example which must be replaced.

## Generate a DDM declaration
```
1. contour profile ddm list --json                  # list all 42+ DDM declaration types
2. contour profile ddm info <type> --json           # show schema (keys, types, defaults)
3. contour profile ddm generate <type> -o decl.json # generate JSON declaration
```

After generating, update the Identifier field:
  "Identifier": "com.yourorg.intelligence.settings"
                  ^^^^^^^^^^^ use the org domain from the user

## Find DDM declarations by keyword
```
contour profile search <keyword> --json
# Filter results where kind == "DdmDeclaration"
```

## Common DDM types
- com.apple.configuration.passcode.settings — Passcode requirements
- com.apple.configuration.softwareupdate.settings — OS update enforcement
- com.apple.configuration.intelligence.settings — Apple Intelligence settings
- com.apple.configuration.screensaver.settings — Screen saver settings
- com.apple.activation.simple — Simple activation predicate
"#;

const SOP_SANTA: &str = r#"# SOP: Santa Allowlist Generation

## Quick: Scan local apps → mobileconfig (no Fleet needed)
```
1. contour santa scan -f csv -o apps.csv            # scan /Applications
2. contour santa allow -i apps.csv --org com.yourco -o santa.mobileconfig
```

## Quick: Fleet CSV → mobileconfig
```
contour santa allow -i fleet-export.csv --org com.yourco --rule-type team-id
```

## Full pipeline: Fleet CSV → bundles → ring profiles
```
1. contour santa pipeline -i fleet.csv -b bundles.toml --org com.yourco -o profiles/
   # Combines discovery, classification, and generation in one command
   # --conflict-policy: first-match | most-specific | priority | error
   # --rule-type: bundle | prefer-team-id | prefer-signing-id | binary-only
```

## Ring-based deployment (staged rollouts)

Rings enable staged rollouts where you deploy rules progressively:
- Ring 1 (canary): IT/security team tests first
- Ring 2-3: pilot groups
- Ring 4-5: production (all devices)

Each ring generates up to 3 profiles by rule category:
- suffix `a` = Software rules (TeamID, SigningID, Binary, Certificate)
- suffix `b` = CEL rules (Common Expression Language, Santa 2024.x+)
- suffix `c` = FAA rules (File Access Authorization)

Rules auto-categorize — you provide all rules, contour splits them.

### Naming convention
```
{prefix}{ring}{category}
santa1a = Ring 1, Software rules
santa1b = Ring 1, CEL rules
santa1c = Ring 1, FAA rules
santa2a = Ring 2, Software rules
santa3b = Ring 3, CEL rules
...
```

If a ring has >1000 rules in a category, profiles split: santa1a-001, santa1a-002, etc.

### Generate ring profiles
```
1. contour santa rings init --num-rings 5 -o rings.yaml     # create ring config
2. contour santa rings generate <rules> \
     --num-rings 5 \
     --org com.yourco \
     --prefix santa \
     -o rings/
   # Output:
   #   rings/santa1a.mobileconfig  (ring 1, software)
   #   rings/santa1b.mobileconfig  (ring 1, CEL)
   #   rings/santa1c.mobileconfig  (ring 1, FAA)
   #   rings/santa2a.mobileconfig  (ring 2, software)
   #   ...
   #   rings/santa5c.mobileconfig  (ring 5, FAA)
```

### Assign rules to rings
Rules are assigned via the `ring` field in YAML/JSON rule files:
```yaml
- rule_type: TeamId
  identifier: EQHXZ8M8AV
  policy: Allowlist
  ring: ring0          # → goes to Ring 1 profiles
```

Or via rings.yaml config that maps labels/criteria to rings.

## Fleet GitOps output

Generate a complete Fleet GitOps directory with ring-targeted profiles:
```
contour santa fleet <rules> \
  --org com.yourco \
  --team Workstations \
  --num-rings 5 \
  --prefix santa \
  -o fleet-output/

# Output structure (v4.82+ layout):
#   fleet-output/
#   ├── fleets/
#   │   └── Workstations.yml         # fleet YAML with profile references
#   ├── platforms/
#   │   └── macos/
#   │       └── configuration-profiles/
#   │           ├── santa1a.mobileconfig
#   │           ├── santa1b.mobileconfig
#   │           └── ...
#   └── labels/
#       ├── santa-ring-0.labels.yml   # ring targeting labels
#       └── santa-ring-1.labels.yml
```

### Fragment mode (recommended for adding to existing Fleet repos)
```
contour santa fleet <rules> --fragment --org com.yourco -o fragment/
# Generates composable fragment — doesn't overwrite existing default.yml
# Output: fragment.toml + platforms/ directory for merging into Fleet GitOps
```

## Fetch rules from external sources
```
contour santa fetch osquery <json>                  # osquery santa_rules table
contour santa fetch mobileconfig <file>             # extract from existing profile
contour santa fetch santactl <output>               # santactl fileinfo output
contour santa fetch installomator <labels>          # Installomator TeamIDs
contour santa fetch fleet-csv <csv>                 # Fleet software CSV export
```

## Rule management
```
contour santa add --file rules.csv <rule>           # add a rule
contour santa remove --file rules.csv <rule>        # remove a rule
contour santa filter rules.csv --type team-id       # filter by type
contour santa validate rules.csv --json             # validate rules
contour santa stats rules.csv                       # rule statistics
contour santa snip rules.csv -o extracted.csv --match <pattern>  # extract matching
```

## CEL expression tools (Santa 2024.x+)
```
contour santa cel fields --json                     # list available fields (app.team_id, etc.)
contour santa cel check '<expression>' --json       # validate expression compiles
contour santa cel eval '<expression>' \
  --field team_id=EQHXZ8M8AV \
  --field app_name=Chrome --json                    # evaluate against inline app
contour santa cel classify bundles.toml \
  --input fleet.csv --json                          # classify apps against bundles
```

CEL fields: app.app_name, app.signing_id, app.team_id, app.sha256,
app.version, app.bundle_id, app.vendor, app.path, app.device_count
Operators: has(), startsWith(), endsWith(), contains(), matches(), size(),
&&, ||, !, ==, !=, <, >, <=, >=, in

## Output formats
- `--format mobileconfig` — full profile (default, unsigned)
- `--format plist` — raw payload dict (for Workspace ONE)
- `--format plist-full` — full profile as plist (no XML envelope)
- To sign: `contour profile sign <file> --identity "Developer ID Application: ..."`
"#;

const SOP_PPPC: &str = r"# SOP: PPPC/TCC Profile Generation

## Generate PPPC profiles
```
1. contour pppc init                                # create pppc.toml
2. contour pppc scan <app_paths> --json             # scan apps for TCC requirements
3. contour pppc configure pppc.toml                 # interactive service configuration
4. contour pppc generate pppc.toml -o profiles/     # generate mobileconfig
```

## Generate for Fleet (recommended for agents)
```
contour pppc generate pppc.toml --fragment -o fragment/
# Creates fragment.toml + platforms/ directory for merging into Fleet GitOps
```

## Validate existing PPPC config
```
contour pppc validate pppc.toml --json
```
";

const SOP_BTM: &str = r"# SOP: Background Task Management Profiles

## Generate BTM profiles
```
contour btm generate btm.toml -o profiles/
contour btm generate btm.toml --ddm -o ddm/          # DDM declarations (macOS 15+)
```

## Generate for Fleet (fragment mode)
```
contour btm generate btm.toml --fragment -o fragment/
contour btm generate btm.toml --ddm --fragment -o fragment/  # DDM + fragment
```
";

const SOP_NOTIFICATIONS: &str = r"# SOP: Notification Settings Profiles

## Generate notification profiles
```
contour notifications generate notifications.toml -o profiles/
```

## Generate for Fleet (fragment mode)
```
contour notifications generate notifications.toml --fragment -o fragment/
```
";

const SOP_SUPPORT: &str = r"# SOP: Root3 Support App Profiles

## Generate Root3 Support App profiles
```
contour support generate -o profiles/
```

## Generate for Fleet (fragment mode)
```
contour support generate --fragment -o fragment/
```
";

const SOP_FLEET_MIGRATE: &str = r"# SOP: Migrate Fleet GitOps Repo to v4.83 Structure

The v4.83 structure (from `fleetctl new`) is the definitive layout for Fleet GitOps.
This SOP guides an LLM agent to restructure an existing repo without data loss.

## v4.83 Definitive Directory Structure

```
it-and-security/
├── default.yml                                    # global: org_settings, controls, labels
├── fleets/
│   ├── workstations.yml                           # fleet: controls, profiles, software, policies
│   └── personal-mobile-devices.yml
├── labels/
│   └── *.yml                                      # one label per .yml file
└── platforms/
    ├── all/
    │   ├── icons/                                 # app icons for software
    │   ├── policies/                              # cross-platform policies
    │   └── reports/                               # cross-platform reports
    ├── android/
    │   ├── configuration-profiles/
    │   └── managed-app-configurations/
    ├── ios/
    │   ├── configuration-profiles/                # .mobileconfig
    │   └── declaration-profiles/                  # .json DDM
    ├── ipados/
    │   ├── configuration-profiles/
    │   └── declaration-profiles/
    ├── linux/
    │   ├── policies/
    │   ├── reports/
    │   ├── scripts/                               # .sh
    │   └── software/
    ├── macos/
    │   ├── commands/                              # MDM command .plist files
    │   ├── configuration-profiles/                # .mobileconfig
    │   ├── declaration-profiles/                  # .json DDM declarations
    │   ├── enrollment-profiles/                   # DEP .json profiles
    │   ├── policies/                              # .yml policy files
    │   ├── reports/                               # .yml report files
    │   ├── scripts/                               # .sh scripts
    │   └── software/                              # .yml software packages
    └── windows/
        ├── configuration-profiles/                # .xml CSP profiles
        ├── policies/
        ├── reports/
        ├── scripts/                               # .ps1 scripts
        └── software/
```

## Key Changes from Legacy/v4.82

### Path mapping: lib/ -> platforms/
```
lib/agent-options.yml           -> (removed or inline in fleet YAML)
lib/macos/configuration-profiles/ -> platforms/macos/configuration-profiles/
lib/macos/scripts/              -> platforms/macos/scripts/
lib/all/labels/                 -> labels/
```

### Path mapping: v4.82 -> v4.83
```
platforms/macos/configuration-profiles/*.json  -> platforms/macos/declaration-profiles/*.json
(DDM declarations were mixed with mobileconfigs in v4.82, now separated)
```

### YAML key changes
```
team_settings:    -> settings:          (v4.82 already did this)
no-team.yml       -> unassigned.yml     (v4.82 already did this)
macos_settings:   -> apple_settings:    (v4.83)
  custom_settings:  -> configuration_profiles:
- path: file.mobileconfig -> - paths: ../platforms/macos/configuration-profiles/*.mobileconfig
                               (glob patterns instead of per-file references)
```

### Fleet YAML profile references (v4.83 uses globs)
```yaml
# v4.82 (per-file)
controls:
  macos_settings:
    custom_settings:
      - path: ../platforms/macos/configuration-profiles/wifi.mobileconfig
      - path: ../platforms/macos/configuration-profiles/vpn.mobileconfig

# v4.83 (glob)
controls:
  apple_settings:
    configuration_profiles:
      - paths: ../platforms/macos/declaration-profiles/*.json
      - paths: ../platforms/macos/configuration-profiles/*.mobileconfig
  windows_settings:
    configuration_profiles:
      - paths: ../platforms/windows/configuration-profiles/*.xml
```

### Labels (v4.83 uses glob in default.yml)
```yaml
# v4.82
labels:
  - path: ./labels/my-label.yml

# v4.83
labels:
  - paths: ./labels/*.yml
```

## Step-by-Step Migration

### 1. Create the new directory structure
```bash
mkdir -p platforms/{all/{icons,policies,reports},android/{configuration-profiles,managed-app-configurations}}
mkdir -p platforms/{ios,ipados}/{configuration-profiles,declaration-profiles}
mkdir -p platforms/macos/{commands,configuration-profiles,declaration-profiles,enrollment-profiles,policies,reports,scripts,software}
mkdir -p platforms/{windows/{configuration-profiles,policies,reports,scripts,software}}
mkdir -p platforms/linux/{policies,reports,scripts,software}
mkdir -p labels fleets
```

### 2. Move files from old locations
```bash
# From lib/ (legacy)
mv lib/macos/configuration-profiles/*.mobileconfig platforms/macos/configuration-profiles/
mv lib/macos/configuration-profiles/*.json platforms/macos/declaration-profiles/
mv lib/macos/scripts/* platforms/macos/scripts/
mv lib/all/labels/*.yml labels/

# From flat platforms/ (v4.82 — DDM mixed with mobileconfig)
# Separate .json (DDM) from .mobileconfig
mv platforms/macos/configuration-profiles/*.json platforms/macos/declaration-profiles/ 2>/dev/null
```

### 3. Update default.yml
```yaml
# Change labels from per-file to glob
labels:
  - paths: ./labels/*.yml
```

### 4. Update fleet YAML files
```yaml
# Change macos_settings -> apple_settings with glob paths
controls:
  apple_settings:
    configuration_profiles:
      - paths: ../platforms/macos/declaration-profiles/*.json
      - paths: ../platforms/macos/configuration-profiles/*.mobileconfig
  windows_settings:
    configuration_profiles:
      - paths: ../platforms/windows/configuration-profiles/*.xml
  scripts:
    - paths: ../platforms/macos/scripts/*.sh
    - paths: ../platforms/windows/scripts/*.ps1
    - paths: ../platforms/linux/scripts/*.sh

policies:
  - paths: ../platforms/macos/policies/*.yml
  - paths: ../platforms/windows/policies/*.yml
  - paths: ../platforms/linux/policies/*.yml

reports:
  - paths: ../platforms/all/reports/*.yml
  - paths: ../platforms/macos/reports/*.yml

software:
  packages:
    # per-platform packages here
  fleet_maintained_apps:
    # slugs here
```

### 5. Set up CI/CD (.github/)

The v4.83 CI/CD structure uses a composite action + shell script:
```
.github/
├── fleet-gitops/
│   ├── action.yml       # composite action: installs fleetctl, configures, runs gitops.sh
│   └── gitops.sh        # iterates fleets/*.yml, validates unique names, runs dry-run + apply
└── workflows/
    └── workflow.yml      # triggers on push to main, PR (dry-run), nightly, manual
```

Key CI/CD details:
- gitops.sh iterates fleets/*.yml (glob, not hardcoded filenames)
- Uses --delete-other-fleets to remove fleets not in YAML
- fleetctl version auto-detected from Fleet server API
- PR triggers dry-run only, push to main triggers real apply
- Requires secrets: FLEET_URL, FLEET_API_TOKEN
- Nightly run at 6AM UTC ensures drift detection

### 5b. Verify CI/CD against v4.83 reference

Generate a fresh reference and diff against your existing repo:
```bash
# Option A: use fleetctl new (requires fleetctl v4.83+, no network needed)
fleetctl new /tmp/fleet-ref
diff -r .github /tmp/fleet-ref/.github
diff default.yml /tmp/fleet-ref/default.yml
diff -r fleets /tmp/fleet-ref/fleets

# Option B: fetch templates from GitHub (if fleetctl not installed)
diff .github/fleet-gitops/gitops.sh <(curl -fsSL https://raw.githubusercontent.com/fleetdm/fleet/main/cmd/fleetctl/fleetctl/templates/new/.github/fleet-gitops/gitops.sh)
```

Key things to check in the diff:
- gitops.sh references fleets/ (not teams/)
- gitops.sh uses --delete-other-fleets (not --delete-other-teams)
- action.yml has delete-other-fleets input
- workflow.yml triggers on push to main + PR (dry-run) + nightly

### 6. Validate
```bash
fleetctl gitops --dry-run -f default.yml -f fleets/workstations.yml
```

### 7. Clean up
After migration, the old lib/ directory should be empty and can be removed.

## Reference (canonical source of truth)
- `fleetctl new` scaffolds a complete v4.83 repo with CI/CD, fleets, labels, and platforms
- Templates: github.com/fleetdm/fleet/tree/main/cmd/fleetctl/fleetctl/templates/new
- GitOps parser: github.com/fleetdm/fleet/blob/main/cmd/fleetctl/fleetctl/gitops.go
- Generator: github.com/fleetdm/fleet/blob/main/cmd/fleetctl/fleetctl/new.go
- CI action: github.com/fleetdm/fleet/tree/main/cmd/fleetctl/fleetctl/templates/new/.github

## Important Rules
- DDM declaration .json files go in declaration-profiles/, NOT configuration-profiles/
- .mobileconfig files go in configuration-profiles/
- .xml Windows profiles go in configuration-profiles/
- Use glob paths (paths: *.mobileconfig) not per-file paths (path: file.mobileconfig)
- Labels are one .yml file per label in labels/ directory
- Policies/reports/scripts are per-platform under platforms/<platform>/
- The apple_settings key replaces macos_settings for profile references
- Every fleet YAML must have a unique name: value (CI rejects duplicates)
- CI uses --delete-other-fleets by default (fleets not in YAML get removed)
";

const SOP_ENROLLMENT: &str = r#"# SOP: DEP/ADE Enrollment Profiles (Setup Assistant)

Generate enrollment profiles that control the macOS/iOS Setup Assistant experience
for devices enrolling via Apple Business Manager (ABM) / Apple Device Enrollment (ADE).

## List available skip keys
```
contour profile enrollment list --platform macOS --json
contour profile enrollment list --platform iOS --json
contour profile enrollment list --platform macOS --os-version 26.0 --json
```

Each skip key controls one Setup Assistant screen (e.g., AppleID, Siri, Privacy).
Keys have platform and OS version gating — some only exist on macOS 11+, some are iOS-only.

## Generate enrollment profile

### Interactive (recommended for first time)
```
contour profile enrollment generate --platform macOS --interactive -o enrollment.dep.json
```
Shows a checklist of all skip keys with descriptions. Common enterprise defaults are pre-selected.
Toggle items with Space, confirm with Enter.

### Skip all available screens
```
contour profile enrollment generate --platform macOS --skip-all -o enrollment.dep.json
```

### Skip specific screens
```
contour profile enrollment generate --platform macOS \
  --skip AppleID,TOS,Siri,Privacy,Diagnostics,ScreenTime,iCloudStorage \
  -o enrollment.dep.json
```

## Output format
The generated JSON matches what Fleet expects:
```json
{
  "profile_name": "Automatic enrollment profile",
  "allow_pairing": true,
  "is_supervised": true,
  "is_mdm_removable": false,
  "language": "en",
  "region": "US",
  "skip_setup_items": ["AppleID", "TOS", "Siri", ...]
}
```

## Use with Fleet GitOps (v4.83 structure)
```
# Place in the enrollment-profiles directory
cp enrollment.dep.json platforms/macos/enrollment-profiles/automatic-enrollment.dep.json

# Reference in fleet YAML (fleets/workstations.yml)
controls:
  setup_experience:
    apple_setup_assistant: ../platforms/macos/enrollment-profiles/automatic-enrollment.dep.json
```

The filename is arbitrary — Fleet reads it by path reference, not by name convention.

## Common skip key sets

### Enterprise standard (skip most, keep FileVault + Biometric)
```
contour profile enrollment generate --platform macOS \
  --skip AppleID,AppStore,Diagnostics,iCloudDiagnostics,iCloudStorage,Location,Payment,Privacy,ScreenTime,Siri,TermsOfAddress,TOS,UnlockWithWatch,Appearance,Welcome,Wallpaper \
  -o enrollment.dep.json
```

### Maximum skip (skip everything available)
```
contour profile enrollment generate --platform macOS --skip-all -o enrollment.dep.json
```
Note: --skip-all includes FileVault and SoftwareUpdate. If you want users to see those
screens during setup, use --interactive and deselect them, or use --skip with explicit keys.

### Minimal (only skip legal/diagnostics)
```
contour profile enrollment generate --platform macOS \
  --skip TOS,Diagnostics,iCloudDiagnostics,Privacy \
  -o enrollment.dep.json
```

## Agent decision guide

When an agent is asked to generate an enrollment profile:
1. Ask: which platform? (macOS, iOS, iPadOS)
2. Ask: target OS version? (affects available skip keys)
3. Recommend: interactive mode for first-time setup
4. ALWAYS keep FileVault and SoftwareUpdate enabled (do NOT skip them)
   - FileVault: ensures disk encryption during setup
   - SoftwareUpdate: ensures device gets latest OS before use
5. Common items safe to skip: AppleID, TOS, Siri, Diagnostics, Privacy, ScreenTime, Payment
6. Items to discuss with user before skipping: Biometric (Touch ID), Appearance, Location

## Key facts
- is_supervised: true enables full MDM control (required for most enterprise features)
- is_mdm_removable: false prevents users from removing the MDM profile
- Skipping FileVault only skips the Setup Assistant prompt — FileVault CAN still be enforced via MDM profile, but best practice is to let users set it up during onboarding
- Skip keys are version-gated — use --os-version to see only keys valid for your target OS
- The --interactive flag shows descriptions for each key to help make informed choices
"#;

const SOP_CI: &str = r"# SOP: GitHub Actions & CI Setup for contour

## Environment Variables

contour reads these env vars as fallbacks when CLI flags are not provided:

| Variable | Purpose | Required |
|----------|---------|----------|
| `CONTOUR_ORG` | Organization reverse-domain (e.g., com.fleetdm) | Yes for any profile generation |
| `CONTOUR_NAME` | Organization display name (e.g., Fleet Device Management) | Optional (sets PayloadOrganization) |

Resolution order for both: CLI flag → env var → .contour/config.toml → error (org) or empty (name).

## Setup: Repository Variables

Use GitHub repository variables (not secrets — these are not sensitive):

```bash
gh variable set CONTOUR_ORG --repo yourorg/fleet-gitops --body 'com.yourcompany'
gh variable set CONTOUR_NAME --repo yourorg/fleet-gitops --body 'Your Company Inc.'
```

## Workflow Configuration

### Install contour in GitHub Actions
```yaml
- name: Install contour
  run: |
    curl -fsSL -o contour.pkg https://github.com/macadmins/contour/releases/latest/download/contour-*.pkg
    sudo installer -pkg contour.pkg -target /
```

### Use contour with env vars
```yaml
- name: Generate profiles
  env:
    CONTOUR_ORG: ${{ vars.CONTOUR_ORG }}
    CONTOUR_NAME: ${{ vars.CONTOUR_NAME }}
  run: |
    contour profile generate com.apple.mobiledevice.passwordpolicy --full -o profiles/passcode.mobileconfig
    contour profile import --jamf ./jamf-backup/profiles/macos/ --all -o profiles/
    contour profile validate profiles/ --recursive --json
```

### Use contour with Claude Code in GitHub Actions
```yaml
- name: Install contour and setup agent
  env:
    CONTOUR_ORG: ${{ vars.CONTOUR_ORG }}
    CONTOUR_NAME: ${{ vars.CONTOUR_NAME }}
  run: |
    sudo installer -pkg contour.pkg -target /
    contour setup-agent
```

This creates CLAUDE.md + .claude/skills/ so Claude Code knows how to use contour.

### Fleet GitOps + contour workflow
```yaml
env:
  CONTOUR_ORG: ${{ vars.CONTOUR_ORG }}
  CONTOUR_NAME: ${{ vars.CONTOUR_NAME }}
  FLEET_URL: ${{ secrets.FLEET_URL }}
  FLEET_API_TOKEN: ${{ secrets.FLEET_API_TOKEN }}

steps:
  - uses: actions/checkout@v4
  - name: Install contour
    run: sudo installer -pkg contour.pkg -target /
  - name: Validate all profiles
    run: contour profile validate platforms/macos/configuration-profiles/ --recursive --json
  - name: Apply GitOps
    run: ./.github/fleet-gitops/gitops.sh
```

## Key Patterns for CI

- CONTOUR_ORG/CONTOUR_NAME as repository variables (vars), not secrets
- FLEET_URL/FLEET_API_TOKEN as repository secrets
- contour auto-validates on generate — no separate validate step needed
- --all flag skips interactive prompts (required in CI)
- --json for machine-readable output in logs
- contour setup-agent writes CLAUDE.md for Claude Code CI integration

## Allowed Tools for claude.yml

If using Claude Code with contour in CI, add to your claude.yml:
```yaml
allowed_tools:
  - Bash(contour *)
```
";

const SOP_SCHEMA_DATA: &str = r#"# SOP: Embedded Schema Data Management

Contour embeds parquet datasets from the posture pipeline at compile time.
This SOP covers verifying, updating, and tracking that embedded data.

## What's Embedded

### mdm-schema crate (crates/mdm-schema/data/)
- capabilities.parquet — Apple MDM profiles, DDM declarations, commands (13,500+ rows)
- profilecreator.parquet — Community ProfileManifests (8,900+ rows)
- skip_keys.parquet — Setup Assistant skip keys (71 rows)

### mscp-schema crate (crates/mscp-schema/data/)
- rules_versioned.parquet — mSCP security rules with enforcement metadata (540 rows)
- rule_payloads.parquet — Check/fix scripts, mobileconfig_info, DDM details (463 rows)
- baseline_edges.parquet — Rule-to-baseline membership (4,400+ rows)
- baseline_meta.parquet — Baseline names, titles, authors (14 rows)
- rule_meta.parquet — Rule title, discussion, severity (463 rows)
- control_tiers.parquet — NIST 800-53 control tiers (728 rows)
- sections.parquet — mSCP section definitions (11 rows)
- envelope_patterns.parquet — XML nesting templates (4 rows)
- envelope_meta_keys.parquet — Envelope metadata key definitions (20 rows)

## Three-Layer Versioning (from posture)

### Layer 1: Schema Version (CalVer)
Each JSON Schema in posture's out/schemas/ has:
  x-schema-version: "2026.04.02.1" (YYYY.MM.DD.MICRO)
Only bumps when type structure changes (fields added/removed).
Same version = safe to drop in new parquet files.

### Layer 2: Data Hash (SHA-256)
Each schema also has:
  x-data-file: "skip_keys.parquet"
  x-data-sha256: "7227c5b9a67c..."
Verify after copying: shasum -a 256 data/file.parquet

### Layer 3: Manifest (out/manifest.json)
Complete inventory: filename, sha256, rows, bytes, columns per file.
Diff old vs new manifest to see exactly what changed.

## Update Workflow

### 1. Check compatibility
```
posture compat-check --contour /path/to/contour/crates/
```
Reports: EXACT (safe), COMPATIBLE (new nullable columns), or BREAKING (needs code changes).

### 2. Copy files
```
cp posture/out/capabilities.parquet crates/mdm-schema/data/
cp posture/out/skip_keys.parquet crates/mdm-schema/data/
cp posture/out/{baseline_meta,baseline_edges,control_tiers,rule_meta,sections}.parquet crates/mscp-schema/data/
cp posture/out/{rules_versioned,rule_payloads,envelope_patterns,envelope_meta_keys}.parquet crates/mscp-schema/data/
```

### 3. Verify integrity
```
posture validate
# Or manually:
shasum -a 256 crates/mdm-schema/data/*.parquet
shasum -a 256 crates/mscp-schema/data/*.parquet
```

### 4. Run tests
```
cargo test -p mdm-schema -p mscp-schema
```
Tests assert minimum row counts — if data is empty or schema changed, tests fail.

### 5. If BREAKING changes
- Compare Arrow schemas in reader modules (e.g., rule_meta.rs) against new parquet columns
- Update col() calls for renamed/new columns
- Add new fields to Rust types in types.rs
- Re-run tests

## Excluding Volatile Files
source_versions.parquet and platform_validity.parquet change on every regeneration.
Use --exclude with posture validate if only checking core data stability.

## Reference
- Posture consumer guide: CONSUMER_GUIDE.md in posture output
- Posture CLI: github.com/headmin/posture
- posture validate — verify all hashes
- posture compat-check — check schema compatibility
- posture data-report — generate manifest.json
"#;

const SOP_OSQUERY: &str = r#"# SOP: osquery Schema Lookup + Fleet Policy Patterns

## Search tables and columns
```
contour osquery search disk_encryption --json     # find tables/columns matching keyword
contour osquery search filevault --platform darwin --json
contour osquery search preferences --json
contour osquery search firewall --platform darwin  # human-readable output
```

## Show full table schema
```
contour osquery table preferences --json          # all columns with types, descriptions
contour osquery table alf --json                  # Application Layer Firewall
contour osquery table disk_encryption --json
contour osquery table apps --json                 # installed applications
```

## Statistics
```
contour osquery stats --json                      # 283 tables, 2581 columns, per-platform counts
```

## Idiomatic Fleet Policy Query Patterns

These are production patterns from Fleet's own it-and-security repo.

### Check if a setting is enabled (boolean check)
```sql
-- Disk encryption (macOS)
SELECT 1 FROM filevault_status WHERE status LIKE '%on%';

-- Disk encryption (Linux)
SELECT 1 FROM mounts m, disk_encryption d WHERE m.device_alias = d.name AND d.encrypted = 1 AND m.path = '/';

-- Disk encryption (Windows)
SELECT 1 FROM bitlocker_info WHERE protection_status = 1;

-- Firewall enabled (macOS)
-- Use: contour osquery table alf --json to see available columns
SELECT 1 FROM alf WHERE global_state >= 1;
```

### Check if an app is installed
```sql
-- By bundle identifier (preferred, stable across versions)
SELECT 1 FROM apps WHERE bundle_identifier = 'com.1password.1password';

-- By name (Windows)
SELECT 1 FROM programs WHERE name = '1Password';
```

### Check app version (version_compare function)
```sql
-- Fail if outdated (NOT EXISTS pattern)
SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM apps WHERE name = 'Slack.app' AND version_compare(bundle_short_version, '4.48.100') < 0);

-- Multi-OS version check
SELECT 1 FROM os_version WHERE version >= '26.4' OR version >= '15.7.5';
```

### Check available disk space
```sql
-- macOS/Linux (>10% free)
SELECT 1 FROM mounts WHERE path = '/' AND CAST(blocks_available AS REAL) / blocks > 0.10;

-- Windows
SELECT 1 WHERE (SELECT CAST(SUM(free_space) AS REAL) / SUM(size) FROM logical_drives WHERE file_system = 'NTFS') > 0.10;
```

### Check software updates
```sql
SELECT 1 FROM software_update WHERE software_update_required = 0;
```

### Check MDM profile installed
```sql
SELECT 1 FROM macos_profiles WHERE identifier = 'com.fleetdm.nudge.managed';
```

### Report/collect data (snapshot queries)
```sql
-- Detect Apple Intelligence
SELECT * FROM plist WHERE path LIKE '/Users/%/Library/Preferences/com.apple.CloudSubscriptionFeatures.optIn.plist';

-- Collect XProtect reports
SELECT * FROM xprotect_reports;
```

### Complex: multi-condition with EXISTS
```sql
-- App installed + profile present + package receipt
SELECT 1 WHERE
  EXISTS (SELECT 1 FROM macos_profiles WHERE identifier = 'com.fleetdm.nudge.managed')
  AND EXISTS (SELECT 1 FROM apps WHERE bundle_identifier = 'com.github.macadmins.Nudge' AND bundle_short_version LIKE '2.%')
  AND EXISTS (SELECT 1 FROM package_receipts WHERE package_id = 'com.fleetdm.Nudge.assets');
```

## Fleet Software Assignment Patterns

### Custom package YAML (platforms/macos/software/1password.yml)
```yaml
url: https://downloads.1password.com/mac/1Password.pkg
```

### Policy with auto-install (install_software)
```yaml
- name: macOS - 1Password installed
  query: SELECT 1 FROM apps WHERE bundle_identifier = 'com.1password.1password';
  install_software:
    package_path: ../software/1password.yml
  platform: darwin
```
When the policy fails, Fleet auto-installs the package.

### Software in fleet YAML (self-service + categories + labels)
```yaml
software:
  packages:
    - path: ../platforms/macos/software/1password.yml
      self_service: true
      setup_experience: true        # install during first-time setup
      categories:
        - Security
    - path: ../platforms/macos/software/firefox.yml
      self_service: true
      labels_include_any:           # only install on matching hosts
        - "Macs with Firefox needed"
      categories:
        - Browsers
  fleet_maintained_apps:
    - slug: slack/darwin
      self_service: true
      categories:
        - Communication
```

## Agent decision guide
1. Use `contour osquery search <keyword>` to find the right table
2. Use `contour osquery table <name> --json` to see all columns + types
3. Check platform support before writing the query
4. Use the idiomatic patterns above — do NOT invent new query structures
5. For version checks: always use `version_compare()` function, not string comparison
6. For app checks: prefer `bundle_identifier` over `name` (stable across locales)
7. For policy auto-install: reference software YAML via `install_software.package_path`
"#;

/// Write a top-level command group and its subcommands as an index.
fn write_index_group(buf: &mut String, cmd: &clap::Command, root: &str) -> Result<()> {
    let about = cmd.get_about().map(|a| a.to_string()).unwrap_or_default();
    let name = cmd.get_name();

    writeln!(buf, "### {root} {name} — {about}")?;

    let subs: Vec<_> = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .collect();

    if subs.is_empty() {
        // Leaf command at top level (e.g. `contour init`)
        writeln!(buf)?;
        return Ok(());
    }

    for sub in &subs {
        let sub_about = sub.get_about().map(|a| a.to_string()).unwrap_or_default();
        let sub_name = sub.get_name();

        // Check if this sub has its own subcommands
        let nested: Vec<_> = sub
            .get_subcommands()
            .filter(|s| !s.is_hide_set() && s.get_name() != "help")
            .collect();

        if nested.is_empty() {
            writeln!(buf, "  {sub_name:20} {sub_about}")?;
        } else {
            // Show nested group (e.g. profile docs, profile payload, mscp odv)
            writeln!(buf, "  {sub_name:20} {sub_about}")?;
            for n in &nested {
                let n_about = n.get_about().map(|a| a.to_string()).unwrap_or_default();
                writeln!(buf, "    {}.{:16} {n_about}", sub_name, n.get_name())?;
            }
        }
    }

    writeln!(buf)?;
    Ok(())
}

// ── Command mode (--command) ─────────────────────────────────────────

/// Generate full detail for a single command identified by dotted path.
///
/// Path examples: `santa.add`, `profile.docs.generate`, `pppc.scan`
pub fn generate_command(cmd: &clap::Command, path: &str, writer: &mut impl Write) -> Result<()> {
    let parts: Vec<&str> = path.split('.').collect();

    let mut current = cmd;
    let mut prefix = cmd.get_name().to_string();

    for part in &parts {
        let found = current.get_subcommands().find(|s| s.get_name() == *part);

        match found {
            Some(sub) => {
                prefix = format!("{prefix} {part}");
                current = sub;
            }
            None => {
                let available: Vec<_> = current
                    .get_subcommands()
                    .filter(|s| !s.is_hide_set() && s.get_name() != "help")
                    .map(|s| s.get_name().to_string())
                    .collect();
                bail!(
                    "Unknown command '{}' at '{}'. Available: {}",
                    part,
                    prefix,
                    available.join(", ")
                );
            }
        }
    }

    let mut buf = String::with_capacity(2 * 1024);
    write_command(
        &mut buf,
        current,
        &prefix_without_last(&prefix, current.get_name()),
        2,
    )?;
    writer.write_all(buf.as_bytes())?;
    Ok(())
}

/// Get the prefix (everything before the last segment).
fn prefix_without_last(full: &str, last: &str) -> String {
    if let Some(stripped) = full.strip_suffix(last) {
        stripped.trim_end().to_string()
    } else {
        full.to_string()
    }
}

// ── Full mode (--full, existing behavior) ────────────────────────────

/// Generate the complete CLI reference as markdown and write it to `writer`.
pub fn generate_full(cmd: &clap::Command, writer: &mut impl Write) -> Result<()> {
    let mut buf = String::with_capacity(8 * 1024);

    // Header
    writeln!(buf, "# {} CLI reference (for AI agents)", cmd.get_name())?;
    writeln!(buf)?;
    if let Some(version) = cmd.get_version() {
        writeln!(buf, "Version: {version}")?;
    }
    if let Some(about) = cmd.get_about() {
        writeln!(buf, "{about}")?;
    }
    writeln!(buf)?;

    // Global flags
    let global_args: Vec<_> = cmd
        .get_arguments()
        .filter(|a| GLOBAL_FLAGS.contains(&a.get_id().as_str()))
        .collect();

    if !global_args.is_empty() {
        writeln!(buf, "## Global flags")?;
        writeln!(buf)?;
        write_flags_table(&mut buf, &global_args)?;
        writeln!(buf)?;
    }

    // Walk subcommands
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() || SKIP_SUBCOMMANDS.contains(&sub.get_name()) {
            continue;
        }
        write_command(&mut buf, sub, cmd.get_name(), 2)?;
    }

    writer.write_all(buf.as_bytes())?;
    Ok(())
}

/// Backwards-compatible alias — calls `generate_full`.
pub fn generate(cmd: &clap::Command, writer: &mut impl Write) -> Result<()> {
    generate_full(cmd, writer)
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Recursively write a command and its subcommands.
fn write_command(buf: &mut String, cmd: &clap::Command, prefix: &str, depth: usize) -> Result<()> {
    let full_name = format!("{prefix} {}", cmd.get_name());
    let heading = "#".repeat(depth.min(6));

    writeln!(buf, "{heading} {full_name}")?;
    writeln!(buf)?;

    if let Some(about) = cmd.get_long_about().or_else(|| cmd.get_about()) {
        writeln!(buf, "{about}")?;
        writeln!(buf)?;
    }

    // Collect non-hidden, non-global, non-builtin args
    let args: Vec<_> = cmd
        .get_arguments()
        .filter(|a| {
            !a.is_hide_set()
                && a.get_id() != "help"
                && a.get_id() != "version"
                && !GLOBAL_FLAGS.contains(&a.get_id().as_str())
        })
        .collect();

    // Positional args — show in usage line
    let positionals: Vec<_> = args.iter().filter(|a| a.is_positional()).collect();
    if !positionals.is_empty() {
        let usage: Vec<String> = positionals
            .iter()
            .map(|a| {
                let name = a
                    .get_value_names()
                    .map(|v| {
                        v.iter()
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_else(|| a.get_id().to_string().to_uppercase());
                if a.is_required_set() {
                    format!("<{name}>")
                } else {
                    format!("[{name}]")
                }
            })
            .collect();
        writeln!(buf, "Usage: `{full_name} {}`", usage.join(" "))?;
        writeln!(buf)?;

        // Describe positionals if they have help text
        for a in &positionals {
            if let Some(help) = a.get_help() {
                let name = a.get_id().as_str();
                writeln!(buf, "- `{name}`: {help}")?;
            }
        }
        if positionals.iter().any(|a| a.get_help().is_some()) {
            writeln!(buf)?;
        }
    }

    // Flag args
    let flags: Vec<_> = args
        .iter()
        .filter(|a| !a.is_positional())
        .copied()
        .collect();
    if !flags.is_empty() {
        write_flags_table(buf, &flags)?;
        writeln!(buf)?;
    }

    // Recurse into subcommands
    let subs: Vec<_> = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .collect();

    for sub in subs {
        write_command(buf, sub, &full_name, depth + 1)?;
    }

    Ok(())
}

/// Write a markdown table of flags.
fn write_flags_table(buf: &mut String, args: &[&clap::Arg]) -> Result<()> {
    // Sort: required first, then alphabetical
    let mut sorted: Vec<_> = args.to_vec();
    sorted.sort_by(|a, b| {
        b.is_required_set()
            .cmp(&a.is_required_set())
            .then_with(|| flag_name(a).cmp(&flag_name(b)))
    });

    writeln!(buf, "| Flag | Type | Default | Description |")?;
    writeln!(buf, "|------|------|---------|-------------|")?;

    for arg in &sorted {
        let name = flag_name(arg);
        let type_str = arg_type(arg);
        let default = arg_default(arg);
        let desc = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
        let req = if arg.is_required_set() {
            " **(required)**"
        } else {
            ""
        };

        writeln!(buf, "| `{name}` | {type_str} | {default} | {desc}{req} |")?;
    }

    Ok(())
}

/// Format the flag name (--long / -short).
fn flag_name(arg: &clap::Arg) -> String {
    match (arg.get_long(), arg.get_short()) {
        (Some(l), Some(s)) => format!("--{l}, -{s}"),
        (Some(l), None) => format!("--{l}"),
        (None, Some(s)) => format!("-{s}"),
        (None, None) => arg.get_id().to_string(),
    }
}

/// Determine the type string for an argument.
fn arg_type(arg: &clap::Arg) -> String {
    // Boolean flags (SetTrue/SetFalse) — just show "flag"
    if matches!(
        arg.get_action(),
        clap::ArgAction::SetTrue | clap::ArgAction::SetFalse
    ) {
        return "flag".to_string();
    }

    let possible = arg.get_possible_values();
    if !possible.is_empty() {
        let vals: Vec<_> = possible
            .iter()
            .filter(|v| !v.is_hide_set())
            .map(|v| v.get_name().to_string())
            .collect();
        return format!("`{}`", vals.join("\\|"));
    }

    if arg.get_action().takes_values() {
        if let Some(names) = arg.get_value_names() {
            return names
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", ");
        }
        return "STRING".to_string();
    }

    "flag".to_string()
}

/// Format the default value.
fn arg_default(arg: &clap::Arg) -> String {
    let defaults = arg.get_default_values();
    if defaults.is_empty() {
        return "—".to_string();
    }
    let vals: Vec<_> = defaults.iter().filter_map(|v| v.to_str()).collect();
    format!("`{}`", vals.join(", "))
}

// ── JSON mode (--json) ───────────────────────────────────────────────

/// Generate the command tree as structured JSON.
/// If `path` is provided, scopes to that subtree with global flags stripped.
pub fn generate_json(
    cmd: &clap::Command,
    path: Option<&str>,
    writer: &mut impl Write,
) -> Result<()> {
    let json = if let Some(path) = path {
        // Walk to the target command, then output without globals
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = cmd;
        for part in &parts {
            current = current
                .get_subcommands()
                .find(|s| s.get_name() == *part)
                .ok_or_else(|| {
                    let available: Vec<_> = current
                        .get_subcommands()
                        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
                        .map(|s| s.get_name().to_string())
                        .collect();
                    anyhow::anyhow!(
                        "Unknown command '{part}'. Available: {}",
                        available.join(", ")
                    )
                })?;
        }
        command_to_json_no_globals(current)
    } else {
        command_to_json(cmd)
    };
    let output = serde_json::to_string_pretty(&json)?;
    writer.write_all(output.as_bytes())?;
    writeln!(writer)?;
    Ok(())
}

/// Convert a command to JSON, stripping global flags (for subtree scoping).
fn command_to_json_no_globals(cmd: &clap::Command) -> serde_json::Value {
    let args: Vec<serde_json::Value> = cmd
        .get_arguments()
        .filter(|a| {
            !a.is_hide_set()
                && a.get_id() != "help"
                && a.get_id() != "version"
                && !a.is_global_set()
        })
        .map(arg_to_json)
        .collect();

    let subcommands: Vec<serde_json::Value> = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .map(command_to_json_no_globals)
        .collect();

    let mut obj = serde_json::json!({
        "name": cmd.get_name(),
        "about": cmd.get_about().map(|a| a.to_string()),
    });

    if let Some(long_about) = cmd.get_long_about() {
        obj["long_about"] = serde_json::json!(long_about.to_string());
    }

    if !args.is_empty() {
        obj["args"] = serde_json::json!(args);
    }

    if !subcommands.is_empty() {
        obj["subcommands"] = serde_json::json!(subcommands);
    }

    obj
}

/// Convert a clap Command into a JSON value recursively.
fn command_to_json(cmd: &clap::Command) -> serde_json::Value {
    let args: Vec<serde_json::Value> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set() && a.get_id() != "help" && a.get_id() != "version")
        .map(arg_to_json)
        .collect();

    let subcommands: Vec<serde_json::Value> = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .map(command_to_json)
        .collect();

    let mut obj = serde_json::json!({
        "name": cmd.get_name(),
        "about": cmd.get_about().map(|a| a.to_string()),
    });

    if let Some(version) = cmd.get_version() {
        obj["version"] = serde_json::json!(version);
    }

    if let Some(long_about) = cmd.get_long_about() {
        obj["long_about"] = serde_json::json!(long_about.to_string());
    }

    if !args.is_empty() {
        obj["args"] = serde_json::json!(args);
    }

    if !subcommands.is_empty() {
        obj["subcommands"] = serde_json::json!(subcommands);
    }

    obj
}

/// Convert a clap Arg into a JSON value.
fn arg_to_json(arg: &clap::Arg) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "name": arg.get_id().as_str(),
        "required": arg.is_required_set(),
        "positional": arg.is_positional(),
    });

    if let Some(long) = arg.get_long() {
        obj["long"] = serde_json::json!(format!("--{long}"));
    }

    if let Some(short) = arg.get_short() {
        obj["short"] = serde_json::json!(format!("-{short}"));
    }

    if let Some(help) = arg.get_help() {
        obj["help"] = serde_json::json!(help.to_string());
    }

    let defaults = arg.get_default_values();
    if !defaults.is_empty() {
        let vals: Vec<&str> = defaults.iter().filter_map(|v| v.to_str()).collect();
        obj["default"] = serde_json::json!(vals.join(", "));
    }

    if arg.get_action().takes_values() {
        let possible: Vec<_> = arg
            .get_possible_values()
            .iter()
            .map(|v| v.get_name().to_string())
            .collect();
        if !possible.is_empty() {
            obj["possible_values"] = serde_json::json!(possible);
        }
    }

    if arg.is_global_set() {
        obj["global"] = serde_json::json!(true);
    }

    obj
}

// ── Skill file installation ─────────────────────────────────────────

/// Install a Claude Code / Kilo Code skill file for contour.
///
/// Creates `.claude/skills/contour.md` in the current working directory so
/// AI agents automatically discover contour capabilities.
/// Embedded skill file templates.
const SKILL_TEMPLATE: &str = include_str!("../skills/contour/SKILL.md");
const SOP_ROUTING_TEMPLATE: &str = include_str!("../skills/contour/references/sop-routing.md");

/// Install contour skill files for AI agents.
///
/// Creates:
/// - `.claude/skills/contour.md` — skill file (for local Claude Code sessions)
/// - Appends full contour instructions to `CLAUDE.md` (for CI/GitHub Actions)
/// - Appends full contour instructions to `AGENT.md` (for Kilo Code and others)
///
/// The full content goes into CLAUDE.md/AGENT.md because CI agents read those
/// but NOT `.claude/skills/`. A pointer isn't enough — the full instructions
/// must be in the file the agent reads at session start.
pub fn install_skill(version: &str) -> Result<()> {
    use std::fs;
    use std::path::Path;

    let skill_content = SKILL_TEMPLATE.replace("{{VERSION}}", version);

    // 1. Install .claude/skills/contour/ directory (for local sessions)
    let skill_dir = Path::new(".claude/skills/contour");
    let refs_dir = skill_dir.join("references");
    fs::create_dir_all(&refs_dir)?;
    fs::write(skill_dir.join("SKILL.md"), &skill_content)?;
    fs::write(refs_dir.join("sop-routing.md"), SOP_ROUTING_TEMPLATE)?;
    eprintln!("\u{2713} Installed .claude/skills/contour/SKILL.md");

    // 2. Write full content into CLAUDE.md and AGENT.md (for CI)
    for agent_file in &["CLAUDE.md", "AGENT.md"] {
        let path = Path::new(agent_file);
        if path.exists() {
            let existing = fs::read_to_string(path)?;
            if existing.contains("contour — macOS MDM Configuration Toolkit") {
                // Already has full content — replace the contour section
                eprintln!(
                    "  {agent_file} already has contour instructions (use --force to replace)"
                );
            } else {
                // Append full skill content
                let mut updated = existing;
                if !updated.ends_with('\n') {
                    updated.push('\n');
                }
                updated.push('\n');
                updated.push_str(&skill_content);
                fs::write(path, updated)?;
                eprintln!("\u{2713} Added contour instructions to {agent_file}");
            }
        } else {
            // Create with full content
            fs::write(path, &skill_content)?;
            eprintln!("\u{2713} Created {agent_file} with contour instructions");
        }
    }

    eprintln!();
    eprintln!("  Agents will now discover contour in both local and CI environments.");
    eprintln!("  Regenerate with: contour help-ai --install-skill");
    eprintln!();
    eprintln!("  TIP: Set your org domain in CLAUDE.md to avoid com.example defaults:");
    eprintln!("    ## Organization");
    eprintln!("    Default org domain: com.yourcompany");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, Command};

    fn sample_cmd() -> Command {
        Command::new("test-tool")
            .version("1.0.0")
            .about("A test tool")
            .arg(
                Arg::new("verbose")
                    .long("verbose")
                    .short('v')
                    .global(true)
                    .action(clap::ArgAction::SetTrue)
                    .help("Enable verbose output"),
            )
            .subcommand(
                Command::new("sub")
                    .about("A subcommand")
                    .arg(
                        Arg::new("input")
                            .long("input")
                            .required(true)
                            .help("Input file path"),
                    )
                    .arg(
                        Arg::new("format")
                            .long("format")
                            .value_parser(["json", "yaml", "toml"])
                            .default_value("json")
                            .help("Output format"),
                    ),
            )
    }

    #[test]
    fn generates_full_markdown() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        generate_full(&cmd, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("# test-tool CLI reference"));
        assert!(text.contains("Version: 1.0.0"));
        assert!(text.contains("## Global flags"));
        assert!(text.contains("--verbose"));
        assert!(text.contains("## test-tool sub"));
        assert!(text.contains("--input"));
        assert!(text.contains("**(required)**"));
        assert!(text.contains("json\\|yaml\\|toml"));
        // Boolean flags should show "flag", not "true|false"
        assert!(!text.contains("true\\|false"));
    }

    #[test]
    fn generates_index() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        generate_index(&cmd, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("# test-tool"));
        assert!(text.contains("Agent guide"));
        assert!(text.contains("Command index"));
        assert!(text.contains("sub"));
        assert!(text.contains("A subcommand"));
        // Index should NOT contain flag details
        assert!(!text.contains("--input"));
    }

    #[test]
    fn generates_single_command() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        generate_command(&cmd, "sub", &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("test-tool sub"));
        assert!(text.contains("--input"));
        assert!(text.contains("--format"));
    }

    #[test]
    fn command_not_found_error() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        let err = generate_command(&cmd, "nonexistent", &mut output).unwrap_err();
        assert!(err.to_string().contains("Unknown command"));
        assert!(err.to_string().contains("sub"));
    }

    #[test]
    fn skips_help_subcommand() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        generate_full(&cmd, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        // clap auto-adds a help subcommand; we should skip it
        assert!(!text.contains("## test-tool help"));
    }

    #[test]
    fn skips_hidden_args() {
        let cmd = Command::new("app").arg(
            Arg::new("secret")
                .long("secret")
                .hide(true)
                .help("Hidden arg"),
        );
        let mut output = Vec::new();
        generate_full(&cmd, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(!text.contains("secret"));
    }

    #[test]
    fn backward_compat_generate() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        generate(&cmd, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("# test-tool CLI reference"));
    }
}
