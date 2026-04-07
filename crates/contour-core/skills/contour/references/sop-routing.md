# SOP Routing Reference

Detailed intent-to-SOP mapping for contour. Use this when the compact table in SKILL.md isn't enough.

## CRITICAL: Organization domain required

Before ANY profile generation, you MUST have the user's org domain.
Check CLAUDE.md for a configured default. If none exists, ASK the user.
NEVER default to `com.example` — this produces invalid output that must be redone.
Pass `--org <domain>` on every generate, normalize, synthesize, and import command.

## Fleet Policy & osquery → `--sop osquery`

Use when: writing Fleet policies, osquery queries, compliance checks, software assignments.

```bash
contour osquery search disk_encryption --json     # find tables
contour osquery table alf --json                  # show columns
contour help-ai --sop osquery                     # full patterns + Fleet software assignment
```

Includes: idiomatic query patterns (disk encryption, app install, version check, disk space),
software assignment YAML templates, and Fleet auto-install via `install_software`.

## Mobileconfig Profile → `--sop profile`

Use when: generating, validating, normalizing, signing, or synthesizing Apple configuration profiles.

```bash
contour profile search passcode --json
contour profile generate com.apple.mobiledevice.passwordpolicy --full --org <ORG_DOMAIN>
contour help-ai --sop profile
```

Includes: generate, validate, normalize, duplicate, synthesize, Jamf import, MDM commands, enrollment profiles.

## Import and normalize Jamf data → `--sop profile`

Use when: migrating profiles from Jamf Pro to Fleet or another MDM.

```bash
# Export from Jamf
jamf-cli pro backup --output ./jamf-backup --resources profiles

# Import, normalize, validate
contour profile import --jamf ./jamf-backup/profiles/macos/ --all -o profiles/ --org <ORG_DOMAIN>
```

## MDM Commands → `--sop profile`

Use when: generating MDM command plist payloads (restart, lock, erase, etc.)

```bash
contour profile command list --json               # 65 commands
contour profile command generate DeviceLock --set PIN=123456 --uuid --base64
```

## mSCP Compliance → `--sop mscp`

Use when: working with CIS, STIG, 800-53, CMMC baselines or mSCP security rules.

```bash
contour mscp schema baselines --json              # 14 baselines
contour mscp schema rules --baseline cis_lvl1 --json
contour mscp schema rule os_airdrop_disable --json  # detail + ODV options
```

Rules with `has_odv: true` require organization-defined values — show the user `odv_options` and ask.

## DEP Enrollment → `--sop enrollment`

Use when: creating Setup Assistant enrollment profiles for ABM/ADE.

```bash
contour profile enrollment list --platform macOS --json
contour profile enrollment generate --platform macOS --interactive -o enrollment.dep.json
```

ALWAYS keep FileVault and SoftwareUpdate enabled (do NOT skip them).

## Fleet GitOps Migration → `--sop fleet-migrate`

Use when: restructuring a Fleet GitOps repo from legacy/v4.82 to v4.83 structure.

```bash
contour help-ai --sop fleet-migrate               # full directory mapping + CI/CD diff
fleetctl new /tmp/fleet-ref && diff -r .github /tmp/fleet-ref/.github
```

Key change: `declaration-profiles/` separated from `configuration-profiles/`, glob `paths:` patterns.

## Santa Rules → `--sop santa`

Use when: creating Santa allowlists, CEL rules, FAA policies, ring deployment.

```bash
contour santa cel check 'has(app.team_id)' --json
contour santa cel compile -c 'target.team_id == EQHXZ8M8AV' --result blocklist --json
contour santa faa schema --json
```

## DDM Declarations → `--sop ddm`

Use when: generating Apple Declarative Device Management JSON declarations.

```bash
contour profile ddm list --json                   # 42+ types
contour profile ddm info com.apple.configuration.passcode.settings --json
contour profile ddm generate com.apple.configuration.passcode.settings -o decl.json
```

After generating, update the Identifier field with the user's org domain — never leave as `com.example`.

## Synthesize from managed preferences → `--sop profile`

Use when: converting deployed managed preference plists into proper mobileconfigs.

```bash
contour profile synthesize /Library/Managed\ Preferences/ -o profiles/ --org <ORG_DOMAIN> --validate
```

## Other SOPs

| SOP | Use when |
|-----|----------|
| `--sop pppc` | PPPC/TCC privacy profiles |
| `--sop btm` | Background Task Management profiles |
| `--sop notifications` | Notification settings profiles |
| `--sop support` | Root3 Support App profiles |
| `--sop schema-data` | Embedded parquet data management |
