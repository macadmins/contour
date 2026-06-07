# SOP Routing Reference

Detailed intent-to-SOP mapping for contour. Use this when the compact table in SKILL.md isn't enough.

## CRITICAL: Organization domain required

Before ANY profile generation, you MUST have the user's org domain.
Resolution order: `--org` flag → `CONTOUR_ORG` env var → `.contour/config.toml` → error.
In CI/GitHub Actions: set `CONTOUR_ORG` as a repository secret or env var.
Interactive: ask the user if not configured.
NEVER default to `com.example` — this produces invalid output that must be redone.

## osquery & policy patterns → `--sop osquery`

Use when: writing osquery queries, compliance checks, or policies for any
osquery-consuming engine (Fleet shown as the canonical example).

```bash
contour osquery search disk_encryption --json     # find tables
contour osquery table alf --json                  # show columns
contour help-ai --sop osquery                     # full patterns + software-assignment recipes
```

Includes: idiomatic query patterns (disk encryption, app install, version check, disk space),
software-assignment YAML templates, and Fleet's `install_software`
auto-install wiring as the worked example.

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

## Display-Name Naming → `--sop profile-naming`

Use when: renaming profile display names to a friendly, consistent scheme,
bootstrapping a `name.toml` naming map, or reshuffling identifiers/UUIDs to
match the names after a manual round.

```bash
contour profile classify <DIR> -r --emit-map name.toml   # scan → name.toml scaffold (best-guess apps)
contour profile classify <DIR> -r --map name.toml         # dry-run preview (old → new)
contour profile classify <DIR> -r --map name.toml --write # apply renames
contour profile reidentify <DIR> -r --scheme name --org <ORG> --write  # reshuffle ids/UUIDs to match
contour help-ai --sop profile-naming
```

Scopes: App (`App - OneDrive (Settings)`), User (`PayloadScope == User`), System.
Override the schema with `name.toml`/`.contour/naming.yaml`; keep org-internal
app names local (gitignored), never in a committed map.

## mSCP Compliance → `--sop mscp`

Use when: working with CIS, STIG, 800-53, CMMC baselines or mSCP security rules.

```bash
contour mscp schema baselines --json              # 14 baselines
contour mscp schema rules --baseline cis_lvl1 --json
contour mscp schema rule os_airdrop_disable --json  # detail + ODV options
```

Rules with `has_odv: true` require organization-defined values — show the user `odv_options` and ask.

## mSCP → osquery / Fleet policies → `--sop mscp-osquery`

Use when: turning mSCP baseline rules into osquery **detection** (Fleet
policies or a vendor-neutral osquery query pack) rather than enforcement.
Native osquery-table queries (Tier-1) where a table fits, an audit-script →
results-plist fallback (Tier-2) for the residual.

```bash
contour mscp generate -m ./macos_security -k disa_stig -o out \
  --fleet-mode --osquery --org <ORG_DOMAIN>            # Fleet policies.yml (default)
contour mscp generate -m ./macos_security -k cis_lvl1 -o out \
  --fleet-mode --osquery --osquery-format pack --org <ORG_DOMAIN>   # vendor-neutral pack
contour help-ai --sop mscp-osquery                     # full Tier-1/Tier-2 model + plist contract
```

`--osquery` requires a resolvable org (`--org` / `CONTOUR_ORG` / config). Read
the emitted `<baseline>.osquery-coverage.md` to see the Tier-1/Tier-2 split.

## DEP Enrollment → `--sop enrollment`

Use when: creating Setup Assistant enrollment profiles for ABM/ADE.

```bash
contour profile enrollment list --platform macOS --json
contour profile enrollment generate --platform macOS --interactive -o enrollment.dep.json
contour profile enrollment generate --platform macOS --skip "Siri,TOS,Diagnostics,Privacy" -o enrollment.dep.json
contour profile enrollment generate --skip-list skip-list.toml -o enrollment.dep.json
```

Pick whichever mode fits — interactive for one-off, `--skip` for CI
one-liners, `--skip-list` for the reusable, version-controlled file.
`--skip-all` is rejected by the NEVER_SKIP guardrail (FileVault /
SoftwareUpdate). Never skip those.

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

## GitHub Actions & CI → `--sop ci`

Use when: setting up contour in GitHub Actions, configuring env vars, or CI workflows.

Key contract: `CONTOUR_ORG` and `CONTOUR_NAME` registered as repository
**variables** (not secrets). The MDM API token is a **secret**. contour
reads `CONTOUR_ORG` / `CONTOUR_NAME` automatically — no `--org` flag
needed in CI when env vars are set. See `--sop ci` for the full wiring
contract and example workflow.

## Other SOPs

| SOP | Use when |
|-----|----------|
| `--sop pppc` | PPPC/TCC privacy profiles |
| `--sop btm` | Background Task Management profiles |
| `--sop notifications` | Notification settings profiles |
| `--sop support` | Root3 Support App profiles |
| `--sop ci` | GitHub Actions setup, env vars, workflow config |
