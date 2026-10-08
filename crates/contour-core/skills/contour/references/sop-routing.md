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
osquery-consuming engine (Fleet as the worked example).

```bash
contour osquery search disk_encryption --json     # find tables
contour osquery table alf --json                  # show columns
```

## Mobileconfig Profile → `--sop profile`

Use when: generating, validating, normalizing, signing, or synthesizing Apple configuration profiles.

```bash
contour profile search passcode --json
contour profile generate com.apple.mobiledevice.passwordpolicy --full --org <ORG_DOMAIN>
```

## Import and normalize Jamf data → `--sop profile`

Use when: migrating profiles from Jamf Pro to Fleet or another MDM.

```bash
contour profile import --jamf ./jamf-backup/profiles/macos/ --all -o profiles/ --org <ORG_DOMAIN>
```

## MDM Commands → `--sop profile`

Use when: generating MDM command plist payloads (restart, lock, erase, etc.)

```bash
contour profile command list --json
```

## Display-Name Naming → `--sop profile-naming`

Use when: renaming profile display names to a consistent scheme,
bootstrapping a `name.toml` naming map, or reshuffling identifiers/UUIDs to
match the names.

```bash
contour profile classify <DIR> -r --emit-map name.toml   # scan → name.toml scaffold
```

## MCX Domain Rename → `--sop mcx`

Use when: renaming or re-domaining a **managed-preference domain** — the
dictionary KEY an MCX payload nests its settings under. `normalize` /
`reidentify` cannot reach this.

```bash
contour profile mcx list <DIR> -r                          # survey domains first
contour profile mcx rename <DIR> -r --interactive          # guided, dry-run
```

## MCP Server → `--sop mcp`

Use when: wiring contour into an AI agent client (Claude Code, Cursor, Codex)
as an MCP server, or debugging one that will not connect.

```bash
contour-mcp --register                 # prints the claude mcp add commands
```

## mSCP Compliance → `--sop mscp`

Use when: working with CIS, STIG, 800-53, CMMC baselines or mSCP security rules.

```bash
contour mscp schema baselines --json
contour mscp schema rule os_airdrop_disable --json  # detail + ODV options
```

Rules with `has_odv: true` require organization-defined values — show the user `odv_options` and ask.

## mSCP → osquery / Fleet policies → `--sop mscp-osquery`

Use when: turning mSCP baseline rules into osquery **detection** (Fleet
policies or a vendor-neutral query pack) rather than enforcement.

```bash
contour mscp generate -m ./macos_security -k cis_lvl1 -o out --fleet-mode --osquery --org <ORG_DOMAIN>
```

## DEP Enrollment → `--sop enrollment`

Use when: creating Setup Assistant enrollment profiles for ABM/ADE.

```bash
contour profile enrollment generate --platform macOS --interactive -o enrollment.dep.json
```

FileVault and SoftwareUpdate are never skipped (NEVER_SKIP), by any route.

## Fleet GitOps Migration → `--sop fleet-migrate`

Use when: restructuring a Fleet GitOps repo from legacy/v4.82 to v4.83 structure.

## Santa Rules → `--sop santa`

Use when: creating Santa allowlists, CEL rules, FAA policies.

```bash
contour santa cel check 'has(app.team_id)' --json
```

## DDM Declarations → `--sop ddm`

Use when: generating Apple Declarative Device Management JSON declarations.

```bash
contour profile ddm list --json
contour profile ddm info com.apple.configuration.passcode.settings --json
```

Never leave an Identifier as `com.example` — use the user's org domain.

## Platform SSO → `--sop platform-sso`

Use when: IdP-backed login on macOS 27 — login/unlock/FileVault policies, Touch ID
or Apple Watch required, Authenticated Guest Mode, Tap to Login. Four presets ship; start there.

```bash
contour profile ddm compose --preset platform-sso-touchid --org com.acme -o ./out --json
```

## Which apps may run (macOS allow / deny lists) → `profile ddm app-control`

Use when: **allowlisting or denylisting apps on macOS** over DDM —
`com.apple.configuration.app.settings` `AllowedBinaries` / `DeniedBinaries`.
macOS 27+, supervised. Code signatures are read with `codesign`; Santa is not
needed.

```bash
contour profile ddm app-control scan                        # /Applications → [[allow]] entries
contour profile ddm app-control scan -I                     # pick what to allow and to deny
contour profile ddm app-control scan /Applications/X.app --deny -o deny.toml
# review app-control.toml, then:
contour profile ddm app-control generate --org <ORG_DOMAIN> -o out/ --write
contour profile ddm validate out/
```

Rules agents get wrong:

- **An allow list is exclusive** — only matching binaries run, apart from
  system-critical processes. Keep `allow_apple = true` (adds
  `TeamID = "*APPLE*"`), or Apple's own apps stop launching; `--no-apple`
  turns it off and says so.
- **Allow by vendor `team_id`, not `signing_id`.** Helpers, XPC services and
  updaters run under other signing IDs of the same team; a per-app allow
  entry blocks them. Deny entries may name the app.
- **Apple's identifier rules:** an allow entry needs `team_id` or `cdhash`; a
  deny entry needs `team_id`, `cdhash` or `signing_id`. `BinaryIdentifier` is
  the array element's name, not a key — fields go directly in the entry.
- `DeniedApps` / `AllowedApps` (bundle IDs) are iOS/tvOS/visionOS only.

## App privacy defaults → `--sop app-privacy`

Use when: **granting an app a privacy permission up front** (camera,
microphone, local network, accessibility, …) so the user is not queued TCC
prompts. macOS 26+, user-channel enrollment. Apple has no `Deny`, and `None`
still prompts — to block, stay on PPPC. Never hand-write the
`PermissionDefaults` key; `scan` reads it from the installed app.

```bash
contour profile ddm app-privacy scan /Applications/zoom.us.app
```

## Composed identifiers → `--sop composed-identifiers`

Use when: a key wants `"Bundle-ID (Team-ID)"` or `"Bundle-ID
{Designated-Requirement}"` — app.settings privacy keys, content filter and
DNS-proxy providers, VPN plugins, `app.managed`, extensible SSO, Safari extensions.

## Service configuration files → `--sop service-config`

Use when: managing a service's **on-disk text configuration** (`/etc/ssh`,
`/etc/sudoers`, `/etc/pam.d`, shell profiles, `/Library/Security`, …).
macOS 14+, supervised.

```bash
contour profile ddm service-config build ./staging --service com.apple.sshd \
    --base-url cdn.example.org/ddm --org <ORG_DOMAIN> -o out/ --write
```

## Synthesize from managed preferences → `--sop profile`

Use when: converting deployed managed preference plists into proper mobileconfigs.

```bash
contour profile synthesize /Library/Managed\ Preferences/ -o profiles/ --org <ORG_DOMAIN> --validate
```

## GitHub Actions & CI → `--sop ci`

Use when: setting up contour in GitHub Actions, configuring env vars, or CI workflows.
`CONTOUR_ORG` / `CONTOUR_NAME` are repository **variables** (not secrets); the
MDM API token is a **secret**.

## Windows CSP / ADMX / DISA STIG → `--sop windows`

Use when: finding which Windows CSP controls a feature, reading CSP node
types/enums/version gates, **generating the SyncML** (including third-party
app policies via ADMXInstall), **or working with the embedded DISA STIG corpus**.

```bash
contour profile search bitlocker --windows
contour profile windows generate windows.toml
contour profile windows stig list
```

A STIG export is a subset — read the SOP before shipping one. There is no
`profile windows validate`.

## "AI" — two SOPs, pick by what is being managed

| The ask is about… | SOP |
|---|---|
| Apple's own AI features: Writing Tools, Genmoji, Image Playground, on-device dictation, the ChatGPT external-intelligence hook, `app.settings` execution control | `--sop generative` |
| An AI coding tool's own settings: Claude Code, OpenAI Codex, Cursor, Gemini Enterprise mobile | `--sop app-policy` |

The bare alias `ai` is refused; use one of the two names.

## Apple Intelligence → `--sop generative`

Use when: authoring `intelligence.settings`, `external-intelligence.settings`,
`app.settings` or `safari.settings` DDM declarations. Released schema; no `--beta`.

## AI coding tools' managed configuration → `--sop app-policy`

Use when: managing Claude Code, OpenAI Codex, Cursor or Gemini Enterprise
mobile through the vendor's preference domain (an `mcx_domain` recipe).

## OS seed schema (beta) → `--sop beta`

The beta channel serves Apple's pre-release OS seed when the binary carries
one, and refuses otherwise. Check `contour census` (or the opening of
`--sop beta`) before routing anyone to `--beta`.

Use when a seed is carried: looking up seed-only declarations, keys and status
items (`contour profile ddm info <type> --beta`, `profile search <kw> --beta`,
`profile ddm status <kw> --beta`). mSCP has no pre-release branch, so
`contour mscp schema search <kw> --beta` refuses and says so.

## Other SOPs

| SOP | Use when |
|-----|----------|
| `--sop pppc` | PPPC/TCC privacy profiles |
| `--sop btm` | Background Task Management profiles |
| `--sop notifications` | Notification settings profiles |
| `--sop support` | Root3 Support App profiles |
