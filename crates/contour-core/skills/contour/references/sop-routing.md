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

## MCX Domain Rename → `--sop mcx`

Use when: renaming or re-domaining a **managed-preference domain** — the
dictionary KEY an MCX payload nests its settings under. Distinct from
display-name renaming above: the reference-rewriting never touches keys, so
`normalize`/`reidentify` cannot reach this.

```bash
contour profile mcx list <DIR> -r                          # survey domains first
contour profile mcx rename <DIR> -r --interactive          # guided, dry-run
contour profile mcx rename <DIR> -r --interactive --write  # apply
contour profile mcx rename <DIR> -r --from-prefix de.example.legacy \
    --to-prefix de.example.new --write                     # scripted, family rename
contour help-ai --sop mcx
```

Dry-run by default. Parses to verify scope, then edits only the accounted-for
`<key>` tags — the rest of the file stays byte-for-byte. Refuses rather than
half-writing (`DomainNotPresent` / `OccurrenceMismatch` / `TargetAlreadyPresent`).

## MCP Server → `--sop mcp`

Use when: wiring contour into an AI agent client (Claude Code, Cursor, Codex)
as an MCP server, or debugging one that will not connect.

```bash
sudo installer -pkg contour-mcp-<version>.pkg -target /   # its own pkg
contour-mcp --register                 # prints the claude mcp add commands
contour-mcp --print-tools              # inspect the 7-tool catalogue
contour help-ai --sop mcp
```

stdio transport only — no port, no listener, no authentication. Read-only is
structural: the crates that write MDM artifacts are not in its dependency tree
(`cargo tree -p contour-mcp --depth 1` to confirm).

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
`--skip-all` skips every pane that may be skipped — never FileVault or
SoftwareUpdate (the NEVER_SKIP guardrail), which are refused by any route.

## Fleet GitOps Migration → `--sop fleet-migrate`

Use when: restructuring a Fleet GitOps repo from legacy/v4.82 to v4.83 structure.

```bash
contour help-ai --sop fleet-migrate               # full directory mapping + CI/CD diff
fleetctl new /tmp/fleet-ref && diff -r .github /tmp/fleet-ref/.github
```

Key change: `declaration-profiles/` separated from `configuration-profiles/`, glob `paths:` patterns.

## Santa Rules → `--sop santa`

Use when: creating Santa allowlists, CEL rules, FAA policies.

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

## Platform SSO → `--sop platform-sso`

Use when: IdP-backed login on macOS 27 — login/unlock/FileVault policies, Touch ID
or Apple Watch required, Authenticated Guest Mode, Tap to Login with an NFC badge.
Four presets ship; start there.

```bash
contour profile ddm compose --list-presets --json | jq '.[] | select(.name | startswith("platform-sso"))'
contour profile ddm compose --preset platform-sso-touchid --org com.acme -o ./out --json
contour profile ddm validate ./out --json     # cross-key rules name both keys: "A ↔ B: …"
```

The IdP's `ExtensionComposedIdentifier` and `URLs` are placeholders in every preset;
nothing composes correctly until they are the operator's. Tap to Login also needs two
asset declarations the preset does not emit.

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
- **Allow by vendor `team_id`, not `signing_id`.** An app's helpers, XPC
  services and updaters run under other signing IDs of the same team; a
  per-app allow entry blocks them. Deny entries may name the app.
- **Apple's identifier rules:** an allow entry needs `team_id` or `cdhash`; a
  deny entry needs `team_id`, `cdhash` or `signing_id`. `BinaryIdentifier` is
  the array element's name, not a key — fields go directly in the entry.
- `DeniedApps` / `AllowedApps` (bundle IDs) are iOS/tvOS/visionOS only.

## App privacy defaults → `--sop app-privacy`

Use when: **granting an app a privacy permission up front** — camera,
microphone, local network, accessibility, Bluetooth, dictation, location —
so the user meets one managed decision instead of a queue of TCC prompts.
macOS 26+, user-channel enrollment.

```bash
contour profile ddm app-privacy scan /Applications/zoom.us.app
# set justification + uncomment the permissions the app needs
contour profile ddm app-privacy generate --org <ORG_DOMAIN> -o out/ --write
contour profile ddm app-privacy import-pppc pppc.toml   # migrate from PPPC
```

Two rules agents get wrong from published examples: **Apple has no `Deny`**
(values are `Allow` / `None`), and **`None` means unmanaged — the user is
still prompted**, not denied. To actually block a permission, stay on PPPC.

Never hand-write the `PermissionDefaults` key: on macOS it is the bundle id
plus the app's designated requirement in braces, on iOS the bare bundle id,
and the wrong one for the platform validates, deploys, reports Verified and
manages nothing. `scan` reads the requirement from the installed app.

## Composed identifiers → `--sop composed-identifiers`

Use when: a key wants `"Bundle-ID (Team-ID)"` or `"Bundle-ID
{Designated-Requirement}"` — app.settings privacy keys, web content filter
and DNS-proxy providers, VPN plugins, `app.managed`, extensible SSO, Safari
extensions. Nine keys, two spellings, and the platform decides which.

## Service configuration files → `--sop service-config`

Use when: managing a service's **on-disk text configuration** — `/etc/ssh`,
`/etc/sudoers`, `/etc/pam.d`, `/etc/cups`, `/etc/apache2`, shell profiles,
`/etc/SmartcardLogin.plist`, or `/Library/Security` (SecurityAgent plugins,
login banner). macOS 14+, supervised.

```bash
contour profile ddm service-config build ./staging --service com.apple.sshd \
    --base-url cdn.example.org/ddm --org <ORG_DOMAIN> -o out/ --write
contour profile ddm service-config rehost out/ --base-url <NEW_BASE> --verify --write
```

The staged tree mirrors the filesystem from `/` — stage `etc/ssh/sshd_config`,
not `ssh/sshd_config`. Use `rehost` when the artifact moves between hosting
providers: it re-points the URL and never touches the hash.

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

## Windows CSP / ADMX / DISA STIG → `--sop windows`

Use when: finding which Windows CSP controls a feature, reading CSP node
types/enums/version gates, **generating the SyncML** — including third-party
app policies (Chrome, Edge, M365, OneDrive) delivered through ADMXInstall —
**or working with the embedded DISA STIG corpus** (rules, registry checks,
Fleet policies).

```bash
contour profile search bitlocker --windows
contour profile info BitLocker --windows --full
contour profile windows generate windows.toml            # bare fragments
contour profile windows generate windows.toml --admx-dir ./admx
contour profile windows apps search cookies --app chrome   # third-party policy names
contour profile windows apps show chrome DefaultCookiesSetting   # + the [[setting]] to paste
contour profile windows stig list                        # STIG profiles, and what is enforceable
contour profile windows stig show V-253444               # one check: how to enforce, how to verify
contour profile windows stig export --profile dod-windows-11-stig-v2r4
```

An export is a subset — only rules with both an enforcement and a compliance
query — and the file's header says by how much. Recipe 6 in the SOP has the
rest.

Not available: `profile windows validate`. Generation refuses unsupported
paths, values, channels and actions, so what contour writes is checked —
but a SyncML document contour did not produce is not.

## "AI" — two SOPs, pick by what is being managed

| The ask is about… | SOP |
|---|---|
| Apple's own AI features: Writing Tools, Genmoji, Image Playground, on-device dictation, the ChatGPT external-intelligence hook, `app.settings` execution control | `--sop generative` |
| An AI coding tool's own settings: Claude Code, OpenAI Codex, Cursor, Gemini Enterprise mobile | `--sop app-policy` |

The bare alias `ai` is refused for this reason; use one of the two names.

## Apple Intelligence → `--sop generative`

Use when: authoring `com.apple.configuration.intelligence.settings`,
`external-intelligence.settings`, `app.settings` or `safari.settings` DDM
declarations. All are in the released schema (26.4 / 27.0); no `--beta`.

## AI coding tools' managed configuration → `--sop app-policy`

Use when: managing Claude Code, OpenAI Codex, Cursor or Gemini Enterprise
mobile on managed Macs through the vendor's preference domain. The working
path today is an `mcx_domain` recipe (e.g. `com.anthropic.claudecode`);
the embedded app-policy dataset has no query CLI yet.

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
| `--sop ci` | GitHub Actions setup, env vars, workflow config |
| `--sop windows` | Windows CSP schema exploration (`--windows`), SyncML generation, DISA STIG corpus |
| `--sop generative` | Apple Intelligence DDM payloads (intelligence / external-intelligence / app.settings) |
| `--sop platform-sso` | Platform SSO on macOS 27: login policies, Touch ID, guest mode, Tap to Login; four presets |
| `--sop app-policy` | AI coding tools' managed configuration (Claude Code, OpenAI Codex, Cursor, Gemini Enterprise mobile) |
