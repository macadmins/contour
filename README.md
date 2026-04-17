<p align="center">
  <img src="images/contour.png" alt="Contour" width="200">
</p>

# Contour

**The Swiss Army Knife for Apple Device Management tasks**

> **Status: Preview** — almost feature-complete for core workflows, APIs and flags may still change before 1.0.

One binary, multiple tools. A Mac admin's special tooling to slice and dice configuration profiles, validate, unsign/sign, and prepare them for MDM migration and GitOps work — start transforming existing profiles and create new ones.

## Tools

| Tool | Description |
|------|-------------|
| [`contour profile`](docs/contour-profile.md) | Normalize, validate, sign, generate, search, and import Apple configuration profiles. 500+ payload schemas embedded. |
| `contour profile synthesize` | Reverse-engineer managed preference plists (from `/Library/Managed Preferences/`) into validated mobileconfigs. Matches keys against Apple schema. |
| `contour profile import --jamf` | Import from [Jamf Pro backup](https://github.com/Jamf-Concepts/jamf-cli) YAML — extract, normalize, validate in one step. |
| `contour profile command` | Generate 65 MDM command plist payloads (RestartDevice, DeviceLock, EraseDevice, etc.) with `--base64` for Fleet API. |
| `contour profile enrollment` | Generate DEP/ADE enrollment profiles from embedded Setup Assistant skip keys (71 keys, platform/version gated). |
| `contour osquery` | Search and inspect 283 embedded osquery tables (2,581 columns) for writing queries and policies. |
| [`contour pppc`](docs/contour-pppc.md) | Generate TCC/Privacy Preferences profiles from app bundles. Scan → configure → generate workflow. |
| [`contour santa`](docs/contour-santa.md) | Santa allowlists + CEL toolkit (compile, eval, validate, dry-run, classify) + FAA plist generation. |
| [`contour mscp`](docs/contour-mscp.md) | mSCP baseline transformer with embedded schema query API (540 rules, 14 baselines, ODV support). |
| [`contour btm`](docs/contour-btm.md) | Generate Background Task Management (service management) profiles for managed login items. |
| [`contour notifications`](docs/contour-notifications.md) | Generate notification settings profiles with per-app control. |

## Highlights

- **GitOps-ready** — Every tool follows `init → scan → generate`. Version-control configs, generate/validate profiles in CI pipelines.
- **Auto-validation** — Every generated profile is validated against the Apple schema before writing.
- **Jamf import** — `--jamf` extracts, normalizes, and validates profiles from Jamf backup YAML to convert for GitOps.
- **Fragment output** — `--fragment` prepares artifacts for Fleet GitOps v4.83 directory structures.
- **MDM commands** — Generate MDM command plist payloads to use with NanoMDM or Fleet API.
- **LLM-friendly** — `contour help-ai` + `contour setup-agent` provide local lookup and schema info for AI-agent-assisted workflows.
- **One binary** — All tools ship as a single `contour` binary (signed + notarized for Apple Silicon, Linux for CI/CD).

## Install

Download the latest `.pkg` from [Releases](https://github.com/headmin/contour/releases) and install. The binary is signed and notarized by Apple.

```bash
# Or install manually
sudo installer -pkg contour-*.pkg -target /
```

## Quick Start

```bash
# Normalize and validate profiles for GitOps
contour profile normalize ./profiles -r --org com.acme --name "Acme Corp"

# Import from Jamf backup (extract, normalize, validate in one step)
contour profile import --jamf /path/to/jamf-backup/profiles/macos/ --all -o profiles/ --org com.acme

# Synthesize mobileconfigs from managed preference plists
contour profile synthesize /Library/Managed\ Preferences/ -o profiles/ --org com.acme --validate

# Search payload types and generate profiles
contour profile search passcode --json
contour profile generate com.apple.mobiledevice.passwordpolicy --full --org com.acme

# Generate MDM command payloads
contour profile command generate RestartDevice --uuid -o restart.plist
contour profile command generate DeviceLock --set PIN=123456 --uuid --base64  # for Fleet API

# Generate DEP enrollment profile
contour profile enrollment generate --platform macOS --interactive -o enrollment.dep.json

# Query embedded osquery schema
contour osquery search disk_encryption --json
contour osquery table alf --json

# Query mSCP compliance rules
contour mscp schema baselines --json
contour mscp schema rules --baseline cis_lvl1 --json

# Generate a PPPC profile granting Full Disk Access
contour pppc scan -p /Applications -o pppc.toml --org com.acme
contour pppc generate pppc.toml -o pppc.mobileconfig

# Santa: scan, CEL check, generate
contour santa scan -f csv -o apps.csv
contour santa cel check 'has(app.team_id) && app.team_id == "EQHXZ8M8AV"' --json
contour santa allow -i apps.csv --org com.acme -o santa.mobileconfig
```

## AI Agent Setup

```bash
# Install agent skill files (Claude Code, Kilo Code, etc.)
contour setup-agent

# Progressive help for agents
contour help-ai                     # command index + SOP routing
contour help-ai --sop profile      # profile generation workflow
contour help-ai --sop osquery      # Fleet policy query patterns
contour help-ai --sop fleet-migrate # GitOps repo migration guide
```

## Usage

```bash
contour --help          # Overview of all tools
contour <tool> --help   # Tool-specific help
contour help-ai         # LLM-optimized help for AI-assisted workflows
```

## Documentation

Detailed guides for each tool:

- [Profile Toolkit](docs/contour-profile.md) — normalize, validate, sign, diff, DDM declarations, payload extraction
- [PPPC Toolkit](docs/contour-pppc.md) — 24 TCC services, interactive and batch configuration, CSV input
- [Santa Toolkit](docs/contour-santa.md) — rule management, five fetch sources, prep command for full Santa deployment
- [mSCP Toolkit](docs/contour-mscp.md) — 24 baselines, Fleet/Jamf/Munki output, ODV overrides, cross-baseline deduplication
- [BTM Toolkit](docs/contour-btm.md) — launch item scanning, DDM declarations (macOS 15+), multi-machine merge
- [Notifications Toolkit](docs/contour-notifications.md) — per-app alert control, interactive configuration wizard

## License

Apache-2.0
