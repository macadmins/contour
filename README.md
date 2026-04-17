<p align="center">
  <img src="images/contour.png" alt="Contour" width="200">
</p>

# Contour

**The Swiss Army Knife for Apple Device Management tasks**

> **Status: Preview** — almost feature-complete for core workflows, APIs and flags may still change before 1.0.

One signed binary that makes modern device management simpler: it normalizes configs consistently and surfaces errors clearly so outcomes diff cleanly. Whether you, your mdm vendor, or an agent wrote them, Contour supports profiles, DDM, Santa, PPPC, mSCP, osquery, BTM, and notification payloads. Prepare artifacts for MDM migration and GitOps workflows from the Terminal, in CI, or via an AI agent. Two modes, same core — every artifact is validated against the embedded Apple schema

## Why

**Device config deserves the same rigor as the code you ship to production.**

Profiles, DDM declarations, Santa rules, osquery policies — it's all code, but the tooling around it has lived in GUIs and copy-paste. Drift becomes normal. Typos ship. And AI agents are now writing the same config with no guardrails.

- **How.** The Apple schema for MDM/profiles, declarative management, and osquery is embedded. Processors and the generator validate against it before writing. Identifiers and UUIDs are handled deterministically.
- **What.** One signed binary. Tools that diff cleanly, normalize consistently, and fail loud when something's wrong — whether you or an agent wrote it.

## How it's used

Two modes, same core — every artifact is validated against the embedded Apple schema before it lands.

### As a CLI toolkit

Every tool is a first-class CLI. Use it in CI, makefiles, or at the terminal.

| Tool | Description |
|------|-------------|
| [`contour profile`](docs/contour-profile.md) | Normalize, validate, sign, generate, search, and import Apple configuration profiles against the embedded schema. |
| `contour profile synthesize` | Reverse-engineer managed preference plists into validated mobileconfigs. |
| `contour profile import --jamf` | Import from [Jamf Pro backup](https://github.com/Jamf-Concepts/jamf-cli) YAML — extract, normalize, validate in one step. |
| `contour profile command` | Generate MDM command plist payloads (RestartDevice, DeviceLock, EraseDevice, …) with `--base64` for the Fleet API. |
| `contour profile enrollment` | Generate DEP/ADE enrollment profiles from Setup Assistant skip keys, platform/version-gated. |
| `contour osquery` | Search and inspect the embedded osquery schema for writing queries and policies. |
| [`contour pppc`](docs/contour-pppc.md) | Generate TCC/Privacy Preferences profiles from app bundles. Scan → configure → generate. |
| [`contour santa`](docs/contour-santa.md) | Santa allowlists, CEL toolkit (compile, eval, validate, dry-run, classify), and FAA plist generation. |
| [`contour mscp`](docs/contour-mscp.md) | mSCP baseline transformer with embedded schema query API and ODV support. |
| [`contour btm`](docs/contour-btm.md) | Generate Background Task Management profiles for managed login items. |
| [`contour notifications`](docs/contour-notifications.md) | Generate notification settings profiles with per-app control. |

Common commands:

```bash
# Normalize and validate profiles for GitOps
contour profile normalize ./profiles -r --org com.acme --name "Acme Corp"

# Import from Jamf backup
contour profile import --jamf /path/to/jamf-backup/profiles/macos/ --all -o profiles/ --org com.acme

# Synthesize mobileconfigs from managed preference plists
contour profile synthesize /Library/Managed\ Preferences/ -o profiles/ --org com.acme --validate

# Search + generate a profile
contour profile search passcode --json
contour profile generate com.apple.mobiledevice.passwordpolicy --full --org com.acme

# MDM command for Fleet API
contour profile command generate DeviceLock --set PIN=123456 --uuid --base64

# DEP enrollment profile
contour profile enrollment generate --platform macOS --interactive -o enrollment.dep.json

# Query mSCP compliance rules
contour mscp schema baselines --json
contour mscp schema rules --baseline cis_lvl1 --json

# PPPC profile
contour pppc scan -p /Applications -o pppc.toml --org com.acme
contour pppc generate pppc.toml -o pppc.mobileconfig

# Santa allowlist
contour santa scan -f csv -o apps.csv
contour santa allow -i apps.csv --org com.acme -o santa.mobileconfig
```

### As an AI skill

Because validation is baked into every generator, Contour is also safe to hand to an agent. Install it as a skill for Claude Code (and similar):

```bash
contour setup-agent
```

The agent gets the Apple schema, routed SOPs for each task, and a generator that refuses to write a broken file. You ask in plain English; the agent picks the right command and the tool keeps it honest.

```bash
contour help-ai                     # what the agent sees: command index + SOP routing
contour help-ai --sop profile       # profile generation SOP
contour help-ai --sop fleet-migrate # GitOps repo migration SOP
```

## Install

Download the latest `.pkg` from [Releases](https://github.com/headmin/contour/releases):

```bash
contour --help          # Overview of all tools
contour <tool> --help   # Tool-specific help
contour help-ai         # LLM-optimized help for AI-assisted workflows
```

The binary is signed + notarized by Apple, stapled for offline verification.

## Documentation

- [Profile Toolkit](docs/contour-profile.md) — normalize, validate, sign, diff, DDM declarations, payload extraction
- [PPPC Toolkit](docs/contour-pppc.md) — TCC services, interactive and batch configuration, CSV input
- [Santa Toolkit](docs/contour-santa.md) — rule management, multiple fetch sources, `prep` for full Santa deployment
- [mSCP Toolkit](docs/contour-mscp.md) — Fleet/Jamf/Munki output, ODV overrides, cross-baseline deduplication
- [BTM Toolkit](docs/contour-btm.md) — launch item scanning, DDM declarations (macOS 15+), multi-machine merge
- [Notifications Toolkit](docs/contour-notifications.md) — per-app alert control, interactive configuration wizard

## License

Apache-2.0
