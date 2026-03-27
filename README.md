<p align="center">
  <img src="images/contour.png" alt="Contour" width="200">
</p>

# Contour

**The Swiss Army Knife for Apple Device Management Profiles**

One binary, multiple tools. A Mac admin's special tooling to slice and dice configuration profiles, validate, unsign/sign, and prepare them for MDM migration and GitOps work — start transforming existing profiles and create new ones.

## Tools

| Tool | Description |
|------|-------------|
| [`contour profile`](docs/contour-profile.md) | Normalize, validate, sign, diff, and inspect Apple configuration profiles. 180+ payload schemas embedded. |
| [`contour pppc`](docs/contour-pppc.md) | Generate TCC/Privacy Preferences profiles from app bundles. Scan → configure → generate workflow. |
| [`contour santa`](docs/contour-santa.md) | Build Santa allowlists and mobileconfig profiles. Scan, merge, fetch from Installomator/Fleet/osquery. |
| [`contour mscp`](docs/contour-mscp.md) | Transform macOS Security Compliance Project baselines into MDM-ready profiles and scripts. |
| [`contour btm`](docs/contour-btm.md) | Generate Background Task Management (service management) profiles for managed login items. |
| [`contour notifications`](docs/contour-notifications.md) | Generate notification settings profiles with per-app control. |

## Highlights

- **GitOps-ready** — Every tool follows `init → scan → generate`. Version-control your configs, generate profiles in CI.
- **Fragment output** — `--fragment` prepares for Fleet GitOps directory structures.
- **LLM-friendly** — `contour help-ai` provides progressive discovery for AI-agent-assisted workflows.
- **One binary** — All tools ship as a single `contour` binary (22 MB, native ARM64).

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

# Generate a PPPC profile granting Full Disk Access
contour pppc -p /Applications --service fda -o pppc.mobileconfig --org com.acme

# Scan local apps and generate a Santa allowlist
contour santa scan --output-format mobileconfig --org com.acme -o santa-rules.mobileconfig

# Transform mSCP baselines for Fleet
contour mscp init --org com.acme --fleet --sync --baselines cis_lvl1
contour mscp generate-all -c mscp.toml

# Generate managed login items profile from installed launch daemons
contour btm scan --mode launch-items --org com.acme -o btm.toml
contour btm generate btm.toml -o btm.mobileconfig

# Configure notification settings
contour notifications scan -p /Applications -o notifications.toml --org com.acme
contour notifications generate notifications.toml --combined -o notifications.mobileconfig
```

## Usage

```bash
contour --help          # Overview of all tools
contour <tool> --help   # Tool-specific help
contour help-llm        # LLM-optimized help for AI-assisted workflows
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
