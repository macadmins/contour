<div align="center">

<img src="images/contour.png" alt="Contour" width="200">

# Contour

### Reshape the way Apple device configurations are managed. Schema, not vibes.

CLI for control, AI for intent — ship consistent, declarative Apple configurations at scale.

</div>

> **Status: Preview** — feature-complete for core workflows; APIs and flags may still change before 1.0.

Contour works with your **existing** profiles first — normalize, validate, sign, and diff them in bulk and in parallel. Postprocessing produces consistent, deterministic formatting that diffs cleanly into a GitOps repo and stays portable across any MDM. As another use case Contour also generates new `.mobileconfig` profiles and Declarative Device Management (DDM) JSON declarations for macOS, iOS, iPadOS, tvOS, watchOS, and visionOS. A built-in **recipe** feature keeps generation organized: describe intent and config in a small TOML file, reference secrets from a vault (resolved at generate time, never committed), then re-run the recipe to produce the same artifact every time.

Every artifact — whether postprocessed or freshly generated — is validated against Apple's official device-management schema, embedded directly in the binary. Neither you nor an AI agent can ship config that won't apply.

One signed + notarized binary. Use it as a CLI in terminals and CI, or install it as a AI agent skill so an LLM can drive it under schema constraints. Background on the design and the validation model lives in [docs/contour.md](docs/contour.md).

## Quick Start

Download the latest signed + notarized `.pkg` from [Releases](https://github.com/macadmins/contour/releases), then:

```bash
sudo installer -pkg ~/Downloads/contour-<version>.pkg -target /
contour --help
```

### Use case 1 — Postprocess existing profiles

The most common entry point. Contour standardizes identifiers, regenerates UUIDs deterministically, and validates against the embedded Apple schema. Works on a single file or a whole tree.

**Single file** — quick fix-up of one profile:

```bash
contour profile normalize ./restrictions.mobileconfig --org com.acme --name "Acme Corp"
```

**Batch** — process a directory recursively, in parallel, with a markdown report:

```bash
contour profile normalize ./profiles -r --org com.acme --name "Acme Corp" --report normalize.md
```

`--dry-run` previews without writing; `--json` emits a CI-friendly summary. Output diffs cleanly into a GitOps repo on every run.

### Use case 2 — Generate new profiles

Either from a payload type, or from a reusable **recipe** TOML (with secrets resolved from a vault at generate time):

```bash
contour init                                                # one-time: write .contour/config.toml
contour profile search passcode --json                      # discover the payload type
contour profile generate com.apple.mobiledevice.passwordpolicy --full --org com.acme -o passcode.mobileconfig

# Or render a recipe (reproducible, secret-aware):
contour profile generate --recipe ./recipes/passcode.toml --org com.acme -o passcode.mobileconfig
```

### Use case 3 — Hand it to an AI agent (no install required)

Any agent that can shell out can use Contour — tell it where the binary is and to start with `help-ai` for command discovery. The `.pkg` installs to `/usr/local/bin/contour`:

**Profile (`.mobileconfig`) — the classic delivery path:**

```text
You ▸ "Use /usr/local/bin/contour. Start with `contour help-ai --sop profile` to
       learn the workflow, then generate a passcode policy profile for com.acme
       requiring 12+ chars and no simple passcodes (e.g., '1234'). Validate it
       and save to profiles/passcode.mobileconfig."

Agent does (autonomously):
  /usr/local/bin/contour help-ai --sop profile           # routed procedural SOP
  /usr/local/bin/contour profile search passcode --json  # discover the payload type
  /usr/local/bin/contour profile generate com.apple.mobiledevice.passwordpolicy \
      --set "minLength=12" --set "allowSimple=false" \
      --full --org com.acme -o profiles/passcode.mobileconfig
  /usr/local/bin/contour profile validate profiles/passcode.mobileconfig
```

**DDM declaration (JSON) — the modern declarative path:**

```text
You ▸ "Use /usr/local/bin/contour. Start with `contour help-ai --sop ddm` to
       learn the DDM workflow, then generate a DDM passcode declaration with
       the same policy (12+ chars, no simple passcodes) and save it to
       declarations/passcode.settings.json."

Agent does (autonomously):
  /usr/local/bin/contour help-ai --sop ddm                              # routed DDM SOP
  /usr/local/bin/contour profile ddm list | grep -i passcode            # find the type
  /usr/local/bin/contour profile ddm info passcode.settings --json      # inspect schema
  /usr/local/bin/contour profile ddm generate passcode.settings --full \
      -o declarations/passcode.settings.json
  /usr/local/bin/contour profile ddm validate declarations/passcode.settings.json
```

The agent reads only the schema slice it asked for, picks the right payload, and the generator refuses to write anything that wouldn't apply. Because the entire Apple MDM/DDM schema is embedded in the binary, there are no remote fetches, no large context dumps, and no tokens wasted re-discovering the same payload catalog on every run — fast, offline-capable, and predictable. For a tighter, Claude-Code-specific integration with embedded SOP routing, install the skill: `contour setup-agent`.

Full walk-through with examples for each toolkit: [docs/contour-getting-started.md](docs/contour-getting-started.md).

## Repository Layout

- [docs](docs) — public documentation, one file per toolkit, plus recipes and getting-started guides.
- [crates](crates) — Rust workspace source.
- [docs/examples](docs/examples) — sample inputs (rules, baselines, recipes, presets).
- [scripts](scripts) — local CI parity check and release build script.
- [crates/contour-core/skills/contour](crates/contour-core/skills/contour) — embedded Claude Code skill (also installable via `contour setup-agent`).

## Toolkits

Each toolkit is a subcommand of `contour`, with its own focused guide.

| Subcommand | Guide |
|---|---|
| `contour profile` — `.mobileconfig`, DDM, recipes, MDM commands, ADE enrollment | [contour-profile.md](docs/contour-profile.md) |
| `contour santa` — Santa allowlists, CEL, FAA, ring editions, baseline merge | [contour-santa.md](docs/contour-santa.md) |
| `contour pppc` — Privacy/TCC profiles from app bundles | [contour-pppc.md](docs/contour-pppc.md) |
| `contour mscp` — macOS Security Compliance Project baselines | [contour-mscp.md](docs/contour-mscp.md) |
| `contour btm` — Background Task Management service profiles | [contour-btm.md](docs/contour-btm.md) |
| `contour notifications` — Per-app notification settings | [contour-notifications.md](docs/contour-notifications.md) |
| `contour osquery` — Embedded osquery schema reference | — |

The umbrella binary, the standalone commands (`init`, `setup-agent`, `help-ai`, …), and shared configuration are documented in [contour.md](docs/contour.md) and [contour-config.md](docs/contour-config.md).

## AI agent integration

Contour is a CLI, not an MCP server — the agent invokes contour with a selector and receives exactly the schema slice it asked for. The Apple MDM/DDM schema lives inside the binary, so an agent never re-fetches the same reference data over the network and never pays tokens to keep it pinned in context. No MCP orchestration, no large context dump, no flaky web round-trips. Validation is baked into every generator, so an agent cannot ship a broken profile. Full details: [docs/contour.md#ai-agent-integration](docs/contour.md#ai-agent-integration).

## Build from source

```bash
cargo build --release -p contour
./target/release/contour --help
```

Release builds (signed + notarized `.pkg`) are produced by GitHub Actions; the local equivalent is [scripts/build-release.sh](scripts/build-release.sh). For CI-parity checks before pushing, [scripts/ci-check.sh](scripts/ci-check.sh).

## License

Apache-2.0.
