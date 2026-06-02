<div align="center">

<img src="images/contour.png" alt="Contour" width="200">

# Contour

### Reshape the way Apple device configurations are managed. Schema, not vibes.

CLI for control, AI for intent. Ship consistent, declarative Apple configurations at scale.

</div>

**Contour brings order to Apple device configuration.**

Got profiles already? Drop them in. Contour normalizes, validates, signs, and diffs them in bulk and in parallel. The output is clean and deterministic: drops into any GitOps repo, works with any MDM.

Building new ones? Contour generates `.mobileconfig` profiles and Declarative Device Management (DDM) JSON declarations for every Apple platform: macOS, iOS, iPadOS, tvOS, watchOS, and visionOS.

Need it reusable? Capture intent in a small **recipe** TOML. Reference secrets from your vault; they resolve at generate time and never enter the repo. Re-run the recipe and you get the same artifact, every time.

Every artifact is checked against Apple's official device-management schema, embedded right in the binary. Whether you wrote the config or an AI agent did, what ships actually applies.

One signed and notarized binary. Use it in your terminal, in CI, or hand it to an AI agent. More details: [docs/contour.md](docs/contour.md).

## Quick Start

Download the latest signed + notarized `.pkg` from [Releases](https://github.com/macadmins/contour/releases), then:

```bash
sudo installer -pkg ~/Downloads/contour-<version>.pkg -target /
contour --help
```

### Use case 1: Postprocess existing profiles

The most common entry point. Contour standardizes identifiers, regenerates UUIDs deterministically, and validates against the embedded Apple schema. Works on a single file or a whole tree.

**Single file.** Quick fix-up of one profile:

```bash
contour profile normalize ./restrictions.mobileconfig --org com.acme --name "Acme Corp"
```

**Batch.** Process a directory recursively, in parallel, with a markdown report:

```bash
contour profile normalize ./profiles -r --org com.acme --name "Acme Corp" --report normalize.md
```

**What you get:** every profile consistently formatted, with the org identifier and name set throughout. No per-file sprawl. Everything tied to your org and shaped the same way.

- **One normalized `.mobileconfig` per input.** Identifiers prefixed with your `--org`, organization name set from `--name`, UUIDs regenerated deterministically, payload keys sorted, version tags fixed, MDM placeholders (`$VAR`, `{{var}}`, `%Var%`) preserved.
- **A markdown report** (`--report normalize.md`) with per-file pass/fail counts, every rule that fired, and citations to the Apple device-management spec each fix enforces. Drop it into a PR description so reviewers see exactly what changed.
- **A typed exit code.** `0` on success, non-zero on any validation failure. Add `--json` to parse the summary in CI; `--dry-run` previews without touching the filesystem.

Run normalize again on the same input and the bytes don't move. Diffs cleanly into a GitOps repo on every run.

### Use case 2: Generate new profiles

Either from a payload type, or from a reusable **recipe** TOML (with secrets resolved from a vault at generate time):

```bash
contour init                                                # one-time: write .contour/config.toml
contour profile search passcode --json                      # discover the payload type
contour profile generate com.apple.mobiledevice.passwordpolicy --full --org com.acme -o passcode.mobileconfig

# Or render a built-in recipe (reproducible, secret-aware). Bare name, no path needed:
contour profile generate --recipe restrictions --org com.acme -o restrictions.mobileconfig
# List all built-in recipes:
contour profile generate --list-recipes
```

**Have an existing `.mobileconfig`?** Import it once to a recipe TOML, then version-control the recipe and re-render forever:

```bash
contour profile library import ./Privileges.mobileconfig --into ./contour-presets
# Writes ./contour-presets/recipes/privileges.toml + a stub privileges.meaning.md.
# Round-trips: `contour profile generate --recipe privileges` reproduces the same payload.
```

**What you get:** schema-valid `.mobileconfig` files tied to your org, ready to ship to any MDM.

- **Generated from intent, not hand-edited XML.** The schema-driven generator fills in every required field, sets a stable PayloadIdentifier under your org, and emits a normalized plist that diffs cleanly.
- **Recipes are version-control friendly.** One small TOML captures what to ship; rerun produces a byte-identical profile. Secrets stay in your vault and resolve at generate time.
- **Round-trip importable.** An existing `.mobileconfig` becomes a recipe + a `.meaning.md` sidecar so reviewers know what the recipe is for.

### Use case 3: Hand it to an AI agent 

Any agent that can shell out can use Contour. Tell it where the binary is and to start with `help-ai` for command discovery. The `.pkg` installs to `/usr/local/bin/contour`:

**Profile (`.mobileconfig`).** The classic delivery path:

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

**DDM declaration (JSON).** The modern declarative path:

```text
You ▸ "Use /usr/local/bin/contour. Start with `contour help-ai --sop ddm` to
       learn the DDM workflow, then generate a DDM passcode declaration with
       the same policy (12+ chars, no simple passcodes) and save it to
       declarations/passcode.settings.json."

Agent does (autonomously):
  /usr/local/bin/contour help-ai --sop ddm                              # routed DDM SOP
  /usr/local/bin/contour profile ddm search passcode --json             # discover the declaration type
  /usr/local/bin/contour profile ddm info passcode.settings --json      # inspect schema
  /usr/local/bin/contour profile ddm generate passcode.settings --full \
      --org com.acme -o declarations/passcode.settings.json
  /usr/local/bin/contour profile ddm validate declarations/passcode.settings.json
```

**Batch normalize (a CIS baseline).** Postprocess and validate an existing profile tree:

```text
You ▸ "Use /usr/local/bin/contour. Read `contour help-ai --sop profile` first.
       Then normalize every profile in ./profiles whose filename starts with
       'CIS_': set --org com.acme, regenerate UUIDs deterministically, validate
       each one. Save a markdown report and tell me which files failed."

Agent does (autonomously):
  /usr/local/bin/contour help-ai --sop profile           # routed procedural SOP
  ls ./profiles/CIS_*.mobileconfig                       # confirm the input set
  /usr/local/bin/contour profile normalize ./profiles/CIS_*.mobileconfig \
      --org com.acme --name "Acme Corp" \
      --report cis-normalize.md --json
  # parses the JSON summary; surfaces any non-zero `failed` count back to you
```

**What you get:** a valid profile or DDM declaration the agent built under schema constraints, plus a fast and predictable agent loop.

- **Schema-bound output.** The generator refuses to write anything that doesn't match Apple's schema, so an agent cannot accidentally ship a broken key or invented field.
- **No remote fetches, no token burn.** The entire Apple MDM/DDM schema lives in the binary. The agent reads only the slice it asks for via `help-ai`. No MCP orchestration, no large context dumps, no flaky web round-trips.
- **Fast, offline-capable, repeatable.** Same prompt, same commands, same artifact. Works the same on a laptop, in CI, or on an air-gapped build host.

For a tighter, Claude-Code-specific integration with embedded SOP routing, install the skill: `contour setup-agent`.

Full walk-through with examples for each toolkit: [docs/contour-getting-started.md](docs/contour-getting-started.md).

## Repository Layout

- [docs](docs): public documentation, one file per toolkit, plus recipes and getting-started guides.
- [crates](crates): Rust workspace source.
- [docs/examples](docs/examples): sample inputs (rules, baselines, recipes, presets).
- [scripts](scripts): local CI parity check and release build script.
- [crates/contour-core/skills/contour](crates/contour-core/skills/contour): embedded Claude Code skill (also installable via `contour setup-agent`).

## Toolkits

Each toolkit is a subcommand of `contour`, with its own focused guide.

| Subcommand | Guide |
|---|---|
| `contour profile`: `.mobileconfig`, DDM, recipes, MDM commands, ADE enrollment | [contour-profile.md](docs/contour-profile.md) |
| `contour santa`: Santa allowlists, CEL, FAA, ring editions, baseline merge | [contour-santa.md](docs/contour-santa.md) |
| `contour pppc`: Privacy/TCC profiles from app bundles | [contour-pppc.md](docs/contour-pppc.md) |
| `contour mscp`: macOS Security Compliance Project baselines | [contour-mscp.md](docs/contour-mscp.md) |
| `contour btm`: Background Task Management service profiles | [contour-btm.md](docs/contour-btm.md) |
| `contour notifications`: Per-app notification settings | [contour-notifications.md](docs/contour-notifications.md) |
| `contour osquery`: Embedded osquery schema reference | — |

The umbrella binary, the standalone commands (`init`, `setup-agent`, `help-ai`, …), and shared configuration are documented in [contour.md](docs/contour.md) and [contour-config.md](docs/contour-config.md).

## AI agent integration

Contour is a CLI, not an MCP server. The agent invokes contour with a selector and receives exactly the schema slice it asked for. The Apple MDM/DDM schema lives inside the binary, so an agent never re-fetches the same reference data over the network and never pays tokens to keep it pinned in context. No MCP orchestration, no large context dump, no flaky web round-trips. Validation is baked into every generator, so an agent cannot ship a broken profile. Full details: [docs/contour.md#ai-agent-integration](docs/contour.md#ai-agent-integration).

## Builds

Release builds (signed + notarized `.pkg`) are produced by GitHub Actions; the local equivalent is [scripts/build-release.sh](scripts/build-release.sh). For CI-parity checks before pushing, [scripts/ci-check.sh](scripts/ci-check.sh).

## License

Apache-2.0.
