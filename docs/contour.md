# contour -- Apple Device Management Toolkit

> **Status: Preview** — feature-complete for core workflows; APIs and flags may still change before 1.0.

`contour` is a single binary that bundles a family of toolkits for Apple
(and cross-platform) device management — configuration profiles, Santa,
PPPC/TCC, mSCP baselines, Background Task Management, notifications, and
more. Each toolkit is a subcommand with its own documentation; this page
covers the umbrella binary and the standalone, non-toolkit commands.

## Toolkits

Each toolkit has a dedicated guide:

| Subcommand | Toolkit | Guide |
|---|---|---|
| `contour profile` | Apple configuration profiles (`.mobileconfig`), DDM, recipes | [contour-profile.md](contour-profile.md) |
| `contour pppc` | Privacy Preferences Policy Control (TCC) | [contour-pppc.md](contour-pppc.md) |
| `contour santa` | Santa allowlists / binary authorization | [contour-santa.md](contour-santa.md) |
| `contour mscp` | macOS Security Compliance Project baselines | [contour-mscp.md](contour-mscp.md) |
| `contour btm` | Background Task Management service profiles | [contour-btm.md](contour-btm.md) |
| `contour notifications` | Per-app notification settings | [contour-notifications.md](contour-notifications.md) |
| `contour osquery` | Query the embedded osquery schema | — |
| `contour support` | Root3 Support App profile generator | — |

Shared configuration for all toolkits lives in `.contour/config.toml` —
see [contour-config.md](contour-config.md).

## Standalone commands

### `contour init`

Interactive wizard that creates `.contour/config.toml` — the shared,
repo-level config every toolkit reads.

```
contour init [PATH] [flags]
```

| Flag | Description | Default |
|---|---|---|
| `[PATH]` | Repository root | current directory |
| `--name <NAME>` | Organization name | prompted |
| `--domain <DOMAIN>` | Reverse-DNS domain (e.g. `com.acme`) | prompted / derived |
| `--server-url <URL>` | MDM server URL | prompted |
| `--platforms <LIST>` | Comma-separated platforms (`macos,ios,…`) | prompted |
| `--deterministic-uuids <BOOL>` | Reproducible UUIDs for GitOps | prompted |
| `--library-path <DIR>` | Default preset/recipe library directory | prompted |
| `--mdm <FLAVOUR>` | MDM platform — `fleet`, `jamf`, or `apple` | prompted |
| `-y, --yes` | Non-interactive (use flags/defaults, no prompts) | `false` |

`--mdm` writes the `[mdm_variables]` section: `mdm = "<flavour>"` is set,
and that platform's variable catalogue is written as a commented
`# [mdm_variables.pool]` template ready to uncomment. In interactive
mode the wizard asks for the platform if `--mdm` is not given.

```bash
# Interactive
contour init

# Non-interactive, with the Fleet variable template
contour init --domain com.acme --name "Acme" --mdm fleet --yes
```

### `contour trainer`

Interactive, step-by-step training mode for a chosen toolkit.

```bash
contour trainer santa     # also: pppc | mscp | profile | btm | config
```

### `contour help-agents` (alias `help-ai`)

Prints a CLI reference optimized for AI agents — a command index, or
full detail for one command via `--command <dotted.name>`.

```bash
contour help-agents
contour help-agents --command santa.add
```

### `contour setup-agent`

Installs the contour skill file for Claude Code so an agent can drive
contour with the documented conventions.

### `contour help-json`

Emits the CLI surface as JSON — for tooling that needs a machine-readable
command/flag schema.

### `contour completions`

Sets up shell tab-completion. Supports **zsh**, **bash**, and **fish**.

```
contour completions [SHELL] [--install] [--script]
```

| Form | What it does |
|---|---|
| `contour completions` | Detects the current shell from `$SHELL`, lets you confirm/pick, then prints the install guide |
| `contour completions <shell>` | Prints a per-shell install guide — where the file goes, the rc line, how to reload |
| `contour completions <shell> --install` | Writes the completion file to its conventional location and prints any one-time rc setup |
| `contour completions <shell> --script` | Emits only the raw completion script to stdout, for piping or packaging |

```bash
# Detect shell, print a tailored guide
contour completions

# Install directly
contour completions zsh --install

# Manual / packaging — raw script
contour completions fish --script > ~/.config/fish/completions/contour.fish
```

`--install` targets `~/.zfunc/_contour` (zsh), `~/.bash_completion.d/contour`
(bash), or `~/.config/fish/completions/contour.fish` (fish). zsh and bash
need a one-time rc line (printed after install); fish auto-loads its
completions directory.

## Global flags

| Flag | Description |
|---|---|
| `-v, --verbose` | Verbose logging |
| `--json` | JSON output for CI/CD integration |
| `--version` | Version, build timestamp, and license |
| `--help` | Help for any command |
