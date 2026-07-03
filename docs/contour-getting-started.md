# Getting Started with contour

> **Status: Preview** — feature-complete for core workflows, APIs and flags may still change before 1.0.

`Contour` automates Apple device configuration creation and processing. Instead of hand-editing multiple `.mobileconfig` XML files, regenerating UUIDs, or managing DDM JSON by hand, Contour lets you batch-process them and even generate configs. Its recipe feature captures intent in concise TOML files, and Contour outputs schema-valid configuration profiles and DDM declaration files, formatted and ready for any MDM or GitOps workflow — including Fleet, Jamf Pro, and other device management systems. 

Build for Mac administrators and client platform engineers who treat Apple devices as code, this guide walks you from installation to generating your first profile.


## Install

contour ships as a signed + notarized macOS `.pkg`. Download the latest from
[Releases](https://github.com/macadmins/contour/releases), then:

```bash
sudo installer -pkg ~/Downloads/contour-<version>.pkg -target /
contour --version
```

The binary is signed with a Developer ID, notarized, and stapled, so it runs
without Gatekeeper prompts and verifies offline.

## Orientation

`contour` is an umbrella over several focused toolkits. Run `contour --help`
for the full list; the subcommands you'll use most:

| Command | What it does |
|---------|--------------|
| `profile` | Apple configuration profile toolkit — normalize, validate, sign, generate (incl. recipes & DDM) |
| `mscp` | macOS Security Compliance Project baseline → Fleet/Jamf/Munki output |
| `btm` | Background Task Management — managed login/service items (macOS 13+) |
| `notifications` | Per-app notification settings profiles |
| `pppc` | Privacy/PPPC (TCC) mobileconfig profiles from app bundles |
| `santa` | Santa binary-authorization mobileconfig profiles |
| `support` | Root3 Support App per-brand profiles |
| `osquery` | Offline osquery table/column schema reference |
| `init` | Initialize `.contour/config.toml` for this repository |
| `trainer` | Interactive, step-by-step guided workflows |
| `help-agents` (`help-ai`) | LLM-optimized CLI reference for AI-assisted workflows |
| `setup-agent` | Install the AI agent skill file (`.claude/skills/contour.md`) |
| `completions` | Shell completion install guide / installer / raw script |

Every command supports `--help` and `-v` (verbose), and accepts `--json`
(machine output, where applicable).

## Set up your project — `contour init`

Most workflows read shared defaults (organization identity, signing identity,
secret catalogue) from a `.contour/config.toml` at your repo root. Create one:

```bash
contour init
```

This records your reverse-domain `org` (the `PayloadIdentifier` prefix), an
optional signing identity, and more — so you don't repeat `--org` on every
command. See [contour-config.md](contour-config.md) for the full reference.

## Three starter workflows

### 1. Generate a profile from a built-in recipe

Recipes bundle tested settings into one command. List what ships, then render:

```bash
contour profile generate --list-recipes
contour profile generate --recipe crowdstrike --org com.acme -o ./profiles/
```

Recipes with placeholders take `--set KEY=VALUE` (secrets can be `op://…`
references). Go deep in [contour-recipes.md](contour-recipes.md).

### 2. Pre-approve TCC app privacy with PPPC profiles

The recurring two-step pattern — scan apps into an editable policy, then
generate the profile:

```bash
contour pppc scan -p /Applications -o pppc.toml --org com.acme
contour pppc configure pppc.toml          # tweak which services each app gets
contour pppc generate pppc.toml -o ./profiles/
```

### 3. Build a security baseline

Turn an mSCP baseline into a full GitOps ready tree with profiles, scripts, and
declarative-management artifacts:

```bash
contour mscp init --org com.acme --name "Acme Corp" --fleet --sync
contour mscp generate --mscp-repo ./macos_security --keyword cis_lvl1 \
  --output ./output --use-uv --fleet-mode --generate-ddm
contour mscp verify --output ./output
```

`--sync` clones the mSCP 2.0 repo (`main` branch); `--use-uv` runs the
Python toolchain `uv` [by astral](https://docs.astral.sh/uv/) as interpreter. Full pipeline in
[contour-mscp.md](contour-mscp.md).

## Why validation matters — schema, not vibes

Apple's MDM/DDM schema is full of details that human-language intent
doesn't survive. A few classes of surprise the schema captures and a
plain text prompt does not:

- **Legacy names freeze in place.** The key controlling biometric unlock
  is still `allowFingerprintForUnlock` (and `allowFingerprintModification`),
  even though it covers Touch ID, Face ID, and Optic ID. The 2013 naming
  is preserved for API stability. An agent told to "require Touch ID"
  could emit `TouchID = true` — a key that doesn't exist; Apple silently
  ignores it on the device.
- **Different concerns live in different payloads.** "Require 12+ char
  passcode and biometric unlock" spans two payloads:
  `com.apple.mobiledevice.passwordpolicy` for the complexity rules and
  `com.apple.applicationaccess` (Restrictions) for the biometric controls.
  There is no single "passcode" payload that does both.
- **Version-gated keys.** Some keys only exist on certain OS versions —
  introduced in 14.0, removed in 16.0, deprecated since 15.0. The schema
  carries that metadata; contour filters availability when you pass
  `--os-version`.
- **Supervision and scope constraints.** Many restrictions only take
  effect on supervised devices, or only in a `System`-scoped profile,
  or only when the device is in a specific MDM enrolment state.

Contour validates every field against the embedded Apple schema **before
writing**. An unknown key like `TouchID = true` is rejected at generate
time with a `SCHEMA_VIOLATION` error — not silently written into a
profile that ships and produces no effect on devices.

This matters most when an AI agent is driving. Without a schema check,
the agent produces plausible-looking config that fails silently in
production. With contour in the loop, the agent either uses a real key
or gets a fast, typed error it can recover from on the next attempt —
the failure surfaces at authoring time, not at MDM-push time, and not
at the user's device.

## Learn interactively — `contour trainer`

Prefer to be walked through it? `contour trainer` runs guided, step-by-step
workflows that print the exact commands as you go:

```bash
contour trainer
```

## Where to go next

| Guide | Covers |
|-------|--------|
| [contour.md](contour.md) | The umbrella binary — `init`, `trainer`, agents, completions |
| [contour-recipes.md](contour-recipes.md) | Recipes, DDM presets, and building a reusable library |
| [contour-profile.md](contour-profile.md) | Configuration profiles: normalize, validate, sign, secrets |
| [contour-pppc.md](contour-pppc.md) | Privacy/PPPC (TCC) profiles |
| [contour-santa.md](contour-santa.md) | Santa allowlists and binary authorization |
| [contour-mscp.md](contour-mscp.md) | mSCP baseline transformation (Fleet/Jamf/Munki) |
| [contour-btm.md](contour-btm.md) | Background Task Management service profiles |
| [contour-notifications.md](contour-notifications.md) | Per-app notification settings |
| [contour-config.md](contour-config.md) | `.contour/config.toml` shared configuration |
