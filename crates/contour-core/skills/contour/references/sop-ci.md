# SOP: GitHub Actions & CI Setup for contour

Wire contour into a GitHub Actions workflow so profile generation,
validation, and MDM-side deployment run consistently in CI. This SOP
is a **hybrid**: the bulk is configuration recipes (env vars, workflow
snippets, secrets vs. variables), with one small procedural block for
the bootstrap step that has unambiguous preconditions.

The full-workflow example below uses Fleet's GitOps `gitops.sh` as the
deploy step because it has a stable env-var contract and is widely
deployed; the same pattern applies to any MDM that exposes a
shell-callable apply script (Jamf, Kandji, etc.) — substitute the
deploy step and its env vars accordingly.

For the developer-side mirror of this (catch the same errors at commit
time), see `--sop precommit`.

---

## Environment variables (the contract)

contour reads these env vars as fallbacks when CLI flags are not provided:

| Variable | Purpose | Required |
|---|---|---|
| `CONTOUR_ORG` | Organization reverse-DNS (e.g. `com.acme`) | Yes for any profile/DDM generation |
| `CONTOUR_NAME` | Display name (sets `PayloadOrganization`) | Optional |

**Resolution order** (per `crates/contour-core/src/config.rs::resolve_org`):

```
1. --org / --name CLI flag
2. CONTOUR_ORG / CONTOUR_NAME env var
3. .contour/config.toml in cwd or any ancestor
4. organization.domain in profile.toml
5. error (org) or empty (name)
```

For DDM `compose` and `generate` specifically, the same fallback chain
applies — confirmed in `contour-core::config::resolve_org_domain` and
pinned by `trap_40` in `sop_traps.rs`.

---

## Repo wiring contract

Before the workflow can run, the repo needs the right keys registered
in the right place. Use whatever tool you prefer (GitHub UI, `gh` CLI,
Terraform) — only the contract below matters.

| Key | Kind | Why |
|---|---|---|
| `CONTOUR_ORG` | repository **variable** | reverse-DNS organization (e.g. `com.yourcompany`); appears in CI logs unredacted regardless, so making it a secret buys nothing |
| `CONTOUR_NAME` | repository **variable** (optional) | display name for `PayloadOrganization` |
| MDM URL (e.g. `FLEET_URL`) | repository **variable** or **secret** depending on sensitivity | API endpoint your apply step calls |
| MDM API token (e.g. `FLEET_API_TOKEN`) | repository **secret** | grants write access; never log, never put in a variable |

**Validation rules** the agent should enforce when configuring or auditing:

- `CONTOUR_ORG` must match `^[a-z0-9-]+(\.[a-z0-9-]+)+$` — reverse-DNS only.
- `CONTOUR_ORG` must not be `com.example` — that produces invalid output that has to be redone.
- The MDM API token must be registered as a **secret**, not a variable.
- `CONTOUR_ORG` and `CONTOUR_NAME` must be **variables**, not secrets.

These are the load-bearing rules — the rest of CI setup is YAML
configuration that doesn't have meaningful "fail fast" preconditions,
just text. Most teams set up the keys once via the GitHub UI or their
IaC of choice, then never touch them.

---

## Workflow recipes

### Install contour in a job

```yaml
- name: Install contour
  run: |
    curl -fsSL -o contour.pkg \
      https://github.com/macadmins/contour/releases/latest/download/contour-*.pkg
    sudo installer -pkg contour.pkg -target /
    contour --version
```

For pinned versions (recommended in production CI):

```yaml
- name: Install contour 0.2.0
  run: |
    curl -fsSL -o contour.pkg \
      https://github.com/macadmins/contour/releases/download/v0.2.0/contour-0.2.0.pkg
    sudo installer -pkg contour.pkg -target /
```

### Generate / validate profiles using env vars

```yaml
- name: Generate and validate profiles
  env:
    CONTOUR_ORG:  ${{ vars.CONTOUR_ORG }}
    CONTOUR_NAME: ${{ vars.CONTOUR_NAME }}
  run: |
    contour profile generate com.apple.mobiledevice.passwordpolicy \
        --full -o platforms/macos/configuration-profiles/passcode.mobileconfig
    contour profile import --jamf ./jamf-backup/profiles/macos/ \
        --all -o platforms/macos/configuration-profiles/
    contour profile validate platforms/macos/configuration-profiles/ \
        --recursive --json
```

`vars.X` reads a repository variable; `secrets.X` reads a secret. Use
the right one per the INVARIANTS above.

### DDM compose in CI

```yaml
- name: Compose DDM bundles
  env:
    CONTOUR_ORG: ${{ vars.CONTOUR_ORG }}
  run: |
    for bundle in ddm-bundles/*.toml; do
      contour profile ddm compose "$bundle" \
          -o platforms/macos/declaration-profiles/ --json
    done
    contour profile ddm verify platforms/macos/declaration-profiles --json
```

### Full workflow (Fleet GitOps shown as the deploy step)

The example apply step calls Fleet's `gitops.sh`; for other MDMs,
substitute your vendor's apply script and its env-var contract.

```yaml
name: MDM GitOps
on:
  push:        { branches: [main] }
  pull_request: { branches: [main] }
  schedule:    [cron: '0 6 * * *']     # nightly drift detection
  workflow_dispatch: {}

env:
  CONTOUR_ORG:     ${{ vars.CONTOUR_ORG }}
  CONTOUR_NAME:    ${{ vars.CONTOUR_NAME }}
  # Fleet-specific env vars below — substitute for your MDM.
  FLEET_URL:       ${{ secrets.FLEET_URL }}
  FLEET_API_TOKEN: ${{ secrets.FLEET_API_TOKEN }}
  FLEET_DRY_RUN_ONLY: ${{ github.event_name == 'pull_request' }}

jobs:
  apply:
    runs-on: macos-latest                 # macOS runner — contour signs/validates plists
    steps:
      - uses: actions/checkout@v4

      - name: Install contour
        run: |
          curl -fsSL -o contour.pkg \
            https://github.com/macadmins/contour/releases/latest/download/contour-*.pkg
          sudo installer -pkg contour.pkg -target /

      - name: Validate every staged artifact
        run: |
          contour profile validate platforms/macos/configuration-profiles/ \
              --recursive --json
          contour profile ddm validate platforms/macos/declaration-profiles/ \
              --json
          contour profile ddm verify platforms/macos/declaration-profiles \
              --json

      - name: Apply (Fleet example)
        run: ./.github/fleet-gitops/gitops.sh
        # For other MDMs, swap this for your vendor's apply script.
```

The PR trigger sets `FLEET_DRY_RUN_ONLY=true` (read by Fleet's
`gitops.sh`), so PRs only validate without applying. Push-to-main
applies for real. Your MDM's apply script likely has an equivalent
dry-run flag — wire it the same way.

### Claude Code in GitHub Actions

If you're using Claude Code in CI (e.g. for issue-driven profile
generation), wire contour's agent skills:

```yaml
- name: Bootstrap contour agent context
  env:
    CONTOUR_ORG: ${{ vars.CONTOUR_ORG }}
  run: |
    sudo installer -pkg contour.pkg -target /
    # init-skill pins the org into the skill so agents never hit com.example.
    # --yes is required in CI (no TTY to prompt). `setup-agent` is the alias.
    contour init-skill --org "$CONTOUR_ORG" --yes   # writes CLAUDE.md + .claude/skills/
```

This makes the SOPs (`--sop profile`, `--sop ddm`, etc.) discoverable
by Claude Code in the CI environment.

In your `.github/workflows/claude.yml`, allow contour invocations:

```yaml
allowed_tools:
  - Bash(contour *)
```

---

## Patterns that have bitten people

| Symptom | Cause | Fix |
|---|---|---|
| `INVALID_ORG` from `ddm compose`/`generate` in CI | `CONTOUR_ORG` set as a secret instead of variable, or not set at all | Move to repository variable; verify it's listed under variables, not secrets |
| Profiles generate with `com.example` identifiers | `CONTOUR_ORG` is unset and the runner has no `.contour/config.toml` | Set the variable; or commit `.contour/config.toml` to the repo |
| Fleet's `gitops.sh` deletes a fleet you wanted to keep | `FLEET_DELETE_OTHER_FLEETS=true` (the default) and the fleet's YAML is missing from `fleets/` | Add the fleet YAML, or set `FLEET_DELETE_OTHER_FLEETS=false` for that run. Other MDMs' apply scripts have equivalent destructive defaults — read your vendor's docs. |
| Profiles regenerate with churn on every CI run | Old contour version (pre-`cdeed17`) — recipe field iteration was non-deterministic | Upgrade contour; the fix landed via HashMap → BTreeMap |
| `ddm verify` complains about unsubscribed status keys | Predicate references `@status('foo')` but no `status-subscriptions` declaration covers it | Use `compose` with `[subscriptions]` (see `--sop ddm`); the SOP enforces this at authoring time |

---

## Why this SOP is hybrid (not fully procedural)

- The **bootstrap** (variables, secrets, repo wiring) IS procedural —
  there's a clear order, typed errors, and verifiable postconditions.
  That's the `configure_ci` block above.
- The **workflow YAML** is configuration. Trying to express "every
  possible workflow shape" as a procedure produces worse output than
  showing the canonical patterns and letting the user pick.

The two halves complement each other: run the procedure once to wire
the repo, then copy the workflow recipes for the specific jobs you
need.

---

## Reference

- contour env-var resolution: `crates/contour-core/src/config.rs::resolve_org`
- DDM-handler env-var fix: commit `8dc7e05` (CONTOUR_ORG honoured in `ddm generate` + `compose`)
- Trap pinning the env-var path: `trap_40_ddm_compose_honors_contour_org_env`
- Fleet GitOps deploy script (used as the example apply step):
  `fleet/cmd/fleetctl/fleetctl/templates/new/.github/fleet-gitops/gitops.sh`
- Fleet GitOps schema (vendor-specific reference):
  `fleet/docs/Configuration/yaml-files.md`
- For other MDMs (Jamf, Kandji, …), see your vendor's deploy-script docs
  and substitute the apply step + secrets accordingly.
