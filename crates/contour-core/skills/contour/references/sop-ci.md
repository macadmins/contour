# SOP: GitHub Actions & CI Setup for contour

Wire contour into a GitHub Actions workflow so profile generation,
validation, and Fleet GitOps deployment run consistently in CI. This
SOP is a **hybrid**: the bulk is configuration recipes (env vars,
workflow snippets, secrets vs. variables), with one small procedural
block for the bootstrap step that has unambiguous preconditions.

For the developer-side mirror of this (catch the same errors at commit
time), see `--sop precommit`.

---

## Environment variables (the contract)

contour reads these env vars as fallbacks when CLI flags are not provided:

| Variable | Purpose | Required |
|---|---|---|
| `CONTOUR_ORG` | Organization reverse-DNS (e.g. `com.fleetdm`) | Yes for any profile/DDM generation |
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

## PROCEDURE configure_ci(repo_owner, repo_name, contour_org, contour_name)

```
SCHEMA_TOOL: gh repo view {repo_owner}/{repo_name}
             gh variable list --repo {repo_owner}/{repo_name}
             gh secret list --repo {repo_owner}/{repo_name}

INPUT:
  repo_owner    : GitHub org/user owning the GitOps repo (e.g. "yourorg")
  repo_name     : repo name (e.g. "fleet-gitops")
  contour_org   : reverse-DNS organization (e.g. "com.yourcompany")
  contour_name  : optional display name (e.g. "Your Company Inc.")

PRECONDITIONS:
  ASSERT gh CLI authenticated
    HALT "run `gh auth login` first"
  ASSERT contour_org matches /^[a-z0-9-]+(\.[a-z0-9-]+)+$/
    HALT "contour_org must be reverse-DNS (a-z 0-9 . -); got '{contour_org}'"
  ASSERT contour_org != "com.example"
    HALT "refusing default 'com.example' — set the real org domain"

STEP 1 — Set repository VARIABLES (NOT secrets — these are not sensitive):
  gh variable set CONTOUR_ORG  --repo {repo_owner}/{repo_name} --body '{contour_org}'
  if contour_name is provided:
    gh variable set CONTOUR_NAME --repo {repo_owner}/{repo_name} --body '{contour_name}'

STEP 2 — Set the Fleet-side SECRETS (sensitive — these go in secrets):
  echo "$FLEET_URL"       | gh secret set FLEET_URL       --repo {repo_owner}/{repo_name}
  echo "$FLEET_API_TOKEN" | gh secret set FLEET_API_TOKEN --repo {repo_owner}/{repo_name}

STEP 3 — Verify wiring:
  gh variable list --repo {repo_owner}/{repo_name} | grep -E '^CONTOUR_(ORG|NAME)\s'
  gh secret   list --repo {repo_owner}/{repo_name} | grep -E '^FLEET_(URL|API_TOKEN)\s'
  ASSERT both lists contain the expected entries
    HALT "{name} not registered — re-run STEP 1/2 or check `gh auth status`"

INVARIANTS:
  # CONTOUR_ORG/CONTOUR_NAME are repository VARIABLES, not secrets — they
  # appear in the Fleet GitOps output unredacted, so encrypting them
  # buys nothing and just makes debugging harder.
  ASSERT CONTOUR_ORG  is registered as a variable, not a secret
  ASSERT CONTOUR_NAME is registered as a variable, not a secret

  # FLEET_API_TOKEN is sensitive — must be a secret.
  ASSERT FLEET_API_TOKEN is registered as a secret, not a variable

POSTCONDITIONS:
  RETURN {
    repo: "{repo_owner}/{repo_name}",
    variables: ["CONTOUR_ORG", "CONTOUR_NAME"?],
    secrets:   ["FLEET_URL", "FLEET_API_TOKEN"],
  }
```

This procedural block is small because the rest of CI setup is YAML
configuration that doesn't have meaningful "fail fast" preconditions —
it's just text.

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

### Fleet GitOps + contour (full workflow)

```yaml
name: Fleet GitOps
on:
  push:        { branches: [main] }
  pull_request: { branches: [main] }
  schedule:    [cron: '0 6 * * *']     # nightly drift detection
  workflow_dispatch: {}

env:
  CONTOUR_ORG:     ${{ vars.CONTOUR_ORG }}
  CONTOUR_NAME:    ${{ vars.CONTOUR_NAME }}
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

      - name: Apply Fleet GitOps
        run: ./.github/fleet-gitops/gitops.sh
```

The PR trigger sets `FLEET_DRY_RUN_ONLY=true` (read by `gitops.sh`), so
PRs only validate without applying. Push-to-main applies for real.

### Claude Code in GitHub Actions

If you're using Claude Code in CI (e.g. for issue-driven profile
generation), wire contour's agent skills:

```yaml
- name: Bootstrap contour agent context
  env:
    CONTOUR_ORG: ${{ vars.CONTOUR_ORG }}
  run: |
    sudo installer -pkg contour.pkg -target /
    contour setup-agent          # writes CLAUDE.md + .claude/skills/
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
| `INVALID_ORG` from `ddm compose`/`generate` in CI | `CONTOUR_ORG` set as a secret instead of variable, or not set at all | Move to repository variable; check `gh variable list` |
| Profiles generate with `com.example` identifiers | `CONTOUR_ORG` is unset and the runner has no `.contour/config.toml` | Set the variable; or commit `.contour/config.toml` to the repo |
| `gitops.sh` deletes a fleet you wanted to keep | `FLEET_DELETE_OTHER_FLEETS=true` (the default) and the fleet is missing from `fleets/` | Add the fleet YAML, or set `FLEET_DELETE_OTHER_FLEETS=false` for that run |
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
- Fleet's `gitops.sh` env-var contract: `fleet/cmd/fleetctl/fleetctl/templates/new/.github/fleet-gitops/gitops.sh`
- Fleet GitOps schema: `fleet/docs/Configuration/yaml-files.md`
