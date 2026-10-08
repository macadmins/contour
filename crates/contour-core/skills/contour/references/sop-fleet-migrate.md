# SOP: Migrate a Fleet GitOps Repo to v4.83 Structure

A **one-time migration playbook**, driven by a human who eyeballs each diff.
Goal: take a legacy (`lib/`) or v4.82 (flat `platforms/`, `macos_settings`)
repo to the structure `fleetctl new` scaffolds today (validated against
fleetctl v4.84.2 and `fleet/docs/Configuration/yaml-files.md`).

On **v4.82** already (flat `platforms/`)? Most steps are no-ops; do the
YAML-key and DDM-separation work in steps 4–5.

## Hard rules (don't drop these)

- **DDM declarations live in `platforms/<os>/declaration-profiles/`**, not
  in `configuration-profiles/`.
- **`controls.apple_settings.configuration_profiles` defaults to `paths:` globs**.
  Use per-file `path:` when one profile needs `labels_include_all`,
  `labels_include_any`, or `labels_exclude_any` filtering.
- **`scripts:` is nested under `controls:`**, but **`reports:` and `policies:`
  are TOP-LEVEL fleet keys** — not under `controls`.
- **`fleets/` is the directory** (NOT `teams/`); **`unassigned.yml`** is the
  no-fleet bucket file (NOT `no-team.yml`).
- **Every fleet YAML has a unique `name:`** — gitops.sh blocks duplicates.
- **Every label referenced in policies/reports/software** must appear in
  the `labels:` section of `default.yml` or the relevant fleet YAML.
- **`apple_settings.configuration_profiles`** replaces
  `macos_settings.custom_settings` (v4.83.0; old names are deprecated
  aliases). Never both in one place: Fleet rejects `apple_settings` beside
  `macos_settings` as conflicting field names. contour writes the new names
  in files it creates and keeps a file's existing spelling when it edits one.
- **Never auto-fix a migration step**: stop at each manual diff checkpoint
  for a human to review.


## Canonical v4.83 directory tree (what `fleetctl new` produces)

```
your-gitops-repo/
├── default.yml                                    # global: org_settings, agent_options, controls, labels?
├── fleets/
│   ├── workstations.yml                           # per-fleet: name, controls, software, policies, settings
│   ├── personal-mobile-devices.yml
│   └── unassigned.yml                             # the "no fleet" bucket (not "no-team.yml" anymore)
├── labels/
│   ├── apple-silicon-macos-hosts.yml              # one or more label .yml files
│   ├── arm-based-windows-hosts.yml
│   └── …
├── platforms/
│   ├── all/{icons,policies,reports}/              # cross-platform assets
│   ├── android/{configuration-profiles,managed-app-configurations}/
│   ├── ios/{configuration-profiles,declaration-profiles}/
│   ├── ipados/{configuration-profiles,declaration-profiles}/
│   ├── linux/{policies,reports,scripts,software}/
│   ├── macos/
│   │   ├── commands/                              # MDM command .plist files
│   │   ├── configuration-profiles/                # .mobileconfig
│   │   ├── declaration-profiles/                  # .json (DDM)
│   │   ├── enrollment-profiles/                   # DEP .json profiles
│   │   ├── policies/                              # per-platform policies (.yml)
│   │   ├── reports/
│   │   ├── scripts/                               # .sh
│   │   └── software/                              # .yml package definitions
│   └── windows/{configuration-profiles,policies,reports,scripts,software}/
└── .github/
    ├── fleet-gitops/
    │   ├── action.yml
    │   └── gitops.sh
    └── workflows/
        └── workflow.yml
```

**Note on `lib/`** — Fleet also documents a `lib/` folder for shared
YAMLs referenced by `path:`. Pick one storage convention; the canonical one
is `labels/` + `platforms/<platform>/`.

## Top-level YAML keys (verified against fleetctl v4.84.2)

`default.yml` (global) — three keys:
```yaml
org_settings:                # required, default.yml ONLY
controls:                    # global controls (optional per-fleet override)
labels:                      # references label files
```

`fleets/<fleet-name>.yml`:
```yaml
name:                        # required, unique across all fleets
controls:                    # nested: setup_experience, apple_settings,
                             #         windows_settings, scripts
reports:                     # TOP-LEVEL — list of `- paths:` globs
policies:                    # TOP-LEVEL — list of `- paths:` globs
software:                    # fleet_maintained_apps, packages, app_store_apps
agent_options:               # optional (per docs)
settings:                    # optional (per-fleet settings; replaces team_settings)
```

`fleets/unassigned.yml` (hosts in no fleet) does NOT support `labels:`.


## Step-by-step migration

### 1. Snapshot the current repo

```bash
git status                                  # clean working tree
git switch -c migrate/v4.83                 # work on a branch
fleetctl gitops --dry-run -f default.yml    # snapshot the current valid state
```

If the dry-run already fails, fix that first.

### 2. Create the canonical v4.83 tree

```bash
mkdir -p platforms/all/{icons,policies,reports}
mkdir -p platforms/android/{configuration-profiles,managed-app-configurations}
mkdir -p platforms/{ios,ipados}/{configuration-profiles,declaration-profiles}
mkdir -p platforms/linux/{policies,reports,scripts,software}
mkdir -p platforms/macos/{commands,configuration-profiles,declaration-profiles,enrollment-profiles,policies,reports,scripts,software}
mkdir -p platforms/windows/{configuration-profiles,policies,reports,scripts,software}
mkdir -p fleets labels
```

### 3. Move existing assets

#### From legacy (`lib/`)

```bash
mv lib/macos/configuration-profiles/*.mobileconfig platforms/macos/configuration-profiles/  2>/dev/null || true
mv lib/macos/configuration-profiles/*.json         platforms/macos/declaration-profiles/    2>/dev/null || true
mv lib/macos/scripts/*                             platforms/macos/scripts/                 2>/dev/null || true
mv lib/all/labels/*.yml                            labels/                                   2>/dev/null || true
mv lib/all/policies/*.yml                          platforms/all/policies/                   2>/dev/null || true
```

#### From v4.82 (DDM `.json` mixed with `.mobileconfig`)

```bash
mv platforms/macos/configuration-profiles/*.json platforms/macos/declaration-profiles/ 2>/dev/null || true
```

**Manual diff checkpoint #1**: confirm every file moved correctly:

```bash
find . -name "*.mobileconfig" | sort > /tmp/mobileconfigs.txt
find . -name "*.json" -path "*declaration-profiles*" | sort > /tmp/ddm.txt
# compare against your pre-move snapshot
```

### 4. Rewrite `default.yml`

Rename `controls.macos_settings.custom_settings` →
`controls.apple_settings.configuration_profiles`. Keep only
`org_settings`, `controls`, `labels`, referencing files via `paths:` globs:

```yaml
labels:
  - paths: ./labels/*.yml
```

Verify no `team_settings:` remains (it is `settings:` since v4.82).

### 5. Rewrite each `fleets/*.yml` — canonical glob form

The scaffold's `workstations.yml` is the reference shape:

```yaml
name: "💻 Workstations"

controls:
  setup_experience:
    # apple_setup_assistant: ../platforms/macos/enrollment-profiles/automatic-enrollment.dep.json

  apple_settings:
    configuration_profiles:
      - paths: ../platforms/macos/declaration-profiles/*.json
      - paths: ../platforms/macos/configuration-profiles/*.mobileconfig

  windows_settings:
    configuration_profiles:
      - paths: ../platforms/windows/configuration-profiles/*.xml

  scripts:
    - paths: ../platforms/macos/scripts/*.sh
    - paths: ../platforms/windows/scripts/*.ps1
    - paths: ../platforms/linux/scripts/*.sh

reports:
  - paths: ../platforms/all/reports/*.yml
  - paths: ../platforms/macos/reports/*.yml
  - paths: ../platforms/windows/reports/*.yml
  - paths: ../platforms/linux/reports/*.yml

policies:
  - paths: ../platforms/macos/policies/*.yml
  - paths: ../platforms/windows/policies/*.yml
  - paths: ../platforms/linux/policies/*.yml

software:
  fleet_maintained_apps: # …
  packages:              # …
  app_store_apps:        # …
```

`name:` must be unique across `fleets/*.yml` (`gitops.sh` fails duplicates).

### 5b. Per-file form for label-targeted profiles (alternative)

When one profile needs label filtering, use the **per-file `path:` form**
alongside globs:

```yaml
controls:
  apple_settings:
    configuration_profiles:
      # bulk-include via glob
      - paths: ../platforms/macos/configuration-profiles/*.mobileconfig
      # then a single file with label targeting
      - path: ../platforms/macos/configuration-profiles/exec-only-profile.mobileconfig
        labels_include_all:
          - Executives
      - path: ../platforms/macos/configuration-profiles/temporary-bypass.mobileconfig
        labels_exclude_any:
          - VIP
```

Only one of `labels_include_all`, `labels_include_any`, or
`labels_exclude_any` per entry. Glob and per-file entries can mix in
the same `configuration_profiles:` array.

Rename any `no-team.yml` to `unassigned.yml` (fleet schema minus `labels:`).

**Manual diff checkpoint #2**: every fleet YAML must pass a dry-run:

```bash
for f in fleets/*.yml; do
  echo "=== $f ==="
  fleetctl gitops --dry-run -f default.yml -f "$f" || break
done
```

### 6. Move labels

One `labels/<set>.yml` per label set, each with inline definitions:

```yaml
- name: Apple Silicon
  description: Hosts on M-series Apple Silicon
  query: SELECT 1 FROM system_info WHERE cpu_type LIKE 'arm64%'
  label_membership_type: dynamic
  platform: darwin
```

`default.yml` references them via:

```yaml
labels:
  - path: ./labels/apple-silicon.yml
  - path: ./labels/engineering.yml
```

Confirm no label is referenced but missing (see Hard rules).

### 7. Migrate `.github/fleet-gitops/`

Replace an older or hand-written `gitops.sh` with the canonical one. Env vars:

| Env var | Default | Purpose |
|---|---|---|
| `FLEET_GITOPS_DIR` | `.` | Repo root (override for monorepos) |
| `FLEET_GLOBAL_FILE` | `$FLEET_GITOPS_DIR/default.yml` | Global file path |
| `FLEETCTL` | `fleetctl` | Binary on PATH (override for testing) |
| `FLEET_DRY_RUN_ONLY` | `false` | If `true`, only `--dry-run` runs |
| `FLEET_DELETE_OTHER_FLEETS` | `true` | Delete fleets not in YAML |
| `FLEET_URL` | (secret) | Required |
| `FLEET_API_TOKEN` | (secret) | Required |

**Manual diff checkpoint #3** — generate a fresh reference and diff:

```bash
fleetctl new /tmp/fleet-ref                              # requires fleetctl ≥ 4.83
diff -r .github /tmp/fleet-ref/.github
diff default.yml /tmp/fleet-ref/default.yml              # diff schema, not values
```

Or fetch directly from upstream:

```bash
curl -fsSL -o /tmp/gitops.sh \
  https://raw.githubusercontent.com/fleetdm/fleet/main/cmd/fleetctl/fleetctl/templates/new/.github/fleet-gitops/gitops.sh
diff .github/fleet-gitops/gitops.sh /tmp/gitops.sh
```

Look specifically for:
- Script iterates `fleets/*.yml` (NOT `teams/*.yml`)
- Uses `--delete-other-fleets` (NOT `--delete-other-teams`)
- `name:` uniqueness check via perl one-liner present
- Workflow triggers on push to `main`, PR (dry-run), nightly, manual

### 8. Validate everything together

```bash
fleetctl gitops --dry-run -f default.yml \
  $(for f in fleets/*.yml; do echo -n "-f $f "; done)
```

Then validate contour-emitted artifacts (catches what the dry-run won't):

```bash
contour profile validate platforms/macos/configuration-profiles/ --recursive --json
contour profile ddm validate platforms/macos/declaration-profiles/ --json
contour profile ddm verify platforms/macos/declaration-profiles --json
contour osquery validate . --recursive --json     # every policy, report and label query, both schemas
```

`osquery validate` fails on a table or column neither embedded schema has.
For a repo `contour mscp generate` produced, `contour mscp validate -o .`
adds Fleet's own schema. A `pre-commit` hook (`--sop precommit`) runs the
same check.

### 9. Clean up

After everything passes:

```bash
git rm -r lib/                               # legacy storage gone
git status                                   # confirm no stragglers
```

Commit in two parts: first the moves only, then the YAML rewrites.


## Attach a baseline across many fleets (inject engine)

On a v4.83 repo, `contour mscp generate --fleets … | --all-fleets
[--exclude-fleets …] | --canonical-fleets` attaches a baseline (glob-shared,
comment-preserving, idempotent, fail-closed); `--remove` withdraws it. Full
flag set: `--sop mscp`.

## Why this SOP isn't procedural

YAML migrations carry semantic deltas (a dropped label, profile or fleet)
that need a human eyeing each diff gate; `AUTO_FIX` blocks would invite
exactly that auto-fixing.

## Reference (canonical sources)

- `fleetctl new` — scaffolds a complete v4.83 repo with CI/CD, fleets,
  labels, and platforms (`fleetctl new ~/some-dir`)
- Templates: `fleet/cmd/fleetctl/fleetctl/templates/new/`
- Docs: `fleet/docs/Configuration/yaml-files.md`
- GitOps script: `fleet/cmd/fleetctl/fleetctl/templates/new/.github/fleet-gitops/gitops.sh`
- GitOps parser: `fleet/cmd/fleetctl/fleetctl/gitops.go`
