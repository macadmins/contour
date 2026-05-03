# SOP: Migrate a Fleet GitOps Repo to v4.83 Structure

A **one-time migration playbook**, not a callable procedure. Driven by
a human who can eyeball each diff. The goal: take a Fleet GitOps repo
on legacy (`lib/`) or v4.82 (flat `platforms/`, `macos_settings`)
shape and end up matching the structure `fleetctl new` scaffolds today.

Validated against:
- A live `fleetctl v4.84.2` scaffold (`fleetctl new`) — the
  source of truth for what the canonical layout actually generates today
- `fleet/docs/Configuration/yaml-files.md`
- `fleet/cmd/fleetctl/fleetctl/templates/new/.github/fleet-gitops/gitops.sh`

If you're on **v4.82** already (flat `platforms/`), most steps are a
no-op — you only need the YAML-key + DDM-separation work in steps 4–5.

---

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

**Note on `lib/`** — Fleet's docs also document a `lib/` folder for
shared label / policy / report YAMLs referenced by `path:` from
`default.yml`. It's an alternative to platforms-specific dirs; pick one
storage convention and stick to it. `fleetctl new` uses `labels/` and
`platforms/<platform>/` and that's the recommended canonical shape.

## Top-level YAML keys (verified against fleetctl v4.84.2)

`default.yml` (global) — the scaffolded shape uses just three keys:
```yaml
org_settings:                # required, default.yml ONLY
controls:                    # global controls (optional per-fleet override)
labels:                      # references label files
```

`fleets/<fleet-name>.yml` — the scaffolded shape:
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

> **Important shape detail**: `scripts` lives **inside `controls:`**.
> `reports` and `policies` are **top-level fleet keys**, NOT nested
> under controls. This is easy to get backwards.

`fleets/unassigned.yml` is the bucket for hosts not claimed by any
fleet. It does NOT support a `labels:` key (per `yaml-files.md`).

---

## Step-by-step migration

### 1. Snapshot the current repo

```bash
git status                                  # clean working tree
git switch -c migrate/v4.83                 # work on a branch
fleetctl gitops --dry-run -f default.yml    # snapshot the current valid state
```

If the dry-run already fails on the unmigrated repo, fix that first
— migration on top of brokenness compounds the error surface.

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
# Separate DDM from configuration profiles. v4.83 puts DDM in its own dir.
mv platforms/macos/configuration-profiles/*.json platforms/macos/declaration-profiles/ 2>/dev/null || true
```

**Manual diff checkpoint #1**: confirm every file moved correctly:

```bash
find . -name "*.mobileconfig" | sort > /tmp/mobileconfigs.txt
find . -name "*.json" -path "*declaration-profiles*" | sort > /tmp/ddm.txt
# compare against your pre-move snapshot
```

### 4. Rewrite `default.yml`

The big YAML-key change is `controls.macos_settings.custom_settings` →
`controls.apple_settings.configuration_profiles`. The **canonical v4.84+
form uses `paths:` globs** (one entry per directory), not per-file
references. The scaffolded `default.yml` has just three top-level keys
— `org_settings`, `controls`, `labels` — and references everything via
glob:

```yaml
labels:
  - paths: ./labels/*.yml
```

`team_settings:` → `settings:` was already done in v4.82. Verify it's
gone in your migrated tree.

### 5. Rewrite each `fleets/*.yml` — canonical glob form

The scaffold's `workstations.yml` is the reference shape. Every profile,
script, policy, and report block uses `paths:` globs against the
canonical platforms tree:

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

The `name:` field at top must be unique across all `fleets/*.yml`
(`gitops.sh` enforces this via a perl one-liner — duplicates fail the
run).

### 5b. Per-file form for label-targeted profiles (alternative)

When a single profile needs label filtering (e.g. only deploy to one
department), the **per-file `path:` form is supported** alongside the
glob form (per `yaml-files.md` `### apple_settings and windows_settings`):

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

If any file is named `no-team.yml`, rename to `unassigned.yml`. The
`fleets/unassigned.yml` file represents hosts not assigned to any fleet
and follows the same schema as a fleet file minus `labels:`.

**Manual diff checkpoint #2**: every fleet YAML should now parse with
`fleetctl gitops --dry-run -f fleets/<name>.yml`. Loop over them:

```bash
for f in fleets/*.yml; do
  echo "=== $f ==="
  fleetctl gitops --dry-run -f default.yml -f "$f" || break
done
```

### 6. Move labels

`fleetctl new` puts each label set in its own `labels/<set>.yml` file.
Each file holds one or more inline label definitions (see
`yaml-files.md` `## labels`):

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

Fleet's docs note that **any label referenced in policies, reports, or
software MUST appear in the `labels:` section** — confirm none are
referenced and missing.

### 7. Migrate `.github/fleet-gitops/`

`fleetctl new` ships a canonical `gitops.sh`; if your repo has an older
or hand-written one, replace it. The stable env-var contract is:

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

Then validate every contour-emitted artifact at the same time —
catches schema regressions that the Fleet-side dry-run won't:

```bash
contour profile validate platforms/macos/configuration-profiles/ --recursive --json
contour profile ddm validate platforms/macos/declaration-profiles/ --json
contour profile ddm verify platforms/macos/declaration-profiles --json
```

If you have an active `pre-commit` hook (see `--sop precommit`), this
is the same check the hook runs — clean here means clean for every
subsequent commit.

### 9. Clean up

After everything passes:

```bash
git rm -r lib/                               # legacy storage gone
git status                                   # confirm no stragglers
```

Commit in two parts so the diff is reviewable: first the
restructure (moves only, no content changes), then the YAML rewrites.
Cherry-picking gets cleaner if the migration needs to be partially
reverted later.

---

## Hard rules (don't drop these)

- **DDM declarations live in `platforms/<os>/declaration-profiles/`**, not
  in `configuration-profiles/`. Mixing them broke validation in v4.82
  → v4.83.
- **`controls.apple_settings.configuration_profiles` defaults to `paths:` globs**
  (verified against fleetctl v4.84.2). Per-file `path:` is also supported
  and is the form to use when a single profile needs `labels_include_all`,
  `labels_include_any`, or `labels_exclude_any` filtering.
- **`scripts:` is nested under `controls:`**, but **`reports:` and `policies:`
  are TOP-LEVEL fleet keys** — not under `controls`. Easy to get backwards.
- **`fleets/` is the directory** (NOT `teams/`); **`unassigned.yml`** is the
  no-fleet bucket file (NOT `no-team.yml`).
- **Every fleet YAML has a unique `name:`** — gitops.sh blocks duplicates.
- **Every label referenced in policies/reports/software** must appear in
  the `labels:` section of `default.yml` or the relevant fleet YAML.
- **`apple_settings`** replaces `macos_settings` (which itself replaced
  `controls.macos_settings.custom_settings` from earlier eras).

---

## Why this SOP isn't procedural

A migration like this is a one-time, eyes-on operation. Every step has
a "manual diff checkpoint" because YAML migrations have meaningful
semantic deltas — missing a label, dropping a profile, or merging two
fleets is not something an agent should auto-fix without a human eyeing
the diff. Procedural format with `AUTO_FIX` blocks would encourage
exactly that auto-fixing.

The right shape for this content is a numbered playbook with explicit
diff gates between steps. If the same migration becomes a repeating
pattern (e.g. v4.83 → v4.84), revisit and consider promoting parts to a
procedural SOP.

## Reference (canonical sources)

- `fleetctl new` — scaffolds a complete v4.83 repo with CI/CD, fleets,
  labels, and platforms (`fleetctl new ~/some-dir`)
- Templates: `fleet/cmd/fleetctl/fleetctl/templates/new/`
- Docs: `fleet/docs/Configuration/yaml-files.md`
- GitOps script: `fleet/cmd/fleetctl/fleetctl/templates/new/.github/fleet-gitops/gitops.sh`
- GitOps parser: `fleet/cmd/fleetctl/fleetctl/gitops.go`
