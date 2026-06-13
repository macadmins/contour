# Import & maintain existing profiles

A practical guide to bringing existing `.mobileconfig` profiles into contour and
keeping them clean at scale: **import**, **batch-normalize**, **regenerate UUIDs**,
**apply custom naming**, **audit**, and **detect cross-profile collisions** —
including the recently added `audit`, `classify`, `reidentify`, and `collisions`
commands.

Most commands take one file or a whole tree (`-r`), run in parallel, and support
`--dry-run` (preview) and `--json` (CI). The transforming maintenance commands
(`classify`, `reidentify`) **default to a dry-run preview** and only write with
`--write`.

> **Org domain:** identity-rewriting commands need one (`--org com.acme`, or
> `export CONTOUR_ORG=com.acme`, or `.contour/config.toml`). contour never falls
> back to `com.example`. Examples below assume `export CONTOUR_ORG=com.acme`.

---

## 1. Import — bring profiles in

```bash
# Interactive: pick which profiles to import from a directory.
contour profile import ./incoming --org com.acme --name "Acme Corp" -o ./profiles

# Non-interactive (everything), recursive, for scripts/CI:
contour profile import ./incoming --all --org com.acme --name "Acme Corp" -o ./profiles

# From a Jamf Pro backup (jamf-cli export — YAML with embedded mobileconfig):
contour profile import --jamf ./jamf-backup/profiles/macos/ --all -o ./profiles --org com.acme

# Preview only; fail the run if any profile is invalid:
contour profile import ./incoming --all --dry-run --strict --org com.acme
```

Import normalizes identifiers under `--org`, sets the organization name, regenerates
UUIDs, and validates — all in one step. Skip pieces with `--no-uuid` / `--no-validate`.

---

## 2. Batch normalize — the workhorse

`normalize` is the bulk maintenance command: standardize identifiers, set the org
name, regenerate UUIDs deterministically, sort payload keys, fix version tags, and
**preserve MDM placeholders** (`$VAR`, `{{var}}`, `%Var%`).

```bash
# Whole tree, recursive, parallel, with a markdown report for the PR:
contour profile normalize ./profiles -r --org com.acme --name "Acme Corp" --report normalize.md

# Preview without writing:
contour profile normalize ./profiles -r --org com.acme --dry-run

# Keep existing UUIDs / skip validation if you need to:
contour profile normalize ./profiles -r --org com.acme --no-uuid
contour profile normalize ./profiles -r --org com.acme --no-validate

# Single file from the macOS pasteboard:
contour profile normalize --pasteboard --org com.acme -o restrictions.mobileconfig
```

Re-running `normalize` on the same input is **byte-stable** — it diffs cleanly into a
GitOps repo every time. The `--report` file lists per-file pass/fail counts and every
rule that fired, with citations to Apple's device-management spec.

---

## 3. Recreate UUIDs

```bash
# Regenerate all PayloadUUIDs across a tree:
contour profile uuid ./profiles -r

# Predictable (deterministic v5) UUIDs — same input → same UUIDs, ideal for GitOps:
contour profile uuid ./profiles -r --predictable

# Preview:
contour profile uuid ./profiles -r --dry-run
```

After changing UUIDs, make `PayloadIdentifier`s consistent with them using
**`reidentify`** (preview by default; `--write` to apply):

```bash
# Sync each PayloadIdentifier to its PayloadUUID (default scheme):
contour profile reidentify ./profiles -r --org com.acme --write

# Or derive identifiers from a slug of the display name instead:
contour profile reidentify ./profiles -r --org com.acme --scheme name --write
```

> **GitOps tip:** set `deterministic_uuids = true` in `.contour/config.toml` (via
> `contour init --deterministic-uuids true`) so generate/normalize produce
> reproducible UUIDs without passing `--predictable` each time.

---

## 4. Apply custom naming (`classify`)

`classify` rewrites each profile's `PayloadDisplayName` to a consistent, templated
convention. The default template is `{scope} - {kind} ({subject})` — e.g.
`System - Wi-Fi (Corp WiFi)`. It previews by default; `--write` applies. With no
`--map`, contour uses its **built-in** naming rules:

```bash
contour profile classify ./profiles -r            # preview the renames
contour profile classify ./profiles -r --write    # apply them
```

### Customizing the rules — and where the files live

To change the convention (the format template, the `kind` label per payload type,
or the friendly name per app bundle ID), scaffold an editable **rules file** with
`--emit-map`, edit it, then apply it with `--map`.

**`name.toml` is a rules file, not a per-profile list.** It holds the *naming
convention* (formats + `[kinds]` + `[apps]`), and one copy applies to every profile.
It is written to — and read from — **your current working directory** (the path you
pass to `--emit-map` / `--map`), *not* the profiles folder. Keep it at your repo root,
alongside (not inside) the profiles directory, and run contour from there:

```
my-repo/                     ← run contour from here
├── name.toml                ← the naming rules (edit once, reuse)
└── profiles/                ← the .mobileconfig files being renamed
    ├── corp-wifi.mobileconfig
    └── restrictions.mobileconfig
```

```bash
cd my-repo

# 1. Scaffold the rules file in the CWD (here: my-repo/name.toml). This SCANS the
#    profiles and pre-fills best-guess app names (review the `# review` lines); it
#    does NOT rename anything.
contour profile classify ./profiles -r --emit-map name.toml

# 2. Edit ./name.toml — adjust `system_format`/`app_format`, the [kinds] labels
#    (payload-type → kind), and the [apps] friendly names (bundle-id → subject).

# 3. Apply your rules to the profiles (path is relative to the CWD, not ./profiles):
contour profile classify ./profiles -r --map name.toml --write
```

> The `<PATHS>` argument is the profiles; `--map` / `--emit-map` is the rules file.
> They're independent paths, both resolved from where you run the command — so
> `--map name.toml` means `./name.toml`, regardless of where `./profiles` lives.

Rebuild identifiers/UUIDs to match the new names in the same pass with
`--sync-identity` (requires `--org`; `--scheme name|uuid`):

```bash
contour profile classify ./profiles -r --write --sync-identity --org com.acme --scheme name
```

---

## 5. Audit — find binary content, certs, and secrets

`audit` scans profiles for embedded certificates, binary blobs, deprecated payloads,
and **secrets** — a good pre-commit / pre-import gate.

```bash
# Full audit of a tree, with a markdown report:
contour profile audit ./profiles -r --md-report audit.md

# CI gate: fail the run if any secret is found:
contour profile audit ./profiles -r --secrets-only --fail-on-secrets --json

# Narrow scans:
contour profile audit ./profiles -r --certs-only
contour profile audit ./profiles -r --with-deprecations

# Quarantine flagged profiles into a separate directory:
contour profile audit ./profiles -r --route-into ./flagged
```

---

## 6. Maintain over time — diff, plan, rollback

```bash
# What changed between two profiles:
contour profile diff old.mobileconfig new.mobileconfig

# Terraform-plan-style change impact between a baseline tree and a proposed one:
contour profile plan ./baseline ./proposed --json

# Restore UUIDs from a baseline (cherry-pick) so identity stays stable across edits:
contour profile rollback ./baseline ./current

# Duplicate one profile into a fresh identity (new name, identifier, UUIDs):
contour profile duplicate ./template.mobileconfig --name "Acme Wi-Fi" --org com.acme --predictable -o wifi.mobileconfig
```

---

## 7. Detect cross-profile collisions (`collisions`)

macOS does **not** reliably merge two *separate* profiles that manage the **same
payload domain** (e.g. a CIS profile and an org profile both setting
`com.apple.applicationaccess`) — "complementary split management" is fragile. The
`collisions` detector finds these so you can consolidate to **one profile per domain**.

It recursively scans `.mobileconfig` profiles **and** DDM `.json` declarations, groups
payloads by domain **within a co-apply scope** (each directory is a scope by default,
so different tenants don't false-positive), and reports any domain managed by 2+ files.
Per key it tells you whether it is a:

- **conflict** — set to *different* values across profiles (the dangerous case);
- **redundant** — same value everywhere (safe to drop the duplicate);
- **complementary** — set in only one (the keys to *port* when consolidating).

```bash
# Read-only gap analysis of a repo (per-directory scope):
contour profile collisions ./profiles -r

# Treat the whole tree as one host (default: each directory is a separate scope):
contour profile collisions ./profiles -r --flat

# CI gate — fail if any key conflicts across co-applied profiles:
contour profile collisions ./profiles -r --fail-on-conflict --json
# …or fail on any same-domain split at all:
contour profile collisions ./profiles -r --fail-on-split

# Markdown key-matrix for the PR / consolidation work:
contour profile collisions ./profiles -r --md-report collisions.md
```

**Consolidating a split:** the report's **complementary** keys are exactly what to port
from the redundant file (e.g. CIS) into the org profile that should own the domain;
**conflict** keys need a decision; **redundant** keys can be dropped. Once one profile
owns the domain end-to-end, delete the other and re-run `collisions` to confirm it's
clean. It is read-only — it never edits profiles.

---

## A complete maintenance pipeline

Import a messy export, gate on secrets, name consistently, normalize, and validate —
ready to commit:

```bash
export CONTOUR_ORG=com.acme

# 1. Import everything from a Jamf backup
contour profile import --jamf ./jamf-backup/profiles/macos/ --all -o ./profiles --name "Acme Corp"

# 2. Block secrets before they enter the repo
contour profile audit ./profiles -r --secrets-only --fail-on-secrets --md-report audit.md

# 3. Apply consistent display names (+ matching identifiers)
contour profile classify ./profiles -r --write --sync-identity --scheme name

# 4. Final normalize pass (deterministic UUIDs, sorted keys, report)
contour profile normalize ./profiles -r --name "Acme Corp" --report normalize.md

# 5. Flag any domain managed by two profiles (macOS won't merge them) — gate the PR
contour profile collisions ./profiles -r --fail-on-conflict --md-report collisions.md

# 6. Validate the whole tree
contour profile validate ./profiles -r --json
```

Re-run any time — deterministic UUIDs and stable formatting mean the bytes only move
when the content actually changes.

---

## Tips

- **Dry-run first.** `classify` and `reidentify` preview by default — inspect, then
  add `--write`. `normalize` / `uuid` / `import` take `--dry-run`.
- **Deterministic UUIDs for GitOps.** `--predictable` (or `deterministic_uuids` in
  config) keeps diffs clean and re-runs reproducible.
- **Reports for review.** `--report` (normalize) and `--md-report` (audit) drop a
  markdown summary straight into a PR description.
- **`--json` everywhere** for CI; combine `audit --fail-on-secrets`,
  `collisions --fail-on-conflict`, and `validate` as gates with typed exit codes.
- **One profile per domain.** `collisions ./profiles -r --fail-on-conflict` catches
  two profiles managing the same `PayloadType` — which macOS won't reliably merge.
- **MDM variables survive.** Normalization preserves `$VAR` / `{{var}}` / `%Var%`
  placeholders — see `contour profile variables` for the known catalog.
