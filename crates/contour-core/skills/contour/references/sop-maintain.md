# SOP: Maintain & consolidate an existing profile repo

This SOP covers keeping a repo of existing `.mobileconfig` profiles (and DDM `.json`
declarations) healthy at scale: **import → audit → name → re-identify → normalize →
collision-check → validate**. It centers on the hygiene gates an agent should run
before committing, and the **collision consolidation** workflow (the fragile case
macOS doesn't merge). Naming detail lives in `--sop profile-naming` (classify);
change-impact in `--sop profile-changes` (plan/rollback); generation in `--sop profile`.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`

## The hygiene pipeline

```
contour profile import <src> --all --org ORG --name "NAME" -o ./profiles   # bring in
contour profile audit ./profiles -r --secrets-only --fail-on-secrets --json # gate: no secrets
contour profile classify ./profiles -r --write --sync-identity --scheme name # consistent names
contour profile normalize ./profiles -r --org ORG --name "NAME" --report normalize.md
contour profile collisions ./profiles -r --fail-on-conflict --md-report collisions.md # gate: no split conflicts
contour profile validate ./profiles -r --json                              # gate: schema-valid
```

Every gate has a typed non-zero exit; chain them in CI. `--dry-run` (import/normalize/
uuid) and the default dry-run of `classify`/`reidentify` preview before `--write`.

> **PRECONDITION — `--org`:** identity-rewriting commands (import, normalize, reidentify,
> classify --sync-identity, duplicate) require an org domain (`--org`, `CONTOUR_ORG`, or
> `.contour/config.toml`). Never `com.example`.

---

## PROCEDURE detect_collisions(repo)

macOS does **not** reliably merge two *separate* profiles that manage the same payload
domain (`PayloadType`). Before consolidating, get a precise per-domain, per-key map.

```
TOOL: contour profile collisions <repo> -r [--flat] [--fail-on-conflict] [--md-report PATH] --json

SCOPE MODEL (critical — avoids false positives):
  default  → each directory is one co-apply scope (a tenant/team). Two tenants
             managing the same domain do NOT collide.
  --flat   → the whole tree is one scope. Use this to answer "if ONE host got
             every profile here, which domains would be split across files?"

OUTPUT per colliding domain, per key — a KeyVerdict:
  conflict       same key, DIFFERENT values across files → the dangerous case (gate on this)
  redundant      same key, SAME value everywhere → safe to drop the duplicate
  complementary  set in exactly one file → the keys to PORT when consolidating

INTERPRETATION:
  - A domain with only `complementary` keys across N files can be safely MERGED into
    one profile (no conflicts) — e.g. 19 single-setting Restrictions profiles → one.
  - A domain with `conflict` keys needs a human decision: the profiles disagree, and
    on-device only one wins (silently). `--fail-on-conflict` makes CI catch this.

CONSOLIDATION (make one profile own a domain end-to-end):
  STEP 1  collisions <repo> -r --flat --md-report collisions.md   # the gap map
  STEP 2  pick the profile that should OWN the domain (usually the org profile)
  STEP 3  port every `complementary` key from the other files into the owner;
          resolve each `conflict` key deliberately; drop `redundant` duplicates
  STEP 4  delete the now-redundant files
  STEP 5  re-run collisions to confirm the domain is owned by exactly one file
  INVARIANT: collisions is READ-ONLY — it never edits profiles. The edits in STEP 3
             are done with normalize/generate/your editor, then re-validated.
```

---

## PROCEDURE gate_secrets(repo)

```
contour profile audit <repo> -r --secrets-only --fail-on-secrets --json
  → non-zero exit if any payload carries a secret (entropy-bearing value). Use as a
    pre-commit / pre-import gate so credentials never enter the repo.
contour profile audit <repo> -r --certs-only            # list certificate payloads
contour profile audit <repo> -r --with-deprecations     # flag deprecated payloads/keys
contour profile audit <repo> -r --route-into ./flagged  # quarantine flagged profiles
contour profile audit <repo> -r --md-report audit.md    # full report for review
```

## PROCEDURE stabilize_identity(repo)

```
# Regenerate UUIDs; --predictable for reproducible (GitOps-stable) v5 UUIDs:
contour profile uuid <repo> -r --predictable
# Make PayloadIdentifiers consistent with the (new) UUIDs or with a name-slug:
contour profile reidentify <repo> -r --org ORG --write          # scheme: uuid (default)
contour profile reidentify <repo> -r --org ORG --scheme name --write
```
`reidentify` previews by default; pass `--write` to apply. Prefer `deterministic_uuids
= true` in `.contour/config.toml` so generate/normalize stay reproducible.

---

## Other operations (cross-references)

| Need | SOP |
|---|---|
| Consistent display names (`classify`, name.toml rules) | `--sop profile-naming` |
| Change impact / rollback (`plan`, `diff`, `rollback`) | `--sop profile-changes` |
| Generate/validate a single profile or DDM | `--sop profile` / `--sop ddm` |
| Jamf import | `import --jamf <backup> --all -o ./profiles --org ORG` |

## GOTCHAS

- **`audit --route-into <dir>` MOVES flagged profiles** out of the source tree into
  `<dir>` — it doesn't copy. Re-point later steps at the source dir, not an emptied one.
- **`normalize`/`uuid` without `-o` write `*-normalized` / `*-uuid` copies** rather than
  editing in place — those copies then self-collide. Pass `-o <dir>` or process in place.
- **Collisions ≠ duplicates of the same file.** A signed + unsigned copy of one profile in
  one directory IS reported (2 files, same domain). Scope/clean those out first.

## Key flags

- `-r` / `--max-depth N` — recursive scan. `--json` — structured output for CI/agents.
- `--fail-on-conflict` / `--fail-on-secrets` — CI gates with typed exit codes.
- `--md-report PATH` — markdown report (collisions key-matrix, audit findings, normalize rules).
- `--flat` (collisions) — whole-repo-on-one-host view; default is per-directory scope.
