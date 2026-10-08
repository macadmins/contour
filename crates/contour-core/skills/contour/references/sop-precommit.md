# SOP: Contour as a Git Pre-Commit Validator

Wire contour validators into a Git pre-commit hook so a malformed profile,
dangling DDM reference or broken TOML in a staged change blocks the commit.

Canonical install: **`uvx pre-commit`** (the
[pre-commit](https://pre-commit.com/) framework run via
[`uv`](https://docs.astral.sh/uv/), no global Python install). A
framework-free shell hook is also documented.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`

## Compact hook usage

| Intent | Command |
|---|---|
| One-shot validate everything | `uvx pre-commit run --all-files` |
| Install as native git hook | `uvx pre-commit install` |
| Validate only changed files (CI) | `uvx pre-commit run --from-ref origin/main --to-ref HEAD` |
| Run a single hook | `uvx pre-commit run contour-profile-validate` |
| Test against unreleased contour | `CONTOUR=/path/to/dev/contour uvx pre-commit run --all-files` |
| Same, persistently in your shell | `export CONTOUR=…/dist/contour` then any of the above |

**Recommended dev flow:** `uvx pre-commit install` once → hooks fire on
every `git commit`. For pre-release contour: `CONTOUR=…/dist/contour git commit`
(env propagates into the hook).

## ERROR-CODE ENUM

```
INVALID_FORMAT         file doesn't parse (TOML / plist / JSON)
SCHEMA_VIOLATION       fails the embedded Apple/MDM/DDM schema
                       OR a DDM directory has dangling cross-references
IO_ERROR               file unreadable / path missing
INVALID_ORG            org-domain check failed (DDM compose path)
UNKNOWN                unmatched
```

The hook only needs its exit status (block-or-pass); `error_code` from
`--json` makes a useful summary.

## PROCEDURE configure_pre_commit_validation(repo_root, hook_style)

```
SCHEMA_SOURCE: contour's embedded schema registry (Apple device-management,
                osquery, mSCP — refreshed per release)
SCHEMA_TOOL:   contour profile validate <paths> --json
               contour profile ddm validate <paths> --json
               contour profile ddm verify <dir> --json
               contour {pppc|btm|notifications|support} validate <toml> --json
               contour mscp validate -o <repo-root> --json

INPUT:
  repo_root   : GitOps repo root (Fleet v4.83 layout shown; any
                contour-output repo works)
  hook_style  : "git-hooks"            — plain `.git/hooks/pre-commit`
                "pre-commit-framework" — pre-commit (Python)
                "husky"                — Node-based hook manager
                "lefthook"             — Go-based

PRECONDITIONS:
  ASSERT contour --version succeeds
    HALT "contour binary not on PATH; install via the .pkg or
          `brew install contour` (planned)"
  ASSERT inside a git repo (git rev-parse --git-dir succeeds)
    HALT "not a git repository: {repo_root}"
  ASSERT no conflicting hook already installed for hook_style
    AUTO_FIX: back up existing hook to {hook}.backup-{ts} and proceed,
              OR document the chained-hook layout for the framework
  WARN if `git config core.hooksPath` is set to a non-default value
       — the new hook may not be picked up; ensure the path matches.

STEP 1 — Classify staged changes:
  staged = git diff --cached --name-only --diff-filter=ACMR

  Bucket by file shape (layout-agnostic; Fleet v4.83 paths shown).

  buckets = {
    profiles_macos    : staged.match("*.mobileconfig"),
    ddm_files         : staged.match("**/declaration-profiles/*.json"),
    ddm_dirs          : unique(parent(f) for f in ddm_files),
    enrollment_files  : staged.match("**/enrollment-profiles/*.dep.json"),
    pppc_tomls        : staged.match("**/pppc.toml"),
    btm_tomls         : staged.match("**/btm.toml"),
    notif_tomls       : staged.match("**/notifications.toml"),
    support_tomls     : staged.match("**/support.toml"),
    mscp_present      : staged.matchesAny("mscp/**", "platforms/macos/configuration-profiles/mscp_*"),
  }

STEP 2 — Validate each bucket:
  errors = []

  if buckets.profiles_macos:
    contour profile validate {paths} --json
    on non-zero: errors += parse_failure_categories(stdout)

  if buckets.ddm_files:
    contour profile ddm validate {paths} --json
    on non-zero: errors += per-file-errors

  for dir in buckets.ddm_dirs:
    # Cross-file DAG check (asset → configuration → activation +
    # predicate ↔ subscription); catches dangling refs that per-file
    # validation passes.
    contour profile ddm verify {dir} --json
    on non-zero: errors += verify-errors

  for tool, files in {pppc, btm, notifications, support}:
    for f in files:
      contour {tool} validate {f} --json
      on non-zero: errors += per-file-errors

  if buckets.mscp_present:
    # Whole-repo GitOps validate (paths, identifiers, label refs).
    # Slow; opt-in via --mscp flag in the hook config.
    contour mscp validate -o {repo_root} --strict --json
    on non-zero: errors += mscp-errors

  # NB: enrollment .dep.json has no validator; the hook skips them —
  # say so in the README so authors know.

POSTCONDITIONS:
  if len(errors) > 0:
    Print human-readable summary grouped by file:
      "{file}: {error_code}: {first error message}"
    HALT exit 1   # blocks the commit
  else:
    exit 0        # commit proceeds

INVARIANTS:
  # The hook MUST only validate staged changes, not the whole tree
  # (whole-tree is slow and surfaces errors unrelated to this commit).
  ASSERT every path passed to contour came from `git diff --cached`
  # The hook MUST exit 0 on no-op commits (no relevant files staged).
  ASSERT no validators run when buckets are all empty
  # Repo-relative paths so the hook works from any cwd in the worktree.
  ASSERT every path is repo-relative (not absolute)

STEP 3 — Smoke test:
  # 3a. Negative case: malformed profile
  echo '<plist><dict>BROKEN</dict></plist>' > platforms/macos/configuration-profiles/bad.mobileconfig
  git add platforms/macos/configuration-profiles/bad.mobileconfig
  git commit -m "test"
  ASSERT exit code != 0
  ASSERT stderr/stdout includes the file path AND error_code
    HALT "hook accepted malformed profile — installation broken"

  # 3b. Fix and re-commit
  rm platforms/macos/configuration-profiles/bad.mobileconfig
  # OR fix the file's content
  git add platforms/macos/configuration-profiles/bad.mobileconfig
  git commit -m "test"
  ASSERT exit code == 0

POSTCONDITIONS:
  RETURN {
    hook_path: ".git/hooks/pre-commit" | ".pre-commit-config.yaml" | ".husky/pre-commit",
    style:     hook_style,
    validators_active: [profile, ddm, ddm-verify, pppc?, btm?, notif?, support?, mscp?],
  }
```

---

## Hook scripts (prose recipes — copy/paste)

Ready-to-paste implementations of STEP 2.

### Style A: `pre-commit` framework via `uvx` (recommended)

Drop `.pre-commit-config.yaml` at the repo root (also shipped at
`docs/examples/.pre-commit-config.yaml` for copy-paste):

```yaml
repos:
  - repo: local
    hooks:
      - id: contour-profile-validate
        name: contour — validate macOS configuration profiles
        entry: bash -c '"${CONTOUR:-contour}" profile validate "$@" --json' --
        language: system
        files: \.mobileconfig$
        pass_filenames: true

      - id: contour-ddm-validate
        name: contour — validate DDM declarations
        entry: bash -c '"${CONTOUR:-contour}" profile ddm validate "$@" --json' --
        language: system
        files: declaration-profiles/.*\.json$
        pass_filenames: true

      - id: contour-ddm-verify
        name: contour — verify DDM cross-references (asset/config/predicate)
        entry: bash -c '"${CONTOUR:-contour}" profile ddm verify platforms/macos/declaration-profiles --json' --
        language: system
        files: declaration-profiles/
        pass_filenames: false

      - id: contour-pppc-validate
        name: contour — validate pppc.toml
        entry: bash -c '"${CONTOUR:-contour}" pppc validate "$@" --json' --
        language: system
        files: pppc\.toml$
        pass_filenames: true

      - id: contour-btm-validate
        name: contour — validate btm.toml
        entry: bash -c '"${CONTOUR:-contour}" btm validate "$@" --json' --
        language: system
        files: btm\.toml$
        pass_filenames: true

      - id: contour-notifications-validate
        name: contour — validate notifications.toml
        entry: bash -c '"${CONTOUR:-contour}" notifications validate "$@" --json' --
        language: system
        files: notifications\.toml$
        pass_filenames: true

      - id: contour-support-validate
        name: contour — validate support.toml
        entry: bash -c '"${CONTOUR:-contour}" support validate "$@" --json' --
        language: system
        files: support\.toml$
        pass_filenames: true
```

Keep the `bash -c '...' --` shape: it passes files via `"$@"` and keeps
`${CONTOUR:-contour}`, so `CONTOUR=…/dist/contour` overrides the binary
without touching `PATH`.

Install:
```bash
uvx pre-commit install                  # registers .git/hooks/pre-commit
uvx pre-commit run --all-files          # one-shot validate the whole tree
```

### Style B: framework-free `.git/hooks/pre-commit`

Save as `.git/hooks/pre-commit`, `chmod +x` (also shipped at
`docs/examples/pre-commit-contour.sh`):

```bash
#!/usr/bin/env bash
# Contour pre-commit hook — validates staged contour artifacts.
set -uo pipefail
CONTOUR="${CONTOUR:-contour}"   # override: CONTOUR=/path/to/dist/contour git commit

staged() { git diff --cached --name-only --diff-filter=ACMR -- "$@" 2>/dev/null; }

profiles=$(staged '*.mobileconfig')
ddm_files=$(staged '**/declaration-profiles/*.json')
pppc_files=$(staged '**/pppc.toml')
btm_files=$(staged '**/btm.toml')
notif_files=$(staged '**/notifications.toml')
support_files=$(staged '**/support.toml')

# No-op fast path.
if [[ -z "$profiles$ddm_files$pppc_files$btm_files$notif_files$support_files" ]]; then
  exit 0
fi

failed=0
fail() { echo "✗ contour: $*" >&2; failed=1; }

if [[ -n "$profiles" ]]; then
  # shellcheck disable=SC2086
  "$CONTOUR" profile validate $profiles --json >/dev/null 2>&1 \
    || fail "configuration profile(s) failed validation; \
             run: $CONTOUR profile validate $profiles"
fi

if [[ -n "$ddm_files" ]]; then
  # shellcheck disable=SC2086
  "$CONTOUR" profile ddm validate $ddm_files --json >/dev/null 2>&1 \
    || fail "DDM declaration(s) failed schema validation; \
             run: $CONTOUR profile ddm validate $ddm_files"

  # Cross-reference DAG check per touched DDM dir.
  ddm_dirs=$(echo "$ddm_files" | xargs -I{} dirname {} | sort -u)
  for dir in $ddm_dirs; do
    "$CONTOUR" profile ddm verify "$dir" --json >/dev/null 2>&1 \
      || fail "DDM cross-references in $dir don't resolve; \
               run: $CONTOUR profile ddm verify $dir"
  done
fi

# Lifecycle TOMLs (pppc / btm / notifications / support).
for f in $pppc_files;    do "$CONTOUR" pppc          validate "$f" --json >/dev/null 2>&1 || fail "pppc:          $f"; done
for f in $btm_files;     do "$CONTOUR" btm           validate "$f" --json >/dev/null 2>&1 || fail "btm:           $f"; done
for f in $notif_files;   do "$CONTOUR" notifications validate "$f" --json >/dev/null 2>&1 || fail "notifications: $f"; done
for f in $support_files; do "$CONTOUR" support       validate "$f" --json >/dev/null 2>&1 || fail "support:       $f"; done

if [[ $failed -ne 0 ]]; then
  echo "" >&2
  echo "✗ contour pre-commit blocked: fix the errors above and re-commit." >&2
  exit 1
fi

exit 0
```

Install:
```bash
cp docs/examples/pre-commit-contour.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Other hook frameworks (one-liners)

- **husky** (Node): `.husky/pre-commit` → `exec docs/examples/pre-commit-contour.sh`
- **lefthook** (Go): point each command at `${CONTOUR:-contour} <verb>`; same env-var dance applies

---

## Demo — the malformed → fix → pass loop

With the hook installed, staging a profile with an unknown `PayloadType`
blocks the commit:

```
$ git commit -m "add: bad profile"
✗ contour: configuration profile(s) failed validation;
           run: contour profile validate platforms/macos/configuration-profiles/bad.mobileconfig

✗ contour pre-commit blocked: fix the errors above and re-commit.

$ contour profile validate platforms/macos/configuration-profiles/bad.mobileconfig --json | jq '.[] | .errors'
[
  "Unknown payload type: com.apple.does.not.exist",
  "Missing PayloadIdentifier",
  "Missing PayloadUUID"
]
```

Fix or remove the file, `git add -u`, and re-commit; nothing invalid staged
→ clean exit, commit lands.

## Operational notes

- **Bypassing**: `git commit --no-verify`. Emergencies only; document the
  bypass in the commit message.
- **Rename/delete**: `--diff-filter=ACMR` covers Add / Copy / Modify /
  Rename; pure deletes (`D`) skip validation. Renames re-validate the new
  path's content.
- **Performance**: validates take ~50ms per file. The slow outlier is
  `contour mscp validate` on a full repo — gate it behind `--mscp` opt-in
  or a `commit-msg` hook.
- **CI parity**: run the same validators in CI — see `--sop ci`.
- **Schema freshness**: schemas are embedded per release; re-installing
  the binary refreshes them. No per-repo schema config.

---

## Key facts

- **What the hook MUST validate (staged-only)**: every contour-typed
  file changed in the commit. Whole-tree validation belongs in CI.
- **What it MUST NOT do**: run `contour profile generate` or any
  network-bound operation. Hooks are validation only.
- **DDM cross-references** (predicate referencing an unsubscribed
  `@status`, `*AssetReference` to a missing asset): wire `ddm verify` into
  the hook even when `ddm validate` is already there.
- **`--json`** on every validator emits a stable envelope
  (`{success, error, error_code}`) — summarize without parsing prose.
