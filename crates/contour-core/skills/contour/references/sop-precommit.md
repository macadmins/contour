# SOP: Contour as a Git Pre-Commit Validator

Wire `contour validate` into a Git pre-commit hook so a malformed profile
in a staged change blocks the commit before it lands. Cheap insurance
that catches schema regressions, dangling DDM references, and broken
TOML configs at the developer's keyboard rather than in CI 20 minutes
later — or worse, on production devices days later.

The canonical install path is **`uvx pre-commit`** (the
[pre-commit](https://pre-commit.com/) framework run ephemerally via
[`uv`](https://docs.astral.sh/uv/) — no global Python install required).
A framework-free shell hook is also documented for repos that prefer
zero external tooling.

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
every `git commit`. For pre-release contour testing, prefix with
`CONTOUR=…/dist/contour git commit` (env propagates into the hook
subprocess).

## ERROR-CODE ENUM

```
INVALID_FORMAT         file doesn't parse (TOML / plist / JSON)
SCHEMA_VIOLATION       fails the embedded Apple/MDM/DDM schema
                       OR a DDM directory has dangling cross-references
IO_ERROR               file unreadable / path missing
INVALID_ORG            org-domain check failed (DDM compose path)
UNKNOWN                unmatched
```

The hook itself only needs `exit 0` (block-or-pass), but reading the
error_code from `--json` lets you surface a useful summary message.

---

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
  repo_root   : Fleet GitOps repo root (or any contour-output repo)
  hook_style  : "git-hooks"            — plain `.git/hooks/pre-commit`
                "pre-commit-framework" — pre-commit (Python tool, the
                                          dominant pattern in Fleet
                                          GitOps repos)
                "husky"                — Node-based hook manager
                "lefthook"             — Go-based, parallel-friendly
                                          alternative

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

  Bucket by extension and path. The SOP-canonical layout is Fleet's
  v4.83 (`platforms/{platform}/...`) but the matchers are layout-
  agnostic — they key off file shape, not directory.

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
    # predicate ↔ subscription). Fires on dangling refs even if every
    # individual file passed schema validation above.
    contour profile ddm verify {dir} --json
    on non-zero: errors += verify-errors

  for tool, files in {pppc, btm, notifications, support}:
    for f in files:
      contour {tool} validate {f} --json
      on non-zero: errors += per-file-errors

  if buckets.mscp_present:
    # Whole-repo Fleet GitOps validate (paths, identifiers, label refs).
    # Slow-ish; opt-in via --mscp flag in the hook config.
    contour mscp validate -o {repo_root} --strict --json
    on non-zero: errors += mscp-errors

  # NB: enrollment .dep.json has no validator surface yet (Phase 2).
  # The hook silently skips them; flag in the README so authors know.

POSTCONDITIONS:
  if len(errors) > 0:
    Print human-readable summary grouped by file:
      "{file}: {error_code}: {first error message}"
    HALT exit 1   # blocks the commit
  else:
    exit 0        # commit proceeds

INVARIANTS:
  # The hook MUST only validate staged changes — not the whole working
  # tree. Otherwise:
  #   1. Slow on large repos (mSCP can take >10s for big baselines)
  #   2. Surfaces unrelated errors that aren't part of this commit
  ASSERT every path passed to contour came from `git diff --cached`

  # The hook MUST exit 0 on no-op commits (no relevant files staged).
  # Otherwise the hook becomes friction on pure-doc / unrelated commits.
  ASSERT no validators run when buckets are all empty

  # Validators receive RELATIVE paths from the repo root so the hook
  # works from any cwd inside the worktree.
  ASSERT every path is repo-relative (not absolute)

STEP 3 — Smoke test (the verification the user described):
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

The procedural half above is the contract; the recipes below are the
ready-to-paste implementations of STEP 2.

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

The `bash -c '...' --` shape is intentional: it lets pre-commit pass
file arguments via `"$@"` while keeping the `${CONTOUR:-contour}`
indirection so `CONTOUR=…/dist/contour` overrides the binary without
mutating `PATH`.

Install:
```bash
uvx pre-commit install                  # registers .git/hooks/pre-commit
uvx pre-commit run --all-files          # one-shot validate the whole tree
```

### Style B: framework-free `.git/hooks/pre-commit`

Drop in `.git/hooks/pre-commit`, `chmod +x`. No external dependencies.
Same script ships at `docs/examples/pre-commit-contour.sh`:

```bash
#!/usr/bin/env bash
# Contour pre-commit hook — validates staged contour artifacts.
# Exits non-zero on the first error so git aborts the commit.

set -uo pipefail

# Override binary location with `CONTOUR=/path/to/dist/contour git commit`
# (env propagates into this hook subprocess). Defaults to whatever's on PATH.
CONTOUR="${CONTOUR:-contour}"

# Resolve staged files relative to repo root.
staged() { git diff --cached --name-only --diff-filter=ACMR -- "$@" 2>/dev/null; }

# Group staged files into buckets.
profiles=$(staged '*.mobileconfig')
ddm_files=$(staged '**/declaration-profiles/*.json')
pppc_files=$(staged '**/pppc.toml')
btm_files=$(staged '**/btm.toml')
notif_files=$(staged '**/notifications.toml')
support_files=$(staged '**/support.toml')

# No-op fast path: nothing to validate.
if [[ -z "$profiles$ddm_files$pppc_files$btm_files$notif_files$support_files" ]]; then
  exit 0
fi

failed=0
fail() { echo "✗ contour: $*" >&2; failed=1; }

# .mobileconfig — schema-validate every staged profile.
if [[ -n "$profiles" ]]; then
  # shellcheck disable=SC2086
  "$CONTOUR" profile validate $profiles --json >/dev/null 2>&1 \
    || fail "configuration profile(s) failed validation; \
             run: $CONTOUR profile validate $profiles"
fi

# DDM .json — per-file schema validate.
if [[ -n "$ddm_files" ]]; then
  # shellcheck disable=SC2086
  "$CONTOUR" profile ddm validate $ddm_files --json >/dev/null 2>&1 \
    || fail "DDM declaration(s) failed schema validation; \
             run: $CONTOUR profile ddm validate $ddm_files"

  # Then a directory-level cross-reference DAG check on every dir
  # that touched DDM files. Catches dangling asset/config/predicate refs.
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

Starting point: clean Fleet GitOps repo with the hook registered:

```
$ uvx pre-commit install
pre-commit installed at .git/hooks/pre-commit
```

Now simulate a developer staging a malformed profile:

```
$ cat <<'EOF' > platforms/macos/configuration-profiles/bad.mobileconfig
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>PayloadType</key>
  <string>com.apple.does.not.exist</string>
</dict>
</plist>
EOF

$ git add platforms/macos/configuration-profiles/bad.mobileconfig
$ git commit -m "add: bad profile"
✗ contour: configuration profile(s) failed validation;
           run: contour profile validate platforms/macos/configuration-profiles/bad.mobileconfig

✗ contour pre-commit blocked: fix the errors above and re-commit.

$ # Investigate:
$ contour profile validate platforms/macos/configuration-profiles/bad.mobileconfig --json | jq '.[] | .errors'
[
  "Unknown payload type: com.apple.does.not.exist",
  "Missing PayloadIdentifier",
  "Missing PayloadUUID"
]

$ # Fix it (or remove the file):
$ rm platforms/macos/configuration-profiles/bad.mobileconfig
$ git add -u
$ git commit -m "add: bad profile"
[main abc1234] add: bad profile

$ # The hook ran but found nothing staged — clean exit, commit lands.
```

---

## Operational notes

- **Bypassing the hook**: `git commit --no-verify` skips it. Reserve for
  emergencies and document the bypass in the commit message.
- **Pre-commit on rename/delete**: the `--diff-filter=ACMR` covers Add /
  Copy / Modify / Rename. Pure deletes (`D`) skip validation — there's
  nothing to validate. Renames re-validate with the new path's content.
- **Performance**: contour validates are fast (~50ms per file, parallel
  with rayon by default). Even large commits stay <1s. The slow outlier
  is `contour mscp validate` on a full Fleet repo — gate that behind
  `--mscp` opt-in or a `commit-msg` hook so it doesn't block every
  routine commit.
- **CI parity**: the same validators that run in the hook should run
  in CI. The procedural SOP for CI lives in `--sop ci`; the hook is
  the developer-side mirror of that.
- **Schema freshness**: contour ships embedded schemas per release;
  re-installing the binary refreshes Apple's schema — no per-repo
  schema config required.

---

## Key facts

- **What the hook MUST validate (staged-only)**: every contour-typed
  file changed in the commit. Whole-tree validation belongs in CI.
- **What it MUST NOT do**: run `contour profile generate` or any
  network-bound operation. Hooks are validation only.
- **DDM cross-references** are a recurring footgun (predicate references
  an unsubscribed `@status`, or `*AssetReference` points at a missing
  asset). `ddm verify` was built specifically for this — wire it into
  the hook even if individual `ddm validate` is already there.
- **`--json` mode** on every validator emits a stable error envelope
  (`{success, error, error_code}`) so the hook can produce structured
  summaries without parsing prose.
