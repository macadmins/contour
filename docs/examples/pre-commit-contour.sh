#!/usr/bin/env bash
# Contour pre-commit hook — validates staged contour artifacts.
# Drop this in .git/hooks/pre-commit and chmod +x.
#
# Override binary location with `CONTOUR=/path/to/dist/contour git commit`
# (env propagates into this hook subprocess). Defaults to whatever's on PATH.
#
# Exits non-zero on the first failed validation so git aborts the commit.
# Bypass for emergencies: `git commit --no-verify`.

set -uo pipefail

CONTOUR="${CONTOUR:-contour}"

# Resolve staged files relative to repo root.
staged() { git diff --cached --name-only --diff-filter=ACMR -- "$@" 2>/dev/null; }

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

  # Directory-level cross-reference DAG check on every dir that touched
  # DDM files. Catches dangling asset/config refs and unsubscribed
  # @status() predicate keys (Error.UnableToEvaluatePredicate at deploy).
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
