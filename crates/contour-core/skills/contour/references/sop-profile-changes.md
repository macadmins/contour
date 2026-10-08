# SOP: Profile Change Impact Review (plan / rollback)

Bulk `.mobileconfig` edits can reinstall payloads fleet-wide or silently
disable settings in ways text diffs don't show. Use this SOP whenever you
are about to:

- Regenerate UUIDs across more than one profile
- Refactor or "normalize" a directory of profiles
- Apply a vendor's profile pack into an existing GitOps repo
- Review a PR that modifies multiple `.mobileconfig` files
- Roll back a recent profile change without losing the legitimate parts

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`

## Why this matters (the risk model)

Apple MDM matches **profiles** by outer `PayloadIdentifier` (match → update
in place), then **inner payloads** by `PayloadUUID`:

1. Same UUID, same type → **in-place update** of that payload's values.
2. New UUID → existing payload **removed**, new payload installed.
3. Missing UUID (was there, isn't now) → existing payload **removed**.

**The destructive case** is point 2: a re-randomised `PayloadUUID` looks like
"just a UUID rotation" but is a remove + reinstall — a deconfigured window,
and for SCEP a fresh certificate enrollment per device against the CA.

**The silent-failure cases:**

| Pattern | Failure mode |
|---|---|
| Regenerated SCEP `PayloadUUID` but left `PayloadCertificateUUID` pointing at the old SCEP UUID | Identity preference does not bind; mTLS to the IdP fails without an obvious error. |
| Set `refreshSOFAFeedTime` as `<string>300</string>` instead of `<integer>` | Nudge rejects the type and silently falls back to its 86,400-second default. |
| TCC ACL rule changed from `BundleIdentifier=com.okta.mobile` to `BundleIdentifierPrefix=com.okta.` | Every `com.okta.*` bundle now satisfies the rule — scope broadened. |
| Missing `PayloadDisplayName` on a nested payload | Cosmetic; low priority. |

`contour profile plan` and `contour profile rollback` make these changes
visible and reversible.

## TIER ENUM (the change taxonomy)

`contour profile plan` classifies every payload-level delta into exactly
one tier. Agents and CI branch on it.

```
NOOP              canonical-form-only delta after normalize; nothing pushed
IN_PLACE_UPDATE   same PayloadUUID + PayloadType, payload values changed
ADD               PayloadUUID exists in proposed, not in baseline
REMOVE            PayloadUUID exists in baseline, not in proposed
REPLACE           PayloadUUID changed but (PayloadType, PayloadIdentifier)
                  match — destructive remove + reinstall
REF_BROKEN        PayloadCertificateUUID / PayloadCertificateAnchorUUID /
                  EAP / IKEv2 ref points at a UUID that does not resolve
SCOPE_BROADENED   TCC ACL widened (BundleIdentifier → BundleIdentifierPrefix
                  / Path → PathPrefix), PayloadScope widened, managed-domain
                  wildcard introduced
TYPE_INVALID      plist value type does not match the consuming-app schema
DEPRECATED        introduces a deprecated payload type or key
```

**Default exit policy** (CI-ready):

| Tier | Exit | Override |
|---|---|---|
| NOOP / IN_PLACE_UPDATE / ADD / REMOVE | 0 | — |
| REPLACE | non-zero | `--accept-replace` |
| SCOPE_BROADENED | non-zero | `--accept-scope-change` |
| REF_BROKEN / TYPE_INVALID / DEPRECATED | non-zero | none — fix the change |

## ERROR-CODE ENUM (procedure failures, not findings)

Findings ride in the TIER ENUM; these codes cover procedure-level failures.
Agents MUST switch on these and never substring-match the prose `error` field.

```
INVALID_FORMAT       not a valid plist / corrupted / not a profile
INVALID_BASELINE     baseline path doesn't exist or doesn't parse
INVALID_PROPOSED     proposed path doesn't exist or doesn't parse
PLAN_BLOCKED         plan succeeded but exit policy denies (REPLACE etc.
                     without accept flag, or any blocker tier)
ROLLBACK_UNSAFE      rollback would produce a broken reference graph
                     (post-rollback link::validator failed); fail closed
IO_ERROR             file unreadable / disk full / permission denied
UNKNOWN              unmatched — treat as fatal, do NOT auto-retry
```

## PROCEDURE plan_profile_changes(baseline, proposed, accept)

```
SCHEMA_SOURCE: contour's embedded schemas + per-app schemas
                (Nudge, Santa, Okta Verify, Munki) under crates/mdm-schema
SCHEMA_TOOL:   contour profile plan <baseline> <proposed> --json

INPUT:
  baseline  : path to a profile, a directory of profiles, or "git:<ref>"
              (e.g. "git:HEAD" — read from the working tree's git index)
  proposed  : path to a profile, a directory of profiles, or "-" (stdin)
  accept    : object with optional flags
              { replace      : bool   # downgrade REPLACE to warning
              , scope_change : bool   # downgrade SCOPE_BROADENED to warning
              , fleet_size   : int    # multiply blast-radius numbers
              }

PRECONDITIONS:
  ASSERT baseline resolves
    HALT INVALID_BASELINE "baseline path does not exist or did not parse"
  ASSERT proposed resolves
    HALT INVALID_PROPOSED "proposed path does not exist or did not parse"
  ASSERT both sides have the same number of profiles when directories,
         OR baseline and proposed are both single files
    WARN  "directory shape changed; ADD/REMOVE tiers will be non-empty"
  AUTO_FIX: normalize both sides through normalize_profile (predictable
            v5 UUIDs when --org is supplied) before classifying.

EXECUTION:
  result = contour profile plan {baseline} {proposed} --json
           [--recursive] [--org {org}] [--predictable]
           [--accept-replace if accept.replace]
           [--accept-scope-change if accept.scope_change]
           [--fleet-size {accept.fleet_size}]

  # JSON shape (success path):
  { "success": true,
    "summary": { "noop": int, "in_place_update": int, "add": int,
                 "remove": int, "replace": int, "ref_broken": int,
                 "scope_broadened": int, "type_invalid": int, "deprecated": int },
    "changes": [ { "tier": <TIER>, "file": "<path>", "payload_index": int,
                   "payload_type": string, "payload_identifier": string,
                   "baseline_uuid": string|null, "proposed_uuid": string|null,
                   "fields_changed": [string], "evidence": string,
                   "blast_radius": { "endpoints": int|null, "narrative": string } }, ... ],
    "exit_policy": "ok"|"blocked",
    "blockers": [ "<TIER>:<file>:<payload_index>", ... ] }

POSTCONDITIONS:
  SWITCH result.exit_code
    CASE 0:
      RETURN { plan: result, ok: true }
    CASE non-zero:
      SWITCH result.error_code
        CASE INVALID_BASELINE:
          HALT  "baseline could not be resolved: {result.error}"
        CASE INVALID_PROPOSED:
          HALT  "proposed could not be resolved: {result.error}"
        CASE PLAN_BLOCKED:
          REQUIRE human approval listing result.blockers
          # if accepted, retry with the matching accept flag(s)
        DEFAULT:
          HALT  "plan failed: {result.error_code}: {result.error}"

INVARIANTS:
  - Re-running plan with identical inputs produces identical output
    (after normalize). Non-determinism in plan output is a bug.
  - REPLACE and IN_PLACE_UPDATE are mutually exclusive for a given pair.
  - Every REF_BROKEN finding names both the source payload (containing
    the dangling reference) and the dead UUID it points at.
```

## PROCEDURE rollback_profile_changes(baseline, current, filter)

```
SCHEMA_SOURCE: contour cross-reference catalog
                (crates/profile/src/link/types.rs::REFERENCE_FIELDS)
SCHEMA_TOOL:   contour profile rollback <baseline> <current> --json

INPUT:
  baseline  : the "good" state (file, directory, or "git:<ref>")
  current   : the state to repair (file or directory)
  filter    : { uuids_only       : bool   # restore only PayloadUUID values
              , payload_types    : [string] # restore only these types
              , refs_only        : bool   # restore only payloads other
                                          # payloads reference (certs etc.)
              , rewrite_refs     : bool   # default true; rewrite cross-
                                          # references after restoring UUIDs
              }

PRECONDITIONS:
  ASSERT baseline resolves
    HALT INVALID_BASELINE
  ASSERT current resolves
    HALT INVALID_PROPOSED
  ASSERT filter.uuids_only OR filter.payload_types is non-empty
                            OR filter.refs_only
    WARN  "no rollback filter set — every PayloadUUID will be restored"
    REQUIRE human approval

EXECUTION:
  result = contour profile rollback {baseline} {current} --json
           [--uuids-only if filter.uuids_only]
           [--payload-type {t} for t in filter.payload_types]
           [--refs-only if filter.refs_only]
           [--no-rewrite-refs if not filter.rewrite_refs]
           [--dry-run on first pass]

  # JSON shape (success path; dry-run identical except `applied: false`):
  { "success": true, "applied": bool, "uuids_restored": int,
    "refs_rewritten": int, "files_changed": [string],
    "post_validation": { "valid": bool, "errors": [...] } }

POSTCONDITIONS:
  ASSERT result.post_validation.valid
    HALT ROLLBACK_UNSAFE
         "rollback would orphan {result.post_validation.errors.len()}
          cross-reference(s); aborted before write."
  # Re-plan to confirm the diff collapses:
  CALL plan_profile_changes(baseline, current_after_rollback, {})
  ASSERT result.summary.replace == 0 AND result.summary.ref_broken == 0
    WARN "rollback applied but plan still reports destructive tiers;
          investigate before pushing"
  RETURN result

INVARIANTS:
  - Rollback never *generates* UUIDs. It only restores values from baseline.
  - Reference rewrite is symmetric with extraction: every UUID that
    `link::extractor` finds, `rollback::restorer` can rewrite.
  - Fail closed on broken references — never write a half-rolled-back
    profile.
```

## PROCEDURE review_bulk_profile_pr(pr_ref, base_ref)

Reach for this first when reviewing a PR that touches multiple profiles.

```
INPUT:
  pr_ref    : git ref of the PR head (e.g. origin/feature-branch)
  base_ref  : git ref of the merge base (default: origin/main)

STEP 1 — Plan the change:
  CALL plan_profile_changes(baseline = "git:" + base_ref,
    proposed = pr_ref worktree, accept = {})

  SWITCH plan.summary
    CASE all NOOP:
      RETURN { verdict: "approve", note: "no semantic change after normalize" }

    CASE only IN_PLACE_UPDATE/ADD/REMOVE:
      RETURN { verdict: "approve", note: "<n> in-place updates, <n> adds, <n> removes" }

    CASE any REF_BROKEN, TYPE_INVALID, DEPRECATED:
      # Hard blockers. Do not approve.
      RETURN { verdict: "request_changes",
               required_fixes: plan.blockers,
               note: "fix the change; these tiers don't have an accept flag" }

    CASE only REPLACE, no other blockers:
      IF unintentional UUID churn (most common):
        CALL rollback_profile_changes(baseline = "git:" + base_ref,
          current = pr_ref worktree, filter = { uuids_only: true })
        Then re-plan; should collapse to NOOP / IN_PLACE_UPDATE.
      IF intentional (e.g. rotating a SCEP cert):
        REQUIRE human approval naming each REPLACE'd payload type
        and (if --fleet-size set) the blast-radius narrative.
        Approver re-runs plan with --accept-replace.

    CASE only SCOPE_BROADENED:
      WARN to human: list each ACL rule with old → new shape
      REQUIRE human approval; --accept-scope-change to proceed.

    CASE mixed (e.g. one REPLACE + one REF_BROKEN):
      # Almost always a churn-introduced ref break.
      CALL rollback_profile_changes(baseline = "git:" + base_ref,
        current = pr_ref worktree,
        filter = { uuids_only: true, refs_only: true, rewrite_refs: true })
      Then re-plan; the REF_BROKEN should clear alongside the REPLACE.

POSTCONDITIONS:
  RETURN { verdict, plan, rollback (if applied), required_fixes }

INVARIANTS:
  - Never approve a PR with non-zero blockers without an explicit
    accept flag and a recorded reason.
  - Plan output is the source of truth for review, not a text diff.
```

## Worked example: a Fleet GitOps PR (four review findings)

```bash
# 1. PayloadUUID churn across a directory → REPLACE findings.
contour profile plan baseline/ proposed/ --recursive --json
contour profile rollback baseline/ proposed/ --recursive --uuids-only
contour profile plan baseline/ proposed/ --recursive --json
# Expected: 0 REPLACE; IN_PLACE_UPDATE only for real value changes.

# 2. Orphaned PayloadCertificateUUID (SCEP).
contour profile plan baseline/fleet-okta-conditional-access.mobileconfig \
                     proposed/fleet-okta-conditional-access.mobileconfig --json
# Expected: REPLACE on SCEP + REF_BROKEN on the identity preference.
# rollback --uuids-only fixes both: it rewrites refs by default
# (--no-rewrite-refs opts out).

# 3. Nudge refreshSOFAFeedTime type error.
contour profile plan baseline/nudge-configuration.mobileconfig \
                     proposed/nudge-configuration.mobileconfig --json
# Expected: TYPE_INVALID at refreshSOFAFeedTime; fix to <integer>.

# 4. TCC scope broadening.
contour profile plan baseline/okta-verify-settings.mobileconfig \
                     proposed/okta-verify-settings.mobileconfig --json
# Expected: SCOPE_BROADENED. Keep exact BundleIdentifier, or accept the
# prefix with --accept-scope-change.
```

## Decision tree (when to reach for which command)

```
contour profile plan
  all NOOP/IN_PLACE_UPDATE/ADD/REMOVE        → approve
  any REF_BROKEN/TYPE_INVALID/DEPRECATED     → request changes (no accept flag)
  any REPLACE, unintentional                 → contour profile rollback --uuids-only [--refs-only];
                                               re-plan; should collapse
  any REPLACE, intentional                   → document blast radius; --accept-replace
  any SCOPE_BROADENED                        → security review; --accept-scope-change if approved
  otherwise                                  → approve
```

## Anti-patterns

- **Don't blanket-regenerate UUIDs as part of "normalize" runs.** Use
  `--predictable` (v5 UUIDs from `(org, identifier)`, stable across runs);
  it defaults on when `--org` is set — do not override.
- **Don't approve a profile PR off a text diff alone** for files with
  cross-references (SCEP/identity preferences, EAP/WiFi+root cert, IKEv2
  VPN, FileVault escrow). The text diff cannot see the orphan.
- **Don't `git revert` a churn-only PR** when only some payloads need
  restoring — it discards real value changes; use `contour profile
  rollback --payload-type ...`.
- **Don't substring-match the `error` prose** to detect plan blockers.
  Switch on the TIER ENUM and the `error_code` enum.
- **Don't disable `link::validator`** to make a plan pass — fix the
  cross-reference.

## Wiring (after this SOP ships)

Maintainers only: served by `generate_sop` in
`crates/contour-core/src/help_agents.rs`; `--json` shapes are pinned in
`crates/profile/tests/sop_traps.rs`.
