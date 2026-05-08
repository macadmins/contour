# SOP: Profile Change Impact Review (plan / rollback)

This SOP exists because **bulk edits to `.mobileconfig` files are dangerous
in ways that text diffs don't show.** A change that looks cosmetic in
`git diff` can do a remove-and-reinstall pass on every device in the
fleet, melt your CA under a thundering re-enrollment herd, or silently
disable a setting because a `<string>` was used where the consuming app
wants `<integer>`.

Use this SOP whenever you (or an AI agent) are about to:

- Regenerate UUIDs across more than one profile
- Refactor or "normalize" a directory of profiles
- Apply a vendor's profile pack into an existing GitOps repo
- Review a PR that modifies multiple `.mobileconfig` files
- Roll back a recent profile change without losing the legitimate parts

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`

## Why this matters (the risk model)

Apple MDM matches **profiles** by their outer `PayloadIdentifier`, and
**inner payloads** by `PayloadUUID`. When the new profile is pushed:

1. If outer `PayloadIdentifier` matches an installed profile → MDM updates
   that profile in place.
2. Inside the profile, every inner payload is matched by its
   `PayloadUUID`:
   - Same UUID, same type → **in-place update** of that payload's values.
   - New UUID → existing payload **removed**, new payload installed.
   - Missing UUID (was there, isn't now) → existing payload **removed**.

**The destructive case** is point 2's middle branch. Re-randomising
`PayloadUUID` while leaving `PayloadIdentifier` and `PayloadType` the
same looks identical to a human reviewer ("just a UUID rotation") but
costs the device a remove + reinstall — which for security-sensitive
payloads (SCEP, FileVault recovery escrow, identity preferences,
firewall) means a brief deconfigured window AND, for SCEP, a fresh
certificate enrollment against the CA. On a 15,000-endpoint fleet
that's a 15k-deep CA queue inside one push window.

**The silent-failure case** is what CodeRabbit flagged on a
33-file Fleet GitOps PR:

| Pattern | Failure mode |
|---|---|
| Regenerated SCEP `PayloadUUID` but left `PayloadCertificateUUID` pointing at the old SCEP UUID | Identity preference does not bind. Apps using mTLS to the IdP fail auth without an obvious error path. |
| Set `refreshSOFAFeedTime` as `<string>300</string>` instead of `<integer>` | Nudge's `Codable` decoder rejects the type and silently falls back to its 86,400-second default. The 5-minute interval the admin thought they configured never takes effect. |
| TCC ACL rule changed from `BundleIdentifier=com.okta.mobile` to `BundleIdentifierPrefix=com.okta.` | Every `com.okta.*`-signed bundle now satisfies the rule. Scope broadened past least-privilege. |
| Missing `PayloadDisplayName` on a nested payload | Cosmetic in profile UI; not a behavior change. Real, but low priority. |

These are different shapes of the same underlying problem: **the change
review process couldn't see the change.** `contour profile plan` and
`contour profile rollback` exist to make these invisible classes of
change visible and reversible.

## TIER ENUM (the change taxonomy)

`contour profile plan` classifies every payload-level delta into exactly
one tier. This enum is the contract; tooling, CI, and agents all branch
on it.

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
| REPLACE | non-zero | `--accept-replace` (informed acceptance) |
| SCOPE_BROADENED | non-zero | `--accept-scope-change` (informed acceptance) |
| REF_BROKEN / TYPE_INVALID / DEPRECATED | non-zero | none — fix the change |

## ERROR-CODE ENUM (procedure failures, not findings)

Findings ride in the TIER ENUM above. The error_code enum below
covers procedure-level failures (CLI couldn't run, file unreadable,
etc.). Agents MUST switch on these and never substring-match the
prose `error` field.

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

---

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
  # Determinism is a hard requirement for honest plans:
  AUTO_FIX: normalize both sides through normalize_profile (predictable
            v5 UUIDs when --org is supplied) before classifying.

EXECUTION:
  result = contour profile plan {baseline} {proposed} --json
           [--recursive] [--org {org}] [--predictable]
           [--accept-replace if accept.replace]
           [--accept-scope-change if accept.scope_change]
           [--fleet-size {accept.fleet_size}]

  # JSON shape (success path):
  #   { "success": true,
  #     "summary": { "noop": int, "in_place_update": int, "add": int,
  #                  "remove": int, "replace": int, "ref_broken": int,
  #                  "scope_broadened": int, "type_invalid": int,
  #                  "deprecated": int },
  #     "changes": [
  #       { "tier": <TIER>,
  #         "file": "<path>",
  #         "payload_index": int,
  #         "payload_type": string,
  #         "payload_identifier": string,
  #         "baseline_uuid": string | null,
  #         "proposed_uuid": string | null,
  #         "fields_changed": [string],
  #         "evidence": string,
  #         "blast_radius": { "endpoints": int | null, "narrative": string }
  #       }, ...
  #     ],
  #     "exit_policy": "ok" | "blocked",
  #     "blockers": [ "<TIER>:<file>:<payload_index>", ... ] }

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
          # plan ran, but exit policy denied — surface blockers to human
          REQUIRE human approval listing result.blockers
          # If the human accepts, retry with appropriate accept flag(s)
        DEFAULT:
          HALT  "plan failed: {result.error_code}: {result.error}"

INVARIANTS:
  - Re-running plan with identical inputs produces identical output
    (after normalize). Non-determinism in plan output is a bug.
  - REPLACE and IN_PLACE_UPDATE are mutually exclusive for a given pair.
  - Every REF_BROKEN finding names both the source payload (containing
    the dangling reference) and the dead UUID it points at.
```

---

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

  # JSON shape (success path, dry-run identical except `applied: false`):
  #   { "success": true,
  #     "applied": bool,
  #     "uuids_restored": int,
  #     "refs_rewritten": int,
  #     "files_changed": [string],
  #     "post_validation": { "valid": bool, "errors": [...] } }

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

---

## PROCEDURE review_bulk_profile_pr(pr_ref, base_ref)

The composed workflow an agent uses when asked to review a PR that
touches multiple profiles. This is the procedure to reach for first
when a CodeRabbit-style finding lands on a PR.

```
INPUT:
  pr_ref    : git ref of the PR head (e.g. origin/feature-branch)
  base_ref  : git ref of the merge base (default: origin/main)

STEP 1 — Plan the change:
  CALL plan_profile_changes(
    baseline = "git:" + base_ref,
    proposed = pr_ref worktree,
    accept   = {})

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
      # The 15k-CA-storm pattern. Two paths forward:
      #
      # a) The REPLACE was unintentional UUID churn (most common):
      #    CALL rollback_profile_changes(
      #      baseline = "git:" + base_ref,
      #      current  = pr_ref worktree,
      #      filter   = { uuids_only: true })
      #    Then re-plan. Should collapse to NOOP / IN_PLACE_UPDATE.
      #
      # b) The REPLACE was intentional (e.g. rotating a SCEP cert):
      #    REQUIRE human approval naming each REPLACE'd payload type
      #    and (if --fleet-size set) the blast-radius narrative.
      #    Approver re-runs plan with --accept-replace.

    CASE only SCOPE_BROADENED:
      # Security review territory. Surface the diff explicitly:
      WARN to human: list each ACL rule with old → new shape
      REQUIRE human approval; --accept-scope-change to proceed.

    CASE mixed (e.g. one REPLACE + one REF_BROKEN):
      # The Okta SCEP bug shape. Almost always a churn-introduced ref break.
      CALL rollback_profile_changes(
        baseline = "git:" + base_ref,
        current  = pr_ref worktree,
        filter   = { uuids_only: true, refs_only: true, rewrite_refs: true })
      Then re-plan. If the REF_BROKEN clears alongside the REPLACE,
      this was the Fleet pattern: vendor regenerated UUIDs, forgot to
      rewrite cross-refs. Rollback fixes both at once.

POSTCONDITIONS:
  RETURN { verdict, plan, rollback (if applied), required_fixes }

INVARIANTS:
  - Never approve a PR with non-zero blockers without an explicit
    accept flag and a recorded reason.
  - Plan output is the source of truth for review. Reviewer-eye
    judgement on a text diff is not sufficient for this class of file.
```

---

## Worked example: the Fleet GitOps PR (the four CodeRabbit findings)

Reproduce the failure modes locally to keep the SOP grounded:

```bash
# 1. The 33-file PayloadUUID churn problem.
contour profile plan baseline/ proposed/ --recursive --json
# Expected: 33 REPLACE findings, 0 IN_PLACE_UPDATE.

# Apply the fix in one pass:
contour profile rollback baseline/ proposed/ --recursive --uuids-only
contour profile plan baseline/ proposed/ --recursive --json
# Expected: 0 REPLACE, possibly some IN_PLACE_UPDATE (real value changes).

# 2. The orphaned PayloadCertificateUUID (Okta SCEP).
contour profile plan baseline/fleet-okta-conditional-access.mobileconfig \
                     proposed/fleet-okta-conditional-access.mobileconfig --json
# Expected: REPLACE on the SCEP payload AND REF_BROKEN on the identity
# preference. rollback --uuids-only --rewrite-refs fixes both.

# 3. The Nudge refreshSOFAFeedTime type error.
contour profile plan baseline/nudge-configuration.mobileconfig \
                     proposed/nudge-configuration.mobileconfig --json
# Expected: TYPE_INVALID at refreshSOFAFeedTime; fix to <integer>.

# 4. The Okta TCC scope broadening.
contour profile plan baseline/okta-verify-settings.mobileconfig \
                     proposed/okta-verify-settings.mobileconfig --json
# Expected: SCOPE_BROADENED on the TCC rule. Decide policy: keep
# exact BundleIdentifier or accept the prefix with --accept-scope-change.
```

## Decision tree (when to reach for which command)

```
    PR / change under review
                │
                ▼
    contour profile plan ──── all NOOP/IN_PLACE_UPDATE/ADD/REMOVE? ── yes ──► approve
                │                                  │
                │                                  └── no
                ▼
    Any REF_BROKEN / TYPE_INVALID / DEPRECATED? ── yes ──► request changes (no accept flag)
                │
                └── no
                ▼
    Any REPLACE? ── yes ──► was it intentional?
                │              │
                │              ├── no  ──► contour profile rollback --uuids-only [--refs-only]
                │              │           re-plan; should collapse.
                │              │
                │              └── yes ──► document blast radius; --accept-replace
                │
                └── no
                ▼
    Any SCOPE_BROADENED? ── yes ──► security review; --accept-scope-change if approved
                │
                └── no
                ▼
            approve
```

## Anti-patterns

- **Don't blanket-regenerate UUIDs as part of "normalize" runs.** Use
  `--predictable` so v5 UUIDs are derived from `(org, identifier)` and
  stay stable across runs. The CLI defaults `--predictable` on when
  `--org` is set; do not override.
- **Don't approve a profile PR off a text diff alone** for files with
  cross-references (SCEP/identity preferences, EAP/WiFi+root cert,
  IKEv2 VPN, FileVault escrow). The text diff cannot see the orphan.
- **Don't `git revert` a churn-only PR** when only some payloads need
  restoring. `git revert` discards real value changes; `contour profile
  rollback --payload-type ...` is the surgical alternative.
- **Don't substring-match the `error` prose** to detect plan blockers.
  Switch on the TIER ENUM and the `error_code` enum.
- **Don't disable `link::validator`** to make a plan pass. A failing
  link validator is the warning shot — fix the cross-reference.

## Wiring (after this SOP ships)

- Help routing: add a `"profile-changes" | "plan" | "rollback"` arm in
  `crates/contour-core/src/help_agents.rs`'s `generate_sop` match,
  pointing to `include_str!("../skills/contour/references/sop-profile-changes.md")`.
- Drift detector: extend `crates/profile/tests/sop_traps.rs` with one
  trap per documented `--json` shape (plan summary, plan changes entry,
  rollback result, error_code envelope).
- Migration status: add a row to `sop-format-spec.md`'s Migration table
  with status "Migrated (procedural)".
