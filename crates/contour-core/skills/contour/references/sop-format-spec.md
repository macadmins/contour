# Procedural SOP — Format Specification

This document defines the **procedural SOP format** used by SOPs that have
been migrated from prose to explicit control flow. It is the format spec,
not an SOP itself. For a working example, see `sop-profile.md` and the three
PROCEDURE blocks it contains.

The format's goal is to remove agent interpretation work: every branch is
explicit, every failure is typed, every contract is verifiable. Drift between
this spec and the CLI is detected by the `sop_traps` integration suite
(`crates/profile/tests/sop_traps.rs`).

---

## Primitives

| Primitive | Semantics |
|---|---|
| `PROCEDURE name(args)` | Reusable sub-routine; agents call by name |
| `SCHEMA_SOURCE: ...` / `SCHEMA_TOOL: ...` | Top-of-PROCEDURE pointer to where authoritative schema/data lives (e.g. an Apple repo + the CLI lookup that surfaces it) |
| `INPUT:` | Required arguments and their contracts |
| `PRECONDITIONS:` | Invariants checked **before** any side effect; fail fast |
| `BUILD ORDER:` | Per-step sequencing requirement: the listed steps MUST execute in the given order, because each step's output is referenced by the next |
| `EXECUTION:` | The CLI call(s) and the documented JSON response shape |
| `POSTCONDITIONS:` | Success-path checks AND every known error branch |
| `INVARIANTS:` | Properties that must hold for ALL inputs of this PROCEDURE (e.g. determinism) |
| `CROSS-FILE INVARIANT` | Relational ASSERT spanning multiple emitted files (e.g. `activation.references.contains(configuration.identifier)`); checked after all files are written |
| `DEPRECATED_LIST` | Named constant of inputs being phased out; `WARN if input in DEPRECATED_LIST` redirects agents to the supported replacement before generation runs |
| `ASSERT condition` | Invariant check; HALT if false |
| `HALT message` | Stop work, return error to caller, do NOT continue |
| `WARN message` | Surface to human; continue execution |
| `REQUIRE human approval` | Explicit escalation point before next step |
| `AUTO_FIX action` | Agent-safe self-correction; retry once |
| `SWITCH expr / CASE / DEFAULT` | Branch on a value; DEFAULT MUST HALT, never silently retry |
| `RETURN value` | Successful exit with payload |

---

## Structural rules for PROCEDUREs

- **Self-contained**: no shared state assumed between PROCEDURE blocks.
- **SCHEMA_SOURCE / SCHEMA_TOOL** at the top of a PROCEDURE tell agents where
  the authoritative schema lives (often Apple's `device-management` repo or
  contour's embedded data) and the exact CLI lookup to query it. Agents should
  prefer the live tool over training-data assumptions.
- **INPUT** declares the contract; the agent must populate every input before
  calling. Document non-obvious shape constraints (e.g. "file path, not directory").
- **PRECONDITIONS** run first, fail fast. Agents should never have to handle
  invalid inputs inside `EXECUTION` — that's what preconditions are for.
  This is also where `DEPRECATED_LIST` checks fire, so deprecated inputs get
  redirected before any side effects run.
- **BUILD ORDER** is for PROCEDUREs that emit multiple files where one file
  references another. List the steps in dependency order (bottom-up): the
  thing that gets referenced is created first, then the referrer. Out-of-order
  execution produces dangling references that fail at deploy time, not at
  authoring time — exactly the kind of failure mode the format is designed
  to prevent.
- **POSTCONDITIONS** cover the success path AND all known error branches.
  Use `SWITCH entry.error_code` over the typed enum below; never substring-match
  `entry.error` (the prose field) inside a SWITCH.
- **CROSS-FILE INVARIANT** runs after all files are written. Use this for
  relational checks the per-file PRECONDITIONS can't see (e.g. "every
  activation references an existing configuration"). If a CROSS-FILE
  INVARIANT fails, treat it as a structural bug — HALT, surface details, do
  not auto-fix.
- **AUTO_FIX is bounded** — exactly **one** retry, never more. Recurring
  failures are structural and must HALT, not loop.
- **INVARIANTS** document properties that hold for ALL inputs (e.g. determinism:
  re-running with identical inputs MUST produce identical output).

---

## ERROR-CODE ENUM (canonical)

Failures from any procedure surface a `error_code` field from this stable enum.
Migrated SOPs MUST switch on these codes. Agents MUST NOT substring-match the
prose `error` field — it's there for human readability, not branching.

```
INVALID_IDENTIFIER     identifier syntax issue (spaces, invalid chars)
INVALID_FORMAT         not a valid plist / corrupted / not a profile
MISSING_PAYLOAD_TYPE   required PayloadType field absent
SCHEMA_VIOLATION       failed Apple-schema validation
IO_ERROR               file not found, permission denied, disk full
INVALID_ORG            org domain malformed
UNKNOWN                unmatched — treat as fatal, do NOT auto-retry
```

**Stability contract:** never rename existing variants. New failure kinds get
new variants; never reclassify an existing code. Migrated SOPs and external
agents may already branch on the old name.

The mapping from prose error message to typed code lives in two parallel
implementations:

- `crates/profile/src/cli/glob_utils.rs::error_code_for` — used by `BatchResult`
  JSON output (normalize, jamf import, and any future batch command)
- `crates/contour-core/src/output.rs::classify_error` — used by `print_error_json`
  for top-level error envelopes when `--json` is set

The duplication is intentional: `contour-core` is upstream of `profile` in the
dep graph, so the mapping can't live only in `profile`. If a third caller
appears, factor into a shared spot.

---

## CLI contract (as of contour ≥0.2.1)

The pilot drove three CLI changes that close the gaps the format originally
had to bend around. Drift is detected by `sop_traps` — 9/9 traps pass means
spec ↔ CLI parity.

| Change | Affects | Trap |
|--------|---------|------|
| Single-file `normalize --json` emits `BatchResult` JSON on success | `normalize_profile` | trap 5 |
| `failure_categories[].files[]` carries typed `error_code` | `normalize_profile`, `import_jamf_backup`, future batch SOPs | trap 6 |
| Top-level errors emit `{success, error, error_code}` JSON on stderr when `--json` is set | all procedures (failure paths) | trap 9 |

**Two response shapes still distinguish empty-source from batch in `import --jamf`** —
the EMPTY-SOURCE shape (`{success: false, total_found: 0, message}`) lacks the
BatchResult fields. Agents detect this by checking for `"total_found"` in the
response. This is documented behavior, not a bug; it lets agents fail fast
without re-parsing potentially-empty `failure_categories[]`.

---

## Migration status

| SOP | Status | Notes |
|-----|--------|-------|
| `SOP_PROFILE` | ✅ Migrated | First, in `sop-profile.md`. 3 procedures + prose for non-piloted ops |
| `SOP_DDM` | ✅ Migrated | `sop-ddm.md`. `create_ddm_config` PROCEDURE introduces BUILD ORDER, CROSS-FILE INVARIANT, DEPRECATED_LIST, SCHEMA_SOURCE primitives |
| `SOP_MSCP` | ✅ Migrated | `sop-mscp.md`. `generate_baseline_compliance` + `resolve_odv` procedures. ODV-resolution is the killer trap prose SOPs only mention weakly |
| `SOP_OSQUERY` | ✅ Migrated | `sop-osquery.md`. `find_query_table` + `write_policy_query` procedures. Cookbook of idiomatic policy patterns kept as prose (Fleet's `it-and-security` repo is the source for several worked examples) |
| `SOP_ENROLLMENT` | ✅ Migrated | `sop-enrollment.md`. `generate_enrollment_profile` enforces a NEVER_SKIP invariant (FileVault, SoftwareUpdate) that prose SOP only mentioned weakly |
| `SOP_PPPC` | ✅ Migrated | `sop-pppc.md`. `generate_pppc_profile` PROCEDURE; per_app vs combined modes; org-suffix INVARIANT on PayloadIdentifier |
| `SOP_BTM` | ✅ Migrated | `sop-btm.md`. `generate_btm_profile` pins the mobileconfig-vs-DDM target choice (macOS 15+ guidance) |
| `SOP_NOTIFICATIONS` | ✅ Migrated | `sop-notifications.md`. `generate_notifications_profile`; documents the user-prior-choice deployment-order constraint |
| `SOP_SUPPORT` | ✅ Migrated | `sop-support.md`. `generate_support_profile` pins `nl.root3.support` PayloadType as an INVARIANT |
| `SOP_PRECOMMIT` | ✅ Migrated | `sop-precommit.md`. `configure_pre_commit_validation` PROCEDURE; uvx pre-commit + framework-free shell hook recipes; `${CONTOUR:-contour}` env-var override for testing pre-release binaries |
| `SOP_SANTA` | ✅ Migrated (cookbook format) | `sop-santa.md`. **Different shape** from procedural: decision tree at top + 6 named recipes. Procedural fights a fan-out command surface. CEL `target.*` field surface verified against `santa/Source/common/cel/Activation.{h,mm}` + santa.proto |
| `SOP_FLEET_MIGRATE` | ✅ Migrated (numbered playbook) | `sop-fleet-migrate.md`. **Different shape** from procedural: numbered playbook with manual diff-checkpoints between steps. Validated against fleetctl v4.84.2 `it-and-security` scaffold + `yaml-files.md`. Canonical v4.84+ form is `paths:` globs; per-file `path:` + `labels_include_*` is the targeted alternative |
| `SOP_CI` | ✅ Migrated (hybrid) | `sop-ci.md`. Hybrid: `configure_ci` PROCEDURE for the `gh variable set` / `gh secret set` bootstrap + workflow-recipe reference for the YAML patterns. Procedural where contracts are sharp; recipes where they're configuration |
| `SOP_SCHEMA_DATA` | ✅ Migrated (hybrid) | `sop-schema-data.md`. Hybrid: data inventory + three-layer versioning reference + `update_schema_data` PROCEDURE for the happy-path refresh from posture. Internal contour-dev SOP |
| `SOP_PROFILE_CHANGES` | ✅ Migrated (procedural) | `sop-profile-changes.md`. Three procedures (`plan_profile_changes`, `rollback_profile_changes`, `review_bulk_profile_pr`) covering bulk-edit risk: PayloadUUID churn, orphaned cross-refs, plist type-shape errors, ACL scope broadening. Forward-spec for `profile plan` + `profile rollback`. Worked example reproduces the four CodeRabbit findings on the Fleet GitOps PR |

**15/15 SOPs migrated.** Three formats are in active use:
- **Procedural** (11 SOPs) — single canonical procedure with typed errors
- **Cookbook / decision tree** (1: SOP_SANTA) — fan-out command surface
- **Numbered playbook** (1: SOP_FLEET_MIGRATE) — one-time, human-driven
- **Hybrid** (2: SOP_CI, SOP_SCHEMA_DATA) — procedure for the bootstrap, reference for the rest

---

## Adding a new SOP — recipe

The 14 existing SOPs cover the current contour surface. Add a new SOP
when a meaningful new tool is added (e.g. a new top-level command) or
when an existing SOP grows past the point where one file is readable.

1. **Pick the format** that fits the content:
   - Procedural (default) — when there's one canonical procedure with
     fail-fast preconditions and verifiable postconditions.
   - Cookbook + decision tree — when the surface is fan-out (multiple
     goals each with a different end-to-end pipeline; SOP_SANTA is the
     example).
   - Numbered playbook — for one-time / human-driven migrations where
     auto-fix would do more harm than good (SOP_FLEET_MIGRATE).
   - Hybrid — when one part is genuinely procedural and the rest is
     reference (SOP_CI, SOP_SCHEMA_DATA).

2. **Trace every documented command end-to-end** against the CLI with
   `--json`. Capture actual JSON shapes; do not guess.

3. **Add traps** to `crates/profile/tests/sop_traps.rs` (or the
   appropriate sibling file) for each precondition and postcondition
   the procedure documents. The trap suite is the effectiveness
   indicator — every migrated SOP should grow it.

4. **Write the SOP** as `crates/contour-core/skills/contour/references/sop-{name}.md`,
   following the closest existing example:
   - Procedural: `sop-profile.md` / `sop-ddm.md`
   - Cookbook + decision tree: `sop-santa.md`
   - Numbered playbook: `sop-fleet-migrate.md`
   - Hybrid: `sop-ci.md` / `sop-schema-data.md`

5. **Wire it up** in `crates/contour-core/src/help_agents.rs`:
   ```rust
   const SOP_FOO: &str = include_str!("../skills/contour/references/sop-foo.md");
   // …add `"foo" | …aliases…` arm to fn generate_sop's match.
   ```

6. **Validate against upstream** when the SOP cites external behaviour
   (Apple's device-management repo, Fleet's `fleetctl new` scaffold,
   Santa's CEL Activation, etc.). Cite the path you validated against
   in the SOP itself.

7. Run `cargo test -p profile --test sop_traps` and
   `cargo test -p contour-core`. Both must stay green.

8. Update this file's "Migration status" table.
