# Pseudocode SOP — Format Specification

This document defines the **procedural pseudocode format** used by SOPs that
have been migrated from prose to explicit control flow. It is the format spec,
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
| `INPUT:` | Required arguments and their contracts |
| `PRECONDITIONS:` | Invariants checked **before** any side effect; fail fast |
| `EXECUTION:` | The CLI call(s) and the documented JSON response shape |
| `POSTCONDITIONS:` | Success-path checks AND every known error branch |
| `INVARIANTS:` | Properties that must hold for ALL inputs (e.g. determinism) |
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
- **INPUT** declares the contract; the agent must populate every input before
  calling. Document non-obvious shape constraints (e.g. "file path, not directory").
- **PRECONDITIONS** run first, fail fast. Agents should never have to handle
  invalid inputs inside `EXECUTION` — that's what preconditions are for.
- **POSTCONDITIONS** cover the success path AND all known error branches.
  Use `SWITCH entry.error_code` over the typed enum below; never substring-match
  `entry.error` (the prose field) inside a SWITCH.
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
| `SOP_MSCP` | ⏳ Pending | Good fit; per-task workflow |
| `SOP_OSQUERY` | ⏳ Pending | Good fit; search/lookup + 6 query patterns |
| `SOP_DDM` | ⏳ Pending | Good fit; same shape as profile generation |
| `SOP_ENROLLMENT` | ⏳ Pending | Good fit; built-in decision guide for skip keys |
| `SOP_PPPC` | ⏳ Pending | Good fit; linear init→scan→configure→generate |
| `SOP_BTM` | ⏳ Pending | Good fit; trivial init→generate |
| `SOP_NOTIFICATIONS` | ⏳ Pending | Good fit; trivial generate-only |
| `SOP_SUPPORT` | ⏳ Pending | Good fit; trivial generate-only |
| `SOP_SANTA` | ❌ Different format | Cookbook of 6 divergent recipes — needs decision tree at top |
| `SOP_FLEET_MIGRATE` | ❌ Different format | One-time migration playbook with manual diff checks |
| `SOP_CI` | ⚠️ Hybrid | Configuration setup + thin `configure-ci` procedure |
| `SOP_SCHEMA_DATA` | ⚠️ Hybrid | Developer reference + happy-path `update-schema-data` procedure |

---

## Migrating a new SOP — recipe

1. Pick an SOP from the "⏳ Pending" list above.
2. **Trace every documented command end-to-end** against the CLI with `--json`.
   Capture actual JSON shapes; do not guess.
3. **Add traps** to `crates/profile/tests/sop_traps.rs` for each precondition
   and postcondition the new procedure documents. The trap suite is the
   effectiveness indicator — every migrated SOP should grow it.
4. **Write the SOP** as `crates/contour-core/skills/contour/references/sop-{name}.md`,
   following the structure of `sop-profile.md`:
   - Brief preamble pointing to this file as the format spec
   - Inline copy of the ERROR-CODE ENUM for self-containment
   - One PROCEDURE block per traced operation
   - Prose recipes for any operation not yet traced
5. **Wire it up** in `crates/contour-core/src/help_agents.rs`:
   ```rust
   const SOP_FOO: &str = include_str!("../skills/contour/references/sop-foo.md");
   ```
6. Run `cargo test -p profile --test sop_traps` and `cargo test -p contour-core`.
   Both must stay green.
7. Update this file's "Migration status" table.
