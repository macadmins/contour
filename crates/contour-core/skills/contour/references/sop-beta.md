# SOP: Beta (pre-release OS seed) schema

This SOP covers contour's **beta channel** — Apple's pre-release OS *seed* schema,
exposed opt-in via the per-command `--beta` flag OR the global `--channel beta` flag
(both select the seed; the effective channel is beta if **either** is set). The
global flag goes before the subcommand: `contour --channel beta profile ...`. The
channel is **rolling**: it always means *the current
seed* (`seed_OS_27_0` / OS 27 at time of writing — run `contour profile info` for the
live pin). When that OS ships, its payloads graduate into stable and the channel
rolls forward to the next seed; nothing here is version-specific. The beta dataset
is a strict **superset** of stable for additions: it carries seed-only declarations
and keys that do not exist in the stable channel. The two channels are isolated by
construction — seed-only types are invisible to (and rejected by) every stable
command — so a profile built for production can never silently absorb a pre-release
key unless `--beta` was explicitly passed.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Companion SOPs: `--sop generative` (Apple Intelligence payloads), `--sop ddm`,
`--sop enrollment`, `--sop schema-data`.

## SCOPE — what `--beta` does and does NOT cover

```
BETA-AWARE (accept --beta, and honor the global --channel beta):
  contour profile generate      <type> --beta   # .mobileconfig from the seed schema
  contour profile ddm generate  <type> --beta
  contour profile ddm validate  <path> --beta
  contour profile ddm search    <kw>   --beta
  contour profile ddm list             --beta
  contour profile ddm info      <type> --beta
  contour profile enrollment list       --beta
  contour profile enrollment generate    --beta

  # Equivalent global form (flag BEFORE the subcommand):
  contour --channel beta profile generate <type> --org <org> -o out.mobileconfig

NOT beta-aware (stable schema only):
  contour mscp ... / contour santa ... # no beta channel
```

When `profile generate` runs on the beta channel it **stamps** the artifact:
`PayloadDescription` is suffixed with `[contour: beta-seed schema]` (visible in MDM
consoles), and a stderr badge prints the pinned seed, e.g.
`⚠ generated from BETA seed schema (Apple seed seed_OS_27_0 <sha>)`. The stamp marks
the profile as built against pre-release schema — see SAFETY before deploying.

Data layer (for reference; agents use the CLI, not these directly):
`mdm_schema::embedded_capabilities_beta()`, `embedded_skip_keys_beta()` read
`crates/mdm-schema/data/beta/*.parquet`, published by the posture-ingest pipeline.

## INVARIANT — channel isolation

```
A seed-only type (introduced in the seed, absent from the stable release) is:
  - FOUND   only under --beta   (ddm info / search / list / generate)
  - VALID   only under --beta   (ddm validate)
  - REJECTED on the stable channel:
      ddm info <seed-type>        -> "not found"
      ddm validate <seed-decl>    -> error "Unknown declaration type … (re-run with --beta)"
      ddm generate <seed-type>    -> "not found"
      enrollment generate --skip <seed-key>  (no --beta) -> "Unknown skip key"
```

Treat this as a guardrail, not an obstacle: if a stable command rejects a type or
key as unknown, the correct fix is almost always to add `--beta`, NOT to work
around the rejection.

---

## PROCEDURE build_beta_artifact(type, org, output)

```
SCHEMA_TOOL: contour profile ddm search <kw> --beta --json
             contour profile ddm info <type> --beta --json

INPUT:
  type    : declaration short name (e.g. app.settings) or FULL type
            (com.apple.configuration.app.settings)
  org     : reverse-domain identifier (e.g. com.acme); required, never com.example
  output  : output file path

PRECONDITIONS:
  ASSERT org matches /^[a-z0-9-]+(\.[a-z0-9-]+)+$/ AND org != "com.example"
    HALT "org must be reverse-domain and not the com.example default"

  # SHORT-NAME RESOLVER GOTCHA — see below. When `type` is a substring of another
  # type (e.g. intelligence.settings ⊂ external-intelligence.settings), `generate`
  # can resolve to the WRONG type. Disambiguate with the FULL type.
  if type is a substring of any other registered type:
    USE the full com.apple.configuration.<type> form

STEP 1 — Confirm the type exists in the beta channel (never speculate):
  hit = contour profile ddm info {type} --beta --json
  ASSERT hit.declaration_type present
    HALT "type {type} not in beta schema; `ddm search {kw} --beta` to find it"
  # Sanity: the resolved Type must match intent (catches the substring gotcha).
  ASSERT hit.declaration_type endswith intended tail

STEP 2 — Generate against the seed schema (fail-closed):
  contour profile ddm generate {full_type} --beta [--full] \
      [--payload values.json] --org {org} -o {output}
  # --full surfaces all optional keys; --payload merges your values over the
  # skeleton. generate is fail-closed: a schema-invalid result is not written.

STEP 3 — Validate against the SAME channel:
  contour profile ddm validate {output} --beta
  ASSERT "valid"
  # Validating a beta artifact WITHOUT --beta is the isolation test: it must
  # report the type as unknown. That is expected, not a failure.

OUTPUT:
  A schema-valid seed declaration. STAMP it mentally as pre-release: see SAFETY.
```

---

## SHORT-NAME RESOLVER GOTCHA

`ddm generate <short>` and `ddm info <short>` use *different* name matching. When a
short name is a substring of another type, `generate` may pick the wrong one:

```
contour profile ddm generate intelligence.settings --beta
  -> may emit Type = com.apple.configuration.EXTERNAL-intelligence.settings (WRONG)
contour profile ddm info intelligence.settings --beta
  -> resolves correctly
```

MITIGATION: pass the **full type** to `generate` for any name that is a substring
of another (`intelligence.settings`, etc.), and verify `Type` in the output. Known
collision pairs: `intelligence.settings` ⊂ `external-intelligence.settings`.

---

## PROVENANCE — which seed is embedded

```
contour profile info            # human: "Apple seed (--beta): <sha> (seed_OS_27_0, <date>)"
contour profile info --json     # sources.apple_device_management_seed.{commit,date,release}
```

The seed pin lives in `schema-versions.toml`, which is **gitignored and
pipeline-maintained** (posture-ingest writes `[apple_device_management_seed]` into
the data zip; `build.rs` extracts it). When the seed line is absent, `profile info`
simply omits it — that means the embedded data predates seed-pin recording, not an
error. To refresh: re-publish from posture-ingest (a *beta* config prints the exact
seed-pin block to paste).

---

## SAFETY — beta is pre-release

- Seed schemas can change or be withdrawn before GA. A `--beta` artifact targets an
  OS that is not yet released; do NOT deploy it to a production fleet expecting
  stability. Treat it as authoring-ahead, validated against the current seed.
- Bumping the embedded seed (new Seed1→Seed2 commit) is a deliberate posture-ingest
  regeneration, not an automatic refresh — `build.rs` keeps existing `data/` until
  it is cleared.

## Key flags

- `--beta` — use the seed channel; default is stable. Omitting it is the isolation test.
- `--full` — include all optional fields (pairs well with `--beta` to surface new seed keys).
- `--payload <file>` — merge JSON/TOML values over the generated skeleton.
- `--json` — structured output for CI/agents.
