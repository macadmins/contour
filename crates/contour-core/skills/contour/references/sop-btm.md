# SOP: Background Task Management (BTM) Profiles

Generate Background Task Management profiles or DDM declarations that
control which LaunchDaemons / LaunchAgents / login items are allowed
on managed macOS hosts.

This SOP exists primarily to pin **one decision point**:
mobileconfig-form (compatible with macOS 13–14) versus DDM declarations
(macOS 15+, the supported path going forward). Agents that pick the
wrong target ship working profiles that silently degrade once the
target version drops the legacy payload.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/contour/tests/sop_traps_btm.rs`

## ERROR-CODE ENUM

```
INVALID_FORMAT         btm.toml is not valid TOML / corrupted
SCHEMA_VIOLATION       rule_type or identifier_type unknown
IO_ERROR               input/output path un-readable / un-writeable
INVALID_ORG            org domain malformed
UNKNOWN                unmatched (e.g. plist round-trip failure)
```

Failure-path JSON envelope (since contour ≥0.2.1):

```json
{ "success": false, "error": "...", "error_code": "UNKNOWN" }
```

---

## PROCEDURE generate_btm_profile(btm_toml, output_dir, target, fragment, per_app)

```
SCHEMA_SOURCE: contour's embedded BTM rule registry (mirrors Apple's
                ServiceManagement.ManagedLoginItems schema)
SCHEMA_TOOL:   contour btm info --json
               contour btm validate {btm_toml} --json

INPUT:
  btm_toml     : path to a populated btm.toml file
  output_dir   : directory to write generated profiles or declarations
  target       : "mobileconfig" — legacy payload (com.apple.servicemanagement.managed)
                 "ddm"          — declaration JSON for macOS 15+ (preferred)
  fragment     : bool — when true, emit a GitOps fragment (Fleet `fragment.toml` schema)
                        directory instead of plain output
  per_app      : bool — split mobileconfig output into one `.mobileconfig`
                        per app (default is one merged file with every app's
                        rules inside). Mobileconfig-only knob: under `--ddm`
                        it is a silent no-op since DDM declarations are
                        inherently per-app.

PRECONDITIONS:
  ASSERT btm_toml exists AND is readable
    HALT "IO_ERROR: btm_toml not found at {btm_toml}"
  ASSERT parent(output_dir) exists OR can be created
    AUTO_FIX: mkdir -p {output_dir}
  ASSERT target in {"mobileconfig", "ddm"}
    HALT "target must be mobileconfig or ddm; got '{target}'"

STEP 1 — Validate the policy file:
  result = contour btm validate {btm_toml} --json
  # Returns:
  #   { "valid": bool,
  #     "btm_app_count": int,
  #     "btm_rule_count": int,
  #     "error_count": int,
  #     "warning_count": int,
  #     "errors":   [ { "rule": str?, "message": str }, ... ],
  #     "warnings": [ { ... }, ... ] }

  ASSERT result.valid == true
    HALT "SCHEMA_VIOLATION: btm.toml has {result.error_count} errors; \
          first: {result.errors[0].message}"

  if result.warning_count > 0:
    WARN "{result.warning_count} warning(s) — first: \
          {result.warnings[0].message}"

  ASSERT result.btm_rule_count > 0
    HALT "no BTM rules in {btm_toml}; run `contour btm scan` first \
          or edit the file to add a [[rules]] entry"

STEP 2 — Generate the output:
  flags = ["-o", output_dir, "--json"]
  if target == "ddm":
    # `--ddm` emits one `.json` DDM declaration per app in combined
    # (default) and `--per-app` mode alike — DDM is per-declaration by
    # nature, so `--per-app` is effectively a no-op under `--ddm`.
    flags += ["--ddm"]
  elif per_app:
    # Mobileconfig path only: combined (default) merges every app into
    # ONE `.mobileconfig` with all rules inside; `--per-app` splits the
    # output into ONE `.mobileconfig` per app — useful when scoping
    # per-app via labels/groups in the MDM, or when removing a single
    # app's profile without touching the others.
    flags += ["--per-app"]
  if fragment:
    flags += ["--fragment"]
  result = contour btm generate {btm_toml} {flags...}

  if result.exit_code != 0:
    HALT "{result.error_code}: {result.error}"

INVARIANTS:
  # mobileconfig + DDM are not interchangeable: generating mobileconfig
  # for a target running macOS 15+ works, but the device will not get
  # subsequent updates via declarative channels. Generating DDM for
  # macOS 13/14 deploys nothing — the declaration is silently ignored.
  WARN if target == "mobileconfig" AND macOS_min_version >= 15
    "mobileconfig BTM is supported but no longer the preferred path \
     for macOS 15+. Consider re-generating with --ddm."
  WARN if target == "ddm" AND macOS_min_version < 15
    "DDM declarations require macOS 15+. Hosts on macOS 13/14 will \
     ignore this. Use --mobileconfig (default) for those hosts."

STEP 3 — Verify the output:
  if fragment:
    ASSERT output_dir contains fragment.toml
      HALT "fragment mode did not produce fragment.toml — likely a CLI bug"
    if target == "ddm":
      ASSERT output_dir contains platforms/macos/declaration-profiles/
        HALT "DDM fragment missing platforms/macos/declaration-profiles/"
    else:
      ASSERT output_dir contains platforms/macos/configuration-profiles/
        HALT "mobileconfig fragment missing configuration-profiles/"
  else:
    if target == "ddm":
      written = list(output_dir, "*.json")
      ASSERT len(written) >= 1
        HALT "no .json declarations emitted"
    else:
      written = list(output_dir, "*.mobileconfig")
      ASSERT len(written) >= 1
        HALT "no .mobileconfig emitted"

POSTCONDITIONS:
  RETURN {
    output_dir,
    target,
    fragment,
    file_count: len(written),
  }
```

---

## Other operations (prose recipes)

### Initialise a new policy file

```
contour btm init --org com.acme -o btm.toml
# Stub with [settings] block and empty apps. Add via scan or
# manual edit.
```

### Scan launch items

```
contour btm scan --org com.acme -o btm.toml --json
# Walks /Library/Launch{Daemons,Agents}/, ~/Library/LaunchAgents/, and
# extracts team IDs / bundle identifiers. Re-runnable; merges with
# existing entries.
```

### Merge rules from another config

```
contour btm merge source.toml --into target.toml
# Useful when consolidating rules from multiple machines into a single
# managed config.
```

### Validate an existing policy

```
contour btm validate btm.toml --json
# Same JSON shape consumed by STEP 1 above.
```

### Diff two policy files

```
contour btm diff base.toml updated.toml --json
# Lists added/removed/changed rules between revisions.
```

---

## Key facts

- BTM rules use `team-id`, `signing-id`, or `bundle-id` as the
  identifier type. `team-id` is the broadest (allows all binaries from
  a vendor) and the most common in practice.
- The DDM target writes `*.json` files conforming to Apple's
  `com.apple.servicemanagement.managed` declaration schema; one file
  per logical rule grouping.
- BTM is the canonical replacement for ManagedLoginItems on macOS 15+.
  Pre-Tahoe hosts continue to honour the mobileconfig form.
- Fragment mode (`--fragment`) is the recommended output for adding to
  a GitOps repo (Fleet v4.83 layout); it places `.mobileconfig` files under
  `platforms/macos/configuration-profiles/` and `.json` declarations
  under `platforms/macos/declaration-profiles/`.
