# SOP: mSCP Security Compliance

This SOP covers the macOS Security Compliance Project (mSCP) integration:
generating MDM-deployable compliance artifacts (mobileconfigs, scripts,
policies, labels) for baselines like CIS Level 1, 800-53, STIG, CMMC.

## Layout: 1.x vs 2.0 (auto-detected)

mSCP ships in two coexisting shapes; contour auto-detects which one a
`--mscp-repo` path holds by sniffing one rule YAML.

| Signal | Layout | Notes |
|---|---|---|
| Top-level `platforms:` key on a rule | **2.0** | multi-OS (`macOS`/`iOS`/`visionOS`) under one rule file |
| Top-level `id:` without `platforms:` | **1.x** | flat schema with top-level `tags`/`check`/`fix` |
| Neither | error | "could not detect mSCP layout" with the offending file |

**1.x rule (legacy):**

```yaml
id: system_settings_screensaver_password_enforce
title: Enforce Screensaver Password
check: '/usr/bin/osascript -l JavaScript ...'
fix: '/usr/bin/defaults write ...'
result: { string: 'true' }
tags: [cis_lvl1, cis_lvl2, disa_stig]
mobileconfig: true
mobileconfig_info:
  com.apple.screensaver:
    askForPassword: true
```

**2.0 rule (multi-OS):**

```yaml
id: system_settings_screensaver_password_enforce
title: Enforce Screensaver Password
platforms:
  macOS:
    '15.0':
      benchmarks:
        - name: cis_lvl1
        - name: disa_stig
          severity: medium
    enforcement_info:
      check: { shell: '/usr/bin/osascript -l JavaScript ...', result: { string: 'true' } }
      fix:   { shell: '/usr/bin/defaults write ...' }
  iOS:
    '18.0':
      supervised: true
      benchmarks:
        - name: cis_lvl1_byod
mobileconfig_info:
  - PayloadType: com.apple.screensaver
    PayloadContent:
      - askForPassword: true
```

**Operator flags** (on `mscp recipe` and friends):

- `--mscp-version <auto|1.x|2.0>` — default `auto`
- `--os <macos|ios|visionos>` — default `macos`; ignored for 1.x
- `--os-version <X.Y>` — default: highest version present in the rule set

Internally the 2.0 deserializer flattens to the same `MscpRule` struct
1.x produces, parameterized on `(os, os_version)`. Downstream extractors,
recipe aggregators, and ODV resolvers don't know or care which layout
the input came from.

---

mSCP rules carry rich metadata that agents must inspect before generation —
the most important is **organization-defined values (ODV)**. Many rules
have a baseline-specific recommended value but a generic `odv_default`
that's wrong for production. Generating without surfacing the choice to
the user produces deployable but incorrect compliance artifacts.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/profile/tests/sop_traps.rs`

## ERROR-CODE ENUM

```
INVALID_IDENTIFIER     baseline name has spaces / invalid chars
INVALID_FORMAT         baseline.toml or repo metadata is corrupted
MISSING_PAYLOAD_TYPE   rule references a payload type the schema doesn't have
SCHEMA_VIOLATION       generated artifact failed Apple-schema validation
IO_ERROR               mscp_repo path missing, output dir un-writeable, etc.
INVALID_ORG            org domain absent or malformed
UNKNOWN                unmatched — treat as fatal, do NOT auto-retry
```

Failure-path JSON envelope (since contour ≥0.2.1):

```json
{ "success": false, "error": "...", "error_code": "INVALID_ORG" }
```

NB: clap-level usage errors (e.g. missing `--mscp-repo`) emit on stderr
without a JSON envelope and exit code 2, NOT 1. Agents that branch on
exit code MUST distinguish 0 (ok), 1 (anyhow error → JSON envelope),
2 (clap usage error → plain stderr).

---

## DEPRECATED_LIST

mSCP rules can produce mobileconfigs that target legacy payloads being
phased out by Apple. The most impactful:

```
DEPRECATED_PAYLOADS = [
  "com.apple.SoftwareUpdate"
    -> use DDM: com.apple.configuration.softwareupdate.settings
              + com.apple.configuration.softwareupdate.enforcement.specific
       (See sop-ddm.md / create_ddm_config.)
]
```

Software-update mSCP rules with `enforcement_type: "mobileconfig"` should
trigger `WARN if any rule in baseline targets a deprecated payload`. The
DDM-native replacement is in scope for `create_ddm_config`, not
`generate_baseline_compliance`.

---

## PROCEDURE generate_baseline_compliance(baseline, org, mscp_repo, output_dir)

```
SCHEMA_SOURCE: usnistgov/macos_security (release branch matching macOS version)
SCHEMA_TOOL:   contour mscp schema baselines --json
               contour mscp schema rules --baseline {name} --json
               contour mscp schema rule {rule_id} --json

INPUT:
  baseline    : baseline name from `mscp schema baselines` (e.g. cis_lvl1,
                800-53r5_high, stig). MUST match an existing baseline; the
                CLI silently emits no rules for unknown names.
  org         : reverse-domain identifier (com.acme). REQUIRED — the CLI
                refuses to default to com.example since contour ≥0.2.1.
  mscp_repo   : path to a checked-out usnistgov/macos_security repo.
                Required for full generation (Python pipeline runs from there).
  output_dir  : where to emit the v4.83 GitOps layout. Will be populated
                with platforms/macos/{configuration-profiles,scripts,policies}/
                {baseline}/, mscp/{baseline}/baseline.toml, labels/, fleets/.

PRECONDITIONS:
  ASSERT baseline matches /^[a-z0-9_]+(-r[0-9]+)?(_[a-z0-9]+)*$/
    HALT "baseline name has invalid chars; got '{baseline}'"
  ASSERT org matches /^[a-z0-9-]+(\.[a-z0-9-]+)+$/
    HALT "org must be reverse-domain; got '{org}'"
  ASSERT org != "com.example"
    HALT "refusing default 'com.example'"
  ASSERT mscp_repo path exists and contains rules/, baselines/
    HALT "mscp_repo {mscp_repo} is not a usnistgov/macos_security checkout"
  ASSERT output_dir exists OR can be created
    AUTO_FIX: mkdir -p {output_dir}

  # Confirm the baseline is real BEFORE running the (slow) Python pipeline.
  baselines = contour mscp schema baselines --json
  ASSERT baseline in baselines.map(b -> b.baseline)
    HALT "unknown baseline '{baseline}'; run `contour mscp schema baselines`"

STEP 1 — ODV resolution (the trap most prose SOPs miss):
  rules = contour mscp schema rules --baseline {baseline} --json
  # NB: returns `[]` with exit 0 for unknown baselines. Already guarded by
  # the precondition above, but the format pattern (check len, not exit)
  # is the same trap as profile search.

  odv_rules = filter(rules, fn r: r.has_odv == true)
  if len(odv_rules) > 0:
    REQUIRE human approval listing each odv rule with:
      - rule.rule_id
      - rule.title
      - rule.payload.odv_options[baseline]   # baseline-specific recommendation
      - rule.odv_default                      # generic fallback (often WRONG)
    # Without explicit user input, the generator silently uses odv_default
    # which produces compliant-looking but incorrect deployments.

STEP 2 — Generation:
  result = contour mscp generate \
    --baseline {baseline} \
    --mscp-repo {mscp_repo} \
    --output {output_dir} \
    --org {org} \
    --json

  # Success-path: prints batch summary; exit 0.
  # Failure-path: emits JSON envelope on stderr with error_code (since B3).

  if result.exit_code == 2:
    HALT "clap usage error: {result.stderr}"   # missing required flag, etc.
  if result.exit_code != 0:
    HALT "{result.error_code}: {result.error}"

STEP 3 — Verify output layout (Fleet v4.83+):
  for each path:
    ASSERT {output_dir}/mscp/{baseline}/baseline.toml exists
    ASSERT {output_dir}/platforms/macos/configuration-profiles/{baseline}/
           contains *.mobileconfig files
    ASSERT {output_dir}/platforms/macos/scripts/{baseline}/ contains *.sh
    ASSERT {output_dir}/labels/mscp-{baseline}.labels.yml exists
  # If any of these fail, the v4.83 layout migration is broken — file an issue.

STEP 4 — Validate the emitted set:
  contour mscp validate --output {output_dir} --json
  # Pre-Phase-1 this hardcoded `lib/mscp/` and always failed. Post-Phase-1
  # it accepts v4.83 layouts. If it errors, the generator and validator
  # have drifted — file an issue.

CROSS-FILE INVARIANT (after STEP 4):
  ASSERT every fleet yaml in {output_dir}/fleets/ that references {baseline}
         points at files that exist on disk
    # Phase 1 fix made the validator's path resolution use the YAML file's
    # parent dir; warnings here mean the fleet yaml has stale paths.

INVARIANTS:
  # Re-running with identical {baseline, org, mscp_repo} MUST produce
  # identical output files (modulo timestamps in baseline.toml).
  # If diff shows content changes, that is a bug.

POSTCONDITIONS:
  RETURN {
    baseline: {baseline},
    output_dir: {output_dir},
    profile_count: count of *.mobileconfig in platforms/macos/configuration-profiles/{baseline}/,
    script_count:  count of *.sh in platforms/macos/scripts/{baseline}/,
    odv_resolved:  list of (rule_id, value) pairs the user approved in STEP 1,
  }
```

---

## PROCEDURE resolve_odv(rule_id)

```
SCHEMA_TOOL: contour mscp schema rule {rule_id} --json

INPUT:
  rule_id : exact mSCP rule id (e.g. os_screensaver_password_enforce)

EXECUTION:
  detail = contour mscp schema rule {rule_id} --json

  # NB: unknown rule_id emits `null` on stdout with exit 0 — agents MUST
  # check the response shape, not exit code.
  ASSERT detail is not null
    HALT "unknown rule_id '{rule_id}'"

  # The shape returned by `schema rule` (verified):
  #   { "rule_id": str,
  #     "title": str,
  #     "baselines": [str],
  #     "has_odv": bool,
  #     "odv_default": value or null,
  #     "payload": { "odv_options": object,    ← per-baseline recommendations
  #                  "check_script": str,
  #                  "fix_script": str,
  #                  "mobileconfig_info": [...],
  #                  ... },
  #     "enforcement_type": str,
  #     ... }

POSTCONDITIONS:
  if detail.has_odv == false:
    RETURN { has_odv: false, value: null }

  # Has ODV — surface the choice; do NOT auto-pick.
  options = detail.payload.odv_options or {}
  REQUIRE human approval with:
    - rule: detail.rule_id  ({detail.title})
    - default: detail.odv_default
    - per-baseline recommendations: options
    - hint: options.hint if present
  RETURN { has_odv: true, value: <user-chosen> }
```

---

## Other operations (prose recipes; not yet migrated)

### List available baselines

```
contour mscp schema baselines --json
# Returns: [{baseline, title, preamble, authors, platforms}, ...]
# 16 baselines registered as of contour 0.2.x.
```

### List rules in a baseline

```
contour mscp schema rules --baseline cis_lvl1 --json
# Returns: [{rule_id, title, has_odv, mobileconfig, has_ddm_info, ...}, ...]
# Empty array (NOT error) for unknown baseline name.
```

### Search rules by keyword

```
contour mscp schema search <keyword> --json
# Returns matching rules across all baselines.
```

### Compare embedded data vs an mSCP repo

```
contour mscp schema compare <mscp_repo_path> --baseline <name> --json
# Diffs the schema embedded in contour against an external repo.
# Useful when contour's embedded data is older than the repo.
```

### Generate from mscp.toml config

```
contour mscp generate-all --config ./mscp.toml
# Multi-baseline batch using the config schema. See `contour mscp init`
# to scaffold mscp.toml, fleet-constraints.yml, and clone the mSCP repo.
```

### Inspect the v4.83 output layout

```
contour mscp list --output ./output --json    # baselines discovered in mscp/
contour mscp validate --output ./output --json # full validation
contour mscp clean --baseline <name> --output ./output --force  # remove
contour mscp deduplicate --output ./output     # find shared profiles
```

---

## Key JSON fields for agents

From `mscp schema rule <id> --json`:

- `has_odv: bool` — true if the rule needs an organization-defined value;
  agents MUST surface the choice to the user (see `resolve_odv` above)
- `odv_default` — generic fallback used silently if user doesn't specify
- `payload.odv_options` — per-baseline recommendations + optional `hint`
- `mobileconfig: bool` — rule is enforceable via MDM mobileconfig
- `has_ddm_info: bool` — rule is enforceable via DDM declaration
- `enforcement_type: str` — how the rule is enforced
- `payload.mobileconfig_info` — array of `{payload_type, keys}` for profile generation
- `payload.check_script` / `payload.fix_script` — bash scripts
- `osquery_checkable: bool` + `osquery_table: str` — when true, the rule
  references an osquery table (validate via `contour osquery table {name}`)
