# SOP: mSCP Security Compliance

Generates MDM-deployable compliance artifacts (mobileconfigs, scripts,
policies, labels) for mSCP baselines (CIS, 800-53, STIG, CMMC, …).

Hard rules:
- **ODVs**: many rules carry an organization-defined value whose generic
  `odv_default` is wrong for production. Surface each choice to the user
  before generating (`resolve_odv`); never auto-pick.
- `--org` is required and must not be `com.example`.
- Unknown baseline / rule names return `[]` / `null` with exit 0: check the
  response shape, not the exit code.

> **OS-preview rules** (Apple Intelligence PCC, Siri AI, …) are on the embedded
> beta channel: `contour mscp schema search <kw> --beta` / `schema rule <id>
> --beta`; see "mSCP OS-preview rules" in `--sop beta`. `mscp recipe` reads a
> repo checkout, so `--beta` does not apply to it.

## Layout: mSCP 2.0 only (verified, 1.x refused)

contour verifies a `--mscp-repo` path by sniffing one rule YAML:

| Signal | Result |
|---|---|
| Top-level `platforms:` key on a rule | **2.0** — proceed |
| Top-level `id:` without `platforms:` | **1.x** — refused with the fix: `git -C <repo> checkout main`; custom 1.x baselines migrate with mSCP's own `--migrate` |
| Neither | error: "could not detect mSCP layout" with the offending file |

`main` carries older OS releases under their own version keys (macOS 15.0,
26.0; iOS 17.0, 18.0), so nothing is lost. On the refusal, switch the
checkout — there is no flag.

A 2.0 rule nests per-OS data under `platforms:` (`macOS: {'15.0': {benchmarks:
[{name: cis_lvl1}]}, enforcement_info: {check, fix}}`, `iOS: {'18.0': {supervised,
benchmarks}}`), with `mobileconfig_info` (PayloadType + PayloadContent) top-level.

Baselines live at `baselines/<os>/<name>_<os>_<version>.yaml`; every flag
takes the bare name (`cis_lvl1`, `800-53r5_high`). Seven (`indigo_*`,
`ios_*`, `nlmapgov_*`, `mscp`) exist only as rule tags, without a file.
A name neither a file nor any rule knows is an error.

**Operator flags** (on `mscp recipe` and friends):

- `--os <macos|ios|visionos>` — default `macos`
- `--os-version <X.Y>` — default: highest version present in the rule set

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

Failure-path JSON envelope:

```json
{ "success": false, "error": "...", "error_code": "INVALID_ORG" }
```

Agents that branch on exit code MUST distinguish 0 (ok), 1 (error → JSON
envelope), 2 (clap usage error, e.g. missing `--mscp-repo` → plain stderr).


## DEPRECATED_LIST

```
DEPRECATED_PAYLOADS = [
  "com.apple.SoftwareUpdate"
    -> use DDM: com.apple.configuration.softwareupdate.settings
              + com.apple.configuration.softwareupdate.enforcement.specific
       (See sop-ddm.md / create_ddm_config.)
]
```

WARN if any rule in the baseline targets a deprecated payload (e.g.
software-update rules with `enforcement_type: "mobileconfig"`). The DDM
replacement belongs to `create_ddm_config`, not `generate_baseline_compliance`.


## Presets — quick baseline selection

Each preset expands to a baseline keyword **and** its platform (`--os`):

```
contour mscp presets                                   # list them (--json for tooling)
contour mscp generate --preset cmmc2    -m {repo} -o {out} --org {org}
contour mscp generate --preset nist-high -m {repo} -o {out} --org {org}
```

Name → keyword: `nist-high|moderate|low` → `800-53r5_*`, `cui` → `800-171`,
`cmmc1|cmmc2` → `cmmc_lvl1|2`, `stig` → `disa_stig`, `ios-stig` → `ios_stig`,
`cis1|cis2` → `cis_lvl1|2`, `cis1-byod|cis2-byod|cis1-enterprise|cis2-enterprise`,
`cis-controls` → `cisv8`, `cnssi-high|moderate|low` → `cnssi-1253_*`.

Raw keywords still work everywhere: `--preset 800-53r5_high` and
`-k 800-53r5_high` are equivalent. `--preset` and `--keyword` are mutually
exclusive; exactly one is required on `generate`.


## PROCEDURE generate_baseline_compliance(baseline, org, mscp_repo, output_dir)

```
SCHEMA_SOURCE: usnistgov/macos_security, `main` branch (mSCP 2.0)
SCHEMA_TOOL:   contour mscp schema baselines --json
               contour mscp schema rules --baseline {name} --json
               contour mscp schema rule {rule_id} --json

INPUT:
  baseline    : name from `mscp schema baselines` (cis_lvl1, 800-53r5_high).
                Unknown names silently emit no rules.
  org         : reverse-domain identifier (com.acme). REQUIRED.
  mscp_repo   : usnistgov/macos_security checkout (Python pipeline runs there).
  output_dir  : v4.83 GitOps layout: platforms/macos/{configuration-profiles,
                scripts,policies}/{baseline}/, mscp/{baseline}/baseline.toml,
                labels/, fleets/.

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

  # Confirm the baseline BEFORE the slow Python pipeline.
  baselines = contour mscp schema baselines --json
  ASSERT baseline in baselines.map(b -> b.baseline)
    HALT "unknown baseline '{baseline}'; run `contour mscp schema baselines`"

STEP 1 — ODV resolution:
  rules = contour mscp schema rules --baseline {baseline} --json
  # `[]` with exit 0 for unknown baselines — check len, not exit.

  odv_rules = filter(rules, fn r: r.has_odv == true)
  if len(odv_rules) > 0:
    REQUIRE human approval listing each odv rule's rule_id, title,
      payload.odv_options[baseline] (recommendation) and odv_default (often WRONG)
    # Otherwise the generator silently uses odv_default.

STEP 2 — Generation:
  result = contour mscp generate --baseline {baseline} --mscp-repo {mscp_repo} \
             --output {output_dir} --org {org} --json

  # Failure: JSON envelope on stderr with error_code.
  if result.exit_code == 2:
    HALT "clap usage error: {result.stderr}"   # missing required flag, etc.
  if result.exit_code != 0:
    HALT "{result.error_code}: {result.error}"

STEP 3 — Verify output layout (Fleet v4.83+), under {output_dir}:
  ASSERT mscp/{baseline}/baseline.toml exists
  ASSERT platforms/macos/configuration-profiles/{baseline}/*.mobileconfig exist
  ASSERT platforms/macos/scripts/{baseline}/*.sh exist
  ASSERT labels/mscp-{baseline}.labels.yml exists
  # Any failure here is a contour bug — file an issue.

STEP 4 — Validate the emitted set:
  contour mscp validate --output {output_dir} --json
  # An error means generator and validator drifted — file an issue.

CROSS-FILE INVARIANT (after STEP 4):
  ASSERT every fleet yaml in {output_dir}/fleets/ that references {baseline}
         points at files that exist on disk
    # Warnings here mean the fleet yaml has stale paths.

INVARIANTS:
  # Identical {baseline, org, mscp_repo} MUST produce identical output
  # (modulo baseline.toml timestamps); a content diff is a bug.

POSTCONDITIONS:
  RETURN { baseline, output_dir, profile_count, script_count,
           odv_resolved: (rule_id, value) pairs approved in STEP 1 }
```


## When a baseline contradicts itself

Some baselines set one key two ways. `all_rules`, `cmmc_lvl2`,
`cnssi-1253_high|moderate|low` and `hicp_lp` carry both
`auth_smartcard_certificate_trust_enforce_high` (`checkCertificateTrust` 3)
and `..._moderate` (2).

**mSCP's own generator silently ships the later-listed rule's value** —
`checkCertificateTrust = 2` even for `cnssi-1253_high`, weaker than the name
implies. Mention it whenever it applies.

contour keeps the same value and says so:

```
mscp recipe      prints WARNING; recipe description records
                 "conflict kept as mSCP does: ..."
mscp generate    prints the WARNING before mSCP's output; JSON warnings record it
posture generate same WARNING, same value
```

Only a scalar set two ways conflicts; list/dict entries (DisabledSystemSettings
panes, SkipSetupItems, `Apps`) merge.

To ship the other value:

```
1. Tailor the baseline (preferred; mSCP-native):
     mSCP's scripts/generate_baseline.py -t moves the unwanted rule into a
     `section: Excluded` block. mSCP and contour (recipe and generate) skip
     it; the recipe description names those rules.
2. Untailored baseline, recipe only:
     contour mscp recipe -r <repo> -k cnssi-1253_high \
         --exclude-rule auth_smartcard_certificate_trust_enforce_moderate
     The recipe description records the exclusion.
```

Do NOT use `excluded_rules` in mscp.toml for this on the generate path: mSCP
merges both rules into the profile first and excluded_rules drops whole
profiles afterwards, so the merged value stays (contour says so). Tailor.

## PROCEDURE resolve_odv(rule_id)

```
SCHEMA_TOOL: contour mscp schema rule {rule_id} --json

INPUT:
  rule_id : exact mSCP rule id (e.g. os_screensaver_password_enforce)

EXECUTION:
  detail = contour mscp schema rule {rule_id} --json

  # Unknown rule_id → `null`, exit 0. Check the shape, not exit code.
  ASSERT detail is not null
    HALT "unknown rule_id '{rule_id}'"

  # Shape: { rule_id, title, baselines[], has_odv, odv_default,
  #   payload: { odv_options, check_script, fix_script, mobileconfig_info, … },
  #   enforcement_type, … }   — see "Key JSON fields" below.

POSTCONDITIONS:
  if detail.has_odv == false:
    RETURN { has_odv: false, value: null }

  # Has ODV — do NOT auto-pick.
  options = detail.payload.odv_options or {}
  REQUIRE human approval with:
    - rule: detail.rule_id  ({detail.title})
    - default: detail.odv_default
    - per-baseline recommendations: options
    - hint: options.hint if present
  RETURN { has_odv: true, value: <user-chosen> }
```


## Other operations (prose recipes; not yet migrated)

### List available baselines

```
contour mscp schema baselines --json
# Returns: [{baseline, title, preamble, authors, platforms}, ...]
```

### List rules in a baseline

```
contour mscp schema rules --baseline cis_lvl1 --json
# Returns: [{rule_id, title, has_odv, mobileconfig, has_ddm_info, ...}, ...]
```

### Search rules by keyword

```
contour mscp schema search <keyword> --json
# Returns matching rules across all baselines.
```

### Compare embedded data vs an mSCP repo

```
contour mscp schema compare <mscp_repo_path> <baseline> --json
# Diffs contour's embedded data against a (possibly newer) repo.
```

### Generate from mscp.toml config

```
contour mscp generate-all --config ./mscp.toml
# Multi-baseline batch. `contour mscp init` scaffolds mscp.toml and
# fleet-constraints.yml and clones the mSCP repo.
```

### Inspect the v4.83 output layout

```
contour mscp list --output ./output --json    # baselines discovered in mscp/
contour mscp validate --output ./output --json # full validation
contour mscp clean --baseline <name> --output ./output --force  # remove
contour mscp deduplicate --output ./output     # find shared profiles
```

### Attach a baseline to existing fleets (inject engine)

```
# Generate AND attach profiles + scripts to fleet files. Unscoped by default.
contour mscp generate --mscp-repo R --keyword cis_lvl1 --output O --org ORG \
  --fleets workstations,kiosks   # attach to named fleets (comma-separated)
  # --all-fleets                   # attach to EVERY fleet under fleets/ (multi-brand)
  # --exclude-fleets a,b           # with --all-fleets, skip these
  # --fleet-label "SYS - VIP"      # scope the attached profiles to a label
  # --canonical-fleets             # greenfield: scaffold workstations + personal-mobile-devices, attach to workstations
  # --glob                         # one *.mobileconfig glob entry instead of per-file
#
# Idempotent and comment-preserving. A `# contour:<baseline>` marker leads each
# injected block; .contour/fleet-injections.toml records every attach.
# ONE profile set is referenced by MANY fleets via glob — never duplicated or re-identified per fleet.
# Fail-closed: a splice that would produce invalid YAML is refused; the file stays untouched.

# Withdraw (manifest-driven; removes only what it added):
contour mscp generate --mscp-repo R --keyword cis_lvl1 --output O --org ORG \
  --fleets kiosks --remove
```

### Generate Fleet scheduled-query reports

```
# --osquery also emits Fleet "reports" (scheduled data collection — NOT pass/fail):
#   platforms/macos/reports/<baseline>-compliance.reports.yml  — per-rule audit-plist status
#   platforms/macos/reports/security-posture.reports.yml       — OS/FileVault/SIP/firewall/Gatekeeper/screen-lock
contour mscp generate --mscp-repo R --keyword cis_lvl1 --output O --org ORG --osquery
#
# Override/extend the posture pack with a repo-local .contour/security-posture.toml
# ([[report]] tables: name, description, query, platform=darwin, interval,
# observer_can_run, automations_enabled). Canonical fleets glob
# ../platforms/macos/reports/*.yml, so reports apply automatically.
# Verify the emitted queries with `contour osquery verify` (see --sop osquery).
```


## Key JSON fields for agents

From `mscp schema rule <id> --json`:

- `has_odv: bool` — needs an ODV; MUST surface the choice (`resolve_odv`)
- `odv_default` — generic fallback used silently if the user doesn't choose
- `payload.odv_options` — per-baseline recommendations + optional `hint`
- `mobileconfig: bool` / `has_ddm_info: bool` — enforceable via mobileconfig / DDM
- `enforcement_type: str` — how the rule is enforced
- `payload.mobileconfig_info` — `[{payload_type, keys}]` for profile generation
- `payload.check_script` / `payload.fix_script` — bash scripts
- `osquery_checkable: bool` + `osquery_table: str` — rule references an osquery
  table (validate via `contour osquery table {name}`)
