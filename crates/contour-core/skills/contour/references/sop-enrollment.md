# SOP: DEP/ADE Enrollment Profiles (Setup Assistant)

Generate enrollment profiles that control the macOS / iOS Setup Assistant
experience for devices enrolling via Apple Business Manager (ABM) / Apple
Device Enrollment (ADE).

This SOP exists primarily to prevent **one specific agent trap**:
`--skip-all` includes `FileVault` and `SoftwareUpdate` in the generated
skip set, but those screens should almost never be skipped in production
(FileVault is required for disk encryption setup, and skipping
SoftwareUpdate during onboarding leaves devices on stale OS versions
during their first connected hour). The procedural format catches this
at PRECONDITIONS time so it can't slip through.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/contour/tests/sop_traps_osquery.rs` (mscp/profile companions)

## ERROR-CODE ENUM

```
INVALID_FORMAT         malformed --skip key list
SCHEMA_VIOLATION       skip key not registered for the requested platform/OS
IO_ERROR               output path un-writeable
UNKNOWN                unmatched (e.g. no skip flag given)
```

Failure-path JSON envelope (since contour ≥0.2.1):

```json
{ "success": false, "error": "...", "error_code": "UNKNOWN" }
```

## NEVER_SKIP set (the invariant)

These skip keys MUST NOT appear in the generated `skip_setup_items` for
production enrollment profiles:

```
NEVER_SKIP = ["FileVault", "SoftwareUpdate"]
```

- **FileVault**: skipping the Setup Assistant pane bypasses the user-led
  encryption flow. While FileVault can still be enforced via MDM profile
  later, the recovery-key prompt won't run, and recovery keys end up
  unmanaged.
- **SoftwareUpdate**: skipping leaves the device on whatever OS shipped
  with the hardware until the user (or MDM policy) triggers an update.
  Combined with macOS Tahoe's deprecation of legacy software-update
  payloads, this gap can stretch from hours to weeks.

The `--skip-all` CLI flag DOES include both. Procedural SOP MUST filter
them out before generating, or document an explicit override decision.

As of contour ≥0.3.0-beta.5, the NEVER_SKIP guardrail is also enforced
in code: `contour profile enrollment generate` refuses to write a profile
whose final skip set contains `FileVault` or `SoftwareUpdate`, regardless
of whether they came from `--skip`, `--skip-all`, or `--skip-list`.
Defence-in-depth — the SOP catches it at planning time, the CLI catches
it at generation time.

---

## PROCEDURE generate_enrollment_profile(platform, os_version, intent, output_file)

```
SCHEMA_SOURCE: contour's embedded skip-key registry (snapshot of Apple's
                ADE schema for macOS / iOS / iPadOS)
SCHEMA_TOOL:   contour profile enrollment list --platform {platform} --json
               contour profile enrollment list --platform {platform} \
                                                --os-version {ver} --json

INPUT:
  platform     : "macOS" | "iOS" | "iPadOS"
  os_version   : optional target OS version string (e.g. "26.0")
                 — narrows the available skip keys (some only exist on
                   newer OSes; --os-version filters out the unavailable ones)
  intent       : one of:
                   "enterprise_standard"  — skip most legal/diagnostics,
                                            keep FileVault + Biometric
                   "minimal"              — skip only legal/diagnostics
                   "interactive"          — surface the full checklist to
                                            the user for case-by-case choice
                   "skip_all_with_overrides" — start from --skip-all,
                                            then explicitly UN-skip the
                                            NEVER_SKIP set
  output_file  : path to write the JSON profile

PRECONDITIONS:
  ASSERT platform in {"macOS", "iOS", "iPadOS"}
    HALT "platform must be macOS, iOS, or iPadOS; got '{platform}'"
  ASSERT parent(output_file) exists OR can be created
    AUTO_FIX: mkdir -p {parent(output_file)}
  ASSERT intent in known intents
    HALT "{intent} is not a known intent; pick from list or extend the SOP"

STEP 1 — Discover available skip keys:
  available = contour profile enrollment list --platform {platform} \
              [--os-version {os_version}] --json
  # Returns array of:
  #   { "key": str,           ← machine identifier (use this in --skip)
  #     "title": str,         ← human-readable name
  #     "description": str,
  #     "platform": str,
  #     "introduced": str?,   ← OS version key was added (e.g. "11.0")
  #     "removed": str?,      ← OS version key was removed (deprecation)
  #     "deprecated": str?,
  #     "always_skippable": bool }

  ASSERT len(available) > 0
    HALT "no skip keys for {platform}{os_version}; check args"

STEP 2 — Resolve skip set per intent:
  SWITCH intent:
    CASE "interactive":
      # Hand off to the user — surface available[] as a checklist with
      # description tooltips. Pre-select common enterprise defaults but
      # let the user decide; do NOT auto-skip anything.
      skip_keys = REQUIRE human approval, choosing from available
      flag = "--skip {comma-joined skip_keys}"

    CASE "enterprise_standard":
      # Sensible defaults: skip the legal/marketing screens, keep
      # security and update screens.
      skip_keys = filter(available, fn k: k.key in [
        "AppleID", "AppStore", "Diagnostics", "iCloudDiagnostics",
        "iCloudStorage", "Location", "Payment", "Privacy", "ScreenTime",
        "Siri", "TermsOfAddress", "TOS", "UnlockWithWatch", "Appearance",
        "Welcome", "Wallpaper",
      ]).map(k -> k.key)
      flag = "--skip {comma-joined skip_keys}"

    CASE "minimal":
      skip_keys = filter(available, fn k: k.key in [
        "TOS", "Diagnostics", "iCloudDiagnostics", "Privacy",
      ]).map(k -> k.key)
      flag = "--skip {comma-joined skip_keys}"

    CASE "skip_all_with_overrides":
      # Use --skip-all but then drop the NEVER_SKIP set.
      skip_keys = available.map(k -> k.key) - NEVER_SKIP
      flag = "--skip {comma-joined skip_keys}"

INVARIANTS (apply to every intent except "interactive"):
  ASSERT NEVER_SKIP set is disjoint from skip_keys
    # i.e. "FileVault" not in skip_keys AND "SoftwareUpdate" not in skip_keys
    HALT "intent {intent} produced a skip set including NEVER_SKIP \
          ({offending_keys}); refusing to generate. To override, use \
          --interactive and document the security rationale."
  # `interactive` is exempt because the human explicitly chose; in that
  # case the procedure must surface the warning to the user before
  # accepting the choice (REQUIRE human approval already gates this).

STEP 3 — Generation:
  result = contour profile enrollment generate --platform {platform} \
           [--os-version {os_version}] \
           {flag} \
           -o {output_file} --json

  # Success-path JSON shape:
  #   { "success": true,
  #     "platform": str,
  #     "os_version": str?,
  #     "available_count": int,
  #     "output_file": str,
  #     "profile": { ... },         ← embedded copy of what was written
  #   }
  # Failure path (no flag, conflicting flags, unknown key) emits the
  # standard JSON envelope on stderr with error_code.

  if result.exit_code != 0:
    HALT "{result.error_code}: {result.error}"

STEP 4 — Verify written file:
  written = read({output_file}) as JSON
  ASSERT written has top-level keys:
    "skip_setup_items" : list of strings
    "is_supervised"    : bool
    "is_mdm_removable" : bool
    "allow_pairing"    : bool
    "profile_name"     : str
    "language"         : str
    "region"           : str

  ASSERT every k in NEVER_SKIP is NOT in written.skip_setup_items
    # Defence-in-depth: if the CLI ever changes such that a flag combo
    # smuggles a NEVER_SKIP key through, this catches it after the file
    # is written but before the agent reports success.
    HALT "{k} ended up in skip_setup_items; this is a SOP/CLI drift bug"

POSTCONDITIONS:
  RETURN {
    output_file,
    platform,
    skipped_count: len(written.skip_setup_items),
    skipped_keys: written.skip_setup_items,
    intent,
  }
```

---

## Other operations (prose recipes)

### Reusable skip list (skip-list.toml)

Capture an org's chosen skip set in a version-controlled TOML file so it
can be re-applied across many enrollment profile generations.

```toml
# skip-list.toml
version = 1
platform = "macOS"           # optional; overrides --platform default
os_version = "26.0"          # optional
profile_name = "Acme Onboarding"  # optional
skip = [
  "Appearance",
  "Siri",
  "Diagnostics",
  "Privacy",
  "TOS",
]
# FileVault and SoftwareUpdate are rejected by the NEVER_SKIP guardrail
# regardless of source; do not list them here.
```

Apply with:

```bash
contour profile enrollment generate --skip-list skip-list.toml -o dep.json
```

Precedence rules:
- `--platform`, `--os-version`, `--profile-name` CLI flags override the
  file's values when explicitly set (their defaults are treated as "not set").
- `--skip <csv>` is unioned with the file's `skip` list (deduplicated).
- `--skip-list` conflicts with `--skip-all` and `--interactive` (clap-enforced).
- The NEVER_SKIP guardrail is applied to the final, post-merge selection
  regardless of source — a `FileVault` or `SoftwareUpdate` entry in the
  file or in `--skip` aborts generation before any output is written.

### List skip keys for a platform

```
contour profile enrollment list --platform macOS --json
contour profile enrollment list --platform iOS --json
contour profile enrollment list --platform macOS --os-version 26.0 --json
contour profile enrollment list --platform macOS --beta --deprecated   # only deprecated/removed keys + version
```

### Presets, language flavors, interactive wizard

```
# Built-in presets (all schema-backed; keep Biometric + Location visible,
# skip everything else, NEVER_SKIP panes always preserved):
contour profile enrollment presets                       # list: auto-advance, shared-ipad, manual
contour profile enrollment generate --preset auto-advance -o p.json   # macOS, auto_advance_setup=true
contour profile enrollment generate --preset shared-ipad  -o p.json   # iOS/iPadOS
contour profile enrollment generate --preset manual       -o p.json   # macOS, no auto-advance

# Language fast-presets — --language pairs a default region (en→US, de→DE,
# fr→FR, es→ES); --region overrides:
contour profile enrollment generate --preset manual --language de -o p.json   # language=de region=DE

# Interactive wizard (prompts platform → OS version → language → panes to keep):
contour profile enrollment generate --interactive
```

### Migrate an existing profile to a newer OS version

Re-validates `skip_setup_items` against the target OS and drops keys Apple
removed or deprecated by then (remove-only — never adds panes). Platform is
required (skip keys are platform-scoped) since the ADE JSON doesn't record it.

```
contour profile enrollment migrate old15.json --to-version 26 --platform macOS -o new26.json
# e.g. drops `Wallpaper` (removed in macOS 26.0); keeps everything still valid.
```

### Use the generated profile in a GitOps repo (Fleet v4.83 layout shown)

```
# Place under platforms/macos/enrollment-profiles/
cp enrollment.dep.json \
  platforms/macos/enrollment-profiles/automatic-enrollment.dep.json

# Reference from the consuming YAML (Fleet's `controls.setup_experience` shape):
controls:
  setup_experience:
    apple_setup_assistant:
      ../platforms/macos/enrollment-profiles/automatic-enrollment.dep.json
```

The filename is arbitrary — Fleet reads by path reference, not name
convention. Other GitOps engines that consume DEP profiles use
analogous path references.

---

## Key facts

- `is_supervised: true` enables full MDM control (required for most
  enterprise features).
- `is_mdm_removable: false` prevents end-users from removing the MDM
  profile.
- Skip keys are **version-gated**. Use `--os-version` to filter to keys
  valid for your target OS — passing a key that doesn't exist on the
  target version produces a SCHEMA_VIOLATION error from the CLI.
- The `--interactive` flag shows descriptions for each key to help make
  informed choices; pair it with the `interactive` intent above for
  case-by-case enrollment design.
