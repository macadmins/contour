# SOP: PPPC / TCC Profile Generation

Generate Privacy Preferences Policy Control (PPPC) profiles that grant
managed apps access to TCC-protected services (ScreenCapture,
Accessibility, Camera, Microphone, Files & Folders, etc.) on macOS.

The procedural half pins the contract for `contour pppc generate`. The
prose half lists `init / scan / configure / validate / diff / batch`
recipes — agents touch those infrequently, so they stay as cookbooks.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/contour/tests/sop_traps_pppc.rs` (companion to the
existing `sop_traps*` suites)

## ERROR-CODE ENUM

```
INVALID_IDENTIFIER     org domain malformed (e.g. spaces, missing dot)
INVALID_FORMAT         pppc.toml is not valid TOML / corrupted
SCHEMA_VIOLATION       TCC service or identifier_type not registered
IO_ERROR               input/output path un-readable / un-writeable
INVALID_ORG            org domain malformed (canonical for org input)
UNKNOWN                unmatched (e.g. parse error in upstream lib)
```

Failure-path JSON envelope (since contour ≥0.2.1):

```json
{ "success": false, "error": "...", "error_code": "UNKNOWN" }
```

---

## PROCEDURE generate_pppc_profile(pppc_toml, output_dir, mode, fragment)

```
SCHEMA_SOURCE: contour's embedded TCC service registry (snapshot of
                Apple's PPPC-supported services per macOS release)
SCHEMA_TOOL:   contour pppc info --json
               contour pppc validate {pppc_toml} --json

INPUT:
  pppc_toml    : path to a populated pppc.toml file
  output_dir   : directory to write generated profiles
  mode         : "per_app"  — one profile per app entry (default)
                 "combined" — single profile with all entries merged
  fragment     : bool — when true, emit a Fleet GitOps fragment
                        directory instead of plain mobileconfig files

PRECONDITIONS:
  ASSERT pppc_toml exists AND is readable
    HALT "IO_ERROR: pppc_toml not found at {pppc_toml}"
  ASSERT parent(output_dir) exists OR can be created
    AUTO_FIX: mkdir -p {output_dir}
  ASSERT mode in {"per_app", "combined"}
    HALT "mode must be per_app or combined; got '{mode}'"

STEP 1 — Validate the policy file:
  result = contour pppc validate {pppc_toml} --json
  # Returns:
  #   { "valid": bool,
  #     "app_count": int,
  #     "error_count": int,
  #     "warning_count": int,
  #     "errors":   [ { "app": str?, "service": str?, "message": str }, ... ],
  #     "warnings": [ { ... }, ... ] }

  ASSERT result.valid == true
    HALT "SCHEMA_VIOLATION: pppc.toml has {result.error_count} \
          errors; first: {result.errors[0].message}"

  if result.warning_count > 0:
    WARN "{result.warning_count} warning(s) — first: \
          {result.warnings[0].message}"

  ASSERT result.app_count > 0
    HALT "no apps in {pppc_toml}; run `contour pppc scan` first or \
          edit the file to add an [[apps]] entry"

STEP 2 — Generate the profile(s):
  flags = ["-o", output_dir, "--json"]
  if mode == "combined":
    flags += ["--combined"]
  if fragment:
    flags += ["--fragment"]
  result = contour pppc generate {pppc_toml} {flags...}

  if result.exit_code != 0:
    # Failure prints {success:false, error_code, error} on stderr.
    HALT "{result.error_code}: {result.error}"

INVARIANTS:
  # Each generated profile MUST embed an org identifier on every payload
  # — Apple's MDM stack rejects profiles whose payloads have a bare
  # PayloadIdentifier without a reverse-DNS prefix.
  ASSERT every emitted .mobileconfig has PayloadIdentifier matching
    pattern "^[a-z0-9.-]+(\\.[A-Za-z0-9-_]+)+$"
    HALT "INVALID_ORG: emitted profile has malformed PayloadIdentifier; \
          check the [config].org value in {pppc_toml}"

  # Camera and Microphone are DENY-ONLY per Apple's TCC spec. A PPPC
  # profile cannot grant access to either — it can only deny. The CLI
  # enforces this by emitting Authorization="Deny" whenever Camera or
  # Microphone appears in services = [...]. An agent asked to "grant
  # Slack camera access" via PPPC is asking for something Apple does
  # not allow; the user must accept the OS prompt instead.
  ASSERT for every entry in services where service in {Camera, Microphone}:
    intent == "deny"
    HALT "INVALID_FORMAT: Camera/Microphone are deny-only in PPPC. \
          To allow {service} for {app}, the user must accept the \
          OS prompt — no profile can pre-grant. Remove {service} from \
          services if your intent was to allow it; keep it only to \
          actively deny."

  # Authorization defaults vary by service:
  #   Camera, Microphone        → "Deny"            (deny-only; see above)
  #   ScreenCapture, ListenEvent → "AllowStandardUserToSetSystemService"
  #   all others                → "Allow"
  # Agents writing follow-up SOPs that read the emitted Authorization
  # keys must accept this enum.
  WARN "default Authorization is per-service (see SCHEMA_TOOL output \
        from `contour pppc info --json`); verify per-service before deploy"

STEP 3 — Verify written profiles:
  if fragment:
    ASSERT output_dir contains fragment.toml
      HALT "fragment mode did not produce fragment.toml — likely a CLI bug"
    ASSERT output_dir contains a platforms/macos/ subtree
      HALT "fragment mode missing platforms/macos/ — wiring is broken"
  else:
    written = list(output_dir, "*.mobileconfig")
    ASSERT len(written) >= 1 (per_app: >= 1 per app; combined: == 1)
      HALT "no .mobileconfig emitted; check stderr for hidden errors"

POSTCONDITIONS:
  RETURN {
    output_dir,
    mode,
    fragment,
    profile_count: len(written) if not fragment else 1,
  }
```

---

## Other operations (prose recipes)

### Initialise a new policy file

```
contour pppc init --org com.acme --output pppc.toml
# Creates a stub with [config].org and an empty apps = [] list.
```

### Scan apps to populate the policy

```
contour pppc scan /Applications --org com.acme -o pppc.toml --json
# Walks the given paths, extracts bundle IDs / code-signing identifiers,
# and writes [[apps]] entries. Re-runnable; merges with existing entries.
```

### Interactively configure TCC services

```
contour pppc configure pppc.toml
# REPL-style wizard — walks each app and prompts per service. Best for
# the first pass; afterwards edit the TOML directly.
```

### Validate an existing policy

```
contour pppc validate pppc.toml --json
# Same JSON shape consumed by STEP 1 above.
```

### Diff two policy files

```
contour pppc diff base.toml updated.toml --json
# Useful in CI to gate config changes; output lists added/removed apps
# and per-app service deltas.
```

### Batch-update services across many apps

```
contour pppc batch pppc.toml --service ScreenCapture=Allow \
                              --bundle-id com.example.app
# Idempotent; safe to commit and re-run.
```

---

## Key facts

- **Camera and Microphone are deny-only.** Per Apple's TCC spec, a PPPC
  profile cannot grant access to Camera or Microphone — only deny. The
  user must accept the OS prompt for those services. If an agent is
  asked to "grant {app} camera access" via PPPC, the correct answer is
  "PPPC cannot do that; ship the app and let the user accept the prompt".
- Authorization defaults by service:
  | Service                     | Default Authorization                 |
  |-----------------------------|---------------------------------------|
  | Camera, Microphone          | `Deny` (deny-only by Apple policy)    |
  | ScreenCapture, ListenEvent  | `AllowStandardUserToSetSystemService` |
  | All others (FDA, etc.)      | `Allow`                               |
- The `[config].org` field becomes the reverse-DNS prefix for every
  PayloadIdentifier; changing it after deployment forces re-installation
  on every host.
- `identifier_type` controls whether the profile keys on `bundleID` (most
  apps) or `path` (binaries / unsigned apps). `bundleID` is preferred —
  paths break when apps move.
- An `[[apps]]` entry is shaped:
  ```toml
  [[apps]]
  name = "Slack"
  bundle_id = "com.tinyspeck.slackmacgap"
  code_requirement = "anchor apple generic and ..."
  identifier_type = "bundleID"      # or "path"
  services = ["screen-capture", "microphone"]
  ```
  Service slugs are kebab-case: `camera`, `microphone`, `screen-capture`,
  `accessibility`, `fda` (Full Disk Access), etc. Run
  `contour pppc info --json` for the complete enum.
- Fragment mode (`--fragment`) is the recommended output for adding to
  an existing Fleet GitOps repo; it produces a fragment.toml manifest
  plus a platforms/macos/ subtree that merges cleanly into v4.83 layout.
- TCC services accept `Allow` or `Deny`. `Deny` profiles are useful for
  hardening (e.g. block ScreenCapture for browsers), but most production
  use cases are allowlists.
