# SOP: Notification Settings Profiles

Generate `com.apple.notificationsettings` profiles that pre-set
notification permissions (Banner / Lock screen / Critical Alert /
Notification Centre / Sounds / Preview type) for managed apps so
end-users don't see the OS prompt on first launch.

The procedural half pins the contract for `contour notifications generate`.
Other lifecycle ops (`init / scan / configure / validate / diff`)
mirror the PPPC flow and stay as prose recipes.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/contour/tests/sop_traps_notifications.rs`

## ERROR-CODE ENUM

```
INVALID_FORMAT         notifications.toml is not valid TOML / corrupted
SCHEMA_VIOLATION       alert_type / preview_type value not in allowed set
IO_ERROR               input/output path un-readable / un-writeable
INVALID_ORG            org domain malformed
UNKNOWN                unmatched
```

Failure-path JSON envelope (since contour ≥0.2.1):

```json
{ "success": false, "error": "...", "error_code": "UNKNOWN" }
```

---

## PROCEDURE generate_notifications_profile(notif_toml, output_dir, fragment)

```
SCHEMA_SOURCE: contour's embedded NotificationSettings registry
                (mirrors Apple's com.apple.notificationsettings keys)
SCHEMA_TOOL:   contour notifications validate {notif_toml} --json

INPUT:
  notif_toml   : path to a populated notifications.toml file
  output_dir   : directory to write generated profiles
  fragment     : bool — when true, emit a GitOps fragment (Fleet `fragment.toml` schema)

PRECONDITIONS:
  ASSERT notif_toml exists AND is readable
    HALT "IO_ERROR: notifications.toml not found at {notif_toml}"
  ASSERT parent(output_dir) exists OR can be created
    AUTO_FIX: mkdir -p {output_dir}

STEP 1 — Validate the policy file:
  result = contour notifications validate {notif_toml} --json
  # Returns:
  #   { "valid": bool,
  #     "app_count": int,
  #     "error_count": int,
  #     "warning_count": int,
  #     "errors":   [ { "app": str?, "key": str?, "message": str }, ... ],
  #     "warnings": [ { ... }, ... ] }

  ASSERT result.valid == true
    HALT "SCHEMA_VIOLATION: notifications.toml has {result.error_count} \
          errors; first: {result.errors[0].message}"

  if result.warning_count > 0:
    WARN "{result.warning_count} warning(s) — first: \
          {result.warnings[0].message}"

  ASSERT result.app_count > 0
    HALT "no apps configured in {notif_toml}; run \
          `contour notifications scan` first or edit the file"

STEP 2 — Generate the profile:
  flags = ["-o", output_dir, "--json"]
  if fragment:
    flags += ["--fragment"]
  result = contour notifications generate {notif_toml} {flags...}

  if result.exit_code != 0:
    HALT "{result.error_code}: {result.error}"

INVARIANTS:
  # NotificationSettings deployed via MDM bypass the user prompt — but
  # ONLY for apps the user has not yet interacted with. Once the user
  # has seen the OS notification prompt, the profile no longer wins.
  # Document this as a deployment-order constraint, not a CLI failure.
  WARN "deploy NotificationSettings BEFORE the user first launches \
        the target app, or the profile is silently overridden by \
        the user's prior choice"

STEP 3 — Verify the output:
  if fragment:
    ASSERT output_dir contains fragment.toml
      HALT "fragment mode did not produce fragment.toml"
    ASSERT output_dir contains platforms/macos/configuration-profiles/
      HALT "fragment missing platforms/macos/configuration-profiles/"
  else:
    written = list(output_dir, "*.mobileconfig")
    ASSERT len(written) >= 1
      HALT "no .mobileconfig emitted; check stderr"

POSTCONDITIONS:
  RETURN {
    output_dir,
    fragment,
    profile_count: len(written),
  }
```

---

## Other operations (prose recipes)

### Initialise a new policy file

```
contour notifications init --org com.acme -o notifications.toml
# Stub with [config] block and empty apps = []. Edit manually or scan
# to populate.
```

### Scan apps

```
contour notifications scan /Applications --org com.acme \
  -o notifications.toml --json
# Walks the given paths and creates [[apps]] entries with bundle IDs
# and sensible per-app defaults (alerts on, critical off).
```

### Interactively configure

```
contour notifications configure notifications.toml
# REPL wizard — walks each app and prompts per setting.
```

### Validate

```
contour notifications validate notifications.toml --json
# Same JSON shape consumed by STEP 1 above.
```

### Diff two policy files

```
contour notifications diff base.toml updated.toml --json
# Lists added/removed apps and per-app setting deltas.
```

---

## Key facts

- Notification settings keys (per app):
  - `alert_type`         — `none` | `banner` | `alert`
  - `badges_enabled`     — bool (red dot on icon)
  - `sounds_enabled`     — bool
  - `notifications_enabled` — bool (master switch)
  - `show_in_lock_screen` — bool
  - `show_in_notification_centre` — bool
  - `critical_alert_enabled` — bool (must be entitled by Apple)
  - `preview_type`       — `never` | `when_unlocked` | `always`
- Critical alerts require an Apple-issued entitlement — most apps can't
  use them. The CLI accepts the value; deployment fails on the device
  if the entitlement is missing.
- Once a user interacts with an app and accepts/declines its
  notification prompt, the user's choice is sticky — the profile only
  reliably wins for first-time launches.
- Fragment mode (`--fragment`) is the recommended output for adding to
  a GitOps repo (Fleet v4.83 layout) (v4.83 layout).
