# SOP: App privacy defaults (DDM)

Pre-answer an app's privacy prompts with
`com.apple.configuration.app.settings`, so users meet one managed decision
instead of a queue of TCC dialogs.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/profile/tests/sop_traps.rs`

---

## WHEN TO USE

Route here when the user wants to **grant an app a privacy permission up
front** — camera, microphone, local network, accessibility, Bluetooth,
dictation or location — on a Mac managed over DDM.

Do NOT route here for:

- **Denying** a permission. Apple provides no deny; see VALUE_SEMANTICS.
- Permissions outside the eight in PERMISSION_REGISTRY — screen recording,
  full disk access, Apple Events, the folder policies. Those remain PPPC
  (`--sop profile`, `com.apple.TCC.configuration-profile-policy`).
- Managing which apps may run. That is `app.settings`'s *other* half,
  `Allowed`, and a different intent: `contour profile ddm app-control`.

## WHAT THE DEVICE DOES

The declaration carries a `Privacy.PermissionDefaults` map. Each key names
one app; each value pre-answers that app's prompts and records a
justification the user can read. A permission the map does not mention is
left alone.

Requirements: macOS 26 or later and **user-channel** enrollment. Verify the
minimum OS against your fleet before relying on it — Apple's per-key
documentation is thinner than the schema, and a declaration the OS ignores
still reports Verified.

## PERMISSION_REGISTRY

| TOML key | Apple key | Values |
|---|---|---|
| `accessibility` | `Accessibility` | `Allow`, `None` |
| `bluetooth` | `Bluetooth` | `Allow`, `None` |
| `camera` | `Camera` | `Allow`, `None` |
| `dictation` | `Dictation` | `Allow`, `None` |
| `local_network` | `LocalNetwork` | `Allow`, `None` |
| `location` | `Location` | `Always`, `WhileUsing`, `None` |
| `location_accuracy` | `LocationAccuracy` | `Precise`, `Approximate`, `None` |
| `microphone` | `Microphone` | `Allow`, `None` |

`OrganizationJustification` is **required** on every entry and is shown to
the user.

Authoritative check:
`contour profile ddm info com.apple.configuration.app.settings --full`.

## VALUE_SEMANTICS

Three rules that published write-ups get wrong. An agent MUST apply these
rather than copying an example found online.

1. **There is no `Deny`.** The values are `Allow` and `None` only.
   contour refuses `Deny` by name.
2. **`None` means unmanaged, not denied.** The app is left to the normal
   prompt flow and the user decides. It does not block the permission.
3. **Omitting a permission does the same as `None`.** A map listing only
   `Camera` says nothing about the microphone.

So a request to "block the camera for this app" has **no answer in this
declaration**. Say so, and route to the app-specific restriction payload or
to not deploying the app, rather than emitting `Camera = "None"` and calling
it blocked.

## KEY_CONSTRUCTION

**The key format differs by platform, and neither form works on the other.**
Apple:

> In iOS, the app identifier is a bundle ID, for example, "com.example.app".
>
> In macOS, the app identifier is a composed identifier. The format of the
> composed identifier is "Bundle-ID {Designated-Requirement}". […] The
> device only applies defaults for an app if its code signature matches the
> composed identifier.

```
iOS      us.zoom.xos
macOS    us.zoom.xos {identifier "us.zoom.xos" and anchor apple generic and certificate …}
```

Apple ships both spellings in its own examples — `example1.json` is iOS,
`example2.json` is macOS. A declaration written for one platform cannot be
retargeted at the other by changing the activation predicate; the key itself
must change.

On macOS the requirement comes from `codesign -d -r-` and must be
byte-exact. This is the trap that defines the whole workflow: a wrong,
stale, or wrong-platform key produces a declaration that validates, deploys,
reports **Verified**, and manages nothing. It is silent in every channel an
operator would check.

Eight other keys across Apple's schema take a composed identifier, four of
them with a *team ID* in parentheses rather than a requirement in braces —
`--sop composed-identifiers` has the full registry.

Agents MUST NOT compose this key by hand or from memory. `app-privacy scan`
reads it from the installed app, and refuses any app whose requirement it
cannot read rather than writing a placeholder.

## ERROR-CODE ENUM

Inherited from `--sop ddm`. Agents MUST switch on `error_code`, never prose.

```
SCHEMA_VIOLATION       failed Apple-schema validation
INVALID_ORG            org domain malformed or absent
IO_ERROR               file not found, permission denied, disk full
UNKNOWN                unmatched — treat as fatal, do NOT auto-retry
```

---

## PROCEDURE grant_app_privacy(app_paths, org, permissions, justification)

```
SCHEMA_SOURCE: apple/device-management (release branch)
SCHEMA_TOOL:   contour profile ddm info com.apple.configuration.app.settings --json

INPUT:
  app_paths     : installed .app bundles, e.g. /Applications/zoom.us.app
  org           : reverse-domain identifier; contour refuses com.example
  permissions   : subset of PERMISSION_REGISTRY, per app
  justification : user-visible reason, per app

PRECONDITIONS:
  ASSERT every path in app_paths exists on THIS machine
    HALT "app-privacy reads the designated requirement from the installed
          app; {path} is not present. Install it, or obtain the requirement
          from a machine that has it."

  ASSERT no requested value is "Deny"
    HALT "Apple has no Deny for app privacy. 'None' leaves the permission
          unmanaged and the user is still prompted. To actually prevent
          access, use a restriction payload — see VALUE_SEMANTICS."

  ASSERT justification is non-empty for every app
    HALT "OrganizationJustification is required and is shown to the user"

STEP 1 — Scan the apps:
  contour profile ddm app-privacy scan {app_paths...} -o app-privacy.toml

  # Refuses an unsigned or unreadable app by name. Do NOT work around this
  # by hand-writing designated_requirement — see KEY_CONSTRUCTION.
  if exit != 0:
    HALT "{stderr}"

STEP 2 — Set justification and permissions:
  # scan writes every permission commented out, so the file is inert until
  # an operator states intent. Uncomment only what the app needs.
  edit app-privacy.toml

  ASSERT each edited value is legal for its permission (PERMISSION_REGISTRY)
    # location and location_accuracy do NOT take "Allow"

STEP 3 — Generate (dry run first):
  contour profile ddm app-privacy generate app-privacy.toml \
      --org {org} -o ./declarations/app-privacy

  # Dry run by default; nothing is written.
  SWITCH exit_code
    CASE 0:        continue
    DEFAULT:       HALT "{error_code}: {error}"

STEP 4 — Apply:
  contour profile ddm app-privacy generate app-privacy.toml \
      --org {org} -o ./declarations/app-privacy --write

POSTCONDITIONS:
  ASSERT configuration.json exists AND activation.json exists
    HALT "a configuration alone is inert — it needs an activation"

  ASSERT configuration.Type == "com.apple.configuration.app.settings"

  FOR EACH key IN configuration.Payload.Privacy.PermissionDefaults:
    ASSERT key matches /^\S+ \{.+\}$/
      HALT "key must be '<bundle id> {<designated requirement>}'; got {key}"
    ASSERT entry.OrganizationJustification is non-empty

  CROSS-FILE INVARIANT:
    activation.Payload.StandardConfigurations contains configuration.Identifier

  RETURN { files: [configuration.json, activation.json], apps: N }
```

---

## PROCEDURE migrate_from_pppc(pppc_file, org)

```
INPUT:
  pppc_file : an existing pppc.toml

STEP 1 — Import:
  contour profile ddm app-privacy import-pppc {pppc_file} -o app-privacy.toml

STEP 2 — Read the unmapped list, and do not discard it:
  # Only five PPPC services have an app.settings equivalent:
  #   camera, microphone, accessibility, bluetooth,
  #   speech-recognition → Dictation
  # Everything else — fda, apple-events, screen-capture, documents,
  # desktop, downloads, photos, contacts, calendar, reminders, … — has NO
  # equivalent and is reported as unmapped.

  ASSERT the operator is told which grants did not carry over
    WARN "these apps still need their PPPC profile deployed: {unmapped}"

  # An agent MUST NOT report the migration as complete when the unmapped
  # list is non-empty. The PPPC profile is still load-bearing.

STEP 3 — Continue at grant_app_privacy STEP 2.
```

---

## TRAPS

| Trap | Symptom | Guard |
|---|---|---|
| Hand-written designated requirement | Declaration Verified, prompts still appear | `scan` extracts it; unreadable app is refused |
| iOS key shape used on macOS (bare bundle ID) | Declaration Verified, no defaults applied | `form emit --os macos` refuses: `composed-identifier` |
| macOS key shape used on iOS (braces) | Same, silently | `form emit --os ios` refuses |
| `Deny` used | Value rejected, or worse, assumed to block | Refused by name with an explanation |
| `None` believed to deny | Permission silently left to the user | VALUE_SEMANTICS |
| Omitted permission believed denied | Same | VALUE_SEMANTICS |
| `Allow` on `location` | Schema violation | Per-permission value sets |
| Empty justification | Apple requires it | Refused before writing |
| PPPC migration assumed complete | Screen recording, FDA silently lost | `import-pppc` lists unmapped grants |
| Missing activation | Nothing applies | `generate` always emits one |
| Device-channel enrollment | Declaration ignored | User channel required |

---

## RELATED

- `--sop profile` — PPPC for the permissions this declaration cannot express
- `--sop ddm` — activation, predicates and the subscription rule
- `--sop service-config` — the other `services.*` declaration family
