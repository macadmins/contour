# SOP: Apple Intelligence configuration (DDM)

**Scope: Apple's own AI features, delivered as DDM declarations.** On-device Apple
Intelligence (Writing Tools, Genmoji, Image Playground, …), the external-intelligence
hook that lets a third-party assistant such as ChatGPT plug into the OS, and the
`app.settings` binary execution control that shipped alongside them.

> **Not this SOP:** managing the AI *coding tools* themselves — Claude Code, OpenAI
> Codex, Cursor, Gemini Enterprise mobile — through their vendor preference domains.
> That is `--sop app-policy`. The two share the word "AI" and nothing else: this SOP
> is `com.apple.configuration.*` declarations; that one is `com.anthropic.claudecode`,
> `com.openai.codex` and friends as managed-preferences profiles.

Every payload here is in the **released schema** (intelligence and external-intelligence
since 26.4, app.settings since 27.0, safari.settings since 26.0). None of it needs
`--beta`.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Companion SOPs: `--sop ddm`, `--sop santa` (the app.settings bridge), `--sop app-policy` (AI coding tools).

## THE GENERATIVE PAYLOAD MAP

```
com.apple.configuration.intelligence.settings           # on-device Apple Intelligence
  AllowGenmoji / AllowImagePlayground / AllowImageWand   # creation features
  AllowWritingTools / AllowVisualIntelligenceSummary     # text + visual
  AllowPersonalizedHandwritingResults / AllowAppleIntelligenceReport
  ForceOnDeviceOnlyDictation / ForceOnDeviceOnlyTranslation   # keep data on device
  Apps.{Calendar.AllowNaturalLanguageEditing, Mail.AllowSmartReplies, …}  # per-app

com.apple.configuration.external-intelligence.settings  # third-party AI (e.g. ChatGPT)
  Enabled / AllowSignIn
  AllowedWorkspaceIDs[]                                  # 27.0 allowlist of workspaces

com.apple.configuration.app.settings                    # binary execution control (ES)
  Allowed.{AllowedBinaries[], DeniedBinaries[], AllowedApps[], DeniedApps[],
           AlwaysAllowManagedApps}
  Privacy.PermissionDefaults{ <app-id>: {Camera, Microphone, Location, …} }

com.apple.configuration.safari.settings                 # incl. 27.0 Privacy.PermissionDefaults
```

`intelligence.settings` is a substring of `external-intelligence.settings` — pass the
**full type** to `generate`, or the short-name resolver can pick the wrong one.

---

## PROCEDURE managed_ai_policy(org, output)

Author an organizational Apple Intelligence policy (e.g. allow Writing Tools, disable
Genmoji / Image Playground, keep dictation on-device).

```
STEP 1 — Author the value payload (only the keys intent needs; merged over skeleton):
  values.json:
    {
      "AllowGenmoji": false,
      "AllowImagePlayground": false,
      "AllowWritingTools": true,
      "ForceOnDeviceOnlyDictation": true,
      "Apps": { "Calendar": { "AllowNaturalLanguageEditing": false },
                "Mail":     { "AllowSmartReplies": true } }
    }

STEP 2 — Generate (FULL type avoids the substring gotcha):
  contour profile ddm generate com.apple.configuration.intelligence.settings \
      --payload values.json --org {org} -o {output}

STEP 3 — Validate:
  contour profile ddm validate {output}   ASSERT "valid"
  # Verify Type == com.apple.configuration.intelligence.settings (NOT external-…).
```

## PROCEDURE external_ai_allowlist(org, output)

Gate third-party AI integrations to approved workspaces.

```
values.json: { "Enabled": true, "AllowSignIn": false,
               "AllowedWorkspaceIDs": ["acme-prod-workspace", "acme-research"] }

contour profile ddm generate com.apple.configuration.external-intelligence.settings \
    --payload values.json --org {org} -o {output}
contour profile ddm validate {output}
```

## PROCEDURE app_execution_control(org, output)

Populate `app.settings` with REAL apps. Prefer the **santa→app.settings bridge** over
hand-writing binary identifiers — it derives `AllowedBinaries`/`DeniedBinaries` from
code-signing identifiers and enforces the schema's per-list identifier rules
(`AllowedBinaries` ⇒ CDHash|TeamID; `DeniedBinaries` ⇒ CDHash|TeamID|SigningID).

```
OPTION A — from existing Santa rules:
  contour santa app-settings rules.json --from-rules --org {org} -o {output}

OPTION B — from a live scan of installed apps:
  contour santa scan ... > scan.csv          # santactl inventory (needs Santa)
  contour santa app-settings scan.csv --org {org} -o {output}

ADD app privacy permission defaults (Camera/Mic/Location per app):
  contour santa app-settings scan.csv --scaffold -o app-permissions.toml   # editable skeleton
  # edit OrganizationJustification + per-permission values, then:
  contour santa app-settings scan.csv --permissions app-permissions.toml --org {org} -o {output}

VALIDATE:
  contour profile ddm validate {output}

NOTE: DeniedBinaries under Endpoint Security TERMINATES running processes of a
matched binary, not just future launches. The command warns when it emits deny
entries — surface that warning to the operator.
```

See `--sop santa` for the full identifier-strategy detail (`--rule-type`,
`--platform`, `*APPLE*` sentinel, never-skip guardrails).

---

## SAFETY

- These payloads are recent (26.4 / 27.0). Older devices in the fleet ignore keys
  their OS predates; `contour profile ddm info <type>` shows per-OS introduction.
- `app.settings` deny rules are high-impact (process termination). Stage them through
  a rollout cohort (a Fleet label) before fleet-wide application.

## Key flags

- `--payload <file>` — merge intent values over the generated skeleton.
- `--full` — surface every optional knob (useful when exploring what a payload offers).
- santa bridge: `--from-rules`, `--scaffold`, `--permissions`, `--deny`, `--always-allow-managed`.
