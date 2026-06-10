# SOP: Generative / Apple Intelligence configuration

This SOP covers the OS 27 **generative-AI and app-control** DDM declarations:
on-device Apple Intelligence, third-party ("external") intelligence integrations,
and binary execution control. Every payload here is **seed-only** — it lives in the
beta channel and requires `--beta` on generate/validate. Read `--sop beta` first for
channel rules and the short-name resolver gotcha; this SOP is the payload-specific
layer on top of it.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Companion SOPs: `--sop beta` (channel), `--sop santa` (the app.settings bridge), `--sop ddm`.

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

INVARIANT: all of the above are seed-only → `--beta` is mandatory on `generate` and
`validate`. Without it the stable channel rejects them as unknown (see `--sop beta`).

`intelligence.settings` is a substring of `external-intelligence.settings` — pass the
**full type** to `generate` (the resolver gotcha in `--sop beta`).

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

STEP 2 — Generate against the seed schema (FULL type avoids the substring gotcha):
  contour profile ddm generate com.apple.configuration.intelligence.settings \
      --beta --payload values.json --org {org} -o {output}

STEP 3 — Validate:
  contour profile ddm validate {output} --beta   ASSERT "valid"
  # Verify Type == com.apple.configuration.intelligence.settings (NOT external-…).
```

## PROCEDURE external_ai_allowlist(org, output)

Gate third-party AI integrations to approved workspaces.

```
values.json: { "Enabled": true, "AllowSignIn": false,
               "AllowedWorkspaceIDs": ["acme-prod-workspace", "acme-research"] }

contour profile ddm generate com.apple.configuration.external-intelligence.settings \
    --beta --payload values.json --org {org} -o {output}
contour profile ddm validate {output} --beta
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

VALIDATE (app.settings is a seed type → --beta):
  contour profile ddm validate {output} --beta

NOTE: DeniedBinaries under Endpoint Security TERMINATES running processes of a
matched binary, not just future launches. The command warns when it emits deny
entries — surface that warning to the operator.
```

See `--sop santa` for the full identifier-strategy detail (`--rule-type`,
`--platform`, `*APPLE*` sentinel, never-skip guardrails).

---

## SAFETY

- These payloads target an unreleased OS (27.0). They validate against the current
  seed but the seed can change before GA — author ahead, don't ship to production
  fleets as final. See `--sop beta` SAFETY.
- `app.settings` deny rules are high-impact (process termination). Stage them through
  a rollout cohort (a Fleet label / ring) before fleet-wide application.

## Key flags

- `--beta` — mandatory: every payload here is seed-only.
- `--payload <file>` — merge intent values over the generated skeleton.
- `--full` — surface every optional knob (useful when exploring what a payload offers).
- santa bridge: `--from-rules`, `--scaffold`, `--permissions`, `--deny`, `--always-allow-managed`.
