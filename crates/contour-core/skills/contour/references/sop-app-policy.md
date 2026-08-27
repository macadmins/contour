# SOP: AI-tool managed configuration (app policies)

Contour embeds a policy dataset for AI coding tools — the managed-
configuration surface of Claude Code (591 keys), OpenAI Codex (14), Cursor
(9), and Gemini Enterprise mobile (8): 622 (tool × key) rows with delivery
channels, enum vocabularies, and NIST 800-53 control mappings
(`app-policy-schema` crate, `app_policies.parquet`).

**Status: dataset embedded, no query CLI yet.** There is no
`contour app-policy search` today — this SOP documents what exists and the
one workflow that already works end-to-end: delivering managed settings to
an AI tool **as a macOS configuration profile** through contour's existing
recipe machinery.

---

## Decision tree

```
What are you trying to do?
│
├─ Lock down Claude Code on managed Macs (permissions, model policy)
│  → Recipe 1: managed-preferences profile via mcx_domain
│
├─ Manage Codex on managed Macs
│  → Recipe 1 applies, plus the base64-TOML caveat below
│
├─ Deliver settings as files (managed-settings.json, managed_config.toml)
│  → Out of contour's scope by decision — file delivery is the MDM/GitOps
│    side's job; the profile channel outranks the file channel for both
│    vendors anyway
│
└─ Query the key catalogue programmatically
   → Not yet — the app-policy-schema crate has a reader; a
     `contour app-policy search|info` CLI is the planned surface
```

---

## Recipe 1: Claude Code managed-preferences profile

Claude Code reads the `com.anthropic.claudecode` managed-preferences domain,
and managed scope outranks everything including CLI flags. Author a recipe
`[[profile]]` block with `mcx_domain` (same mechanism the embedded
`disablebonjouradvertisement` recipe uses):

```toml
[recipe]
name = "claude-code-policy"
description = "Org-managed Claude Code settings"

[[profile]]
filename = "claude-code-policy.mobileconfig"
payload_type = "com.apple.ManagedClient.preferences"
mcx_domain = "com.anthropic.claudecode"
display_name = "Claude Code Managed Policy"
description = "Org-managed Claude Code settings"

# Nested settings are TOML tables — they render as plist dicts.
[profile.fields.permissions]
deny = ["Bash(curl:*)", "Read(./.env)"]
allow = ["Bash(git status)"]
```

Render and validate as usual:

```bash
contour profile generate --recipe ./claude-code.toml --org <ORG_DOMAIN> -o ./out
```

Key facts from the dataset worth honoring in the recipe:

- **Nested keys become plist dicts** (`permissions.allow` → `permissions`
  dict with an `allow` array); arrays stay arrays.
- **`managed_only` keys** (the `allowManaged*Only` lockdown trio,
  `forceLoginOrgUUID`, `requiredMinimumVersion`) are only honored from
  managed scope — exactly what this profile provides.
- The authoritative key list is Anthropic's settings JSON-Schema
  (`json.schemastore.org/claude-code-settings.json`); the embedded dataset
  pins a source hash per ingest.

## Codex caveat

Codex's profile channel (`com.openai.codex`) expects `config_toml_base64` /
`requirements_toml_base64` — **base64-encoded TOML inside a plist string**.
Contour can carry the key via `extra_fields`, but the blob is opaque to
schema validation, org-rename, and diff, and long base64 values can trip the
secret-entropy audit. Treat Codex profiles as passthrough artifacts and keep
the source TOML in the repo next to the recipe. (Vendor guidance: no secrets
or high-churn values in the payload.)

---

## Traps

- **No schema validation for these domains yet.** `com.anthropic.claudecode`
  is not in the Apple schema registry, so generated profiles validate
  structurally (envelope, MCX shape) but keys are not checked against the
  vendor catalogue. The dataset exists precisely to close this gap — until a
  CLI lands, verify key names against the vendor schema by hand.
- **Vendor keys drift fast.** The dataset is a pinned snapshot
  (source hash + ingest date per row); check the vendor's docs before
  shipping a policy built from memory.
- **Never `com.example`.** Same org-domain rule as every generate.

## Roadmap

Planned surface (not yet implemented): `contour app-policy search <q>` /
`contour app-policy info <tool> [key]` over the embedded dataset, and
key-level validation of `mcx_domain` recipes against it.
