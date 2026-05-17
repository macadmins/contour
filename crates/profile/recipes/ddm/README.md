# Built-in DDM bundles

Reusable `ddm compose` bundle TOMLs for common authoring intents. Each
file describes one DDM intent (asset/configuration/activation triple)
and composes into agent-ready declaration JSON via:

```bash
contour profile ddm compose <bundle.toml> -o ./out/
```

The `intent_name` in each bundle is used as the suffix segment in
computed identifiers (`{org}.{kind}.{intent_name}`). `CONTOUR_ORG`
or `--org` decides the prefix.

## Available presets

| Bundle | What it does |
|---|---|
| `disable-apple-intelligence-macos.toml` | Sets every `com.apple.configuration.intelligence.settings` toggle to `false` (Writing Tools, Genmoji, Image Playground, Image Wand, Personalized Handwriting, Visual Intelligence Summary, Apple Intelligence Report) plus nested Mail (`AllowSmartReplies`, `AllowSummary`) and Notes (`AllowTranscription`, `AllowTranscriptionSummary`) — for macOS scope |
| `disable-apple-intelligence-ios.toml` | Same payload as the macOS bundle, distinct intent_name so identifiers and group-targeting stay separate — for iOS / iPadOS scope |
| `external-intelligence-settings.toml` | Disables third-party external intelligence integrations (ChatGPT and similar) via `com.apple.configuration.external-intelligence.settings`; commented keys cover the keep-enabled / workspace-scoped case |
| `keyboard-settings.toml` | Managed `com.apple.configuration.keyboard.settings` — turns dictation off and leaves the other typing aids on; all eight keys stated explicitly for easy adjustment |
| `managed-migration-assistant.toml` | Runs Migration Assistant under managed control via `com.apple.configuration.migration-assistant.settings`, carrying over Security & Privacy settings |
| `siri-settings.toml` | Managed `com.apple.configuration.siri.settings` — keeps Siri enabled but off the lock screen, profanity filter forced, no user-generated content; set `Enabled = false` to disable Siri entirely |

All bundles use a simple activation (no predicate) — scope to platform
via your MDM's group/team assignment.

## Verifying the output

After composing:

```bash
contour profile ddm verify ./out/        # cross-reference DAG
contour profile ddm validate ./out/configuration.json --json
```

## Adding new presets

Author a new TOML, name it descriptively (`<verb>-<thing>-<scope>.toml`),
list it in the table above. Verify it composes + verifies clean before
landing.
