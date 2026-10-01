# DDM examples — Apple's declarations with contour

A copy-paste guide to **list, inspect, transform, generate, and validate** Declarative
Device Management (DDM) declarations with contour, built around the examples Apple
publishes in its [device-management](https://github.com/apple/device-management)
repository.

Everything here is the **released schema**. The beta channel is disabled in this build
and `--beta` refuses, so no command below carries it.

> **Org domain:** every generate needs one (`--org com.acme`, or `export
> CONTOUR_ORG=com.acme`, or `.contour/config.toml`). contour never falls back to
> `com.example`. The examples below assume `export CONTOUR_ORG=com.acme`.

> **Two kinds of "AI".** Apple Intelligence declarations (`intelligence.settings`,
> `external-intelligence.settings`, `app.settings`) are covered here and in
> `contour help-ai --sop generative`. Managing the AI *coding tools* (Claude Code,
> Codex, Cursor, Gemini Enterprise mobile) is a different thing: see
> `contour help-ai --sop app-policy`.

---

## 0. Where the examples come from

Apple ships one or more example JSON files per declaration type and per status item:

```
device-management/
  declarative/declarations/{activations,assets,configurations,management}/<type>.yaml   # schemas
  examples/declarative/declarations/<category>/<type>/example1.json …                  # declaration examples
  examples/declarative/status/<status-item>/example1.json …                            # what a device reports
```

contour embeds a pinned copy of both the schemas and the examples (the same files,
one embedded entry per `exampleN.json`), so every command works offline. A local checkout lets you reach the files directly, and lets you run
against a schema **newer than the embedded pin**:

```bash
git clone https://github.com/apple/device-management ~/Code/GitHub/device-management
export DM=~/Code/GitHub/device-management
git -C "$DM" log -1 --format='%h %ad %s' --date=short     # e.g. "09f249a 2026-09-17 Release-v27.0"
```

Every schema-reading subcommand (`list`, `search`, `info`, `generate`, `validate`,
`compose`) accepts `--schema-path "$DM"` (`-p`) to use the checkout instead of the
embedded copy. `examples` and `transform --type` read the embedded examples only;
`transform <file>`, `parse` and `validate` take any file, so the on-disk examples
work through those.

---

## 1. List and search

```bash
contour profile ddm list                       # every embedded declaration type
contour profile ddm list --json | jq -r '.[].type'
contour profile ddm search passcode --json     # substring match across name, title, description, keys
contour profile ddm list -p "$DM"              # same, from the checkout
```

The embedded set covers the configuration families you will reach for most:
`passcode.settings`, `softwareupdate.*`, `safari.*`, `screensharing.*`,
`security.*`, `services.*`, `network.*` (relay, DNS, VPN), `app.managed`,
`app.settings`, `intelligence.settings`, `external-intelligence.settings`,
plus assets, activations, and the `management.*` declarations.

---

## 2. Inspect a type's schema

```bash
contour profile ddm info passcode.settings --json
contour profile ddm info app.settings
contour profile ddm info com.apple.configuration.intelligence.settings    # full type when a short name is ambiguous
contour profile ddm info passcode.settings -p "$DM"                        # from the checkout
```

**Use the full type for names that are a substring of another type.**
`intelligence.settings` is contained in `external-intelligence.settings`. The
short-name resolver matches at dot boundaries, so the short form is usually right,
but the full `com.apple.configuration.*` type is never wrong.

---

## 3. Read Apple's examples

Embedded, by type — each entry is one of Apple's `exampleN.json` files, with its tab
title and description:

```bash
contour profile ddm examples passcode.settings
#   [0] Complex
#       This configuration applies a complex passcode policy.
#   [1] Regular expression
#       This configuration applies a passcode policy using a regular expression.
contour profile ddm examples app.settings --json
```

On disk, the same files:

```bash
ls "$DM"/examples/declarative/declarations/configurations/passcode.settings/
#   example1.json  example2.json
cat "$DM"/examples/declarative/declarations/configurations/intelligence.settings/example1.json
```

Apple's examples carry placeholder `Identifier` and `ServerToken` UUIDs. They parse
and validate as they are:

```bash
contour profile ddm parse    "$DM"/examples/declarative/declarations/configurations/passcode.settings/example1.json
contour profile ddm validate "$DM"/examples/declarative/declarations/configurations/passcode.settings/example1.json
#   ✓ example1.json is valid
```

---

## 4. Transform an example into a working declaration

`transform` takes an Apple example and makes it yours: your org in the `Identifier`,
Apple's `ServerToken` dropped, placeholder values replaced.

```bash
# From the embedded copy (type + index, as listed by `ddm examples`):
contour profile ddm transform --type app.settings --example 2 --org com.acme -o app.settings.json

# From a file in the checkout:
contour profile ddm transform \
    "$DM"/examples/declarative/declarations/configurations/intelligence.settings/example1.json \
    --org com.acme -o intelligence.settings.json

# Replace Apple's sample values with yours, and refuse to write if a placeholder survives:
cat > values.toml <<'TOML'
"com.example.TestApp (ABCDE12345)" = "com.acme.Tool (EQHXZ8M8AV)"
TOML
contour profile ddm transform \
    "$DM"/examples/declarative/declarations/configurations/app.managed/example3.json \
    --org com.acme --values values.toml --strict -o app.managed.json
```

The values file is a flat find→replace map (TOML or JSON), matched as substrings
against Apple's exact placeholder text, so copy the placeholder verbatim. `--strict`
fails the transform if any `com.example` text survives.

**What needs a values map.** Every one of Apple's 94 declaration examples transforms
and validates with `--org` alone. 75 are complete as they stand. The other 19 carry an
identifier only you can supply, which Apple spells `com.example.*`: a bundle ID or
composed identifier (`app.managed`, `app.settings`, `safari.extensions.settings`), an
extension or plugin ID (`extensiblesso`, `network.dns-proxy`, `network.vpn.vpn-plugin`,
`network.webcontent-filter.plugin`), or a launchd label (`services.background-tasks`).
Map those with `--values`, or for `app.settings` fill the lists from a scan of real
installed apps. **Santa is not required**: the scan reads code signatures with
`santactl` when it is present and with `codesign`, which every Mac has, when it is
not. Without Santa the CSV lacks `version` and `sha256`; the identifiers
`app.settings` needs (team ID, signing ID, CDHash) are all there.

```bash
contour santa scan -o scan.csv
contour profile ddm transform --type app.settings --example 2 --org com.acme \
    --scan scan.csv -o app.settings.json              # AllowedBinaries from the scan
contour profile ddm transform --type app.settings --example 2 --org com.acme \
    --scan scan.csv --deny -o app.settings.json       # …or DeniedBinaries
```

Section 5c has the DDM-native route, which skips the CSV and the Santa toolkit
altogether.

---

## 5. Generate from the schema

When no example fits, generate from the schema. `--full` emits every optional key;
`--payload` merges your values over the skeleton. Generation is **fail-closed**: a
schema-invalid result is never written.

```bash
contour profile ddm generate passcode.settings --full --org com.acme -o passcode.settings.json
```

### 5a. Apple Intelligence (`intelligence.settings`)

Apple's `intelligence.settings/example1.json` turns every feature off and forces
on-device dictation and translation. A typical policy is more selective:

```bash
cat > intel.json <<'JSON'
{
  "AllowGenmoji": false,
  "AllowImagePlayground": false,
  "AllowWritingTools": true,
  "ForceOnDeviceOnlyDictation": true,
  "Apps": {
    "Mail":  { "AllowSmartReplies": true, "AllowSummary": false },
    "Notes": { "AllowTranscription": false }
  }
}
JSON
contour profile ddm generate com.apple.configuration.intelligence.settings \
    --payload intel.json -o intelligence.settings.json
```

### 5b. External intelligence (`external-intelligence.settings`)

Gate third-party assistants (ChatGPT and the like) to approved workspaces. Compare
with `external-intelligence.settings/example1.json` in the checkout.

```bash
cat > extintel.json <<'JSON'
{ "Enabled": true, "AllowSignIn": false,
  "AllowedWorkspaceIDs": ["acme-prod-workspace", "acme-research"] }
JSON
contour profile ddm generate com.apple.configuration.external-intelligence.settings \
    --payload extintel.json -o external-intelligence.settings.json
```

### 5c. Binary execution control (`app.settings`) with real apps

Apple publishes a dozen `app.settings` examples (`alr-*.json`) that show every
identifier shape. Do not hand-write identifiers; read them off the installed apps.
Both routes below enforce the schema's per-list rules (`AllowedBinaries` ⇒
CDHash|TeamID, `DeniedBinaries` ⇒ CDHash|TeamID|SigningID), and **neither needs
Santa installed**: signatures come from `codesign`, which every Mac has.

**DDM-native route.** Scan into an editable policy file, review it, then compose the
configuration and its activation:

```bash
contour profile ddm app-control scan /Applications -o app-control.toml   # [[allow]] entries at the vendor's team ID
contour profile ddm app-control scan /Applications --deny -o app-control.toml   # …or [[deny]]
# review app-control.toml, then:
contour profile ddm app-control generate app-control.toml --org com.acme -o out/ --write
contour profile ddm validate out/
contour profile ddm verify   out/      # configuration ↔ activation cross-reference
```

An allow list is exclusive: only matching binaries run, apart from system-critical
processes. `allow_apple = true` in the policy file keeps Apple's own apps running.

**Santa toolkit route.** If you already manage Santa, the same declaration can come
from your rules or a Santa scan, and can carry per-app privacy defaults:

```bash
contour santa app-settings rules.json --from-rules --org com.acme -o app.settings.json   # from Santa rules

contour santa scan -o scan.csv                                                            # santactl, or codesign
contour santa app-settings scan.csv --org com.acme -o app.settings.json

contour santa app-settings scan.csv --scaffold -o app-permissions.toml       # Camera/Mic/Location skeleton; edit, then:
contour santa app-settings scan.csv --permissions app-permissions.toml --org com.acme -o app.settings.json
```

> `DeniedBinaries` under Endpoint Security **terminates running processes**, not just
> future launches. Stage deny rules through a rollout cohort before fleet-wide.

### 5d. Explore any other type

```bash
contour profile ddm generate com.apple.configuration.safari.settings        --full -o safari.settings.json
contour profile ddm generate com.apple.configuration.content-cache.settings --full -o content-cache.settings.json
contour profile ddm generate com.apple.configuration.network.relay          --full -o network.relay.json
```

---

## 6. Validate

```bash
contour profile ddm validate .                           # a directory, or a single file
contour profile ddm validate intelligence.settings.json --json
contour profile ddm validate out/ -p "$DM"               # against the checkout's schema
```

---

## 7. Bundles: compose and verify

For multi-component setups (asset + configuration + activation with cross-references),
author a bundle TOML and use **compose**. It wires identifiers and references by
construction and is fail-closed. A runnable bundle lives in
[`examples/ddm-exchange-bundle.toml`](examples/ddm-exchange-bundle.toml). Apple's
`activations/simple/` and `assets/` examples show the shapes compose produces.

```bash
contour profile ddm compose docs/examples/ddm-exchange-bundle.toml -o out/ --json
contour profile ddm verify  out/ --json          # cross-reference + predicate check
```

See `contour help-ai --sop ddm` for the bundle format and the dependency DAG.

---

## 8. Status items: the other half

Declarations go down; status items come back. Apple's
`examples/declarative/status/<item>/exampleN.json` files show what a device reports
for each item. contour lists the items and their scopes per OS:

```bash
contour profile ddm status
contour profile ddm status --json
cat "$DM"/examples/declarative/status/passcode.is-compliant/example1.json
```

Subscribe to the items you need with `management.status-subscriptions`
(`examples/declarative/declarations/configurations/management.status-subscriptions/example1.json`).

---

## Practical tips

- **Start from Apple's example, then `transform`.** It is the fastest way to a valid
  declaration, and the example already shows the key shapes Apple intends.
- **`--full` to explore, `--payload` to author.** `--full` surfaces every optional
  knob; `--payload` merges only what you mean to set.
- **Use the full `com.apple.configuration.*` type** for any short name that is a
  substring of another type.
- **Checkout newer than the pin?** Pass `-p "$DM"` and validate against the same
  schema you generated with.
- **Always validate**, and stage high-impact declarations (`app.settings` deny rules,
  software update enforcement) through a cohort before fleet-wide.
- **`--json` everywhere** for CI and agents.
