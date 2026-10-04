# SOP: Santa Allowlist Generation

Santa is allowlist-driven endpoint security for macOS. The CLI surface
fans out across discovery (scan, fetch), classification (CEL, bundles),
generation (allow, pipeline), and rule management (add, remove,
filter, validate). This SOP is **not** a single procedure — it's a
**decision tree** that points you at the right recipe for the goal,
plus six cookbook recipes that work end-to-end.

If you came here to migrate a profile or wire a DDM declaration, this
isn't your SOP. Try `--sop profile`, `--sop ddm`, or `--sop precommit`.

## Rule: Santa is `com.northpolesec.santa`

One domain, no exceptions. Santa's daemon names its own preference domain —
`kMobileConfigDomain` in `SNTConfigurator.mm` — and it is North Pole
Security's. **A Google-signed Santa is not supported anywhere in contour.**

- Never author, suggest or accept `com.google.santa`. Reading a profile that
  carries it is refused by name, telling the operator what to change it to.
- The embedded schema is derived from Santa's own source, so it describes
  `com.northpolesec.santa` and nothing else. `com.google.santa` is not in
  the dataset — not gated, not present.
- If you find a legacy profile, the fix is the PayloadType, not a flag.

This is not a preference. Do not offer the old domain as a compatibility
option, and do not restore it to a schema, an allow list or a fixture.

---

## Decision tree — pick your goal

```
What are you trying to do?
│
├─ I just want a Santa profile from /Applications, no Fleet
│  → Recipe 1: Local scan → mobileconfig
│
├─ I have a Fleet software CSV and want a single allowlist profile
│  → Recipe 2: Fleet CSV → mobileconfig
│
├─ I have rules from osquery / mobileconfig / santactl / Installomator
│  → Recipe 5: Fetch from external sources
│
├─ I'm classifying apps against bundle definitions (CEL)
│  → Recipe 6: CEL classification
│
└─ I'm editing an existing rules CSV (add / remove / filter / validate)
   → Rule-management cookbook (below)
```

---

## Recipe 1: Local scan → mobileconfig

Single-machine workflow — no Fleet, just "what's on this Mac
right now → allowlist profile":

```bash
contour santa scan -f csv -o apps.csv
contour santa allow -i apps.csv --org com.yourco -o santa.mobileconfig
```

Output: a single signed-or-unsigned mobileconfig you can drop into MDM
or sideload for testing. `apps.csv` is durable — commit it for repeat
generation.

## Recipe 2: Fleet CSV → mobileconfig

You have a Fleet "software" CSV export (the install-base inventory).
Pick the rule type that matches your trust model:

```bash
contour santa allow -i fleet-export.csv --org com.yourco --rule-type team-id
```

`--rule-type` options:
- `team-id` — broadest (allow all binaries from a vendor); most common
- `signing-id` — narrower (specific app/vendor combination)
- `binary` — narrowest (one specific SHA hash)
- `bundle` — group of related binaries; pair with `bundles.toml`

Default `--conflict-policy` is `most-specific` — when the same identifier
appears across multiple rule types, the narrowest rule wins.

## Recipe 5: Fetch rules from external sources

```bash
contour santa fetch osquery <json>          # osquery santa_rules table
contour santa fetch mobileconfig <file>     # extract from existing profile
contour santa fetch santactl <output>       # `santactl fileinfo` output
contour santa fetch installomator <labels>  # Installomator TeamIDs
contour santa fetch fleet-csv <csv>         # Fleet software CSV export
contour santa fetch fleet-apps <json>       # fleet-maintained-apps catalog → Santa + DDM
```

The first five emit a normalized rules CSV/JSON you can hand to Recipe 2.

## Recipe 5.5: fleet-maintained-apps catalog → Santa rules + DDM app.settings

The community **fleet-maintained-apps** tracker publishes a signing-info catalog
for ~1,200 known-good Mac apps — each record carries `signingId`
(`TEAMID:bundle`), `teamId`, `cdhash`, and `sha256`. That is exactly the
vocabulary both Santa rules and the DDM `com.apple.configuration.app.settings`
binary entries need, so one source feeds both.

Source (download first — contour is offline by design):
`https://github.com/allenhouchins/fleet-maintained-apps-growth-tracker/blob/main/data/app_security_info.json`
(raw: `https://raw.githubusercontent.com/allenhouchins/fleet-maintained-apps-growth-tracker/main/data/app_security_info.json`)

```bash
curl -sSL <raw-url> -o app_security_info.json

# Default: SigningID match, allow policy, emit BOTH a Santa .mobileconfig and a
# DDM app.settings declaration into ./out
contour santa fetch fleet-apps app_security_info.json --org com.yourco -o out/
#   → out/santa-rules.mobileconfig   (SIGNINGID allow rules)
#   → out/app-settings.json          (AllowedBinaries: {SigningID, TeamID})

# Options
#   --match signingid|teamid|cdhash   signingid = per-app (default, stable across
#                                       updates); teamid = per-vendor (fewest rules);
#                                       cdhash = per-build (strict, churns on update)
#   --policy allow|deny               allow (known-good catalog, default) or deny
#   --emit santa,ddm,rules            pick artifacts (default santa,ddm)
```

Validate the emitted declaration: `contour profile ddm validate out/app-settings.json`.
app.settings shipped in OS 27.0, so the released schema covers it — no `--beta`.

## Recipe 5.6: keep Santa and app.settings in agreement (`santa parity`)

Santa and a `com.apple.configuration.app.settings` declaration are **independent
gates** — a binary runs only when neither blocks it. `AllowedBinaries` is a
lockdown ("the device only allows binaries that match"), so Santa in lockdown
plus an app.settings allowlist means **every app must be admitted twice**, and
any drift between the two blocks it through whichever gate nobody was watching.

Prefer one gate owning the allowlist: Santa lockdown + app.settings
`DeniedBinaries` only, or app.settings `AllowedBinaries` + Santa in monitor
mode. When both must be allowlists, check them before every deploy:

```bash
contour santa parity rules.yaml --declaration app-settings.json
contour santa parity rules.yaml --declaration app-settings.json --santa-mode monitor
contour santa parity rules.yaml --declaration app-settings.json --json   # CI
```

Reports, and exits non-zero on any of:

| Finding | Meaning |
|---|---|
| Allowed by Santa, blocked by app.settings | only when app.settings is an allowlist |
| Allowed by app.settings, blocked by Santa | only when Santa is in lockdown/standalone |
| Cancelled by a deny on the other gate | a deny covering the *whole* allow |
| Santa rules app.settings cannot express | `BINARY` (SHA-256), `CERTIFICATE`, CEL |

Matching is **coverage, not equality**: a `{TeamID: X}` allow admits every
`SIGNINGID X:app` allow, so that is not drift. A narrow deny inside a broad
allow (deny one app from a team the other gate allows) is a carve-out, not a
contradiction. A CDHash is never assumed to belong to a TeamID — that needs
the binary.

`--santa-mode` defaults to `lockdown`, the strict case: in monitor mode Santa
blocks nothing, so an app.settings-only allow is harmless and is not reported.

## Recipe 6: CEL classification (Santa 2024.x+)

Common Expression Language gives you predicates over target metadata
without enumerating each binary. Santa evaluates predicates at execution
time against an `Activation` proto whose `target` field carries the
binary's codesigning + file info.

Workflow: define bundles in TOML → classify Fleet inventory against them:

```bash
contour santa cel fields --json                         # list available fields
contour santa cel check '<expression>' --json           # syntax-validate
contour santa cel eval '<expression>' \
    --field team_id=EQHXZ8M8AV --field path=/Applications/Chrome.app --json
contour santa cel classify bundles.toml \
    --input fleet.csv --json                            # batch classify
```

**CEL namespace is `target.*`** (verified against
`santa/Source/common/cel/Activation.{h,mm}` + `santa.proto`):

| Field | Source | Example |
|---|---|---|
| `target.team_id` | CodeSigning.team_id | `target.team_id == 'EQHXZ8M8AV'` |
| `target.signing_id` | CodeSigning.signing_id | `target.signing_id == 'team:com.example.app'` |
| `target.cdhash` | CodeSigning.cdhash (bytes) | `target.cdhash == b'...'` |
| `target.signing_time` | CodeSigning.signing_time (Timestamp) | `target.signing_time >= timestamp('2025-01-01T00:00:00Z')` |
| `target.secure_signing_time` | CodeSigning.secure_signing_time (Timestamp) | same as above |
| `target.is_platform_binary` | derived (Apple-signed system binary) | `!target.is_platform_binary` |
| `target.path` | FileInfo.path | `target.path.startsWith('/Applications/')` |
| `target.hash` | FileInfo.hash.hash (sha256 hex) | `target.hash == '7227c5b9...'` |

Real Santa-tested expressions (from `Test.mm`):
```cel
target.team_id == 'EQHXZ8M8AV'
target.signing_time >= timestamp('2025-05-28T12:00:00Z')
!target.is_platform_binary
!target.is_platform_binary && target.team_id == 'EQHXZ8M8AV'
```

**Operators (CEL spec, also exercised in Santa upstream):** `has()`,
`startsWith()`, `endsWith()`, `contains()`, `matches()`, `size()`,
`timestamp()`, `&&`, `||`, `!`, `==`, `!=`, `<`, `>`, `<=`, `>=`, `in`.

> **Note**: contour's `santa cel fields --json` is the source of truth
> for the field list contour ships with — Santa upstream may add fields
> faster than contour mirrors them. Always cross-check before using a
> field in a contour-generated rule.

---

## Rule-management cookbook

Once you have a rules CSV, contour ships small subcommands for routine
edits — meant to be scripted, idempotent, and CI-friendly:

```bash
contour santa add --file rules.csv --teamid <TEAM_ID>  # add one rule
contour santa remove --file rules.csv <rule>        # remove one rule
contour santa filter rules.csv --rule-type team-id  # filter by type
contour santa validate rules.csv --json             # validate (CI gate)
contour santa stats rules.csv                       # rule counts per category
contour santa snip --source rules.csv --dest extracted.csv --identifier <pattern>
```

`validate --json` is the canonical pre-commit check (see `--sop precommit`
for hook wiring).

---

## Output formats

| Flag | Use case |
|---|---|
| `--format mobileconfig` (default) | Standard signed-or-unsigned profile |
| `--format plist` | Raw payload dict (for Workspace ONE) |
| `--format plist-full` | Full profile as plist, no XML envelope |

To sign a generated profile:

```bash
contour profile sign <file> --identity "Developer ID Application: ..."
```

---

## Why this SOP isn't procedural

The procedural format (used by `--sop profile`, `--sop ddm`, etc.)
shines when there's one canonical procedure and the failure modes are
explicit. Santa's surface is a **fan-out** — different goals call for
different recipes, with no single "the procedure" to enforce. A
decision tree at the top + named recipes is the right shape for this
content.

Common Santa errors (rule-type collisions, missing TeamID prefixes,
CEL syntax) are caught by `contour santa validate --json` and surfaced
via the standard error envelope (`success`, `error`, `error_code`),
which the rule-management cookbook above wires into.
