# SOP: Santa Allowlist Generation

Santa is allowlist-driven endpoint security for macOS. The CLI surface
fans out across discovery (scan, fetch), classification (CEL, bundles),
generation (allow, rings, fleet), and rule management (add, remove,
filter, validate). This SOP is **not** a single procedure — it's a
**decision tree** that points you at the right recipe for the goal,
plus six cookbook recipes that work end-to-end.

If you came here to migrate a profile or wire a DDM declaration, this
isn't your SOP. Try `--sop profile`, `--sop ddm`, or `--sop precommit`.

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
├─ I want staged rollouts (Ring 1 canary → Ring 5 production)
│  → Recipe 3: Ring-based deployment
│
├─ I want a complete Fleet GitOps directory with rings + labels
│  → Recipe 4: Fleet GitOps fragment
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

Single-machine workflow — no Fleet, no rings, just "what's on this Mac
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

## Recipe 3: Ring-based deployment (editions)

Each ring profile is a self-contained **edition** — core rules merged with
that ring's specialized rules into one complete allowlist. Hosts receive
exactly one edition, scoped by Fleet labels. Santa does not layer overlapping
mobileconfigs cleanly on a single host, so editions ship whole and are never
stacked. The primary workflow: scaffold a ring config, customize it, then
generate editions.

```bash
# 1. Scaffold the ring shape (names, priorities, fleet labels)
contour santa rings init --num-rings 5 -o rings.yaml

# 2. (Optional) edit rings.yaml to customize descriptions / labels
$EDITOR rings.yaml

# 3. Generate the editions from your rules + the ring config
contour santa rings generate <rules> \
    --org com.yourco --prefix santa --rings-config rings.yaml -o rings/
```

If you don't need to customize, the shorthand skips `rings.yaml`:

```bash
contour santa rings generate <rules> \
    --org com.yourco --prefix santa --num-rings 5 -o rings/
```

`--num-rings` accepts `1..=16` (5 and 7 use built-in templates).

Output filenames follow `{prefix}{ring}{category}`:

| Ring | Software | CEL | FAA |
|---|---|---|---|
| 1 (canary) | `santa1a.mobileconfig` | `santa1b.mobileconfig` | `santa1c.mobileconfig` |
| 2 | `santa2a.mobileconfig` | `santa2b.mobileconfig` | `santa2c.mobileconfig` |
| ... | | | |
| 5 (production) | `santa5a.mobileconfig` | `santa5b.mobileconfig` | `santa5c.mobileconfig` |

Categories are auto-detected from rule type:
- **`a`** — Software rules (TeamID, SigningID, Binary, Certificate)
- **`b`** — CEL rules (Common Expression Language, Santa 2024.x+)
- **`c`** — FAA rules (File Access Authorization)

Pass `--max-rules N` to split large editions: `santa1a-001`, `santa1a-002`, …
Without it, editions are not split.

**Assigning content to editions.** Each rule's `rings:` field declares which
editions include it. An empty (or omitted) `rings:` means the rule is **core**
— it ships in every edition.

```yaml
- rule_type: TEAMID
  identifier: EQHXZ8M8AV
  policy: ALLOWLIST
  # core (no `rings:` field)

- rule_type: TEAMID
  identifier: ABC1234567
  policy: ALLOWLIST
  rings: [ring0]          # canary only

- rule_type: SIGNINGID
  identifier: team:com.example.tool
  policy: ALLOWLIST
  rings: [ring0, ring1]   # canary + pilot
```

A rule that references a ring name not in the active config triggers a
warning so typos don't silently vanish from every edition. Add `--strict` to
turn that warning into a hard error in CI:

```bash
contour santa rings generate <rules> --rings-config rings.yaml --strict -o rings/
```

## Recipe 4: Fleet GitOps fragment

The full pipeline: rules → ring editions → labels → fleet YAML, all
laid out as a Fleet v4.83 directory tree. `santa fleet` accepts the same
ring-config flags as `rings generate` (`--rings-config`, `--max-rules`,
`--strict`) — same edition model, same rule-side `rings:` annotations.

```bash
contour santa fleet <rules> \
    --org com.yourco \
    --team Workstations \
    --rings-config rings.yaml \
    --prefix santa \
    -o fleet-output/
```

Output layout:

```
fleet-output/
├── fleets/
│   └── Workstations.yml         # fleet YAML with profile references
├── platforms/
│   └── macos/
│       └── configuration-profiles/
│           ├── santa1a.mobileconfig
│           └── ...
└── labels/
    ├── santa-ring-0.labels.yml   # ring-targeting labels
    └── santa-ring-1.labels.yml
```

For adding to an existing Fleet repo without overwriting `default.yml`,
use **fragment mode**:

```bash
contour santa fleet <rules> --fragment --org com.yourco -o fragment/
# Output: fragment.toml + platforms/ subtree, ready to merge into v4.83
```

## Recipe 5: Fetch rules from external sources

```bash
contour santa fetch osquery <json>          # osquery santa_rules table
contour santa fetch mobileconfig <file>     # extract from existing profile
contour santa fetch santactl <output>       # `santactl fileinfo` output
contour santa fetch installomator <labels>  # Installomator TeamIDs
contour santa fetch fleet-csv <csv>         # Fleet software CSV export
```

Each emits a normalized rules CSV/JSON you can hand to Recipes 2–4.

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
contour santa add --file rules.csv <rule>           # add one rule
contour santa remove --file rules.csv <rule>        # remove one rule
contour santa filter rules.csv --type team-id       # filter by type
contour santa validate rules.csv --json             # validate (CI gate)
contour santa stats rules.csv                       # rule counts per category
contour santa snip rules.csv -o extracted.csv --match <pattern>
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
