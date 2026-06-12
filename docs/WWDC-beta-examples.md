# WWDC beta examples — OS 27 DDM with contour

A practical, copy-paste guide to **list, inspect, generate, and validate** Apple's
pre-release OS 27 ("WWDC seed") DDM declarations with contour — and the same moves
for the **common, already-shipping** declarations.

Everything beta lives behind one opt-in flag: **`--beta`**. The beta channel is a
strict *superset* of stable and is isolated by construction — seed-only types are
invisible to (and rejected by) the stable channel, so you never ship a pre-release
key by accident. For the procedural detail see `contour help-ai --sop beta` and
`contour help-ai --sop generative`.

> **Org domain:** every generate needs one (`--org com.acme`, or `export
> CONTOUR_ORG=com.acme`, or `.contour/config.toml`). contour never falls back to
> `com.example`. The examples below assume `export CONTOUR_ORG=com.acme`.

---

## 0. Which seed am I building against?

```bash
contour profile info
#   Apple device-management: 67045e2 (2026-03-25)
#   Apple seed (--beta):     1548d42 (seed_OS_27_0, 2026-06-08)   ← the embedded seed
```

If the "Apple seed" line is absent, the embedded data has no seed pinned and
`--beta` adds nothing — you're between an OS GA and the next seed.

---

## 1. List — what's available

```bash
# Common (stable) declaration types:
contour profile ddm list

# Beta channel — same list PLUS the OS 27 seed additions:
contour profile ddm list --beta

# See just what the seed adds (the delta), as JSON:
diff \
  <(contour profile ddm list --json       | jq -r '.[].type' | sort) \
  <(contour profile ddm list --beta --json | jq -r '.[].type' | sort) \
  | grep '^>'
```

The OS 27 seed adds, among others:
`app.settings`, `intelligence.settings`, `external-intelligence.settings`,
`content-cache.settings`, `extensible-sso`, `safari.settings` (new Privacy keys),
and the whole `network.*` family (`network.relay`, `network.dns-proxy`,
`network.dns-settings`, `network.vpn.{ikev2,ipsec,always-on,vpn-plugin}`).

---

## 2. Show — inspect a type's schema

```bash
# Common:
contour profile ddm info passcode.settings --json

# Beta seed type:
contour profile ddm info app.settings --beta
contour profile ddm info network.vpn.ikev2 --beta --json
```

**Tip — use the full type for names that are a substring of another type.**
`intelligence.settings` is contained in `external-intelligence.settings`; the
short-name resolver matches at dot boundaries (so `intelligence.settings` is
correct), but when in doubt the full type is unambiguous:

```bash
contour profile ddm info com.apple.configuration.intelligence.settings --beta
```

---

## 3. Generate — the OS 27 generative / Apple Intelligence features

`ddm generate <type> [--full] [--payload values.json]`. `--full` emits every
optional key; `--payload` merges your values over the schema skeleton. Generation
is **fail-closed** — a schema-invalid result is never written.

### 3a. Apple Intelligence policy (`intelligence.settings`)

```bash
cat > intel.json <<'JSON'
{
  "AllowGenmoji": false,
  "AllowImagePlayground": false,
  "AllowWritingTools": true,
  "ForceOnDeviceOnlyDictation": true,
  "Apps": {
    "Calendar": { "AllowNaturalLanguageEditing": false },
    "Mail":     { "AllowSmartReplies": true }
  }
}
JSON

contour profile ddm generate com.apple.configuration.intelligence.settings \
    --beta --payload intel.json -o intelligence.settings.json
```

### 3b. Third-party AI gating (`external-intelligence.settings`)

```bash
cat > extintel.json <<'JSON'
{ "Enabled": true, "AllowSignIn": false,
  "AllowedWorkspaceIDs": ["acme-prod-workspace", "acme-research"] }
JSON

contour profile ddm generate com.apple.configuration.external-intelligence.settings \
    --beta --payload extintel.json -o external-intelligence.settings.json
```

### 3c. Binary execution control (`app.settings`) — populate with REAL apps

Use contour's **Santa → app.settings bridge** rather than hand-writing identifiers;
it enforces the schema's per-list rules (`AllowedBinaries` ⇒ CDHash|TeamID,
`DeniedBinaries` ⇒ CDHash|TeamID|SigningID).

```bash
# From existing Santa rules:
cat > rules.json <<'JSON'
[
  {"rule_type":"TEAMID","policy":"ALLOWLIST","identifier":"EQHXZ8M8AV","description":"Google"},
  {"rule_type":"TEAMID","policy":"ALLOWLIST","identifier":"2BUA8C4S2C","description":"1Password"},
  {"rule_type":"SIGNINGID","policy":"BLOCKLIST","identifier":"BJ4HAAB9B3:us.zoom.xos","description":"Block Zoom"}
]
JSON
contour santa app-settings rules.json --from-rules --org com.acme -o app.settings.json

# …or from a live scan of installed apps (needs Santa's santactl):
#   contour santa scan ... > scan.csv
#   contour santa app-settings scan.csv --org com.acme -o app.settings.json
# …add per-app privacy defaults (Camera/Mic/Location):
#   contour santa app-settings scan.csv --scaffold -o app-permissions.toml   # edit, then:
#   contour santa app-settings scan.csv --permissions app-permissions.toml --org com.acme -o app.settings.json
```

> `DeniedBinaries` under Endpoint Security **terminates running processes**, not just
> future launches. Stage deny rules through a rollout cohort before fleet-wide.

### 3d. Other new seed configs

```bash
contour profile ddm generate com.apple.configuration.safari.settings        --beta --full -o safari.settings.json
contour profile ddm generate com.apple.configuration.content-cache.settings --beta --full -o content-cache.settings.json
contour profile ddm generate com.apple.configuration.network.relay          --beta --full -o network.relay.json
```

---

## 4. Validate — and prove channel isolation

```bash
# Validate a whole directory (or a single file) against the seed schema:
contour profile ddm validate . --beta
#   ✓ intelligence.settings.json is valid
#   Summary: N valid, 0 invalid out of N files

# Channel isolation: the SAME file on the stable channel is rejected — a seed-only
# type is "unknown" without --beta. This is the guardrail, not an error to fix:
contour profile ddm validate app.settings.json
#   error: Unknown declaration type … (re-run with --beta)
```

---

## 5. The "common" (stable) path — same moves, no `--beta`

Everything above works for already-shipping declarations by dropping `--beta`:

```bash
# Discover → inspect → generate → validate a stable passcode declaration:
contour profile ddm search passcode --json
contour profile ddm info  passcode.settings --json
contour profile ddm generate passcode.settings --full --org com.acme -o passcode.settings.json
contour profile ddm validate passcode.settings.json
```

For multi-component setups (asset + configuration + activation with cross-references),
author a bundle TOML and use **compose** — it wires identifiers and references by
construction and is fail-closed:

```bash
contour profile ddm compose bundle.toml -o out/ --json
contour profile ddm verify  out/ --json          # cross-reference + predicate check
```

See `contour help-ai --sop ddm` for the bundle format and the dependency DAG.

Beyond DDM, the common toolkits are unchanged:

```bash
contour profile generate <payload-type> --full --org com.acme -o profile.mobileconfig
contour profile normalize ./profiles -r --org com.acme --name "Acme Corp" --report normalize.md
```

---

## 6. Beta also covers Setup Assistant skip keys

```bash
contour profile enrollment list --platform macOS --beta        # incl. OS 27 keys (e.g. LiquidGlass)
contour profile enrollment generate --platform macOS --beta --skip LiquidGlass -o enroll.json
```
Without `--beta`, a seed-only key is rejected as unknown — same isolation as DDM.

---

## Practical tips

- **`--beta` is opt-in and rolling.** It always means *the current seed*; when that
  OS ships, its payloads graduate to stable and `--beta` is no longer required.
  Check `contour profile info` for the live pin.
- **Use the full `com.apple.configuration.*` type** for any short name that is a
  substring of another type (`intelligence.settings`); it's unambiguous.
- **`--full` to explore, `--payload` to author.** `--full` surfaces every optional
  knob; `--payload` merges only what you mean to set.
- **Always validate**, and validate against the **same channel** you generated with.
- **Beta is pre-release.** It validates against the current seed, but the seed can
  change before GA — author ahead, don't ship to production fleets as final.
- **`--json` everywhere** for CI and agents.
