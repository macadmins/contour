# SOP: mSCP → osquery Bridge

This SOP covers turning mSCP macOS security rules into **osquery detection**
— native-table queries where an osquery table can answer the check directly,
and an audit-script → results-plist fallback for everything else. It is the
companion to `--sop mscp` (which generates the *enforcement* artifacts:
mobileconfigs, scripts, labels); this SOP is about *detection / monitoring*.

The bridge is vendor-neutral: it emits either a Fleet `policies.yml` (default)
or a portable osquery **query pack** JSON, plus a coverage report. No
per-baseline code — every rule is classified the same way, so any baseline
(`cis_lvl1`, `disa_stig`, `800-53r5_high`, …) works.

## When to use

Activate this SOP when the user wants to **monitor** mSCP compliance with
osquery rather than (or in addition to) enforcing it with profiles:

- "Turn this STIG baseline into Fleet policies / osquery checks"
- "Which mSCP rules can osquery detect natively vs. need a script?"
- "Generate a vendor-neutral osquery pack for CIS Level 1"
- "Audit compliance on-device and read the results back through osquery"

For *enforcement* (deploying the settings) stay in `--sop mscp`. For raw
osquery table/column lookup and idiomatic query patterns, use `--sop osquery`.

---

## The two-tier model

Every rule lands in exactly one tier:

| Tier | Mechanism | When |
|---|---|---|
| **Tier-1 (native)** | a real osquery table query (`managed_policies`, `sharing_preferences`, `launchd_overrides`, `plist`, `disk_encryption`, `sip_config`, `gatekeeper`, `alf`, `nvram`) | the check maps cleanly to a table column |
| **Tier-2 (residual)** | an on-device **audit script** writes a boolean per rule into a **results plist**; osquery's `plist` table reads it back | no native table can answer the check exactly |
| Excluded | not emitted at all | mSCP helper rules (e.g. `supplemental_*`), not real checks |

**Native first, script only for the residual.** Tier-1 is always preferred:
it queries live host state directly, with no script, no plist, no launchd job
to schedule. The audit script exists only to cover the rules no table can
express. This keeps the on-device surface minimal and the data fresh — a
1,000-line audit script that re-implements checks osquery already does
natively is the anti-pattern this design avoids.

### Why a rule falls to Tier-2

- Its `mobileconfig_info` contains an **array** value (`managed_policies`
  can only match scalar key/value pairs exactly — array membership can't be
  asserted in one row, so it goes residual).
- Its check is an arbitrary shell pipeline with no corresponding table.
- Its native table exists but the specific column/label can't be derived
  cleanly from the rule (the builder returns `None` → residual).

---

## Invocation

The bridge rides on the standard `mscp generate` run via `--osquery`:

```bash
contour mscp generate \
  -m <mscp-repo> -k <baseline> -o <out> \
  --fleet-mode --osquery \
  [--osquery-format fleet|pack] \
  [--osquery-audit slim|full] \
  --org <ORG_DOMAIN>
```

| Flag | Default | Meaning |
|---|---|---|
| `--osquery` | off | emit the osquery bridge artifacts |
| `--osquery-format` | `fleet` | `fleet` → `<baseline>.policies.yml`; `pack` → `<baseline>.pack.json` (vendor-neutral) |
| `--osquery-audit` | `slim` | `slim` → audit script covers **residual only** (Tier-1 uses native queries); `full` → audit script covers **all** rules, every policy reads the plist |
| `--org` | (required) | reverse-domain org; see below |

`--osquery` **requires a resolvable org** (`--org` flag → `CONTOUR_ORG` env
var → `.contour/config.toml`). Without one it errors:
`--osquery requires an organization domain`. The org is woven into the
results-plist path and the launchd label, so it can't default to
`com.example`. In CI, set `CONTOUR_ORG` as a repository variable.

### Examples

```bash
# Fleet policies for a STIG baseline (native queries + slim audit script)
contour mscp generate -m ./macos_security -k disa_stig -o out \
  --fleet-mode --osquery --org com.acme

# Vendor-neutral osquery pack, CIS Level 1
contour mscp generate -m ./macos_security -k cis_lvl1 -o out \
  --fleet-mode --osquery --osquery-format pack --org com.acme

# Full audit (every rule goes through the script + plist; no native queries)
contour mscp generate -m ./macos_security -k disa_stig -o out \
  --fleet-mode --osquery --osquery-audit full --org com.acme
```

## Output

Written to `<out>/osquery/<baseline>/`:

| File | Purpose |
|---|---|
| `<baseline>.policies.yml` *or* `<baseline>.pack.json` | the detection queries (Fleet format or pack format) |
| `<baseline>-audit.sh` | the Tier-2 audit script (slim or full) |
| `<org>.<baseline>.audit.launchd.plist` | LaunchDaemon that runs the audit script on a schedule |
| `<baseline>.osquery-coverage.md` | per-rule coverage matrix + Tier-1/Tier-2/Excluded counts |

---

## The results-plist contract

Tier-2 rules are detected indirectly:

1. The **audit script** (`<baseline>-audit.sh`) runs each residual rule's
   check on-device and writes a boolean per rule into a results plist:
   `/Library/Preferences/<org>.<baseline>.audit.plist`, keyed by `rule_id`
   (`-bool true` = compliant). It clears the plist at the top of each run so
   stale results never linger.
2. The **launchd plist** (`<org>.<baseline>.audit.launchd.plist`) schedules
   the script. Install it to `/Library/LaunchDaemons/`, install the script
   to the path the launchd `ProgramArguments` points at (`/usr/local/bin/<baseline>-audit.sh`
   by default), then `launchctl load` it. `RunAtLoad` is set and it re-runs
   on `StartInterval`.
3. The **detection query** for a residual rule reads the cached result via
   osquery's `plist` table:
   `SELECT 1 FROM plist WHERE path = '<plist>' AND key = '<rule_id>' AND value = 'true'`
   — one row = compliant (osquery policy convention: a row means pass).

So Tier-2 is: **script writes → plist caches → osquery reads.** The launchd
cadence, not the policy query, governs freshness for residual rules. Tier-1
rules have no such indirection — they query live state every run.

## Reading the coverage report

`<baseline>.osquery-coverage.md` is the first thing to inspect after a run.
The header gives the split:

```
Tier-1 native: 142 (38%)
Tier-2 script:  201 (54%)
Excluded:       30
```

followed by a `| rule | tier | table | reason |` matrix. Use it to:

- **Verify the native ratio is sane.** A baseline that lands almost entirely
  in Tier-2 usually means a classification gap, not reality — check the
  `reason` column for rules you expected to be native.
- **Audit which table each rule uses** before trusting the queries.
- **Triage the residual set** — these are the rules whose freshness depends
  on the launchd schedule, so they're the ones to spot-check on-device.

---

## fleet vs. pack (vendor-neutral)

- **`fleet`** (default) emits `<baseline>.policies.yml` in Fleet's policy
  shape (reusing contour's existing `FleetPolicy` model). Drop it into a
  Fleet GitOps repo's `platforms/macos/policies/`. See `--sop fleet-migrate`
  for the canonical tree.
- **`pack`** emits `<baseline>.pack.json`, a standard osquery **query pack**
  (`{ "queries": { "<rule_id>": { query, interval, platform, description } } }`).
  This is the vendor-neutral form — load it into any osquery deployment
  (osquery itself, Kolide, FleetDM, a SIEM's osquery agent) that consumes
  query packs. Choose `pack` when the consumer is not Fleet, or when you want
  the detection logic decoupled from a specific MDM.

Both formats carry the *same* queries (native Tier-1 SQL + Tier-2 plist
reads); only the wrapper differs.

---

## Hard rules (don't drop these)

- **`--osquery` requires an org.** Never let it fall back to `com.example` —
  the org is baked into the results-plist path and launchd label.
- **`--osquery` requires `--org` and a non-Jamf run.** The bridge gate is
  `is_fleet_output && !is_jamf_mode`, and the output structure defaults to
  Pluggable, so `--osquery` runs without `--fleet-mode` as long as you are not
  in Jamf mode. `--fleet-mode` selects the Fleet GitOps layout — use it when you
  want the Fleet-shaped output, but it is not what enables the bridge.
- **Native first.** Prefer `--osquery-audit slim` (the default) so Tier-1
  rules stay as live native queries; only reach for `full` when you
  deliberately want every rule to flow through the on-device audit plist
  (e.g. a single uniform collection path for an air-gapped fleet).
- **Install all three Tier-2 pieces** — the script, the launchd plist, AND
  the policies/pack — or residual queries will read a plist that never gets
  written, and every residual rule will report non-compliant.
- **A row means compliant.** Every emitted query (native or plist-read)
  returns ≥1 row when the host passes — the standard osquery policy
  convention. Don't invert it.

## Reference

- Classifier + table catalog: `crates/mscp/src/osquery/classify.rs`,
  `catalog.rs`
- Audit script + results-plist contract: `crates/mscp/src/osquery/audit_script.rs`
- Coverage report: `crates/mscp/src/osquery/report.rs`
- Adapters: `crates/mscp/src/osquery/adapters/{fleet,pack}.rs`
- Related SOPs: `--sop mscp` (enforcement), `--sop osquery` (table lookup +
  query patterns), `--sop fleet-migrate` (where `.policies.yml` lands)
