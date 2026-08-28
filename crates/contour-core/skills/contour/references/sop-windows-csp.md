# SOP: Windows CSP schema exploration

Contour embeds Microsoft's DDF v2 Windows CSP catalogue — 313 CSPs, 2,925
setting nodes — queryable offline via `--windows` on `profile search` and
`profile info`. This SOP covers **exploration only**: finding a CSP, reading
its keys, types, and allowed values.

**What contour does NOT do (yet):** generate Windows profiles. There is no
SyncML/XML output path. To author a deployable Windows profile from what you
find here, hand the key path and value to your Fleet GitOps Windows profile
(a `<Replace>` SyncML document) or your MDM's CSP editor. If a
`windows-csp-profile` skill is available in your environment, route
authoring there.

---

## Decision tree

```
What are you trying to do?
│
├─ Find which CSP controls a Windows feature (BitLocker, Defender, …)
│  → Recipe 1: Search
│
├─ Read a CSP's keys, types, enums, and Windows-version gates
│  → Recipe 2: Inspect
│
├─ Turn a CSP key into a deployable Windows profile
│  → Recipe 3: the SyncML authoring contract (manual — contour
│    emits no SyncML)
│
├─ Windows STIG compliance (rules, registry checks, Fleet policies)
│  → "Embedded STIG datasets" below — data embedded, no CLI yet
│
└─ Apple payloads, DDM, mobileconfig
   → Wrong SOP: drop --windows; see --sop profile / --sop ddm
```

---

## Recipe 1: Search

```bash
contour profile search bitlocker --windows
contour profile search defender --windows --json
```

Output columns worth reading:

- **Category** is `windows-csp` (a native CSP node) or `windows-admx`
  (an ADMX-backed Group Policy surfaced through the Policy CSP — same
  delivery mechanism, but values are policy-XML strings, not typed scalars).
- **Platforms** shows `Windows` — these entries never claim Apple support,
  and the Windows set never appears in a search without `--windows`.

## Recipe 2: Inspect

```bash
contour profile info BitLocker --windows          # top-level summary
contour profile info BitLocker --windows --full   # every node
contour profile info BitLocker --windows --json   # machine-readable
```

What the fields mean on the Windows side:

- `values:` on a field lists the **MSFT AllowedValues enumeration** — the
  only legal values for that node. Anything else is rejected by the CSP at
  apply time.
- `introduced:` carries a **Windows build version** (e.g. `10.0.15063` =
  Windows 10 1703), not a marketing version.
- `[required]` marks nodes the CSP expects on every operation.

## Recipe 3: From CSP node to Fleet SyncML (manual authoring contract)

Contour gives you the node and its legal values; the deployable artifact is
a SyncML fragment you author by hand (or via your MDM). The contract, per
Fleet's CSP guides (fleetdm.com/guides/creating-windows-csps):

```xml
<Replace>                                   <!-- Replace = modify; Add = new -->
  <Item>
    <Meta><Format xmlns="syncml:metinf">int</Format></Meta>
    <Target>
      <LocURI>./Device/Vendor/MSFT/Policy/Config/{Area}/{PolicyName}</LocURI>
    </Target>
    <Data>7</Data>
  </Item>
</Replace>
```

- **LocURI** = `./Device/Vendor/MSFT/` + the CSP path — `{Area}` is the
  CSP name from `profile search --windows`, `{PolicyName}` the field name
  from `profile info --windows`.
- **`<Format>` must match the field's type** from `info`: `int` for
  integers (and booleans as 0/1), `chr` for strings and every ADMX-backed
  policy. `chr` on an integer node is a classic silent failure.
- **`windows-admx` fields take a policy-XML body**, not a scalar:
  `<![CDATA[<enabled/><data id="..." value="..."/>]]>` — the legal `value`s
  are the field's `values:` list. If the device reports "success but result
  couldn't be verified", escape the XML (`&lt;enabled/&gt;`) instead of
  using CDATA.
- **Verify on-device**: applied values land in the registry under
  `HKLM\SOFTWARE\Microsoft\Provisioning\NodeCache\CSP` (Policy-CSP areas
  additionally under `PolicyManager\current` — not the Group Policy path
  Microsoft's docs show). Event log:
  `DeviceManagement-Enterprise-Diagnostics-Provider/Admin`.
- **Canary first.** Fleet's own guidance: roll authored or converted CSP
  profiles to a small test group before broad deployment.

Worked micro-example (Windows Update deadline, from Fleet's
custom-windows-updates guide): node
`./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineForQualityUpdates`,
format `int`, data `7` (days). Gotcha: deadline policies override legacy
`AllowAutoUpdate` when both exist.

## Embedded STIG datasets (windows-schema crate, no CLI yet)

The `windows-schema` crate embeds the Windows 11 STIG compliance corpus —
the Windows counterpart to mSCP, kept strictly separate from the Apple
datasets:

- `windows_rules` — 258 STIG rules (severity, CCI tags, check/fix flags)
- `stig_registry_checks` — 122 registry checks, each with a **generated
  osquery query** (drop-in Fleet compliance policies)
- `fleet_stigs` — 836 Fleet-deployable policies pairing a CSP OMA-URI +
  ready SyncML enforcement fragment with an `mdm_bridge` compliance query;
  `enforcement_status` marks each as generated / blocked / unmapped

No CLI surface reads these yet — agents reach them through the crate's
readers. A query/export command is the documented roadmap.

## Data maturity — read this before trusting the output

Windows is new territory for contour, and the datasets are first-generation.
Known limits, stated plainly:

- **No field validation on device semantics.** Contour validates nothing
  about a SyncML doc you author — unlike the Apple path, there is no
  generate/validate loop. Cross-check every node against Microsoft's CSP
  documentation before deploying.
- **The data has already had one real defect**: an early build stamped 83%
  of CSP rows `platform: macOS`. It's fixed and pinned by a test, but treat
  it as the calibration point for how much to trust unreviewed corners.
- **DDF quirks pass through uncorrected** (case-duplicate CSP names,
  build-number version strings, `[required]` flags that reflect DDF
  metadata rather than practical deployment requirements).
- **Scope semantics are unmodeled**: `./Device/` vs `./User/` LocURI
  scoping exists in the CSP world but is not represented in the dataset.
- Expertise on this surface is thinner than on the Apple side — when
  contour's data and Microsoft's docs disagree, **Microsoft's docs win**;
  please report the mismatch.

---

## Traps

- **`--windows` and `--beta` are mutually exclusive** — the Windows dataset
  has no seed channel; clap rejects the combination.
- **Case-sensitive near-duplicates exist in the DDF itself** (`BitLocker`
  and `Bitlocker` are two distinct CSPs). Search is case-insensitive and
  shows both; `info` lookup is exact — copy the Payload Type verbatim from
  the search results.
- **`windows-admx` values are not scalars.** ADMX-backed policies take the
  `<enabled/>`/`<data …/>` policy-XML string format at deploy time; the
  schema here tells you the node path and that it exists, not the XML body.
- **No org domain involved.** Exploration is read-only; `--org` is neither
  needed nor consulted.

## Key flags

- `--windows` — query the Windows CSP dataset; default is the Apple schema.
- `--full` — expand every node (CSPs like `LocalPoliciesSecurityOptions`
  carry 80+).
- `--json` — structured output for CI/agents.
