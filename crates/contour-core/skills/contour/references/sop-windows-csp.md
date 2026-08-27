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
│  → Out of scope here — take Recipe 2's output to Fleet GitOps /
│    your MDM's SyncML surface
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
