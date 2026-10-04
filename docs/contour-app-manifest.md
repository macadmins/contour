# `contour app manifest`

App code identities as a first-class artifact, for tools that cannot run
`codesign` — a CI job, a web composer, a Linux host.

```
contour app manifest [PATHS…] [-o FILE|STEM] [--format auto|json|parquet]
```

Scans `.app` bundles (default `/Applications`) and records, for each, what
`codesign` and `Info.plist` say. Nothing is reconstructed from a template:
the designated requirement encodes the certificate chain, and only 19 of 55
locally scanned apps reconstruct from the Developer ID template — a
synthesised requirement produces a declaration that reports Verified and
manages nothing.

| Field | Source |
|---|---|
| `bundle_id`, `name`, `version`, `build` | `Info.plist` |
| `signing_id`, `team_id` (`*APPLE*` for platform binaries) | `codesign -dvvv` |
| `signing_state` | classified from the leaf `Authority=` only: `DeveloperID`, `AppStore`, `TestFlight`, `Enterprise`, `Apple`, `adhoc`, or `unknown` — never the nearest guess; `leaf_authority` is beside it |
| `cdhash` | one per architecture slice, keyed as `codesign` names them |
| `designated_requirement` | `codesign -d -r-`, byte for byte |
| `provenance` | always `observed` — so a merge with another source can tell read from reconstructed |

**Two tables, two lifetimes.** Identity (signing id × team id × requirement)
is stable across an app's builds; the CDHash changes with every release.
JSON carries both nested. `--format parquet` — or `--format auto` above 2,000
apps with `-o` — writes the pair `<stem>.identity.parquet` (one row per app)
and `<stem>.builds.parquet` (one row per slice).

**One unreadable bundle costs one entry in `failed[]`**, named with its
reason; the scan succeeds.

```bash
contour app manifest                                  # summary table of /Applications
contour app manifest -o apps.json                     # full manifest
contour --json app manifest /Applications /System/Applications
contour app manifest /Applications -o fleet --format parquet   # fleet.identity.parquet + fleet.builds.parquet
```
