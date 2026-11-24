# SOP: Latest Apple OS versions (SOFA lookup)

contour's embedded data knows which keys exist, not which OS shipped last
week. For current versions, builds, update product keys, betas and actively
exploited CVEs, look them up in SOFA, the Mac Admins community feed:

    https://sofafeed.macadmins.io/v2/summary.json

contour does not fetch it: the binary makes no network calls. You (the agent)
fetch it with your own web tool or `curl`, every time the answer matters.
Never answer "what is the latest macOS" from training data.

## PROCEDURE latest_os(platform?)

SCHEMA_SOURCE: SOFA summary feed (`SchemaVersion`, `GeneratedAt`,
`Platforms.<OS>.Majors[]`, `Betas`, `ExploitedCVEs`)

EXECUTION:

```bash
curl -sf https://sofafeed.macadmins.io/v2/summary.json | jq '{
  generated: .GeneratedAt,
  latest: (.Platforms | with_entries(.value = [.value.Majors[] | {
    major: .Major, name: .Name, version: .Latest.Version,
    released: .Latest.ReleaseDate, builds: [.Latest.Builds[]?.Build],
    priority: .Latest.Priority, exploited: .Latest.ExploitedCVEs,
    security_info: .Latest.SecurityInfoURL }])),
  betas: .Betas }'
```

Platforms: `macOS`, `iOS`, `tvOS`, `watchOS`, `visionOS`, `Safari`; one entry
per supported major, newest first.

POSTCONDITIONS:
- Fetch failed or not JSON: WARN "SOFA unavailable — versions not checked";
  say so to the person and do not guess a version.
- Quote `generated` with any version you report.
- `exploited` non-empty: WARN — say the update fixes an actively exploited
  CVE, and link `security_info` (Apple's own page) as the authority.

RETURN the versions, with `generated`.

## PROCEDURE update_product_keys(version)

macOS devices below 27.0 only. `ScheduleOSUpdate` names an update by
product key, and Apple removed it, with the other OS update commands, in
27.0: from 27.0 the declaration below is the only path.

```bash
curl -sf https://sofafeed.macadmins.io/v2/summary.json | jq -r --arg v 27.2.1 '
  .Platforms.macOS.Majors[] | .ProductKeys // {} | to_entries[]
  | .key as $k | .value[] | select(test("_\($v)_")) | "\($k)\t\(.)"'
```

- `Update` keys stay within a major (`…_minor`); `Upgrade` keys cross to a
  new major (`…_major`) and are listed under the older major.
- `patch` is the delta, `full` the whole installer; one key per build, and a
  version often has several builds (hardware-specific). Pick the build your
  fleet runs; ASK when unsure.

## Use the result

```bash
# DDM, the only path from 27.0: enforce a version by a deadline
contour profile ddm generate softwareupdate.enforcement.specific \
  --set TargetOSVersion=27.2.1 --set TargetLocalDateTime=2026-12-01T18:00:00 \
  --org com.acme -o enforce.json

# Devices below 27.0 only: install a specific update by product key
contour profile command generate ScheduleOSUpdate \
  --set 'Updates=[{"ProductKey":"MSU_UPDATE_26B131_patch_27.2.1_minor","InstallAction":"InstallASAP"}]' \
  -o update.plist
```

- From 27.0, `com.apple.SoftwareUpdate` and `AvailableOSUpdates`,
  `ScheduleOSUpdate`, `ScheduleOSUpdateScan`, `OSUpdateStatus` are gone: the
  dataset's `ddm_equivalent` names each replacement (`contour profile info
  <type> --json`). Status: subscribe to `softwareupdate.install-state`.
- Leave `TargetBuildVersion` out unless the person names a build: one
  version has several builds and a wrong one never installs.
- `--os-version <latest>` on `profile validate` / `form` checks keys against
  the version devices will run.
- `betas` versus `contour census`: when SOFA lists a newer seed than the
  binary's beta dataset, say `--beta` answers for the older seed.

## INVARIANTS

- SOFA is community data built from Apple's releases. When it and Apple's
  security page disagree, Apple's page wins; say so.
- The feed changes daily: look it up again rather than reuse an earlier
  answer from this session.
