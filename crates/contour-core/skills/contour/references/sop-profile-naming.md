# SOP: Profile Display-Name Naming

This SOP covers giving configuration profiles consistent, end-user-friendly
**display names** with `contour profile classify`, bootstrapping the naming map
with the scanner, and keeping `PayloadIdentifier`/UUIDs in sync afterward with
`contour profile reidentify`.

It is detection/cosmetics + identity hygiene, not enforcement. For generating
the profiles themselves, use `--sop profile`.

## When to use

- "Rename these profiles to a friendly, consistent scheme"
- "Make the display names readable in Settings → Profiles"
- "Bootstrap a naming map / name.toml for our profile set"
- "After hand-editing names, reshuffle the identifiers/UUIDs to match"

## The naming schema (built-in default)

Each profile is classified into one of three **scopes**, rendered with a
scope label and the payload **kind** + a **subject** detail:

| scope | when | format | example |
|---|---|---|---|
| **App** | every kind-contributing payload is app-config AND an app name is derivable | `App - {subject} ({kind})` | `App - OneDrive (Settings)` |
| **User** | envelope `PayloadScope == "User"` | `User - {kind} ({subject})` | `User - Restriction (Dock)` |
| **System** | otherwise (default) | `System - {kind} ({subject})` | `System - Network (Corp Wi-Fi)` |

App scope derives the app name from the payload: preference domain
(`ManagedClient.preferences`), `NotificationSettings[].BundleIdentifier`
(notifications), and TCC `Services.*[].Identifier` (privacy) — so all three of
`App - OneDrive (Settings | Notification | Privacy Control)` resolve to App scope.

The schema (formats, scope labels, kinds, subject rules, and the app-name
**matrix**) is contour's embedded default. Override it per-org with a
`name.toml` (TOML) or a YAML map — resolution: `--map <path>` →
`.contour/name.toml` → `.contour/naming.yaml` → embedded default.

### Tenant / site code knobs

When recovering a detail from an existing name, four lists control org-specific
tokens (whole-word, case-insensitive):

- `strip_leading_default` — leading scope/cluster words to drop (e.g. `System`, your tenant prefix).
- `strip_tokens_default` — tokens to remove wherever they appear (trailing/mid-name).
- `keep_trailing` — codes preserved and re-appended as a `… - {code}` **suffix** (e.g. a site code).
- `keep_leading` — codes preserved and re-prepended as a `{code} - …` **prefix** (e.g. a tenant/cluster code that should lead the name).

Keep org-internal codes in a **local** `.contour/name.toml` (gitignored), never in
a committed map.

## Procedure

```
1. SCAN to bootstrap the map (first time, or when adding new apps)
   contour profile classify <DIR> --recursive --emit-map name.toml
   → writes a full name.toml scaffold; every unmapped bundle id gets a
     best-guess name marked "# review" in [apps]. NOTHING falls back silently.

2. REVIEW name.toml — fix the "# review" guesses (the matrix is `id: Desired
   Name`, e.g.  "com.spotify.client" = "Spotify"). Keep org-internal app names
   in a LOCAL .contour/name.toml (gitignored), not in a committed map.

3. PREVIEW the rename (dry-run is the default — writes nothing)
   contour profile classify <DIR> --recursive --map name.toml
   → prints old → new for every profile; check the scope/subject look right.

4. APPLY
   contour profile classify <DIR> --recursive --map name.toml --write
   → rewrites PayloadDisplayName. Signed profiles are skipped (renaming breaks
     the signature — re-sign deliberately). Idempotent: re-running = 0 changes.

5. (optional) MANUAL ROUND — hand-tweak any final display names.

6. RESHUFFLE IDENTITY to match the final names (needs --org)
   contour profile reidentify <DIR> --recursive --scheme name --org <ORG>          # dry-run
   contour profile reidentify <DIR> --recursive --scheme name --org <ORG> --write
   → re-derives PayloadIdentifier from the display name ({org}.profile.{slug}),
     regenerates UUIDs deterministically, and remaps intra-profile references.
```

Shortcut: `classify --write --sync-identity --org <ORG>` fuses steps 4 + 6 in one
pass (use only when there is NO manual round between rename and reidentify).

## Reidentify schemes

- `--scheme name` — identifier from the display name; **UUIDs regenerated** (the
  "reshuffle"). Use when names are final and identity should track names.
- `--scheme uuid` — identifier = `{org}.{existing-uuid}`; **UUIDs unchanged**. Use
  to fix identifiers while keeping stable UUIDs.

## Rules & cautions

- **Org required** for `reidentify --scheme name` / `classify --sync-identity`:
  `--org` → `CONTOUR_ORG` → `.contour/config.toml` → error. Never `com.example`.
- **A UUID reshuffle changes profile identity.** Fine for a GitOps repo *before*
  deployment; for already-deployed profiles new UUIDs = new profiles (a re-push).
- **Name uniqueness** — hand-edits can collide; classify has a collision guard,
  and reidentify trusts names are unique (it reports duplicate identifiers).
- **Orphan refs** (a UUID reference pointing outside the profile) are reported by
  reidentify → fix inter-profile links with `contour profile link`.
- **No proprietary data in committed maps.** The embedded/`reference/naming.yaml`
  matrix is public apps only; org-internal app names and tenant/cluster tokens
  live in a local, gitignored `.contour/name.toml` / `.contour/naming.yaml`.

## Status outcomes (classify report)

- `renamed` — a friendly name was produced and differs from the old one.
- `unchanged` / `unclassified` — no map payload matched; name left untouched.
- `app-unmapped` — classified, but an app fell back to its raw bundle id. Add the
  id to the `apps` matrix (or re-run `--emit-map`) to clear it.
