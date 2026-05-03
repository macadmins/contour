# SOP: Root3 Support App Profiles

Generate `nl.root3.support` profiles that brand and configure the
Root3 Support menu-bar app — links, branding assets, contact channels,
and any per-brand variants needed in multi-tenant environments.

The procedural half pins the contract for `contour support generate`.
The CLI also supports a wizard mode (no subcommand, walks the user
through brand setup) that is intentionally outside the procedural
format — wizards belong to humans, not agents.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/contour/tests/sop_traps_support.rs`

## ERROR-CODE ENUM

```
INVALID_FORMAT         support.toml is not valid TOML / corrupted
SCHEMA_VIOLATION       brand or asset key not registered
IO_ERROR               input/output path un-readable / un-writeable
                       (also: brand asset folder missing)
INVALID_ORG            org domain malformed
UNKNOWN                unmatched
```

Failure-path JSON envelope (since contour ≥0.2.1):

```json
{ "success": false, "error": "...", "error_code": "UNKNOWN" }
```

---

## PROCEDURE generate_support_profile(support_toml, output_dir, brand, fragment)

```
SCHEMA_SOURCE: Root3 Support app preferences schema
SCHEMA_TOOL:   contour support generate {support_toml} --dry-run --json

INPUT:
  support_toml : path to a populated support.toml config
  output_dir   : directory to write generated profiles
  brand        : optional — when set, emit a single profile for the
                 named brand only (multi-tenant repos)
  fragment     : bool — when true, emit a Fleet GitOps fragment

PRECONDITIONS:
  ASSERT support_toml exists AND is readable
    HALT "IO_ERROR: support.toml not found at {support_toml}"
  ASSERT parent(output_dir) exists OR can be created
    AUTO_FIX: mkdir -p {output_dir}

  # The wizard / `init` step scans a parent directory containing per-
  # brand subfolders (acme/, globex/, initech/, ...). If brand asset paths are
  # broken, the profile still generates but ships without icons.
  ASSERT every [[brands]].asset_path in support_toml resolves to an
         existing directory
    WARN "brand {b.name} asset path missing — profile will deploy \
          without branded icons. Fix or remove the brand entry."

STEP 1 — Dry-run to surface validation problems early:
  result = contour support generate {support_toml} --dry-run --json
  # Dry-run prints what WOULD be written without writing anything;
  # surfaces TOML parse / schema errors before any side effect.

  if result.exit_code != 0:
    HALT "{result.error_code}: {result.error}"

STEP 2 — Generate the profile(s):
  flags = ["-o", output_dir, "--json"]
  if brand:
    flags += ["--brand", brand]
  if fragment:
    flags += ["--fragment"]
  result = contour support generate {support_toml} {flags...}

  if result.exit_code != 0:
    HALT "{result.error_code}: {result.error}"

INVARIANTS:
  # The Root3 Support app reads its preferences from
  # `nl.root3.support`. Profiles MUST use that exact PayloadType — any
  # other value silently deploys a profile the app never reads.
  ASSERT every emitted .mobileconfig has a payload with
         PayloadType == "nl.root3.support"
    HALT "emitted profile has wrong PayloadType — not consumed by \
          the Root3 Support app. Likely a CLI regression."

STEP 3 — Verify the output:
  if fragment:
    ASSERT output_dir contains fragment.toml
      HALT "fragment mode did not produce fragment.toml"
    ASSERT output_dir contains platforms/macos/configuration-profiles/
      HALT "fragment missing platforms/macos/configuration-profiles/"
  else:
    written = list(output_dir, "*.mobileconfig")
    if brand:
      ASSERT len(written) == 1
        HALT "--brand {brand} should emit exactly one profile; \
              got {len(written)}"
    else:
      ASSERT len(written) >= 1
        HALT "no .mobileconfig emitted"

POSTCONDITIONS:
  RETURN {
    output_dir,
    brand,
    fragment,
    profile_count: len(written),
  }
```

---

## Other operations (prose recipes)

### Initialise from a brand-folder layout

```
contour support init <parent_dir> -o support.toml --json
# <parent_dir> contains per-brand subfolders (e.g. acme/, globex/, initech/).
# init walks them and writes [[brands]] entries with asset paths and
# detected names. Edit afterwards to set links, contact info, etc.
```

### Wizard mode (interactive, single-brand)

```
contour support --org com.acme -o support.mobileconfig
# Skips the TOML step entirely; walks the user through brand setup
# in a REPL and writes a single profile. Not for agents — the wizard
# expects a human at the keyboard.
```

---

## Key facts

- The Root3 Support app uses `nl.root3.support` as its preferences
  domain — the procedural INVARIANT above pins this so a CLI
  regression cannot silently change it.
- Multi-brand layouts (one profile per brand) are common when an MSP
  manages tenants under separate org identifiers; use
  `--brand <name>` to scope a single generation.
- Fragment mode (`--fragment`) is the recommended output for adding to
  a Fleet GitOps repo (v4.83 layout). It places `.mobileconfig` files
  under `platforms/macos/configuration-profiles/`.
- `support` is the simplest of the procedural-format SOPs — there is
  no scan/configure step, since brand assets and links are set by
  hand or via `init`.
