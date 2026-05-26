# contour Documentation

`contour` is a single binary bundling a family of Apple device-management
toolkits. Start with the umbrella guide, then the toolkit you need.

## Guides

| Doc | Covers |
|---|---|
| [contour-getting-started.md](contour-getting-started.md) | New here? Install, orientation, and three starter workflows |
| [contour.md](contour.md) | The umbrella binary — toolkit overview, `contour init`, `trainer`, `help-agents`, `completions`, and other standalone commands |
| [contour-profile.md](contour-profile.md) | Configuration profiles (`.mobileconfig`): normalize, validate, sign, import, generate, DDM, recipes, secrets, MDM variables |
| [contour-recipes.md](contour-recipes.md) | Recipes, DDM presets, and building a reusable profile/preset library |
| [contour-pppc.md](contour-pppc.md) | Privacy Preferences Policy Control (TCC) profiles |
| [contour-santa.md](contour-santa.md) | Santa allowlists and binary authorization |
| [contour-mscp.md](contour-mscp.md) | macOS Security Compliance Project baseline transformation |
| [contour-btm.md](contour-btm.md) | Background Task Management service profiles |
| [contour-notifications.md](contour-notifications.md) | Per-app notification settings profiles |
| [contour-support.md](contour-support.md) | Root3 Support App per-brand configuration profiles |
| [contour-osquery.md](contour-osquery.md) | Offline osquery schema reference (table/column lookup) |
| [contour-config.md](contour-config.md) | `.contour/config.toml` reference — the shared, cross-toolkit configuration |

## Examples

The [`examples/`](examples/) directory has runnable samples — a DDM
bundle and pre-commit validation hooks.

## Getting started

New to contour? Read **[contour-getting-started.md](contour-getting-started.md)** —
install, orientation, and three starter workflows. The short version:

```bash
# Create the shared project config
contour init --domain com.acme --name "Acme" --mdm fleet --yes

# Then use a toolkit — e.g. import and normalize profiles
contour profile import ~/vendor-profiles -o ./profiles --all
```
