# contour support -- Root3 Support App Profile Generator

> **Status: Preview** — feature-complete for core workflows, APIs and flags may still change before 1.0.

`contour support` generates configuration profiles for the Root3 Support
App (`nl.root3.support`) — the customizable macOS menu-bar support app.
It scans per-brand asset folders (logos, menu-bar icons), produces a
human-editable `support.toml`, and generates `.mobileconfig` profiles
that brand and configure the Support App for each of your organizations
or sub-brands.

Aimed at Mac admins — especially MSPs and multi-brand organizations —
who deploy the Root3 Support App and need consistent, per-brand
configuration profiles.

## Quick Start

```bash
# Interactive wizard — scan assets, configure, and generate in one go
contour support

# Or the explicit two-step flow
contour support init ./brand-assets -o support.toml
contour support generate support.toml -o ./profiles
```

## Workflow

`contour support` with no subcommand launches an interactive wizard that
walks scan → configure → generate. The explicit subcommands give the
same result in a scriptable, version-controllable form:

```
1. init      → support.toml        (scan brand asset folders, write config)
2. (edit)    → support.toml        (review / adjust common + per-brand settings)
3. generate  → *.mobileconfig      (produce MDM-ready profiles per brand)
```

## support.toml

`init` scans a parent directory of brand subfolders (e.g. `4Y/`, `LH/`,
`LX/`) — each holding that brand's logo, dark-mode logo, and menu-bar
icon — and writes a `support.toml` with a `[common]` section plus one
`[[brands]]` entry per folder. `[common]` settings (title, footer text,
error message, status-bar behavior, welcome screen, storage limit, …)
apply to every brand; any key set on a `[[brands]]` entry overrides the
common value for that brand.

## Commands

### `support init`

Scan brand asset folders and create a `support.toml` config.

```
contour support init <PATH> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATH>` | Parent directory containing brand subfolders | **required** |
| `-o, --output <PATH>` | Output config file path | `support.toml` |

```bash
contour support init ./brand-assets -o support.toml
```

### `support generate`

Generate Support App `.mobileconfig` profiles from a `support.toml`. For
each brand it emits a *discover* profile (full configuration with
embedded assets) and a *default* profile (minimal behavioral config).

```
contour support generate <CONFIG> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<CONFIG>` | Path to the `support.toml` config file | **required** |
| `-o, --output <DIR>` | Output directory | config file's directory |
| `--brand <NAME>` | Generate for a single brand only | all brands |
| `--fragment` | Generate a Fleet GitOps fragment directory | `false` |
| `--dry-run` | Preview what would be generated without writing files | `false` |

```bash
contour support generate support.toml -o ./profiles
contour support generate support.toml --brand LH --dry-run
```

## Output

For each brand, `generate` writes two profiles for the `nl.root3.support`
preference domain:

- `<brand>_nl.root3.support_discover.mobileconfig` — the full
  configuration, including the brand's logo and icon assets.
- `<brand>_default_nl.root3.support.mobileconfig` — a minimal
  behavioral profile, with no embedded assets.

With `--fragment`, the profiles are laid out as a Fleet GitOps fragment
directory ready to merge into a Fleet repository.
