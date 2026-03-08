# contour profile -- Configuration Profile Toolkit

`contour profile` is a CLI toolkit for managing Apple configuration profiles (`.mobileconfig`). It handles normalization, validation, signing, UUID management, payload inspection, and documentation generation for macOS fleets.

Aimed at Mac admins who manage profiles across MDM solutions, GitOps repositories, or local development workflows.

## Quick Start

```bash
# Set up a new project with org defaults
contour profile init --org com.yourorg --name "Your Org"

# Import vendor profiles from a directory
contour profile import ~/Downloads/vendor-profiles -o ./profiles

# Standardize everything (identifiers, UUIDs, filenames)
contour profile normalize ./profiles -r --org com.yourorg
```

## Configuration

### profile.toml

Created by `profile init`. Place it at the root of your profile project. Commands walk up the directory tree to find it.

```toml
[organization]
domain = "com.yourorg"       # Reverse domain (required)
name = "Your Org"            # Sets PayloadOrganization

[renaming]
scheme = "display-name"      # "identifier", "display-name", or "template"
template = "{org}-{type}-{name}"  # Only used with scheme = "template"

[uuid]
predictable = false          # Use deterministic v5 UUIDs
uppercase = true             # Uppercase UUID output

[output]
directory = "./output"       # Default output directory
unsigned_suffix = "-unsigned"

[processing]
validate_on_export = true
parallel_batch = true
max_threads = 4
```

### .contour/config.toml

Repo-level defaults (same schema as `profile.toml`). Shared across all contour subcommands.

### Precedence

CLI flags > `profile.toml` > `.contour/config.toml` > built-in defaults.

---

## Commands

### Getting Started

#### `profile info`

Show Profile CLI version, configuration, and schema statistics. Use this to verify your setup.

```
contour profile info [--json]
```

No additional flags. Displays the loaded `profile.toml` path, org domain, schema count, and version info.

```bash
contour profile info
```

#### `profile init`

Initialize a new `profile.toml` configuration file. Run this once at the root of your profile project.

```
contour profile init [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--org <DOMAIN>` | Organization reverse domain (e.g., `com.yourorg`) | interactive prompt |
| `--name <NAME>` | Organization name | interactive prompt |
| `-o, --output <PATH>` | Output file path | `./profile.toml` |
| `-f, --force` | Overwrite existing config | `false` |

```bash
contour profile init --org com.acme --name "Acme Corp" --force
```

---

### Import & Normalize

#### `profile import`

Import `.mobileconfig` files from a directory. Presents an interactive picker unless `--all` is used. Normalizes and optionally validates imported profiles.

```
contour profile import <SOURCE> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<SOURCE>` | Source directory containing `.mobileconfig` files | **required** |
| `-o, --output <DIR>` | Output directory for imported profiles | current directory |
| `--org <DOMAIN>` | Organization reverse domain | from `profile.toml` |
| `--name <NAME>` | Organization name (sets PayloadOrganization) | from `profile.toml` |
| `--all` | Import all profiles without interactive selection | `false` |
| `--no-validate` | Skip validation after normalization | `false` |
| `--no-uuid` | Skip UUID regeneration | `false` |
| `--max-depth <N>` | Maximum directory depth for recursive search | unlimited |
| `--dry-run` | Preview without writing files | `false` |

```bash
# Import vendor profiles, normalize with org identity
contour profile import ~/vendor-profiles -o ./profiles --org com.acme --all
```

#### `profile normalize`

Standardize identifiers, display names, filenames, and optionally UUIDs across one or more profiles. The core command for ensuring consistency.

```
contour profile normalize <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to normalize | **required** (unless `--pasteboard`) |
| `--pasteboard` | Read profile from macOS pasteboard | `false` |
| `-o, --output <PATH>` | Output file or directory | in-place |
| `--org <DOMAIN>` | Organization reverse domain | from `profile.toml` |
| `--name <NAME>` | Organization name (sets PayloadOrganization) | from `profile.toml` |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-validate` | Skip validation | `false` |
| `--no-uuid` | Skip UUID regeneration | `false` |
| `--no-parallel` | Disable parallel processing | `false` |
| `--dry-run` | Preview without writing files | `false` |

```bash
# Normalize all profiles in a directory tree
contour profile normalize ./profiles -r --org com.acme --name "Acme Corp"
```

#### `profile duplicate`

Clone a profile with a new identity -- new name, identifier, and UUIDs. Useful for creating variants (e.g., staging vs. production).

```
contour profile duplicate <SOURCE> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<SOURCE>` | Source `.mobileconfig` file | **required** |
| `--name <NAME>` | New PayloadDisplayName | interactive prompt |
| `-o, --output <PATH>` | Output file path | auto-generated |
| `--org <DOMAIN>` | Organization reverse domain | from `profile.toml` |
| `--predictable` | Use deterministic v5 UUIDs based on new identifier | `false` |
| `--dry-run` | Preview without writing files | `false` |

```bash
contour profile duplicate wifi-corp.mobileconfig --name "WiFi Guest" -o wifi-guest.mobileconfig
```

#### `profile uuid`

Regenerate UUIDs without changing other profile properties. Supports both random (v4) and predictable (v5) modes.

```
contour profile uuid <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to process | **required** |
| `-o, --output <PATH>` | Output file or directory | in-place |
| `--org <DOMAIN>` | Organization reverse domain (for predictable UUIDs) | from `profile.toml` |
| `-p, --predictable` | Generate deterministic v5 UUIDs | `false` |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |
| `--dry-run` | Preview without writing files | `false` |

```bash
# Regenerate UUIDs predictably for GitOps reproducibility
contour profile uuid ./profiles -r -p --org com.acme
```

---

### Inspect & Validate

#### `profile scan`

Preview profile metadata without modifying anything. Shows identifiers, UUIDs, payload types, and optionally simulates what normalize would change.

```
contour profile scan <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to scan | **required** |
| `--simulate` | Simulate normalize with configured domain | `false` |
| `--org <DOMAIN>` | Organization reverse domain for simulation | from `profile.toml` |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |

```bash
# Audit all profiles in a directory
contour profile scan ./profiles -r --json
```

#### `profile validate`

Validate profiles against Apple's payload schemas. Reports missing required keys, incorrect types, and unknown fields.

```
contour profile validate <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to validate | **required** |
| `--no-schema` | Skip schema-based validation of payload fields | `false` |
| `--schema-path <DIR>` | Path to external schema directory (ProfileManifests, Apple YAML) | embedded schemas |
| `--strict` | Treat warnings as errors | `false` |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |

```bash
# Strict validation against embedded Apple schemas
contour profile validate ./profiles -r --strict
```

#### `profile diff`

Compare two configuration profiles side-by-side. Shows added, removed, and changed keys across all payloads.

```
contour profile diff <FILE1> <FILE2> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE1>` | First configuration profile | **required** |
| `<FILE2>` | Second configuration profile | **required** |
| `-o, --output <PATH>` | Output diff to file | stdout |

```bash
contour profile diff baseline.mobileconfig updated.mobileconfig
```

#### `profile payload list`

List all payloads in a profile, showing type, display name, and UUID for each.

```
contour profile payload list <FILE>
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE>` | Path to the configuration profile | **required** |

```bash
contour profile payload list corp-settings.mobileconfig --json
```

#### `profile payload read`

Read a specific value from a payload by type and key.

```
contour profile payload read <FILE> --type <TYPE> --key <KEY> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE>` | Path to the configuration profile | **required** |
| `-t, --type <TYPE>` | Payload type (e.g., `wifi`, `com.apple.wifi.managed`) | **required** |
| `-k, --key <KEY>` | Key to read | **required** |
| `--index <N>` | Payload index if multiple of same type (0-based) | `0` |

```bash
contour profile payload read wifi.mobileconfig --type com.apple.wifi.managed --key SSID_STR
```

#### `profile payload extract`

Extract specific payload types from a profile into a new, standalone profile.

```
contour profile payload extract <FILE> --type <TYPE>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE>` | Path to the configuration profile | **required** |
| `-t, --type <TYPE>...` | Payload type(s) to extract | **required** |
| `-o, --output <PATH>` | Output file path | stdout |

```bash
# Extract just the VPN payload from a multi-payload profile
contour profile payload extract all-settings.mobileconfig --type com.apple.vpn.managed -o vpn-only.mobileconfig
```

---

### Signing

#### `profile identities`

List available signing identities (certificates) from your Keychain. Use to find the identity name or SHA-1 for `profile sign`.

```
contour profile identities [--json]
```

No additional flags.

```bash
contour profile identities
```

#### `profile sign`

Sign profiles with a Developer ID or MDM signing certificate.

```
contour profile sign <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to sign | **required** |
| `-o, --output <PATH>` | Output file or directory | in-place |
| `-i, --identity <ID>` | Signing identity (certificate name or SHA-1) | interactive prompt |
| `-k, --keychain <PATH>` | Keychain path | default keychain |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |
| `--dry-run` | Preview without writing files | `false` |

```bash
contour profile sign ./profiles -r -i "Developer ID Application: Acme Corp"
```

#### `profile verify`

Verify that a profile's signature is valid and the certificate chain is trusted.

```
contour profile verify <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to verify | **required** |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |

```bash
contour profile verify ./signed-profiles -r
```

#### `profile unsign`

Strip signatures from signed profiles, returning them to unsigned XML plist format. Useful before editing or re-normalizing.

```
contour profile unsign <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to unsign | **required** |
| `-o, --output <PATH>` | Output file or directory | in-place |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |
| `--dry-run` | Preview without writing files | `false` |

```bash
contour profile unsign vendor-signed.mobileconfig -o vendor-unsigned.mobileconfig
```

---

### Linking

#### `profile link`

Cross-reference UUIDs between profiles. When profiles reference each other (e.g., a certificate profile referenced by a WiFi profile), this command updates the UUID references to match. Optionally merges multiple profiles into one.

```
contour profile link <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | Profile file(s) or directory to link | **required** |
| `-o, --output <PATH>` | Output file (merged) or directory (separate) | in-place |
| `--org <DOMAIN>` | Organization reverse domain | from `profile.toml` |
| `-p, --predictable` | Generate deterministic v5 UUIDs | `false` |
| `--merge` | Merge all profiles into a single output profile | `false` |
| `--no-validate` | Skip validation of cross-references | `false` |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--dry-run` | Preview changes without writing files | `false` |

```bash
# Link cert + WiFi profiles and merge into one
contour profile link cert.mobileconfig wifi.mobileconfig --merge -o corp-wifi.mobileconfig
```

---

### Documentation Generation

#### `profile docs generate`

Generate markdown documentation from embedded payload schemas.

```
contour profile docs generate -o <DIR> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <DIR>` | Output directory | **required** |
| `--payload <TYPE>` | Specific payload type (generates one file) | all payloads |
| `-c, --category <CAT>` | Filter by category: `apple`, `apps`, `prefs` | all categories |

```bash
contour profile docs generate -o ./docs --category apple
```

#### `profile docs list`

List available payloads for documentation generation.

```
contour profile docs list [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --category <CAT>` | Filter by category: `apple`, `apps`, `prefs` | all categories |

```bash
contour profile docs list --category apps --json
```

#### `profile docs from-profile`

Generate documentation from an existing profile, showing which keys are configured vs. available.

```
contour profile docs from-profile <FILE> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<FILE>` | Path to the configuration profile | **required** |
| `-o, --output <PATH>` | Output file path | stdout |

```bash
contour profile docs from-profile wifi.mobileconfig -o wifi-docs.md
```

#### `profile docs ddm`

Generate markdown documentation for DDM declaration schemas.

```
contour profile docs ddm -o <DIR> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <DIR>` | Output directory | **required** |
| `--declaration <TYPE>` | Specific declaration type | all types |
| `-c, --category <CAT>` | Filter: `configuration`, `activation`, `asset`, `management` | all categories |

```bash
contour profile docs ddm -o ./ddm-docs --category configuration
```

---

### DDM (Declarative Device Management)

#### `profile ddm parse`

Parse and display DDM declaration JSON files. Shows the declaration type, identifier, and payload contents.

```
contour profile ddm parse <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | DDM JSON file(s) or directory | **required** |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |

```bash
contour profile ddm parse ./declarations -r --json
```

#### `profile ddm validate`

Validate DDM declarations against Apple's device-management schemas.

```
contour profile ddm validate <PATHS>... [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<PATHS>...` | DDM JSON file(s) or directory | **required** |
| `-p, --schema-path <DIR>` | Path to Apple device-management repo | embedded schemas |
| `-r, --recursive` | Process directories recursively | `false` |
| `--max-depth <N>` | Maximum directory depth (requires `--recursive`) | unlimited |
| `--no-parallel` | Disable parallel processing | `false` |

```bash
contour profile ddm validate ./declarations -r
```

#### `profile ddm list`

List available DDM declaration types (42 embedded).

```
contour profile ddm list [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --category <CAT>` | Filter: `configuration`, `activation`, `asset`, `management` | all types |
| `-p, --schema-path <DIR>` | Path to external Apple device-management repo | embedded schemas |

```bash
contour profile ddm list --category configuration --json
```

#### `profile ddm info`

Show detailed schema information for a specific DDM declaration type.

```
contour profile ddm info <NAME> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<NAME>` | Declaration type name | **required** |
| `-p, --schema-path <DIR>` | Path to external Apple device-management repo | embedded schemas |

```bash
contour profile ddm info passcode.settings
```

#### `profile ddm generate`

Generate a DDM declaration JSON skeleton from the schema. Useful for bootstrapping new declarations.

```
contour profile ddm generate <NAME> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<NAME>` | Declaration type (e.g., `passcode.settings`) | **required** |
| `-o, --output <PATH>` | Output file path | stdout |
| `--full` | Include all fields, not just required | `false` |
| `-p, --schema-path <DIR>` | Path to external Apple device-management repo | embedded schemas |

```bash
contour profile ddm generate passcode.settings -o passcode.json --full
```

---

## Common Workflows

### Onboarding vendor profiles

Import profiles from a vendor, normalize to your org identity, validate, and sign:

```bash
contour profile import ~/Downloads/vendor/ -o ./profiles --org com.acme --all
contour profile validate ./profiles -r --strict
contour profile sign ./profiles -r -i "Developer ID Application: Acme Corp"
```

### GitOps-ready profiles

Initialize a project, normalize with predictable UUIDs for reproducible diffs, then commit:

```bash
contour profile init --org com.acme --name "Acme Corp"
contour profile normalize ./profiles -r
contour profile uuid ./profiles -r -p --org com.acme
git add profiles/ profile.toml && git commit -m "Normalize profiles"
```

### Audit a directory of profiles

Scan metadata and validate without modifying anything:

```bash
contour profile scan ./profiles -r --json > audit-scan.json
contour profile validate ./profiles -r --strict --json > audit-validate.json
```

### Split and merge payloads

Extract specific payloads from a multi-payload profile, then link and merge:

```bash
contour profile payload extract all-in-one.mobileconfig --type com.apple.wifi.managed -o wifi.mobileconfig
contour profile payload extract all-in-one.mobileconfig --type com.apple.security.pkcs12 -o cert.mobileconfig
contour profile link wifi.mobileconfig cert.mobileconfig --merge -o corp-wifi-bundle.mobileconfig
```

### Unsign, edit, re-sign

```bash
contour profile unsign signed.mobileconfig -o unsigned.mobileconfig
# Edit unsigned.mobileconfig in your editor
contour profile normalize unsigned.mobileconfig
contour profile sign unsigned.mobileconfig -i "Developer ID Application: Acme Corp" -o signed.mobileconfig
```

---

## Global Flags

These flags work with all commands:

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format (for CI/CD pipelines and scripting) |
| `-v, --verbose` | Enable verbose logging |
| `--version` | Show version, build timestamp, and license |
| `--help` | Show help for any command |

## Output Modes

- **Human** (default) -- Formatted tables and colored output for terminal use.
- **JSON** (`--json`) -- Structured JSON for piping into `jq`, CI/CD systems, or other tools.

```bash
# Human output
contour profile scan wifi.mobileconfig

# JSON output for scripting
contour profile scan wifi.mobileconfig --json | jq '.payloads[].type'
```
