# `.contour/config.toml` — Configuration Reference

`.contour/config.toml` holds project-wide defaults so contour commands
don't need repetitive flags. Every section is optional except
`[organization]`.

## Discovery & precedence

contour finds the file by walking **up the directory tree**:

1. From the **recipe path** (or recipe-file location) — the *anchor*. This
   lets a preset library carry its own config.
2. From the **current working directory**.

When both exist, the **CWD config wins** on conflict — your project's
config overrides a preset folder's defaults. For tables (`[vars]`,
`[secrets.refs]`, `[mdm_variables.pool]`) the maps are merged key-by-key.

Resolution order for any single value: **CLI flag → `profile.toml` →
CWD `.contour/config.toml` → anchor `.contour/config.toml` → built-in
default**.

Create one with `contour profile init --org com.yourorg`.

---

## `[organization]` *(required)*

Identity used for `PayloadIdentifier` prefixes and `PayloadOrganization`.

| Key | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Organization display name |
| `domain` | string | yes | Reverse-DNS domain, e.g. `com.acme` |
| `server_url` | string | no | MDM server URL |

```toml
[organization]
name   = "Acme Corp"
domain = "com.acme"
server_url = "https://mdm.acme.com"
```

---

## `[defaults]`

Project-wide defaults for generation and library resolution.

| Key | Type | Default | Description |
|---|---|---|---|
| `platforms` | array of string | — | Restrict output to these OSes |
| `deterministic_uuids` | bool | — | Reproducible UUIDs for GitOps |
| `manifests_path` | path | — | External schema directory |
| `library_path` | path | — | Default `--recipe-path` / `--into` directory |

```toml
[defaults]
deterministic_uuids = true
library_path = "./presets"
```

---

## `[vars]`

Static substitutions for `{{PLACEHOLDER}}` tokens in recipes. contour
substitutes these **at generate time**. CLI `--set` and recipe-level
values override them.

```toml
[vars]
OKTA_DOMAIN = "acme.okta.com"
MDM_SERVER  = "https://mdm.acme.com"
```

A recipe field `Domain = "{{OKTA_DOMAIN}}"` becomes `acme.okta.com`.

---

## `[signing]`

Code-signing defaults for `contour profile sign` when no `--identity`
flag is given.

| Key | Type | Description |
|---|---|---|
| `identity` | string | Developer ID Installer name or SHA-1 hash |
| `team_id` | string | Apple Developer Team ID |

```toml
[signing]
identity = "Developer ID Installer: Acme Corp (ABCD12345)"
team_id  = "ABCD12345"
```

---

## `[validation]`

Schema-validation policy for commands that emit or scan profiles.

| Key | Type | Default | Description |
|---|---|---|---|
| `fail_on_errors` | bool | `true` | Non-zero exit on any schema error |
| `fail_on_warnings` | bool | `false` | Non-zero exit on warnings too |
| `fail_on_deprecations` | bool | `false` | Default for `scan --fail-on-deprecations` |

```toml
[validation]
fail_on_errors       = true
fail_on_warnings     = false
fail_on_deprecations = false
```

---

## `[secrets]`

Secret references that contour **resolves at generate time** — the real
value is fetched and baked into the output (unless `--sanitize` is used).
See the *Secrets* section of `contour-profile.md` for the full workflow.

| Key | Type | Description |
|---|---|---|
| `dotenv` | string | Default `.env` path for `env:` resolution |
| `op_vault` | string | Default 1Password vault (reserved) |

`[secrets.refs]` is a name → reference table. A recipe field
`secret:NAME` resolves through it. Reference targets:

| Prefix | Resolves to |
|---|---|
| `op://vault/item/field` | a 1Password item field (via the `op` CLI) |
| `env:NAME` | a process env var, then a `.env` file |
| `file:/path` | file contents (emitted as binary `Data`) |
| `var:NAME` | a `[mdm_variables.pool]` entry (see below) |

```toml
[secrets]
dotenv   = ".env"          # add .env to .gitignore — never commit it
op_vault = "Corp"

[secrets.refs]
WIFI_PASSWORD = "op://Corp/WiFi/password"
API_KEY       = "env:ACME_API_KEY"
NDES          = "var:SCEP_CHALLENGE"   # reuse an MDM variable as a secret
```

---

## `[mdm_variables]`

MDM **deploy-time** variables — tokens the MDM server (Fleet/Jamf/Apple)
substitutes **on-device at deploy time**. contour passes them through
verbatim; it never resolves them.

| Key | Type | Description |
|---|---|---|
| `mdm` | string | Active flavour: `fleet`, `jamf`, or `apple` — selects the catalogue used to validate tokens |

`[mdm_variables.pool]` is a name → token table. A recipe field
`var:NAME` resolves through it to the token, which is emitted verbatim.
Tokens may be combined with static text (`$USERNAME@acme.com`).

```toml
[mdm_variables]
mdm = "fleet"

[mdm_variables.pool]
SCEP_CHALLENGE = "FLEET_VAR_NDES_SCEP_CHALLENGE"
SCEP_URL       = "FLEET_VAR_NDES_SCEP_PROXY_URL"
USER_EMAIL     = "$USERNAME@acme.com"
```

`contour profile variables --mdm fleet` lists the valid tokens.

---

## The three reference kinds

| Kind | Section | Recipe syntax | Substituted by | When |
|---|---|---|---|---|
| Static var | `[vars]` | `{{NAME}}` | contour | generate |
| Secret | `[secrets]` | `secret:NAME` (or `op://`/`env:`/`file:`) | contour | generate |
| MDM variable | `[mdm_variables]` | `var:NAME` (or `$VARIABLE`/`FLEET_VAR_*`) | the MDM server | deploy |

---

## Full example

```toml
[organization]
name   = "Acme Corp"
domain = "com.acme"
server_url = "https://mdm.acme.com"

[defaults]
deterministic_uuids = true
library_path = "./presets"

[vars]
OKTA_DOMAIN = "acme.okta.com"

[signing]
identity = "Developer ID Installer: Acme Corp (ABCD12345)"
team_id  = "ABCD12345"

[validation]
fail_on_errors       = true
fail_on_warnings     = false
fail_on_deprecations = false

[secrets]
dotenv = ".env"

[secrets.refs]
WIFI_PASSWORD = "op://Corp/WiFi/password"
API_KEY       = "env:ACME_API_KEY"
NDES          = "var:SCEP_CHALLENGE"

[mdm_variables]
mdm = "fleet"

[mdm_variables.pool]
SCEP_CHALLENGE = "FLEET_VAR_NDES_SCEP_CHALLENGE"
SCEP_URL       = "FLEET_VAR_NDES_SCEP_PROXY_URL"
USER_EMAIL     = "$USERNAME@acme.com"
```

Recipe fields drawing on each kind:

```toml
[profile.fields]
ProfileDomain  = "{{OKTA_DOMAIN}}"        # [vars]          → contour substitutes
Password       = "secret:WIFI_PASSWORD"   # [secrets.refs]  → contour resolves op://
Challenge      = "secret:NDES"            # secret: → var:  → FLEET_VAR_… token
URL            = "var:SCEP_URL"           # [mdm_variables] → emitted verbatim
NotificationTo = "var:USER_EMAIL"         # → $USERNAME@acme.com, MDM substitutes
```

## See also

- `contour-profile.md` — the *Secrets* and *MDM variables* sections cover
  the resolution workflow, import redaction, `.env` files, `--sanitize`,
  and the GitHub Actions pattern.
