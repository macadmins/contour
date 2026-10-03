# contour-mcp -- Read-only MCP Server for AI Agents

> **Status: Preview** — feature-complete for core workflows, APIs and flags may still change before 1.0.

`contour-mcp` serves contour's embedded schema data to an AI agent (Claude Code, Cursor, Codex, any MCP client) over the Model Context Protocol. It is a **lookup server, not a generator**: it answers questions about Apple MDM payloads and DDM declarations, Windows CSP, osquery tables and mSCP rules. It cannot write a file.

**What you get:** an agent that checks the real schema instead of guessing key names.

- **Offline.** All data is compiled into the binary. No network, no API keys.
- **No port, no login.** stdio transport only — the client launches `contour-mcp` as a subprocess and owns both ends of the pipe.
- **Read-only by construction.** The crates that write MDM artifacts are not linked into the binary. See [Why it cannot write](#why-it-cannot-write).

Generating artifacts is still the `contour` CLI's job. A typical agent session looks something up with `contour-mcp`, then runs `contour profile …`, `contour santa …` and so on.

## Setup

### 1. Install

`contour-mcp` ships as its own signed, notarized pkg, separate from the `contour` pkg.

```bash
sudo installer -pkg contour-mcp-<version>.pkg -target /
contour-mcp --version
```

| | |
|---|---|
| Installs | `/usr/local/bin/contour-mcp` |
| Package id | `io.macadmins.contour-mcp.pkg` |
| Signing | Developer ID, notarized and stapled |

From source instead:

```bash
cargo build --release -p contour-mcp
# → target/release/contour-mcp
```

### 2. Register with your agent client

Installing does not register the server. Ask the binary for the commands:

```bash
contour-mcp --register
```

It prints the registration commands with its own resolved path filled in, so they paste without editing. It **prints and does not apply** — registering changes your agent configuration, and this binary writes nothing.

**Claude Code**

```bash
# Every project:
claude mcp add --scope user contour /usr/local/bin/contour-mcp

# This repository only (writes .mcp.json, which you can commit for the team):
claude mcp add --scope project contour /usr/local/bin/contour-mcp
```

**Any client that reads an `mcpServers` JSON block** (`.mcp.json`, `~/.claude.json`, Cursor's `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "contour": {
      "command": "/usr/local/bin/contour-mcp"
    }
  }
}
```

**Codex** (`~/.codex/config.toml`):

```toml
[mcp_servers.contour]
command = "/usr/local/bin/contour-mcp"
```

### 3. Verify

```bash
claude mcp list                 # "contour" should show as connected
contour-mcp --print-tools       # the 7-tool catalogue as JSON, no server started
```

If the client will not connect, test the handshake by hand before blaming the client:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28"}}' \
  | contour-mcp
```

One JSON line comes back, with `protocolVersion`, `capabilities.tools` and `serverInfo`. The server speaks MCP `2026-07-28` and negotiates back to `2025-03-26`.

## Tools

All eight are pure lookups — deterministic, and identical for a given build.

| Tool | Arguments (required in **bold**) | Answers |
|---|---|---|
| `contour.schema.search` | **`query`**, `platform`, `windows`, `limit` | Which Apple payload, DDM declaration or Windows CSP key carries this setting? |
| `contour.schema.key` | **`payload_type`**, `key`, `windows` | Every key of one payload with its `path` and `parent`, type, default, per-key deprecation, and a starter snippet. `key` takes a bare name (all keys of that name; `ambiguous: true` when they sit under different parents) or a dot-path (exactly one) |
| `contour.osquery.search` | **`query`**, `platform`, `limit` | Is there an osquery or Fleet table for this? Each hit carries `source`; `fleet` means it needs Fleet's agent |
| `contour.osquery.table` | **`table`** | The columns of one osquery or Fleet table, with Fleet's `examples`, `notes` and `url` where it has them |
| `contour.osquery.validate` | **`sql`**, `platform` | Do these tables and columns exist, is the table on this platform, and will it run under plain osqueryd? Unknown tables come back with suggestions |
| `contour.mscp.rule` | **`rule_id`** | One mSCP rule: severity, check/fix, mobileconfig/DDM enforceable, baselines |
| `contour.mscp.baseline` | **`baseline`**, `limit` | The rules in one baseline (CIS, STIG, 800-53 …) by section |
| `contour.sop` | **`topic`**, `section` | The step-by-step procedure for a contour workflow (same text as `contour help-ai --sop <topic>`) |

Suggested order: a `search` tool to find the identifier, then the detail tool. When `contour.schema.search` returns both a profile payload and a DDM declaration for the same concept, check whether the declaration supersedes the profile before writing the legacy shape.

### Calling a tool by hand

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"contour.osquery.table","arguments":{"table":"processes"}}}' \
  | contour-mcp
```

### Results and errors

- Every tool returns `structuredContent` matching its declared `outputSchema`, mirrored into a text block for clients that ignore structured results.
- Searches return `count`, `truncated` and up to 20 `results` (100 with `limit`). `truncated: true` means narrow the query, not that data is missing.
- A misspelled table, payload or rule id is a **tool error** (`isError: true`) with `suggestions` naming the near misses — retry with a corrected argument.
- An unknown tool (`-32602`) or method (`-32601`) is a **protocol error** — the call itself was wrong.

## Why it cannot write

`contour-mcp` depends only on `mdm-schema`, `osquery-schema`, `mscp-schema` and `contour-core`, none of which contain a file-write call. The crates that write artifacts — `profile`, `mscp`, `santa`, `pppc`, `btm`, `notifications`, `support` — are not in its dependency tree. A write is not blocked at runtime; the code for it is not in the binary.

```bash
cargo tree -p contour-mcp --depth 1
```

The `readOnlyHint` annotation on each tool records the same fact, but clients treat annotations as hints. The dependency tree is the guarantee.

## Good to know

- **Launch it from a client, not a shell.** Run bare, it waits on stdin forever. Use `--print-tools` to look at it from a terminal.
- **The tool list is fixed per build.** The schema is compiled in, so a schema update means installing a newer pkg. Restart the agent client afterwards.
- **Tools only.** No resources or prompts; `resources/list` returns `-32601`.
- **Nothing on stdout but the protocol.** Diagnostics go to stderr, so check the client's MCP log for them.

## Update and remove

```bash
# Update: install the newer pkg over the old one, then restart the client.
sudo installer -pkg contour-mcp-<new-version>.pkg -target /

# Remove:
claude mcp remove contour                 # add --scope project if registered there
sudo rm /usr/local/bin/contour-mcp
sudo pkgutil --forget io.macadmins.contour-mcp.pkg
```

## See also

- `contour help-ai --sop mcp` — the agent-facing procedure this page is based on
- [contour-osquery.md](contour-osquery.md) — the same osquery data as a CLI
- [contour-mscp.md](contour-mscp.md) — generating from mSCP baselines
