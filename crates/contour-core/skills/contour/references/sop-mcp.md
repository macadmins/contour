# SOP: contour MCP edition (read-only schema server)

`contour-mcp` is a separate binary that serves contour's embedded schema data
to an AI agent over the Model Context Protocol. It is a **lookup server, not a
generator**: it answers questions about Apple MDM payloads, osquery tables and
mSCP rules, and it cannot write a file.

Use it when an agent needs schema facts mid-task without shelling out and
parsing CLI output. For generating artifacts, the agent still runs the `contour`
CLI — see `--sop profile`, `--sop ddm`, `--sop santa`.

## When to use

- "Wire contour into Claude Code / Cursor / Codex as an MCP server"
- "The agent keeps guessing Apple payload key names"
- "Let the agent check an osquery table exists before writing SQL"
- "Which baselines contain this mSCP rule?"

## What it is

| Property | Value |
|---|---|
| Binary | `contour-mcp` (separate from `contour`) |
| Transport | stdio only — newline-delimited JSON-RPC on stdin/stdout |
| Protocol | MCP `2026-07-28`, negotiating back to `2025-03-26` |
| Network | none — no port, no listener, no authentication |
| Writes | none — see [Why read-only is structural](#why-read-only-is-structural) |

There is no authentication because there is nothing to authenticate: the client
launches the binary as a subprocess and owns both ends of the pipe. The MCP
specification says the same — implementations on stdio *"SHOULD NOT"* follow
the OAuth authorization spec and should take credentials from the environment.

## Procedure

```
1. INSTALL (its own pkg, separate from the `contour` pkg)
   sudo installer -pkg contour-mcp-<version>.pkg -target /
   → /usr/local/bin/contour-mcp   (pkg id io.macadmins.contour-mcp.pkg)

   From source instead:
   cargo build --release -p contour-mcp
   → target/release/contour-mcp

2. INSPECT the catalogue without starting a server
   contour-mcp --print-tools
   → JSON: 7 tools, each with inputSchema, outputSchema and annotations

3. REGISTER with the agent client
   contour-mcp --register
   → prints the `claude mcp add` commands (project and user scope) and the
     equivalent .mcp.json block, with this binary's resolved absolute path
     filled in, so it pastes without editing.

   It PRINTS and does not apply. Registering edits your agent configuration,
   and this binary writes nothing — see "Why read-only is structural".

   claude mcp add --scope project contour /usr/local/bin/contour-mcp
   claude mcp list          # confirm it registered

4. VERIFY the handshake by hand before blaming the client
   printf '%s\n' \
     '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28"}}' \
     | contour-mcp
   → one JSON line: protocolVersion, capabilities.tools, serverInfo

5. CALL a tool the same way
   printf '%s\n' \
     '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"contour.osquery.table","arguments":{"table":"processes"}}}' \
     | contour-mcp
```

## The tools

All seven are pure lookups over data compiled into the binary. Offline,
deterministic, and identical for a given build.

| Tool | Answers |
|---|---|
| `contour.schema.search` | "which payload or key carries this setting?" |
| `contour.schema.key` | "what are this payload's keys, where each sits (`path`, `parent`), platforms, and a starting snippet?" |
| `contour.osquery.search` | "is there a table for this?" |
| `contour.osquery.table` | "what columns does this table have?" |
| `contour.mscp.rule` | "what is this rule, and which baselines include it?" |
| `contour.mscp.baseline` | "what rules are in CIS level 1?" |
| `contour.sop` | "what is the command sequence for this workflow?" |

Suggested order of use: `search` to find the identifier, then the detail tool.
`contour.schema.search` returns MDM profile payloads *and* DDM declarations for
the same concept, which is the signal to check whether a declaration supersedes
the profile before authoring the legacy shape.

## Result shape

Every tool declares an `outputSchema` and returns `structuredContent`
conforming to it, with the same JSON mirrored into a text block for clients
that ignore structured results. Read `structuredContent`; the text block is a
compatibility shim, not a summary.

Searches return `count`, `truncated` and a capped `results` array — 20 by
default, 100 maximum. A `truncated: true` means narrow the query, not that the
data is missing.

## Errors: two kinds, on purpose

- **Tool execution errors** — a successful JSON-RPC response whose result has
  `isError: true`, carrying `error` and `suggestions`. A misspelled table or
  rule id lands here, and `suggestions` names the near misses so the next call
  can be right. Retry with a corrected argument.
- **Protocol errors** — a JSON-RPC `error` object. Unknown tool name
  (`-32602`) or unknown method (`-32601`). Retrying with different arguments
  will not help; the call itself was wrong.

## Why read-only is structural

`contour-mcp` depends only on `mdm-schema`, `osquery-schema`, `mscp-schema` and
`contour-core`. The crates that generate and write MDM artifacts — `profile`
(110 write sites), `mscp` (73), `santa`, `pppc`, `btm`, `notifications`,
`support` — are **not** in its dependency tree. A write path is not blocked at
runtime; it is not compiled into the binary.

Verify at any time:

```
cargo tree -p contour-mcp --depth 1
```

The `readOnlyHint` annotation on each tool records the same fact, but clients
are instructed to treat annotations as untrusted. The dependency tree is the
guarantee; the annotation is a hint.

## Rules & cautions

- **stdout is the protocol channel.** Never add a `println!` to this binary —
  it corrupts the stream and the client reports a parse error, not a bug. All
  diagnostics go to stderr. This is contour's `--json`-envelope-on-stderr rule
  applied to a second machine consumer.
- **Its own pkg.** The `contour` pkg does not include `contour-mcp`; it ships
  as a separate signed, notarized pkg (`io.macadmins.contour-mcp.pkg`).
  Installing it does not register it — run `contour-mcp --register`.
- **The tool list is immutable per build.** `listChanged` is false and
  `tools/list` returns a 24-hour `ttlMs` with `cacheScope: "public"`, because
  the schema is compiled in. A schema refresh means a new binary.
- **No resources, no prompts.** Only the `tools` capability is declared. A
  client asking for `resources/list` gets `-32601`.
- **Launch it from a client, not a shell.** Run bare, it waits on stdin
  forever. Use `--print-tools` to inspect it interactively.
