//! contour-mcp — a read-only MCP server over contour's embedded schema data.
//!
//! Speaks newline-delimited JSON-RPC on stdin/stdout (the MCP stdio binding).
//! There is no listener, no port and no authentication, because there is
//! nothing to reach over a network: the client launches this as a subprocess
//! and owns both ends of the pipe.
//!
//! **stdout is the protocol channel.** A stray `println!` corrupts the stream
//! and the client sees a parse error rather than a result, so nothing in this
//! binary writes to stdout except the JSON-RPC writer below — diagnostics go
//! to stderr. This is the same reasoning as contour's rule that `--json` error
//! envelopes belong on stderr, applied to a second machine consumer.
//!
//! The binary links only zero-write crates (see Cargo.toml), so "read-only"
//! is a property of what was compiled in, not of what the dispatcher chooses
//! to call.

mod protocol;
mod tools;

use std::io::{BufRead, Write};

use clap::Parser;
use serde_json::{Value, json};

use protocol::{INVALID_PARAMS, METHOD_NOT_FOUND, Request, Response};

#[derive(Debug, Parser)]
#[command(
    name = "contour-mcp",
    about = "Read-only MCP server over contour's embedded Apple MDM, Windows CSP, osquery and mSCP schema",
    long_about = "Serves contour's embedded schema data to AI agents over the MCP stdio \
                  transport. Launch it from an MCP client rather than by hand; run \
                  --print-tools to inspect the catalogue from a terminal.",
    version
)]
struct Cli {
    /// Print the tool catalogue as JSON and exit, without starting the server.
    #[arg(long)]
    print_tools: bool,

    /// Print the commands and config needed to register this server with an
    /// agent client, then exit. Prints only — registering is a change to your
    /// configuration, and this binary does not write files.
    #[arg(long)]
    register: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.print_tools {
        // Explicitly asked for on stdout by a human; the server loop has not
        // started, so there is no protocol stream to corrupt.
        let out = json!({"tools": tools::list()});
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return;
    }

    if cli.register {
        print!("{}", registration_help());
        return;
    }

    if let Err(e) = serve() {
        eprintln!("contour-mcp: {e:#}");
        std::process::exit(1);
    }
}

/// Ready-to-run registration instructions naming this binary's real path.
///
/// Printed, never applied: registering edits the user's agent configuration,
/// and this binary writes nothing. Resolving `current_exe` means the output
/// is correct whether the binary sits in `/usr/local/bin`, in `dist/`, or in
/// a `target/` build directory, so it can be pasted without editing.
fn registration_help() -> String {
    let path = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_or_else(|_| "contour-mcp".to_string(), |p| p.display().to_string());

    format!(
        "# Register contour-mcp with an agent client\n\
         # Resolved binary: {path}\n\
         \n\
         # Claude Code — project scope (this repo only):\n\
         claude mcp add --scope project contour {path}\n\
         \n\
         # Claude Code — user scope (every project):\n\
         claude mcp add --scope user contour {path}\n\
         \n\
         # Or write this to .mcp.json / ~/.claude.json yourself:\n\
         {{\n  \"mcpServers\": {{\n    \"contour\": {{\n      \"command\": \"{path}\"\n    }}\n  }}\n}}\n\
         \n\
         # Verify after registering:\n\
         claude mcp list\n\
         \n\
         # This server exposes {count} read-only tools and cannot write files.\n",
        path = path,
        count = tools::TOOLS.len(),
    )
}

/// Read requests until stdin closes, answering each in turn.
fn serve() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let Some(response) = handle_line(&line) else {
            // A notification, or an unparseable line with no id to answer to.
            continue;
        };

        serde_json::to_writer(&mut stdout, &response)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }

    Ok(())
}

/// Turn one input line into an optional response.
///
/// Returns `None` when the peer expects no reply: a notification, or a message
/// so malformed that there is no `id` to attach an error to.
fn handle_line(line: &str) -> Option<Response> {
    let request: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("contour-mcp: unparseable message: {e}");
            return None;
        }
    };

    if request.is_notification() {
        return None;
    }
    let id = request.id.clone().unwrap_or(Value::Null);

    Some(match request.method.as_str() {
        "initialize" => {
            let client_version = request
                .params
                .get("protocolVersion")
                .and_then(Value::as_str);
            Response::ok(id, protocol::initialize_result(client_version))
        }
        "ping" => Response::ok(id, json!({})),
        "tools/list" => Response::ok(
            id,
            json!({
                "tools": tools::list(),
                // The schema is compiled in, so this list cannot change for the
                // life of the build. Say so, and let the client cache hard.
                "ttlMs": 86_400_000u64,
                "cacheScope": "public",
            }),
        ),
        "tools/call" => call_tool(id, &request.params),
        other => Response::err(id, METHOD_NOT_FOUND, format!("unknown method: {other}")),
    })
}

/// Dispatch `tools/call`.
///
/// An unknown tool is a protocol error — the model cannot fix it by retrying
/// with different arguments. A tool that runs and fails returns a *successful*
/// response carrying `isError: true`, which is the shape models self-correct
/// from.
fn call_tool(id: Value, params: &Value) -> Response {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return Response::err(id, INVALID_PARAMS, "tools/call requires params.name");
    };

    let Some(tool) = tools::find(name) else {
        return Response::err(id, INVALID_PARAMS, format!("unknown tool: {name}"));
    };

    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match (tool.handler)(&args) {
        Ok(structured) => {
            // Structured result plus the same JSON serialized as text: the
            // spec asks for the text block for backwards compatibility with
            // clients that ignore structuredContent.
            let text = serde_json::to_string(&structured).unwrap_or_default();
            Response::ok(
                id,
                json!({
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": structured,
                    "isError": false,
                }),
            )
        }
        Err(e) => {
            let mut text = e.message.clone();
            if !e.suggestions.is_empty() {
                text.push_str("\nDid you mean: ");
                text.push_str(&e.suggestions.join(", "));
            }
            Response::ok(
                id,
                json!({
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": {
                        "error": e.message,
                        "suggestions": e.suggestions,
                    },
                    "isError": true,
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(line: &str) -> Value {
        let r = handle_line(line).expect("expected a response");
        serde_json::to_value(r).unwrap()
    }

    #[test]
    fn registration_help_names_the_real_binary_and_is_pasteable() {
        let help = registration_help();
        // The whole point is a path you can paste; the literal placeholder
        // would mean current_exe() resolution silently failed.
        assert!(help.contains("claude mcp add"), "got: {help}");
        assert!(help.contains("mcpServers"), "got: {help}");
        assert!(
            help.contains("contour-mcp") || help.contains("deps/"),
            "expected the resolved test-binary path, got: {help}"
        );
        // The JSON block must actually parse — a malformed snippet is worse
        // than none, because it fails only after the user has pasted it.
        let start = help.find('{').expect("no JSON block");
        let end = help.rfind('}').expect("no JSON block end");
        let parsed: Value =
            serde_json::from_str(&help[start..=end]).expect("snippet must be valid JSON");
        assert!(parsed["mcpServers"]["contour"]["command"].is_string());
    }

    #[test]
    fn notifications_get_no_response() {
        assert!(handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
    }

    #[test]
    fn garbage_input_does_not_answer_and_does_not_panic() {
        assert!(handle_line("not json at all").is_none());
    }

    #[test]
    fn initialize_reports_tools_capability_and_echoes_version() {
        let v = call(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        );
        assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
        assert!(v["result"]["capabilities"]["tools"].is_object());
        assert_eq!(v["result"]["serverInfo"]["name"], "contour-mcp");
    }

    #[test]
    fn tools_list_returns_the_catalogue_with_cache_hints() {
        let v = call(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let list = v["result"]["tools"].as_array().unwrap();
        assert_eq!(list.len(), tools::TOOLS.len());
        assert_eq!(v["result"]["cacheScope"], "public");
    }

    #[test]
    fn unknown_method_is_a_protocol_error() {
        let v = call(r#"{"jsonrpc":"2.0","id":3,"method":"resources/list"}"#);
        assert_eq!(v["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn unknown_tool_is_a_protocol_error_not_a_tool_error() {
        let v = call(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope"}}"#);
        assert_eq!(v["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn successful_call_carries_structured_content_and_a_text_mirror() {
        let v = call(
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"contour.osquery.table","arguments":{"table":"processes"}}}"#,
        );
        assert_eq!(v["result"]["isError"], false);
        assert_eq!(v["result"]["structuredContent"]["table"], "processes");
        // The text block must be the same JSON, not a prose summary.
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        let reparsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(reparsed, v["result"]["structuredContent"]);
    }

    #[test]
    fn failing_call_is_a_successful_response_flagged_is_error() {
        let v = call(
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"contour.osquery.table","arguments":{"table":"process"}}}"#,
        );
        assert!(v["error"].is_null(), "must not be a protocol error");
        assert_eq!(v["result"]["isError"], true);
        assert!(
            !v["result"]["structuredContent"]["suggestions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}
