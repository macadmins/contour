//! JSON-RPC 2.0 framing and the MCP message shapes this server answers.
//!
//! Targets MCP revision [`PROTOCOL_VERSION`], which removed protocol-level
//! sessions and the GET stream endpoint — every request is self-contained.
//! contour's data is compiled into the binary and never changes at runtime,
//! so there is no session state to keep and none is kept.
//!
//! `initialize` is still answered even though this revision does not require
//! it: deployed clients predate the revision and open with the handshake, and
//! the spec's backward-compatibility guidance is to detect the counterpart's
//! era rather than refuse it.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// MCP revision implemented by this server.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// Revisions this server will echo back during `initialize` rather than
/// forcing a downgrade. All are answered with the same stateless handlers;
/// the differences between them do not reach a read-only tool server.
pub const SUPPORTED_VERSIONS: &[&str] = &["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];

/// JSON-RPC error code for a method this server does not implement.
pub const METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC error code for a malformed or unusable parameter set.
pub const INVALID_PARAMS: i32 = -32602;

/// One decoded JSON-RPC request or notification.
///
/// A message with no `id` is a notification: the caller expects no reply and
/// this server MUST NOT produce one.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl Request {
    /// True when the peer expects no response.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// A JSON-RPC response, either a result or an error.
#[derive(Debug, Clone, Serialize)]
pub struct Response {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
}

/// The `error` member of a JSON-RPC error response.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorObject {
    pub code: i32,
    pub message: String,
}

impl Response {
    /// A successful response carrying `result`.
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    /// A protocol-level failure. Distinct from a tool execution error, which
    /// is a *successful* response whose result carries `isError: true` —
    /// models can self-correct from the latter and rarely from this.
    pub fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(ErrorObject {
                code,
                message: message.into(),
            }),
        }
    }
}

/// Negotiate the revision to report from `initialize`.
///
/// Echoes the client's version when this server can speak it, so a client on
/// an older revision is not forced to downgrade its own expectations; falls
/// back to this server's native revision otherwise.
pub fn negotiate_version(client: Option<&str>) -> &'static str {
    match client {
        Some(v) => SUPPORTED_VERSIONS
            .iter()
            .find(|s| **s == v)
            .copied()
            .unwrap_or(PROTOCOL_VERSION),
        None => PROTOCOL_VERSION,
    }
}

/// The `initialize` result: what this server is and what it can do.
pub fn initialize_result(client_version: Option<&str>) -> Value {
    json!({
        "protocolVersion": negotiate_version(client_version),
        // listChanged is false: the schema is compiled into the binary, so the
        // tool set is immutable for the life of the process. Saying otherwise
        // would invite clients to open a subscription that can never fire.
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": "contour-mcp",
            "title": "contour — Apple MDM, Windows CSP, osquery and mSCP schema",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": concat!(
            "Read-only access to contour's embedded schema data: Apple MDM payload ",
            "capabilities, Microsoft's Windows CSP nodes, osquery tables, and mSCP ",
            "compliance rules. All lookups are ",
            "offline and deterministic. Results are structured; prefer structuredContent ",
            "over the text block. This server cannot write files.\n\n",
            "Apple and Windows are SEPARATE corpora and are never mixed: pass ",
            "`windows: true` to contour.schema.search and contour.schema.key to reach ",
            "Microsoft's CSP nodes. A miss on one corpus reports whether the other ",
            "has the type, so an empty result is not evidence that contour lacks the ",
            "schema.\n\n",
            // Without this, an agent reads the tool list as contour's whole
            // surface and concludes it is a schema oracle — then audits
            // profiles by hand with plutil and jq, finding a fraction of what
            // `profile report` finds. These commands are read-only but are not
            // reachable as tools: they live in a crate this binary does not
            // link, precisely so it cannot write.
            "These tools cover SCHEMA LOOKUP only. contour is a ~30-subcommand CLI, and ",
            "analysing profile FILES is done by running it via shell, not through this ",
            "server. For any scan / audit / review / lint / deprecation request over ",
            "existing .mobileconfig files, run:\n",
            "  contour profile report <dir>                 audit + collisions + deprecations + validate\n",
            "  contour profile validate <file>              schema-validate one profile\n",
            "  contour profile scan --deprecations <path>   per-payload and per-key deprecations\n",
            "  contour profile collisions <dir> -r          two profiles managing one domain\n",
            "  contour profile audit <dir>                  secrets, certs, binary payloads\n",
            "Prefer these over hand-parsing plists: they carry the same embedded schema ",
            "these tools expose. Use contour.sop for the full procedure."
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_has_no_id() {
        let r: Request = serde_json::from_str(r#"{"jsonrpc":"2.0","method":"x"}"#).unwrap();
        assert!(r.is_notification());
    }

    #[test]
    fn request_with_id_is_not_a_notification() {
        let r: Request = serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"x"}"#).unwrap();
        assert!(!r.is_notification());
    }

    #[test]
    fn missing_params_default_to_null() {
        let r: Request = serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"x"}"#).unwrap();
        assert!(r.params.is_null());
    }

    #[test]
    fn negotiation_echoes_a_supported_client_version() {
        assert_eq!(negotiate_version(Some("2025-06-18")), "2025-06-18");
    }

    #[test]
    fn negotiation_falls_back_for_unknown_versions() {
        assert_eq!(negotiate_version(Some("1999-01-01")), PROTOCOL_VERSION);
        assert_eq!(negotiate_version(None), PROTOCOL_VERSION);
    }

    #[test]
    fn error_response_omits_result_field() {
        let r = Response::err(json!(1), METHOD_NOT_FOUND, "nope");
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("\"result\""), "got: {s}");
        assert!(s.contains("\"error\""), "got: {s}");
    }

    #[test]
    fn ok_response_omits_error_field() {
        let r = Response::ok(json!(1), json!({"a": 1}));
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("\"error\""), "got: {s}");
    }
}
