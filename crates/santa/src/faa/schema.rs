//! Static schema definitions for FAA policies.
//!
//! Used by `contour santa faa schema` to output the available rule types,
//! options, process identity fields, and runtime placeholders.

/// Returns the FAA schema as a JSON value.
pub fn faa_schema() -> serde_json::Value {
    serde_json::json!({
        "rule_types": [
            {
                "name": "paths_with_allowed_processes",
                "plist_value": "PathsWithAllowedProcesses",
                "centric": "data",
                "description": "Only listed processes may access these paths"
            },
            {
                "name": "paths_with_denied_processes",
                "plist_value": "PathsWithDeniedProcesses",
                "centric": "data",
                "description": "Listed processes are denied access to these paths"
            },
            {
                "name": "processes_with_allowed_paths",
                "plist_value": "ProcessesWithAllowedPaths",
                "centric": "process",
                "description": "Listed processes may only access these paths"
            },
            {
                "name": "processes_with_denied_paths",
                "plist_value": "ProcessesWithDeniedPaths",
                "centric": "process",
                "description": "Listed processes are denied access to these paths"
            }
        ],
        "options": [
            {"name": "allow_read_access", "type": "bool", "default": false, "description": "Block read access as well as write"},
            {"name": "audit_only", "type": "bool", "default": true, "description": "Log only, do not block"},
            {"name": "silent", "type": "bool", "default": false, "description": "Suppress notification dialog"},
            {"name": "silent_tty", "type": "bool", "default": false, "description": "Suppress TTY message"},
            {"name": "block_message", "type": "string", "default": null, "description": "Custom message shown in block dialog"},
            {"name": "event_detail_url", "type": "string", "default": null, "description": "URL for More Info button (supports runtime placeholders)"},
            {"name": "event_detail_text", "type": "string", "default": null, "description": "Label text for More Info button"}
        ],
        "process_identity_fields": [
            {"name": "team_id", "type": "string", "description": "10-character Apple Team ID"},
            {"name": "signing_id", "type": "string", "description": "Code signing identifier (e.g., com.google.Chrome)"},
            {"name": "platform_binary", "type": "bool", "description": "Whether signed with Apple platform certificate"},
            {"name": "cdhash", "type": "string", "description": "40-character hex CDHash (SHA-1)"},
            {"name": "certificate_sha256", "type": "string", "description": "64-character hex SHA-256 of the signing certificate"},
            {"name": "binary_path", "type": "string", "description": "Absolute path to the binary (least secure)"}
        ],
        "runtime_placeholders": [
            {"name": "%rule_version%", "description": "Policy version"},
            {"name": "%rule_name%", "description": "Policy name"},
            {"name": "%file_identifier%", "description": "SHA-256 of the binary"},
            {"name": "%accessed_path%", "description": "The path being accessed"},
            {"name": "%username%", "description": "Executing user"},
            {"name": "%team_id%", "description": "Team ID"},
            {"name": "%signing_id%", "description": "Signing ID"},
            {"name": "%cdhash%", "description": "CDHash"},
            {"name": "%machine_id%", "description": "Machine identifier"},
            {"name": "%serial%", "description": "Machine serial number"},
            {"name": "%uuid%", "description": "Hardware UUID"},
            {"name": "%hostname%", "description": "System hostname"}
        ]
    })
}
