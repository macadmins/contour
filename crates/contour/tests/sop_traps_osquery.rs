//! Procedural SOP — trap suite for `contour osquery` commands.
//!
//! Companion to `crates/profile/tests/sop_traps.rs` and
//! `crates/mscp/tests/sop_traps_mscp.rs`. Each trap exercises one CLI
//! contract that the procedural SOP in `sop-osquery.md` relies on.
//!
//! Failure means either the CLI changed (update the SOP) or the SOP is
//! wrong (fix the SOP).
//!
//! Spec:    `crates/contour-core/skills/contour/references/sop-format-spec.md`
//! SOP:     `crates/contour-core/skills/contour/references/sop-osquery.md`

use assert_cmd::Command;
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// Trap 19: `osquery search <unknown_keyword> --json` returns `[]` exit 0.
// SOP procedure: find_query_table / STEP 1
// Catches: agents that branch on exit code instead of len(matches). Same
// shape as profile search trap 4 and mscp schema rules trap 16.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_19_osquery_search_unknown_returns_empty_array() {
    let output = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "osquery",
            "search",
            "this_keyword_does_not_match_anything_xyz",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "osquery search exits 0 even when no columns match — agents MUST check len()"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value =
        serde_json::from_str(stdout.trim()).expect("osquery search --json must emit a JSON array");
    assert!(
        parsed.is_array(),
        "osquery search --json returns a JSON array"
    );
    assert_eq!(
        parsed.as_array().unwrap().len(),
        0,
        "no match → empty array"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 20: `osquery search` returns column-level matches (not table-level).
// SOP procedure: find_query_table / STEP 1 (reduce-to-tables step)
// Catches: regressions that change the search granularity. The SOP's
// STEP 2 deduplicates table_name across results because of this — if the
// CLI starts returning one entry per table, STEP 2 still works but the
// docstring would lie.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_20_osquery_search_returns_column_level_entries() {
    let output = Command::cargo_bin("contour")
        .unwrap()
        .args(["osquery", "search", "disk_encryption", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "osquery search must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("must emit JSON array");
    let entries = parsed.as_array().expect("array");
    assert!(
        !entries.is_empty(),
        "disk_encryption should match at least one column"
    );

    // Each entry MUST have BOTH table_name and column_name (column-level).
    let first = &entries[0];
    assert!(
        first.get("table_name").and_then(|v| v.as_str()).is_some(),
        "entry must include table_name"
    );
    assert!(
        first.get("column_name").and_then(|v| v.as_str()).is_some(),
        "entry must include column_name (search is column-level, not table-level)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 21: `osquery table <unknown> --json` exits 1 with a JSON error
//          envelope on stderr (post-B3 contract).
// SOP procedure: find_query_table / STEP 3
// Catches: regressions that drop the JSON error wrapping for unknown
// tables. Agents MUST be able to parse error_code from stderr.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_21_osquery_table_unknown_emits_json_error() {
    let output = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "osquery",
            "table",
            "this_table_does_not_exist_xyz",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "unknown table must exit non-zero");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Value = serde_json::from_str(stderr.trim())
        .expect("post-B3: stderr must be a parseable JSON object on failure");

    assert_eq!(parsed["success"], false);
    assert!(parsed["error_code"].is_string(), "error_code is present");
    let code = parsed["error_code"].as_str().unwrap();
    let known = [
        "INVALID_IDENTIFIER",
        "INVALID_FORMAT",
        "MISSING_PAYLOAD_TYPE",
        "SCHEMA_VIOLATION",
        "IO_ERROR",
        "INVALID_ORG",
        "UNKNOWN",
    ];
    assert!(
        known.contains(&code),
        "error_code {code:?} must be from the documented enum"
    );
    assert!(
        parsed["error"]
            .as_str()
            .is_some_and(|s| s.contains("not found")),
        "error message preserves 'not found' hint"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 22: `osquery table <known> --json` returns a table object with a
//          `columns` array, NOT just a column list.
// SOP procedure: find_query_table / STEP 3
// Catches: regressions that change the response shape. The SOP's
// POSTCONDITIONS check `schema.platforms` and `schema.columns` — both
// must be top-level fields on the same object.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_22_osquery_table_returns_columns_under_table_object() {
    let output = Command::cargo_bin("contour")
        .unwrap()
        .args(["osquery", "table", "alf", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "osquery table alf must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("must emit JSON object");
    assert!(parsed.is_object(), "table response is a JSON object");

    // Required fields the SOP's POSTCONDITIONS reference.
    assert!(parsed.get("table_name").is_some(), "must have table_name");
    assert!(parsed.get("platforms").is_some(), "must have platforms");
    let columns = parsed
        .get("columns")
        .expect("must have columns")
        .as_array()
        .expect("columns is an array");
    assert!(!columns.is_empty(), "alf has columns");

    // Each column entry has the fields the SOP's STEP 3 reads.
    // NB: fields are prefixed (`column_name`, `column_type`, `column_description`)
    // — agents that key off bare `name`/`type` will silently miss them.
    let first = &columns[0];
    assert!(first.get("column_name").is_some(), "column has column_name");
    assert!(first.get("column_type").is_some(), "column has column_type");
}
