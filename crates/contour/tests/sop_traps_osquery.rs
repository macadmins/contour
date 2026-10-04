//! Procedural SOP — trap suite for `contour osquery` and `contour profile
//! enrollment` commands.
//!
//! Companion to `crates/profile/tests/sop_traps.rs` and
//! `crates/mscp/tests/sop_traps_mscp.rs`. Each trap exercises one CLI
//! contract that a procedural SOP relies on.
//!
//! Failure means either the CLI changed (update the SOP) or the SOP is
//! wrong (fix the SOP).
//!
//! Spec:    `crates/contour-core/skills/contour/references/sop-format-spec.md`
//! SOPs:    `sop-osquery.md`, `sop-enrollment.md`

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

    // Stream contract: failure envelope on stderr (see write_error_json).
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Value = serde_json::from_str(stderr.trim())
        .expect("--json failures emit a parseable JSON object on stderr");

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

// ─────────────────────────────────────────────────────────────────────────────
// Trap 23: `profile enrollment generate --skip-all` skips every pane that MAY be
//          skipped, and never FileVault or SoftwareUpdate. Naming either
//          explicitly is refused by the NEVER_SKIP guardrail.
//
// SOP procedure: generate_enrollment_profile / NEVER_SKIP invariant
//
// Catches: regressions that weaken the guardrail (letting FileVault/
// SoftwareUpdate into skip_setup_items by any route), or that make --skip-all
// unusable again.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_23_enrollment_skip_all_honours_the_never_skip_guardrail() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("test.dep.json");

    let result = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "profile",
            "enrollment",
            "generate",
            "--platform",
            "macOS",
            "--skip-all",
            "-o",
            out.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "--skip-all must succeed; stderr: {}",
        String::from_utf8_lossy(&result.stderr),
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).expect("profile written")).unwrap();
    let items: Vec<&str> = doc["skip_setup_items"]
        .as_array()
        .expect("skip_setup_items")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(!items.is_empty(), "--skip-all skipped nothing");
    for kept in ["FileVault", "SoftwareUpdate"] {
        assert!(!items.contains(&kept), "--skip-all must never skip {kept}");
    }

    // Asked for by name, the guardrail still refuses and says why.
    let refused = dir.path().join("refused.dep.json");
    let result = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "profile",
            "enrollment",
            "generate",
            "--platform",
            "macOS",
            "--skip",
            "FileVault,SoftwareUpdate",
            "-o",
            refused.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "naming a NEVER_SKIP pane must be refused"
    );
    let msg = String::from_utf8_lossy(&result.stderr);
    assert!(
        msg.contains("FileVault") && msg.contains("SoftwareUpdate") && msg.contains("NEVER_SKIP"),
        "guardrail rejection must name FileVault, SoftwareUpdate and NEVER_SKIP; got: {msg}"
    );
    assert!(
        !refused.exists(),
        "no profile is written when the guardrail refuses"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 24: `profile enrollment list --json` returns entries with the fields
//          the procedural SOP reads (`key`, `title`, `description`, `platform`,
//          `introduced`, `removed`, `deprecated`, `always_skippable`).
// SOP procedure: generate_enrollment_profile / STEP 1
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_24_enrollment_list_entry_shape() {
    let output = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "profile",
            "enrollment",
            "list",
            "--platform",
            "macOS",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "enrollment list must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value =
        serde_json::from_str(stdout.trim()).expect("enrollment list --json must emit a JSON array");
    let entries = parsed.as_array().expect("array");
    assert!(!entries.is_empty(), "macOS has skip keys");

    let first = &entries[0];
    for required in [
        "key",
        "title",
        "description",
        "platform",
        "introduced",
        "removed",
        "deprecated",
        "always_skippable",
    ] {
        assert!(
            first.get(required).is_some(),
            "entry must include {required}; missing in: {first:?}"
        );
    }
    // `key` MUST be a string — that's the value agents pass to --skip.
    assert!(first["key"].is_string(), "key is a string");
}

#[test]
fn trap_96_osquery_identifier_queries_stay_valid_against_the_schema() {
    // --sop osquery's resolve_app_identifier procedure ships two SQL queries
    // and one hard rule: use `signature`, never the `codesign` Fleet
    // extension. All three are checkable offline against the embedded schema.
    //
    // Drift signal: osquery renames a column the queries depend on (the
    // hash_resources / hash_executable table PARAMETERS especially), or
    // `codesign` appears in core osquery and the rule stops being true.
    use std::path::PathBuf;

    let sop = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../contour-core/skills/contour/references/sop-osquery.md");
    let text = std::fs::read_to_string(&sop).unwrap();
    assert!(
        text.contains("resolve_app_identifier"),
        "the identifier-resolution procedure is missing from --sop osquery"
    );

    // The trust hierarchy's whole point: installer metadata is not a bundle id.
    assert!(
        text.contains("Not a bundle identifier at all"),
        "SOP must warn that installer metadata is not a bundle identifier"
    );
    // And the reason identifier accuracy matters at all.
    assert!(
        text.contains("is not an error"),
        "SOP must state that naming an uninstalled app fails silently"
    );

    // Every column the documented queries rely on must exist in the schema.
    let signature = osquery_schema::osquery::read(osquery_schema::embedded())
        .expect("read embedded osquery schema");

    let cols = |table: &str| -> Vec<String> {
        signature
            .iter()
            .filter(|c| c.table_name == table)
            .map(|c| c.column_name.clone())
            .collect()
    };

    let sig_cols = cols("signature");
    assert!(
        !sig_cols.is_empty(),
        "the `signature` table must exist — the procedure depends on it"
    );
    for needed in [
        "path",
        "identifier",
        "team_identifier",
        "authority",
        "signed",
        "hash_resources",
        "hash_executable",
    ] {
        assert!(
            sig_cols.iter().any(|c| c == needed),
            "signature.{needed} is referenced by --sop osquery but missing from the schema"
        );
    }

    let app_cols = cols("apps");
    for needed in ["name", "path", "bundle_identifier", "bundle_short_version"] {
        assert!(
            app_cols.iter().any(|c| c == needed),
            "apps.{needed} is referenced by --sop osquery but missing from the schema"
        );
    }

    // `codesign` is a Fleet extension. If it ever lands in core osquery the
    // SOP's rule needs rewriting rather than quietly becoming wrong.
    assert!(
        cols("codesign").is_empty(),
        "`codesign` is now in the embedded schema — --sop osquery still tells \
         agents it is a Fleet extension that does not exist in vanilla osqueryd"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 97: every fenced ```sql block in --sop osquery passes the schema check.
// SOP procedure: the whole cookbook (is_setting_enabled, check_software_updates,
// check_mdm_profile, resolve_app_identifier, …)
// Catches: a cookbook query naming a table or column the embedded osquery and
// Fleet schemas do not have, or a required column left unconstrained. The
// cookbook is what an agent copies; a typo there ships to every fleet that
// trusts it.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_97_cookbook_sql_names_real_tables_and_columns() {
    use contour_core::osquery_validate::{Severity, check_query};
    use std::path::PathBuf;

    let sop = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../contour-core/skills/contour/references/sop-osquery.md");
    let text = std::fs::read_to_string(&sop).unwrap();

    // Fenced ```sql blocks only; prose and bash blocks carry no SQL contract.
    let mut blocks: Vec<(usize, String)> = Vec::new();
    let mut current: Option<(usize, String)> = None;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        match &mut current {
            None if t.starts_with("```sql") => current = Some((i + 1, String::new())),
            Some((start, body)) if t.starts_with("```") => {
                blocks.push((*start, std::mem::take(body)));
                current = None;
            }
            Some((_, body)) => {
                body.push_str(line);
                body.push('\n');
            }
            None => {}
        }
    }
    assert!(blocks.len() >= 8, "expected the cookbook's sql blocks, found {}", blocks.len());

    let index = osquery_schema::index();
    let mut failures = Vec::new();
    for (line, sql) in &blocks {
        // One block may hold several statements; check each.
        for stmt in sql.split(';').map(str::trim).filter(|s| s.to_lowercase().contains("from")) {
            let errors: Vec<String> = check_query(stmt, "", index)
                .into_iter()
                .filter(|p| p.severity() == Severity::Error)
                .map(|p| p.to_string())
                .collect();
            if !errors.is_empty() {
                failures.push(format!("sop-osquery.md:{line}: {}\n    {}", errors.join("; "), stmt.replace('\n', " ")));
            }
        }
    }
    assert!(failures.is_empty(), "cookbook SQL fails the schema check:\n{}", failures.join("\n"));
}
