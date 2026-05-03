//! Pseudocode SOP pilot — trap-counter integration suite.
//!
//! Each test exercises one **agent trap** documented in the pseudocode SOP pilot:
//!   `crates/contour-core/skills/contour/references/sop-format-spec.md`
//!
//! A "trap" is a CLI behavior that an agent following a prose SOP could easily
//! miss but that the pseudocode pilot catches by design — via a PRECONDITION,
//! POSTCONDITION, INPUT contract, or branch in EXECUTION.
//!
//! ## What this suite measures
//!
//! - **Pilot-vs-CLI parity**: every trap should pass; failure means either
//!   (a) the CLI changed and the pilot needs updating, or (b) the pilot is wrong
//!   and the CLI is right.
//! - **Drift detector**: run on every `cargo test`. Catches CLI output-format
//!   changes (rename a JSON field, change exit codes) before they break agents.
//! - **Effectiveness signal**: as more SOPs migrate to pseudocode (Phase C of
//!   the migration plan), each new procedure adds traps here. Trap count =
//!   number of agent failure modes the format catches by design.
//!
//! ## What changed in Phase B
//!
//! - **B1**: single-file `normalize --json` now emits a BatchResult JSON object
//!   on success (trap 5 verifies the post-B1 contract strictly)
//! - **B2**: `failure_categories[].files[]` entries now carry typed `error_code`
//!   from a stable enum (trap 6 verifies presence and values)
//! - **B3**: top-level errors emit `{success, error, error_code}` JSON on stderr
//!   when `--json` is set (trap 9 verifies the contract)
//!
//! Each trap is now strict — there's no "either pre-B or post-B" tolerance.
//! A regression that drops any of these will fail this suite.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;

/// Minimal valid Jamf-format YAML (the envelope `contour profile import --jamf` expects).
/// Used by trap 8 to verify discovery filters out non-Jamf YAML silently.
const VALID_JAMF_YAML: &str = r#"_meta:
    schema_version: 1
    cli_version: 1.4.0
    resource_type: profiles
general:
    name: Trap Test Profile
    payloads: |-
        <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>PayloadContent</key><array><dict><key>PayloadDisplayName</key><string>Inner</string><key>PayloadIdentifier</key><string>com.example.inner</string><key>PayloadType</key><string>com.apple.mobiledevice.passwordpolicy</string><key>PayloadUUID</key><string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string><key>PayloadVersion</key><integer>1</integer></dict></array><key>PayloadDisplayName</key><string>Trap Test</string><key>PayloadIdentifier</key><string>com.example.trap</string><key>PayloadType</key><string>Configuration</string><key>PayloadUUID</key><string>12345678-1234-1234-1234-123456789012</string><key>PayloadVersion</key><integer>1</integer></dict></plist>
"#;

// ─────────────────────────────────────────────────────────────────────────────
// Trap 1: Missing --org on `profile generate` is rejected.
// Pilot procedure: generate_profile / PRECONDITIONS
// Catches: agents that forget --org would have produced com.example identifiers.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_01_generate_requires_org() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.mobileconfig");

    Command::cargo_bin("profile")
        .unwrap()
        .args([
            "generate",
            "com.apple.mobiledevice.passwordpolicy",
            "--full",
            "-o",
            out.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--org is required"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 2: Explicit --org com.example is still accepted by the CLI.
// Pilot procedure: generate_profile / PRECONDITIONS (defence-in-depth)
// Catches: prose SOPs say "NEVER default to com.example", but the CLI permits
// the explicit value. The pseudocode pilot enforces this at the agent layer
// via `ASSERT org != "com.example"`. This trap documents that the *agent layer*
// is the only place this rule lives.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_02_generate_accepts_explicit_com_example() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.mobileconfig");

    Command::cargo_bin("profile")
        .unwrap()
        .args([
            "generate",
            "com.apple.mobiledevice.passwordpolicy",
            "--full",
            "--org",
            "com.example",
            "-o",
            out.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();

    // Confirms the CLI itself does NOT enforce this rule. If a future CLI
    // version starts rejecting com.example explicitly, this trap will fail
    // and we tighten the pilot accordingly.
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 3: `-o` passed a directory (not a file) fails on `profile generate`.
// Pilot procedure: generate_profile / INPUT contract
// Catches: agents that build paths via dir-join without specifying a filename.
// (Other commands like `mscp generate -o` accept directories — the per-command
// asymmetry is exactly what the pilot's INPUT block documents.)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_03_generate_rejects_directory_as_output() {
    let dir = tempfile::tempdir().unwrap();

    Command::cargo_bin("profile")
        .unwrap()
        .args([
            "generate",
            "com.apple.mobiledevice.passwordpolicy",
            "--full",
            "--org",
            "com.acme",
            "-o",
            dir.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .failure();
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 4: `profile search` returns `[]` with exit 0 when there is no match.
// Pilot procedure: generate_profile / STEP 1
// Catches: agents that branch on exit code would conclude "search succeeded"
// even with no results. The pilot's `ASSERT len(schema) > 0` requires checking
// array length, not exit code.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_04_search_empty_returns_array_exit_zero() {
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["search", "thisisbogusxyz123", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "search exits 0 even when there is no match — agents MUST check JSON length"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value =
        serde_json::from_str(stdout.trim()).expect("search --json output must be a JSON array");
    assert!(parsed.is_array(), "search --json returns a JSON array");
    assert_eq!(
        parsed.as_array().unwrap().len(),
        0,
        "no match → empty array"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 5: `normalize <file> --json` emits BatchResult-shaped JSON on success.
// Pilot procedure: normalize_profile / EXECUTION (single-file branch)
// Behavior (post-B1): emits a JSON object with operation/success/total/files[].
// Catches: regressions that drop the JSON output. Pre-B1 (silent stdout) is no
// longer acceptable — the agent contract requires parseable output.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_05_normalize_single_file_json_shape() {
    let dir = tempfile::tempdir().unwrap();
    let mc = dir.path().join("p.mobileconfig");
    let normalized = dir.path().join("p.normalized.mobileconfig");

    // Generate a profile to normalize.
    Command::cargo_bin("profile")
        .unwrap()
        .args([
            "generate",
            "com.apple.mobiledevice.passwordpolicy",
            "--full",
            "--org",
            "com.acme",
            "-o",
            mc.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();

    let output = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "normalize",
            mc.to_str().unwrap(),
            "--org",
            "com.acme",
            "-o",
            normalized.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "normalize succeeds on valid file");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim())
        .expect("normalize --json must emit parseable JSON (post-B1 contract)");

    assert_eq!(parsed["operation"], "normalize");
    assert_eq!(parsed["success"], true);
    assert_eq!(parsed["total"], 1);
    assert_eq!(parsed["succeeded"], 1);

    let files = parsed["files"]
        .as_array()
        .expect("post-B1: single-file mode includes a `files` array");
    assert_eq!(files.len(), 1);
    let file = &files[0];
    assert!(file["input"].is_string(), "file entry has input path");
    assert!(file["output"].is_string(), "file entry has output path");
    assert!(
        file["identifier"]
            .as_str()
            .is_some_and(|s| s.starts_with("com.acme.")),
        "identifier was prefixed with --org"
    );
    assert!(file["uuid"].is_string(), "uuid is present");
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 6: BatchResult failure entries expose typed `error_code` (Phase B2).
// Pilot procedures: normalize_profile + import_jamf_backup / POSTCONDITIONS
// Catches: regressions that drop the typed code, leaving agents to substring-
// match prose. The pseudocode SOPs use the SWITCH-on-error_code pattern; this
// trap ensures that pattern keeps working.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_06_batch_failures_have_error_code() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("bad.mobileconfig"), "garbage").unwrap();

    let output = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "normalize",
            dir.path().to_str().unwrap(),
            "--org",
            "com.acme",
            "--json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim())
        .expect("batch normalize --json output must be valid JSON");

    let entry = &parsed["failure_categories"][0]["files"][0];
    assert!(
        entry["error"].is_string(),
        "failure entry has prose `error` field for human readability"
    );

    let code = entry
        .get("error_code")
        .expect("post-B2: every failure entry includes typed `error_code`")
        .as_str()
        .expect("error_code is a string");
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
        "error_code {code:?} must be from the documented enum {known:?}"
    );
    // Specifically: garbage content should classify as INVALID_FORMAT, not UNKNOWN.
    assert_eq!(
        code, "INVALID_FORMAT",
        "garbage file should be classified as INVALID_FORMAT, got {code}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 7: `import --jamf` returns a different JSON shape for empty source dirs.
// Pilot procedure: import_jamf_backup / EMPTY-SOURCE shape
// Catches: agents that key off `succeeded`/`total` would NPE on the empty path.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_07_jamf_import_empty_source_alt_shape() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();

    let output = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "import",
            "--jamf",
            src.path().to_str().unwrap(),
            "-o",
            out.path().to_str().unwrap(),
            "--org",
            "com.acme",
            "--all",
            "--json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim())
        .expect("empty-source jamf import --json output must be valid JSON");

    assert!(
        parsed.get("total_found").is_some(),
        "empty source has `total_found` field — branch detection signal for agents"
    );
    assert_eq!(parsed["total_found"], 0);
    assert_eq!(parsed["success"], false);
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 9: top-level errors with `--json` emit a parseable JSON envelope
//         on stderr (Phase B3).
// Pilot context: pseudocode SOPs treat failure paths as JSON; without B3, the
// CLI fell back to plain `Error: ...` on stderr, breaking that contract.
// Catches: regressions that drop the JSON-error wrapping in main(), or any
// missing `error_code` on a top-level error.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_09_top_level_error_emits_json_with_code() {
    // Trigger a known precondition failure: missing --org on `profile generate`.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.mobileconfig");

    let output = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "generate",
            "com.apple.mobiledevice.passwordpolicy",
            "--full",
            "-o",
            out.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "missing --org must exit non-zero");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Value = serde_json::from_str(stderr.trim())
        .expect("post-B3: stderr must be a parseable JSON object on failure");

    assert_eq!(parsed["success"], false);
    assert_eq!(parsed["error_code"], "INVALID_ORG");
    assert!(
        parsed["error"]
            .as_str()
            .is_some_and(|s| s.contains("--org is required")),
        "error message preserves the human-readable hint"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 8: `import --jamf` silently filters non-Jamf YAML from the source dir.
// Pilot procedure: import_jamf_backup / POSTCONDITIONS
// Catches: agents that expect `total` to equal "all .yaml files in dir" would
// over-count. The CLI only counts files matching the Jamf envelope.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_08_jamf_import_silently_filters_bad_yaml() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();

    fs::write(src.path().join("bad.yaml"), "not a jamf profile").unwrap();
    fs::write(src.path().join("good.yaml"), VALID_JAMF_YAML).unwrap();

    let output = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "import",
            "--jamf",
            src.path().to_str().unwrap(),
            "-o",
            out.path().to_str().unwrap(),
            "--org",
            "com.acme",
            "--all",
            "--json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value =
        serde_json::from_str(stdout.trim()).expect("jamf import --json output must be valid JSON");

    assert_eq!(parsed["operation"], "jamf_import");
    assert_eq!(
        parsed["total"], 1,
        "non-Jamf YAML is silently filtered, NOT counted in total"
    );
    assert_eq!(parsed["failed"], 0, "bad YAML is filtered (not a failure)");
    assert_eq!(
        parsed["succeeded"], 1,
        "good Jamf YAML imports successfully"
    );
}
