//! Procedural SOP — trap-counter integration suite.
//!
//! Each test exercises one **agent trap** documented in the procedural SOP
//! format spec at:
//!   `crates/contour-core/skills/contour/references/sop-format-spec.md`
//!
//! A "trap" is a CLI behavior that an agent following a prose SOP could easily
//! miss but that the procedural SOP catches by design — via a PRECONDITION,
//! POSTCONDITION, INPUT contract, or branch in EXECUTION.
//!
//! ## What this suite measures
//!
//! - **SOP-vs-CLI parity**: every trap should pass; failure means either
//!   (a) the CLI changed and the SOP needs updating, or (b) the SOP is wrong
//!   and the CLI is right.
//! - **Drift detector**: run on every `cargo test`. Catches CLI output-format
//!   changes (rename a JSON field, change exit codes) before they break agents.
//! - **Effectiveness signal**: as more SOPs migrate to the procedural format
//!   (Phase 3 of the migration plan), each new procedure adds traps here.
//!   Trap count = number of agent failure modes the format catches by design.
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
use base64::Engine;
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
// the explicit value. The procedural SOP enforces this at the agent layer
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
// match prose. The procedural SOPs use the SWITCH-on-error_code pattern; this
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
// SOP context: procedural SOPs treat failure paths as JSON; without B3, the
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

// ─────────────────────────────────────────────────────────────────────────────
// Trap 13: deprecated payload `com.apple.SoftwareUpdate` has DDM-native
//          replacements registered in the embedded schema.
// Pilot procedure: create_ddm_config / DEPRECATED_LIST + PRECONDITIONS
// Catches: agents that keep generating the legacy profile payload — broken
// on macOS Tahoe (26/27) where the legacy SoftwareUpdate payload is removed.
// The procedural SOP redirects to the DDM replacements, but only if those types
// exist in the registered DDM schema. This trap pins their existence.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_13_ddm_softwareupdate_replacements_exist() {
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["ddm", "list", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "ddm list must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value =
        serde_json::from_str(stdout.trim()).expect("ddm list --json must emit a JSON array");
    let entries = parsed.as_array().expect("ddm list returns an array");

    let has_type = |needle: &str| -> bool {
        entries
            .iter()
            .any(|e| e.get("type").and_then(|t| t.as_str()) == Some(needle))
    };

    assert!(
        has_type("com.apple.configuration.softwareupdate.settings"),
        "DDM softwareupdate.settings must be registered (replacement for legacy com.apple.SoftwareUpdate payload)"
    );
    assert!(
        has_type("com.apple.configuration.softwareupdate.enforcement.specific"),
        "DDM softwareupdate.enforcement.specific must be registered (companion to .settings)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 14: `ddm generate` writes ServerToken-free declarations.
// Pilot procedure: create_ddm_config / INVARIANTS
// Catches: regressions that start authoring ServerToken — that field is
// server-managed and writing it locally causes deploy collisions.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_14_ddm_generate_omits_server_token() {
    let dir = tempfile::tempdir().unwrap();
    // ddm generate requires org via .contour/config.toml
    let contour_dir = dir.path().join(".contour");
    fs::create_dir_all(&contour_dir).unwrap();
    fs::write(
        contour_dir.join("config.toml"),
        "[organization]\ndomain = \"com.acme\"\nname = \"Acme\"\n",
    )
    .unwrap();

    let out = dir.path().join("decl.json");
    let result = Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "ddm",
            "generate",
            "com.apple.configuration.passcode.settings",
            "-o",
            out.to_str().unwrap(),
            "--full",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "ddm generate must succeed; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let body = fs::read_to_string(&out).unwrap();
    let parsed: Value = serde_json::from_str(&body).expect("declaration must be valid JSON");

    assert!(
        parsed.get("ServerToken").is_none(),
        "authored declaration must NOT contain ServerToken; it is added by the MDM server. \
         Found: {:?}",
        parsed.get("ServerToken")
    );
    // Sanity check: the keys we DO expect are present.
    assert!(parsed.get("Type").is_some(), "Type field is present");
    assert!(parsed.get("Identifier").is_some(), "Identifier is present");
    assert!(parsed.get("Payload").is_some(), "Payload is present");
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 15: `ddm generate` builds Identifier as `{org}.{type-tail}`, which
//          collides for any two types ending in the same segment
//          (e.g. *.settings, *.simple). Agents must rename emitted
//          identifiers before assembling a multi-component DDM set.
// Pilot procedure: create_ddm_config / STEP 2 (identifier choice)
// Catches: regressions that change the identifier-building scheme silently.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_15_ddm_generate_identifier_uses_type_tail() {
    let dir = tempfile::tempdir().unwrap();
    let contour_dir = dir.path().join(".contour");
    fs::create_dir_all(&contour_dir).unwrap();
    fs::write(
        contour_dir.join("config.toml"),
        "[organization]\ndomain = \"com.acme\"\nname = \"Acme\"\n",
    )
    .unwrap();

    // Generate two configurations whose types both end in `.settings`.
    let cases = [
        (
            "com.apple.configuration.passcode.settings",
            dir.path().join("passcode.json"),
        ),
        (
            "com.apple.configuration.softwareupdate.settings",
            dir.path().join("softwareupdate.json"),
        ),
    ];
    for (type_name, out) in &cases {
        let result = Command::cargo_bin("profile")
            .unwrap()
            .current_dir(dir.path())
            .args([
                "ddm",
                "generate",
                type_name,
                "-o",
                out.to_str().unwrap(),
                "--full",
                "--json",
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "ddm generate {type_name} must succeed; stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    let id_for = |path: &std::path::Path| -> String {
        let body = fs::read_to_string(path).unwrap();
        let parsed: Value = serde_json::from_str(&body).unwrap();
        parsed["Identifier"].as_str().unwrap().to_string()
    };
    let passcode_id = id_for(&cases[0].1);
    let softwareupdate_id = id_for(&cases[1].1);

    // Both end in `.settings`, so type-tail-based identifier generation
    // produces collision: passcode_id == softwareupdate_id == "com.acme.settings".
    // The procedural SOP's STEP 2 mandates agents override this default.
    assert_eq!(
        passcode_id, "com.acme.settings",
        "passcode identifier follows {{org}}.{{type-tail}} pattern"
    );
    assert_eq!(
        softwareupdate_id, "com.acme.settings",
        "softwareupdate identifier follows {{org}}.{{type-tail}} pattern \
         — collides with passcode (this is the trap; SOP requires agents override)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Compose traps (31–35) — pin the contract for `ddm compose <bundle.toml>`,
// the combined-format generator that replaces the manual asset →
// configuration → activation orchestration documented in the procedural
// SOP's `create_ddm_config` PROCEDURE. By construction, dangling references
// and identifier collisions become impossible; these traps pin that
// guarantee so future schema changes can't drift the contract.
// ─────────────────────────────────────────────────────────────────────────────

/// Helper: write a profile.toml with the given org domain in `dir`.
fn write_profile_toml(dir: &std::path::Path, domain: &str) {
    let contour_dir = dir.join(".contour");
    fs::create_dir_all(&contour_dir).unwrap();
    fs::write(
        contour_dir.join("config.toml"),
        format!("[organization]\ndomain = \"{domain}\"\nname = \"Acme\"\n"),
    )
    .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 31: `ddm compose` wires the asset reference into the configuration's
//          `*AssetReference` field — by construction, no dangling refs.
// Pilot procedure: create_ddm_config / STEP 3b (now collapsed into compose)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_31_ddm_compose_wires_asset_reference() {
    let dir = tempfile::tempdir().unwrap();
    write_profile_toml(dir.path(), "com.acme");

    let bundle = dir.path().join("bundle.toml");
    // Exchange configuration has multiple *AssetReference fields, so the
    // bundle MUST disambiguate via asset_ref_field. This is realistic agent
    // usage — when the schema is ambiguous, the bundle declares its choice.
    fs::write(
        &bundle,
        r#"intent_name = "exchange"

[asset]
type = "com.apple.asset.credential.userpassword"

[asset.payload]
Username = "user@example.com"

[configuration]
type = "com.apple.configuration.account.exchange"
asset_ref_field = "AuthenticationCredentialsAssetReference"

[configuration.payload]
HostName = "outlook.example.com"

[activation]
"#,
    )
    .unwrap();

    let out = dir.path().join("out");
    let result = Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--json",
            "ddm",
            "compose",
            bundle.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "compose must succeed; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let asset_id =
        serde_json::from_str::<Value>(&fs::read_to_string(out.join("asset.json")).unwrap())
            .unwrap()["Identifier"]
            .as_str()
            .unwrap()
            .to_string();
    let config: Value =
        serde_json::from_str(&fs::read_to_string(out.join("configuration.json")).unwrap()).unwrap();

    // Compose wired the explicit asset_ref_field with the asset identifier —
    // no editing required. Verifies the cross-file reference invariant
    // holds by construction.
    assert_eq!(
        config["Payload"]["AuthenticationCredentialsAssetReference"]
            .as_str()
            .unwrap(),
        asset_id,
        "configuration must reference asset identifier verbatim"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 32: `ddm compose` populates `Payload.StandardConfigurations` on the
//          activation with the configuration's identifier.
// Pilot procedure: create_ddm_config / STEP 3c (now collapsed into compose)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_32_ddm_compose_wires_standard_configurations() {
    let dir = tempfile::tempdir().unwrap();
    write_profile_toml(dir.path(), "com.acme");

    let bundle = dir.path().join("bundle.toml");
    fs::write(
        &bundle,
        r#"intent_name = "passcode"

[configuration]
type = "com.apple.configuration.passcode.settings"

[configuration.payload]
MinimumLength = 8

[activation]
predicate = "@status(passcode-compliance.compliant) == false"
"#,
    )
    .unwrap();

    let out = dir.path().join("out");
    let result = Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--json",
            "ddm",
            "compose",
            bundle.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "compose must succeed; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let config_id =
        serde_json::from_str::<Value>(&fs::read_to_string(out.join("configuration.json")).unwrap())
            .unwrap()["Identifier"]
            .as_str()
            .unwrap()
            .to_string();
    let activation: Value =
        serde_json::from_str(&fs::read_to_string(out.join("activation.json")).unwrap()).unwrap();

    let std_configs = activation["Payload"]["StandardConfigurations"]
        .as_array()
        .expect("StandardConfigurations is an array");
    assert_eq!(std_configs.len(), 1, "single configuration ref");
    assert_eq!(
        std_configs[0].as_str().unwrap(),
        config_id,
        "activation references configuration identifier verbatim"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 33: `ddm compose` rejects bundles whose configuration has multiple
//          `*AssetReference` fields without an explicit `asset_ref_field`.
// Pilot procedure: create_ddm_config / STEP 2
// Catches: an agent invokes compose for a multi-credential type (Mail
// account has Incoming + Outgoing credentials) without disambiguating; the
// CLI must refuse before any file lands on disk.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_33_ddm_compose_rejects_ambiguous_asset_ref() {
    // Find a configuration type with >=2 *AssetReference fields in the
    // embedded schema. If none exists today, the trap is informational and
    // exits 0 — fixing this requires schema changes upstream.
    let registry = profile::schema::SchemaRegistry::embedded().expect("embedded registry loads");
    let multi = registry
        .by_category("ddm-configuration")
        .into_iter()
        .find(|m| {
            m.fields
                .keys()
                .filter(|k| k.ends_with("AssetReference"))
                .count()
                >= 2
        });
    let Some(multi) = multi else {
        eprintln!(
            "trap_33: no configuration type in the embedded schema has >=2 \
             *AssetReference fields; AmbiguousAssetRef path is unit-tested in \
             ddm::compose::tests::compose_rejects_ambiguous_asset_ref"
        );
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    write_profile_toml(dir.path(), "com.acme");

    let bundle = dir.path().join("bundle.toml");
    let asset_type = registry
        .by_category("ddm-asset")
        .first()
        .map(|m| m.payload_type.clone())
        .expect("at least one asset type registered");
    fs::write(
        &bundle,
        format!(
            r#"intent_name = "ambig"

[asset]
type = "{asset_type}"

[configuration]
type = "{config_type}"
"#,
            config_type = multi.payload_type,
        ),
    )
    .unwrap();

    let out = dir.path().join("out");
    let result = Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--json",
            "ddm",
            "compose",
            bundle.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "compose must refuse ambiguous asset_ref"
    );

    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("SCHEMA_VIOLATION"),
        "stderr must include error_code SCHEMA_VIOLATION; got: {stderr}"
    );

    // Atomicity: no files emitted on failure.
    assert!(
        !out.join("asset.json").exists(),
        "no files should be written on compose failure"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 34: extends trap_14's ServerToken guarantee to the bundle path —
//          `ddm compose` must NOT author ServerToken on any emitted
//          declaration.
// Pilot procedure: create_ddm_config / INVARIANTS
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_34_ddm_compose_emits_no_server_token() {
    let dir = tempfile::tempdir().unwrap();
    write_profile_toml(dir.path(), "com.acme");

    let bundle = dir.path().join("bundle.toml");
    fs::write(
        &bundle,
        r#"intent_name = "no-token"

[configuration]
type = "com.apple.configuration.passcode.settings"

[configuration.payload]
MinimumLength = 8

[activation]
"#,
    )
    .unwrap();

    let out = dir.path().join("out");
    let result = Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--json",
            "ddm",
            "compose",
            bundle.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "compose must succeed; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    for filename in ["configuration.json", "activation.json"] {
        let body = fs::read_to_string(out.join(filename)).unwrap();
        assert!(
            !body.contains("\"ServerToken\""),
            "{filename}: compose must NOT author ServerToken (server-managed field)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 35: `ddm compose` rejects orphan assets by default; `--allow-orphans`
//          opts out. Catches bundles that declare an asset the configuration
//          has nowhere to wire to.
// Pilot procedure: create_ddm_config / INVARIANTS (orphan section)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_35_ddm_compose_strict_orphan_default() {
    let dir = tempfile::tempdir().unwrap();
    write_profile_toml(dir.path(), "com.acme");

    let bundle = dir.path().join("bundle.toml");
    fs::write(
        &bundle,
        r#"intent_name = "orphan"

[asset]
type = "com.apple.asset.credential.userpassword"

[configuration]
type = "com.apple.configuration.passcode.settings"

[configuration.payload]
MinimumLength = 8
"#,
    )
    .unwrap();

    // Strict mode (default): MissingAssetRef fires (passcode.settings has no
    // *AssetReference field), which is the structural manifestation of an
    // orphan asset. The check happens before any I/O.
    let out = dir.path().join("out");
    let strict = Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--json",
            "ddm",
            "compose",
            bundle.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!strict.status.success(), "strict mode rejects orphan asset");
    let stderr = String::from_utf8_lossy(&strict.stderr);
    assert!(
        stderr.contains("SCHEMA_VIOLATION"),
        "stderr includes SCHEMA_VIOLATION; got: {stderr}"
    );

    // No files on disk — atomic failure.
    assert!(
        !out.join("asset.json").exists() && !out.join("configuration.json").exists(),
        "compose failure leaves no files behind"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2 traps (36–39): predicate ↔ status-subscription cross-validation.
//
// Apple's DDM spec defines two distinct predicate failure modes:
//   - Error.PredicateFailed         — evaluated cleanly to false (gating)
//   - Error.UnableToEvaluatePredicate — couldn't evaluate (e.g., a referenced
//                                       @status('key') isn't subscribed)
// The second is an authoring bug that ships clean and breaks at deploy.
// `compose` PRECONDITION + `ddm verify` directory-level cross-check pin
// this so it can't drift.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Trap 36: `ddm compose` rejects a bundle whose activation predicate
//          references a status key that the bundle's [subscriptions].keys
//          list does not cover.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_36_compose_rejects_unsubscribed_status_key() {
    let dir = tempfile::tempdir().unwrap();
    write_profile_toml(dir.path(), "com.acme");

    let bundle = dir.path().join("bundle.toml");
    fs::write(
        &bundle,
        r#"intent_name = "miss-sub"

[configuration]
type = "com.apple.configuration.passcode.settings"

[configuration.payload]
MinimumLength = 8

[activation]
predicate = "@status('passcode.is-compliant') == TRUE"
"#,
    )
    .unwrap();

    let out = dir.path().join("out");
    let result = Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--json",
            "ddm",
            "compose",
            bundle.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "compose must reject unsubscribed status key"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("SCHEMA_VIOLATION"),
        "stderr includes SCHEMA_VIOLATION; got: {stderr}"
    );
    assert!(
        stderr.contains("passcode.is-compliant"),
        "error names the missing key"
    );
    assert!(
        !out.join("configuration.json").exists() && !out.join("activation.json").exists(),
        "compose failure leaves no files behind"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 37: `ddm compose` with a [subscriptions] section emits a fourth
//          declaration file `status-subscriptions.json` whose
//          Payload.StatusItems list matches the declared keys.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_37_compose_emits_status_subscriptions_file() {
    let dir = tempfile::tempdir().unwrap();
    write_profile_toml(dir.path(), "com.acme");

    let bundle = dir.path().join("bundle.toml");
    fs::write(
        &bundle,
        r#"intent_name = "with-sub"

[configuration]
type = "com.apple.configuration.passcode.settings"

[configuration.payload]
MinimumLength = 8

[activation]
predicate = "@status('passcode.is-compliant') == TRUE"

[subscriptions]
keys = ["passcode.is-compliant"]
"#,
    )
    .unwrap();

    let out = dir.path().join("out");
    let result = Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--json",
            "ddm",
            "compose",
            bundle.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(result.status.success(), "compose must succeed");

    let subs_path = out.join("status-subscriptions.json");
    assert!(subs_path.exists(), "status-subscriptions.json emitted");

    let subs: Value = serde_json::from_str(&fs::read_to_string(&subs_path).unwrap()).unwrap();
    assert_eq!(
        subs["Type"].as_str().unwrap(),
        "com.apple.configuration.management.status-subscriptions"
    );
    let items = subs["Payload"]["StatusItems"]
        .as_array()
        .expect("StatusItems is an array");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["Name"].as_str().unwrap(),
        "passcode.is-compliant",
        "StatusItems[].Name carries the subscribed key per Apple's schema"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 38: `ddm verify <dir>` finds an activation predicate that references
//          a key not covered by any status-subscriptions in the directory.
//          Hand-author a directory of declarations missing the subscription
//          and assert verify exits non-zero with UnsubscribedStatusKey.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_38_verify_finds_unsubscribed_predicate_key_in_directory() {
    let dir = tempfile::tempdir().unwrap();
    let decls = dir.path().join("decls");
    fs::create_dir_all(&decls).unwrap();

    fs::write(
        decls.join("configuration.json"),
        r#"{
            "Type": "com.apple.configuration.passcode.settings",
            "Identifier": "com.acme.config.x",
            "Payload": { "MinimumLength": 8 }
        }"#,
    )
    .unwrap();
    fs::write(
        decls.join("activation.json"),
        r#"{
            "Type": "com.apple.activation.simple",
            "Identifier": "com.acme.activation.x",
            "Payload": {
                "StandardConfigurations": ["com.acme.config.x"],
                "Predicate": "@status('passcode.is-compliant') == TRUE"
            }
        }"#,
    )
    .unwrap();

    let result = Command::cargo_bin("profile")
        .unwrap()
        .args(["--json", "ddm", "verify", decls.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "verify must fail when predicate key is unsubscribed"
    );

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("verify --json emits JSON");
    assert_eq!(parsed["success"], false);
    let errs = parsed["errors"].as_array().expect("errors array");
    let unsubscribed = errs
        .iter()
        .find(|e| e["kind"] == "UnsubscribedStatusKey")
        .expect("UnsubscribedStatusKey error present");
    assert_eq!(
        unsubscribed["key"].as_str().unwrap(),
        "passcode.is-compliant"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 40: `CONTOUR_ORG` env var is honored by `ddm compose` and `ddm
//          generate` — pinned because both handlers initially shipped
//          with only profile.toml + .contour/config.toml resolution,
//          breaking CI workflows that set CONTOUR_ORG. Resolution order:
//          profile.toml → CONTOUR_ORG → .contour/config.toml.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_40_ddm_compose_honors_contour_org_env() {
    let dir = tempfile::tempdir().unwrap();
    // No profile.toml, no .contour/config.toml — only CONTOUR_ORG.
    let bundle = dir.path().join("bundle.toml");
    fs::write(
        &bundle,
        r#"intent_name = "env-test"

[configuration]
type = "com.apple.configuration.passcode.settings"

[configuration.payload]
MinimumLength = 8
"#,
    )
    .unwrap();

    let out = dir.path().join("out");
    let result = Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir.path())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("CONTOUR_ORG", "com.envacme")
        .args([
            "--json",
            "ddm",
            "compose",
            bundle.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "compose with CONTOUR_ORG must succeed; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let cfg: Value =
        serde_json::from_str(&fs::read_to_string(out.join("configuration.json")).unwrap()).unwrap();
    assert_eq!(
        cfg["Identifier"].as_str().unwrap(),
        "com.envacme.config.env-test",
        "Identifier reflects CONTOUR_ORG env var, not a hardcoded fallback"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 39: `ddm verify <dir>` exits 0 on a clean directory — configuration
//          + activation + matching status-subscriptions all wired correctly.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_39_verify_passes_clean_directory() {
    let dir = tempfile::tempdir().unwrap();
    let decls = dir.path().join("decls");
    fs::create_dir_all(&decls).unwrap();

    fs::write(
        decls.join("configuration.json"),
        r#"{
            "Type": "com.apple.configuration.passcode.settings",
            "Identifier": "com.acme.config.x",
            "Payload": { "MinimumLength": 8 }
        }"#,
    )
    .unwrap();
    fs::write(
        decls.join("activation.json"),
        r#"{
            "Type": "com.apple.activation.simple",
            "Identifier": "com.acme.activation.x",
            "Payload": {
                "StandardConfigurations": ["com.acme.config.x"],
                "Predicate": "@status('passcode.is-compliant') == TRUE"
            }
        }"#,
    )
    .unwrap();
    fs::write(
        decls.join("status-subscriptions.json"),
        r#"{
            "Type": "com.apple.configuration.management.status-subscriptions",
            "Identifier": "com.acme.subscriptions.x",
            "Payload": {
                "StatusItems": [{"Name": "passcode.is-compliant"}]
            }
        }"#,
    )
    .unwrap();

    let result = Command::cargo_bin("profile")
        .unwrap()
        .args(["--json", "ddm", "verify", decls.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "verify on a clean directory must succeed; stdout: {}",
        String::from_utf8_lossy(&result.stdout)
    );

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("verify --json emits JSON");
    assert_eq!(parsed["success"], true);
    assert_eq!(parsed["errors"].as_array().unwrap().len(), 0);
    // No warnings either — config IS referenced by activation, subscription IS used.
    assert_eq!(parsed["warnings"].as_array().unwrap().len(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 41: `profile generate --recipe` produces byte-identical output across
//          independent process invocations. Each Rust process gets a fresh
//          HashMap hasher seed, so iterating a HashMap to build the plist
//          produces non-deterministic key order — semantically harmless
//          (Apple parses dicts by key, not position) but creates spurious
//          diff churn on every CI regen. Pinned by switching ProfileSpec
//          fields to BTreeMap; this trap fires if anyone reverts that.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_41_recipe_generation_is_byte_stable() {
    let dir = tempfile::tempdir().unwrap();
    write_profile_toml_for_org(dir.path(), "com.acme", "Acme");

    let mut hashes: Vec<Vec<u8>> = Vec::new();
    for run_idx in 0..3 {
        let run_dir = dir.path().join(format!("run{run_idx}"));
        fs::create_dir_all(&run_dir).unwrap();

        let result = Command::cargo_bin("profile")
            .unwrap()
            .current_dir(dir.path())
            .args([
                "generate",
                "--recipe",
                "okta",
                "--set",
                "OKTA_DOMAIN=acme.okta.com",
                "--set",
                "REGISTRATION_TOKEN=tok",
                "--set",
                "SCEP_CHALLENGE=ch",
                "-o",
                run_dir.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "recipe generation must succeed; stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );

        // Concatenate every emitted file in lexicographic order so we get a
        // stable digest of the whole bundle.
        let mut entries: Vec<_> = fs::read_dir(&run_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        entries.sort();
        let mut buf = Vec::new();
        for path in &entries {
            buf.extend_from_slice(&fs::read(path).unwrap());
        }
        assert!(!buf.is_empty(), "recipe must emit at least one file");
        hashes.push(buf);
    }

    assert_eq!(hashes[0], hashes[1], "run 0 and 1 must be byte-identical");
    assert_eq!(hashes[1], hashes[2], "run 1 and 2 must be byte-identical");
}

/// Helper: write a profile.toml-equivalent .contour/config.toml in `dir`.
fn write_profile_toml_for_org(dir: &std::path::Path, domain: &str, name: &str) {
    let contour_dir = dir.join(".contour");
    fs::create_dir_all(&contour_dir).unwrap();
    fs::write(
        contour_dir.join("config.toml"),
        format!("[organization]\nname = \"{name}\"\ndomain = \"{domain}\"\n"),
    )
    .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1 lint traps (42–46): per-violation fixtures pin that each named
// lint check fires on its own fixture (positive case) and that the clean
// baseline never trips any of them (negative case).
//
// Per-violation accountability is the whole point — combined-violation
// fixtures hide which tier caught what. The fixtures live under
// `crates/profile/tests/fixtures/lint/` and are named after the check
// they trigger.
// ─────────────────────────────────────────────────────────────────────────────

fn lint_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("lint")
        .join(format!("{name}.mobileconfig"))
}

/// Run validate against a fixture and return the parsed JSON envelope's
/// `lint_findings` array. Single-file path → `lint_findings` is at the
/// top level of the JSON object.
fn lint_findings_for(fixture: &str) -> Vec<Value> {
    let path = lint_fixture_path(fixture);
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["validate", path.to_str().unwrap(), "--no-schema", "--json"])
        .output()
        .unwrap();
    // exit code may be non-zero (e.g. duplicate-uuid is an error) — that's fine.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("validate --json emits JSON");
    parsed["lint_findings"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[test]
fn trap_42_lint_duplicate_payload_uuid_fires_only_on_its_fixture() {
    let findings = lint_findings_for("duplicate-payload-uuid");
    let names: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["check"].as_str())
        .collect();
    assert!(
        names.contains(&"duplicate-payload-uuid"),
        "expected duplicate-payload-uuid finding; got {names:?}"
    );

    let clean = lint_findings_for("clean");
    assert!(
        !clean.iter().any(|f| f["check"] == "duplicate-payload-uuid"),
        "clean baseline must not trip duplicate-payload-uuid"
    );
}

#[test]
fn trap_43_lint_payload_version_type_fires_only_on_its_fixture() {
    let findings = lint_findings_for("payload-version-type");
    let names: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["check"].as_str())
        .collect();
    assert!(
        names.contains(&"payload-version-type"),
        "expected payload-version-type finding; got {names:?}"
    );
    let clean = lint_findings_for("clean");
    assert!(
        !clean.iter().any(|f| f["check"] == "payload-version-type"),
        "clean baseline must not trip payload-version-type"
    );
}

#[test]
fn trap_44_lint_placeholder_payload_uuid_fires_only_on_its_fixture() {
    let findings = lint_findings_for("placeholder-payload-uuid");
    let names: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["check"].as_str())
        .collect();
    assert!(
        names.contains(&"placeholder-payload-uuid"),
        "expected placeholder-payload-uuid finding; got {names:?}"
    );
    let clean = lint_findings_for("clean");
    assert!(
        !clean
            .iter()
            .any(|f| f["check"] == "placeholder-payload-uuid"),
        "clean baseline must not trip placeholder-payload-uuid"
    );
}

#[test]
fn trap_45_lint_deprecated_payload_type_fires_only_on_its_fixture() {
    let findings = lint_findings_for("deprecated-payload-type");
    let names: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["check"].as_str())
        .collect();
    assert!(
        names.contains(&"deprecated-payload-type"),
        "expected deprecated-payload-type finding; got {names:?}"
    );
    let clean = lint_findings_for("clean");
    assert!(
        !clean
            .iter()
            .any(|f| f["check"] == "deprecated-payload-type"),
        "clean baseline must not trip deprecated-payload-type"
    );
}

#[test]
fn trap_46_lint_clean_baseline_has_no_findings() {
    // Independent gate: the clean baseline must produce ZERO lint
    // findings. If a future check starts firing on clean, either the
    // check is wrong or the baseline needs updating — both worth
    // surfacing loudly.
    let clean = lint_findings_for("clean");
    assert!(
        clean.is_empty(),
        "clean baseline must have no lint findings; got {clean:?}"
    );
}

#[test]
fn trap_68_ddm_compose_preset_works_without_source_tree() {
    // End-user UX: ddm compose --preset <NAME> --org <ORG> composes
    // entirely from embedded TOML — no source-tree path, no env vars,
    // no .contour/config.toml needed. Drift signal: preset name change
    // or embedded TOML failing to parse as a Bundle.
    let out = tempfile::tempdir().unwrap();
    let result = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "ddm",
            "compose",
            "--preset",
            "disable-apple-intelligence-macos",
            "--org",
            "com.acme",
            "-o",
            out.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "preset compose with --org must succeed without env or config; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let parsed: Value = serde_json::from_slice(&result.stdout).expect("JSON");
    assert_eq!(parsed["success"], true);
    assert!(out.path().join("configuration.json").exists());
    assert!(out.path().join("activation.json").exists());

    // Verify --org actually scoped the configuration identifier.
    let config_json: Value =
        serde_json::from_slice(&fs::read(out.path().join("configuration.json")).unwrap()).unwrap();
    let id = config_json["Identifier"].as_str().unwrap();
    assert!(
        id.starts_with("com.acme."),
        "configuration identifier must start with --org prefix; got {id}"
    );
}

#[test]
fn trap_69_ddm_compose_list_presets_advertises_known_presets() {
    let result = Command::cargo_bin("profile")
        .unwrap()
        .args(["ddm", "compose", "--list-presets", "--json"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let parsed: Value = serde_json::from_slice(&result.stdout).expect("JSON");
    let arr = parsed.as_array().expect("array");
    let names: Vec<&str> = arr.iter().filter_map(|e| e["name"].as_str()).collect();
    assert!(names.contains(&"disable-apple-intelligence-macos"));
    assert!(names.contains(&"disable-apple-intelligence-ios"));
}

#[test]
fn trap_70_ddm_compose_unknown_preset_errors_with_valid_list() {
    let result = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "ddm",
            "compose",
            "--preset",
            "bogus-not-a-preset",
            "-o",
            "/tmp/x",
        ])
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "unknown preset must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("Unknown --preset 'bogus-not-a-preset'"),
        "stderr should name the contract; got: {stderr}"
    );
    assert!(stderr.contains("disable-apple-intelligence-macos"));
}

#[test]
fn trap_67_single_instance_payload_repeated_fires_on_real_apply_mode_single() {
    // End-to-end: per-violation fixture has com.apple.NetworkBrowser
    // (apply_mode=single in the embedded parquet) listed twice. The
    // lint must fire at warning severity. If apply_mode parsing breaks
    // upstream or the registry stops carrying single-mode payloads,
    // this trap fails first.
    let findings = lint_findings_for("single-instance-payload-repeated");
    let names: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["check"].as_str())
        .collect();
    assert!(
        names.contains(&"single-instance-payload-repeated"),
        "expected single-instance-payload-repeated; got {names:?}"
    );
    let sev = findings
        .iter()
        .find(|f| f["check"] == "single-instance-payload-repeated")
        .and_then(|f| f["severity"].as_str());
    assert_eq!(sev, Some("warning"), "must be warning severity");

    // Clean baseline never trips the new check.
    let clean = lint_findings_for("clean");
    assert!(
        !clean
            .iter()
            .any(|f| f["check"] == "single-instance-payload-repeated"),
        "clean baseline must not trip single-instance-payload-repeated"
    );
}

#[test]
fn trap_52_lint_nested_missing_payload_version_fires_only_on_its_fixture() {
    // Tier-1 default-on check: a nested payload missing the literal
    // PayloadVersion key fires `nested-missing-payload-version` at
    // error severity. Real-world Fleet repos have ~80+ files with
    // this drift; the structural validator can't see it because the
    // serde deserializer silently defaults the missing field.
    let findings = lint_findings_for("nested-missing-payload-version");
    let names: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["check"].as_str())
        .collect();
    assert!(
        names.contains(&"nested-missing-payload-version"),
        "expected nested-missing-payload-version finding; got {names:?}"
    );
    let sev = findings
        .iter()
        .find(|f| f["check"] == "nested-missing-payload-version")
        .and_then(|f| f["severity"].as_str());
    assert_eq!(sev, Some("error"), "must be error severity");

    let clean = lint_findings_for("clean");
    assert!(
        !clean
            .iter()
            .any(|f| f["check"] == "nested-missing-payload-version"),
        "clean baseline must not trip nested-missing-payload-version"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// --lint-policy traps (47–51): the opt-in surface for Tier-2
// (org-policy) lint checks. `validate` defaults to Apple-schema only;
// `--lint-policy` adds authoring-convention checks on top.
// ─────────────────────────────────────────────────────────────────────────────

/// Variant of `lint_findings_for` that runs validate with extra args
/// (for `--lint-policy …` and/or `--strict`).
fn lint_findings_with_args(fixture: &str, extra_args: &[&str]) -> Vec<Value> {
    let path = lint_fixture_path(fixture);
    let mut args = vec!["validate", path.to_str().unwrap(), "--no-schema", "--json"];
    args.extend_from_slice(extra_args);
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(&args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("validate --json emits JSON");
    parsed["lint_findings"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[test]
fn trap_47_default_validate_does_not_fire_tier_2() {
    // The architectural contract: `validate` (no flag) is Apple-schema
    // only. Even on a fixture that would trigger every Tier-2 check,
    // none should appear in lint_findings without `--lint-policy`.
    let names: Vec<String> = lint_findings_for("payload-identifier-reverse-dns")
        .iter()
        .filter_map(|f| f["check"].as_str().map(str::to_string))
        .collect();
    for tier_2 in [
        "payload-identifier-reverse-dns",
        "payload-organization-required",
        "payload-scope-consistency",
        "nested-payload-identifier-prefix",
    ] {
        assert!(
            !names.iter().any(|n| n == tier_2),
            "Tier-2 check {tier_2} fired in default validate; got {names:?}"
        );
    }
}

#[test]
fn trap_48_lint_policy_named_check_fires_only_that_check() {
    // Single explicit name → exactly that Tier-2 check fires; the
    // other three stay silent even on a fixture they would trigger.
    let findings = lint_findings_with_args(
        "payload-identifier-reverse-dns",
        &["--lint-policy", "payload-identifier-reverse-dns"],
    );
    let names: Vec<String> = findings
        .iter()
        .filter_map(|f| f["check"].as_str().map(str::to_string))
        .collect();
    assert!(
        names.iter().any(|n| n == "payload-identifier-reverse-dns"),
        "expected payload-identifier-reverse-dns; got {names:?}"
    );
    for other in [
        "payload-organization-required",
        "payload-scope-consistency",
        "nested-payload-identifier-prefix",
    ] {
        assert!(
            !names.iter().any(|n| n == other),
            "non-selected Tier-2 {other} must not fire; got {names:?}"
        );
    }
}

#[test]
fn trap_49_lint_policy_all_fires_every_tier_2_check_on_matching_fixture() {
    // `--lint-policy all` enables every Tier-2 check. On a fixture
    // crafted to trip all four, all four should appear.
    let mut profile = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("lint");
    profile.push("all-tier-2.mobileconfig");
    fs::write(
        &profile,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadType</key><string>Configuration</string>
    <key>PayloadVersion</key><integer>1</integer>
    <key>PayloadIdentifier</key><string>BareIdentifier</string>
    <key>PayloadUUID</key><string>A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D</string>
    <key>PayloadDisplayName</key><string>All Tier-2</string>
    <key>PayloadScope</key><string>User</string>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key><string>com.apple.MCXFileVault2</string>
            <key>PayloadVersion</key><integer>1</integer>
            <key>PayloadIdentifier</key><string>com.othervendor.fv</string>
            <key>PayloadUUID</key><string>B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E</string>
        </dict>
    </array>
</dict>
</plist>"#,
    )
    .unwrap();
    let findings = lint_findings_with_args("all-tier-2", &["--lint-policy", "all"]);
    let names: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["check"].as_str())
        .collect();
    for required in [
        "payload-identifier-reverse-dns",
        "payload-organization-required",
        "payload-scope-consistency",
        "nested-payload-identifier-prefix",
    ] {
        assert!(
            names.contains(required),
            "expected {required} in --lint-policy all output; got {names:?}"
        );
    }
    let _ = fs::remove_file(&profile);
}

#[test]
fn trap_50_lint_policy_unknown_name_errors_with_valid_list() {
    let path = lint_fixture_path("clean");
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "validate",
            path.to_str().unwrap(),
            "--no-schema",
            "--lint-policy",
            "bogus-not-a-real-check",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "unknown --lint-policy name must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown --lint-policy check"),
        "stderr should name the contract; got: {stderr}"
    );
    assert!(
        stderr.contains("bogus-not-a-real-check"),
        "stderr should echo the bad name"
    );
    assert!(stderr.contains("all"), "stderr should list 'all' as valid");
    assert!(
        stderr.contains("payload-identifier-reverse-dns"),
        "stderr should list valid Tier-2 names"
    );
}

#[test]
fn trap_51_strict_promotes_tier_2_warning_to_error_when_selected() {
    // Tier-2 is opt-in; `--strict` is severity-only (does NOT widen the
    // check set). When both are set, the selected Tier-2 warning is
    // promoted to error.
    let warn = lint_findings_with_args(
        "payload-identifier-reverse-dns",
        &["--lint-policy", "payload-identifier-reverse-dns"],
    );
    let warn_sev = warn
        .iter()
        .find(|f| f["check"] == "payload-identifier-reverse-dns")
        .and_then(|f| f["severity"].as_str())
        .map(str::to_string);
    assert_eq!(warn_sev.as_deref(), Some("warning"));

    let err = lint_findings_with_args(
        "payload-identifier-reverse-dns",
        &[
            "--lint-policy",
            "payload-identifier-reverse-dns",
            "--strict",
        ],
    );
    let err_sev = err
        .iter()
        .find(|f| f["check"] == "payload-identifier-reverse-dns")
        .and_then(|f| f["severity"].as_str())
        .map(str::to_string);
    assert_eq!(err_sev.as_deref(), Some("error"));
}

// ─────────────────────────────────────────────────────────────────────────────
// info / docs ergonomics traps (53–55): direct schema lookup without
// disk I/O. `profile info <type>` mirrors `profile ddm info <name>`,
// returning every field's plist tag so agents can answer "what type
// does Apple expect for <key> in <payload>?" in one CLI call. The
// `--stdout` flag on `docs generate` removes the file-write detour.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn trap_53_info_returns_plist_tag_for_known_field() {
    // The motivating use case: an agent checks the type of
    // `safariAcceptCookies` in `com.apple.applicationaccess`. Apple
    // specs it as <real> (counterintuitive — values look enum-shaped).
    // The info command must surface that exact plist tag.
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["info", "com.apple.applicationaccess", "--full", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "info <type> must exit 0 on known type"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("info --json emits JSON");
    let fields = parsed["fields"].as_array().expect("fields is an array");
    let safari = fields
        .iter()
        .find(|f| f["name"] == "safariAcceptCookies")
        .expect("safariAcceptCookies must be present in com.apple.applicationaccess");
    assert_eq!(
        safari["plist_tag"], "real",
        "Apple specs safariAcceptCookies as <real>; agent must see that exact tag"
    );
}

#[test]
fn trap_54_info_unknown_payload_type_errors_with_hint() {
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["info", "com.apple.bogus.never.exists", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "info on unknown payload type must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr}{stdout}");
    assert!(
        combined.contains("not found"),
        "must explain that the type is not found; got: {combined}"
    );
}

#[test]
fn trap_56_search_field_returns_field_detail_with_plist_tag() {
    // `search --field <name>` is a single-call answer to "what type
    // does Apple expect for <key>?". Each hit must include the field's
    // plist_tag (the literal `<real>` / `<integer>` / etc. an author
    // would write in the .mobileconfig).
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["search", "--field", "safariAcceptCookies", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "search --field must exit 0 on hit");
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("must emit JSON");
    let arr = parsed.as_array().expect("returns a JSON array");
    assert!(
        !arr.is_empty(),
        "safariAcceptCookies exists in com.apple.applicationaccess; got {arr:?}"
    );
    let hit = &arr[0];
    assert_eq!(
        hit["payload_type"], "com.apple.applicationaccess",
        "must report the payload that contains the field"
    );
    assert_eq!(
        hit["field"]["plist_tag"], "real",
        "Apple specs safariAcceptCookies as <real>; --field must surface that"
    );
    assert_eq!(hit["field"]["name"], "safariAcceptCookies");
}

#[test]
fn trap_57_search_field_no_match_returns_empty_array() {
    // No false-error on misses — return [] so CI scripts can simply
    // check len == 0.
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "search",
            "--field",
            "bogus_never_a_real_apple_key",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "no-match --field must exit 0, not error"
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("must emit JSON");
    let arr = parsed.as_array().expect("returns a JSON array");
    assert!(arr.is_empty(), "expected empty array; got {arr:?}");
}

#[test]
fn trap_59_search_include_fields_returns_categorized_shape() {
    // Polymorphic mode emits {payload_matches[], field_matches[],
    // summary, query} — never mixed. Each hit carries a matched_in[]
    // array naming where the substring landed.
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["search", "cookie", "--include-fields", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "polymorphic search must exit 0");
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("must emit JSON");

    assert!(
        parsed.get("payload_matches").is_some(),
        "envelope must have payload_matches[]"
    );
    assert!(
        parsed.get("field_matches").is_some(),
        "envelope must have field_matches[]"
    );
    assert_eq!(parsed["query"], "cookie");

    let fm = parsed["field_matches"]
        .as_array()
        .expect("field_matches is array");
    assert!(
        !fm.is_empty(),
        "expect at least one field_match for 'cookie'; got {fm:?}"
    );

    // Locate safariAcceptCookies and verify matched_in tags
    // surface — this is the whole point of the new mode.
    let safari = fm
        .iter()
        .find(|m| m["field"]["name"] == "safariAcceptCookies")
        .expect("safariAcceptCookies must appear");
    let matched_in = safari["matched_in"]
        .as_array()
        .expect("matched_in is an array");
    let tags: Vec<&str> = matched_in.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        tags.contains(&"name"),
        "field-name match must report 'name' in matched_in; got {tags:?}"
    );
    assert_eq!(safari["field"]["plist_tag"], "real");
}

#[test]
fn trap_65_disable_apple_intelligence_bundles_compose_clean() {
    // Built-in DDM bundles for disabling Apple Intelligence (macOS + iOS).
    // Drift signal: schema renamed a key, removed the declaration, or
    // changed the activation contract — bundle stops composing or the
    // composed JSON stops validating against Apple's schema.
    use std::path::PathBuf;
    let recipes_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("recipes")
        .join("ddm");

    for preset in [
        "disable-apple-intelligence-macos",
        "disable-apple-intelligence-ios",
    ] {
        let bundle = recipes_dir.join(format!("{preset}.toml"));
        assert!(
            bundle.exists(),
            "built-in DDM bundle '{preset}' missing — recipes/ddm/ moved or renamed?"
        );
        let out = tempfile::tempdir().unwrap();

        let output = Command::cargo_bin("profile")
            .unwrap()
            .env("CONTOUR_ORG", "com.acme")
            .args([
                "ddm",
                "compose",
                bundle.to_str().unwrap(),
                "-o",
                out.path().to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ddm compose '{preset}' must succeed; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Confirm both files emitted + content set the AI toggles to false.
        let config_path = out.path().join("configuration.json");
        let activation_path = out.path().join("activation.json");
        assert!(config_path.exists(), "{preset}: configuration.json missing");
        assert!(
            activation_path.exists(),
            "{preset}: activation.json missing"
        );

        let config: Value =
            serde_json::from_slice(&fs::read(&config_path).unwrap()).expect("valid JSON");
        assert_eq!(
            config["Type"], "com.apple.configuration.intelligence.settings",
            "{preset}: declaration type mismatch"
        );
        let payload = &config["Payload"];
        for key in [
            "AllowAppleIntelligenceReport",
            "AllowGenmoji",
            "AllowImagePlayground",
            "AllowImageWand",
            "AllowPersonalizedHandwritingResults",
            "AllowVisualIntelligenceSummary",
            "AllowWritingTools",
        ] {
            assert_eq!(
                payload[key], false,
                "{preset}: top-level {key} must be false"
            );
        }
        for (sub, key) in [
            ("Mail", "AllowSmartReplies"),
            ("Mail", "AllowSummary"),
            ("Notes", "AllowTranscription"),
            ("Notes", "AllowTranscriptionSummary"),
        ] {
            assert_eq!(
                payload[sub][key], false,
                "{preset}: nested {sub}.{key} must be false"
            );
        }

        // ddm verify the whole directory passes.
        let verify = Command::cargo_bin("profile")
            .unwrap()
            .args(["ddm", "verify", out.path().to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        assert!(
            verify.status.success(),
            "{preset}: ddm verify must pass; stderr: {}",
            String::from_utf8_lossy(&verify.stderr)
        );
    }
}

#[test]
fn trap_61_info_exposes_os_support_metadata() {
    // info <type> --json must surface the per-OS support map for any
    // payload that has it (introduced/deprecated/removed/supervised/
    // device_channel/user_channel/...). Wifi has macOS + iOS detail
    // available in the embedded parquet — verify a stable subset.
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["info", "com.apple.wifi.managed", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "info wifi must succeed");
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let os_support = parsed["os_support"].as_object().expect("os_support is map");
    assert!(
        os_support.contains_key("macOS"),
        "wifi must expose macOS support detail; got keys {:?}",
        os_support.keys().collect::<Vec<_>>()
    );
    let mac = &os_support["macOS"];
    assert_eq!(
        mac["introduced"], "10.7",
        "macOS introduced version must surface from upstream parquet"
    );
    assert_eq!(
        mac["device_channel"], true,
        "macOS device_channel flag must surface"
    );
}

#[test]
fn trap_62_info_os_filter_scopes_output() {
    // --os macOS scopes platforms to only that OS and sets os_filter,
    // so jq filters can branch on the focus.
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["info", "com.apple.wifi.managed", "--os", "macOS", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(parsed["os_filter"], "macOS");
    let platforms = parsed["platforms"].as_array().expect("platforms array");
    assert_eq!(platforms.len(), 1, "platforms scoped to single OS");
    assert_eq!(platforms[0], "macOS");
    assert!(parsed["os_support"]["macOS"].is_object());
    assert!(
        parsed["os_support"].get("iOS").is_none(),
        "iOS detail must be absent in --os macOS output"
    );
}

#[test]
fn trap_63_info_unknown_os_errors() {
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["info", "com.apple.wifi.managed", "--os", "mars"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "unknown --os must exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown --os 'mars'"),
        "stderr must name the contract; got: {stderr}"
    );
    assert!(stderr.contains("macOS"), "stderr must list valid platforms");
}

#[test]
fn trap_64_info_field_carries_combinetype_when_present() {
    // DDM declarations carry `combinetype` on most fields. Verify a
    // known DDM payload exposes the new key on at least one field.
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "info",
            "com.apple.configuration.softwareupdate.settings",
            "--full",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let fields = parsed["fields"].as_array().expect("fields array");
    let with_combine: Vec<&Value> = fields
        .iter()
        .filter(|f| f["combinetype"].as_str().is_some())
        .collect();
    assert!(
        !with_combine.is_empty(),
        "expected at least one field with combinetype on a DDM payload; found 0"
    );
}

#[test]
fn trap_66_info_field_introduced_by_platform_is_per_os_map() {
    // Per-OS field-level introduced/deprecated (Gap #3): the embedded
    // parquet has rows keyed by (payload_type, platform, key). The
    // reader now merges into a per-platform map so agents can answer
    // "when did this key land on iOS vs macOS?" without losing data.
    //
    // Without --os: introduced_by_platform is a JSON object keyed by
    // platform name with > 1 entries for any cross-platform key.
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["info", "com.apple.applicationaccess", "--full", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let safari = parsed["fields"]
        .as_array()
        .expect("fields array")
        .iter()
        .find(|f| f["name"] == "safariAcceptCookies")
        .expect("safariAcceptCookies must exist");

    let intro = safari["introduced_by_platform"]
        .as_object()
        .expect("introduced_by_platform is a map (no --os)");
    assert!(
        intro.len() > 1,
        "safariAcceptCookies is on multiple platforms; expected >1 entries, got {intro:?}"
    );
    assert!(
        intro.contains_key("iOS"),
        "must include iOS entry; got {intro:?}"
    );
    assert!(
        intro.contains_key("macOS"),
        "must include macOS entry; got {intro:?}"
    );

    // With --os iOS: the map collapses to a flat string so jq
    // .fields[].introduced_by_platform reads the version directly.
    let scoped = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "info",
            "com.apple.applicationaccess",
            "--os",
            "iOS",
            "--full",
            "--json",
        ])
        .output()
        .unwrap();
    let scoped_parsed: Value = serde_json::from_slice(&scoped.stdout).expect("JSON");
    let scoped_safari = scoped_parsed["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "safariAcceptCookies")
        .expect("safariAcceptCookies in --os iOS output");
    let scoped_intro = scoped_safari["introduced_by_platform"]
        .as_str()
        .expect("--os scope flattens introduced_by_platform to a string");
    assert_eq!(
        scoped_intro,
        intro["iOS"].as_str().unwrap(),
        "scoped flat value must equal the iOS entry from the unscoped map"
    );
}

#[test]
fn trap_60_search_include_fields_requires_query() {
    // --include-fields is a polymorphic substring widening — there's
    // no substring without a query, so clap rejects.
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["search", "--include-fields"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "--include-fields without query must error"
    );
}

#[test]
fn trap_58_search_query_and_field_mutually_exclusive() {
    // clap rejects both forms together — they're different modes.
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args(["search", "wifi", "--field", "passcode"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "clap must reject query + --field together"
    );
}

#[test]
fn trap_55_docs_generate_stdout_writes_no_files() {
    // --stdout streams markdown to stdout instead of writing to disk —
    // no /tmp clutter, no second-pass grep on a file. Verify (a) markdown
    // headed with the title appears on stdout, and (b) clap rejects
    // running both --output and --stdout together.
    let output = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "docs",
            "generate",
            "--stdout",
            "--payload",
            "com.apple.applicationaccess",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "docs --stdout must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("# "),
        "stdout must start with markdown header; got first 60 chars: {:?}",
        &stdout.chars().take(60).collect::<String>()
    );
    assert!(
        stdout.contains("safariAcceptCookies"),
        "stdout markdown must include the field table"
    );

    // Mutual exclusion: clap rejects both --output and --stdout.
    let conflict = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "docs",
            "generate",
            "--stdout",
            "--output",
            "/tmp/should-not-exist",
            "--payload",
            "com.apple.applicationaccess",
        ])
        .output()
        .unwrap();
    assert!(
        !conflict.status.success(),
        "clap must reject --stdout + --output as mutually exclusive"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 71: External --preset-path library overrides embedded preset.
// Library extensibility: anyone can publish a directory of `.toml` bundles
// and override built-in DDM presets by name. End-to-end check that the
// override wins on `compose` and that listings flag the shadow with
// "(overrides embedded)".
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_71_preset_path_override_wins_and_lists_with_label() {
    let lib = tempfile::tempdir().unwrap();
    // External preset shadows the built-in `disable-apple-intelligence-macos`
    // — distinguishable by `intent_name` so we can tell which body composed.
    let body = r#"
intent_name = "external-override-marker"

[configuration]
type = "com.apple.configuration.intelligence.settings"

  [configuration.payload]
  AllowGenmoji = false
"#;
    fs::write(
        lib.path().join("disable-apple-intelligence-macos.toml"),
        body,
    )
    .unwrap();
    let lib_path = lib.path().to_str().unwrap();

    // 1. compose with --preset-path picks up the override.
    let out = tempfile::tempdir().unwrap();
    let composed = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "ddm",
            "compose",
            "--preset",
            "disable-apple-intelligence-macos",
            "--preset-path",
            lib_path,
            "--org",
            "com.acme",
            "-o",
            out.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        composed.status.success(),
        "preset compose with --preset-path must succeed; stderr: {}",
        String::from_utf8_lossy(&composed.stderr)
    );
    // configuration.json is always emitted; its Identifier is
    // `{org}.config.{intent_name}` — the override's intent_name is
    // the load-time discriminator.
    let config_path = out.path().join("configuration.json");
    let config: Value =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).expect("configuration JSON");
    let identifier = config["Identifier"].as_str().unwrap_or_default();
    assert!(
        identifier.contains("external-override-marker"),
        "external preset must win on compose — configuration Identifier should carry the override's intent_name; got {identifier}"
    );

    // 2. --list-presets --preset-path emits the override label on the source.
    let listed = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "ddm",
            "compose",
            "--list-presets",
            "--preset-path",
            lib_path,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(listed.status.success(), "list-presets must exit 0");
    let parsed: Value = serde_json::from_slice(&listed.stdout).expect("list JSON");
    let arr = parsed.as_array().expect("array");
    let entry = arr
        .iter()
        .find(|p| p["name"] == "disable-apple-intelligence-macos")
        .expect("preset must appear in listing");
    let source = entry["source"].as_str().unwrap_or_default();
    assert!(
        source.contains("overrides embedded"),
        "shadowed embedded preset must carry the override label; source={source}"
    );
    // exactly one entry — no duplicate from the embedded fallback.
    assert_eq!(
        arr.iter()
            .filter(|p| p["name"] == "disable-apple-intelligence-macos")
            .count(),
        1,
        "external must shadow embedded — no duplicate entry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 72: External --recipe-path overrides embedded recipe in listing.
// Symmetric with trap 71 for MDM recipes. Catches regressions where the
// listing reverts to "embedded wins" while load picks the external — the
// pre-fix bug that motivated this trap.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_72_recipe_path_override_lists_with_label() {
    let lib = tempfile::tempdir().unwrap();
    // Minimal Recipe TOML shadowing the built-in `okta`. Description is
    // the load-time discriminator.
    let body = r#"
[recipe]
name = "okta"
description = "external-okta-override"
vendor = "MyOrg"

[[profile]]
filename = "custom-okta.mobileconfig"
payload_type = "com.apple.extensiblesso"
display_name = "Custom Okta"
description = "User override"

[profile.fields]
Type = "Redirect"
TeamIdentifier = "DEADBEEF"
ExtensionIdentifier = "com.okta.mobile.auth-service-extension"
"#;
    fs::write(lib.path().join("okta.toml"), body).unwrap();
    let lib_path = lib.path().to_str().unwrap();

    let listed = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "generate",
            "--list-recipes",
            "--recipe-path",
            lib_path,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "list-recipes must exit 0; stderr: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let parsed: Value = serde_json::from_slice(&listed.stdout).expect("list-recipes JSON");
    let recipes = parsed["recipes"].as_array().expect("recipes array");
    let okta = recipes
        .iter()
        .find(|r| r["name"] == "okta")
        .expect("okta entry must appear in listing");
    let source = okta["source"].as_str().unwrap_or_default();
    assert!(
        source.contains("overrides embedded"),
        "shadowed embedded recipe must carry the override label; source={source}"
    );
    assert_eq!(
        okta["description"].as_str(),
        Some("external-okta-override"),
        "listing must reflect the external recipe's description (external wins on listing)"
    );
    assert_eq!(
        recipes.iter().filter(|r| r["name"] == "okta").count(),
        1,
        "exactly one okta entry — external must shadow embedded"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 73: `profile library new` scaffolds a working preset library.
// End-to-end: scaffold a fresh dir, then run `ddm compose --preset-path
// <dir>/ddm --preset <name>` against the just-emitted preset to prove
// the scaffold isn't just file-shaped — it actually composes.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_73_library_new_scaffolds_a_working_library() {
    let tmp = tempfile::tempdir().unwrap();
    let lib_root = tmp.path().join("lib");

    let scaffold = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "new", lib_root.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        scaffold.status.success(),
        "library new must succeed; stderr: {}",
        String::from_utf8_lossy(&scaffold.stderr)
    );
    let parsed: Value = serde_json::from_slice(&scaffold.stdout).expect("JSON envelope");
    assert_eq!(parsed["success"], true);
    let file_count = parsed["file_count"].as_u64().expect("file_count");
    assert!(file_count > 0, "scaffold must write files");

    // Top-level files land.
    assert!(lib_root.join("README.md").exists());
    assert!(lib_root.join(".gitignore").exists());
    assert!(lib_root.join(".github/workflows/validate.yml").exists());

    // Each DDM preset has a sibling .meaning.md (the user-requested
    // sidecar pattern — regression target if the scaffolder ever
    // forgets to emit them).
    let macos_toml = lib_root.join("ddm/disable-apple-intelligence-macos.toml");
    let macos_meaning = lib_root.join("ddm/disable-apple-intelligence-macos.meaning.md");
    assert!(macos_toml.exists(), "scaffold must copy DDM preset TOMLs");
    assert!(
        macos_meaning.exists(),
        ".meaning.md sidecar must accompany every preset"
    );
    let meaning_body = fs::read_to_string(&macos_meaning).unwrap();
    assert!(
        meaning_body.contains("## Intent"),
        ".meaning.md must include the Intent section"
    );

    // Re-running without --force must refuse on a non-empty target.
    let refused = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "new", lib_root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "second scaffold without --force must fail"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("already exists") && stderr.contains("--force"),
        "refusal must mention --force; got: {stderr}"
    );

    // The scaffolded preset must actually compose.
    let out = tempfile::tempdir().unwrap();
    let composed = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "ddm",
            "compose",
            "--preset-path",
            lib_root.join("ddm").to_str().unwrap(),
            "--preset",
            "disable-apple-intelligence-macos",
            "--org",
            "com.acme",
            "-o",
            out.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        composed.status.success(),
        "scaffolded preset must compose; stderr: {}",
        String::from_utf8_lossy(&composed.stderr)
    );
    assert!(out.path().join("configuration.json").exists());
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 74: hardening-macos-baseline recipe emits both mobileconfig and DDM.
// Hybrid recipe pattern — the [[ddm]] section composes alongside the
// [[profile]] section in one `generate --recipe` invocation. Catches:
//   - Recipe loader dropping the `ddm` field
//   - DDM compose path silently skipped during recipe generation
//   - Embedded recipe drifting from the documented mSCP-derived values
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_74_hardening_baseline_emits_mobileconfig_and_ddm() {
    let out = tempfile::tempdir().unwrap();
    let result = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "generate",
            "--recipe",
            "hardening-macos-baseline",
            "--org",
            "com.acme",
            "-o",
            out.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "hardening-macos-baseline must compose; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let parsed: Value = serde_json::from_slice(&result.stdout).expect("JSON envelope");
    assert_eq!(parsed["success"], true);
    assert_eq!(parsed["recipe"], "hardening-macos-baseline");

    // 3 mobileconfig profiles emitted.
    let profiles = parsed["profiles"].as_array().expect("profiles array");
    assert_eq!(
        profiles.len(),
        3,
        "expected 3 mobileconfigs; got {profiles:?}"
    );
    assert!(out.path().join("gatekeeper.mobileconfig").exists());
    assert!(out.path().join("firewall.mobileconfig").exists());
    assert!(out.path().join("password-policy.mobileconfig").exists());

    // DDM bundle emitted under <intent_name>/.
    let ddm = parsed["ddm"].as_array().expect("ddm array");
    assert!(
        ddm.iter().any(|d| d["kind"] == "configuration"),
        "ddm array must include a configuration; got {ddm:?}"
    );
    assert!(
        ddm.iter().any(|d| d["kind"] == "activation"),
        "ddm array must include an activation; got {ddm:?}"
    );
    let cfg_path = out
        .path()
        .join("softwareupdate-settings/configuration.json");
    let act_path = out.path().join("softwareupdate-settings/activation.json");
    assert!(cfg_path.exists(), "DDM configuration.json missing");
    assert!(act_path.exists(), "DDM activation.json missing");

    // Configuration carries the org-prefixed identifier and the
    // mSCP-derived AutomaticActions.InstallOSUpdates value.
    let cfg: Value = serde_json::from_slice(&fs::read(&cfg_path).unwrap()).unwrap();
    assert_eq!(
        cfg["Type"].as_str(),
        Some("com.apple.configuration.softwareupdate.settings")
    );
    assert_eq!(
        cfg["Identifier"].as_str(),
        Some("com.acme.config.softwareupdate-settings")
    );
    assert_eq!(
        cfg["Payload"]["AutomaticActions"]["InstallOSUpdates"].as_str(),
        Some("AlwaysOn"),
        "AutomaticActions.InstallOSUpdates must propagate from the recipe"
    );

    // No recipe placeholders surface. The password-policy mobileconfig
    // carries Apple's `{{key}}/{{value}}` runtime template markers from
    // the embedded schema — these are NOT user-fillable and must be
    // filtered from the placeholder warning. A regression here means
    // operators see a misleading "Replace these placeholders" prompt.
    let placeholders = parsed["placeholders"]
        .as_array()
        .expect("placeholders array");
    assert!(
        placeholders.is_empty(),
        "hardening recipe must not surface any user placeholders; got: {placeholders:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 75: `profile library normalize --style {flat,nested}` is reversible
// and preserves recipe semantics. Catches regressions where:
//   - Indentation changes break the TOML parse
//   - normalize stops being idempotent
//   - flip → flip back doesn't return to byte-identical content
//   - the restyled recipe stops composing
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_75_library_normalize_round_trips_and_preserves_semantics() {
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");

    // Scaffold a fresh library — embedded hardening recipe lands as nested.
    let scaffold = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "new", lib.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(scaffold.status.success());

    let recipe_path = lib.join("recipes/hardening-macos-baseline.toml");
    let original = fs::read_to_string(&recipe_path).unwrap();

    // Flip to flat.
    let flat = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "normalize",
            lib.to_str().unwrap(),
            "--style",
            "flat",
        ])
        .output()
        .unwrap();
    assert!(
        flat.status.success(),
        "normalize --style flat must succeed; stderr: {}",
        String::from_utf8_lossy(&flat.stderr)
    );
    let after_flat = fs::read_to_string(&recipe_path).unwrap();
    assert_ne!(
        original, after_flat,
        "flat normalize must change a nested-style file"
    );

    // Idempotency: a second flat normalize is a no-op.
    let flat_again = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "normalize",
            lib.to_str().unwrap(),
            "--style",
            "flat",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(flat_again.status.success());
    let parsed: Value = serde_json::from_slice(&flat_again.stdout).unwrap();
    let rewritten = parsed["rewritten"].as_array().expect("rewritten array");
    assert!(
        rewritten.is_empty(),
        "second flat normalize must rewrite nothing (idempotency); got: {rewritten:?}"
    );

    // Flip back to nested — must restore the original byte-for-byte
    // (the embedded recipe was authored in nested style).
    let nested = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "normalize",
            lib.to_str().unwrap(),
            "--style",
            "nested",
        ])
        .output()
        .unwrap();
    assert!(nested.status.success());
    let after_nested = fs::read_to_string(&recipe_path).unwrap();
    assert_eq!(
        original, after_nested,
        "flat → nested must round-trip to the original byte-for-byte"
    );

    // After all the flipping, the recipe still composes.
    let out = tempfile::tempdir().unwrap();
    let composed = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "generate",
            "--recipe-path",
            lib.join("recipes").to_str().unwrap(),
            "--recipe",
            "hardening-macos-baseline",
            "--org",
            "com.acme",
            "-o",
            out.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        composed.status.success(),
        "post-normalize recipe must still compose; stderr: {}",
        String::from_utf8_lossy(&composed.stderr)
    );
    let cfg: Value = serde_json::from_slice(
        &fs::read(
            out.path()
                .join("softwareupdate-settings/configuration.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        cfg["Payload"]["AutomaticActions"]["InstallOSUpdates"].as_str(),
        Some("AlwaysOn"),
        "DDM payload must survive the round-trip"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 76: `profile library import <FILE.mobileconfig>` produces a
// loadable recipe + sidecar. Validates the inverse-of-synthesize path
// end-to-end on a real-world MCX-style profile (SAP Privileges).
// Catches regressions where:
//   - The plist→toml converter loses or corrupts nested dicts
//   - Envelope keys leak into [profile.fields]
//   - The emitted TOML doesn't round-trip through `recipe::loader`
//   - The .meaning.md sidecar isn't written
//   - Re-running without --force silently overwrites
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_76_library_import_round_trips_real_mobileconfig() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/import/Privileges.mobileconfig");
    assert!(
        fixture.exists(),
        "fixture must exist at {}",
        fixture.display()
    );

    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");

    // Scaffold a fresh library so recipes/ exists.
    let scaffold = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "new", lib.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(scaffold.status.success());

    // Import the fixture.
    let result = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "import",
            fixture.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "library import must succeed; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let parsed: Value = serde_json::from_slice(&result.stdout).expect("JSON envelope");
    assert_eq!(parsed["success"], true);
    assert_eq!(parsed["payload_count"], 1);
    let pts = parsed["payload_types"].as_array().expect("payload_types");
    assert_eq!(
        pts.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>(),
        vec!["com.apple.ManagedClient.preferences"]
    );

    // Both files were written.
    let recipe_path = lib.join("recipes/privileges.toml");
    let meaning_path = lib.join("recipes/privileges.meaning.md");
    assert!(recipe_path.exists(), "recipe TOML missing");
    assert!(meaning_path.exists(), ".meaning.md sidecar missing");
    let meaning_body = fs::read_to_string(&meaning_path).unwrap();
    assert!(
        meaning_body.contains("## Intent"),
        ".meaning.md must include the Intent section"
    );
    // Schema enrichment: the Payloads section pulls the schema title
    // ("Managed Preferences") and the Apple description ("…configures
    // managed preferences."). A regression that drops the registry
    // lookup or breaks the section emitter would land here first.
    assert!(
        meaning_body.contains("## Payloads"),
        ".meaning.md must include the schema-enriched Payloads section"
    );
    // Title can come from either the envelope schema ("Managed
    // Preferences") OR — preferred when we have it — the MCX preference
    // domain match in ProfileCreator ("SAP Privileges"). Either is a
    // valid schema match; the test just requires *some* title above
    // the bare payload-type fallback.
    assert!(
        meaning_body.contains("Managed Preferences") || meaning_body.contains("SAP Privileges"),
        "schema title must appear in the payload heading; got: {meaning_body}"
    );
    assert!(
        meaning_body.contains("**Platforms:**"),
        "Platforms line (with per-OS introduced versions) must appear"
    );
    // Source label is `apple schema` for the envelope path, `apps schema`
    // for the ProfileCreator MCX-domain path. Both are valid.
    assert!(
        meaning_body.contains("apple schema") || meaning_body.contains("apps schema"),
        "schema source label must appear ('Source: apple schema')"
    );

    // The imported recipe round-trips through --list-recipes.
    let listed = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "generate",
            "--list-recipes",
            "--recipe-path",
            lib.join("recipes").to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let list_json: Value = serde_json::from_slice(&listed.stdout).unwrap();
    let recipes = list_json["recipes"].as_array().unwrap();
    let priv_entry = recipes
        .iter()
        .find(|r| r["name"] == "privileges")
        .expect("imported recipe must appear in listing");
    assert_eq!(
        priv_entry["description"].as_str(),
        Some("Privileges configuration"),
        "PayloadDisplayName must propagate to recipe.description"
    );
    assert_eq!(
        priv_entry["vendor"].as_str(),
        Some("SAP SE"),
        "PayloadOrganization must propagate to recipe.vendor"
    );
    assert_eq!(
        priv_entry["profile_count"].as_u64(),
        Some(1),
        "single inner payload → single [[profile]] block"
    );

    // PayloadRemovalDisallowed from the source envelope must propagate
    // to the imported recipe — the SAP fixture sets it true. Read the
    // TOML directly since --list-recipes only surfaces summary fields.
    let recipe_toml = fs::read_to_string(&recipe_path).unwrap();
    assert!(
        recipe_toml.contains("removal_disallowed = true"),
        "PayloadRemovalDisallowed=true must propagate to the recipe; got: {recipe_toml}"
    );

    // Re-running without --force must refuse.
    let refused = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "import",
            fixture.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "second import without --force must fail"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("already exists") && stderr.contains("--force"),
        "refusal must mention --force; got: {stderr}"
    );

    // --force succeeds and overwrites in place.
    let forced = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "import",
            fixture.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert!(
        forced.status.success(),
        "import --force must succeed; stderr: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 77: bulk `library import <DIR>` walks a directory, disambiguates
// same-stem files via parent-dir prefix, and round-trips MDM placeholders
// through `<data>` and `<string>` channels.
//
// Catches regressions where:
//   - Directory mode regresses to single-file-only
//   - `<data>$VAR</data>` placeholders fail strict plist parse
//   - Real `<data>` blobs break the importer instead of being base64-encoded
//   - Same-stem files in different subdirs collide on output
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_77_library_import_directory_with_data_and_placeholders() {
    let tmp = tempfile::tempdir().unwrap();

    // Build a tiny directory tree with three .mobileconfig files:
    //   ios/lock-screen.mobileconfig         (envelope text)
    //   ipados/lock-screen.mobileconfig      (envelope text — same stem!)
    //   shared/cert.mobileconfig             (real <data> + $VAR placeholder)
    let src = tmp.path().join("src");
    let ios_dir = src.join("ios");
    let ipados_dir = src.join("ipados");
    let shared_dir = src.join("shared");
    fs::create_dir_all(&ios_dir).unwrap();
    fs::create_dir_all(&ipados_dir).unwrap();
    fs::create_dir_all(&shared_dir).unwrap();

    // Two files with identical stems → must disambiguate by parent
    // directory in bulk mode.
    let envelope = |display: &str, ident: &str, uuid: &str| -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.shareddeviceconfiguration</string>
<key>PayloadIdentifier</key><string>{ident}.inner</string>
<key>PayloadUUID</key><string>{uuid}</string>
<key>PayloadVersion</key><integer>1</integer>
<key>LockScreenFootnote</key><string>Property of $ORG_NAME</string>
</dict></array>
<key>PayloadDisplayName</key><string>{display}</string>
<key>PayloadIdentifier</key><string>{ident}</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>{uuid}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>"#
        )
    };
    fs::write(
        ios_dir.join("lock-screen.mobileconfig"),
        envelope(
            "Lock screen iOS",
            "com.example.ios.lock",
            "11111111-1111-1111-1111-111111111111",
        ),
    )
    .unwrap();
    fs::write(
        ipados_dir.join("lock-screen.mobileconfig"),
        envelope(
            "Lock screen iPadOS",
            "com.example.ipados.lock",
            "22222222-2222-2222-2222-222222222222",
        ),
    )
    .unwrap();

    // <data>$VAR</data> placeholder + real <data> blob in one profile.
    // The lenient parser substitutes the $VAR before plist parsing;
    // the importer must restore the original placeholder and base64-
    // encode the real binary blob.
    let real_data_b64 = base64::engine::general_purpose::STANDARD.encode(b"hello");
    let cert_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.security.pkcs1</string>
<key>PayloadIdentifier</key><string>com.example.cert.inner</string>
<key>PayloadUUID</key><string>33333333-3333-3333-3333-333333333333</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadCertificateFileName</key><string>ca.der</string>
<key>PayloadContent</key><data>$DOGFOOD_OKTA_CA_CERTIFICATE</data>
<key>RealBlob</key><data>{real_data_b64}</data>
</dict></array>
<key>PayloadDisplayName</key><string>Certificate</string>
<key>PayloadIdentifier</key><string>com.example.cert</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>44444444-4444-4444-4444-444444444444</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>"#
    );
    fs::write(shared_dir.join("cert.mobileconfig"), cert_xml).unwrap();

    let lib = tmp.path().join("lib");
    let scaffold = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "new", lib.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(scaffold.status.success());

    // Run bulk import.
    let result = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "import",
            src.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "bulk import must succeed; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let parsed: Value = serde_json::from_slice(&result.stdout).expect("JSON envelope");
    assert_eq!(parsed["scanned"], 3);
    assert_eq!(parsed["imported"], 3);
    assert_eq!(parsed["failed"], 0);

    // Both lock-screen files exist under disambiguated names.
    let recipes_dir = lib.join("recipes");
    let lock_recipes: Vec<_> = std::fs::read_dir(&recipes_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".toml") && n.contains("lock-screen"))
        .collect();
    assert_eq!(
        lock_recipes.len(),
        2,
        "both ios + ipados lock-screen recipes must coexist via parent-dir disambiguation; got: {lock_recipes:?}"
    );
    assert!(
        lock_recipes.iter().any(|n| n.starts_with("ios-")
            || n.starts_with("ipados-")
            || n.contains("ios")
            || n.contains("ipados")),
        "at least one disambiguated recipe must carry a parent-dir prefix; got: {lock_recipes:?}"
    );

    // The cert recipe restored the $VAR placeholder and base64-encoded
    // the real blob.
    let cert_toml = std::fs::read_to_string(recipes_dir.join("cert.toml")).unwrap();
    assert!(
        cert_toml.contains("$DOGFOOD_OKTA_CA_CERTIFICATE"),
        "MDM placeholder in <data> must round-trip back into TOML; got: {cert_toml}"
    );
    assert!(
        cert_toml.contains("base64:"),
        "real <data> blob must be encoded with the base64: prefix; got: {cert_toml}"
    );

    // String-channel placeholder (`$ORG_NAME` inside a <string>) also
    // round-trips through the sentinel mapping.
    let ios_recipe_path = recipes_dir
        .read_dir()
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .map(|n| n.ends_with(".toml") && n.contains("lock-screen"))
                .unwrap_or(false)
        })
        .expect("at least one lock-screen recipe");
    let ios_toml = std::fs::read_to_string(&ios_recipe_path).unwrap();
    assert!(
        ios_toml.contains("$ORG_NAME"),
        "MDM placeholder in <string> must round-trip back into TOML; got: {ios_toml}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 78: `profile library validate <PATH>` catches compose-time
// breakage. Catches regressions where:
//   - clean library produces zero findings
//   - unknown payload types fall through to a hard error instead of a
//     warning (severity drift hurts CI gating)
//   - DDM bundles with bogus configuration types pass validation
//   - exit code doesn't reflect error severity
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_78_library_validate_flags_unknown_types_and_compose_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");

    // Scaffold a fresh library — embedded recipes are known-good.
    let scaffold = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "new", lib.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(scaffold.status.success());

    // 1. Clean library validates with zero findings.
    let clean = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "validate", lib.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "clean library must validate with exit 0; stderr: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let parsed: Value = serde_json::from_slice(&clean.stdout).expect("clean JSON");
    assert_eq!(parsed["errors"], 0);
    assert_eq!(parsed["warnings"], 0);
    assert_eq!(parsed["success"], true);

    // 2. Drop a deliberately broken recipe in: bogus payload_type
    //    (warning) + bogus DDM configuration type (error).
    let broken = r#"[recipe]
name = "_broken"
description = "trap fixture"

[[profile]]
filename = "x.mobileconfig"
payload_type = "com.example.totally.bogus"
display_name = "Bogus"

[[ddm]]
intent_name = "broken-bundle"

[ddm.configuration]
type = "com.apple.configuration.totally.bogus"

[ddm.activation]
type = "com.apple.activation.simple"
"#;
    fs::write(lib.join("recipes/_broken.toml"), broken).unwrap();

    let dirty = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "validate", lib.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        !dirty.status.success(),
        "library with errors must exit non-zero"
    );
    let dirty_parsed: Value = serde_json::from_slice(&dirty.stdout).expect("dirty JSON");
    let findings = dirty_parsed["findings"].as_array().expect("findings array");

    let unknown = findings
        .iter()
        .find(|f| f["check"] == "unknown-payload-type")
        .expect("must flag the bogus payload_type as unknown");
    assert_eq!(unknown["severity"].as_str(), Some("warning"));

    let ddm_unknown = findings
        .iter()
        .find(|f| f["check"] == "ddm-unknown-type")
        .expect("must flag the bogus DDM configuration type");
    assert_eq!(
        ddm_unknown["severity"].as_str(),
        Some("error"),
        "DDM compose failure must be an error, not a warning"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 79: `profile library import` accepts DDM declaration JSON.
//
// Catches:
//   - `.json` not routed to the DDM importer
//   - configuration declarations not landing under `<lib>/ddm/`
//   - `--name` override not flowing through to intent_name (so the
//     regenerated identifier doesn't match the source)
//   - activation/asset declarations silently importing as bundles
//     (they should bail with a clear error pointing at the
//     configuration JSON instead)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_79_library_import_handles_ddm_json() {
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");

    let scaffold = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "new", lib.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(scaffold.status.success());

    // Synthetic DDM configuration JSON (a real-world shape).
    let cfg_json = r#"{
        "Type": "com.apple.configuration.softwareupdate.settings",
        "Identifier": "com.acme.config.softwareupdate-settings",
        "Payload": {
            "Notifications": true,
            "AllowStandardUserOSUpdates": false,
            "AutomaticActions": {
                "Download": "AlwaysOn",
                "InstallOSUpdates": "AlwaysOn"
            }
        }
    }"#;
    let cfg_path = tmp.path().join("configuration.json");
    fs::write(&cfg_path, cfg_json).unwrap();

    // 1. Single-file import with --name override.
    let result = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "import",
            cfg_path.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
            "--name",
            "softwareupdate-settings",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "DDM JSON import must succeed; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let parsed: Value = serde_json::from_slice(&result.stdout).expect("JSON envelope");
    assert_eq!(parsed["payload_count"], 1);
    let pts = parsed["payload_types"].as_array().unwrap();
    assert_eq!(
        pts[0].as_str(),
        Some("com.apple.configuration.softwareupdate.settings")
    );
    let bundle_path = lib.join("ddm/softwareupdate-settings.toml");
    let meaning_path = lib.join("ddm/softwareupdate-settings.meaning.md");
    assert!(
        bundle_path.exists(),
        "DDM bundle must land under <lib>/ddm/"
    );
    assert!(
        meaning_path.exists(),
        "DDM .meaning.md sidecar must accompany it"
    );

    // 2. The imported bundle must compose round-trip.
    let out = tempfile::tempdir().unwrap();
    let composed = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "ddm",
            "compose",
            "--preset-path",
            lib.join("ddm").to_str().unwrap(),
            "--preset",
            "softwareupdate-settings",
            "--org",
            "com.acme",
            "-o",
            out.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        composed.status.success(),
        "imported DDM bundle must compose; stderr: {}",
        String::from_utf8_lossy(&composed.stderr)
    );

    // 3. Regenerated configuration JSON matches the source semantics.
    let regen: Value =
        serde_json::from_slice(&fs::read(out.path().join("configuration.json")).unwrap()).unwrap();
    assert_eq!(
        regen["Type"].as_str(),
        Some("com.apple.configuration.softwareupdate.settings")
    );
    assert_eq!(
        regen["Identifier"].as_str(),
        Some("com.acme.config.softwareupdate-settings"),
        "with --name override, the regenerated Identifier must match the source"
    );
    assert_eq!(
        regen["Payload"]["AutomaticActions"]["InstallOSUpdates"].as_str(),
        Some("AlwaysOn"),
        "nested payload keys must round-trip"
    );

    // 4. Activation declarations are rejected with the documented error.
    let act_json = r#"{
        "Type": "com.apple.activation.simple",
        "Identifier": "com.acme.activation.x",
        "Payload": {"StandardConfigurations": ["com.acme.config.x"]}
    }"#;
    let act_path = tmp.path().join("activation.json");
    fs::write(&act_path, act_json).unwrap();
    let refused = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "import",
            act_path.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "activation declarations must NOT import as bundles"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("com.apple.configuration.") && stderr.contains("import the configuration"),
        "refusal must point at the configuration JSON; got: {stderr}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 80: MCX-style profiles auto-unwrap on import and re-wrap on
// generate. The Privileges fixture is the canonical case:
//   PayloadContent[0].PayloadContent['corp.sap.privileges']
//     .Forced[0].mcx_preference_settings.<settings>
// becomes a flat `[profile.fields]` plus `mcx_domain = "corp.sap.privileges"`.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_80_mcx_profile_unwraps_on_import_and_rewraps_on_generate() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/import/Privileges.mobileconfig");
    assert!(fixture.exists());

    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");
    let scaffold = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "new", lib.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(scaffold.status.success());

    let imported = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "import",
            fixture.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "import must succeed; stderr: {}",
        String::from_utf8_lossy(&imported.stderr)
    );

    // 1. Imported recipe is FLAT — fields live at top of [profile.fields],
    //    `mcx_domain` records the source preference domain.
    let recipe_path = lib.join("recipes/privileges.toml");
    let recipe_toml = fs::read_to_string(&recipe_path).unwrap();
    assert!(
        recipe_toml.contains("mcx_domain = \"corp.sap.privileges\""),
        "mcx_domain must propagate from the source preference domain; got: {recipe_toml}"
    );
    assert!(
        recipe_toml.contains("EnforcePrivileges = \"user\""),
        "MCX inner settings must surface flat under [profile.fields]; got: {recipe_toml}"
    );
    assert!(
        !recipe_toml.contains("[profile.fields.PayloadContent"),
        "MCX envelope must be unwrapped, not preserved as nested sub-tables; got: {recipe_toml}"
    );

    // 2. Re-generating the recipe re-wraps the canonical envelope.
    let out = tempfile::tempdir().unwrap();
    let regen = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "generate",
            "--recipe-path",
            lib.join("recipes").to_str().unwrap(),
            "--recipe",
            "privileges",
            "--org",
            "com.acme",
            "-o",
            out.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        regen.status.success(),
        "generate from MCX recipe must succeed; stderr: {}",
        String::from_utf8_lossy(&regen.stderr)
    );
    let regen_xml = fs::read_to_string(out.path().join("preferences.mobileconfig")).unwrap();
    assert!(
        regen_xml.contains("corp.sap.privileges"),
        "regenerated MCX mobileconfig must carry the preference domain"
    );
    assert!(
        regen_xml.contains("mcx_preference_settings"),
        "regenerated MCX mobileconfig must wrap settings under mcx_preference_settings"
    );
    assert!(
        regen_xml.contains("<key>EnforcePrivileges</key>")
            && regen_xml.contains("<string>user</string>"),
        "EnforcePrivileges=\"user\" must survive flatten→regen round-trip"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 81: `library diff` reports semantic recipe changes and matches
// diff(1) exit semantics. Catches regressions where:
//   - identical files don't exit 0
//   - field-level changes inside [profile.fields] aren't surfaced
//   - added DDM bundles aren't reported
//   - JSON `findings` array drops entries on edge-case shapes
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_81_library_diff_reports_semantic_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let a_path = tmp.path().join("a.toml");
    let b_path = tmp.path().join("b.toml");

    let a_body = r#"
[recipe]
name = "demo"
description = "before"

[[profile]]
filename = "p.mobileconfig"
payload_type = "com.apple.security.firewall"
display_name = "FW"

[profile.fields]
EnableFirewall = true
EnableStealthMode = false
"#;
    let b_body = r#"
[recipe]
name = "demo"
description = "after"

[[profile]]
filename = "p.mobileconfig"
payload_type = "com.apple.security.firewall"
display_name = "FW"

[profile.fields]
EnableFirewall = true
EnableStealthMode = true
BlockAllIncoming = true

[[ddm]]
intent_name = "su"

[ddm.configuration]
type = "com.apple.configuration.softwareupdate.settings"

[ddm.configuration.payload]
Notifications = true
"#;
    fs::write(&a_path, a_body).unwrap();
    fs::write(&b_path, b_body).unwrap();

    // Identical → exit 0, no findings.
    let identical = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "diff",
            a_path.to_str().unwrap(),
            a_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        identical.status.success(),
        "identical recipes must exit 0; stderr: {}",
        String::from_utf8_lossy(&identical.stderr)
    );
    let parsed: Value = serde_json::from_slice(&identical.stdout).expect("identical JSON");
    assert_eq!(parsed["identical"], true);
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);

    // Different → exit 1 with the right findings.
    let different = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "diff",
            a_path.to_str().unwrap(),
            b_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        !different.status.success(),
        "differing recipes must exit non-zero (diff(1) semantics)"
    );
    let parsed: Value = serde_json::from_slice(&different.stdout).expect("diff JSON");
    assert_eq!(parsed["identical"], false);
    let findings = parsed["findings"].as_array().expect("findings array");
    let paths: Vec<&str> = findings.iter().filter_map(|f| f["path"].as_str()).collect();

    // Expected findings:
    //  - recipe.description changed
    //  - profile.fields.EnableStealthMode changed
    //  - profile.fields.BlockAllIncoming added
    //  - ddm[su] added
    assert!(
        paths.contains(&"recipe.description"),
        "must flag description change; got: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.contains("EnableStealthMode")),
        "must flag EnableStealthMode change; got: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.contains("BlockAllIncoming")),
        "must flag BlockAllIncoming added; got: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.contains("ddm[su]")),
        "must flag added DDM bundle; got: {paths:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 82: XML comments captured during `library import` survive into the
// emitted TOML, anchored above the matching key.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_82_library_import_preserves_xml_comments_as_toml_comments() {
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");
    let scaffold = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "new", lib.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(scaffold.status.success());

    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.security.firewall</string>
<key>PayloadIdentifier</key><string>com.example.fw.inner</string>
<key>PayloadUUID</key><string>11111111-1111-1111-1111-111111111111</string>
<key>PayloadVersion</key><integer>1</integer>
<!--
    Distinctive marker: pencils
    Documents EnableFirewall — the canonical anchored case.
-->
<key>EnableFirewall</key>
<true/>
</dict></array>
<key>PayloadDisplayName</key><string>FW</string>
<key>PayloadIdentifier</key><string>com.example.fw</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>22222222-2222-2222-2222-222222222222</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>"#;
    let src = tmp.path().join("fw.mobileconfig");
    fs::write(&src, xml).unwrap();

    let imported = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "import",
            src.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "import must succeed; stderr: {}",
        String::from_utf8_lossy(&imported.stderr)
    );

    let recipe_path = lib.join("recipes/fw.toml");
    let recipe_toml = fs::read_to_string(&recipe_path).unwrap();

    assert!(
        recipe_toml.contains("# Distinctive marker: pencils"),
        "XML comment text must be preserved as TOML `#` line; got: {recipe_toml}"
    );
    assert!(
        recipe_toml.contains("# Documents EnableFirewall"),
        "multi-line comment must round-trip; got: {recipe_toml}"
    );

    let lines: Vec<&str> = recipe_toml.lines().collect();
    let marker_pos = lines
        .iter()
        .position(|l| l.contains("Distinctive marker: pencils"))
        .expect("marker must be present");
    let next_real = lines[marker_pos + 1..]
        .iter()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .expect("must have a real line after the comment block");
    assert!(
        next_real.trim_start().starts_with("EnableFirewall"),
        "comment must be anchored above EnableFirewall; got next-real-line: {next_real}"
    );

    let out = tempfile::tempdir().unwrap();
    let regen = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "generate",
            "--recipe-path",
            lib.join("recipes").to_str().unwrap(),
            "--recipe",
            "fw",
            "--org",
            "com.acme",
            "-o",
            out.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        regen.status.success(),
        "comment-decorated recipe must still parse + compose; stderr: {}",
        String::from_utf8_lossy(&regen.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 83: `library import --combine --name X` folds N source files into
// one recipe with N `[[profile]]` blocks, and `generate --combined`
// emits ONE multi-payload .mobileconfig instead of N. Catches:
//   - Multi-input CLI dropped the new `Vec<String>` shape
//   - --combine without --name silently picks a default (loses
//     disambiguation guarantee)
//   - Combined emission writes N files instead of one
//   - Outer envelope identifier doesn't include `--org` prefix
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_83_library_import_combine_and_generate_combined() {
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");
    let scaffold = Command::cargo_bin("profile")
        .unwrap()
        .args(["library", "new", lib.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(scaffold.status.success());

    let envelope = |display: &str,
                    ident: &str,
                    uuid: &str,
                    payload_type: &str,
                    key: &str|
     -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>{payload_type}</string>
<key>PayloadIdentifier</key><string>{ident}.inner</string>
<key>PayloadUUID</key><string>{uuid}</string>
<key>PayloadVersion</key><integer>1</integer>
<key>{key}</key><true/>
</dict></array>
<key>PayloadDisplayName</key><string>{display}</string>
<key>PayloadIdentifier</key><string>{ident}</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>{uuid}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>"#
        )
    };
    let f1 = tmp.path().join("cs-firewall.mobileconfig");
    let f2 = tmp.path().join("cs-gatekeeper.mobileconfig");
    let f3 = tmp.path().join("cs-content.mobileconfig");
    fs::write(
        &f1,
        envelope(
            "FW",
            "com.example.fw",
            "11111111-1111-1111-1111-111111111111",
            "com.apple.security.firewall",
            "EnableFirewall",
        ),
    )
    .unwrap();
    fs::write(
        &f2,
        envelope(
            "GK",
            "com.example.gk",
            "22222222-2222-2222-2222-222222222222",
            "com.apple.systempolicy.control",
            "EnableAssessment",
        ),
    )
    .unwrap();
    fs::write(
        &f3,
        envelope(
            "CC",
            "com.example.cc",
            "33333333-3333-3333-3333-333333333333",
            "com.apple.applicationaccess",
            "allowContentCaching",
        ),
    )
    .unwrap();

    // --combine without --name must refuse.
    let no_name = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "import",
            f1.to_str().unwrap(),
            f2.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
            "--combine",
        ])
        .output()
        .unwrap();
    assert!(
        !no_name.status.success(),
        "--combine without --name must fail"
    );
    let stderr = String::from_utf8_lossy(&no_name.stderr);
    assert!(
        stderr.contains("--name"),
        "refusal must point at --name; got: {stderr}"
    );

    // Combine 3 sources into one recipe.
    let combined = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "library",
            "import",
            f1.to_str().unwrap(),
            f2.to_str().unwrap(),
            f3.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
            "--combine",
            "--name",
            "crowdstrike",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        combined.status.success(),
        "combined import must succeed; stderr: {}",
        String::from_utf8_lossy(&combined.stderr)
    );
    let parsed: Value = serde_json::from_slice(&combined.stdout).expect("JSON");
    assert_eq!(parsed["payload_count"], 3);
    let recipe_path = lib.join("recipes/crowdstrike.toml");
    let recipe_toml = fs::read_to_string(&recipe_path).unwrap();
    assert_eq!(
        recipe_toml.matches("\n[[profile]]\n").count(),
        3,
        "combined recipe must carry 3 [[profile]] blocks; got: {recipe_toml}"
    );

    // Default emission: 3 files, none called crowdstrike.mobileconfig.
    let out_default = tempfile::tempdir().unwrap();
    let gen_default = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "generate",
            "--recipe-path",
            lib.join("recipes").to_str().unwrap(),
            "--recipe",
            "crowdstrike",
            "--org",
            "com.acme",
            "-o",
            out_default.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(gen_default.status.success());
    let default_count = std::fs::read_dir(out_default.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s == "mobileconfig")
                .unwrap_or(false)
        })
        .count();
    assert_eq!(default_count, 3, "default emission must write 3 files");
    assert!(
        !out_default.path().join("crowdstrike.mobileconfig").exists(),
        "default emission must NOT produce a combined file"
    );

    // --combined emission: ONE file with 3 inner payloads.
    let out_combined = tempfile::tempdir().unwrap();
    let gen_combined = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "generate",
            "--recipe-path",
            lib.join("recipes").to_str().unwrap(),
            "--recipe",
            "crowdstrike",
            "--org",
            "com.acme",
            "-o",
            out_combined.path().to_str().unwrap(),
            "--combined",
        ])
        .output()
        .unwrap();
    assert!(
        gen_combined.status.success(),
        "--combined emission must succeed; stderr: {}",
        String::from_utf8_lossy(&gen_combined.stderr)
    );
    let combined_path = out_combined.path().join("crowdstrike.mobileconfig");
    assert!(
        combined_path.exists(),
        "combined output must land at <recipe-name>.mobileconfig"
    );
    let combined_xml = fs::read_to_string(&combined_path).unwrap();
    // Outer envelope + 3 inner payloads = 4 PayloadType keys.
    assert_eq!(
        combined_xml.matches("<key>PayloadType</key>").count(),
        4,
        "combined .mobileconfig must have 1 outer + 3 inner PayloadType keys"
    );
    // Outer identifier carries `--org` prefix + recipe name.
    assert!(
        combined_xml.contains("<string>com.acme.crowdstrike</string>"),
        "combined output's outer identifier must be com.acme.<recipe-name>"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 84: `generate --recipe` accepts a direct path to a TOML file
// (no --recipe-path round-trip) AND multiple --recipe values for
// batch generation. Catches:
//   - Path-like values fall through the bare-name lookup and 404
//   - Multiple --recipe values silently use only the first
//   - Recipe name mismatch between filename stem and `[recipe].name`
//     surfaces wrong files in the output dir
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_84_generate_accepts_path_and_multiple_recipes() {
    let tmp = tempfile::tempdir().unwrap();

    // Two recipe TOMLs in arbitrary locations (NOT in a library).
    let r1 = tmp.path().join("recipe-one.toml");
    let r2 = tmp.path().join("recipe-two.toml");
    fs::write(
        &r1,
        r#"[recipe]
name = "alpha"
description = "first"

[[profile]]
filename = "fw.mobileconfig"
payload_type = "com.apple.security.firewall"
display_name = "FW"
[profile.fields]
EnableFirewall = true
"#,
    )
    .unwrap();
    fs::write(
        &r2,
        r#"[recipe]
name = "beta"
description = "second"

[[profile]]
filename = "gk.mobileconfig"
payload_type = "com.apple.systempolicy.control"
display_name = "GK"
[profile.fields]
EnableAssessment = true
"#,
    )
    .unwrap();

    // Direct path, single recipe — no --recipe-path used.
    let out_single = tempfile::tempdir().unwrap();
    let single = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "generate",
            "--recipe",
            r1.to_str().unwrap(),
            "--org",
            "com.acme",
            "-o",
            out_single.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        single.status.success(),
        "direct-path --recipe must succeed without --recipe-path; stderr: {}",
        String::from_utf8_lossy(&single.stderr)
    );
    assert!(out_single.path().join("fw.mobileconfig").exists());

    // Two --recipe values — batch generation. Filenames from each
    // recipe should both land in the shared output dir.
    let out_multi = tempfile::tempdir().unwrap();
    let multi = Command::cargo_bin("profile")
        .unwrap()
        .env_remove("CONTOUR_ORG")
        .args([
            "generate",
            "--recipe",
            r1.to_str().unwrap(),
            r2.to_str().unwrap(),
            "--org",
            "com.acme",
            "-o",
            out_multi.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        multi.status.success(),
        "multiple --recipe values must succeed; stderr: {}",
        String::from_utf8_lossy(&multi.stderr)
    );
    assert!(
        out_multi.path().join("fw.mobileconfig").exists(),
        "first recipe's profile must land"
    );
    assert!(
        out_multi.path().join("gk.mobileconfig").exists(),
        "second recipe's profile must land — multi-recipe loop ran for both"
    );
}
