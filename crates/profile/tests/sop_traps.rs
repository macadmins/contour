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
