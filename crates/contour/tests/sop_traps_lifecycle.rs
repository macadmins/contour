//! Procedural SOP — trap suite for the four lifecycle-style commands
//! (`pppc`, `btm`, `notifications`, `support`).
//!
//! Companion to `sop_traps_osquery.rs`. Each trap pins one CLI contract
//! that a procedural SOP relies on; failure means either the CLI changed
//! (update the SOP) or the SOP is wrong (fix the SOP).
//!
//! Spec:    `crates/contour-core/skills/contour/references/sop-format-spec.md`
//! SOPs:    `sop-pppc.md`, `sop-btm.md`, `sop-notifications.md`,
//!          `sop-support.md`

use assert_cmd::Command;
use serde_json::Value;
use std::fs;

// ─────────────────────────────────────────────────────────────────────────────
// Trap 25: `pppc validate <empty config> --json` succeeds with valid:true,
//          app_count:0. The SOP's STEP 1 reads these fields verbatim — if
//          the CLI ever renames them, the procedure can't decide whether to
//          continue.
// SOP procedure: generate_pppc_profile / STEP 1
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_25_pppc_validate_empty_config_shape() {
    let dir = tempfile::tempdir().unwrap();
    let toml = dir.path().join("pppc.toml");

    let init = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "pppc",
            "init",
            "--org",
            "com.acme",
            "--output",
            toml.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(init.status.success(), "pppc init must succeed");

    let output = Command::cargo_bin("contour")
        .unwrap()
        .args(["pppc", "validate", toml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "pppc validate (empty) exits 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("emit JSON");
    assert_eq!(parsed["valid"], true, "empty config is valid");
    assert_eq!(parsed["app_count"], 0, "no apps yet");
    assert!(parsed["errors"].is_array(), "errors is an array");
    assert!(parsed["warnings"].is_array(), "warnings is an array");
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 26: `pppc generate <missing-file>` exits 1 with a JSON error
//          envelope on stderr (post-B3 contract).
// SOP procedure: generate_pppc_profile / STEP 2 failure path
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_26_pppc_generate_missing_file_emits_json_error() {
    let output = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "pppc",
            "generate",
            "this_file_does_not_exist_xyz.toml",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "missing input must exit non-zero");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Value =
        serde_json::from_str(stderr.trim()).expect("post-B3: stderr is JSON object on failure");
    assert_eq!(parsed["success"], false);
    assert_eq!(
        parsed["error_code"], "IO_ERROR",
        "missing file must classify as IO_ERROR"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 27: `btm validate --json` returns a valid:true / btm_rule_count:0
//          shape. The SOP's STEP 1 keys off `btm_rule_count` (NOT
//          `app_count` like pppc/notifications) — agents that copy-paste
//          the pppc procedure will see this divergence.
// SOP procedure: generate_btm_profile / STEP 1
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_27_btm_validate_uses_btm_rule_count_field() {
    let dir = tempfile::tempdir().unwrap();
    let toml = dir.path().join("btm.toml");

    let init = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "btm",
            "init",
            "--org",
            "com.acme",
            "-o",
            toml.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(init.status.success(), "btm init must succeed");

    let output = Command::cargo_bin("contour")
        .unwrap()
        .args(["btm", "validate", toml.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "btm validate (empty) exits 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("emit JSON");
    assert_eq!(parsed["valid"], true);
    assert!(
        parsed.get("btm_rule_count").is_some(),
        "btm validate uses btm_rule_count (not app_count) — pinning this so \
         agents that copy the pppc procedure see the divergence"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 28: `notifications validate --json` returns the same shape as pppc
//          (valid, app_count, errors, warnings). The SOP's STEP 1 expects
//          this — pinning so agents can share the validation block.
// SOP procedure: generate_notifications_profile / STEP 1
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_28_notifications_validate_shape_matches_pppc() {
    let dir = tempfile::tempdir().unwrap();
    let toml = dir.path().join("notifications.toml");

    let init = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "notifications",
            "init",
            "--org",
            "com.acme",
            "-o",
            toml.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(init.status.success(), "notifications init must succeed");

    let output = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "notifications",
            "validate",
            toml.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "notifications validate exits 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("emit JSON");
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["app_count"], 0);
    assert!(parsed["errors"].is_array());
    assert!(parsed["warnings"].is_array());
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 29: `support generate <missing>` exits 1 with a JSON error envelope.
// SOP procedure: generate_support_profile / STEP 2 failure path
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_29_support_generate_missing_emits_json_error() {
    let output = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "support",
            "generate",
            "this_support_config_does_not_exist_xyz.toml",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "missing input must exit non-zero");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = stderr.trim();
    // Some commands print the envelope on stderr, some on stdout depending
    // on how the failure is plumbed; accept either as long as the envelope
    // exists somewhere with success:false and a known error_code.
    let parsed: Value = serde_json::from_str(combined)
        .or_else(|_| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            serde_json::from_str::<Value>(stdout.trim())
        })
        .expect("post-B3: failure must emit JSON envelope on stderr or stdout");

    assert_eq!(parsed["success"], false);
    let code = parsed["error_code"].as_str().expect("error_code is string");
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 30: `pppc generate` on a populated config produces .mobileconfig
//          files under the requested output directory. The SOP's STEP 3
//          asserts at least one file exists; if the CLI silently changes
//          the output extension, this trap fires.
// SOP procedure: generate_pppc_profile / STEP 3
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_30_pppc_generate_emits_mobileconfig() {
    let dir = tempfile::tempdir().unwrap();
    let toml = dir.path().join("pppc.toml");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();

    // Hand-author a minimal valid pppc.toml — `pppc init` writes an empty
    // app list which would give us 0 outputs. We need at least one app
    // entry for STEP 3 to be exercised.
    //
    // Schema (from `crates/pppc/src/pppc.rs::PppcAppEntry`):
    //   name:               required string
    //   bundle_id:          required string (bundle ID or path)
    //   code_requirement:   required string (codesign requirement)
    //   identifier_type:    "bundleID" (default) | "path"
    //   services:           array of service slugs (camera, microphone,
    //                       screen-capture, accessibility, fda, ...)
    fs::write(
        &toml,
        r#"[config]
org = "com.acme"

[[apps]]
name = "Slack"
bundle_id = "com.tinyspeck.slackmacgap"
code_requirement = "anchor apple generic"
services = ["screen-capture"]
"#,
    )
    .unwrap();

    let output = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "pppc",
            "generate",
            toml.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    if !output.status.success() {
        // If the schema doesn't accept this minimal layout, surface the
        // exact message so the trap-vs-SOP fix is obvious.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "pppc generate failed:\nstdout: {stdout}\nstderr: {stderr}\n\
             — if the [[apps]] schema changed, update this trap AND \
             sop-pppc.md's worked example."
        );
    }

    let written: Vec<_> = fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s == "mobileconfig")
        })
        .collect();
    assert!(
        !written.is_empty(),
        "pppc generate must emit at least one .mobileconfig file"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 31a: Camera and Microphone are DENY-ONLY per Apple's TCC spec.
//           A PPPC profile cannot grant access to either; the CLI enforces
//           this by emitting Authorization="Deny" regardless. Pin so the
//           SOP's INVARIANT cannot drift if a future commit "fixes" this.
// SOP procedure: generate_pppc_profile / INVARIANTS
// Catches: an agent asked to "grant Slack camera access" via PPPC and
// shipping an Allow rule that Apple's runtime will reject.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_31a_pppc_camera_microphone_are_deny_only() {
    let dir = tempfile::tempdir().unwrap();
    let toml = dir.path().join("pppc.toml");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();

    fs::write(
        &toml,
        r#"[config]
org = "com.acme"

[[apps]]
name = "Slack"
bundle_id = "com.tinyspeck.slackmacgap"
code_requirement = "anchor apple generic"
services = ["camera", "microphone"]
"#,
    )
    .unwrap();

    let out = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "pppc",
            "generate",
            toml.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "pppc generate must succeed");

    let entry = fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| {
            e.path()
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s == "mobileconfig")
        })
        .expect("at least one .mobileconfig must be written");

    let body = fs::read_to_string(entry.path()).unwrap();
    // Both Camera and Microphone keys MUST be present and both MUST
    // carry an Authorization of "Deny". A future regression that
    // emits "Allow" or "AllowStandardUserToSetSystemService" for
    // either service violates Apple's TCC policy.
    assert!(body.contains("<key>Camera</key>"), "Camera key present");
    assert!(
        body.contains("<key>Microphone</key>"),
        "Microphone key present"
    );

    // Crude but effective: the only Authorization values in this profile
    // should be "Deny" — no Allow variants for Camera/Microphone.
    assert!(
        !body.contains(">Allow<") && !body.contains("AllowStandardUserToSet"),
        "Camera/Microphone-only profile contains a non-Deny Authorization \
         — Apple TCC spec violation"
    );
    assert!(
        body.matches(">Deny<").count() >= 2,
        "expected at least 2 Deny rules (Camera + Microphone); body: {body}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 31: `btm generate --ddm` ALONE (combined mode, the default) emits a
//          single `.mobileconfig` file — NOT `.json` declarations. To get
//          declarations the agent MUST pair `--ddm` with `--per-app`. Pin
//          this so the SOP's STEP 2 (which now passes both) cannot drift.
// SOP procedure: generate_btm_profile / STEP 2
// Catches: an agent reading "DDM declaration JSON for macOS 15+" in the
// SOP and passing only `--ddm` will silently ship .mobileconfig and the
// declarative channel will receive nothing.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_31_btm_ddm_alone_does_not_emit_json_combined_mode_quirk() {
    let dir = tempfile::tempdir().unwrap();
    let toml = dir.path().join("btm.toml");
    let out_combined = dir.path().join("out-combined");
    let out_per_app = dir.path().join("out-per-app");
    fs::create_dir_all(&out_combined).unwrap();
    fs::create_dir_all(&out_per_app).unwrap();

    // Hand-author a minimal valid btm.toml with one app + one rule.
    // BTM uses `[settings]` (not `[config]`) and `[[apps]]` with at
    // least one rule each.
    fs::write(
        &toml,
        r#"[settings]
org = "com.acme"

[[apps]]
name = "Slack"
bundle_id = "com.tinyspeck.slackmacgap"
team_id = "BQR82RBBHL"

[[apps.rules]]
rule_type = "TeamIdentifier"
rule_value = "BQR82RBBHL"
"#,
    )
    .unwrap();

    // Combined mode (default): `--ddm` alone is silently ignored.
    let combined = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "btm",
            "generate",
            toml.to_str().unwrap(),
            "--ddm",
            "-o",
            out_combined.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(combined.status.success(), "btm generate --ddm exits 0");

    let combined_json = fs::read_dir(&out_combined)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s == "json")
        })
        .count();
    assert_eq!(
        combined_json, 0,
        "combined-mode --ddm currently emits .mobileconfig, not .json — \
         if this changes, the SOP's STEP 2 quirk note can be removed"
    );

    // Per-app + DDM: actually emits .json declarations.
    let per_app = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "btm",
            "generate",
            toml.to_str().unwrap(),
            "--ddm",
            "--per-app",
            "-o",
            out_per_app.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        per_app.status.success(),
        "btm generate --ddm --per-app exits 0; stderr: {}",
        String::from_utf8_lossy(&per_app.stderr)
    );

    let per_app_json = fs::read_dir(&out_per_app)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s == "json")
        })
        .count();
    assert!(
        per_app_json >= 1,
        "--ddm --per-app MUST emit at least one .json declaration; got {per_app_json}"
    );
}
