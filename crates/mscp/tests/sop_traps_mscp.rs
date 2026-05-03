//! Trap suite — mscp commands on v4.83 layout (Phase 1 sister-suite).
//!
//! Companion to `crates/profile/tests/sop_traps.rs`. The profile-side suite
//! covers `contour profile *` commands; this suite covers `contour mscp *`
//! commands that all broke after the v4.83 generate-flow migration left the
//! downstream commands hardcoded to legacy `lib/mscp/` paths.
//!
//! Each trap:
//! 1. Builds a minimal v4.83-shaped output fixture in a temp dir
//! 2. Runs the mscp binary against it
//! 3. Asserts the command succeeds (or returns the right v4.83 data)
//!
//! Failure of any trap means a v4.83 mscp command regressed.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;

/// Build a minimal v4.83 mscp output directory containing a single baseline.
///
/// Layout produced (matching what `contour mscp generate` writes since the
/// v4.83 migration):
///   {root}/mscp/{baseline}/baseline.toml
///   {root}/platforms/macos/configuration-profiles/{baseline}/dummy.mobileconfig
///   {root}/platforms/macos/scripts/{baseline}/dummy.sh
///   {root}/labels/mscp-{baseline}.labels.yml
///   {root}/fleets/{baseline}.yml
///   {root}/default.yml
fn build_v4_83_fixture(root: &Path, baseline: &str) {
    let baseline_dir = root.join("mscp").join(baseline);
    fs::create_dir_all(&baseline_dir).unwrap();

    // Minimal baseline.toml (BaselineReference TOML format)
    let baseline_toml = format!(
        r#"[baseline]
name = "{baseline}"
platform = "macos"
generated_at = "2026-01-01T00:00:00Z"

[[profiles]]
path = "../../platforms/macos/configuration-profiles/{baseline}/dummy.mobileconfig"
labels_include_all = ["mscp-{baseline}"]

[[scripts]]
path = "../../platforms/macos/scripts/{baseline}/dummy.sh"
labels_include_all = ["mscp-{baseline}"]
script_type = "audit"
"#
    );
    fs::write(baseline_dir.join("baseline.toml"), baseline_toml).unwrap();

    // Profile artifact (minimal valid mobileconfig stub)
    let profiles_dir = root
        .join("platforms")
        .join("macos")
        .join("configuration-profiles")
        .join(baseline);
    fs::create_dir_all(&profiles_dir).unwrap();
    fs::write(
        profiles_dir.join("dummy.mobileconfig"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>PayloadType</key><string>Configuration</string></dict></plist>
"#,
    )
    .unwrap();

    // Script artifact
    let scripts_dir = root
        .join("platforms")
        .join("macos")
        .join("scripts")
        .join(baseline);
    fs::create_dir_all(&scripts_dir).unwrap();
    fs::write(scripts_dir.join("dummy.sh"), "#!/bin/bash\nexit 0\n").unwrap();

    // Labels at top-level (v4.83+)
    let labels_dir = root.join("labels");
    fs::create_dir_all(&labels_dir).unwrap();
    fs::write(
        labels_dir.join(format!("mscp-{baseline}.labels.yml")),
        format!("- name: mscp-{baseline}\n  description: trap fixture\n  label_membership_type: manual\n"),
    )
    .unwrap();

    // Fleets dir + default.yml so validate doesn't trip on missing structure
    let fleets_dir = root.join("fleets");
    fs::create_dir_all(&fleets_dir).unwrap();
    fs::write(
        fleets_dir.join(format!("{baseline}.yml")),
        "name: trap-team\n",
    )
    .unwrap();
    fs::write(
        root.join("default.yml"),
        "org_settings:\n  org_name: trap\n",
    )
    .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 10: `mscp validate` succeeds on a v4.83-shaped output directory.
// Pre-Phase-1: validate hardcoded lib/mscp/ existence check → ALWAYS FAILED.
// Post-Phase-1: validate checks mscp/ (where baseline components now live).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_10_mscp_validate_passes_on_v4_83() {
    let dir = tempfile::tempdir().unwrap();
    build_v4_83_fixture(dir.path(), "cis_lvl1");

    Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "validate",
            "--output",
            dir.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 11: `mscp list` discovers v4.83 baselines.
// Pre-Phase-1: list scanned lib/mscp/ → returned empty for v4.83 layouts.
// Post-Phase-1: list scans mscp/ where baseline.toml manifests live.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_11_mscp_list_finds_v4_83_baselines() {
    let dir = tempfile::tempdir().unwrap();
    build_v4_83_fixture(dir.path(), "cis_lvl1");

    let output = Command::cargo_bin("mscp")
        .unwrap()
        .args(["list", "--output", dir.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "mscp list must succeed on a v4.83 fixture; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The list shape is implementation-defined; we just assert the baseline
    // name is present somewhere in the parseable JSON output.
    let parsed: Value =
        serde_json::from_str(stdout.trim()).expect("mscp list --json must emit parseable JSON");
    let dump = parsed.to_string();
    assert!(
        dump.contains("cis_lvl1"),
        "expected baseline 'cis_lvl1' in output; got: {dump}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 12: `mscp clean` works against v4.83 layout.
// Pre-Phase-1: clean looked at lib/mscp/{name} → "Baseline not found".
// Post-Phase-1: clean looks at mscp/{name} (v4.83 component dir).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_12_mscp_clean_works_on_v4_83() {
    let dir = tempfile::tempdir().unwrap();
    build_v4_83_fixture(dir.path(), "cis_lvl1");

    // --force to bypass the "still referenced by team file" check.
    Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "clean",
            "--baseline",
            "cis_lvl1",
            "--output",
            dir.path().to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success();

    // After clean, the baseline component dir AND the labels file must be gone.
    assert!(
        !dir.path().join("mscp").join("cis_lvl1").exists(),
        "baseline component dir should be removed"
    );
    assert!(
        !dir.path()
            .join("labels")
            .join("mscp-cis_lvl1.labels.yml")
            .exists(),
        "label file should be removed (v4.83 path)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 16: `mscp schema rules --baseline <unknown>` returns `[]` with exit 0.
// SOP procedure: generate_baseline_compliance / PRECONDITIONS
// Catches: agents that branch on exit code would assume "rules listed
// successfully" for a misspelled baseline name. The procedural SOP requires
// checking array length, not exit code (same shape as profile search trap 4).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_16_mscp_schema_rules_unknown_baseline_returns_empty_array() {
    let output = Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "schema",
            "rules",
            "--baseline",
            "this_baseline_does_not_exist_xyz",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "schema rules exits 0 even for unknown baseline — agents MUST check JSON length"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value =
        serde_json::from_str(stdout.trim()).expect("schema rules --json must emit a JSON array");
    assert!(parsed.is_array(), "schema rules returns a JSON array");
    assert_eq!(
        parsed.as_array().unwrap().len(),
        0,
        "unknown baseline → empty array"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 17: `mscp schema rule <unknown_id>` returns the JSON literal `null`
//          on stdout with exit 0. Agents MUST check `result is not null`,
//          not `result.exit_code == 0`.
// SOP procedure: resolve_odv / EXECUTION
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_17_mscp_schema_rule_unknown_id_returns_null() {
    let output = Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "schema",
            "rule",
            "this_rule_id_does_not_exist_xyz",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "schema rule exits 0 even for unknown rule_id"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim())
        .expect("schema rule --json must emit valid JSON for unknown rules too");
    assert!(
        parsed.is_null(),
        "unknown rule_id → JSON literal `null`, got: {parsed}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 18: `mscp schema rules --json` entries expose the `has_odv` field.
// SOP procedure: generate_baseline_compliance / STEP 1 + resolve_odv
// Catches: regressions that drop or rename has_odv. The procedural SOP's
// ODV-resolution step keys off this field; renaming it silently breaks the
// flow that surfaces ODV choices to the user.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_18_mscp_schema_rules_expose_has_odv_field() {
    let output = Command::cargo_bin("mscp")
        .unwrap()
        .args(["schema", "rules", "--baseline", "cis_lvl1", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "schema rules cis_lvl1 must succeed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value =
        serde_json::from_str(stdout.trim()).expect("schema rules --json must emit a JSON array");
    let rules = parsed.as_array().expect("schema rules returns an array");

    assert!(
        !rules.is_empty(),
        "cis_lvl1 has rules; if this fails, embedded schema data is broken"
    );

    // Every rule entry MUST expose has_odv (typed bool); the procedural SOP's
    // resolve_odv step relies on it.
    let first = &rules[0];
    let has_odv = first.get("has_odv");
    assert!(
        has_odv.is_some(),
        "rule entry MUST include `has_odv` field; got keys: {:?}",
        first.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    assert!(
        has_odv.unwrap().is_boolean(),
        "has_odv MUST be a boolean (procedural SOP filters on it)"
    );
}
