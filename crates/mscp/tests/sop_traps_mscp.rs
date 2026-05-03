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
