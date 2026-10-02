//! Trap suite — mscp commands on v4.83 layout (Phase 1 sister-suite).
//!
//! Companion to `crates/profile/tests/sop_traps.rs`. The profile-side suite
//! covers `contour profile *` commands; this suite covers `contour mscp *`
//! commands that all broke after the v4.83 generate-flow migration left the
//! downstream commands hardcoded to legacy `lib/mscp/` paths.
//!
//! Each trap runs the mscp binary against a fixture and asserts on the
//! result. The fixtures differ by group:
//! - Traps 10-12: a minimal v4.83-shaped output dir in a temp dir; the
//!   command must succeed.
//! - Traps 16-18b: the embedded schema dataset (`mscp schema ...`); the
//!   output must have the right JSON shape.
//! - Traps 19, 22-25: a minimal mSCP 2.0 repo in a temp dir (`mscp recipe
//!   --mscp-repo`); 23 and 25 assert a refusal, the rest a correct recipe.
//!
//! Failure of any trap means an mscp command regressed.

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

// ─────────────────────────────────────────────────────────────────────────────
// Trap 18b: `--keyword` is the new primary flag (mSCP 2.0 alignment) and
// `--baseline` / `-b` remain accepted as clap aliases. The wiring must
// route both forms to the same code path so existing scripts and recipes
// using `--baseline` keep working forever.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_18b_baseline_alias_for_keyword_round_trips() {
    // `schema rules` is the cheapest baseline-consuming subcommand: no
    // mSCP repo required, embedded parquet only. We compare two invocations
    // that should produce byte-identical JSON output.
    let via_keyword = Command::cargo_bin("mscp")
        .unwrap()
        .args(["schema", "rules", "--keyword", "cis_lvl1", "--json"])
        .output()
        .unwrap();
    assert!(
        via_keyword.status.success(),
        "schema rules --keyword cis_lvl1 must succeed (new primary flag); stderr: {}",
        String::from_utf8_lossy(&via_keyword.stderr)
    );

    let via_alias = Command::cargo_bin("mscp")
        .unwrap()
        .args(["schema", "rules", "--baseline", "cis_lvl1", "--json"])
        .output()
        .unwrap();
    assert!(
        via_alias.status.success(),
        "schema rules --baseline cis_lvl1 must still succeed (back-compat alias)"
    );

    let via_short = Command::cargo_bin("mscp")
        .unwrap()
        .args(["schema", "rules", "-k", "cis_lvl1", "--json"])
        .output()
        .unwrap();
    assert!(
        via_short.status.success(),
        "`-k cis_lvl1` short form must succeed"
    );

    let via_short_alias = Command::cargo_bin("mscp")
        .unwrap()
        .args(["schema", "rules", "-b", "cis_lvl1", "--json"])
        .output()
        .unwrap();
    assert!(
        via_short_alias.status.success(),
        "`-b cis_lvl1` short alias must still succeed (back-compat)"
    );

    // All four forms must produce identical output — otherwise clap is
    // routing them to different code paths.
    assert_eq!(via_keyword.stdout, via_alias.stdout);
    assert_eq!(via_keyword.stdout, via_short.stdout);
    assert_eq!(via_keyword.stdout, via_short_alias.stdout);
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 19: `mscp recipe --baseline X --mscp-repo Y` aggregates every rule's
// mobileconfig payload by Apple payload type into one recipe TOML. Catches:
//   - aggregator skipping rules with no `mobileconfig_info`
//   - separate payload types collapsing into a single profile
//   - field collision policy regressing (must warn + last-writer-wins)
//   - output not honoring `-o` / falling back to a hardcoded path
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_19_mscp_recipe_aggregates_baseline_rules() {
    let tmp = tempfile::tempdir().unwrap();

    // Two rules targeting the firewall payload (collision on
    // EnableFirewall + extra key) plus one rule on a separate payload.
    write_v2x_rule(
        tmp.path(),
        "system_settings",
        "fw_enable",
        "  macOS:\n    '15.0':\n      benchmarks:\n        - name: tinybase\n",
        "mobileconfig_info:\n  - PayloadType: com.apple.security.firewall\n    PayloadContent:\n      - EnableFirewall: false\n",
    );
    write_v2x_rule(
        tmp.path(),
        "system_settings",
        "fw_stealth",
        "  macOS:\n    '15.0':\n      benchmarks:\n        - name: tinybase\n",
        "mobileconfig_info:\n  - PayloadType: com.apple.security.firewall\n    PayloadContent:\n      - EnableFirewall: true\n        EnableStealthMode: true\n",
    );
    write_v2x_rule(
        tmp.path(),
        "system_settings",
        "ss_idle",
        "  macOS:\n    '15.0':\n      benchmarks:\n        - name: tinybase\n",
        "mobileconfig_info:\n  - PayloadType: com.apple.screensaver\n    PayloadContent:\n      - idleTime: 300\n",
    );
    // A rule with no mobileconfig payload that must be skipped.
    write_v2x_rule(
        tmp.path(),
        "system_settings",
        "script_only",
        "  macOS:\n    '15.0':\n      benchmarks:\n        - name: tinybase\n",
        "",
    );
    write_v2x_baseline(
        tmp.path(),
        "tinybase",
        "macos",
        "15.0",
        &["fw_enable", "fw_stealth", "ss_idle", "script_only"],
    );

    let recipe_out = tmp.path().join("tinybase.toml");
    let output = Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "recipe",
            "--mscp-repo",
            tmp.path().to_str().unwrap(),
            "--baseline",
            "tinybase",
            "-o",
            recipe_out.to_str().unwrap(),
            "--org",
            "com.acme",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mscp recipe must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = fs::read_to_string(&recipe_out).expect("recipe TOML must exist at -o path");

    // Two distinct payload types ⇒ two profile blocks.
    assert_eq!(
        body.matches("[[profile]]").count(),
        2,
        "expected one profile per payload type; got: {body}"
    );
    assert!(body.contains(r#"payload_type = "com.apple.security.firewall""#));
    assert!(body.contains(r#"payload_type = "com.apple.screensaver""#));

    // Last-writer-wins: fw_stealth overwrites fw_enable's
    // EnableFirewall value.
    assert!(
        body.contains("EnableFirewall = true"),
        "EnableFirewall must take the later writer's value; got: {body}"
    );
    assert!(body.contains("EnableStealthMode = true"));
    assert!(body.contains("idleTime = 300"));

    // Collision warning surfaces on stderr — operators rely on this
    // for compliance review.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("EnableFirewall"),
        "stderr must surface the collision; got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Phase 6 traps — mSCP 2.0 (multi-OS) layout transition
// ---------------------------------------------------------------------------

/// Write a single 2.0-shaped rule into `<root>/rules/<category>/<id>.yaml`.
/// `platforms_yaml` is the inline body for the `platforms:` block.
fn write_v2x_rule(root: &Path, category: &str, id: &str, platforms_yaml: &str, extras: &str) {
    let rules = root.join("rules").join(category);
    fs::create_dir_all(&rules).unwrap();
    let body = format!(
        "id: {id}\ntitle: {id} title\ndiscussion: trap fixture\nreferences:\n  nist:\n    cce:\n      macos_15:\n        - CCE-00000-0\n    800-53r5:\n      - AC-1\nplatforms:\n{platforms_yaml}{extras}"
    );
    fs::write(rules.join(format!("{id}.yaml")), body).unwrap();
}

/// Write the 2.0 baseline FILE that `MscpLayout::baseline_file` resolves:
/// `baselines/<os>/<name>_<os>_<version>.yaml`. Its `profile[].rules[]` list is
/// the authoritative membership source, so a fixture that writes one exercises
/// the explicit path rather than the benchmark-tag fallback.
fn write_v2x_baseline(root: &Path, name: &str, os: &str, version: &str, rule_ids: &[&str]) {
    let dir = root.join("baselines").join(os);
    fs::create_dir_all(&dir).unwrap();
    let mut rules = String::new();
    for id in rule_ids {
        use std::fmt::Write;
        writeln!(rules, "      - {id}").unwrap();
    }
    let body = format!(
        "title: 'macOS {version}: Security Configuration - {name}'\n\
         description: trap fixture baseline\n\
         parent_values: recommended\n\
         platform:\n  os: macOS\n  version: {version}\n\
         profile:\n  - section: system_settings\n    rules:\n{rules}"
    );
    fs::write(dir.join(format!("{name}_{os}_{version}.yaml")), body).unwrap();
}

/// Trap 22 — `mscp recipe` verifies a 2.0 tree and reads it as such.
///
/// Failure mode: the detector misclassifies and the extractor silently
/// returns zero rules (because 2.0 schema lacks the 1.x top-level keys).
#[test]
fn trap_22_mscp_recipe_auto_detects_v2x_layout() {
    let tmp = tempfile::tempdir().unwrap();
    write_v2x_rule(
        tmp.path(),
        "system_settings",
        "tiny_v2_rule",
        "  macOS:\n    '15.0':\n      benchmarks:\n        - name: tinybase_v2\n",
        "mobileconfig_info:\n  - PayloadType: com.apple.screensaver\n    PayloadContent:\n      - askForPassword: true\n",
    );

    let recipe_out = tmp.path().join("tinybase_v2.toml");
    let output = Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "recipe",
            "--mscp-repo",
            tmp.path().to_str().unwrap(),
            "--baseline",
            "tinybase_v2",
            "-o",
            recipe_out.to_str().unwrap(),
            "--org",
            "com.acme",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "a 2.0 tree must verify and read; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = fs::read_to_string(&recipe_out).unwrap();
    assert!(
        body.contains("[[profile]]"),
        "a 2.0 recipe should emit at least one [[profile]] block; got: {body}"
    );
    assert!(
        body.contains("com.apple.screensaver"),
        "screensaver payload from the 2.0 rule must reach the recipe; got: {body}"
    );
}

/// Trap 23 — a 1.x checkout is refused, not parsed. contour reads mSCP 2.0
/// only; the refusal must name the layout and the fix (`checkout main`), and
/// must not write a recipe. Before this, the same tree produced a recipe from
/// the flat schema — plausible output from a deprecated source.
#[test]
fn trap_23_mscp_recipe_refuses_a_1x_checkout_and_names_the_fix() {
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("flat_rule.yaml"),
        r#"id: flat_rule
title: 1.x mobileconfig rule
discussion: ""
tags:
  - tinybase_flag
mobileconfig: true
mobileconfig_info:
  com.apple.security.firewall:
    EnableFirewall: true
"#,
    )
    .unwrap();

    let recipe_out = tmp.path().join("tinybase_flag.toml");
    let output = Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "recipe",
            "--mscp-repo",
            tmp.path().to_str().unwrap(),
            "--baseline",
            "tinybase_flag",
            "-o",
            recipe_out.to_str().unwrap(),
            "--org",
            "com.acme",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a 1.x checkout must be refused; stderr: {stderr}"
    );
    assert!(
        stderr.contains("1.x layout") && stderr.contains("checkout main"),
        "refusal must name the layout and the fix; got: {stderr}"
    );
    assert!(
        !recipe_out.exists(),
        "no recipe may be written from a 1.x tree"
    );
}

/// Trap 24 — `--os ios --os-version 18.0` filters to iOS-only
/// benchmarks. A multi-OS rule that lists `cis_lvl1` only on macOS and
/// `cis_lvl1_byod` only on iOS must produce different recipes per OS.
#[test]
fn trap_24_mscp_recipe_v2x_ios_targeting_filters_correctly() {
    let tmp = tempfile::tempdir().unwrap();
    // Multi-OS rule: macOS-only baseline `mac_only`, iOS-only baseline `ios_only`.
    write_v2x_rule(
        tmp.path(),
        "settings",
        "multi_os_rule",
        concat!(
            "  macOS:\n",
            "    '15.0':\n",
            "      benchmarks:\n",
            "        - name: mac_only\n",
            "  iOS:\n",
            "    '18.0':\n",
            "      supervised: true\n",
            "      benchmarks:\n",
            "        - name: ios_only\n",
        ),
        "mobileconfig_info:\n  - PayloadType: com.apple.applicationaccess\n    PayloadContent:\n      - allowAirDrop: false\n",
    );

    // Run #1: macOS target asking for iOS baseline → no match.
    let mac_out = tmp.path().join("ios_under_macos.toml");
    let mac = Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "recipe",
            "--mscp-repo",
            tmp.path().to_str().unwrap(),
            "--baseline",
            "ios_only",
            "-o",
            mac_out.to_str().unwrap(),
            "--org",
            "com.acme",
            "--os",
            "macos",
            "--os-version",
            "15.0",
        ])
        .output()
        .unwrap();
    assert!(mac.status.success());
    let mac_body = fs::read_to_string(&mac_out).unwrap();
    assert!(
        !mac_body.contains("[[profile]]"),
        "macOS target must not match the iOS-only baseline; got: {mac_body}"
    );

    // Run #2: iOS target asking for the iOS baseline → match.
    let ios_out = tmp.path().join("ios_under_ios.toml");
    let ios = Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "recipe",
            "--mscp-repo",
            tmp.path().to_str().unwrap(),
            "--baseline",
            "ios_only",
            "-o",
            ios_out.to_str().unwrap(),
            "--org",
            "com.acme",
            "--os",
            "ios",
            "--os-version",
            "18.0",
        ])
        .output()
        .unwrap();
    assert!(
        ios.status.success(),
        "iOS target must succeed; stderr: {}",
        String::from_utf8_lossy(&ios.stderr)
    );
    let ios_body = fs::read_to_string(&ios_out).unwrap();
    assert!(
        ios_body.contains("[[profile]]") && ios_body.contains("com.apple.applicationaccess"),
        "iOS target must produce the applicationaccess profile; got: {ios_body}"
    );
}

/// Trap 25: on a 2.0 tree, a baseline name that no file and no rule on ANY
/// platform knows must be refused, not silently answered with zero rules.
/// Contrast trap_24: `ios_only` on a macOS target is a known name with no
/// members for that target and stays a green, empty recipe.
#[test]
fn trap_25_mscp_recipe_v2x_unknown_baseline_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_v2x_rule(
        tmp.path(),
        "settings",
        "known_rule",
        concat!(
            "  macOS:\n",
            "    '15.0':\n",
            "      benchmarks:\n",
            "        - name: mac_only\n",
        ),
        "mobileconfig_info:\n  - PayloadType: com.apple.applicationaccess\n    PayloadContent:\n      - allowAirDrop: false\n",
    );

    let out = tmp.path().join("typo.toml");
    let run = Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "recipe",
            "--mscp-repo",
            tmp.path().to_str().unwrap(),
            "--baseline",
            "mac_onyl",
            "-o",
            out.to_str().unwrap(),
            "--org",
            "com.acme",
            "--os",
            "macos",
            "--os-version",
            "15.0",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        !run.status.success(),
        "an unknown 2.0 baseline must fail, not produce an empty recipe; stderr: {stderr}"
    );
    assert!(
        stderr.contains("mac_onyl") && stderr.contains("no rule on any platform"),
        "error must name the baseline and say nothing knows it; got: {stderr}"
    );
    assert!(
        !out.exists(),
        "no recipe may be written for an unknown baseline"
    );
}
