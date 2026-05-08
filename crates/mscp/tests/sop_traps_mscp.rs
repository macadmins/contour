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

// ─────────────────────────────────────────────────────────────────────────────
// Trap 19: `mscp recipe --baseline X --mscp-repo Y` aggregates every rule's
// mobileconfig payload by Apple payload type into one recipe TOML. Catches:
//   - aggregator skipping rules with `mobileconfig: false`
//   - separate payload types collapsing into a single profile
//   - field collision policy regressing (must warn + last-writer-wins)
//   - output not honoring `-o` / falling back to a hardcoded path
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_19_mscp_recipe_aggregates_baseline_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();

    // Two rules targeting the firewall payload (collision on
    // EnableFirewall + extra key) plus one rule on a separate payload.
    fs::write(
        rules_dir.join("fw_enable.yaml"),
        r#"id: fw_enable
title: Enable firewall
discussion: ""
tags:
  - tinybase
mobileconfig: true
mobileconfig_info:
  com.apple.security.firewall:
    EnableFirewall: false
"#,
    )
    .unwrap();
    fs::write(
        rules_dir.join("fw_stealth.yaml"),
        r#"id: fw_stealth
title: Stealth mode
discussion: ""
tags:
  - tinybase
mobileconfig: true
mobileconfig_info:
  com.apple.security.firewall:
    EnableFirewall: true
    EnableStealthMode: true
"#,
    )
    .unwrap();
    fs::write(
        rules_dir.join("ss_idle.yaml"),
        r#"id: ss_idle
title: Screensaver idle
discussion: ""
tags:
  - tinybase
mobileconfig: true
mobileconfig_info:
  com.apple.screensaver:
    idleTime: 300
"#,
    )
    .unwrap();
    // A non-mobileconfig rule that must be skipped.
    fs::write(
        rules_dir.join("script_only.yaml"),
        r#"id: script_only
title: Script only
discussion: ""
tags:
  - tinybase
mobileconfig: false
"#,
    )
    .unwrap();

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

// ─────────────────────────────────────────────────────────────────────────────
// Trap 20: `mscp recipe` emits `[[ddm]]` blocks for rules with `ddm_info`,
// alongside the `[[profile]]` blocks for mobileconfig rules. Rules sharing
// a `declarationtype` merge into one bundle. Catches:
//   - aggregator dropping ddm-only rules on the floor
//   - intent_name not stripping the Apple `com.apple.configuration.` prefix
//   - configuration payload missing the merged ddm_key/ddm_value pairs
//   - round-trip via `profile generate --recipe` failing on the new shape
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_20_mscp_recipe_emits_ddm_blocks_alongside_profiles() {
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();

    // One mobileconfig rule (firewall) plus two DDM rules sharing
    // a declarationtype. Aggregated output must carry one
    // `[[profile]]` and one `[[ddm]]` block.
    fs::write(
        rules_dir.join("fw.yaml"),
        r#"id: fw
title: Enable firewall
discussion: ""
tags:
  - tinybase
mobileconfig: true
mobileconfig_info:
  com.apple.security.firewall:
    EnableFirewall: true
"#,
    )
    .unwrap();
    fs::write(
        rules_dir.join("su_download.yaml"),
        r#"id: su_download
title: Software update download
discussion: ""
tags:
  - tinybase
mobileconfig: false
ddm_info:
  declarationtype: com.apple.configuration.softwareupdate.settings
  ddm_key: AutomaticActions
  ddm_value:
    Download: AlwaysOn
"#,
    )
    .unwrap();
    fs::write(
        rules_dir.join("su_notify.yaml"),
        r#"id: su_notify
title: Software update notifications
discussion: ""
tags:
  - tinybase
mobileconfig: false
ddm_info:
  declarationtype: com.apple.configuration.softwareupdate.settings
  ddm_key: Notifications
  ddm_value: true
"#,
    )
    .unwrap();

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

    // 1. Both kinds of blocks are present, exactly once.
    assert_eq!(
        body.matches("[[profile]]").count(),
        1,
        "expected one profile block; got: {body}"
    );
    assert_eq!(
        body.matches("[[ddm]]").count(),
        1,
        "expected one ddm block; got: {body}"
    );

    // 2. The DDM block has the canonical shape — intent_name comes
    //    from stripping `com.apple.configuration.`, configuration
    //    type is preserved verbatim, and both ddm_keys merged.
    assert!(body.contains(r#"intent_name = "softwareupdate-settings""#));
    assert!(body.contains(r#"type = "com.apple.configuration.softwareupdate.settings""#));
    assert!(body.contains("Notifications = true"));
    assert!(body.contains("[ddm.configuration.payload.AutomaticActions]"));
    assert!(body.contains(r#"Download = "AlwaysOn""#));

    // 3. Round-trip: profile generate --recipe must accept the new
    //    shape and emit both a mobileconfig and DDM declaration JSON
    //    files in the intent_name subdirectory.
    let render_out = tmp.path().join("rendered");
    let render = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "generate",
            "--recipe",
            recipe_out.to_str().unwrap(),
            "--org",
            "com.acme",
            "-o",
            render_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        render.status.success(),
        "profile generate --recipe must accept ddm-bearing recipe; stderr: {}",
        String::from_utf8_lossy(&render.stderr)
    );

    assert!(
        render_out.join("firewall.mobileconfig").exists(),
        "mobileconfig must render at expected name"
    );
    let intent_dir = render_out.join("softwareupdate-settings");
    assert!(
        intent_dir.exists() && intent_dir.is_dir(),
        "DDM intent directory must exist at {}",
        intent_dir.display()
    );
    assert!(
        intent_dir.join("configuration.json").exists(),
        "DDM configuration declaration must be emitted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trap 21: `mscp recipe --odv-mode variable` keeps `"$ODV"` placeholders in
// every field that originally carried one and emits resolved defaults under a
// top-level `[odv]` table. Editing the [odv] entry then regenerating the
// profile via `profile generate --recipe` propagates the new value end-to-end.
// Catches:
//   - aggregator failing to emit [odv] / mixing modes
//   - profile loader not running resolve_odv before payload build (would
//     produce a literal "$ODV" string in the rendered profile)
//   - operator edits to [odv] not reaching the rendered mobileconfig
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_21_mscp_recipe_variable_mode_round_trips_through_odv_edits() {
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();

    fs::write(
        rules_dir.join("ts.yaml"),
        r#"id: ts
title: Time server
discussion: ""
tags:
  - tinybase
mobileconfig: true
mobileconfig_info:
  com.apple.MCX:
    timeServer: $ODV
odv:
  recommended: time.nist.gov
  tinybase: time.apple.com
"#,
    )
    .unwrap();

    let recipe_out = tmp.path().join("tinybase.toml");
    let r = Command::cargo_bin("mscp")
        .unwrap()
        .args([
            "recipe",
            "--mscp-repo",
            tmp.path().to_str().unwrap(),
            "--baseline",
            "tinybase",
            "--odv-mode",
            "variable",
            "-o",
            recipe_out.to_str().unwrap(),
            "--org",
            "com.acme",
        ])
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "variable mode must succeed; stderr: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    // 1. Field still carries the literal "$ODV"; defaults live under [odv].
    let body = fs::read_to_string(&recipe_out).unwrap();
    assert!(body.contains(r#"timeServer = "$ODV""#));
    assert!(body.contains("[odv]"));
    assert!(body.contains(r#"timeServer = "time.apple.com""#));

    // 2. Round-trip with the default value: rendered MCX profile carries
    //    "time.apple.com" (resolve_odv runs at load time).
    let rt_default = tmp.path().join("rt-default");
    let r = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "generate",
            "--recipe",
            recipe_out.to_str().unwrap(),
            "--org",
            "com.acme",
            "-o",
            rt_default.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "variable-mode round-trip must succeed; stderr: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let mcx = fs::read_to_string(rt_default.join("MCX.mobileconfig")).unwrap();
    assert!(
        mcx.contains("<string>time.apple.com</string>"),
        "default [odv].timeServer must reach rendered profile; got: {mcx}"
    );
    assert!(
        !mcx.contains("$ODV"),
        "no literal $ODV must remain in rendered profile"
    );

    // 3. Operator-edit workflow: change [odv] to a new value, regenerate,
    //    and confirm the new value reaches the rendered profile.
    let edited = body.replace(
        r#"timeServer = "time.apple.com""#,
        r#"timeServer = "pool.ntp.org""#,
    );
    let edited_path = tmp.path().join("tinybase-edited.toml");
    fs::write(&edited_path, edited).unwrap();

    let rt_edited = tmp.path().join("rt-edited");
    let r = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "generate",
            "--recipe",
            edited_path.to_str().unwrap(),
            "--org",
            "com.acme",
            "-o",
            rt_edited.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(r.status.success());
    let mcx_edited = fs::read_to_string(rt_edited.join("MCX.mobileconfig")).unwrap();
    assert!(
        mcx_edited.contains("<string>pool.ntp.org</string>"),
        "edited [odv] value must reach rendered profile; got: {mcx_edited}"
    );
}
