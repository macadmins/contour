//! Trap suite — `contour mscp recipe` round-trips through `contour profile`.
//!
//! These traps cross a crate boundary: `mscp recipe` writes a recipe and
//! `profile generate --recipe` must render it. Both halves run through the
//! `contour` binary, which carries both command trees and is what an operator
//! runs. Cargo names only a package's own binaries to its integration tests,
//! so the standalone `profile` binary is not reachable from the mscp crate's
//! tests — which is why these live here.

use assert_cmd::Command;
use std::fs;
use std::path::Path;

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

    // One mobileconfig rule (firewall) plus two DDM rules sharing
    // a declarationtype. Aggregated output must carry one
    // `[[profile]]` and one `[[ddm]]` block.
    write_v2x_rule(
        tmp.path(),
        "system_settings",
        "fw",
        "  macOS:\n    '15.0':\n      benchmarks:\n        - name: tinybase\n",
        "mobileconfig_info:\n  - PayloadType: com.apple.security.firewall\n    PayloadContent:\n      - EnableFirewall: true\n",
    );
    write_v2x_rule(
        tmp.path(),
        "system_settings",
        "su_download",
        "  macOS:\n    '15.0':\n      benchmarks:\n        - name: tinybase\n",
        "ddm_info:\n  declarationtype: com.apple.configuration.softwareupdate.settings\n  ddm_key: AutomaticActions\n  ddm_value:\n    Download: AlwaysOn\n",
    );
    write_v2x_rule(
        tmp.path(),
        "system_settings",
        "su_notify",
        "  macOS:\n    '15.0':\n      benchmarks:\n        - name: tinybase\n",
        "ddm_info:\n  declarationtype: com.apple.configuration.softwareupdate.settings\n  ddm_key: Notifications\n  ddm_value: true\n",
    );
    write_v2x_baseline(
        tmp.path(),
        "tinybase",
        "macos",
        "15.0",
        &["fw", "su_download", "su_notify"],
    );

    let recipe_out = tmp.path().join("tinybase.toml");
    let output = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "mscp",
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
    let render = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "profile",
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

    write_v2x_rule(
        tmp.path(),
        "system_settings",
        "ts",
        "  macOS:\n    '15.0':\n      benchmarks:\n        - name: tinybase\n",
        "mobileconfig_info:\n  - PayloadType: com.apple.MCX\n    PayloadContent:\n      - timeServer: $ODV\nodv:\n  recommended: time.nist.gov\n  tinybase: time.apple.com\n",
    );
    write_v2x_baseline(tmp.path(), "tinybase", "macos", "15.0", &["ts"]);

    let recipe_out = tmp.path().join("tinybase.toml");
    let r = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "mscp",
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
    let r = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "profile",
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
    let r = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "profile",
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
