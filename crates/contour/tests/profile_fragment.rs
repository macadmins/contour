//! `contour profile generate --fragment` writes what Fleet accepts, where Fleet
//! expects it, and refuses what Fleet would refuse at upload.
//!
//! Each fragment's `fleets/reference-fleet.yml` is checked against Fleet's own
//! GitOps JSON Schema — the pinned copy `mscp-schema` embeds, the one
//! `mscp validate` uses. Placement follows `fleetctl new`'s template
//! (`platforms/macos/configuration-profiles`, `…/declaration-profiles`).

use assert_cmd::Command;
use std::path::Path;

fn contour(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("contour")
        .unwrap()
        .args(args)
        .current_dir(dir)
        .env_remove("CONTOUR_ORG")
        .output()
        .unwrap()
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let out = contour(dir, args);
    assert!(
        out.status.success(),
        "`contour {}` failed:\n{}{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn refused(dir: &Path, args: &[&str]) -> String {
    let out = contour(dir, args);
    assert!(
        !out.status.success(),
        "`contour {}` should have been refused",
        args.join(" ")
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The fleet file parses, and Fleet's schema accepts it.
fn fleet_yaml(frag: &Path) -> serde_json::Value {
    let text =
        std::fs::read_to_string(frag.join("fleets/reference-fleet.yml")).expect("fleet file");
    let yaml: yaml_serde::Value = yaml_serde::from_str(&text).expect("fleet file is YAML");
    let json = serde_json::to_value(&yaml).unwrap();
    let schema: serde_json::Value = serde_json::from_slice(
        mscp_schema::embedded_fleet_gitops_schema().expect("this build embeds Fleet's schema"),
    )
    .unwrap();
    let v = jsonschema::validator_for(&schema).expect("Fleet's schema compiles");
    let errs: Vec<String> = v
        .iter_errors(&json)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(
        errs.is_empty(),
        "Fleet's schema rejects the fragment:\n{}\n\n{text}",
        errs.join("\n")
    );
    json
}

fn profiles(yaml: &serde_json::Value) -> Vec<serde_json::Value> {
    yaml["controls"]["apple_settings"]["configuration_profiles"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// Every path the fleet file names exists, relative to fleets/ as Fleet resolves it.
fn paths_resolve(frag: &Path, yaml: &serde_json::Value) {
    let fleets = frag.join("fleets");
    let mut all: Vec<String> = Vec::new();
    for e in profiles(yaml) {
        all.push(e["path"].as_str().unwrap().into());
        if let Some(a) = e.get("activation").and_then(|a| a.as_str()) {
            all.push(a.into());
        }
    }
    for e in yaml["controls"]["apple_settings"]["assets"]
        .as_array()
        .into_iter()
        .flatten()
    {
        all.push(e["path"].as_str().unwrap().into());
    }
    for p in all {
        assert!(
            fleets.join(&p).exists(),
            "the fleet file names {p}, which is not there"
        );
    }
}

fn recipe(dir: &Path, name: &str, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join(format!("{name}.toml")),
        format!("[recipe]\nname = \"{name}\"\ndescription = \"test\"\n\n{body}"),
    )
    .unwrap();
}

#[test]
fn a_payload_type_becomes_one_profile_under_apple_settings() {
    let t = tempfile::tempdir().unwrap();
    ok(
        t.path(),
        &[
            "profile",
            "generate",
            "com.apple.dock",
            "--org",
            "com.acme",
            "--fragment",
            "-o",
            "frag",
        ],
    );
    let frag = t.path().join("frag");
    let yaml = fleet_yaml(&frag);
    assert!(
        yaml["controls"].get("macos_settings").is_none(),
        "the deprecated key must not be emitted"
    );
    let p = profiles(&yaml);
    assert_eq!(p.len(), 1);
    assert_eq!(
        p[0]["path"],
        "../platforms/macos/configuration-profiles/com.apple.dock.mobileconfig"
    );
    paths_resolve(&frag, &yaml);
    assert!(frag.join("fragment.toml").exists());
}

#[test]
fn a_recipe_places_profiles_and_declarations_and_leaves_plain_activations_to_fleet() {
    let t = tempfile::tempdir().unwrap();
    let out = ok(
        t.path(),
        &[
            "profile",
            "generate",
            "--recipe",
            "hardening-macos-baseline",
            "--org",
            "com.acme",
            "--fragment",
            "-o",
            "frag",
        ],
    );
    let frag = t.path().join("frag");
    let yaml = fleet_yaml(&frag);
    let p = profiles(&yaml);
    let paths: Vec<&str> = p.iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert!(paths.iter().any(
        |p| p.starts_with("../platforms/macos/configuration-profiles/")
            && p.ends_with(".mobileconfig")
    ));
    assert!(
        paths.contains(&"../platforms/macos/declaration-profiles/softwareupdate-settings.json"),
        "{paths:?}"
    );
    assert!(
        p.iter().all(|e| e.get("activation").is_none()),
        "a plain activation is Fleet's to make"
    );
    assert!(!frag.join("platforms/macos/activations").exists());
    assert!(out.contains("Fleet makes the activation"), "{out}");
    paths_resolve(&frag, &yaml);
    // Nothing is left where Fleet's template globs would upload it by mistake.
    for e in std::fs::read_dir(frag.join("platforms/macos/declaration-profiles")).unwrap() {
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(e.unwrap().path()).unwrap()).unwrap();
        assert!(
            v["Type"]
                .as_str()
                .unwrap()
                .starts_with("com.apple.configuration."),
            "{v}"
        );
    }
}

#[test]
fn an_activation_with_a_predicate_is_kept_and_linked() {
    let t = tempfile::tempdir().unwrap();
    let recipes = t.path().join("recipes");
    recipe(
        &recipes,
        "predicated",
        r#"
[[ddm]]
intent_name = "passcode-on-macos-15"
  [ddm.configuration]
  type = "com.apple.configuration.passcode.settings"
    [ddm.configuration.payload]
    MinimumLength = 12
  [ddm.activation]
  type = "com.apple.activation.simple"
  predicate = "TRUEPREDICATE"
"#,
    );
    let out = ok(
        t.path(),
        &[
            "profile",
            "generate",
            "--recipe",
            "predicated",
            "--recipe-path",
            recipes.to_str().unwrap(),
            "--org",
            "com.acme",
            "--fragment",
            "-o",
            "frag",
        ],
    );
    let frag = t.path().join("frag");
    let yaml = fleet_yaml(&frag);
    let p = profiles(&yaml);
    assert_eq!(p.len(), 1);
    assert_eq!(
        p[0]["path"],
        "../platforms/macos/declaration-profiles/passcode-on-macos-15.json"
    );
    assert_eq!(
        p[0]["activation"],
        "../platforms/macos/activations/passcode-on-macos-15.json"
    );
    paths_resolve(&frag, &yaml);
    assert!(
        out.contains("FLEET_MDM_ALLOW_CUSTOM_ACTIVATIONS"),
        "the server opt-in must be named: {out}"
    );
}

#[test]
fn an_activation_naming_two_configurations_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let recipes = t.path().join("recipes");
    recipe(
        &recipes,
        "two-refs",
        r#"
[[ddm]]
intent_name = "both"
  [ddm.configuration]
  type = "com.apple.configuration.passcode.settings"
    [ddm.configuration.payload]
    MinimumLength = 12
  [ddm.activation]
  type = "com.apple.activation.simple"
  references = ["com.acme.one", "com.acme.two"]
"#,
    );
    let err = refused(
        t.path(),
        &[
            "profile",
            "generate",
            "--recipe",
            "two-refs",
            "--recipe-path",
            recipes.to_str().unwrap(),
            "--org",
            "com.acme",
            "--fragment",
            "-o",
            "frag",
        ],
    );
    assert!(err.contains("exactly one declaration"), "{err}");
    assert!(
        !t.path().join("frag").exists(),
        "a refused fragment leaves nothing behind"
    );
}

#[test]
fn status_subscriptions_are_refused_as_fleet_refuses_them() {
    let t = tempfile::tempdir().unwrap();
    let recipes = t.path().join("recipes");
    recipe(
        &recipes,
        "subs",
        r#"
[[ddm]]
intent_name = "watched"
  [ddm.configuration]
  type = "com.apple.configuration.passcode.settings"
    [ddm.configuration.payload]
    MinimumLength = 12
  [ddm.subscriptions]
  keys = ["device.operating-system.version"]
"#,
    );
    let err = refused(
        t.path(),
        &[
            "profile",
            "generate",
            "--recipe",
            "subs",
            "--recipe-path",
            recipes.to_str().unwrap(),
            "--org",
            "com.acme",
            "--fragment",
            "-o",
            "frag",
        ],
    );
    assert!(err.contains("status subscriptions"), "{err}");
    assert!(!t.path().join("frag").exists());
}

/// contour composes a status-reading predicate only with a subscription for
/// it (the device cannot evaluate it otherwise), and Fleet refuses that
/// subscription — so the fragment refuses, and says it is that conflict.
#[test]
fn a_predicate_that_needs_a_status_subscription_is_refused_with_the_reason() {
    let t = tempfile::tempdir().unwrap();
    let recipes = t.path().join("recipes");
    recipe(
        &recipes,
        "status-predicate",
        r#"
[[ddm]]
intent_name = "passcode-on-macos-15"
  [ddm.configuration]
  type = "com.apple.configuration.passcode.settings"
    [ddm.configuration.payload]
    MinimumLength = 12
  [ddm.activation]
  type = "com.apple.activation.simple"
  predicate = "@status(device.operating-system.version) >= '15.0'"
  [ddm.subscriptions]
  keys = ["device.operating-system.version"]
"#,
    );
    let err = refused(
        t.path(),
        &[
            "profile",
            "generate",
            "--recipe",
            "status-predicate",
            "--recipe-path",
            recipes.to_str().unwrap(),
            "--org",
            "com.acme",
            "--fragment",
            "-o",
            "frag",
        ],
    );
    assert!(err.contains("Fleet cannot deliver this predicate"), "{err}");
    assert!(!t.path().join("frag").exists());
}

#[test]
fn a_filevault_profile_is_refused_before_anything_is_written() {
    let t = tempfile::tempdir().unwrap();
    let err = refused(
        t.path(),
        &[
            "profile",
            "generate",
            "com.apple.MCX.FileVault2",
            "--org",
            "com.acme",
            "--fragment",
            "-o",
            "frag",
        ],
    );
    assert!(err.contains("can't include FileVault settings"), "{err}");
    assert!(!t.path().join("frag").exists());
}

#[test]
fn a_raw_plist_or_a_used_directory_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let err = refused(
        t.path(),
        &[
            "profile",
            "generate",
            "com.apple.dock",
            "--org",
            "com.acme",
            "--fragment",
            "--format",
            "plist",
            "-o",
            "frag",
        ],
    );
    assert!(err.contains("--format plist"), "{err}");
    std::fs::create_dir_all(t.path().join("used")).unwrap();
    std::fs::write(t.path().join("used/stale.mobileconfig"), "x").unwrap();
    let err = refused(
        t.path(),
        &[
            "profile",
            "generate",
            "com.apple.dock",
            "--org",
            "com.acme",
            "--fragment",
            "-o",
            "used",
        ],
    );
    assert!(err.contains("not empty"), "{err}");
}

#[test]
fn json_mode_prints_one_document() {
    let t = tempfile::tempdir().unwrap();
    let out = ok(
        t.path(),
        &[
            "--json",
            "profile",
            "generate",
            "--recipe",
            "hardening-macos-baseline",
            "--org",
            "com.acme",
            "--fragment",
            "-o",
            "frag",
        ],
    );
    let v: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}):\n{out}"));
    assert_eq!(v["success"], true);
    assert!(v["files"].as_array().unwrap().len() >= 4);
}
