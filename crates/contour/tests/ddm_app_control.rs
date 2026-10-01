//! `profile ddm app-control`: scan with codesign, generate a declaration.
//!
//! Driven through the binary against an app every Mac has, so the test does
//! not depend on what is installed. macOS only: the scan reads code
//! signatures with `codesign`.
#![cfg(target_os = "macos")]

use assert_cmd::Command;

const CALCULATOR: &str = "/System/Applications/Calculator.app";

fn contour(dir: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("contour").unwrap();
    c.current_dir(dir);
    c
}

/// An Apple app scans to Apple's sentinel, and the composed allow list
/// carries it once — the default Apple entry is not added a second time.
#[test]
fn an_apple_app_scans_to_the_apple_sentinel_and_composes_once() {
    let dir = tempfile::tempdir().unwrap();
    let out = contour(dir.path())
        .args(["profile", "ddm", "app-control", "scan", CALCULATOR])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let toml = std::fs::read_to_string(dir.path().join("app-control.toml")).unwrap();
    assert!(toml.contains("team_id = \"*APPLE*\""), "{toml}");
    assert!(toml.contains("intent_name = \"app-allowlist\""), "{toml}");

    let out = contour(dir.path())
        .args([
            "profile",
            "ddm",
            "app-control",
            "generate",
            "--org",
            "com.acme",
            "-o",
            "b",
            "--write",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("b/configuration.json")).unwrap())
            .unwrap();
    assert_eq!(config["Type"], "com.apple.configuration.app.settings");
    let list = config["Payload"]["Allowed"]["AllowedBinaries"]
        .as_array()
        .unwrap();
    let apple = list.iter().filter(|e| e["TeamID"] == "*APPLE*").count();
    assert_eq!(apple, 1, "{list:?}");
    assert!(
        dir.path().join("b/activation.json").is_file(),
        "the configuration is not inert"
    );

    let out = contour(dir.path())
        .args(["profile", "ddm", "validate", "b"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A deny scan names the app, lands in DeniedBinaries, and adds no Apple
/// entry — a deny list is not exclusive.
#[test]
fn a_deny_scan_names_the_app() {
    let dir = tempfile::tempdir().unwrap();
    let out = contour(dir.path())
        .args([
            "profile",
            "ddm",
            "app-control",
            "scan",
            CALCULATOR,
            "--deny",
            "-o",
            "d.toml",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = contour(dir.path())
        .args([
            "profile",
            "ddm",
            "app-control",
            "generate",
            "d.toml",
            "--org",
            "com.acme",
            "-o",
            "d",
            "--write",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("d/configuration.json")).unwrap())
            .unwrap();
    let allowed = &config["Payload"]["Allowed"];
    assert_eq!(
        allowed["DeniedBinaries"][0]["SigningID"],
        "com.apple.calculator"
    );
    assert!(allowed["AllowedBinaries"].is_null());
    assert_eq!(config["Identifier"], "com.acme.config.app-denylist");
}
