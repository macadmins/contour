//! `profile validate --json` must say what its exit code says.
//!
//! The single-file JSON path set `valid` from the basic and lint checks only,
//! while its exit code also counted schema failures. A profile with a type
//! error printed `"valid": true` and exited 1 — so anything reading the
//! obvious field passed it. The multi-file path already combined both.

use assert_cmd::Command;

fn validate(path: &std::path::Path) -> (i32, serde_json::Value) {
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args(["--json", "profile", "validate"])
        .arg(path)
        .output()
        .unwrap();
    let json = serde_json::from_slice(&out.stdout).expect("validate --json prints JSON");
    (out.status.code().unwrap_or(-1), json)
}

#[test]
fn the_valid_field_agrees_with_the_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("dock.mobileconfig");
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args([
            "profile",
            "generate",
            "com.apple.dock",
            "--org",
            "com.acme",
            "-o",
        ])
        .arg(&good)
        .output()
        .unwrap();
    assert!(out.status.success(), "generate a profile to test with");

    let (code, json) = validate(&good);
    assert_eq!((code, json["valid"].as_bool()), (0, Some(true)));

    // A string where the schema wants a boolean.
    let bad = dir.path().join("bad.mobileconfig");
    let text = std::fs::read_to_string(&good).unwrap();
    let text = text.replacen(
        "<key>PayloadContent</key>\n\t<array>\n\t\t<dict>",
        "<key>PayloadContent</key>\n\t<array>\n\t\t<dict>\n\t\t\t<key>autohide</key>\n\t\t\t<string>yes</string>",
        1,
    );
    assert!(
        text.contains("<string>yes</string>"),
        "the test edit applied"
    );
    std::fs::write(&bad, text).unwrap();

    let (code, json) = validate(&bad);
    assert_eq!(code, 1, "a type error fails validation");
    assert_eq!(json["schema_validation"]["valid"].as_bool(), Some(false));
    assert_eq!(
        json["valid"].as_bool(),
        Some(false),
        "the top-level field must agree with the exit code — it read true here"
    );
}
