//! Integration: `profile classify`.

use std::process::Command;

fn contour() -> Command {
    Command::new(env!("CARGO_BIN_EXE_profile"))
}

const WIFI: &str = "tests/fixtures/classify/wifi.mobileconfig";

#[test]
fn dry_run_previews_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("wifi.mobileconfig");
    std::fs::copy(WIFI, &src).unwrap();
    let before = std::fs::read_to_string(&src).unwrap();

    let out = contour()
        .args(["classify", src.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], false);
    assert_eq!(v["changed"], 1);
    assert_eq!(v["profiles"][0]["new_name"], "System - Wi-Fi (Corporate)");

    // Nothing written on dry-run.
    assert_eq!(std::fs::read_to_string(&src).unwrap(), before);
}

#[test]
fn write_applies_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("wifi.mobileconfig");
    std::fs::copy(WIFI, &src).unwrap();

    // First write changes the name.
    let out = contour()
        .args(["classify", src.to_str().unwrap(), "--write", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["changed"], 1);
    assert!(
        std::fs::read_to_string(&src)
            .unwrap()
            .contains("System - Wi-Fi (Corporate)")
    );

    // Second write is a no-op.
    let out2 = contour()
        .args(["classify", src.to_str().unwrap(), "--write", "--json"])
        .output()
        .unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&out2.stdout).unwrap();
    assert_eq!(v2["changed"], 0);
}

/// A minimal restriction profile (no subject-producing field) → bare "Restriction".
fn restriction_profile(display_name: &str, id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadDisplayName</key><string>{display_name}</string>
  <key>PayloadIdentifier</key><string>com.acme.{id}</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>00000000-0000-0000-0000-0000000000{id}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key><array><dict>
    <key>PayloadType</key><string>com.apple.MCX</string>
    <key>PayloadIdentifier</key><string>com.acme.{id}.mcx</string>
    <key>PayloadUUID</key><string>11111111-1111-1111-1111-1111111111{id}</string>
    <key>PayloadVersion</key><integer>1</integer>
  </dict></array>
</dict></plist>
"#
    )
}

#[test]
fn colliding_names_get_numeric_suffixes_and_are_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    // Two restriction profiles whose names strip to nothing distinguishing, so
    // both classify to the bare "Restriction" and collide.
    std::fs::write(
        dir.path().join("a.mobileconfig"),
        restriction_profile("System - Restrictions", "11"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.mobileconfig"),
        restriction_profile("System - Restrictions", "22"),
    )
    .unwrap();

    let out = contour()
        .args([
            "classify",
            dir.path().to_str().unwrap(),
            "-r",
            "--write",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    let names: Vec<String> = v["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["new_name"].as_str().unwrap().to_string())
        .collect();
    // Both written, distinct: the path-sorted-first gets the bare name.
    assert!(names.contains(&"System - Restriction".to_string()));
    assert!(names.contains(&"System - Restriction (2)".to_string()));
    assert_eq!(v["changed"], 2);

    // Re-run: the suffixed names are already in place → no further change.
    let out2 = contour()
        .args([
            "classify",
            dir.path().to_str().unwrap(),
            "-r",
            "--write",
            "--json",
        ])
        .output()
        .unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&out2.stdout).unwrap();
    assert_eq!(v2["changed"], 0);
}
