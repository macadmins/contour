//! Integration: `profile scan --deprecations`.

use std::process::Command;

fn contour() -> Command {
    Command::new(env!("CARGO_BIN_EXE_profile"))
}

const DEPRECATED_PROFILE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.test.dep</string>
  <key>PayloadUUID</key><string>1AE33410-88E1-40DE-B41E-08BCD69B6238</string>
  <key>PayloadDisplayName</key><string>Dep Test</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.SoftwareUpdate</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.test.dep.su</string>
      <key>PayloadUUID</key><string>B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E</string>
    </dict>
  </array>
</dict>
</plist>
"#;

#[test]
fn scan_deprecations_flags_deprecated_payload_type() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("dep.mobileconfig");
    std::fs::write(&file, DEPRECATED_PROFILE).unwrap();

    let out = contour()
        .args(["scan", file.to_str().unwrap(), "--deprecations", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "scan should succeed without the gate");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"deprecations\""),
        "JSON should carry a deprecations field: {stdout}"
    );
    assert!(
        stdout.contains("com.apple.SoftwareUpdate"),
        "deprecated payload type should appear: {stdout}"
    );
}

#[test]
fn scan_without_flag_has_no_deprecation_field() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("dep.mobileconfig");
    std::fs::write(&file, DEPRECATED_PROFILE).unwrap();

    let out = contour()
        .args(["scan", file.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("\"deprecations\""),
        "default scan must not include deprecations: {stdout}"
    );
}

const CLEAN_PROFILE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.test.clean</string>
  <key>PayloadUUID</key><string>1AE33410-88E1-40DE-B41E-08BCD69B6239</string>
  <key>PayloadDisplayName</key><string>Clean</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.example.private.thing</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.test.clean.x</string>
      <key>PayloadUUID</key><string>C2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D70</string>
    </dict>
  </array>
</dict>
</plist>
"#;

#[test]
fn fail_on_deprecations_exits_nonzero_when_found() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("dep.mobileconfig");
    std::fs::write(&file, DEPRECATED_PROFILE).unwrap();

    let out = contour()
        .args([
            "scan",
            file.to_str().unwrap(),
            "--deprecations",
            "--fail-on-deprecations",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "gate should fail the run when a deprecation is present"
    );
}

#[test]
fn fail_on_deprecations_exits_zero_when_clean() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("clean.mobileconfig");
    std::fs::write(&file, CLEAN_PROFILE).unwrap();

    let out = contour()
        .args([
            "scan",
            file.to_str().unwrap(),
            "--deprecations",
            "--fail-on-deprecations",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "gate should pass when no deprecations are present"
    );
}

#[test]
fn scan_md_report_writes_markdown_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("dep.mobileconfig");
    std::fs::write(&file, DEPRECATED_PROFILE).unwrap();
    let report = dir.path().join("report.md");

    let out = contour()
        .args([
            "scan",
            file.to_str().unwrap(),
            "--md-report",
            report.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let md = std::fs::read_to_string(&report).expect("report file written");
    assert!(md.contains("# Deprecation Report"), "md: {md}");
    assert!(md.contains("com.apple.SoftwareUpdate"), "md: {md}");
    assert!(md.contains("### Critical"), "md: {md}");
}
