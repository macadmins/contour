//! Integration: `profile library import` redacts sensitive fields.

use std::process::Command;

fn contour() -> Command {
    Command::new(env!("CARGO_BIN_EXE_profile"))
}

const WIFI_PROFILE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.test.wifi</string>
  <key>PayloadUUID</key><string>1AE33410-88E1-40DE-B41E-08BCD69B6238</string>
  <key>PayloadDisplayName</key><string>Corp WiFi</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.wifi.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.test.wifi.net</string>
      <key>PayloadUUID</key><string>B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E</string>
      <key>SSID_STR</key><string>CorpNet</string>
      <key>Password</key><string>hunter2-supersecret</string>
      <key>EncryptionType</key><string>WPA2</string>
    </dict>
  </array>
</dict>
</plist>
"#;

#[test]
fn library_import_redacts_sensitive_password() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("wifi.mobileconfig");
    std::fs::write(&src, WIFI_PROFILE).unwrap();
    let lib = dir.path().join("lib");

    let out = contour()
        .args([
            "library",
            "import",
            src.to_str().unwrap(),
            "--into",
            lib.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "import should succeed");

    let toml = std::fs::read_to_string(lib.join("recipes/wifi.toml")).unwrap();
    assert!(
        toml.contains("Password = \"TODO: PASSWORD\""),
        "password should be redacted: {toml}"
    );
    assert!(
        !toml.contains("hunter2"),
        "real password must not appear in recipe TOML: {toml}"
    );
    assert!(
        toml.contains("secrets = [\"PASSWORD\"]"),
        "[recipe] secrets should list PASSWORD: {toml}"
    );
    // Non-sensitive fields keep their real values.
    assert!(toml.contains("SSID_STR = \"CorpNet\""), "toml: {toml}");

    let meaning = std::fs::read_to_string(lib.join("recipes/wifi.meaning.md")).unwrap();
    assert!(
        meaning.contains("## Secrets"),
        "sidecar should have a Secrets section: {meaning}"
    );
    assert!(
        !meaning.contains("hunter2"),
        "real password must not appear in the sidecar: {meaning}"
    );
}
