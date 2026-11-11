//! `ddm migrate` gives every payload a verdict and accounts for every key:
//! converted when that is safe, refused when it would change what devices
//! enforce, and never dropped without saying so.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

const WIFI: &str = "<dict><key>SSID_STR</key><string>corp</string>\
    <key>PayloadIdentifier</key><string>com.acme.wifi</string>\
    <key>PayloadType</key><string>com.apple.wifi.managed</string>\
    <key>PayloadUUID</key><string>22222222-2222-4333-8444-555555555555</string>\
    <key>PayloadVersion</key><integer>1</integer></dict>";

/// A profile with one passcode payload holding `keys`, then `extra` payloads.
fn profile(dir: &Path, keys: &str, extra: &str) -> String {
    let path = dir.join("passcode.mobileconfig");
    std::fs::write(
        &path,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>PayloadContent</key><array>
<dict>{keys}
<key>PayloadDisplayName</key><string>Passcode</string>
<key>PayloadIdentifier</key><string>com.acme.passcode.p</string>
<key>PayloadType</key><string>com.apple.mobiledevice.passwordpolicy</string>
<key>PayloadUUID</key><string>11111111-2222-4333-8444-555555555555</string>
<key>PayloadVersion</key><integer>1</integer>
</dict>{extra}
</array>
<key>PayloadDisplayName</key><string>Passcode</string>
<key>PayloadIdentifier</key><string>com.acme.passcode</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>"#
        ),
    )
    .unwrap();
    path.to_string_lossy().into_owned()
}

/// Run `ddm migrate --write --json`; returns (report, exit ok, written declaration).
fn migrate(dir: &Path, file: &str) -> (Value, bool, Option<Value>) {
    let out_dir = dir.join("out");
    let out = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "ddm", "migrate", file, "--org", "com.acme", "--write", "--json", "-o",
        ])
        .arg(&out_dir)
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&out.stdout).expect("report JSON on stdout");
    let written = std::fs::read(out_dir.join("passcode.configuration.json"))
        .ok()
        .map(|b| serde_json::from_slice(&b).expect("declaration is JSON"));
    (report, out.status.success(), written)
}

fn payload(report: &Value, index: usize) -> &Value {
    &report["files"][0]["payloads"][index]
}

#[test]
fn a_passcode_payload_becomes_the_native_declaration() {
    let dir = tempfile::tempdir().unwrap();
    let file = profile(
        dir.path(),
        "<key>forcePIN</key><true/><key>minLength</key><integer>8</integer>\
         <key>allowSimple</key><false/>",
        "",
    );
    let (report, ok, written) = migrate(dir.path(), &file);
    assert!(ok, "{report}");
    assert_eq!(payload(&report, 0)["verdict"], "native", "{report}");

    let decl = written.expect("the declaration is written");
    assert_eq!(decl["Type"], "com.apple.configuration.passcode.settings");
    assert_eq!(decl["Payload"]["MinimumLength"], 8);
    assert_eq!(decl["Payload"]["RequirePasscode"], true);
    // allowSimple = false means a complex passcode is required: the sense flips.
    assert_eq!(decl["Payload"]["RequireComplexPasscode"], true);

    // The declaration contour wrote is one contour accepts.
    let valid = Command::cargo_bin("profile")
        .unwrap()
        .args(["ddm", "validate", "--strict", "--json"])
        .arg(dir.path().join("out/passcode.configuration.json"))
        .output()
        .unwrap();
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stdout)
    );
}

/// The declaration requires a passcode as soon as it manages any passcode
/// setting; the profile does not. Converting would lock unprotected devices.
#[test]
fn a_payload_that_does_not_require_a_passcode_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = profile(
        dir.path(),
        "<key>maxFailedAttempts</key><integer>6</integer>",
        "",
    );
    let (report, ok, written) = migrate(dir.path(), &file);
    assert_eq!(payload(&report, 0)["verdict"], "refused", "{report}");
    assert!(
        payload(&report, 0)["reason"]
            .as_str()
            .is_some_and(|r| r.contains("forcePIN")),
        "{report}"
    );
    assert!(written.is_none(), "a refused payload writes nothing");
    assert!(!ok, "a refused payload must not exit 0");
}

#[test]
fn a_key_with_no_declaration_key_is_reported_not_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let file = profile(
        dir.path(),
        "<key>forcePIN</key><true/><key>someVendorKey</key><string>x</string>",
        "",
    );
    let (report, ok, written) = migrate(dir.path(), &file);
    assert_eq!(payload(&report, 0)["verdict"], "partial", "{report}");
    assert_eq!(payload(&report, 0)["left"][0], "someVendorKey", "{report}");
    assert!(written.is_none(), "a partial payload writes nothing");
    assert!(!ok);
}

#[test]
fn other_payloads_are_reported_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let file = profile(dir.path(), "<key>forcePIN</key><true/>", WIFI);
    let before = std::fs::read(&file).unwrap();
    let (report, ok, written) = migrate(dir.path(), &file);
    assert!(ok, "{report}");
    assert_eq!(payload(&report, 0)["verdict"], "native", "{report}");
    assert_eq!(payload(&report, 1)["verdict"], "legacy", "{report}");
    assert!(written.is_some());
    assert_eq!(
        std::fs::read(&file).unwrap(),
        before,
        "the source is never changed"
    );
}

#[test]
fn a_second_run_writes_the_same_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let file = profile(
        dir.path(),
        "<key>forcePIN</key><true/><key>minLength</key><integer>8</integer>",
        "",
    );
    let out = dir.path().join("out/passcode.configuration.json");
    migrate(dir.path(), &file);
    let first = std::fs::read(&out).unwrap();
    migrate(dir.path(), &file);
    assert_eq!(std::fs::read(&out).unwrap(), first);
}
