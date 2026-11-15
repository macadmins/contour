//! A key the payload type's schema does not define is ignored by the device.
//! `profile validate` reports it as a warning, and `--strict` makes it an
//! error, the same split `ddm validate` has.

use assert_cmd::Command;
use serde_json::Value;

const PROFILE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.applicationaccess</string>
<key>PayloadIdentifier</key><string>com.acme.restrictions.payload</string>
<key>PayloadUUID</key><string>5B0E2F0A-7C1D-4E93-A6F8-2D4C9B1E3A57</string>
<key>PayloadVersion</key><integer>1</integer>
<key>zzNotARealRestriction</key><false/>
</dict></array>
<key>PayloadDisplayName</key><string>Restrictions</string>
<key>PayloadIdentifier</key><string>com.acme.restrictions</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>C83D9A14-6E2B-4F70-9D15-A7E4B0F2C961</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>"#;

fn validate(strict: bool) -> (Value, bool) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("restrictions.mobileconfig");
    std::fs::write(&file, PROFILE).unwrap();
    let mut args = vec!["validate", file.to_str().unwrap(), "--json"];
    if strict {
        args.push("--strict");
    }
    let out = Command::cargo_bin("profile")
        .unwrap()
        .args(&args)
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).expect("validate JSON on stdout");
    (v, out.status.success())
}

fn codes(v: &Value, list: &str) -> Vec<String> {
    v["schema_validation"][list]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["code"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn an_unknown_key_warns_and_fails_only_with_strict() {
    let (v, ok) = validate(false);
    assert!(ok, "a warning must not fail the run: {v}");
    assert_eq!(codes(&v, "warnings"), ["UNKNOWN_KEY"]);

    let (v, ok) = validate(true);
    assert!(!ok, "--strict must fail the run: {v}");
    assert_eq!(codes(&v, "errors"), ["UNKNOWN_KEY"]);
}
