//! Integration tests for `profile collisions` — cross-profile payload-domain
//! collision detection (CLI level).

use assert_cmd::Command;
use serde_json::Value;
use std::fs;

/// A minimal `.mobileconfig` with one `com.apple.applicationaccess` payload whose
/// inner keys are supplied as raw plist `<key>…</key><value/>` lines.
fn write_profile(path: &std::path::Path, ident: &str, uuid: &str, inner: &str) {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>{ident}</string>
<key>PayloadUUID</key><string>{uuid}</string>
<key>PayloadDisplayName</key><string>{ident}</string>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.applicationaccess</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>{ident}.r</string>
<key>PayloadUUID</key><string>{uuid}</string>
{inner}
</dict></array></dict></plist>"#
    );
    fs::write(path, xml).unwrap();
}

#[test]
fn flags_same_domain_split_with_conflict_and_complementary() {
    let dir = tempfile::tempdir().unwrap();
    let scope = dir.path().join("tenant-a");
    fs::create_dir_all(&scope).unwrap();
    write_profile(
        &scope.join("cis.mobileconfig"),
        "com.acme.cis",
        "11111111-1111-1111-1111-111111111111",
        "<key>allowCamera</key><false/><key>forceCisOnly</key><true/>",
    );
    write_profile(
        &scope.join("org.mobileconfig"),
        "com.acme.org",
        "22222222-2222-2222-2222-222222222222",
        "<key>allowCamera</key><true/><key>allowOrgOnly</key><true/>",
    );

    let out = Command::cargo_bin("profile")
        .unwrap()
        .args(["collisions", dir.path().to_str().unwrap(), "-r", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let report: Value = serde_json::from_slice(&out.stdout).expect("collisions JSON");
    let cols = report["collisions"].as_array().unwrap();
    assert_eq!(cols.len(), 1, "exactly one colliding domain");
    assert_eq!(cols[0]["domain"], "com.apple.applicationaccess");

    let verdict = |k: &str| {
        cols[0]["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["key"] == k)
            .map(|e| e["verdict"].as_str().unwrap().to_string())
    };
    assert_eq!(verdict("allowCamera").as_deref(), Some("conflict")); // false vs true
    assert_eq!(verdict("forceCisOnly").as_deref(), Some("complementary"));
    assert_eq!(verdict("allowOrgOnly").as_deref(), Some("complementary"));
}

#[test]
fn fail_on_conflict_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    write_profile(
        &dir.path().join("a.mobileconfig"),
        "com.acme.a",
        "11111111-1111-1111-1111-111111111111",
        "<key>allowCamera</key><false/>",
    );
    write_profile(
        &dir.path().join("b.mobileconfig"),
        "com.acme.b",
        "22222222-2222-2222-2222-222222222222",
        "<key>allowCamera</key><true/>",
    );

    Command::cargo_bin("profile")
        .unwrap()
        .args([
            "collisions",
            dir.path().to_str().unwrap(),
            "--fail-on-conflict",
        ])
        .assert()
        .failure();
}

#[test]
fn per_directory_scope_does_not_collide_across_tenants() {
    // Same domain in two sibling directories must NOT collide by default…
    let dir = tempfile::tempdir().unwrap();
    for tenant in ["tenant-a", "tenant-b"] {
        let s = dir.path().join(tenant);
        fs::create_dir_all(&s).unwrap();
        write_profile(
            &s.join("p.mobileconfig"),
            &format!("com.{tenant}.p"),
            "11111111-1111-1111-1111-111111111111",
            "<key>allowCamera</key><false/>",
        );
    }

    let out = Command::cargo_bin("profile")
        .unwrap()
        .args(["collisions", dir.path().to_str().unwrap(), "-r", "--json"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        report["collisions"].as_array().unwrap().len(),
        0,
        "no cross-tenant collision"
    );

    // …but with --flat (one host gets both) it does.
    let out_flat = Command::cargo_bin("profile")
        .unwrap()
        .args([
            "collisions",
            dir.path().to_str().unwrap(),
            "-r",
            "--flat",
            "--json",
        ])
        .output()
        .unwrap();
    let report_flat: Value = serde_json::from_slice(&out_flat.stdout).unwrap();
    assert_eq!(
        report_flat["collisions"].as_array().unwrap().len(),
        1,
        "--flat collides"
    );
}
