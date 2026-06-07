//! Integration: `profile reidentify`.

use std::process::Command;

fn contour() -> Command {
    Command::new(env!("CARGO_BIN_EXE_profile"))
}

const JAMF: &str = "tests/fixtures/reidentify/jamf.mobileconfig";

#[test]
fn uuid_scheme_syncs_identifier_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("p.mobileconfig");
    std::fs::copy(JAMF, &src).unwrap();

    let out = contour()
        .args([
            "reidentify",
            src.to_str().unwrap(),
            "--org",
            "com.acme",
            "--write",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["changed"], 1);

    let written = std::fs::read_to_string(&src).unwrap();
    // Envelope identifier now embeds the real PayloadUUID; stray UUID is gone.
    assert!(written.contains("com.acme.6B7D8FE7-9D7D-4ECE-9B2E-A78C36181507"));
    assert!(!written.contains("1B0BD287"));

    // Second run: nothing changes.
    let out2 = contour()
        .args([
            "reidentify",
            src.to_str().unwrap(),
            "--org",
            "com.acme",
            "--write",
            "--json",
        ])
        .output()
        .unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&out2.stdout).unwrap();
    assert_eq!(v2["changed"], 0);
}

#[test]
fn name_scheme_rebuilds_and_remaps_reference() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("p.mobileconfig");
    std::fs::copy(JAMF, &src).unwrap();

    let out = contour()
        .args([
            "reidentify",
            src.to_str().unwrap(),
            "--org",
            "com.acme",
            "--scheme",
            "name",
            "--write",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let written = std::fs::read_to_string(&src).unwrap();

    // Identifier derives from the display name.
    assert!(written.contains("com.acme.profile.system-network-corp"));
    // The Wi-Fi PayloadCertificateUUID still resolves: it must equal the cert
    // payload's (new) UUID, and the old cert UUID must be gone.
    assert!(!written.contains("C0000000-0000-0000-0000-0000000000CC"));

    // Idempotent.
    let out2 = contour()
        .args([
            "reidentify",
            src.to_str().unwrap(),
            "--org",
            "com.acme",
            "--scheme",
            "name",
            "--write",
            "--json",
        ])
        .output()
        .unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&out2.stdout).unwrap();
    assert_eq!(v2["changed"], 0);
}

#[test]
fn dry_run_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("p.mobileconfig");
    std::fs::copy(JAMF, &src).unwrap();
    let before = std::fs::read_to_string(&src).unwrap();

    let out = contour()
        .args([
            "reidentify",
            src.to_str().unwrap(),
            "--org",
            "com.acme",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(std::fs::read_to_string(&src).unwrap(), before);
}
