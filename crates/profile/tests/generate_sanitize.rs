//! Integration: `profile generate --sanitize` leaves secret references
//! unresolved in the output.

use std::process::Command;

fn contour() -> Command {
    Command::new(env!("CARGO_BIN_EXE_profile"))
}

const WIFI_RECIPE: &str = r#"[recipe]
name = "wifi"
description = "Test WiFi"

[[profile]]
filename = "wifi.mobileconfig"
payload_type = "com.apple.wifi.managed"
display_name = "WiFi"
description = ""
removal_disallowed = false

[profile.fields]
SSID_STR = "TestNet"
Password = "env:WIFI_PW"
EncryptionType = "WPA2"

[profile.extra_fields]
"#;

/// Read every file under `dir`, recursively, concatenated.
fn read_all(dir: &std::path::Path) -> String {
    let mut out = String::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            for entry in std::fs::read_dir(&p).unwrap().flatten() {
                stack.push(entry.path());
            }
        } else if let Ok(s) = std::fs::read_to_string(&p) {
            out.push_str(&s);
        }
    }
    out
}

#[test]
fn sanitize_leaves_secret_reference_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    let recipe = dir.path().join("wifi.toml");
    std::fs::write(&recipe, WIFI_RECIPE).unwrap();
    let out = dir.path().join("out");

    // --sanitize: no WIFI_PW in the environment, but generation must
    // still succeed because the reference is not resolved.
    let status = contour()
        .args([
            "generate",
            "--recipe",
            recipe.to_str().unwrap(),
            "--org",
            "com.test",
            "-o",
            out.to_str().unwrap(),
            "--sanitize",
        ])
        .env_remove("WIFI_PW")
        .output()
        .unwrap();
    assert!(status.status.success(), "sanitized generate should succeed");

    let content = read_all(&out);
    assert!(
        content.contains("env:WIFI_PW"),
        "sanitized output must keep the reference literal: {content}"
    );
}

#[test]
fn without_sanitize_secret_reference_is_resolved() {
    let dir = tempfile::tempdir().unwrap();
    let recipe = dir.path().join("wifi.toml");
    std::fs::write(&recipe, WIFI_RECIPE).unwrap();
    let out = dir.path().join("out");

    let status = contour()
        .args([
            "generate",
            "--recipe",
            recipe.to_str().unwrap(),
            "--org",
            "com.test",
            "-o",
            out.to_str().unwrap(),
        ])
        .env("WIFI_PW", "hunter2real")
        .output()
        .unwrap();
    assert!(status.status.success(), "generate should succeed");

    let content = read_all(&out);
    assert!(
        content.contains("hunter2real"),
        "output must contain the resolved secret: {content}"
    );
    assert!(
        !content.contains("env:WIFI_PW"),
        "the reference should not survive when resolved: {content}"
    );
}
