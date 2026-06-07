//! Integration: `profile audit`.

use std::process::Command;

fn contour() -> Command {
    Command::new(env!("CARGO_BIN_EXE_profile"))
}

const SAMPLE: &str = "tests/fixtures/audit/sample.mobileconfig";

#[test]
fn audit_json_reports_summary_and_classifications() {
    let out = contour()
        .args(["audit", SAMPLE, "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "audit should exit 0");

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["total"], 1);

    let summary = &v["summary"];
    assert_eq!(summary["cert_payloads"], 1);
    assert_eq!(summary["cert_breakdown"]["root"], 1);
    assert_eq!(summary["payloads_with_secrets"], 1);
    // The root cert blob and the font are both binary.
    assert_eq!(summary["binary_payloads"], 2);

    let profile = &v["profiles"][0];
    let buckets = profile["buckets"].as_array().unwrap();
    let names: Vec<&str> = buckets.iter().map(|b| b.as_str().unwrap()).collect();
    assert!(names.contains(&"certs"));
    assert!(names.contains(&"secrets"));
    assert!(names.contains(&"binary"));
}

#[test]
fn audit_fail_on_secrets_exits_nonzero() {
    let out = contour()
        .args(["audit", SAMPLE, "--fail-on-secrets"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "should fail because the sample carries secrets"
    );
}

#[test]
fn audit_certs_only_filters_json_buckets() {
    // Mutually-exclusive flags error out.
    let out = contour()
        .args(["audit", SAMPLE, "--certs-only", "--secrets-only"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "conflicting focus flags must error");
}

#[test]
fn audit_route_dry_run_moves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("sample.mobileconfig");
    std::fs::copy(SAMPLE, &src).unwrap();
    let triage = dir.path().join("triage");

    let out = contour()
        .args([
            "audit",
            src.to_str().unwrap(),
            "--route-into",
            triage.to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(src.exists(), "dry-run must not move the source");
    assert!(!triage.exists(), "dry-run must not create the triage tree");
}

#[test]
fn audit_route_moves_into_matching_buckets() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("sample.mobileconfig");
    std::fs::copy(SAMPLE, &src).unwrap();
    let triage = dir.path().join("triage");

    let out = contour()
        .args([
            "audit",
            src.to_str().unwrap(),
            "--route-into",
            triage.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Source moved (removed), copied into every matching bucket.
    assert!(!src.exists(), "source should be removed after move");
    assert!(triage.join("certs/sample.mobileconfig").exists());
    assert!(triage.join("secrets/sample.mobileconfig").exists());
    assert!(triage.join("binary/sample.mobileconfig").exists());
}
