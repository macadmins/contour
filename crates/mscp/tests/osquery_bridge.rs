//! Integration: `mscp generate --osquery` over the local `macos_security` repo.
//!
//! The `mscp` binary exposes `generate` as a top-level subcommand, so this
//! test drives `CARGO_BIN_EXE_mscp` directly (no `mscp` subcommand prefix).
//!
//! `--osquery` requires a resolvable org (`--org`). The tests are `#[ignore]`,
//! declaring what they need, and they PANIC rather than return when asked to
//! run without it: a test that returns early passes, which looks the same as
//! a test that ran.
//!
//! Needs an mSCP 2.0 checkout named by `CONTOUR_MSCP_REPO`, as the other
//! checkout-backed tests do. (mSCP 1.x is not supported: contour refuses a
//! 1.x tree, so a 1.x checkout cannot exercise this.)

use std::path::Path;
use std::process::Command;

/// The baseline this test generates.
const BASELINE: &str = "cis_lvl1";

/// The mSCP 2.0 checkout named by `CONTOUR_MSCP_REPO`, when it has `rules/`.
fn repo() -> Option<String> {
    let candidate = std::env::var("CONTOUR_MSCP_REPO").ok()?;
    Path::new(&candidate)
        .join("rules")
        .is_dir()
        .then_some(candidate)
}

/// Whether a `python3` toolchain is on PATH — `mscp generate` shells out to the
/// mSCP Python generation script.
fn has_python() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
#[ignore = "needs an mSCP 2.0 checkout — set CONTOUR_MSCP_REPO — and python3; run with \
            --include-ignored"]
fn osquery_slim_fleet_emits_queries_audit_and_coverage() {
    let repo = repo().unwrap_or_else(|| {
        panic!(
            "asked to run (--include-ignored) but CONTOUR_MSCP_REPO does not name an \
             mSCP 2.0 checkout with a rules/ directory"
        )
    });
    assert!(
        has_python(),
        "asked to run (--include-ignored) but python3 is not on PATH — \
         `mscp generate` shells out to mSCP's Python script"
    );

    let out = tempfile::tempdir().unwrap();
    let out_path = out.path().to_str().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mscp"))
        .args([
            "generate",
            "-m",
            &repo,
            "-k",
            BASELINE,
            "-o",
            out_path,
            "--fleet-mode",
            "--osquery",
            "--osquery-audit",
            "slim",
            "--org",
            "com.acme",
        ])
        .output()
        .expect("failed to spawn mscp");

    // A failing command fails the test and shows the output: a broken
    // generator and a missing dependency are indistinguishable from the
    // outside, and treating either as a skip would pass a test whose code
    // ran and did not work.
    assert!(
        output.status.success(),
        "`mscp generate` failed. If this is a missing Python dependency for the \
         mSCP generation script, install it — do not read a failure here as \
         environmental without checking.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let oq = out.path().join("osquery").join(BASELINE);
    assert!(
        oq.join(format!("{BASELINE}.policies.yml")).exists(),
        "expected Fleet policies.yml"
    );
    assert!(
        oq.join(format!("{BASELINE}-audit.sh")).exists(),
        "expected audit script"
    );
    assert!(
        oq.join(format!("{BASELINE}.osquery-coverage.md")).exists(),
        "expected coverage report"
    );

    let cov = std::fs::read_to_string(oq.join(format!("{BASELINE}.osquery-coverage.md"))).unwrap();
    assert!(
        cov.contains("Tier-1"),
        "coverage report must mention Tier-1; got:\n{cov}"
    );

    // Slim scope: the audit script covers residual rules only — it must not be
    // empty, and the coverage report should account for the tier split.
    let sh = std::fs::read_to_string(oq.join(format!("{BASELINE}-audit.sh"))).unwrap();
    assert!(
        sh.contains("#!/bin/bash"),
        "audit script must be a shell script"
    );

    // Invariant (regression guard for the downgraded-native → phantom-policy bug):
    // every plist-reading policy key must be written by an audit block. Collect the
    // keys the audit script writes, then check each plist-policy key against them.
    let written: std::collections::HashSet<&str> = sh
        .lines()
        .filter_map(|l| {
            l.trim()
                .strip_prefix("/usr/bin/defaults write \"$PLIST\" \"")
        })
        .filter_map(|rest| rest.split('"').next())
        .collect();
    let policies = std::fs::read_to_string(oq.join(format!("{BASELINE}.policies.yml"))).unwrap();
    for line in policies.lines() {
        if let Some(after) = line.split("FROM plist").nth(1) {
            if let Some(key) = after
                .split("key = '")
                .nth(1)
                .and_then(|s| s.split('\'').next())
            {
                assert!(
                    written.contains(key),
                    "policy reads plist key '{key}' that no audit block writes"
                );
            }
        }
    }
}
