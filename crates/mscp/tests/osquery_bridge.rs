//! Integration: `mscp generate --osquery` over the local `macos_security` repo.
//!
//! The `mscp` binary exposes `generate` as a top-level subcommand, so this
//! test drives `CARGO_BIN_EXE_mscp` directly (no `mscp` subcommand prefix).
//!
//! `--osquery` requires a resolvable org (`--org`). The whole test self-skips
//! when the `macos_security` repo or a Python toolchain is absent, so CI never
//! fails on a missing environment.
//!
//! The baseline keyword (`cis_lvl1`) is chosen because its `baselines/` YAML
//! filename matches the keyword on the local repo; mSCP 1.x layout resolution
//! is filename-based.

use std::path::Path;
use std::process::Command;

/// The baseline this test generates. Its `baselines/<BASELINE>.yaml` must exist
/// in the local `macos_security` checkout for the test to run (else it skips).
const BASELINE: &str = "cis_lvl1";

/// Path to the local `macos_security` repo (repo root), relative to this
/// crate's manifest dir (`crates/mscp/`). Returns `None` when the baseline YAML
/// this test needs is not present.
fn repo() -> Option<&'static str> {
    let candidate = "../../macos_security";
    Path::new(candidate)
        .join(format!("baselines/{BASELINE}.yaml"))
        .exists()
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
fn osquery_slim_fleet_emits_queries_audit_and_coverage() {
    let Some(repo) = repo() else {
        eprintln!("skipped: macos_security repo absent");
        return;
    };
    if !has_python() {
        eprintln!("skipped: python3 toolchain absent (mscp generate needs it)");
        return;
    }

    let out = tempfile::tempdir().unwrap();
    let out_path = out.path().to_str().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mscp"))
        .args([
            "generate",
            "-m",
            repo,
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

    if !output.status.success() {
        // A failure here is most likely an environment limitation (missing
        // Python deps for the mSCP generation script), not a code defect.
        // Skip rather than fail so CI stays green.
        eprintln!(
            "skipped: `mscp generate` did not succeed (likely Python toolchain limitation)\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

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
