//! No test in this workspace may skip itself into a pass.
//!
//! A test that returns early on a missing fixture is green on every machine
//! that lacks it — which is usually every CI runner, and eventually every
//! machine. It does not fail, it does not run, and nothing distinguishes the
//! two from the outside. The worst kind runs the code under test, watches it
//! FAIL, prints "skipped" and passes.
//!
//! The rule is: a test that cannot run says so through `#[ignore]`, and the
//! reason names what it needs, so something can arrange to run it.
//!
//!     #[ignore = "needs <what>; run with --include-ignored"]
//!
//! This test is not itself ignored. It reads the repository's own sources.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target" || n == "data") {
                continue;
            }
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

fn sources() -> Vec<(PathBuf, String)> {
    let root = workspace_root();
    let mut files = Vec::new();
    rust_sources(&root.join("crates"), &mut files);
    files
        .into_iter()
        .filter(|f| {
            // This file quotes the patterns it forbids.
            f.file_name().is_none_or(|n| n != "no_silent_skips.rs")
        })
        .map(|f| {
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            let rel = f.strip_prefix(workspace_root()).unwrap_or(&f).to_path_buf();
            (rel, text)
        })
        .collect()
}

/// Nothing prints "skipped" and carries on.
///
/// The string is the tell. A test that has decided to skip says so to the
/// console because there is nowhere else to say it — which is exactly the
/// problem, since nobody reads a passing test's output.
#[test]
fn no_test_prints_that_it_skipped() {
    let mut offenders = Vec::new();
    for (path, text) in sources() {
        for (n, line) in text.lines().enumerate() {
            let l = line.trim();
            if !(l.starts_with("eprintln!") || l.starts_with("println!")) {
                continue;
            }
            let lower = l.to_lowercase();
            if lower.contains("\"skip") || lower.contains("skipped:") || lower.contains("skipping:")
            {
                offenders.push(format!("  {}:{}", path.display(), n + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these look like a test skipping itself into a pass. Use\n  \
         #[ignore = \"needs <what>; run with --include-ignored\"]\nand panic \
         (or assert) when asked to run without it:\n{}",
        offenders.join("\n")
    );
}

/// Every `#[ignore]` says what it needs.
///
/// "requires actual mSCP repository" is a reason a person can read and
/// nothing can act on. `needs ./macos_security` names a path, so a runner can
/// check whether this machine has it.
#[test]
fn every_ignored_test_says_what_it_needs() {
    let mut offenders = Vec::new();
    for (path, text) in sources() {
        for (n, line) in text.lines().enumerate() {
            let l = line.trim();
            if !l.starts_with("#[ignore") {
                continue;
            }
            // `#[ignore]` bare, or a reason that does not name a requirement.
            if !l.contains("needs ") {
                offenders.push(format!("  {}:{}  {}", path.display(), n + 1, l));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these #[ignore] attributes do not say what they need, so nothing can \
         arrange to run them:\n{}",
        offenders.join("\n")
    );
}
