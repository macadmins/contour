#!/usr/bin/env bash
# CI-parity local check.
#
# Mirrors what the GitHub Actions workflows actually gate on, so a clean
# local run here means CI will go green. The implicit `RUSTFLAGS=-D warnings`
# is set by `actions-rust-lang/setup-rust-toolchain@v1` in CI; we set it
# explicitly here to match.
#
# What this checks:
#   * `cargo fmt --all --check`             — formatting hygiene
#   * `RUSTFLAGS=-D warnings cargo build --workspace`  — lib + bin warning-free
#   * `RUSTFLAGS=-D warnings cargo build --release -p contour`  — release.yml parity
#   * `cargo clippy --workspace --all-targets -- -D warnings`  — strict clippy
#     across lib + bins + tests + examples
#   * `cargo test --workspace --no-fail-fast` — the whole test suite
#
# Tests are gated here although no GitHub workflow runs them yet. Without
# it, nothing ran them at all, and a test broken by an intentional change
# stayed broken unnoticed: in September 2026 two traps sat failing for days
# (a new preset collided with trap_79's import name; refusing `btm --ddm`
# contradicted trap_31). The test-code lints that once kept tests out are
# already enforced by clippy `--all-targets` above.
#
# `--no-fail-fast` matters: without it cargo stops at the first failing test
# binary, so one early failure hides every other result in the workspace.
#
# Build cache:
#   `RUSTFLAGS` is part of cargo's fingerprint, so sharing the default
#   `target/` with a plain `cargo test` makes each invocation invalidate
#   everything the other built — a full workspace rebuild per alternation.
#   This gate therefore keeps its own target directory. Override by setting
#   CARGO_TARGET_DIR in the environment.
#
# Usage: ./scripts/ci-check.sh
set -euo pipefail

cd "$(dirname "$0")/.."

export RUSTFLAGS="-D warnings"
: "${CARGO_TARGET_DIR:=$PWD/target/ci-check}"
export CARGO_TARGET_DIR

echo "==> cargo fmt --all --check"
cargo fmt --all --check

echo "==> cargo build --workspace (CI-strict — actions-rust-lang sets RUSTFLAGS=-D warnings)"
cargo build --workspace

echo "==> cargo build --release -p contour (release.yml parity)"
cargo build --release -p contour

echo "==> cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> cargo test --workspace --no-fail-fast"
cargo test --workspace --no-fail-fast

# Tests marked #[ignore] need a fixture this runner may not have (an mSCP
# checkout, a system app). They report as `ignored`, never as `ok`, so a
# missing fixture is visible in the summary instead of passing quietly —
# which is what the old `eprintln!("skipping…"); return;` pattern did, and
# why the mSCP cross-check had never actually run in CI. Opt in where the
# fixture exists:
if [[ -n "${CONTOUR_MSCP_REPO:-}" ]]; then
  echo "==> cargo test -p mscp --test embedded_matches_checkout -- --include-ignored  (CONTOUR_MSCP_REPO set)"
  cargo test -p mscp --test embedded_matches_checkout -- --include-ignored
fi

echo "==> all CI-parity checks passed"
