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
#
# What this does NOT check:
#   * `cargo test` under `-D warnings` — many test-code lints (snake_case
#     in test names, dead-code in test helpers, `#[expect]` unfulfilled
#     under test compilation) aren't currently CI-gated. Add them when
#     a test workflow lands.
#   * Strict `clippy` (`-D warnings` only catches rustc, not clippy).
#     `cargo clippy --all-targets -- -D warnings` would, but trips
#     ~60 pre-existing test-style errors. Not enabled here.
#
# Usage: ./scripts/ci-check.sh
set -euo pipefail

cd "$(dirname "$0")/.."

export RUSTFLAGS="-D warnings"

echo "==> cargo fmt --all --check"
cargo fmt --all --check

echo "==> cargo build --workspace (CI-strict — actions-rust-lang sets RUSTFLAGS=-D warnings)"
cargo build --workspace

echo "==> cargo build --release -p contour (release.yml parity)"
cargo build --release -p contour

echo "==> all CI-parity checks passed"
