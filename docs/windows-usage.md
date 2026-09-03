# Running contour on Windows: a portability assessment

**Status:** research note · 2026-08-27 · audited against workspace `v0.4.1-beta.1`
**Verdict up front:** there is no architectural blocker. The one macOS-bound
command (`profile sign`) already fails gracefully off-platform, the mSCP clone
path already uses a vendored cross-platform git, and CI already proves the
codebase builds and runs beyond macOS (Linux release builds ship today). What
Windows needs is a CI leg, a handful of shell-out audits, and a decision about
which device-local commands are explicitly out of scope.

---

## 1. Question

contour generates and validates Apple MDM artifacts — mobileconfig profiles,
DDM declarations, Santa rules, mSCP compliance output, Fleet GitOps files.
None of that output runs on the machine that generates it; it is text, plist,
and JSON destined for an MDM server. So the question is not "does contour make
sense on Windows" (a Windows-based Mac admin team is a real audience, and the
schema layer already carries Windows CSP metadata) but: **what actually
prevents the binary from being built, tested, and supported on
`x86_64-pc-windows-msvc` today?**

## 2. Method

This note is based on a source audit of the workspace, not on a Windows build.
Specifically:

- every `#[cfg(target_os/unix/windows)]` in the workspace
- every `Command::new` shell-out outside test code
- the dependency graph for platform-native crates
- the signing/unsigning implementation
- hardcoded absolute paths
- the CI workflows and release targets

Claims below cite `file:line` so they can be re-verified. What this note does
**not** include: an actual `cargo build --target x86_64-pc-windows-msvc` run,
or a Windows test-suite pass. Section 6 makes that the first action item.

## 3. Findings

### 3.1 The codebase is already cross-platform in practice

`release.yml` builds and strips `x86_64-unknown-linux-gnu` on `ubuntu-latest`
(`.github/workflows/release.yml:13-45`). contour is therefore not a macOS
program with a theoretical portability story — it already compiles, links, and
ships on a second OS. Windows is the third leg, not the first step off macOS.

The core dependency set is pure Rust and Tier-1 on Windows: `arrow`/`parquet`
(embedded schema data), `serde`, `plist`, `clap`, `walkdir`, `rayon`, `toml`,
`colored`. No `security-framework`, `core-foundation`, or `objc` bindings
appear anywhere in the workspace (verified across all `Cargo.toml`s). The
embedded-data design helps directly: all 13,500+ Apple keys, osquery tables,
and mSCP rules are compiled into the binary as parquet, so there is no
platform-dependent runtime data path at all.

Exactly **one** `#[cfg(unix)]` exists in the entire workspace:
`crates/mscp/src/transformers/script_helpers.rs:248` (Unix file-permission
handling for generated remediation scripts). That is the correct shape — the
generated scripts are zsh/bash for *target* Macs regardless of where they are
generated; only the local `chmod` is platform-gated.

### 3.2 Signing: already handled, better than expected

The earlier assessment flagged `profile sign` as the open question. The code
answers it:

- **Signing** shells out to macOS `security cms`
  (`crates/profile/src/signing/mod.rs:62`) — and is already guarded by
  `require_macos()`, which returns a clean typed error on any other platform:
  *"requires macOS (uses `security` command-line tool)"*
  (`signing/mod.rs:12-17`). The graceful "not available on this platform"
  path recommended in the earlier assessment **already exists**.
- **Unsigning and signature inspection** use the pure-Rust RustCrypto `cms`
  crate (`signing/mod.rs:303-305`, `audit/cert.rs:47-48`), so
  `profile unsign`, signed-profile parsing (`parse_profile_auto_unsign`, used
  by `validate`, `link`, `import`), and certificate audits work on every
  platform today.

A future cross-platform *signing* path (RustCrypto `cms` supports building
`SignedData`, not just parsing it) is an enhancement, not a prerequisite:
profile signing is optional in most MDM pipelines, and Fleet/Jamf can sign
server-side.

### 3.3 Shell-outs: concentrated in one crate, mostly optional paths

All non-test `Command::new` calls in the workspace:

| Site | Invokes | Windows impact |
|------|---------|----------------|
| `crates/profile/src/signing/mod.rs` | `security` | already gated (§3.2) |
| `crates/mscp/src/cli/generate.rs:707,741` | `python3`, `uv` | legacy mSCP-pipeline mode only |
| `crates/mscp/src/cli/generate.rs:809-1037` | `docker`, `container` | optional container mode |
| `crates/mscp/src/cli/generate.rs:557,944-991`, `managers/odv.rs:310` | `git` | metadata/branch queries; needs git on PATH |
| `crates/mscp-schema/build.rs:45,60` | `curl`, `unzip` | **build-time only**, skipped when data present |

Two observations. First, **`mscp init --sync` does not shell out** — it clones
via `git2` with `vendored-openssl` + `vendored-libgit2`
(`crates/mscp/src/cli/init.rs:573`, workspace `Cargo.toml:66`), so the
headline mSCP bootstrap works on a Windows box with no git installed. The
remaining `git` shell-outs are secondary (branch/status reporting, ODV
history) and degrade to error messages, not corruption, when git is absent.

Second, the `curl`/`unzip` shell-out in `mscp-schema/build.rs` is a
*build-machine* concern, not an end-user one: it fires only when
`data/*.parquet` is missing. Windows CI either pre-seeds the data directory
(as `CONTOUR_SCHEMA_SKIP_DOWNLOAD` already allows for the mdm-schema crate) or
the fetch moves to a Rust HTTP client. Users of a released binary never hit
this path.

### 3.4 Commands that are macOS-bound by *meaning*, not by accident

Some subcommands inspect the local machine and are meaningless off-macOS no
matter how portable the code is:

- `contour btm scan` — walks `/Library/LaunchDaemons` and
  `/Library/LaunchAgents` (`crates/btm/src/scan.rs:133-134`)
- `contour santa scan --path /Applications` — inventories local app bundles

These should get the same `require_macos()`-style guard as signing, with an
error that says *why* ("scans the local macOS system"), and be listed as
out-of-scope in a platform-support table. Generation of Santa *rules* from an
existing CSV/JSON inventory, by contrast, is pure data transformation and
works anywhere.

### 3.5 The Windows CSP angle makes this more than a porting exercise

The schema layer already carries Windows: `csp_name` is a first-class column
in the capabilities data (`crates/mdm-schema/src/types.rs:266`,
`capabilities.rs` reads it tolerantly), fed by the posture-ingest Windows
DDF/STIG pipeline. The plausible near-term audience is a Fleet shop managing
both platforms from one GitOps repo — where a Windows admin generating CSP
XML with contour on their own machine is the natural workflow, and "runs on
Windows" stops being a nice-to-have.

As the earlier assessment noted, the reverse also holds: Windows CSP
*generation* could ship before Windows *support*, since macOS-based admins can
build the artifacts. The two are independent shipping decisions.

### 3.6 Residual risks (the honest list)

1. **Untested is unsupported.** No Windows target is exercised in CI; under
   `RUSTFLAGS=-D warnings` a first Windows build will likely surface small
   issues (unused imports under different cfgs, `colored` needing virtual
   terminal enablement on older Windows 10 shells).
2. **Path semantics.** The code consistently uses `Path`/`PathBuf`, and the
   absolute Unix paths that exist are either device-scan features (§3.4) or
   test fixtures — but glob handling (`glob_utils`), `~` expansion if any, and
   path-separator assumptions in *output* (e.g. paths printed into Fleet YAML)
   deserve a targeted review on real Windows.
3. **Config discovery.** `.contour/config.toml` walk-up and `CONTOUR_ORG`
   resolution should behave identically, but home-directory and env handling
   is a classic Windows-divergence spot.
4. **Line endings.** Generated mobileconfig/JSON should stay `\n`; a CRLF
   sneaking in via text-mode writes would break byte-identical determinism —
   the property the CI story depends on. Worth one explicit test.

## 4. Recommendations

Ordered so each step gates the next:

1. **Add `x86_64-pc-windows-msvc` to CI** (build + `cargo test --workspace`
   under `-D warnings`, `CONTOUR_SCHEMA_SKIP_DOWNLOAD=1` with pre-seeded
   data). This converts every claim in this note from "audited" to
   "verified" and keeps it true — untested platforms rot fast.
2. **Extend `require_macos()` to `btm scan` and `santa scan`** so every
   device-local command fails with intent rather than an ENOENT.
3. **Document a platform-support matrix** in the README: generate/validate/
   link/mscp/DDM — all platforms; sign — macOS; local scans — macOS.
4. **Later, if demand appears:** pure-Rust CMS signing (drop the last macOS
   gate), and replacing the residual `git`/`curl`/`unzip` shell-outs with
   `git2`/a Rust HTTP client for a zero-external-tool Windows story.

## 5. Conclusion

The earlier framing — "no architectural blocker visible, but not verified" —
was correct and can now be sharpened: the blockers that were hypothesized
(signing, mSCP cloning) turn out to be already solved in the code, the
platform-specific surface is a single `#[cfg(unix)]` plus one gated command,
and the project already ships on a non-Apple OS. Windows support is a CI
commitment and a short hardening pass, not a port. The strategic reason to
make that commitment is §3.5: contour's data model is already half-Windows;
the binary might as well follow.
