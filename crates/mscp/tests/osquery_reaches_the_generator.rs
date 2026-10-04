//! `--osquery` must reach the generator from every path that can ask for it.
//!
//! The unit tests next to `resolve_osquery_options` prove the precedence rule
//! is right. They cannot prove anyone calls it. That was exactly the shape of
//! the bug: the options were built correctly at the top of the command and a
//! hardcoded `None` was passed at the bottom, so `generate --config
//! mscp.toml --osquery` accepted the flag, wrote no osquery tree, said
//! nothing, and exited 0.
//!
//! Two call sites had that `None` — `contour`'s dispatcher and the standalone
//! `mscp` binary — and a third path, `generate_from_config`, had no way to
//! ask at all. This test reads the sources and requires each of them to route
//! through the shared resolver, so a revert to `None` fails the build with a
//! name rather than going quiet again.
//!
//! It is a source-text test, which is blunt, and deliberately so: the defect
//! is invisible at runtime unless you go looking in an output directory for a
//! thing that is not there.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    // crates/mscp/tests/… → workspace root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// Every source that dispatches a config-driven `generate`, and what it is.
const CONFIG_DRIVEN_CALL_SITES: &[(&str, &str)] = &[
    (
        "crates/contour/src/dispatch.rs",
        "`contour mscp generate --config … --osquery`",
    ),
    (
        "crates/mscp/src/main.rs",
        "`mscp generate --config … --osquery`",
    ),
    (
        "crates/mscp/src/cli/config_generate.rs",
        "`generate-all --config`, via [settings.osquery]",
    ),
];

#[test]
fn every_config_driven_path_routes_through_the_resolver() {
    let root = workspace_root();
    let mut missing = Vec::new();
    for (rel, what) in CONFIG_DRIVEN_CALL_SITES {
        let src = std::fs::read_to_string(root.join(rel))
            .unwrap_or_else(|e| panic!("{rel} must be readable: {e}"));
        if !src.contains("resolve_osquery_options") {
            missing.push(format!("  {rel} — {what}"));
        }
    }
    assert!(
        missing.is_empty(),
        "these config-driven paths no longer route --osquery through \
         resolve_osquery_options:\n{}\n\n\
         A hardcoded `None` here is the original bug: the flag is accepted, \
         nothing is written, and nothing says so.",
        missing.join("\n")
    );
}

/// The phrase that marked the bug must not come back with it.
///
/// Both `None`s carried the comment "osquery — not exposed in config-driven
/// generation", which described the defect accurately enough that it read as
/// a design decision for as long as it survived.
#[test]
fn the_comment_that_excused_the_gap_is_gone() {
    let root = workspace_root();
    let mut found = Vec::new();
    for (rel, _) in CONFIG_DRIVEN_CALL_SITES {
        let src = std::fs::read_to_string(root.join(rel)).expect("readable");
        for (i, line) in src.lines().enumerate() {
            if line.contains("not exposed in config-driven")
                || line.contains("not yet plumbed for generate-all")
            {
                found.push(format!("  {rel}:{}", i + 1));
            }
        }
    }
    assert!(
        found.is_empty(),
        "the gap's own excuse is back in the source:\n{}",
        found.join("\n")
    );
}

/// `generate-all` in CLI-flag mode passes `None` correctly — for now.
///
/// That mode reads no mscp.toml and exposes no `--osquery`, so `None` is the
/// true answer rather than a dropped value. The moment someone adds the flag,
/// that stops being true and the `None` becomes the same silent drop. This
/// test is the tripwire: it fails when the flag appears, pointing at the two
/// call sites in `generate_all_baselines` that would need wiring.
#[test]
fn generate_all_has_no_osquery_flag_to_drop() {
    let root = workspace_root();
    let src = std::fs::read_to_string(root.join("crates/mscp/src/cli/mod.rs")).expect("readable");
    let generate_all = src
        .split("GenerateAll {")
        .nth(1)
        .expect("a GenerateAll command variant");
    let body = &generate_all[..generate_all.find("\n    },").unwrap_or(generate_all.len())];
    assert!(
        !body.contains("osquery"),
        "`generate-all` now takes an osquery flag, but generate_all_baselines() \
         still passes None for it — wire it through, the same way the --config \
         paths route via resolve_osquery_options()"
    );
}
