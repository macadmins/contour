//! `excluded_rules` must reach the code that excludes things.
//!
//! The setting was parsed into `BaselineConfig`, counted, and printed —
//! `Excluded rules: 1` — and then not passed to anything. `generate_baseline`
//! had no parameter for it and no filter consulted it. The template documents
//! it ("List of rule IDs to skip") and ships a working example, so an
//! operator had every reason to believe a rule was held back while it shipped
//! in every artifact.
//!
//! That is worse than a silently ignored flag. A flag that does nothing is
//! quiet; this one reported success it did not have. Nothing in the type
//! system objects to a field that is only ever read for its `.len()`.
//!
//! So the wiring is asserted at the source, the way `--osquery`'s is: the
//! config-driven call sites must hand the setting on, and the applying code
//! must consult the resolver. The behaviour itself is covered by unit tests
//! on `finalize_exclusion_plan` in `managers::category_resolver`.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// Every source that dispatches a config-driven `generate`, and what it is.
const CONFIG_DRIVEN_CALL_SITES: &[(&str, &str)] = &[
    (
        "crates/mscp/src/cli/config_generate.rs",
        "`generate-all --config`",
    ),
    ("crates/mscp/src/main.rs", "`mscp generate --config`"),
    (
        "crates/contour/src/dispatch.rs",
        "`contour mscp generate --config`",
    ),
];

#[test]
fn every_config_driven_path_passes_excluded_rules_on() {
    let root = workspace_root();
    let mut missing = Vec::new();
    for (rel, what) in CONFIG_DRIVEN_CALL_SITES {
        let src = std::fs::read_to_string(root.join(rel))
            .unwrap_or_else(|e| panic!("{rel} must be readable: {e}"));
        if !src.contains("baseline_config.excluded_rules.clone()") {
            missing.push(format!("  {rel} — {what}"));
        }
    }
    assert!(
        missing.is_empty(),
        "these config-driven paths do not pass `excluded_rules` to generate_baseline:\n{}\n\n\
         A config field read only for its length is the original bug: the run prints a \
         count and excludes nothing.",
        missing.join("\n")
    );
}

/// The setting is applied, not merely carried.
///
/// Passing it in and then not using it would look identical from the call
/// sites above.
#[test]
fn the_applying_code_resolves_the_rule_ids() {
    let root = workspace_root();
    let src = std::fs::read_to_string(root.join("crates/mscp/src/cli/process.rs"))
        .expect("process.rs readable");
    assert!(
        src.contains("build_rule_exclusion_plan"),
        "process_baseline takes `excluded_rules` but never resolves it"
    );
    assert!(
        src.contains("baseline.mobileconfigs.retain"),
        "the plan is built but no profile is ever removed from the baseline"
    );
}

/// The count that lied is gone.
///
/// `println!("  Excluded rules: {}", …len())` reported the number of ids in
/// the config, which was true, and meant nothing. It is replaced by a
/// warning that reports what the exclusion did.
#[test]
fn the_count_that_reported_success_is_not_printed_any_more() {
    let root = workspace_root();
    let src = std::fs::read_to_string(root.join("crates/mscp/src/cli/config_generate.rs"))
        .expect("config_generate.rs readable");
    assert!(
        !src.contains("Excluded rules: {}"),
        "config_generate.rs still prints a count of configured ids. That line was the \
         defect's disguise: it told the operator the exclusion happened."
    );
}

/// An unknown rule id must stop the run.
///
/// A typo that excludes nothing is indistinguishable from an exclusion that
/// worked, which is the failure mode this whole setting had.
#[test]
fn an_unknown_rule_id_is_refused_rather_than_ignored() {
    let root = workspace_root();
    let src = std::fs::read_to_string(root.join("crates/mscp/src/cli/process.rs"))
        .expect("process.rs readable");
    // Anchored on the CALL, not the name — the `use` line carries it too,
    // and splitting on the bare name measured the import instead.
    let at = src
        .find("build_rule_exclusion_plan(rules")
        .expect("the rule-exclusion call");
    let block = &src[at..src.len().min(at + 3000)];
    assert!(
        block.contains("plan.unresolved.is_empty()"),
        "the rule-exclusion path does not check for unresolved ids"
    );
    assert!(
        block.contains("anyhow::bail!"),
        "unresolved rule ids must fail the run, not warn: an id that matches nothing \
         excludes nothing, and looks exactly like success"
    );
}

/// The generated config must not ship a rule id.
///
/// `contour mscp init` shipped `excluded_rules = ["os_sshd_permit_root_login"]`
/// for years, and it was wrong twice: the rule is
/// `os_sshd_permit_root_login_configure`, and it carries the 800-53r5_high
/// tag rather than the moderate baseline the example sat under. Neither
/// error could surface while nothing read the setting.
///
/// Now that an unknown id fails the run, a shipped id is a generated config
/// that breaks on first use. And a static template cannot keep one correct:
/// mSCP renames and retags rules between releases, so any id written here
/// rots on someone else's checkout. The comment block explains how to find
/// real ids instead.
#[test]
fn the_generated_config_ships_no_rule_ids() {
    let root = workspace_root();
    let src = std::fs::read_to_string(root.join("crates/mscp/src/config/template.rs"))
        .expect("template.rs readable");
    // Rust initialisers only. The template also contains its own help text
    // as `#`-prefixed lines, and the line documenting this field mentions it
    // by name — which the first version of this test read as an offender.
    let offenders: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("excluded_rules:"))
        .filter(|l| !l.contains("vec![]"))
        .collect();
    assert!(
        offenders.is_empty(),
        "the config template ships rule ids in excluded_rules:\n{}\n\n\
         An id that is absent from the user's mSCP checkout now fails their first \
         run. Ship an empty list and document how to find ids.",
        offenders.join("\n")
    );
}
