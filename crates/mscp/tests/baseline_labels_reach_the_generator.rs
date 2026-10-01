//! `[baselines.labels]` must reach the team YAML.
//!
//! The template calls it "Label targeting for progressive rollout" and the
//! generated `mscp.toml` shipped values for it. `LabelConfig` was parsed into
//! `BaselineConfig` and never read — an operator staging a rollout got no
//! staging and no complaint.
//!
//! Only `include_all` can be honoured, and the constraint is Fleet's: an
//! entry takes at most one label field, and the generated `mscp-<baseline>`
//! label already occupies `labels_include_all`. Adding to that list narrows
//! the target, which is what a staged rollout means. `include_any` would
//! widen it and `exclude_any` needs a second field; either means dropping the
//! baseline label and sending security profiles to a different set of hosts,
//! so the run refuses instead of guessing.
//!
//! Emission is unit-tested in `generators::fleet_gitops`; Fleet's one-field
//! rule in `models::fleet`. These hold the wiring and the template.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

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
fn every_config_driven_path_passes_the_labels_on() {
    let root = workspace_root();
    let mut missing = Vec::new();
    for (rel, what) in CONFIG_DRIVEN_CALL_SITES {
        let src = std::fs::read_to_string(root.join(rel)).expect("readable");
        if !src.contains("baseline_config.labels.clone()") {
            missing.push(format!("  {rel} — {what}"));
        }
    }
    assert!(
        missing.is_empty(),
        "these config-driven paths do not pass `[baselines.labels]` to \
         generate_baseline:\n{}",
        missing.join("\n")
    );
}

/// Carried is not applied.
#[test]
fn the_labels_reach_the_emitted_entries() {
    let root = workspace_root();
    let process = std::fs::read_to_string(root.join("crates/mscp/src/cli/process.rs"))
        .expect("process.rs readable");
    assert!(
        process.contains("extra_include_all"),
        "process_baseline takes the labels but never resolves them into the glob plan"
    );
    let generator =
        std::fs::read_to_string(root.join("crates/mscp/src/generators/fleet_gitops.rs"))
            .expect("fleet_gitops.rs readable");
    assert!(
        generator.contains("chain(extra_include_all.iter().cloned())"),
        "the generator does not add the configured labels to labels_include_all"
    );
}

/// The two that cannot be honoured must fail, not be dropped.
#[test]
fn include_any_and_exclude_any_are_refused_rather_than_ignored() {
    let root = workspace_root();
    let src = std::fs::read_to_string(root.join("crates/mscp/src/cli/process.rs"))
        .expect("process.rs readable");
    let at = src
        .find("let extra_include_all")
        .expect("the label-resolution block");
    let block = &src[at..src.len().min(at + 3000)];
    for field in ["include_any", "exclude_any"] {
        assert!(
            block.contains(field),
            "the label block does not mention {field}; it is being silently dropped"
        );
    }
    assert!(
        block.contains("anyhow::bail!"),
        "a label field that cannot be emitted must fail the run — emitting nothing \
         looks exactly like emitting correctly"
    );
}

/// The generated config must not ship labels.
///
/// It shipped `include_all = ["com.acme.mscp.cis-lvl1"]` and
/// `exclude_any = ["cis-exemption"]`. Both were wrong and neither could
/// surface while nothing read them: contour generates `mscp-<baseline>`
/// labels, never org-prefixed ones, so that include_all named a label that
/// exists in no Fleet instance — and now that it is emitted, every profile
/// in a freshly generated config would require it and reach no hosts at all.
/// The exclude_any would simply fail the run.
///
/// A static template cannot know the labels in someone's Fleet. It ships
/// empty lists and explains the semantics in its comment block.
#[test]
fn the_generated_config_ships_no_labels() {
    let root = workspace_root();
    let src = std::fs::read_to_string(root.join("crates/mscp/src/config/template.rs"))
        .expect("template.rs readable");
    let offenders: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|l| {
            l.starts_with("include_all:")
                || l.starts_with("include_any:")
                || l.starts_with("exclude_any:")
        })
        .filter(|l| !l.contains("vec![]"))
        .collect();
    assert!(
        offenders.is_empty(),
        "the config template ships label names:\n{}\n\n\
         include_all is now emitted into every profile entry, so a name that does not \
         exist in the user's Fleet silently targets nothing; include_any/exclude_any \
         fail the run outright.",
        offenders.join("\n")
    );
}
