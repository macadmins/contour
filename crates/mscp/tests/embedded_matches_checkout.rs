//! The embedded dataset and a live mSCP checkout must agree on baseline
//! membership.
//!
//! contour answers baseline questions two ways: from the parquet embedded at
//! compile time (built from a checkout), and by reading a local checkout
//! directly via `--mscp-repo`. Either can be wrong without the other
//! noticing; "some baselines work" is what that drift looks like from
//! outside.
//!
//! This ties the two together for one baseline: the rule-id set the dataset
//! carries in `baseline_edges` must equal the `profile[].rules[]` list in the file
//! `MscpLayout::baseline_file` resolves. A disagreement means one side moved.
//!
//! Needs a real mSCP 2.0 checkout: set `CONTOUR_MSCP_REPO` to one. Skips
//! loudly when unset — a missing checkout is not a failure, and no default
//! path is assumed, since that would only exist on one machine.

use mscp::layout::MscpLayout;
use std::collections::BTreeSet;
use std::path::PathBuf;

const BASELINE: &str = "cis_lvl1";
const OS_DIR: &str = "macos";
const PLATFORM: &str = "macOS";
const OS_VERSION: &str = "27.0";

/// Mirrors the private membership reader in `extractors::rules` — the
/// authoritative list is `profile[].rules[]`, flattened across sections.
#[derive(serde::Deserialize)]
struct Baseline {
    #[serde(default)]
    profile: Vec<Section>,
}

#[derive(serde::Deserialize)]
struct Section {
    #[serde(default)]
    rules: Vec<String>,
}

fn checkout() -> Option<PathBuf> {
    let candidate = std::env::var_os("CONTOUR_MSCP_REPO").map(PathBuf::from)?;
    candidate.join("rules").exists().then_some(candidate)
}

fn ids_from_file(repo: &std::path::Path) -> BTreeSet<String> {
    let layout = MscpLayout::detect(repo).expect("checkout must be an mSCP 2.0 tree");
    let path = layout
        .baseline_file(repo, BASELINE, OS_DIR, Some(OS_VERSION))
        .expect("baseline file must resolve");
    let text = std::fs::read_to_string(&path).expect("read baseline file");
    let parsed: Baseline = yaml_serde::from_str(&text).expect("parse baseline file");
    parsed.profile.into_iter().flat_map(|s| s.rules).collect()
}

fn ids_from_embedded() -> BTreeSet<String> {
    mscp_schema::baseline_edges::read(mscp_schema::embedded_baseline_edges())
        .expect("read embedded baseline_edges")
        .into_iter()
        .filter(|e| {
            e.baseline == BASELINE
                && e.platform.as_deref() == Some(PLATFORM)
                && e.os_version.as_deref() == Some(OS_VERSION)
        })
        .map(|e| e.rule_id)
        .collect()
}

#[test]
#[ignore = "needs an mSCP 2.0 checkout — set CONTOUR_MSCP_REPO and run with --include-ignored; \
            ci-check.sh does so when the variable is set"]
fn embedded_baseline_edges_match_the_checkout_file() {
    let repo = checkout().expect("CONTOUR_MSCP_REPO must point at an mSCP 2.0 checkout");

    let from_file = ids_from_file(&repo);
    let from_embedded = ids_from_embedded();

    assert!(
        !from_file.is_empty(),
        "the checkout's {BASELINE} file listed no rules — wrong file or wrong reader"
    );
    assert!(
        !from_embedded.is_empty(),
        "embedded baseline_edges carry no rows for {BASELINE}/{PLATFORM}/{OS_VERSION} — \
         the collapse signature"
    );

    let missing: Vec<&String> = from_file.difference(&from_embedded).collect();
    let extra: Vec<&String> = from_embedded.difference(&from_file).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "embedded data and checkout disagree on {BASELINE}/{PLATFORM}/{OS_VERSION}\n  \
         in the file but not embedded ({}): {:?}\n  \
         embedded but not in the file ({}): {:?}\n  \
         republish the dataset, or the local checkout is on a different commit",
        missing.len(),
        &missing[..missing.len().min(5)],
        extra.len(),
        &extra[..extra.len().min(5)]
    );
}

/// The comparison must be capable of failing: point the file side at a
/// baseline the embedded rows do not describe and the sets must diverge.
/// Without this, an always-equal comparison (two empty sets, a filter that
/// matches nothing) would read as a passing cross-check.
#[test]
#[ignore = "needs an mSCP 2.0 checkout — set CONTOUR_MSCP_REPO and run with --include-ignored"]
fn the_cross_check_can_actually_fail() {
    let repo = checkout().expect("CONTOUR_MSCP_REPO must point at an mSCP 2.0 checkout");

    let layout = MscpLayout::detect(&repo).expect("2.0 tree");
    let path = layout
        .baseline_file(&repo, "all_rules", OS_DIR, Some(OS_VERSION))
        .expect("all_rules must resolve");
    let text = std::fs::read_to_string(&path).expect("read");
    let parsed: Baseline = yaml_serde::from_str(&text).expect("parse");
    let all_rules: BTreeSet<String> = parsed.profile.into_iter().flat_map(|s| s.rules).collect();

    let cis = ids_from_embedded();
    assert!(
        all_rules != cis,
        "all_rules and cis_lvl1 came out identical — the comparison is not discriminating"
    );
}
