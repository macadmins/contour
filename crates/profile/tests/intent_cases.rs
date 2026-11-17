//! What an admin asks for, and the key that does it.
//!
//! Each case is a request in plain words and the key the ranked search must
//! put in its first ten. The search is deterministic, so this is a recall
//! measurement that cannot flake. Add a case when a phrase is found to miss;
//! raise a floor when a change makes more of them hit; never lower one to
//! make a change pass.
//!
//! Where the cases come from:
//!
//! - `own`, `windows`: written for this file.
//! - `cis`, `800-53`: every macOS rule of the CIS level 1 and 2 and NIST
//!   800-53r5 moderate and high baselines that a profile enforces with a key
//!   Apple's schema documents, read from contour's embedded mSCP data. The
//!   request is the rule's own title and the key is the one its
//!   `mobileconfig_info` sets; the rule id is in the comment. A rule in both
//!   families is filed under `cis`.
//! - `privileges`: SAP Privileges (`corp.sap.privileges`), requests written
//!   for this file against the keys' descriptions.
//! - `claude-code`: Claude Code managed settings
//!   (`com.anthropic.claudecode`), from the embedded app policy dataset.
//!   No command searches that dataset yet; the case runs the same ranker
//!   over it, which is what such a command would do.
//!
//! [`NOT_BY_PROFILE`] is the other half: requests a profile cannot meet.
//! Both tables live in `cases/mod.rs`.

mod cases;

use cases::{CASES, NOT_BY_PROFILE};
use profile::schema::{SchemaRegistry, rank_text};

const TOP: usize = 10;

/// Cases that must hit, per source: (source, floor).
const FLOORS: &[(&str, usize)] = &[
    ("own", 12),
    ("windows", 4),
    ("cis", 35),
    ("800-53", 41),
    ("privileges", 17),
    ("claude-code", 18),
];

/// Claude Code's managed keys: each key's dotted path, and its
/// `[name, context, text]` document, in the same order.
fn claude_code_docs() -> (Vec<String>, Vec<[String; 3]>) {
    app_policy_schema::app_policies::read(app_policy_schema::embedded_app_policies())
        .unwrap()
        .into_iter()
        .filter(|k| k.tool_id == "claude-code")
        .map(|k| {
            let doc = [
                k.key_name,
                format!(
                    "{} {} {}",
                    k.tool_name,
                    k.macos_domain.unwrap_or_default(),
                    k.key_path
                ),
                format!(
                    "{} {}",
                    k.title.unwrap_or_default(),
                    k.description.unwrap_or_default()
                ),
            ];
            (k.key_path, doc)
        })
        .unzip()
}

#[test]
fn requests_find_their_keys() {
    let apple = SchemaRegistry::embedded().unwrap();
    let windows = SchemaRegistry::embedded_windows().unwrap();
    let (claude_paths, claude) = claude_code_docs();

    let mut misses: Vec<(&str, String)> = Vec::new();
    for &(source, request, payload_type, path) in CASES {
        // The first few keys ranked for the request, and where the expected one landed.
        let (rank, got): (Option<usize>, Vec<String>) = if source == "claude-code" {
            let hits = rank_text(&claude, request);
            (
                hits.iter().position(|(i, _)| claude_paths[*i] == path),
                hits.iter()
                    .take(3)
                    .map(|(i, _)| claude_paths[*i].clone())
                    .collect(),
            )
        } else {
            let registry = if source == "windows" {
                &windows
            } else {
                &apple
            };
            let hits = registry.rank_fields(request);
            (
                hits.iter().position(|h| {
                    // A top-level key with dots in its name has them
                    // escaped in its path; mSCP writes the name.
                    h.manifest.payload_type == payload_type
                        && (h.field.path == path || h.field.name == path)
                }),
                hits.iter().take(3).map(|h| h.field.path.clone()).collect(),
            )
        };
        if rank.is_none_or(|r| r >= TOP) {
            misses.push((
                source,
                format!(
                    "  [{source}] {request:?} -> {payload_type} {path}: {}; got {}",
                    rank.map_or("not found".into(), |r| format!("rank {}", r + 1)),
                    got.join(", "),
                ),
            ));
        }
    }

    for (_, line) in &misses {
        println!("{line}");
    }
    let mut below = Vec::new();
    for &(source, floor) in FLOORS {
        let total = CASES.iter().filter(|c| c.0 == source).count();
        let hit = total - misses.iter().filter(|m| m.0 == source).count();
        println!("{source:<12} {hit:>3}/{total:<3} in the top {TOP} (floor {floor})");
        if hit < floor {
            below.push(format!("{source}: {hit}/{total}, floor {floor}"));
        }
    }
    assert!(
        CASES.iter().all(|c| FLOORS.iter().any(|f| f.0 == c.0)),
        "a case names a source with no floor"
    );
    assert!(
        below.is_empty(),
        "recall fell below its floor: {}",
        below.join("; ")
    );
}

/// The requests in [`NOT_BY_PROFILE`] really are out of a profile's reach.
#[test]
fn script_only_requests_have_no_profile_key() {
    let rules = mscp_schema::rule_meta::read(mscp_schema::embedded_rule_meta()).unwrap();
    for &(request, rule_id) in NOT_BY_PROFILE {
        let rows: Vec<_> = rules.iter().filter(|r| r.rule_id == rule_id).collect();
        assert!(!rows.is_empty(), "{request:?}: mSCP has no rule {rule_id}");
        assert!(
            rows.iter().all(|r| !r.mobileconfig && !r.has_ddm_info),
            "{request:?}: mSCP now enforces {rule_id} with a profile or declaration; move it to CASES"
        );
    }
}
