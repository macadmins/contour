//! An excluded rule leaves every artifact, not only its profile.
//!
//! `excluded_rules` dropped the rule's profile and printed "1 script(s)
//! suppressed" — and the rule's check and fix stayed in the generated
//! scripts, its Fleet policy stayed in `policies/`, and its osquery check
//! stayed in `osquery/`. Suppression was written to a constraints file that
//! nothing read back, and that file landed in whatever directory the command
//! ran from.

use assert_cmd::Command;
use std::path::Path;

const EXCLUDED: &[&str] = &[
    "system_settings_improve_assistive_voice_disable",
    "os_airdrop_disable",
    "audit_auditd_enabled",
];

fn files_mentioning(dir: &Path, needle: &str) -> Vec<String> {
    walk(dir)
        .into_iter()
        .filter(|p| {
            !p.file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with("-constraints.yml"))
        })
        .filter(|p| std::fs::read_to_string(p).is_ok_and(|t| t.contains(needle)))
        .map(|p| p.strip_prefix(dir).unwrap().display().to_string())
        .collect()
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
#[ignore = "needs an mSCP 2.0 checkout — set CONTOUR_MSCP_REPO and run with --include-ignored"]
fn excluded_rules_ship_no_script_policy_or_osquery_check() {
    let repo = std::env::var("CONTOUR_MSCP_REPO")
        .expect("CONTOUR_MSCP_REPO must point at an mSCP 2.0 checkout");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let run_from = dir.path().join("cwd");
    std::fs::create_dir(&run_from).unwrap();
    let config = dir.path().join("mscp.toml");
    std::fs::write(
        &config,
        format!(
            "[settings]\nmscp_repo = {repo:?}\noutput_dir = {out:?}\n\
             [settings.organization]\ndomain = \"com.acme\"\nname = \"Acme\"\n\
             [settings.fleet]\nenabled = true\n[settings.osquery]\nenabled = true\n\
             [output]\nstructure = \"pluggable\"\n\
             [[baselines]]\nname = \"cis_lvl1\"\nexcluded_rules = {EXCLUDED:?}\n"
        ),
    )
    .unwrap();

    let o = Command::cargo_bin("contour")
        .unwrap()
        .current_dir(&run_from)
        .args(["mscp", "generate-all", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));

    for rule in EXCLUDED {
        let left = files_mentioning(&out, rule);
        assert!(left.is_empty(), "{rule} is excluded but still in: {left:?}");
    }
    assert!(
        out.join("mscp/cis_lvl1/fleet-constraints.yml").is_file(),
        "the record of what was excluded sits with the baseline's metadata"
    );
    assert!(
        !out.join("fleet-constraints.yml").exists(),
        "not at the root, beside the GitOps documents"
    );
    assert_eq!(
        std::fs::read_dir(&run_from).unwrap().count(),
        0,
        "nothing is written to the directory the command runs from"
    );
}
