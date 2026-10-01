//! `profile generate --recipe` and its `{{KEY}}` placeholders.
//!
//! A misspelled `--set` key was accepted silently and the run exited 0, as
//! did a run with no `--set` at all — so `generate && deploy` could ship a
//! profile carrying a literal `{{OKTA_DOMAIN}}`.

use assert_cmd::Command;

fn okta(dir: &std::path::Path, out: &str, extra: &[&str]) -> std::process::Output {
    Command::cargo_bin("contour")
        .unwrap()
        .current_dir(dir)
        .args([
            "profile", "generate", "--recipe", "okta", "--org", "com.acme", "-o", out,
        ])
        .args(extra)
        .output()
        .unwrap()
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn a_misspelled_set_key_is_an_error_that_names_the_real_ones() {
    let dir = tempfile::tempdir().unwrap();
    let o = okta(
        dir.path(),
        "typo",
        &["--set", "OKTA_DOMIAN=acme.okta.com", "--allow-placeholders"],
    );
    assert!(!o.status.success(), "a typo must not exit 0");
    let e = stderr(&o);
    assert!(
        e.contains("OKTA_DOMIAN") && e.contains("OKTA_DOMAIN"),
        "{e}"
    );
}

#[test]
fn unfilled_placeholders_fail_unless_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let o = okta(dir.path(), "none", &[]);
    assert!(!o.status.success(), "unfilled placeholders must not exit 0");
    assert!(stderr(&o).contains("OKTA_DOMAIN"));
    assert!(
        dir.path().join("none").read_dir().unwrap().next().is_some(),
        "files are still written"
    );

    let o = okta(dir.path(), "allowed", &["--allow-placeholders"]);
    assert!(o.status.success(), "{}", stderr(&o));
}

#[test]
fn every_placeholder_set_exits_zero_with_none_left() {
    let dir = tempfile::tempdir().unwrap();
    let o = okta(
        dir.path(),
        "full",
        &[
            "--set",
            "OKTA_DOMAIN=acme.okta.com",
            "--set",
            "REGISTRATION_TOKEN=t0k3n",
            "--set",
            "SCEP_CHALLENGE=ch4ll3nge",
        ],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    for f in dir.path().join("full").read_dir().unwrap() {
        let text = std::fs::read_to_string(f.unwrap().path()).unwrap();
        assert!(!text.contains("{{OKTA_DOMAIN}}"));
    }
}
