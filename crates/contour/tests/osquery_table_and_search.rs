//! `contour osquery table` / `search` tell an author what `validate` checks:
//! the WHERE rule for a table, the table named by the query first, and a
//! platform name osquery does not use as an error that names the right one.

use assert_cmd::Command;

fn contour(args: &[&str]) -> std::process::Output {
    Command::cargo_bin("contour").unwrap().args(args).output().unwrap()
}

fn stdout(args: &[&str]) -> String {
    let out = contour(args);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn table_states_the_where_rule() {
    let text = stdout(&["osquery", "table", "file"]);
    assert!(text.contains("Where:") && text.contains("one of directory, path"), "{text}");

    let json: serde_json::Value = serde_json::from_str(&stdout(&["osquery", "table", "yara_file", "--json"])).unwrap();
    assert!(json["where"].as_str().is_some_and(|w| w.contains("sigrule")), "{json}");

    // Fleet-only tables carry their required columns too.
    let text = stdout(&["osquery", "table", "dscl"]);
    assert!(text.contains("Where:") && text.contains("each of command, key, path"), "{text}");

    let text = stdout(&["osquery", "table", "processes"]);
    assert!(!text.contains("Where:"), "{text}");
}

#[test]
fn search_lists_the_named_table_first() {
    for q in ["file", "users", "hash"] {
        let text = stdout(&["osquery", "search", q]);
        let first = text.lines().next().unwrap_or_default();
        assert!(first.starts_with(&format!("{q} (")), "{q}: first line {first:?}");
    }
}

#[test]
fn search_platform_names_the_osquery_spelling() {
    assert!(!stdout(&["osquery", "search", "file", "--platform", "Darwin"]).contains("No matches"));
    let out = contour(&["osquery", "search", "file", "--platform", "macos"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("darwin"));
}
