//! `ddm validate --strict` fails a declaration with keys the schema does not
//! define. The device ignores such keys, so without `--strict` the file
//! passes with a warning and does nothing.

use assert_cmd::Command;
use serde_json::Value;

fn validate(file: &std::path::Path, strict: bool) -> (Value, bool) {
    let mut args = vec!["ddm", "validate", file.to_str().unwrap(), "--json"];
    if strict {
        args.push("--strict");
    }
    let out = Command::cargo_bin("profile")
        .unwrap()
        .args(&args)
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).expect("validate JSON on stdout");
    (v, out.status.success())
}

#[test]
fn an_unknown_top_level_key_fails_only_with_strict() {
    let dir = tempfile::tempdir().unwrap();
    let decl = dir.path().join("updates.json");
    std::fs::write(
        &decl,
        r#"{"Type":"com.apple.configuration.softwareupdate.settings","Identifier":"com.example.updates","Payload":{"made-up-key":true}}"#,
    )
    .unwrap();

    let (v, ok) = validate(&decl, false);
    assert!(ok, "{v}");
    assert_eq!(v[0]["valid"], true, "{v}");
    assert_eq!(v[0]["warnings"][0], "Unknown field: made-up-key", "{v}");

    let (v, ok) = validate(&decl, true);
    assert!(!ok, "--strict must exit non-zero: {v}");
    assert_eq!(v[0]["valid"], false, "{v}");
    assert_eq!(v[0]["errors"][0], "Unknown field: made-up-key", "{v}");
}
