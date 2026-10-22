//! `ddm validate` must report every file it was given. A file that is not a
//! declaration is a failed result, and `--json` exits 1 like the human path.
//! Apple's asset credential examples are bare `Payload` fragments without
//! `Type`; dropping them printed `[]` with exit 0.

use assert_cmd::Command;
use serde_json::Value;

#[test]
fn a_file_that_is_not_a_declaration_is_a_failed_result_not_a_missing_one() {
    let dir = tempfile::tempdir().unwrap();
    let fragment = dir.path().join("scep.json");
    std::fs::write(&fragment, r#"{"URL":"https://example.com/scep","Keysize":2048}"#).unwrap();

    let out = Command::cargo_bin("profile")
        .unwrap()
        .args(["ddm", "validate", fragment.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).expect("validate JSON on stdout");
    let entries = v.as_array().expect("one entry per file");
    assert_eq!(entries.len(), 1, "{v}");
    assert_eq!(entries[0]["valid"], false);
    assert!(
        entries[0]["errors"][0]
            .as_str()
            .is_some_and(|e| e.starts_with("Not a DDM declaration")),
        "{v}"
    );
    assert!(!out.status.success(), "an invalid file must not exit 0");
}

#[test]
fn json_mode_exits_nonzero_on_an_invalid_declaration() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.json");
    // Missing both required keys. `ddm validate` does not type-check values,
    // so a wrong-typed key would not make the declaration invalid.
    std::fs::write(&bad, r#"{"Type":"com.apple.configuration.softwareupdate.enforcement.specific","Identifier":"com.acme.su","Payload":{}}"#).unwrap();
    let out = Command::cargo_bin("profile")
        .unwrap()
        .args(["ddm", "validate", bad.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).expect("validate JSON on stdout");
    assert_eq!(v[0]["valid"], false, "{v}");
    assert!(!out.status.success());
}
