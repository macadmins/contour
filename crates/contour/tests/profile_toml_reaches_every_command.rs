//! A profile.toml is enough: commands chained after `profile generate` read
//! its org and `[uuid]` settings, so no step needs `--org` or `-p` again.

use std::path::Path;

use assert_cmd::Command;

fn contour(dir: &Path, args: &[&str]) {
    let out = Command::cargo_bin("contour")
        .unwrap()
        .current_dir(dir)
        .env_remove("CONTOUR_ORG")
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

fn plist(path: &Path) -> plist::Dictionary {
    plist::Value::from_file(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .into_dictionary()
        .unwrap()
}

fn identifier_and_uuid(path: &Path) -> (String, String) {
    let d = plist(path);
    let s = |k: &str| d[k].as_string().unwrap().to_string();
    (s("PayloadIdentifier"), s("PayloadUUID"))
}

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("profile.toml"),
        "[organization]\ndomain = \"com.acme\"\n\n[uuid]\npredictable = true\nuppercase = false\n",
    )
    .unwrap();
    contour(dir.path(), &["profile", "generate", "com.apple.appstore", "--output", "a.mobileconfig"]);
    dir
}

#[test]
fn duplicate_follows_uuid_settings() {
    let dir = project();
    let root = dir.path();
    contour(root, &["profile", "duplicate", "a.mobileconfig", "--name", "Copy", "-o", "d1.mobileconfig"]);
    contour(root, &["profile", "duplicate", "a.mobileconfig", "--name", "Copy", "-o", "d2.mobileconfig"]);
    let (_, d1) = identifier_and_uuid(&root.join("d1.mobileconfig"));
    let (_, d2) = identifier_and_uuid(&root.join("d2.mobileconfig"));
    assert_eq!(d1, d2, "predictable = true: the same copy gets the same UUID");
    assert_eq!(d1, d1.to_lowercase(), "uppercase = false");
}

#[test]
fn org_commands_read_profile_toml() {
    let dir = project();
    let root = dir.path();

    contour(root, &["profile", "reidentify", "--write", "a.mobileconfig"]);
    assert!(identifier_and_uuid(&root.join("a.mobileconfig")).0.starts_with("com.acme."));

    contour(root, &["profile", "classify", "--write", "--sync-identity", "a.mobileconfig"]);
    assert!(identifier_and_uuid(&root.join("a.mobileconfig")).0.starts_with("com.acme."));

    let mut prefs = plist::Dictionary::new();
    prefs.insert("ShowWelcome".into(), false.into());
    plist::Value::Dictionary(prefs).to_file_xml(root.join("com.example.app.plist")).unwrap();
    contour(root, &["profile", "synthesize", "com.example.app.plist", "-o", "synth"]);
    let made = std::fs::read_dir(root.join("synth")).unwrap().next().unwrap().unwrap().path();
    assert!(identifier_and_uuid(&made).0.starts_with("com.acme."));
}
