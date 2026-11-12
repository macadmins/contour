//! `[output] directory` in profile.toml is where every profile command writes
//! when `-o` is not given — resolved against profile.toml's folder, so a
//! command run from a subfolder writes to the same place.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn contour(dir: &Path) -> Command {
    let mut c = Command::cargo_bin("contour").unwrap();
    c.current_dir(dir).env_remove("CONTOUR_ORG");
    c
}

/// A project with profile.toml at its root, a `work/` subfolder to run from,
/// and `work/in.mobileconfig` — a profile from another org.
fn project() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("profile.toml"),
        "[organization]\ndomain = \"com.acme\"\nname = \"Acme\"\n\n[output]\ndirectory = \"./generated\"\n",
    )
    .unwrap();
    let work = root.path().join("work");
    std::fs::create_dir(&work).unwrap();
    // Built outside the project so its profile.toml does not apply.
    let elsewhere = tempfile::tempdir().unwrap();
    let input = work.join("in.mobileconfig");
    run(contour(elsewhere.path()).args(["profile", "generate", "com.apple.appstore", "--org", "com.other", "-o"]).arg(&input));
    (root, work)
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Files under `<root>/generated`, relative names, sorted.
fn generated(root: &Path) -> Vec<String> {
    let dir = root.join("generated");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("nothing in {}: {e}", dir.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn every_profile_command_writes_to_the_configured_directory() {
    for args in [
        &["profile", "generate", "com.apple.appstore"][..],
        &["profile", "normalize", "in.mobileconfig"],
        &["profile", "uuid", "in.mobileconfig"],
        &["profile", "link", "in.mobileconfig"],
        &["profile", "ddm", "generate", "passcode.settings"],
    ] {
        let (root, work) = project();
        run(contour(&work).args(args));
        assert_eq!(generated(root.path()).len(), 1, "{args:?}: {:?}", generated(root.path()));
        assert!(!work.join("generated").exists(), "{args:?} resolved against the CWD");
    }
}

#[test]
fn import_writes_to_the_configured_directory() {
    let (root, work) = project();
    std::fs::create_dir(work.join("src")).unwrap();
    std::fs::rename(work.join("in.mobileconfig"), work.join("src/in.mobileconfig")).unwrap();
    run(contour(&work).args(["profile", "import", "src", "--all"]));
    assert_eq!(generated(root.path()).len(), 1);
    assert!(!work.join("imported").exists());
}

#[test]
fn cli_output_still_wins() {
    let (root, work) = project();
    run(contour(&work).args(["profile", "link", "in.mobileconfig", "-o", "mine"]));
    assert!(work.join("mine").is_dir());
    assert!(!root.path().join("generated").exists());
}

#[test]
fn unknown_profile_toml_keys_are_reported() {
    let (root, work) = project();
    let path = root.path().join("profile.toml");
    let toml = std::fs::read_to_string(&path).unwrap().replace("[output]", "[ouput]");
    std::fs::write(&path, toml).unwrap();
    let stderr = run(contour(&work).args(["profile", "generate", "com.apple.appstore"]));
    assert!(stderr.contains("unknown key 'ouput'"), "{stderr}");
}
