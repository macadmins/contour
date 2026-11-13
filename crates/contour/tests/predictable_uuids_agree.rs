//! Predictable UUIDs are one scheme: a profile written by `profile generate`
//! keeps its UUIDs when `normalize`, `uuid -p` or `import` rewrites it, so an
//! MDM does not see a change that is not there.

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

/// Outer and inner PayloadUUID of a profile.
fn uuids(path: &Path) -> [String; 2] {
    let v = plist::Value::from_file(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let d = v.as_dictionary().unwrap();
    let inner = d["PayloadContent"].as_array().unwrap()[0].as_dictionary().unwrap();
    [d, inner].map(|d| d["PayloadUUID"].as_string().unwrap().to_string())
}

#[test]
fn generate_then_rewrite_keeps_uuids() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("profile.toml"),
        "[organization]\ndomain = \"com.acme\"\nname = \"Acme\"\n\n[uuid]\npredictable = true\n",
    )
    .unwrap();
    std::fs::write(
        root.join("acme.toml"),
        "[recipe]\nname = \"acme\"\ndescription = \"Acme\"\n\n[[profile]]\n\
         filename = \"acme.mobileconfig\"\npayload_type = \"com.apple.appstore\"\n\
         display_name = \"Acme Settings\"\ndescription = \"\"\n\n\
         [profile.fields]\nrestrict-store-softwareupdate-only = true\n",
    )
    .unwrap();

    contour(root, &["profile", "generate", "--recipe", "acme.toml", "--output", "generated"]);
    let generated = uuids(&root.join("generated/acme.mobileconfig"));

    contour(root, &["profile", "normalize", "--output", "normalized.mobileconfig", "generated/acme.mobileconfig"]);
    assert_eq!(uuids(&root.join("normalized.mobileconfig")), generated, "normalize");

    contour(root, &["profile", "uuid", "-p", "--output", "uuid.mobileconfig", "generated/acme.mobileconfig"]);
    assert_eq!(uuids(&root.join("uuid.mobileconfig")), generated, "uuid -p");

    contour(root, &["profile", "import", "generated", "--all", "--output", "imported"]);
    let imported = std::fs::read_dir(root.join("imported")).unwrap().next().unwrap().unwrap().path();
    assert_eq!(uuids(&imported), generated, "import");

    // `-p` asks for predictable UUIDs even when profile.toml does not.
    std::fs::write(root.join("profile.toml"), "[organization]\ndomain = \"com.acme\"\n").unwrap();
    contour(root, &["profile", "uuid", "-p", "--output", "flag.mobileconfig", "generated/acme.mobileconfig"]);
    assert_eq!(uuids(&root.join("flag.mobileconfig")), generated, "uuid -p without [uuid] predictable");
}
