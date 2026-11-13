//! A generated profile is already normalized: `normalize` leaves its bytes
//! alone, so diffing the two shows nothing, not a reshuffle of every key.

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

#[test]
fn normalize_leaves_generated_profiles_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("profile.toml"),
        "[organization]\ndomain = \"com.acme\"\nname = \"Acmé Örg AB\"\n\n[uuid]\npredictable = true\n",
    )
    .unwrap();
    std::fs::write(
        root.join("acme.toml"),
        "[recipe]\nname = \"acme\"\ndescription = \"Acme\"\n\n\
         [[profile]]\nfilename = \"custom.mobileconfig\"\npayload_type = \"com.acme.app\"\n\
         display_name = \"Acme App\"\ndescription = \"\"\n\n\
         [profile.fields]\nMDM = \"Fleet\"\nAssetTag = \"$FLEET_HOST_VITAL_1\"\n\n\
         [[profile]]\nfilename = \"store.mobileconfig\"\npayload_type = \"com.apple.appstore\"\n\
         display_name = \"Acme Store\"\ndescription = \"\"\n\n\
         [profile.fields]\nrestrict-store-softwareupdate-only = true\n",
    )
    .unwrap();

    contour(root, &["profile", "generate", "--recipe", "acme.toml", "--output", "out/recipe"]);
    contour(root, &["profile", "generate", "com.apple.appstore", "--output", "out/single.mobileconfig"]);
    contour(root, &["santa", "prep", "--org", "com.acme", "-o", "out/santa"]);

    // santa prep (like btm, pppc, notifications, support) still writes the
    // domain as PayloadOrganization; pin the name so only order and UUIDs count.
    let mut checked = 0;
    for (dir, name) in [("out", None), ("out/recipe", None), ("out/santa", Some("com.acme"))] {
        for entry in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "mobileconfig") {
                continue;
            }
            let generated = std::fs::read_to_string(&path).unwrap();
            let rel = path.strip_prefix(root).unwrap().to_str().unwrap().to_string();
            let mut args = vec!["profile", "normalize", "--output", "normalized.mobileconfig", &rel];
            if let Some(name) = name {
                args.extend(["--name", name]);
            }
            contour(root, &args);
            let normalized = std::fs::read_to_string(root.join("normalized.mobileconfig")).unwrap();
            assert_eq!(normalized, generated, "{rel}: normalize rewrote a generated profile");
            checked += 1;
        }
    }
    assert!(checked >= 8, "only {checked} profiles generated");
}
