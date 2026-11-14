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

    let mut checked = 0;
    for dir in ["out", "out/recipe", "out/santa"] {
        for entry in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "mobileconfig") {
                continue;
            }
            let generated = std::fs::read_to_string(&path).unwrap();
            let rel = path.strip_prefix(root).unwrap().to_str().unwrap().to_string();
            assert!(generated.contains("<string>Acmé Örg AB</string>"), "{rel}: PayloadOrganization");
            contour(root, &["profile", "normalize", "--output", "normalized.mobileconfig", &rel]);
            let normalized = std::fs::read_to_string(root.join("normalized.mobileconfig")).unwrap();
            assert_eq!(normalized, generated, "{rel}: normalize rewrote a generated profile");
            checked += 1;
        }
    }
    assert!(checked >= 8, "only {checked} profiles generated");
}

/// Without a name anywhere, every command writes the domain.
#[test]
fn without_a_name_generators_and_normalize_write_the_domain() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("profile.toml"),
        "[organization]\ndomain = \"com.acme\"\n\n[uuid]\npredictable = true\n",
    )
    .unwrap();
    contour(root, &["profile", "generate", "com.apple.appstore", "--output", "a.mobileconfig"]);
    contour(root, &["santa", "prep", "--org", "com.acme", "-o", "santa"]);
    contour(root, &["profile", "normalize", "--output", "n.mobileconfig", "a.mobileconfig"]);
    for path in ["a.mobileconfig", "n.mobileconfig", "santa/santa-tcc.mobileconfig"] {
        let text = std::fs::read_to_string(root.join(path)).unwrap();
        assert!(text.contains("<key>PayloadOrganization</key>\n\t<string>com.acme</string>"), "{path}");
    }
}

/// `.contour/config.toml` alone (from `contour init`) names the org too.
#[test]
fn contour_config_names_the_org() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir(root.join(".contour")).unwrap();
    std::fs::write(
        root.join(".contour/config.toml"),
        "[organization]\nname = \"Acmé Örg AB\"\ndomain = \"com.acme\"\n",
    )
    .unwrap();
    contour(root, &["santa", "prep", "--org", "com.acme", "-o", "santa"]);
    contour(root, &["profile", "generate", "com.apple.appstore", "--output", "a.mobileconfig"]);
    contour(root, &["profile", "normalize", "--output", "n.mobileconfig", "santa/santa-tcc.mobileconfig"]);
    for path in ["santa/santa-tcc.mobileconfig", "a.mobileconfig", "n.mobileconfig"] {
        let text = std::fs::read_to_string(root.join(path)).unwrap();
        assert!(text.contains("<string>Acmé Örg AB</string>"), "{path}");
        assert!(!text.contains("<string>com.acme</string>"), "{path}: domain as PayloadOrganization");
    }
}
