//! Trap — `contour santa prep` and the santa recipe agree on Santa's posture.
//!
//! It renders the recipe with `profile generate --recipe santa` and the
//! prerequisites with `santa prep`, two crates' commands, so both halves run
//! through `contour`: Cargo names only a package's own binaries to its
//! integration tests, and `contour` carries both command trees.

use assert_cmd::Command;
use std::fs;

// ─────────────────────────────────────────────────────────────────────────────
// Trap 98: the two paths that produce Santa's prerequisite profiles must
// agree on posture. `contour profile generate --recipe santa` and
// `contour santa prep` emit the same artifact for the same purpose, and a
// user picking one over the other must not silently get a weaker fleet.
//
// They have already diverged twice: the recipe granted Full Disk Access to
// one of Santa's three signed components while prep granted all three, and
// prep used NonRemovableFromUISystemExtensions (System Settings and Finder
// only) where the recipe used NonRemovableSystemExtensions (SIP-backed, so
// `systemextensionsctl` cannot unload it either).
//
// Catches:
//   - one path adding a hardening key the other lacks
//   - AllowUserOverrides flipping to true, which lets users approve
//     extensions the profile never allowed
//   - the UI-only non-removable key coming back
//   - a signed component losing its Full Disk Access grant
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_98_santa_prep_and_recipe_agree_on_posture() {
    use std::collections::BTreeSet;

    /// Pull (AllowUserOverrides, non-removable keys) out of a sysext profile
    /// and the set of components granted Full Disk Access out of a TCC one.
    fn sysext_posture(path: &std::path::Path) -> (Option<bool>, BTreeSet<String>) {
        let raw = fs::read(path).expect("read sysext profile");
        let doc: plist::Value = plist::from_bytes(&raw).expect("parse sysext plist");
        let dict = doc.as_dictionary().expect("profile is a dict");
        let content = dict
            .get("PayloadContent")
            .and_then(|v| v.as_array())
            .expect("PayloadContent");
        let payload = content[0].as_dictionary().expect("payload dict");
        let overrides = payload
            .get("AllowUserOverrides")
            .and_then(|v| v.as_boolean());
        let keys: BTreeSet<String> = payload
            .keys()
            .filter(|k| k.contains("NonRemovable"))
            .cloned()
            .collect();
        (overrides, keys)
    }

    fn fda_components(path: &std::path::Path) -> BTreeSet<String> {
        let raw = fs::read(path).expect("read tcc profile");
        let doc: plist::Value = plist::from_bytes(&raw).expect("parse tcc plist");
        let dict = doc.as_dictionary().expect("profile is a dict");
        let content = dict
            .get("PayloadContent")
            .and_then(|v| v.as_array())
            .expect("PayloadContent");
        let mut out = BTreeSet::new();
        for payload in content {
            let Some(services) = payload
                .as_dictionary()
                .and_then(|d| d.get("Services"))
                .and_then(|v| v.as_dictionary())
            else {
                continue;
            };
            for (_service, entries) in services {
                for entry in entries.as_array().into_iter().flatten() {
                    let Some(entry) = entry.as_dictionary() else {
                        continue;
                    };
                    // Every entry must pick exactly one authorization key.
                    // Apple: "Every payload needs to include either
                    // Authorization or Allowed, but not both."
                    assert!(
                        !(entry.contains_key("Allowed") && entry.contains_key("Authorization")),
                        "a PPPC entry set both Allowed and Authorization, which Apple forbids"
                    );
                    if let Some(id) = entry.get("Identifier").and_then(|v| v.as_string()) {
                        out.insert(id.to_string());
                    }
                }
            }
        }
        out
    }

    let recipe_dir = tempfile::tempdir().unwrap();
    let prep_dir = tempfile::tempdir().unwrap();

    Command::cargo_bin("contour")
        .unwrap()
        .args([
            "profile",
            "generate",
            "--recipe",
            "santa",
            "--org",
            "com.acme",
            // The recipe's sync server and wiki URL are site-specific
            // placeholders; this trap compares posture, not those.
            "--allow-placeholders",
            "-o",
            recipe_dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("contour")
        .unwrap()
        .args([
            "santa",
            "prep",
            "--org",
            "com.acme",
            "-o",
            prep_dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let (recipe_overrides, recipe_nonremovable) =
        sysext_posture(&recipe_dir.path().join("santa-sysext.mobileconfig"));
    let (prep_overrides, prep_nonremovable) =
        sysext_posture(&prep_dir.path().join("santa-system-extension.mobileconfig"));

    assert_eq!(
        recipe_overrides, prep_overrides,
        "AllowUserOverrides differs between the recipe and prep"
    );
    assert_eq!(
        recipe_overrides,
        Some(false),
        "AllowUserOverrides must be false: true lets a user approve extensions \
         the profile never allowed"
    );

    assert_eq!(
        recipe_nonremovable, prep_nonremovable,
        "the non-removable key differs between the recipe and prep"
    );
    assert!(
        recipe_nonremovable.contains("NonRemovableSystemExtensions"),
        "expected the SIP-backed key; NonRemovableFromUISystemExtensions alone \
         leaves systemextensionsctl able to unload Santa. Got: {recipe_nonremovable:?}"
    );

    let recipe_fda = fda_components(&recipe_dir.path().join("santa-tcc.mobileconfig"));
    let prep_fda = fda_components(&prep_dir.path().join("santa-tcc.mobileconfig"));
    assert_eq!(
        recipe_fda, prep_fda,
        "the set of components granted Full Disk Access differs between the \
         recipe and prep"
    );
    for component in [
        "com.northpolesec.santa",
        "com.northpolesec.santa.daemon",
        "com.northpolesec.santa.bundleservice",
    ] {
        assert!(
            recipe_fda.contains(component),
            "{component} lost its Full Disk Access grant; PPPC is per signed \
             component and Santa ships several. Got: {recipe_fda:?}"
        );
    }

    // Both paths must emit the service-management profile: without it the
    // daemon's login item prompts the user on first start.
    assert!(
        recipe_dir
            .path()
            .join("santa-service-management.mobileconfig")
            .exists(),
        "the recipe stopped emitting the service-management profile"
    );
    assert!(
        prep_dir
            .path()
            .join("santa-service-management.mobileconfig")
            .exists(),
        "prep stopped emitting the service-management profile"
    );
}
