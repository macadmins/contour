//! Sequence test across every generator: with one profile.toml, each writes
//! a profile that `normalize` leaves byte-identical, whose UUIDs are v5 of
//! its identifiers, and that `scan --simulate` predicts unchanged.

use std::path::Path;

use assert_cmd::Command;

fn contour(dir: &Path, args: &[&str]) -> String {
    let out = Command::cargo_bin("contour")
        .unwrap()
        .current_dir(dir)
        .env_remove("CONTOUR_ORG")
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

fn write(root: &Path, name: &str, text: &str) {
    std::fs::write(root.join(name), text).unwrap();
}

fn v5(identifier: &str, uppercase: bool) -> String {
    let uuid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, identifier.as_bytes()).to_string();
    if uppercase { uuid.to_uppercase() } else { uuid }
}

#[test]
fn every_generator_writes_what_normalize_writes() {
    every_generator_agrees(true);
}

/// `[uuid] uppercase = false` reaches every generator, not only `profile`.
#[test]
fn every_generator_follows_uuid_case() {
    every_generator_agrees(false);
}

fn every_generator_agrees(uppercase: bool) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "profile.toml",
        &format!(
            "[organization]\ndomain = \"com.acme\"\nname = \"Acmé Örg AB\"\n\n[uuid]\npredictable = true\nuppercase = {uppercase}\n"
        ),
    );
    write(root, "rules.yaml", "- identifier: EQHXZ8M8AV\n  rule_type: TEAMID\n  policy: ALLOWLIST\n");
    write(root, "pppc.toml", "[config]\norg = \"com.acme\"\n\n[[apps]]\nname = \"Slack\"\nbundle_id = \"com.tinyspeck.slackmacgap\"\ncode_requirement = \"anchor apple generic\"\nservices = [\"screen-capture\"]\n");
    write(root, "btm.toml", "[settings]\norg = \"com.acme\"\n\n[[apps]]\nname = \"Slack\"\nbundle_id = \"com.tinyspeck.slackmacgap\"\nteam_id = \"BQR82RBBHL\"\n\n[[apps.rules]]\nrule_type = \"TeamIdentifier\"\nrule_value = \"BQR82RBBHL\"\n");
    write(root, "notifications.toml", "[settings]\norg = \"com.acme\"\n\n[[apps]]\nname = \"Slack\"\nbundle_id = \"com.tinyspeck.slackmacgap\"\nalerts_enabled = true\nalert_type = 1\nbadges_enabled = true\ncritical_alerts = false\nlock_screen = true\nnotification_center = true\nsounds_enabled = true\n");
    let mut prefs = plist::Dictionary::new();
    prefs.insert("ShowWelcome".into(), false.into());
    plist::Value::Dictionary(prefs).to_file_xml(root.join("com.acme.thing.plist")).unwrap();

    // No --org anywhere: profile.toml is the one source.
    for args in [
        &["profile", "generate", "com.apple.appstore", "--output", "out/generate.mobileconfig"][..],
        &["profile", "synthesize", "com.acme.thing.plist", "-o", "out/synthesize"],
        &["santa", "prep", "-o", "out/santa-prep"],
        &["santa", "config", "-o", "out/santa-config.mobileconfig"],
        &["santa", "generate", "rules.yaml", "-o", "out/santa-rules.mobileconfig"],
        &["pppc", "generate", "pppc.toml", "-o", "out/pppc"],
        &["btm", "generate", "btm.toml", "-o", "out/btm"],
        &["notifications", "generate", "notifications.toml", "-o", "out/notifications"],
    ] {
        contour(root, args);
    }

    let mut checked = 0;
    let mut stack = vec![root.join("out")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path.strip_prefix(root).unwrap().to_str().unwrap().to_string();
            let generated = std::fs::read_to_string(&path).unwrap();
            let profile = plist::Value::from_file(&path).unwrap().into_dictionary().unwrap();
            let s = |d: &plist::Dictionary, k: &str| d[k].as_string().unwrap().to_string();
            let id = s(&profile, "PayloadIdentifier");
            assert!(id.starts_with("com.acme.") && !id.starts_with("com.acme.com.acme."), "{rel}: {id}");
            assert_eq!(s(&profile, "PayloadUUID"), v5(&id, uppercase), "{rel}: outer UUID");
            assert_eq!(s(&profile, "PayloadOrganization"), "Acmé Örg AB", "{rel}");
            for payload in profile["PayloadContent"].as_array().unwrap() {
                let p = payload.as_dictionary().unwrap();
                assert_eq!(s(p, "PayloadUUID"), v5(&s(p, "PayloadIdentifier"), uppercase), "{rel}: inner UUID");
                assert_eq!(s(p, "PayloadOrganization"), "Acmé Örg AB", "{rel}: inner");
            }

            contour(root, &["profile", "normalize", "--output", "normalized.mobileconfig", &rel]);
            let normalized = std::fs::read_to_string(root.join("normalized.mobileconfig")).unwrap();
            assert_eq!(normalized, generated, "{rel}: normalize rewrote a generated profile");

            let scan: serde_json::Value =
                serde_json::from_str(&contour(root, &["profile", "scan", "--simulate", "--json", &rel])).unwrap();
            let sim = &scan["simulation"];
            assert_eq!(sim["envelope_identifier"]["normalized"], id.as_str(), "{rel}: scan --simulate");
            for change in sim["payloads"].as_array().unwrap() {
                assert_eq!(change["normalized"], change["original"], "{rel}: scan --simulate payload");
            }
            checked += 1;
        }
    }
    assert!(checked >= 11, "only {checked} profiles generated");
}
