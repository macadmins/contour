//! Trap suite — santa commands.
//!
//! Covers behaviors that procedural SOPs would rely on. Each test
//! drives the `santa` binary against a temp fixture and asserts the
//! observable contract.

use assert_cmd::Command;
use std::fs;

const RULES_YAML: &str = r"- identifier: EQHXZ8M8AV
  rule_type: TEAMID
  policy: ALLOWLIST
  description: Google
- identifier: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
  rule_type: BINARY
  policy: BLOCKLIST
  description: Bad binary
";

// ─────────────────────────────────────────────────────────────────────────────
// Trap 86: `santa generate --format recipe` produces a contour-shaped
// recipe TOML. The narrow shape (default) emits exactly one
// `[[profile]]` block carrying the `com.northpolesec.santa` payload;
// `--full-bundle` emits four (sysext, TCC, notifications, Santa rules).
// Catches:
//   - Recipe variant accidentally falling through to mobileconfig path
//   - Profile count drift (sysext/TCC/notifications dropped)
//   - Payload type renamed in extracted helper
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn trap_86_santa_recipe_narrow_and_full_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules.yaml");
    fs::write(&rules, RULES_YAML).unwrap();

    // Narrow: single com.northpolesec.santa profile.
    let narrow_out = tmp.path().join("santa.toml");
    let r = Command::cargo_bin("santa")
        .unwrap()
        .args([
            "generate",
            rules.to_str().unwrap(),
            "--org",
            "com.acme",
            "--format",
            "recipe",
            "-o",
            narrow_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "narrow recipe must succeed; stderr: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let narrow = fs::read_to_string(&narrow_out).unwrap();
    assert_eq!(
        narrow.matches("[[profile]]").count(),
        1,
        "narrow shape must emit exactly one profile block"
    );
    assert!(
        narrow.contains(r#"payload_type = "com.northpolesec.santa""#),
        "narrow recipe must declare the Santa payload type"
    );
    // The Rules array round-trips into [[profile.fields.Rules]]
    // sub-tables, so identifiers should appear unchanged.
    assert!(narrow.contains("EQHXZ8M8AV"));

    // Full bundle: sysext + TCC + notifications + santa rules.
    let full_out = tmp.path().join("santa-full.toml");
    let r = Command::cargo_bin("santa")
        .unwrap()
        .args([
            "generate",
            rules.to_str().unwrap(),
            "--org",
            "com.acme",
            "--format",
            "recipe",
            "--full-bundle",
            "-o",
            full_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "full-bundle recipe must succeed; stderr: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let full = fs::read_to_string(&full_out).unwrap();
    assert_eq!(
        full.matches("[[profile]]").count(),
        4,
        "full bundle must emit four profile blocks"
    );
    for expected in [
        "com.apple.system-extension-policy",
        "com.apple.TCC.configuration-profile-policy",
        "com.apple.notificationsettings",
        "com.northpolesec.santa",
    ] {
        assert!(
            full.contains(&format!(r#"payload_type = "{expected}""#)),
            "full bundle must include payload_type {expected}"
        );
    }
    // Northpole identities must reach the rendered TOML — these are
    // the identifiers an operator would override for a vendor fork.
    //
    // Pinned to the crate constant rather than a literal, and pointedly
    // not EQHXZ8M8AV: that is Google's Team ID, and RULES_YAML above
    // already carries it as the Chrome allowlist rule. Asserting on it
    // here passed whether or not a single Northpole identity was
    // emitted — the Chrome rule alone satisfied it.
    assert!(
        full.contains(santa::NORTHPOLE_TEAM_ID),
        "Northpole Team ID {} must be present in the full bundle",
        santa::NORTHPOLE_TEAM_ID
    );
    assert!(
        full.contains("com.northpolesec.santa.daemon"),
        "Santa daemon bundle must be present in TCC entry"
    );
}
