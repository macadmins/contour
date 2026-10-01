//! `profile enrollment generate --skip-all` on every platform.
//!
//! It took every pane listed, FileVault and SoftwareUpdate included, and the
//! NEVER_SKIP guardrail then refused them — so on macOS and iOS the flag could
//! never succeed. iPadOS failed earlier still: Apple lists iPad panes under
//! iOS, and asking for iPadOS found no keys at all.

use assert_cmd::Command;

fn contour() -> Command {
    Command::cargo_bin("contour").unwrap()
}

#[test]
fn skip_all_succeeds_everywhere_and_skips_nothing_the_guardrail_keeps() {
    let dir = tempfile::tempdir().unwrap();
    for platform in ["macOS", "iOS", "iPadOS", "tvOS", "visionOS"] {
        let out_path = dir.path().join(format!("{platform}.json"));
        let out = contour()
            .args([
                "profile",
                "enrollment",
                "generate",
                "--platform",
                platform,
                "--skip-all",
                "-o",
            ])
            .arg(&out_path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{platform}: --skip-all failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out_path).unwrap()).unwrap();
        let items: Vec<&str> = json["skip_setup_items"]
            .as_array()
            .expect("skip_setup_items")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(!items.is_empty(), "{platform}: skipped nothing");
        for kept in ["FileVault", "SoftwareUpdate"] {
            assert!(
                !items.contains(&kept),
                "{platform}: {kept} must never be skipped"
            );
        }
    }
}

/// The guardrail still refuses a pane named explicitly.
#[test]
fn naming_a_guarded_pane_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = contour()
        .args([
            "profile",
            "enrollment",
            "generate",
            "--platform",
            "macOS",
            "--skip",
            "FileVault",
            "-o",
        ])
        .arg(dir.path().join("x.json"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("NEVER_SKIP"));
}

/// iPadOS reads the iOS keys, so it offers the same panes.
#[test]
fn ipados_lists_the_ios_panes() {
    let list = |p: &str| {
        let out = contour()
            .args(["--json", "profile", "enrollment", "list", "--platform", p])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{p}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .matches("\"key\"")
            .count()
    };
    let ipad = list("iPadOS");
    assert!(ipad > 0, "iPadOS has no skip keys");
    assert_eq!(ipad, list("iOS"));
}
