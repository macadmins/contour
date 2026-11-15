//! `form emit` writes documents in the format `normalize` writes, so the
//! wasm module and the MCP tool, which share the emitter, hand back files
//! that a later `normalize` does not reshuffle.
//!
//! `--no-uuid`: emit derives its UUIDs differently from normalize's
//! predictable mode, so the UUIDs are the one thing left out of the claim.

use assert_cmd::Command;

fn profile(dir: &std::path::Path, args: &[&str]) {
    let out = Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir)
        .env_remove("CONTOUR_ORG")
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn normalize_leaves_emitted_documents_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for (type_id, values, intent, file) in [
        (
            "com.apple.applicationaccess",
            r#"{"allowAirDrop":false,"allowCamera":false}"#,
            "restrictions",
            "com.acme.restrictions.mobileconfig",
        ),
        (
            "com.apple.configuration.passcode.settings",
            r#"{"MinimumLength":12,"RequirePasscode":true}"#,
            "passcode",
            "com.acme.config.passcode.json",
        ),
    ] {
        std::fs::write(root.join("values.json"), values).unwrap();
        profile(
            root,
            &[
                "form", "emit", type_id, "--values", "values.json", "--org", "com.acme",
                "--intent", intent, "--os", "macOS", "-o", ".", "--write",
            ],
        );
        let emitted = std::fs::read(root.join(file)).unwrap();
        profile(
            root,
            &["normalize", file, "--org", "com.acme", "--no-uuid", "--in-place"],
        );
        let normalized = std::fs::read(root.join(file)).unwrap();
        assert!(
            emitted == normalized,
            "normalize changed {file}:\n--- emitted\n{}\n--- normalized\n{}",
            String::from_utf8_lossy(&emitted),
            String::from_utf8_lossy(&normalized)
        );
    }
}
