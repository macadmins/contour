//! The Windows SOP must describe the Windows CLI that exists.
//!
//! A SOP sentence such as "contour emits no SyncML" is true when typed and
//! stays in the text after the command ships, unless something re-reads it.
//!
//! That matters more here than for a prose doc. The CSP/ADMX surface is
//! meant to be reached by an agent, and these two files ARE that interface:
//! an agent told the feature does not exist does not go looking for it. The
//! routing entry is worse than the SOP itself, because it turns an agent
//! away before it reads anything else.
//!
//! So the claim is tied to the thing it describes. These tests ask the CLI
//! whether the command exists and ask the SOP what it says, and require the
//! two to agree. A SOP that goes stale now fails the build; a command that
//! is genuinely withdrawn makes them fail too, which is the prompt to say so
//! in the text rather than leave a promise behind.

use assert_cmd::Command;

fn sop(name: &str) -> String {
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args(["help-agents", "--sop", name])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "`help-agents --sop {name}` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// True when `contour profile windows generate` is a real subcommand.
fn windows_generate_exists() -> bool {
    Command::cargo_bin("contour")
        .unwrap()
        .args(["profile", "windows", "generate", "--help"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn the_windows_sop_matches_whether_generate_exists() {
    let text = sop("windows");
    if windows_generate_exists() {
        assert!(
            text.contains("profile windows generate"),
            "`profile windows generate` ships but the windows SOP never names it"
        );
        for stale in [
            "emits no SyncML",
            "does NOT do (yet)",
            "There is no\nSyncML/XML output path",
            "contour emits no SyncML",
        ] {
            assert!(
                !text.contains(stale),
                "the windows SOP still says {stale:?} — the command exists"
            );
        }
    } else {
        assert!(
            !text.contains("profile windows generate"),
            "the windows SOP documents a command that does not exist"
        );
    }
}

/// The dispatcher decides whether an agent ever reaches the SOP above.
///
/// Routing is not served by `--sop` — it is written into
/// `.claude/skills/contour/references/` by `setup-agent`, so the test reads
/// the artifact an agent is actually given.
#[test]
fn the_routing_sop_does_not_turn_agents_away_from_windows_generate() {
    if !windows_generate_exists() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("contour")
        .unwrap()
        .arg("setup-agent")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "setup-agent failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(
        dir.path()
            .join(".claude/skills/contour/references/sop-routing.md"),
    )
    .expect("setup-agent installs sop-routing.md");
    assert!(
        text.contains("profile windows generate"),
        "routing never mentions `profile windows generate`, so an agent asking \
         about Windows authoring is sent to exploration only"
    );
    assert!(
        !text.contains("emits no SyncML"),
        "routing still claims contour emits no SyncML"
    );
}

/// True when `contour profile windows stig` is a real subcommand.
fn windows_stig_exists() -> bool {
    Command::cargo_bin("contour")
        .unwrap()
        .args(["profile", "windows", "stig", "--help"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The same trap, one surface later: the STIG corpus.
///
/// A SOP line such as "data embedded, no CLI yet" must not outlive the
/// command it anticipates, or it turns agents away from it.
///
/// A promise about the future is the most perishable thing a SOP can hold,
/// so it is the thing most worth tying down.
#[test]
fn the_windows_sop_matches_whether_stig_exists() {
    let text = sop("windows");
    if windows_stig_exists() {
        assert!(
            text.contains("profile windows stig"),
            "`profile windows stig` ships but the windows SOP never names it"
        );
        for stale in [
            "no CLI yet",
            "No CLI surface reads these yet",
            "the documented roadmap",
        ] {
            assert!(
                !text.contains(stale),
                "the windows SOP still says {stale:?} — the command exists"
            );
        }
    } else {
        assert!(
            !text.contains("profile windows stig"),
            "the windows SOP documents a command that does not exist"
        );
    }
}

/// Routing has to reach it too, for the reason given above the generate test.
#[test]
fn the_routing_sop_reaches_the_stig_surface() {
    if !windows_stig_exists() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("contour")
        .unwrap()
        .arg("setup-agent")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "setup-agent failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(
        dir.path()
            .join(".claude/skills/contour/references/sop-routing.md"),
    )
    .expect("setup-agent installs sop-routing.md");
    assert!(
        text.contains("profile windows stig"),
        "routing never mentions `profile windows stig`, so an agent asking about \
         Windows STIG compliance is never sent to it"
    );
}

/// An export is a subset, and the SOP has to say so before an agent ships it.
///
/// This is the one claim about the corpus that an operator cannot recover
/// from the output alone if they never read the header: a file of Fleet
/// policies named after a STIG profile looks like that STIG profile.
#[test]
fn the_windows_sop_says_an_export_is_not_the_whole_stig() {
    if !windows_stig_exists() {
        return;
    }
    // Whitespace-normalised, because the claim is a sentence in wrapped
    // prose: it sits inside a bullet, so it carries a newline and the list
    // indent, and neither is part of what the SOP promises. Matching the raw
    // text would tie the test to the wrap column and fail on a reflow that
    // changed nothing.
    let text = sop("windows");
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("Deploying the file is not deploying the STIG."),
        "the windows SOP documents `stig export` without saying the export is a \
         subset of the STIG"
    );
}

/// Third-party app policies are useless without their template, and the flag
/// that supplies it is the one thing an agent cannot guess.
#[test]
fn the_windows_sop_names_the_admx_dir_contract() {
    if !windows_generate_exists() {
        return;
    }
    let text = sop("windows");
    assert!(
        text.contains("--admx-dir"),
        "the SOP describes app policies without naming --admx-dir"
    );
    assert!(
        text.contains("ADMXInstall"),
        "the SOP never explains that app policies need the template ingested first"
    );
}
