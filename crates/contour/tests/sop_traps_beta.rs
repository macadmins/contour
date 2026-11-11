//! The beta SOP must describe the beta channel that exists.
//!
//! With no seed dataset carried, every `*_beta` accessor returns the release's
//! bytes, and `--beta` answers exactly as stable does: scripts that pass the
//! flag keep running between seeds. A SOP or help text still promising
//! "seed-only declarations and keys" would have an agent tell someone to pass
//! `--beta` to find a type that is not there.
//!
//! This is `sop_traps_windows.rs` in mirror image: there a SOP must not deny
//! a command that exists; here it must not promise a dataset that is absent.
//! Same failure, opposite sign: prose and binary drifting apart with nothing
//! holding them together.
//!
//! So the SOP's claim is tied to the bytes, and these tests follow the data
//! in both directions rather than hardcoding today's answer.

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

/// Does this binary carry a distinct seed dataset?
fn beta_is_carried() -> bool {
    contour_form::SchemaRegistry::beta_dataset_is_carried()
}

fn run(args: &[&str]) -> std::process::Output {
    Command::cargo_bin("contour")
        .unwrap()
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn the_beta_sop_says_whether_beta_works() {
    let text = sop("beta");
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if beta_is_carried() {
        assert!(
            !flat.contains("No OS seed is open right now"),
            "a seed dataset is carried again, but the beta SOP still opens by saying \
             the channel serves the release"
        );
    } else {
        assert!(
            flat.contains("No OS seed is open right now"),
            "no seed dataset is carried, so `--beta` serves the release, but the beta \
             SOP does not say so"
        );
        assert!(
            flat.contains("Passing `--beta` today gains nothing"),
            "the SOP is read by agents that act on it; the banner has to say the flag \
             adds nothing today, not only what is true"
        );
    }
}

/// The help text agrees with the flag.
///
/// The SOP is one surface; `--help` is the one most people actually read, and
/// it advertised "includes seed-only declarations and keys" for months after
/// there were none.
#[test]
fn the_help_text_says_beta_is_the_release_between_seeds() {
    if beta_is_carried() {
        return;
    }
    let out = run(&["profile", "--help"]);
    let help = String::from_utf8_lossy(&out.stdout).to_string();
    let flat = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("the release until the next seed") || flat.contains("same as stable"),
        "`contour profile --help` describes the beta channel without saying it serves \
         the release today:\n{help}"
    );
}

/// `SKILL.md` is the first thing an agent reads, so it is checked rather than
/// remembered. It is installed by `setup-agent`, so the test reads what an
/// agent is actually handed.
#[test]
fn the_skill_file_states_the_beta_channel_correctly() {
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
    let text = std::fs::read_to_string(dir.path().join(".claude/skills/contour/SKILL.md"))
        .expect("setup-agent installs SKILL.md");
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");

    // SKILL.md is installed as static text, while whether a seed is carried
    // depends on the build. So it must state the rule, not today's answer.
    assert!(
        flat.contains("and the release otherwise"),
        "SKILL.md must say the beta flags serve the release when no seed is carried:\n{text}"
    );
    assert!(
        flat.contains("`contour census` reports it"),
        "SKILL.md must send agents to `contour census` before suggesting --beta"
    );
    assert!(
        !flat.contains("refuse otherwise"),
        "SKILL.md still says the beta flags refuse without a seed"
    );
}

/// Every command that takes `--beta` answers as stable does between seeds.
///
/// "The beta channel" is not one code path: mSCP reaches its own tables
/// through `mscp::api`, the Apple schema through `contour_form`, so this walks
/// the flag, not the implementation. Each pair is a command an operator or an
/// agent would actually type, with and without the flag.
#[test]
fn every_beta_entry_point_answers_as_stable_between_seeds() {
    if beta_is_carried() {
        return;
    }
    let cases: &[(&[&str], &[&str])] = &[
        (
            &["--channel", "beta", "profile", "info", "com.apple.dock"],
            &["profile", "info", "com.apple.dock"],
        ),
        (
            &["--channel", "beta", "profile", "search", "dock"],
            &["profile", "search", "dock"],
        ),
        (
            &["mscp", "schema", "search", "siri", "--beta"],
            &["mscp", "schema", "search", "siri"],
        ),
        (
            &[
                "mscp",
                "schema",
                "rule",
                "os_apple_intelligence_pcc_disable",
                "--beta",
            ],
            &[
                "mscp",
                "schema",
                "rule",
                "os_apple_intelligence_pcc_disable",
            ],
        ),
    ];
    let mut differ = Vec::new();
    for (beta, stable) in cases {
        let (b, s) = (run(beta), run(stable));
        if !b.status.success() || b.stdout != s.stdout {
            differ.push(format!(
                "  contour {} (exit {:?}{})",
                beta.join(" "),
                b.status.code(),
                if b.stdout != s.stdout {
                    ", output differs from stable"
                } else {
                    ""
                }
            ));
        }
    }
    assert!(
        differ.is_empty(),
        "with no seed carried, these --beta entry points did not answer as stable:\n{}",
        differ.join("\n")
    );
}
