//! The beta SOP must describe the beta channel that exists.
//!
//! With no seed dataset carried, every `*_beta` accessor returns the stable
//! bytes. A SOP or help text still promising "seed-only declarations and
//! keys" would have an agent tell someone to pass `--beta` to find a type
//! that is not there.
//!
//! This is `sop_traps_windows.rs` in mirror image: there a SOP must not deny
//! a command that exists; here it must not promise a dataset that is absent.
//! Same failure, opposite sign: prose and binary drifting apart with nothing
//! holding them together.
//!
//! So the SOP's claim is tied to the bytes. Beta is dormant rather than
//! removed — a future seed brings it back — and these tests follow the data
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

#[test]
fn the_beta_sop_says_whether_beta_works() {
    let text = sop("beta");
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if beta_is_carried() {
        assert!(
            !flat.contains("The beta channel is DISABLED right now"),
            "a seed dataset is carried again, but the beta SOP still opens by saying \
             the channel is disabled — drop the banner and the warning in \
             sop-beta.md, and re-check the --channel help strings"
        );
    } else {
        assert!(
            flat.contains("The beta channel is DISABLED right now"),
            "no seed dataset is carried, so `--beta` refuses — but the beta SOP does \
             not say so. An agent reading it will tell someone to pass a flag that \
             errors."
        );
        assert!(
            flat.contains("Do not tell anyone to pass `--beta` today"),
            "the SOP is read by agents that act on it; the disabled banner has to \
             say what NOT to recommend, not only what is true"
        );
    }
}

/// The flag's behaviour matches what the SOP says about it.
///
/// Reads the binary rather than the source: whatever the SOP claims, this is
/// what someone typing the flag actually gets.
#[test]
fn the_beta_flag_refuses_rather_than_serving_stable() {
    if beta_is_carried() {
        return;
    }
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args(["--channel", "beta", "profile", "info", "com.apple.dock"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "--channel beta succeeded while no seed dataset is carried; it served the \
         stable schema under another name, which is the defect this file exists for"
    );
    let msg = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        msg.contains("beta channel is disabled"),
        "the refusal must say the channel is disabled, not fail obscurely: {msg}"
    );
    assert!(
        msg.contains("dormant") || msg.contains("comes back") || msg.contains("again"),
        "the refusal must say beta returns with a future seed — otherwise it reads \
         as a feature that was removed: {msg}"
    );
}

/// The help text agrees with the flag.
///
/// The SOP is one surface; `--help` is the one most people actually read, and
/// it advertised "includes seed-only declarations and keys" for months after
/// there were none.
#[test]
fn the_help_text_does_not_advertise_a_disabled_channel() {
    if beta_is_carried() {
        return;
    }
    let out = Command::cargo_bin("contour")
        .unwrap()
        .arg("--help")
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout).to_string();
    let flat = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("currently disabled") || flat.contains("DISABLED"),
        "`contour --help` describes the beta channel without saying it is \
         disabled:\n{help}"
    );
}

/// `SKILL.md` is the first thing an agent reads, and it had this right.
///
/// Before the flag refused, that file already said beta "still work[s] but
/// currently return[s] the **stable** dataset" and told agents not to claim
/// otherwise — while `--help` advertised "seed-only declarations and keys"
/// and the SOP described a superset. Three surfaces, one dataset, two of
/// them wrong. The accurate one is now the stale one, in the other
/// direction: beta no longer returns stable, it declines.
///
/// So the file is checked rather than remembered. It is installed by
/// `setup-agent`, so the test reads what an agent is actually handed.
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

    if beta_is_carried() {
        assert!(
            !flat.contains("are **disabled** and refuse"),
            "a seed dataset is carried again, but SKILL.md still tells agents the beta \
             flags refuse"
        );
        return;
    }
    assert!(
        flat.contains("are **disabled** and refuse"),
        "SKILL.md does not say the beta flags refuse. An agent reading it will route \
         someone to a flag that errors:\n{text}"
    );
    assert!(
        !flat.contains("still work but currently return the **stable** dataset"),
        "SKILL.md still describes the OLD behaviour — beta silently returning stable. \
         That is what the refusal replaced."
    );
}

/// Every command that takes `--beta` refuses, not just the Apple ones.
///
/// The first pass at this fixed `contour_form::SchemaRegistry`, which is the
/// Apple schema path, and left `mscp schema search --beta` returning stable
/// rules with exit 0 — the same defect, one crate over, surviving a fix
/// aimed at it. The lesson is that "the beta channel" is not one code path:
/// mSCP reaches its own tables through `mscp::api`, and any future dataset
/// with a seed will reach its own too.
///
/// So this walks the flag, not the implementation. Each command below is one
/// an operator or an agent would actually type.
#[test]
fn every_beta_entry_point_refuses_while_beta_is_disabled() {
    if beta_is_carried() {
        return;
    }
    let cases: &[&[&str]] = &[
        &["--channel", "beta", "profile", "info", "com.apple.dock"],
        &["--channel", "beta", "profile", "search", "dock"],
        &["mscp", "schema", "search", "siri", "--beta"],
        &[
            "mscp",
            "schema",
            "rule",
            "os_apple_intelligence_pcc_disable",
            "--beta",
        ],
    ];
    let mut leaked = Vec::new();
    for args in cases {
        let out = Command::cargo_bin("contour")
            .unwrap()
            .args(*args)
            .output()
            .unwrap();
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if out.status.success() || !combined.contains("beta channel is disabled") {
            leaked.push(format!(
                "  contour {} — exit {:?}, did not refuse",
                args.join(" "),
                out.status.code()
            ));
        }
    }
    assert!(
        leaked.is_empty(),
        "these --beta entry points answered from the stable dataset instead of \
         refusing:\n{}\n\n\
         Route them through the same check: mdm_schema::beta_dataset_is_carried() / \
         mscp_schema::beta_dataset_is_carried(), refusing with \
         mdm_schema::BETA_DISABLED_MESSAGE.",
        leaked.join("\n")
    );
}

/// One channel, one explanation.
///
/// Both refusals print `mdm_schema::BETA_DISABLED_MESSAGE`. Two texts
/// describing one channel is how the SOP and `--help` drifted apart from the
/// dataset and from each other in the first place.
#[test]
fn every_refusal_gives_the_same_explanation() {
    if beta_is_carried() {
        return;
    }
    let apple = Command::cargo_bin("contour")
        .unwrap()
        .args(["--channel", "beta", "profile", "info", "com.apple.dock"])
        .output()
        .unwrap();
    let mscp = Command::cargo_bin("contour")
        .unwrap()
        .args(["mscp", "schema", "search", "siri", "--beta"])
        .output()
        .unwrap();
    let text = |o: &std::process::Output| {
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
    };
    assert_eq!(
        text(&apple),
        text(&mscp),
        "the Apple and mSCP refusals disagree about why beta is off"
    );
}
