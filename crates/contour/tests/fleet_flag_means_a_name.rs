//! `--fleet` means a fleet's name, in every contour command.
//!
//! mscp.toml uses `fleet = "…"` for a name, and so does the CLI:
//!
//! - `mscp init --fleet-gitops` is the Fleet GitOps switch (`--fleet` there
//!   is refused by name, not silently reinterpreted)
//! - `mscp migrate --fleet` is a name
//! - `santa fleet --fleet`, with `--team` as an alias
//! - `mscp generate --fleets` also answers to `--fleet`
//!
//! This walks every command the binary has and requires that a visible
//! `--fleet`, as a flag or an alias, takes `<NAME>`. A new command that reuses
//! the word for a switch or a path fails here, which is the only way a naming
//! rule survives more than one release.

use assert_cmd::Command;
use std::collections::BTreeSet;

fn help(path: &[String]) -> String {
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args(path)
        .arg("--help")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn subcommands(help: &str) -> Vec<String> {
    let Some(rest) = help.split("Commands:").nth(1) else {
        return Vec::new();
    };
    let block = rest.split("\n\n").next().unwrap_or("");
    block
        .lines()
        .filter_map(|l| l.strip_prefix("  "))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|w| w.chars().next().is_some_and(|c| c.is_ascii_lowercase()) && *w != "help")
        .map(str::to_string)
        .collect()
}

/// Every command path, depth first.
fn all_commands() -> Vec<(Vec<String>, String)> {
    let mut out = Vec::new();
    let mut stack = vec![Vec::<String>::new()];
    let mut seen = BTreeSet::new();
    while let Some(path) = stack.pop() {
        if !seen.insert(path.clone()) {
            continue;
        }
        let h = help(&path);
        for sub in subcommands(&h) {
            let mut next = path.clone();
            next.push(sub);
            stack.push(next);
        }
        out.push((path, h));
    }
    out
}

#[test]
fn every_visible_fleet_flag_takes_a_name() {
    let commands = all_commands();
    assert!(
        commands.len() > 100,
        "walked only {} commands — the walk is broken, not the CLI",
        commands.len()
    );

    let mut named = Vec::new();
    let mut wrong = Vec::new();
    for (path, h) in &commands {
        let cmd = format!("contour {}", path.join(" "));
        let lines: Vec<&str> = h.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            // A flag line: `--fleet` or `-f, --fleet`, possibly with a value.
            let declares = t.starts_with("--fleet ")
                || t == "--fleet"
                || t.starts_with("-f, --fleet ")
                || t == "-f, --fleet";
            // `--fleets <NAME>` with `[alias: --fleet]` a few lines below.
            let aliased = t.starts_with("--")
                && lines[i + 1..]
                    .iter()
                    .take(8)
                    .take_while(|l| !l.trim_start().starts_with('-'))
                    .any(|l| {
                        l.contains("alias: --fleet]")
                            || l.contains("aliases: --fleet]")
                            || l.contains("alias: --fleet,")
                            || l.contains("aliases: --fleet,")
                    });
            if declares || aliased {
                if t.contains("<NAME>") {
                    named.push(cmd.clone());
                } else {
                    wrong.push(format!("  {cmd}: {t}"));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "`--fleet` must name a fleet (`--fleet <NAME>`). These use it for something else:\n{}\n\n\
         Pick another word — `--fleet-gitops` for the switch, `--fleet-file` for a path.",
        wrong.join("\n")
    );
    // The commands this rule was written for must still carry it, or the walk
    // is matching nothing and passing by default.
    for expected in [
        "contour santa fleet",
        "contour mscp migrate",
        "contour mscp generate",
    ] {
        assert!(
            named.iter().any(|c| c == expected),
            "{expected} no longer offers `--fleet <NAME>`; found it on: {named:?}"
        );
    }
}

/// The retired switch is refused by name, not silently reinterpreted.
#[test]
fn mscp_init_fleet_points_at_fleet_gitops() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args(["mscp", "init", "--fleet", "--org", "com.acme", "-o"])
        .arg(dir.path().join("m.toml"))
        .output()
        .unwrap();
    assert!(!out.status.success(), "`mscp init --fleet` must fail now");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--fleet-gitops"),
        "the refusal must name the new flag: {err}"
    );
}
