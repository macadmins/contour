//! Integration: `mscp init` → `mscp.toml` → `mscp generate-all --config`, for
//! macOS and iOS baselines in one output, over a real mSCP 2.0 checkout.
//!
//! What it pins:
//! - `init --keywords name,name:os` writes each baseline's `os` into `mscp.toml`;
//! - every output is named `<baseline>_<os>`, macOS included, so a name shared
//!   across platforms (`800-53r5_low`) lands in two places, not one;
//! - files sit in Fleet's current layout (`platforms/<os>/…`, declarations in
//!   `platforms/<os>/declaration-profiles/`), with no legacy `lib/`;
//! - every `path:` a GitOps file names exists;
//! - no script still carries a raw `$ODV`.
//!
//! `#[ignore]`, and it PANICS when asked to run without what it needs — see
//! `osquery_bridge.rs` for why a quiet early return is not an option.

use std::path::{Path, PathBuf};
use std::process::Command;

/// `(baseline, os)` as given to `init`; `800-53r5_low` is on both platforms.
const BASELINES: &[(&str, &str)] = &[
    ("cis_lvl1", "macos"),
    ("800-53r5_low", "macos"),
    ("800-53r5_low", "ios"),
    ("cis_lvl1_byod", "ios"),
];

fn run(args: &[&str]) {
    let out = Command::new(env!("CARGO_BIN_EXE_mscp"))
        .args(args)
        .output()
        .expect("failed to spawn mscp");
    assert!(
        out.status.success(),
        "`mscp {}` failed\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect()
}

/// Every `path: <file>` in a GitOps YAML, resolved against that file.
fn path_refs(yaml: &Path) -> Vec<PathBuf> {
    std::fs::read_to_string(yaml)
        .unwrap()
        .lines()
        .filter_map(|l| l.trim().trim_start_matches("- ").strip_prefix("path: "))
        .map(|p| yaml.parent().unwrap().join(p.trim().trim_matches('"')))
        .collect()
}

#[test]
#[ignore = "needs an mSCP 2.0 checkout — set CONTOUR_MSCP_REPO — and python3; run with \
            --include-ignored"]
fn init_then_generate_all_lays_out_every_platform() {
    let repo = std::env::var("CONTOUR_MSCP_REPO")
        .ok()
        .filter(|r| Path::new(r).join("baselines/ios").is_dir())
        .expect(
            "asked to run (--include-ignored) but CONTOUR_MSCP_REPO does not name an mSCP \
             2.0 checkout with baselines/ios/",
        );

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let out = root.join("output");
    let config = root.join("mscp.toml");

    // 1. init: `name` is macOS, `name:os` is that platform.
    let keywords: Vec<String> = BASELINES
        .iter()
        .map(|(n, os)| match *os {
            "macos" => (*n).to_string(),
            _ => format!("{n}:{os}"),
        })
        .collect();
    run(&[
        "init",
        "-o",
        root.to_str().unwrap(),
        "--org",
        "com.acme",
        "-n",
        "Acme",
        "--fleet-gitops",
        "--keywords",
        &keywords.join(","),
    ]);

    let toml = std::fs::read_to_string(&config).unwrap();
    for (name, os) in BASELINES {
        assert!(
            toml.contains(&format!("name = \"{name}\"\nenabled = true\nos = \"{os}\"")),
            "mscp.toml has no [[baselines]] {name} / {os}:\n{toml}"
        );
    }

    // 2. Point the config at the checkout and turn declarations on.
    let edit = |toml: String, key: &str, value: &str| {
        let line = toml
            .lines()
            .find(|l| l.starts_with(&format!("{key} = ")))
            .unwrap_or_else(|| panic!("mscp.toml has no `{key}`"))
            .to_string();
        toml.replacen(&line, &format!("{key} = {value}"), 1)
    };
    let toml = edit(toml, "mscp_repo", &format!("{repo:?}"));
    let toml = edit(toml, "output_dir", &format!("{:?}", out.to_str().unwrap()));
    let toml = edit(toml, "generate_ddm", "true");
    std::fs::write(&config, toml).unwrap();

    // 3. generate.
    run(&["generate-all", "--config", config.to_str().unwrap()]);

    // 4. Each baseline is `<name>_<os>`, in its own platform's folders.
    for (name, os) in BASELINES {
        let id = format!("{name}_{os}");
        let profiles = out.join(format!("platforms/{os}/configuration-profiles/{id}"));
        assert!(
            !files_under(&profiles).is_empty(),
            "no profiles in {}",
            profiles.display()
        );
        for rel in [
            format!("fleets/{id}.yml"),
            format!("labels/mscp-{id}.labels.yml"),
            format!("mscp/{id}/baseline.toml"),
        ] {
            assert!(out.join(&rel).exists(), "missing {rel}");
        }
        // The bare name is gone, for macOS too.
        assert!(!out.join(format!("fleets/{name}.yml")).exists());

        // iOS baselines cover iPadOS, so their labels name no platform.
        let labels =
            std::fs::read_to_string(out.join(format!("labels/mscp-{id}.labels.yml"))).unwrap();
        assert_eq!(
            labels.contains("platform:"),
            *os == "macos",
            "{id}:\n{labels}"
        );
    }

    // 5. Latest layout only; scripts are a macOS thing.
    assert!(!out.join("lib").exists(), "legacy lib/ was written");
    assert!(!out.join("platforms/ios/scripts").exists());

    // 6. Every path a GitOps file names exists, and declarations are among them.
    let mut yamls = files_under(&out.join("fleets"));
    yamls.push(out.join("default.yml"));
    let refs: Vec<PathBuf> = yamls.iter().flat_map(|y| path_refs(y)).collect();
    let missing: Vec<&PathBuf> = refs.iter().filter(|p| !p.exists()).collect();
    assert!(missing.is_empty(), "dangling path refs: {missing:#?}");
    for os in ["macos", "ios"] {
        let dir = format!("platforms/{os}/declaration-profiles/");
        assert!(
            refs.iter().any(|p| p.to_string_lossy().contains(&dir)),
            "no fleet file references {dir}"
        );
    }

    // 7. Scripts carry the baseline's value, not the placeholder.
    let scripts = files_under(&out.join("platforms/macos/scripts"));
    assert!(!scripts.is_empty(), "no macOS scripts were written");
    let raw: Vec<&PathBuf> = scripts
        .iter()
        .filter(|p| std::fs::read_to_string(p).is_ok_and(|s| s.contains("$ODV")))
        .collect();
    assert!(raw.is_empty(), "raw $ODV left in: {raw:#?}");
}

/// A fragment lists declarations beside profiles, from the platform's own
/// `declaration-profiles/` folder, and every file it lists exists.
#[test]
#[ignore = "needs an mSCP 2.0 checkout — set CONTOUR_MSCP_REPO — and python3; run with \
            --include-ignored"]
fn an_ios_fragment_lists_its_declarations() {
    let repo = std::env::var("CONTOUR_MSCP_REPO")
        .ok()
        .filter(|r| Path::new(r).join("baselines/ios").is_dir())
        .expect(
            "asked to run (--include-ignored) but CONTOUR_MSCP_REPO does not name an mSCP \
             2.0 checkout with baselines/ios/",
        );
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path();
    run(&[
        "generate",
        "-m",
        &repo,
        "-k",
        "cis_lvl1_byod",
        "--os",
        "ios",
        "-o",
        out.to_str().unwrap(),
        "--fragment",
        "--generate-ddm",
    ]);

    let manifest = std::fs::read_to_string(out.join("fragment.toml")).unwrap();
    let listed: Vec<&str> = manifest
        .lines()
        .filter_map(|l| l.strip_prefix("path = \"../"))
        .map(|p| p.trim_end_matches('"'))
        .collect();
    for dir in [
        "platforms/ios/configuration-profiles/cis_lvl1_byod_ios/",
        "platforms/ios/declaration-profiles/cis_lvl1_byod_ios/",
    ] {
        assert!(
            listed.iter().any(|p| p.starts_with(dir)),
            "fragment.toml lists nothing under {dir}:\n{manifest}"
        );
    }
    let missing: Vec<&&str> = listed.iter().filter(|p| !out.join(p).exists()).collect();
    assert!(
        missing.is_empty(),
        "fragment lists missing files: {missing:#?}"
    );
}
