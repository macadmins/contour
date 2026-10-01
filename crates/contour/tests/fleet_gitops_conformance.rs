//! Every contour command that writes Fleet GitOps YAML must write what Fleet
//! accepts.
//!
//! `crates/mscp/tests/fleet_gitops_output_conforms.rs` holds the mSCP
//! generator to Fleet's own schema. It is not the only emitter. btm, pppc,
//! notifications and support write team YAML through `--fragment`, santa
//! writes a `default.yml`, and `profile windows stig export` writes Fleet
//! policies — several of them by assembling YAML line by line
//! (`contour-core::yaml_edit`, `push_str("        labels_include_any:\n")`).
//! String-built YAML is where a schema catches most, because there is no type
//! to object: indentation, nesting and key names are all just text.
//!
//! This file drives each one through the real binary, the way an operator
//! would, and validates what lands on disk against the schema Fleet publishes
//! — the pinned copy `mscp-schema` embeds, the same one `mscp validate` uses
//! by default. `fleet_gitops_output_conforms.rs` asserts
//! its sha256.
//!
//! Every case asserts it found at least one file. A conformance check over an
//! empty directory passes, and an emitter that quietly stops writing is
//! exactly the regression that would otherwise go unseen.

use assert_cmd::Command;
use std::path::{Path, PathBuf};

fn schema() -> serde_json::Value {
    let bytes = mscp_schema::embedded_fleet_gitops_schema().expect(
        "this build embeds no Fleet GitOps schema: its mscp-schema dataset predates \
         the Fleet GitOps schema release. The build refetches a data/ stamped with another \
         pin, so this means the pinned release itself lacks it — or the build ran \
         with CONTOUR_SCHEMA_SKIP_DOWNLOAD, which warns that data/ is not the pin.",
    );
    serde_json::from_slice(bytes).expect("Fleet schema is JSON")
}

fn contour(dir: &Path, args: &[&str]) {
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "`contour {}` failed:\n{}{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn yaml_files(dir: &Path) -> Vec<PathBuf> {
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

fn to_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).expect("readable");
    let yaml: yaml_serde::Value = yaml_serde::from_str(&text).expect("valid YAML");
    serde_json::to_value(yaml).expect("YAML → JSON")
}

/// Validate every YAML file under `dir` as a Fleet GitOps team/global file.
/// Returns the violations, one line each.
/// A validator for one named `$defs` entry of Fleet's schema.
fn def_validator(name: &str) -> jsonschema::Validator {
    let mut spec = serde_json::Map::new();
    spec.insert("$defs".into(), schema()["$defs"].clone());
    spec.insert("$ref".into(), format!("#/$defs/{name}").into());
    jsonschema::validator_for(&serde_json::Value::Object(spec))
        .unwrap_or_else(|e| panic!("{name} compiles: {e}"))
}

/// Is this a label file — the thing `default.yml`'s `labels: - path:` names?
///
/// Those hold a LIST of label specs, not a GitOps document, so they are
/// checked against `$defs/LabelSpec` item by item. The first version of this
/// file validated every YAML against the root schema, which is right for team
/// and global files and wrong for these. santa was the first emitter here to
/// write label files, and the check reported them as santa's fault; they are
/// valid, and the helper was the thing that was wrong.
fn is_label_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".labels.yml") || n.ends_with(".labels.yaml"))
}

/// Validate every YAML file under `dir` against the part of Fleet's schema it
/// is an instance of. Returns (files checked, violations).
fn root_violations(dir: &Path) -> (usize, Vec<String>) {
    let root = jsonschema::validator_for(&schema()).expect("Fleet's schema compiles");
    let label = def_validator("LabelSpec");
    let files = yaml_files(dir);
    let mut bad = Vec::new();
    for f in &files {
        let rel = f.strip_prefix(dir).unwrap_or(f).display().to_string();
        let doc = to_json(f);
        if is_label_file(f) {
            let items = match &doc {
                serde_json::Value::Array(items) => items.clone(),
                other => vec![other.clone()],
            };
            for (i, item) in items.iter().enumerate() {
                for err in label.iter_errors(item) {
                    bad.push(format!("  {rel} #{i} at {}: {err}", err.instance_path()));
                }
            }
        } else {
            for err in root.iter_errors(&doc) {
                bad.push(format!("  {rel} at {}: {err}", err.instance_path()));
            }
        }
    }
    (files.len(), bad)
}

/// Keys Fleet's schema marks deprecated, or never defines, under `controls`.
///
/// Schema validation alone accepts the deprecated aliases, so it cannot catch
/// an emitter falling back to them: this does. `ios_settings` is not a Fleet
/// key at all — contour once wrote it for iOS baselines.
fn deprecated_controls_keys(doc: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(controls) = doc.get("controls").and_then(|c| c.as_object()) else {
        return out;
    };
    for k in ["macos_settings", "ios_settings"] {
        if controls.contains_key(k) {
            out.push(format!("controls.{k}"));
        }
    }
    for (k, v) in controls {
        if v.get("custom_settings").is_some() {
            out.push(format!("controls.{k}.custom_settings"));
        }
    }
    out
}

fn assert_conforms(emitter: &str, dir: &Path) {
    let (checked, bad) = root_violations(dir);
    let deprecated: Vec<String> = yaml_files(dir)
        .iter()
        .flat_map(|f| {
            deprecated_controls_keys(&to_json(f))
                .into_iter()
                .map(move |k| format!("  {}: {k}", f.display()))
        })
        .collect();
    assert!(
        deprecated.is_empty(),
        "{emitter} writes keys Fleet deprecates (use apple_settings.configuration_profiles):\n{}",
        deprecated.join("\n")
    );
    assert!(
        checked > 0,
        "{emitter} wrote no GitOps YAML — a conformance check over nothing passes, so \
         this is a failure"
    );
    assert!(
        bad.is_empty(),
        "{emitter} writes GitOps YAML that Fleet's own schema rejects:\n{}",
        bad.join("\n")
    );
}

/// A one-pixel PNG, for emitters that want brand assets on disk.
const PNG_1X1: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0x0f, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x05, 0x18, 0xd8, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

/// Init a blank config for `tool`, append one app so there is something to
/// emit, and generate the Fleet fragment.
fn fragment_from_one_app(tool: &str, app: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = format!("{tool}.toml");
    contour(
        dir.path(),
        &[
            tool, "init", "--org", "com.acme", "--name", "Acme", "-o", &cfg,
        ],
    );
    // `init` writes `apps = []`; an inline empty array and an [[apps]] table
    // cannot both name the same key.
    let path = dir.path().join(&cfg);
    let text = std::fs::read_to_string(&path).expect("init wrote the config");
    let text = text.replace("apps = []\n", "");
    std::fs::write(&path, format!("{text}\n{app}")).expect("append app");
    contour(
        dir.path(),
        &[tool, "generate", &cfg, "--fragment", "-o", "out"],
    );
    dir
}

#[test]
fn btm_fragments_conform() {
    let dir = fragment_from_one_app(
        "btm",
        r#"[[apps]]
name = "Zoom"
bundle_id = "us.zoom.xos"
team_id = "BJ4HAAB9B3"

[[apps.rules]]
rule_type = "TeamIdentifier"
rule_value = "BJ4HAAB9B3"
"#,
    );
    assert_conforms("btm generate --fragment", &dir.path().join("out"));
}

#[test]
fn pppc_fragments_conform() {
    let dir = fragment_from_one_app(
        "pppc",
        r#"[[apps]]
name = "Zoom"
bundle_id = "us.zoom.xos"
code_requirement = 'identifier "us.zoom.xos" and anchor apple generic and certificate leaf[subject.OU] = "BJ4HAAB9B3"'
identifier_type = "bundleID"
services = ["camera"]
"#,
    );
    assert_conforms("pppc generate --fragment", &dir.path().join("out"));
}

#[test]
fn notifications_fragments_conform() {
    let dir = fragment_from_one_app(
        "notifications",
        "[[apps]]\nname = \"Zoom\"\nbundle_id = \"us.zoom.xos\"\n",
    );
    assert_conforms("notifications generate --fragment", &dir.path().join("out"));
}

#[test]
fn support_fragments_conform() {
    let dir = tempfile::tempdir().expect("tempdir");
    let brand = dir.path().join("assets/acme");
    std::fs::create_dir_all(&brand).expect("brand dir");
    for f in [
        "logo.png",
        "logo_darkmode.png",
        "support-app-menubar-icon.png",
    ] {
        std::fs::write(brand.join(f), PNG_1X1).expect("asset");
    }
    contour(
        dir.path(),
        &["support", "init", "assets", "-o", "support.toml"],
    );
    contour(
        dir.path(),
        &[
            "support",
            "generate",
            "support.toml",
            "--fragment",
            "-o",
            "out",
        ],
    );
    assert_conforms("support generate --fragment", &dir.path().join("out"));
}

/// `profile windows stig export` writes a list of Fleet policies, the file a
/// team's `policies: - path:` points at. Each entry is a `GitOpsPolicySpec`.
#[test]
fn the_stig_export_is_a_list_of_fleet_policies() {
    let dir = tempfile::tempdir().expect("tempdir");
    contour(
        dir.path(),
        &[
            "profile",
            "windows",
            "stig",
            "export",
            "--profile",
            "dod-windows-11-stig-v2r4",
            "-o",
            "w11.yml",
        ],
    );
    let doc = to_json(&dir.path().join("w11.yml"));
    let policies = doc.as_array().expect("a policies file is a list");
    assert!(!policies.is_empty(), "the export wrote no policies");

    let validator = def_validator("GitOpsPolicySpec");

    let bad: Vec<String> = policies
        .iter()
        .enumerate()
        .flat_map(|(i, p)| {
            let name = p["name"].as_str().unwrap_or("?").to_string();
            validator
                .iter_errors(p)
                .map(move |e| format!("  #{i} {name}: {e}"))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        bad.is_empty(),
        "{} of {} STIG policies are rejected by Fleet's GitOpsPolicySpec:\n{}",
        bad.len(),
        policies.len(),
        bad.join("\n")
    );
}

/// Write one santa rule to `dir/rules.yaml`.
fn santa_rules(dir: &Path) {
    std::fs::write(
        dir.join("rules.yaml"),
        "- identifier: EQHXZ8M8AV\n  rule_type: TEAMID\n  policy: ALLOWLIST\n  \
         description: Google\n  group: browsers\n",
    )
    .expect("rules");
}

/// `santa fleet` writes Fleet GitOps that Fleet accepts.
///
/// `default.yml` is the file `fleetctl gitops` reads as the global config,
/// and Fleet's root is closed, so any shape of santa's own is rejected at the
/// first key; every label a profile targets must be defined.
#[test]
fn santa_fleet_conforms() {
    let dir = tempfile::tempdir().expect("tempdir");
    santa_rules(dir.path());
    contour(
        dir.path(),
        &[
            "santa",
            "fleet",
            "rules.yaml",
            "-o",
            "out",
            "--org",
            "com.acme",
            "--num-rings",
            "2",
        ],
    );
    assert_conforms("santa fleet", &dir.path().join("out"));
}

#[test]
fn santa_fleet_fragment_conforms() {
    let dir = tempfile::tempdir().expect("tempdir");
    santa_rules(dir.path());
    contour(
        dir.path(),
        &[
            "santa",
            "fleet",
            "rules.yaml",
            "-o",
            "out",
            "--org",
            "com.acme",
            "--num-rings",
            "2",
            "--fragment",
        ],
    );
    assert_conforms("santa fleet --fragment", &dir.path().join("out"));
}

/// Every label a santa profile targets is defined in the same output.
///
/// The removed emitter pointed profiles at `ring:0`, `ring:1` and wrote no
/// label definitions — so even a correctly shaped file would have sent its
/// profiles to no hosts. Conforming to the schema cannot catch that; the
/// schema has no idea which labels exist. This does.
#[test]
fn santa_profiles_target_only_labels_it_defines() {
    let dir = tempfile::tempdir().expect("tempdir");
    santa_rules(dir.path());
    contour(
        dir.path(),
        &[
            "santa",
            "fleet",
            "rules.yaml",
            "-o",
            "out",
            "--org",
            "com.acme",
            "--num-rings",
            "2",
        ],
    );
    let out = dir.path().join("out");
    let mut defined = std::collections::BTreeSet::new();
    let mut targeted = std::collections::BTreeSet::new();
    for f in yaml_files(&out) {
        let doc = to_json(&f);
        if is_label_file(&f) {
            for item in doc.as_array().into_iter().flatten() {
                if let Some(n) = item["name"].as_str() {
                    defined.insert(n.to_string());
                }
            }
            continue;
        }
        assert!(
            doc["controls"].get("macos_settings").is_none(),
            "{} writes the deprecated macos_settings key",
            f.display()
        );
        let settings = &doc["controls"]["apple_settings"]["configuration_profiles"];
        for entry in settings.as_array().into_iter().flatten() {
            for field in [
                "labels_include_all",
                "labels_include_any",
                "labels_exclude_any",
            ] {
                for l in entry[field].as_array().into_iter().flatten() {
                    if let Some(l) = l.as_str() {
                        targeted.insert(l.to_string());
                    }
                }
            }
        }
    }
    assert!(!targeted.is_empty(), "santa fleet targets no labels at all");
    let missing: Vec<&String> = targeted.difference(&defined).collect();
    assert!(
        missing.is_empty(),
        "santa profiles target labels this output never defines: {missing:?}\n\
         defined: {defined:?}\n\
         A profile aimed at a label that does not exist in Fleet reaches no hosts."
    );
}

/// The santa SOP leaves rings undocumented.
///
/// `santa rings` and `santa fleet` (which builds ring editions) stay in the
/// binary, but are not a documented feature. The SOP is what an agent is
/// handed, so it must not steer one toward them.
#[test]
fn the_santa_sop_does_not_document_rings() {
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args(["help-agents", "--sop", "santa"])
        .output()
        .unwrap();
    let sop = String::from_utf8_lossy(&out.stdout).to_string();
    for word in ["santa rings", "santa fleet", "--num-rings", "--rings-config", "rings:"] {
        assert!(!sop.contains(word), "the santa SOP still mentions {word:?}");
    }
}
