//! What contour writes into a Fleet GitOps tree must conform to Fleet's schema.
//!
//! contour's model types are its own idea of Fleet's format. Fleet publishes
//! the real contract as a JSON Schema
//! (`tools/gitops-auto-complete/generated-schema.json` in fleetdm/fleet).
//!
//! The schema is the one `mscp validate` uses by default: pinned at a Fleet
//! commit, held to its sha256, and shipped in mscp-schema, which embeds it. So the test and the runtime check read one
//! file — a test fixture beside it could agree with itself and disagree with
//! what users are validated against. It is closed at the root
//! (`additionalProperties: false`), so a key Fleet does not define fails,
//! which is precisely the drift this is for.
//!
//! Necessary, not sufficient: the schema lists all three `labels_*` fields as
//! independent, so Fleet's one-field-per-entry rule is still enforced by hand
//! in `CustomSetting::validate`.

use mscp::config::GlobSection;
use mscp::generators::{FleetGitOpsGenerator, GlobPlan};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// The pin: the schema Fleet ships in fleet-v4.92.2 (69c2103f) — contour
/// targets Fleet 4.92 and later.
const SCHEMA_SHA256: &str = "05b5b67de9eade852f2ed06e98cee1ba766bc25c21b8541e1e7e19288ec59055";

fn schema_bytes() -> &'static [u8] {
    mscp_schema::embedded_fleet_gitops_schema().expect(
        "this build embeds no Fleet GitOps schema: its mscp-schema dataset predates \
         the Fleet GitOps schema release. The build refetches a data/ stamped with another \
         pin, so this means the pinned release itself lacks it — or the build ran \
         with CONTOUR_SCHEMA_SKIP_DOWNLOAD — or CONTOUR_SCHEMA_SRC points at a dataset build \
         out/ without fleet-gitops-schema.json.",
    )
}

fn schema() -> serde_json::Value {
    serde_json::from_slice(schema_bytes()).expect("embedded schema is JSON")
}

/// The embedded schema is the pinned one.
///
/// A schema change is the event worth looking at, not absorbing — so a new
/// pin fails here, loudly, until this constant moves with it,
/// rather than quietly moving the goalposts every other test in this file is
/// measured against.
#[test]
fn the_embedded_schema_is_the_pinned_one() {
    let got: String = Sha256::digest(schema_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        got, SCHEMA_SHA256,
        "the Fleet GitOps schema in mscp-schema changed. If the dataset re-pinned it \
         deliberately, read the diff \
         and update SCHEMA_SHA256 here."
    );
}

/// Emit every shape of GitOps file the generator produces.
///
/// Each variant is one a real run reaches: the global and unassigned files, a
/// baseline with profiles, scripts and a policy reference, a baseline with
/// `[baselines.labels] include_all` configured, and a glob-mode baseline.
fn emit_every_shape(dir: &Path) -> Vec<PathBuf> {
    let g = FleetGitOpsGenerator::new_default(dir);
    g.generate_structure().expect("structure");
    g.generate_default_yml().expect("default.yml");
    g.generate_unassigned_yml().expect("unassigned.yml");

    let plain = GlobPlan {
        profiles: None,
        scripts: None,
        extra_include_all: &[],
    };
    g.generate_fleet_yml_with_glob_plan(
        "cis_lvl1",
        &[PathBuf::from("com.apple.dock.mobileconfig")],
        &[(
            PathBuf::from("cis_lvl1_audit.sh"),
            Some(PathBuf::from("cis_lvl1_remediate.sh")),
        )],
        Some(Path::new("cis_lvl1.policies.yml")),
        &plain,
    )
    .expect("plain baseline");

    let extra = vec!["pilot-ring-1".to_string(), "has-t2".to_string()];
    let labelled = GlobPlan {
        profiles: None,
        scripts: None,
        extra_include_all: &extra,
    };
    g.generate_fleet_yml_with_glob_plan(
        "800-53r5_high",
        &[PathBuf::from("com.apple.screensaver.mobileconfig")],
        &[],
        None,
        &labelled,
    )
    .expect("labelled baseline");

    let section = GlobSection {
        enabled: true,
        drop_labels: true,
        exceptions: Vec::new(),
    };
    let globbed = GlobPlan {
        profiles: Some(&section),
        scripts: Some(&section),
        extra_include_all: &[],
    };
    g.generate_fleet_yml_with_glob_plan(
        "800-171",
        &[PathBuf::from("a.mobileconfig")],
        &[(PathBuf::from("s.sh"), None)],
        None,
        &globbed,
    )
    .expect("glob baseline");

    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .map(|e| e.path().to_path_buf())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .collect()
}

#[test]
fn every_emitted_gitops_file_conforms_to_fleets_schema() {
    let dir = tempfile::tempdir().expect("tempdir");
    let files = emit_every_shape(dir.path());

    // Five shapes are emitted above. Fewer found means the walk or the
    // generator changed — and a conformance test that checks nothing passes.
    assert!(
        files.len() >= 5,
        "expected at least 5 GitOps files, found {}: {:?}",
        files.len(),
        files
    );

    let validator = jsonschema::validator_for(&schema()).expect("Fleet's schema compiles");
    let mut failures = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).expect("readable");
        let yaml: yaml_serde::Value = yaml_serde::from_str(&text).expect("valid YAML");
        let json = serde_json::to_value(&yaml).expect("YAML → JSON");
        for k in deprecated_controls_keys(&json) {
            failures.push(format!(
                "  {} uses {k}, which Fleet deprecates or never defines (write \
                 apple_settings.configuration_profiles)",
                f.strip_prefix(dir.path()).unwrap_or(f).display()
            ));
        }
        for err in validator.iter_errors(&json) {
            failures.push(format!(
                "  {} at {}: {}",
                f.strip_prefix(dir.path()).unwrap_or(f).display(),
                err.instance_path(),
                err
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "contour emits GitOps YAML that Fleet's own schema rejects:\n{}\n\n\
         Either contour's output drifted, or Fleet's format did. Check the dataset's \
         data/fleet-gitops-schema/README.md for the pinned version before assuming which.",
        failures.join("\n")
    );
}

/// The check can fail.
///
/// A conformance test that has never been seen rejecting anything is
/// indistinguishable from one wired to nothing. These are the drifts it
/// exists for: a key Fleet does not define (the root is closed), and a field
/// of the wrong type.
#[test]
fn the_schema_rejects_what_fleet_would_reject() {
    let validator = jsonschema::validator_for(&schema()).expect("Fleet's schema compiles");

    let good: serde_json::Value = serde_json::json!({
        "name": "cis-lvl1",
        "controls": { "apple_settings": { "configuration_profiles": [
            { "path": "../p/a.mobileconfig", "labels_include_all": ["mscp-cis_lvl1"] }
        ]}}
    });
    assert!(
        validator.is_valid(&good),
        "a minimal well-formed team file must pass, or the negatives below prove nothing"
    );

    let unknown_root_key = serde_json::json!({ "name": "x", "secrets_manager": {} });
    assert!(
        !validator.is_valid(&unknown_root_key),
        "an undefined root key must fail — the root is closed"
    );

    let wrong_type = serde_json::json!({
        "name": "x",
        "controls": { "apple_settings": { "configuration_profiles": [
            { "path": "../p/a.mobileconfig", "labels_include_all": "mscp-cis_lvl1" }
        ]}}
    });
    assert!(
        !validator.is_valid(&wrong_type),
        "labels_include_all as a string rather than a list must fail"
    );
}

/// The generated config must not point `schemas_path` at nothing.
///
/// It shipped `schemas_path = "./schemas"`, a directory nothing creates. That
/// was harmless while `[validation]` was unreachable. Now `mscp validate
/// --config` reads it and a schema path holding no schema fails the run — so
/// every freshly generated config would have failed its first validate. The
/// fourth setting in this series whose shipped value was wrong and could not
/// be found out until something read it.
#[test]
fn the_generated_config_does_not_ship_a_schema_path() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config/template.rs"),
    )
    .expect("template.rs readable");
    let shipped: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("schemas_path:"))
        .filter(|l| !l.contains("None"))
        .collect();
    assert!(
        shipped.is_empty(),
        "the config template ships a schemas_path:\n{}\n\nNo directory contour creates \
         holds Fleet's schema, so a shipped path fails the user's first `validate --config`.",
        shipped.join("\n")
    );
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
