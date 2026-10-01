//! The refusals the Apple SOP documents must be refusals the code can make.
//!
//! An agent reads `--sop profile` to learn why contour said no. If the SOP
//! names a rule the validator cannot emit, the agent is told to look for a
//! message it will never see; if the validator gains a refusal the SOP does
//! not mention, the agent reads a real refusal as a bug and retries.
//!
//! These datasets moved fast: `SharedStructure` and the `-on-target`
//! availability verdicts both landed within two days of this file, and the
//! SOPs said nothing about either. Documenting them is only half the job —
//! this is the half that keeps the documentation answerable to the code.

use assert_cmd::Command;

fn profile_sop() -> String {
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args(["help-agents", "--sop", "profile"])
        .output()
        .unwrap();
    assert!(out.status.success(), "help-agents --sop profile failed");
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Rule names the SOP promises, against the validator that emits them.
///
/// The check is against `validate.rs` source rather than a public list
/// because there is no runtime registry of rule names — and a test that
/// invented one would be asserting its own copy, which is the failure this
/// whole exercise is about.
#[test]
fn every_rule_the_sop_names_exists_in_the_validator() {
    let sop = profile_sop();
    let validator = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contour-form/src/validate.rs"
    ))
    .expect("validate.rs is in this workspace");

    let documented = [
        "not-authorable",
        "payload-removed-on-target",
        "key-removed-on-target",
        "key-unavailable-on-platform",
        "key-deprecated-on-target",
        "key-removed",
        "payload-removed",
        "key-deprecated",
    ];
    for rule in documented {
        assert!(
            sop.contains(rule),
            "the profile SOP no longer documents `{rule}` — if the rule was \
             withdrawn, remove it here too"
        );
        assert!(
            validator.contains(&format!("\"{rule}\"")),
            "the profile SOP documents `{rule}` but validate.rs cannot emit it"
        );
    }
}

/// The three non-authorable kinds, named where an agent will look.
#[test]
fn the_sop_names_every_non_authorable_kind() {
    let sop = profile_sop();
    for kind in ["MdmCommand", "MdmCheckin", "SharedStructure"] {
        assert!(
            sop.contains(kind),
            "`{kind}` is refused by not_authorable_reason but the SOP never names it"
        );
    }
}

/// End-to-end: a shared structure is actually refused, and the refusal says
/// what the SOP says it says.
#[test]
fn a_shared_structure_is_refused_by_the_cli() {
    let registry = contour_form::SchemaRegistry::embedded().expect("embedded registry");
    let mut shared: Vec<&str> = registry
        .all()
        .filter(|m| m.kind == Some(mdm_schema::PayloadKind::SharedStructure))
        .map(|m| m.payload_type.as_str())
        .collect();
    shared.sort_unstable();
    assert!(
        !shared.is_empty(),
        "the dataset carries no SharedStructure rows — the dataset stopped marking \
         Apple's other/ directory, or this build predates it"
    );

    let subject = shared[0];
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args(["profile", "form", "spec", subject])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "`form spec {subject}` succeeded — a shared structure is not authorable"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("shared structure"),
        "the refusal for {subject} does not explain itself: {err}"
    );
}

/// Every `verdict` the spec can carry is documented, and nothing else is.
///
/// `form spec` and `form emit` speak different vocabularies — verdicts on one,
/// rule names on the other — and an agent that expects one to produce the
/// other's words waits for a string that never comes. The SOP states both;
/// this keeps the verdict half complete.
///
/// The match is exhaustive on purpose: adding a `Verdict` variant fails to
/// compile here until the SOP documents it.
#[test]
fn the_sop_documents_every_verdict() {
    use contour_form::formspec::Verdict;

    fn wire_name(v: Verdict) -> &'static str {
        match v {
            Verdict::Ok => "ok",
            Verdict::RequiresOs => "requires-os",
            Verdict::RequiresSupervision => "requires-supervision",
            Verdict::Deprecated => "deprecated",
            Verdict::Removed => "removed",
            Verdict::Unavailable => "unavailable",
            Verdict::Unknown => "unknown",
        }
    }

    let all = [
        Verdict::Ok,
        Verdict::RequiresOs,
        Verdict::RequiresSupervision,
        Verdict::Deprecated,
        Verdict::Removed,
        Verdict::Unavailable,
        Verdict::Unknown,
    ];
    let sop = profile_sop();
    for v in all {
        let name = wire_name(v);
        // Serde is the contract an agent actually parses; assert the name the
        // SOP prints is the name that lands in --json.
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            format!("\"{name}\""),
            "verdict wire name changed"
        );
        assert!(
            sop.contains(&format!("`{name}`")),
            "`form spec` can report verdict `{name}` but the profile SOP never documents it"
        );
    }
}

/// `contour census` and the sentence in the skill file must be one census.
///
/// The command exists because an installed `SKILL.md` freezes its figures at
/// install time: upgrade the binary and that sentence describes the previous
/// dataset with nothing to say so. Two surfaces means two chances to disagree,
/// so every number the command reports has to appear in the rendered line.
#[test]
fn the_census_command_and_the_skill_line_agree() {
    let json = Command::cargo_bin("contour")
        .unwrap()
        .args(["--json", "census"])
        .output()
        .unwrap();
    assert!(json.status.success(), "`contour --json census` failed");
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).expect("census emits JSON");

    let human = Command::cargo_bin("contour")
        .unwrap()
        .arg("census")
        .output()
        .unwrap();
    assert!(human.status.success(), "`contour census` failed");
    let human = String::from_utf8_lossy(&human.stdout);

    let obj = v.as_object().expect("census JSON is an object");
    assert!(!obj.is_empty(), "census JSON carries no figures");
    for (field, value) in obj {
        // The census reports two kinds of thing, and both have to survive
        // the trip to the human rendering. Counts are figures. `beta_dataset`
        // is a state — whether a pre-release seed dataset is compiled in —
        // and it is in the census precisely because for months the honest
        // answer was "nothing" while `--channel beta` advertised seed-only
        // keys. Exempting it from this check would put it back in the gap it
        // was added to close.
        if let Some(carried) = value.as_bool() {
            let expect = if carried { "carried" } else { "not carried" };
            assert!(
                human.contains(expect),
                "`contour --json census` reports {field}={carried} but the human report \
                 does not say so:\n{human}"
            );
            continue;
        }
        let n = value
            .as_u64()
            .unwrap_or_else(|| panic!("{field} is neither a count nor a state: {value}"));
        assert!(n > 0, "{field} counted 0 — the table did not load");
        // Both renderings group thousands the same way.
        let grouped = {
            let s = n.to_string();
            let mut out = String::new();
            for (i, c) in s.chars().enumerate() {
                if i > 0 && (s.len() - i) % 3 == 0 {
                    out.push(',');
                }
                out.push(c);
            }
            out
        };
        assert!(
            human.contains(&grouped),
            "`contour census` JSON reports {field}={grouped} but the human report does not \
             show it:\n{human}"
        );
    }
}
