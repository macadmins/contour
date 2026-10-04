//! Santa is `com.northpolesec.santa`, everywhere, with no exceptions.
//!
//! Santa's daemon names its own preference domain — `kMobileConfigDomain` in
//! `SNTConfigurator.mm` — and it is North Pole Security's. The Google domain
//! is the pre-fork one, and a Google-signed Santa is not supported.
//!
//! This exists because the old domain kept being *nearly* right. contour's
//! mobileconfig reader accepted it silently: the rules parsed, output looked
//! fine, and nothing said the profile targeted a binary nobody ships. That is
//! the shape of defect worth a test rather than a comment — it does not fail,
//! it just quietly produces something wrong.
//!
//! So the rule is enforced in three places at once: contour must refuse the
//! domain, the SOP must say so, and no shipped recipe may carry it.

use assert_cmd::Command;

const SANTA: &str = "com.northpolesec.santa";
const GOOGLE_SANTA: &str = "com.google.santa";

#[test]
fn the_santa_sop_states_the_one_domain_rule() {
    let out = Command::cargo_bin("contour")
        .unwrap()
        .args(["help-agents", "--sop", "santa"])
        .output()
        .unwrap();
    assert!(out.status.success(), "help-agents --sop santa failed");
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(
        text.contains(SANTA),
        "the Santa SOP never names the domain Santa actually uses"
    );
    assert!(
        text.contains("not supported"),
        "the Santa SOP does not say a Google-signed Santa is unsupported"
    );
    // The old domain may be NAMED — the rule has to say which domain is
    // refused — but only alongside the statement that it is not supported.
    if text.contains(GOOGLE_SANTA) {
        let rule = text
            .split("## Rule: Santa is")
            .nth(1)
            .expect("the old domain appears outside the rule section");
        assert!(
            rule.contains(GOOGLE_SANTA),
            "{GOOGLE_SANTA} is mentioned somewhere other than the rule that forbids it"
        );
    }
}

/// The embedded schema describes one Santa, and it is not Google's.
#[test]
fn the_dataset_carries_no_google_signed_santa() {
    let registry = contour_form::SchemaRegistry::embedded().expect("embedded registry");
    assert!(
        registry.get(SANTA).is_some(),
        "the dataset has no schema for {SANTA}"
    );
    // The dataset drops the retired domain outright; there is no corpus left
    // to admit it even if someone wanted to.
    assert!(
        registry.get(GOOGLE_SANTA).is_none(),
        "{GOOGLE_SANTA} is in the dataset; the dataset must not carry it at all"
    );
}

/// Nothing contour ships may author the retired domain.
#[test]
fn no_shipped_recipe_names_the_retired_domain() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut offenders = Vec::new();
    for sub in ["crates/profile/recipes", "recipes", "crates/santa/recipes"] {
        let path = dir.join(sub);
        if !path.exists() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
            if text.contains(GOOGLE_SANTA) {
                offenders.push(entry.path().display().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these shipped files author {GOOGLE_SANTA}:\n  {}",
        offenders.join("\n  ")
    );
}
