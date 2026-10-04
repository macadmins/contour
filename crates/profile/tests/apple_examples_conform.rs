//! Apple's own example declarations must pass contour's validator.
//!
//! The dataset carries every example Apple publishes in its
//! device-management repository. They are the ground truth for payload
//! layout: if contour reports an error or an unknown field in one, contour
//! is wrong — its schema loader, its validator, or its reading of a key's
//! path — whichever it turns out to be. Presets, recipes and docs are
//! checked against the validator elsewhere; this checks the validator
//! against Apple.

use profile::cli::ddm::declaration_errors;
use profile::ddm::types::Declaration;
use profile::schema::SchemaRegistry;

#[test]
fn every_apple_example_declaration_validates_clean() {
    let registry = SchemaRegistry::embedded().expect("embedded registry");
    let examples =
        mdm_schema::examples::read(mdm_schema::embedded_examples()).expect("embedded examples");

    let mut checked = 0;
    let mut problems = Vec::new();
    for e in &examples {
        // Profile examples are plists; only declarations parse here.
        let Ok(decl) = serde_json::from_str::<Declaration>(&e.json) else {
            continue;
        };
        if registry.get(&decl.declaration_type).is_none() {
            problems.push(format!(
                "{} [{}]: declaration type not in the schema",
                decl.declaration_type, e.source_file
            ));
            continue;
        }
        checked += 1;
        let (errors, warnings) = declaration_errors(&decl, &registry);
        for finding in errors
            .iter()
            .chain(warnings.iter().filter(|w| w.starts_with("Unknown field")))
        {
            problems.push(format!(
                "{} [{}]: {finding}",
                decl.declaration_type, e.source_file
            ));
        }
    }

    // Not vacuous: the dataset carries ~90 declaration examples.
    assert!(
        checked >= 50,
        "only {checked} declaration examples checked — did the examples data move?"
    );
    assert!(
        problems.is_empty(),
        "{} finding(s) in Apple's own examples:\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}
