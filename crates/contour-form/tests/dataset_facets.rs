//! posture's key facets reach forms, search, validation and emit.
//!
//! Against the embedded dataset (posture v2026.11.17-2 or later).

use contour_form::{EmitOptions, FormNode, SchemaRegistry, Target, emit, facets_json, form, validate};

fn reg() -> SchemaRegistry {
    SchemaRegistry::embedded().unwrap()
}

fn node<'a>(nodes: &'a [FormNode], path: &str) -> &'a FormNode {
    nodes
        .iter()
        .find(|n| n.path == path)
        .unwrap_or_else(|| panic!("no node {path}"))
}

/// An integer key's options are numbers with labels, and the first option
/// validates. FormSpec used to offer "0" and then refuse it.
#[test]
fn integer_options_are_typed_and_labelled() {
    let r = reg();
    let spec = form(&r, "corp.sap.privileges", &Target::default()).unwrap();
    let fallback = node(&spec.nodes, "BiometricsFallbackType");
    let options = fallback.options.as_ref().unwrap();
    assert_eq!(options[0], serde_json::json!(0));
    assert_eq!(fallback.option_titles.as_ref().map(Vec::len), Some(options.len()));
    let values = serde_json::json!({ "BiometricsFallbackType": options[0] });
    let errors: Vec<_> = validate(&r, "corp.sap.privileges", &values)
        .into_iter()
        .filter(|d| d.path == "BiometricsFallbackType")
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
}

/// Examples come with their source and never become options.
#[test]
fn examples_are_offered_not_enforced() {
    let r = reg();
    let spec = form(&r, "com.apple.screensaver", &Target::default()).unwrap();
    let module = node(&spec.nodes, "moduleName");
    let examples = module.examples.as_ref().unwrap();
    assert!(examples.iter().any(|e| e.value == "Message" && e.source.starts_with("annotation:")));
    assert!(module.options.is_none());
}

/// A keyword finds a key its own text does not name.
#[test]
fn keywords_rank_a_key_by_the_operators_word() {
    let r = reg();
    let top: Vec<String> = r
        .rank_fields("require Touch ID to become admin")
        .into_iter()
        .take(3)
        .map(|h| format!("{} {}", h.manifest.payload_type, h.field.path))
        .collect();
    assert!(
        top.iter().any(|t| t == "corp.sap.privileges RequireBiometricAuthentication"),
        "{top:?}"
    );
}

/// The schema's sensitive flag reaches the field and the search facets.
#[test]
fn the_schema_marks_credentials() {
    let r = reg();
    let santa = r.get("com.northpolesec.santa").unwrap();
    let password = santa
        .fields
        .values()
        .find(|f| f.path == "ClientAuthCertificatePassword")
        .unwrap();
    assert!(password.flags.sensitive);
    assert_eq!(facets_json(password)["sensitive"], serde_json::json!(true));
}

/// A key that needs a newer app says so in the emitted requirements.
#[test]
fn requirements_name_the_app_version_a_key_needs() {
    let r = reg();
    let opts = EmitOptions {
        org: "com.acme".into(),
        ..Default::default()
    };
    let docs = emit(&r, "com.anthropic.claudecode", &serde_json::json!({ "verbose": true }), &opts).unwrap();
    let req = &docs[0].requirements;
    assert_eq!(req.app_versions.get("verbose").map(String::as_str), Some("2.1.119"), "{req:?}");
}

/// A Windows node the device only reports is not offered and not accepted.
#[test]
fn windows_read_only_nodes_are_refused() {
    let r = SchemaRegistry::embedded_windows().unwrap();
    let bitlocker = r.get("BitLocker").unwrap();
    let status = bitlocker
        .fields
        .values()
        .find(|f| f.path.starts_with("Status") && f.flags.read_only)
        .expect("a read-only BitLocker Status node");
    assert!(
        r.rank_fields("bitlocker device encryption status")
            .iter()
            .all(|h| !h.field.flags.read_only),
        "search offers a read-only node"
    );
    let outcome = contour_form::emit_settings(
        &r,
        &[contour_form::Setting {
            type_id: "BitLocker".into(),
            path: status.path.clone(),
            value: serde_json::json!(1),
        }],
        &EmitOptions {
            org: "com.acme".into(),
            ..Default::default()
        },
    );
    assert!(outcome.documents.is_empty(), "a read-only node was written");
    assert!(outcome.refused.iter().any(|r| r.rule == "read-only"), "{:?}", outcome.refused);
}
