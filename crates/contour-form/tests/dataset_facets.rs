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

/// A Kerberos SSO payload is held to the Kerberos file: Realm is required
/// there. An Okta-style payload is not, though both share the payload type.
#[test]
fn a_payload_is_held_to_the_variant_it_carries() {
    let r = reg();
    let kerberos = serde_json::json!({
        "ExtensionIdentifier": "com.apple.AppSSOKerberos.KerberosExtension",
        "TeamIdentifier": "apple",
        "Type": "Credential",
    });
    let diags = validate(&r, "com.apple.extensiblesso", &kerberos);
    assert!(
        diags.iter().any(|d| d.path == "Realm" && d.rule == "required-missing" && d.message.contains("kerberos")),
        "{diags:?}"
    );

    let okta = serde_json::json!({
        "ExtensionIdentifier": "com.okta.mobile.auth-service-extension",
        "TeamIdentifier": "B7F62B65BN",
        "Type": "Redirect",
        "URLs": ["https://acme.okta.com"],
    });
    let diags = validate(&r, "com.apple.extensiblesso", &okta);
    assert!(diags.iter().all(|d| d.path != "Realm"), "{diags:?}");
}

/// A deprecated restriction says where its setting went: the form node
/// carries the declaration and key, and the deprecation warning names them.
#[test]
fn a_deprecated_key_names_its_declaration_key() {
    let r = reg();
    let target = Target {
        platform: Some(contour_form::Platform::Ios),
        os_version: Some("27.0".into()),
    };
    let spec = form(&r, "com.apple.applicationaccess", &target).unwrap();
    let d = node(&spec.nodes, "blockedAppBundleIDs").ddm_equivalent.as_ref().unwrap();
    assert_eq!(d.declaration, "com.apple.configuration.app.settings");
    assert_eq!(d.key.as_deref(), Some("Allowed.DeniedApps"));

    let values = serde_json::json!({ "blockedAppBundleIDs": ["com.acme.game"] });
    let msg: Vec<String> = contour_form::validate_target(&r, "com.apple.applicationaccess", &values, &target)
        .into_iter()
        .filter(|d| d.path == "blockedAppBundleIDs")
        .map(|d| d.message)
        .collect();
    assert!(
        msg.iter().any(|m| m.contains("deprecated") && m.contains("`Allowed.DeniedApps`")),
        "{msg:?}"
    );
}

/// Software update is DDM only from 27.0: the removed payload names its
/// declaration, its keys the key there, and validation says so.
#[test]
fn software_update_points_to_declarative_management() {
    let r = reg();
    let target = Target {
        platform: Some(contour_form::Platform::MacOS),
        os_version: Some("27.0".into()),
    };
    let spec = form(&r, "com.apple.SoftwareUpdate", &target).unwrap();
    let d = spec.ddm_equivalent.as_ref().expect("payload names its declaration");
    assert_eq!(d.declaration, "com.apple.configuration.softwareupdate.settings");
    let key = node(&spec.nodes, "AutomaticDownload").ddm_equivalent.as_ref().unwrap();
    assert_eq!(key.key.as_deref(), Some("AutomaticActions.Download"));

    let values = serde_json::json!({ "AutomaticDownload": false });
    let msg: Vec<String> = contour_form::validate_target(&r, "com.apple.SoftwareUpdate", &values, &target)
        .into_iter()
        .filter(|d| d.rule == "payload-removed-on-target")
        .map(|d| d.message)
        .collect();
    assert!(
        msg.iter().any(|m| m.contains("com.apple.configuration.softwareupdate.settings")),
        "{msg:?}"
    );
}

/// A renamed key names its replacement in the same payload.
#[test]
fn a_renamed_key_names_its_replacement() {
    let r = reg();
    let spec = form(&r, "com.apple.familycontrols.contentfilter", &Target::default()).unwrap();
    assert_eq!(
        node(&spec.nodes, "whitelistEnabled").replaced_by.as_deref(),
        Some("allowListEnabled")
    );
}

/// Supplemental domains come from the dataset alone: Terminal is there, and
/// Accessibility is posture's (the mSCP key), not a copy kept in code.
#[test]
fn supplemental_domains_come_from_the_dataset() {
    let r = reg();
    let terminal = form(&r, "com.apple.Terminal", &Target::default()).unwrap();
    node(&terminal.nodes, "SecureKeyboardEntry");
    let a11y = form(&r, "com.apple.Accessibility", &Target::default()).unwrap();
    node(&a11y.nodes, "AXSAudioDonationSiriImprovementEnabled");
}
