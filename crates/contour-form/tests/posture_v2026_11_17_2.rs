//! What posture v2026.11.17-2 added, read the way contour reads it.
//!
//! One test per addition, against the embedded dataset, so a later dataset
//! that drops one fails here by name.

use contour_form::{FieldDefinition, FieldType, SchemaRegistry, validate};

fn reg() -> SchemaRegistry {
    SchemaRegistry::embedded().unwrap()
}

fn field<'a>(r: &'a SchemaRegistry, pt: &str, path: &str) -> &'a FieldDefinition {
    r.get(pt)
        .unwrap_or_else(|| panic!("no payload type {pt}"))
        .fields
        .values()
        .find(|f| f.path == path)
        .unwrap_or_else(|| panic!("{pt} has no {path}"))
}

/// App Schema arrays have one element child, so Support App rows validate.
#[test]
fn support_app_rows_are_dictionaries() {
    let r = reg();
    let rows = field(&r, "nl.root3.support", "Rows");
    assert_eq!(rows.field_type, FieldType::Array);
    assert_eq!(field(&r, "nl.root3.support", "Rows.RowsItem").field_type, FieldType::Dictionary);
    let values = serde_json::json!({ "Rows": [{ "Items": [{ "Type": "ComputerName" }] }] });
    let diags = validate(&r, "nl.root3.support", &values);
    assert!(diags.iter().all(|d| !d.path.starts_with("Rows")), "{diags:?}");
}

/// Claude Code is an ordinary, authorable payload type, with unions as Any.
#[test]
fn claude_code_has_a_schema() {
    let r = reg();
    let m = r.get("com.anthropic.claudecode").expect("com.anthropic.claudecode");
    assert!(m.is_authorable());
    assert!(m.fields.len() > 500, "{}", m.fields.len());
    assert_eq!(field(&r, "com.anthropic.claudecode", "forceLoginOrgUUID").field_type, FieldType::Any);
    let env_key = field(&r, "com.anthropic.claudecode", "env.ANTHROPIC_API_KEY");
    assert!(env_key.flags.sensitive);
}

/// The corrections: moduleName optional, mount-controls alert accepted.
#[test]
fn corrections_reach_contour() {
    let r = reg();
    assert!(!field(&r, "com.apple.screensaver", "moduleName").flags.required);
    assert!(
        field(&r, "com.apple.systemuiserver", "mount-controls.cd.ActionStringItem")
            .allowed_values
            .iter()
            .any(|v| v == "alert")
    );
}

/// Setup Assistant skip names: Apple's list, the unversioned keys kept, only
/// names for the payload's platforms.
#[test]
fn skip_setup_items_takes_apples_names() {
    let r = reg();
    let names = &field(&r, "com.apple.SetupAssistant.managed", "SkipSetupItems.SkipSetupItems").allowed_values;
    for n in ["AppleID", "Diagnostics", "TOS", "Siri"] {
        assert!(names.iter().any(|v| v == n), "{n} missing from {names:?}");
    }
    assert!(names.iter().all(|v| v != "TapToSetup"), "a tvOS-only name is offered");
}

/// The supplemental domains mSCP deploys are payload types.
#[test]
fn mscp_deployed_domains_are_present() {
    let r = reg();
    field(&r, "com.apple.Safari", "AutoOpenSafeDownloads");
    field(&r, "com.apple.MobileSMS", "messageSummarizationEnabled");
    assert!(r.get("com.apple.ironwood.support").is_none_or(|m| m.fields.values().all(|f| f.path != "allowSiri3489")));
}

/// Privileges remote logging: ServerType names its values; ServerAddress
/// takes a webhook URL as well as a host.
#[test]
fn privileges_remote_logging_takes_both_server_types() {
    let r = reg();
    let server_type = field(&r, "corp.sap.privileges", "RemoteLogging.ServerType");
    assert_eq!(server_type.allowed_values, ["syslog", "webhook"]);
    assert!(!server_type.description.is_empty());
    let values = serde_json::json!({ "RemoteLogging": {
        "ServerType": "webhook",
        "ServerAddress": "https://hooks.acme.com/privileges",
    }});
    let diags = validate(&r, "corp.sap.privileges", &values);
    assert!(diags.iter().all(|d| d.path != "RemoteLogging.ServerAddress"), "{diags:?}");
}

/// Santa, Support App and Firefox keys have titles; Firefox's required
/// AutoLaunchProtocolsFromOrigins fields are described.
#[test]
fn app_schema_keys_have_titles() {
    let r = reg();
    for pt in ["com.northpolesec.santa", "nl.root3.support", "org.mozilla.firefox"] {
        let untitled: Vec<_> = r
            .get(pt)
            .unwrap()
            .fields
            .values()
            .filter(|f| f.depth == 0 && f.title.is_empty())
            .map(|f| f.path.clone())
            .collect();
        assert!(untitled.is_empty(), "{pt}: {untitled:?}");
    }
    let protocol = field(
        &r,
        "org.mozilla.firefox",
        "AutoLaunchProtocolsFromOrigins.AutoLaunchProtocolsFromOriginsItem.protocol",
    );
    assert!(protocol.description.contains("zoommtg"), "{}", protocol.description);
}

/// Key examples reach hundreds of keys, from all three sources.
#[test]
fn examples_cover_many_keys_from_every_source() {
    let r = reg();
    let mut keys = 0;
    let mut sources = std::collections::BTreeSet::new();
    for m in r.all() {
        for f in m.fields.values() {
            if !f.facets.examples.is_empty() {
                keys += 1;
            }
            for e in &f.facets.examples {
                sources.insert(e.source.split(':').next().unwrap_or_default().to_string());
            }
        }
    }
    assert!(keys > 500, "{keys}");
    assert_eq!(sources.into_iter().collect::<Vec<_>>(), ["annotation", "app-schema", "apple"]);
}

/// mSCP: FileVault2 Enable is the word Apple's key takes; iNDIGO has
/// metadata with a preamble.
#[test]
fn mscp_data_is_typed_and_described() {
    let payloads = mscp_schema::rule_payloads::read(mscp_schema::embedded_rule_payloads()).unwrap();
    let filevault: Vec<_> = payloads
        .iter()
        .filter(|p| p.rule_id == "os_setup_assistant_filevault_enforce")
        .filter_map(|p| p.mobileconfig_info.as_deref())
        .collect();
    assert!(!filevault.is_empty());
    assert!(filevault.iter().all(|i| !i.contains("\"Enable\":true")), "{filevault:?}");
    let meta = mscp_schema::baseline_meta::read(mscp_schema::embedded_baseline_meta()).unwrap();
    for name in ["indigo_base", "indigo_high"] {
        let m = meta.iter().find(|m| m.baseline == name).unwrap();
        assert!(m.preamble.as_deref().is_some_and(|p| p.contains("BSI")), "{name}: {m:?}");
    }
}

/// Windows: text is clean, and nodes a profile cannot set are marked.
#[test]
fn windows_text_is_clean_and_read_only_nodes_are_marked() {
    let r = SchemaRegistry::embedded_windows().unwrap();
    let mut read_only = 0;
    for m in r.all() {
        for f in m.fields.values() {
            assert!(!f.description.contains('\u{c2}'), "{} {}: {}", m.payload_type, f.path, f.description);
            read_only += usize::from(f.flags.read_only);
        }
    }
    assert!(read_only > 100, "{read_only}");
}

/// The beta channel is the 27.3 seed: battery ship mode is in it.
#[test]
fn beta_carries_the_27_3_seed() {
    assert!(SchemaRegistry::beta_dataset_is_carried(), "the pinned dataset carries no beta set");
    let beta = SchemaRegistry::embedded_beta().unwrap();
    let battery = beta
        .get("com.apple.configuration.battery.settings")
        .expect("battery.settings in the 27.3 seed");
    assert!(battery.fields.values().any(|f| f.path == "ShipMode"));
    assert!(reg().get("com.apple.configuration.battery.settings").is_none(), "not in the release");
}
