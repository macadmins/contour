//! Directory-level DDM declaration verifier.
//!
//! Where `compose` enforces the cross-reference DAG **at authoring time**
//! for a single bundle, `verify` checks an existing directory of
//! declarations after-the-fact. Useful for:
//! - hand-authored declaration sets
//! - mixed-provenance directories (some compose, some external)
//! - CI gates on PRs that touch `platforms/macos/declaration-profiles/`
//!
//! Two classes of check:
//!
//! 1. **Reference DAG** — every `*AssetReference` field on a configuration
//!    resolves to an asset declaration in the directory; every entry of
//!    every activation's `Payload.StandardConfigurations` resolves to a
//!    configuration declaration in the directory.
//!
//! 2. **Predicate ↔ subscription** — every `@status('key')` reference in
//!    every activation's `Payload.Predicate` is covered by some
//!    `com.apple.configuration.management.status-subscriptions`
//!    declaration's `Payload.StatusItems[*].Name` in the directory.
//!
//! This module is pure logic (`build_report`); the CLI handler in
//! `cli/ddm.rs` does the I/O of walking the dir, parsing files, and
//! emitting the report.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;

use crate::ddm::predicate::extract_predicate_keys;
use crate::ddm::types::{Declaration, DeclarationType};

/// Outcome of [`build_report`]. Pure data; the CLI handler converts to
/// JSON or human output.
#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    pub assets: Vec<DeclEntry>,
    pub configurations: Vec<ConfigurationEntry>,
    pub activations: Vec<ActivationEntry>,
    pub subscriptions: Vec<SubscriptionEntry>,
    pub errors: Vec<VerifyError>,
    pub warnings: Vec<VerifyWarning>,
}

#[derive(Debug, Clone)]
pub struct DeclEntry {
    pub identifier: String,
    pub r#type: String,
    pub file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ConfigurationEntry {
    pub identifier: String,
    pub r#type: String,
    pub file: PathBuf,
    /// Asset references found in the configuration's payload. Keyed by
    /// the field name that carries them; values are the referenced
    /// asset identifiers.
    pub asset_refs: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct ActivationEntry {
    pub identifier: String,
    pub r#type: String,
    pub file: PathBuf,
    pub configuration_refs: Vec<String>,
    pub predicate: Option<String>,
    /// Status keys the predicate references via @status().
    pub predicate_status_keys: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SubscriptionEntry {
    pub identifier: String,
    pub r#type: String,
    pub file: PathBuf,
    pub status_items: Vec<String>,
}

/// Hard failures — verify exits 1 if any are present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Configuration's `*AssetReference` field points at an identifier
    /// no asset declaration in the directory carries.
    DanglingAssetReference {
        configuration_id: String,
        field: String,
        target: String,
        file: PathBuf,
    },
    /// Activation's `StandardConfigurations` references an identifier
    /// no configuration declaration in the directory carries.
    DanglingConfigurationReference {
        activation_id: String,
        target: String,
        file: PathBuf,
    },
    /// Activation predicate references a `@status('key')` not in any
    /// status-subscriptions declaration.
    UnsubscribedStatusKey {
        activation_id: String,
        key: String,
        file: PathBuf,
    },
    /// Declaration carries a `ServerToken` field — that's a server-managed
    /// field that authors must not populate (Apple sets it at push time).
    ServerTokenAuthored { identifier: String, file: PathBuf },
}

/// Soft signals — verify exits 0 unless `--strict` upgrades these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyWarning {
    /// Asset declared but no configuration in the directory references it.
    OrphanAsset { identifier: String, file: PathBuf },
    /// Configuration declared but no activation in the directory
    /// references it. Apple-side this is valid (a configuration without
    /// activation is still "applied immediately"); we surface it so the
    /// human can confirm intent.
    OrphanConfiguration { identifier: String, file: PathBuf },
    /// Status-subscriptions declares a key that no activation predicate
    /// references. Probably dead-code overhead.
    UnusedSubscriptionKey { key: String, file: PathBuf },
}

/// Build the report from a parsed set of declarations.
///
/// Pure: no I/O, no panics. The CLI handler is responsible for walking
/// the directory and parsing files into `(PathBuf, Declaration)` pairs.
pub fn build_report(declarations: &[(PathBuf, Declaration)]) -> VerifyReport {
    let mut report = VerifyReport::default();

    // First pass: classify declarations.
    for (file, decl) in declarations {
        if decl.server_token.is_some() {
            report.errors.push(VerifyError::ServerTokenAuthored {
                identifier: decl.identifier.clone(),
                file: file.clone(),
            });
        }

        match DeclarationType::from_type_string(&decl.declaration_type) {
            Some(DeclarationType::Asset) => {
                report.assets.push(DeclEntry {
                    identifier: decl.identifier.clone(),
                    r#type: decl.declaration_type.clone(),
                    file: file.clone(),
                });
            }
            Some(DeclarationType::Configuration) => {
                // status-subscriptions is technically a configuration in
                // Apple's category taxonomy (`com.apple.configuration.management.status-subscriptions`);
                // route it to its own bucket so reference checks only
                // look at "real" configurations.
                if decl.declaration_type
                    == "com.apple.configuration.management.status-subscriptions"
                {
                    report.subscriptions.push(SubscriptionEntry {
                        identifier: decl.identifier.clone(),
                        r#type: decl.declaration_type.clone(),
                        file: file.clone(),
                        status_items: extract_status_items(&decl.payload.0),
                    });
                } else {
                    report.configurations.push(ConfigurationEntry {
                        identifier: decl.identifier.clone(),
                        r#type: decl.declaration_type.clone(),
                        file: file.clone(),
                        asset_refs: extract_asset_refs(&decl.payload.0),
                    });
                }
            }
            Some(DeclarationType::Activation) => {
                let predicate = decl
                    .payload
                    .get("Predicate")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let predicate_status_keys = predicate
                    .as_deref()
                    .map(|p| extract_predicate_keys(p).status)
                    .unwrap_or_default();
                report.activations.push(ActivationEntry {
                    identifier: decl.identifier.clone(),
                    r#type: decl.declaration_type.clone(),
                    file: file.clone(),
                    configuration_refs: extract_string_array(
                        &decl.payload.0,
                        "StandardConfigurations",
                    ),
                    predicate,
                    predicate_status_keys,
                });
            }
            Some(DeclarationType::Management) | None => {
                // Management declarations and any uncategorized ones are
                // tracked but not cross-checked here. A future pass can
                // add management-specific rules.
            }
        }
    }

    // Second pass: cross-reference checks.
    let asset_ids: BTreeSet<&str> = report
        .assets
        .iter()
        .map(|a| a.identifier.as_str())
        .collect();
    let config_ids: BTreeSet<&str> = report
        .configurations
        .iter()
        .map(|c| c.identifier.as_str())
        .collect();
    let subscribed_keys: BTreeSet<&str> = report
        .subscriptions
        .iter()
        .flat_map(|s| s.status_items.iter().map(String::as_str))
        .collect();

    // Configuration → asset reference checks.
    let mut referenced_assets: BTreeSet<&str> = BTreeSet::new();
    for cfg in &report.configurations {
        for (field, target) in &cfg.asset_refs {
            if !asset_ids.contains(target.as_str()) {
                report.errors.push(VerifyError::DanglingAssetReference {
                    configuration_id: cfg.identifier.clone(),
                    field: field.clone(),
                    target: target.clone(),
                    file: cfg.file.clone(),
                });
            } else {
                referenced_assets.insert(target.as_str());
            }
        }
    }

    // Activation → configuration reference checks + predicate cross-check.
    let mut referenced_configs: BTreeSet<&str> = BTreeSet::new();
    let mut referenced_status_keys: BTreeSet<&str> = BTreeSet::new();
    for act in &report.activations {
        for target in &act.configuration_refs {
            if !config_ids.contains(target.as_str()) {
                report
                    .errors
                    .push(VerifyError::DanglingConfigurationReference {
                        activation_id: act.identifier.clone(),
                        target: target.clone(),
                        file: act.file.clone(),
                    });
            } else {
                referenced_configs.insert(target.as_str());
            }
        }
        for key in &act.predicate_status_keys {
            referenced_status_keys.insert(key.as_str());
            if !subscribed_keys.contains(key.as_str()) {
                report.errors.push(VerifyError::UnsubscribedStatusKey {
                    activation_id: act.identifier.clone(),
                    key: key.clone(),
                    file: act.file.clone(),
                });
            }
        }
    }

    // Orphan warnings.
    for asset in &report.assets {
        if !referenced_assets.contains(asset.identifier.as_str()) {
            report.warnings.push(VerifyWarning::OrphanAsset {
                identifier: asset.identifier.clone(),
                file: asset.file.clone(),
            });
        }
    }
    for cfg in &report.configurations {
        if !referenced_configs.contains(cfg.identifier.as_str()) {
            report.warnings.push(VerifyWarning::OrphanConfiguration {
                identifier: cfg.identifier.clone(),
                file: cfg.file.clone(),
            });
        }
    }
    for sub in &report.subscriptions {
        for key in &sub.status_items {
            if !referenced_status_keys.contains(key.as_str()) {
                report.warnings.push(VerifyWarning::UnusedSubscriptionKey {
                    key: key.clone(),
                    file: sub.file.clone(),
                });
            }
        }
    }

    report
}

/// Recursively walk a JSON object and collect every key whose name ends
/// with `AssetReference` paired with its string value.
///
/// Apple's Mail account schema has nested fields like
/// `IncomingServer.AuthenticationCredentialsAssetReference`; the embedded
/// CLI schema flattens those to dotted top-level keys, but profiles in
/// the wild may keep them nested. The recursive walk handles both.
fn extract_asset_refs(payload: &std::collections::HashMap<String, Value>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    walk_for_refs(payload, &mut out);
    out
}

fn walk_for_refs(map: &std::collections::HashMap<String, Value>, out: &mut Vec<(String, String)>) {
    for (key, value) in map {
        if key.ends_with("AssetReference")
            && let Some(s) = value.as_str()
            && !s.is_empty()
        {
            out.push((key.clone(), s.to_string()));
        }
        if let Some(child) = value.as_object() {
            // serde_json::Map is not the same as HashMap; convert.
            let nested: std::collections::HashMap<String, Value> =
                child.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            walk_for_refs(&nested, out);
        }
    }
}

fn extract_status_items(payload: &std::collections::HashMap<String, Value>) -> Vec<String> {
    payload
        .get("StatusItems")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    item.as_object()
                        .and_then(|o| o.get("Name"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn extract_string_array(
    payload: &std::collections::HashMap<String, Value>,
    key: &str,
) -> Vec<String> {
    payload
        .get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

impl VerifyReport {
    /// True if no errors are present (ignores warnings).
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }

    /// True under `--strict` semantics: no errors AND no warnings.
    pub fn is_clean_strict(&self) -> bool {
        self.errors.is_empty() && self.warnings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddm::types::DeclarationPayload;

    fn decl(t: &str, id: &str, payload: serde_json::Map<String, Value>) -> Declaration {
        Declaration {
            declaration_type: t.to_string(),
            identifier: id.to_string(),
            server_token: None,
            authentication: None,
            payload: DeclarationPayload(payload.into_iter().collect()),
        }
    }

    fn pb(pairs: &[(&str, Value)]) -> serde_json::Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn clean_report_for_empty_input() {
        let report = build_report(&[]);
        assert!(report.is_clean());
        assert!(report.errors.is_empty());
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn detects_dangling_asset_reference() {
        let cfg = decl(
            "com.apple.configuration.account.exchange",
            "com.acme.config.x",
            pb(&[(
                "AuthenticationCredentialsAssetReference",
                Value::String("com.acme.asset.does-not-exist".into()),
            )]),
        );
        let report = build_report(&[(PathBuf::from("config.json"), cfg)]);
        assert!(!report.is_clean());
        match &report.errors[0] {
            VerifyError::DanglingAssetReference { target, .. } => {
                assert_eq!(target, "com.acme.asset.does-not-exist");
            }
            other => panic!("expected DanglingAssetReference, got {other:?}"),
        }
    }

    #[test]
    fn detects_dangling_configuration_reference() {
        let act = decl(
            "com.apple.activation.simple",
            "com.acme.activation.x",
            pb(&[(
                "StandardConfigurations",
                Value::Array(vec![Value::String("com.acme.config.missing".into())]),
            )]),
        );
        let report = build_report(&[(PathBuf::from("activation.json"), act)]);
        assert_eq!(report.errors.len(), 1);
        match &report.errors[0] {
            VerifyError::DanglingConfigurationReference { target, .. } => {
                assert_eq!(target, "com.acme.config.missing");
            }
            other => panic!("expected DanglingConfigurationReference, got {other:?}"),
        }
    }

    #[test]
    fn detects_unsubscribed_status_key() {
        let act = decl(
            "com.apple.activation.simple",
            "com.acme.activation.x",
            pb(&[
                (
                    "StandardConfigurations",
                    Value::Array(vec![Value::String("com.acme.config.x".into())]),
                ),
                (
                    "Predicate",
                    Value::String("@status('passcode.is-compliant') == TRUE".into()),
                ),
            ]),
        );
        let cfg = decl(
            "com.apple.configuration.passcode.settings",
            "com.acme.config.x",
            pb(&[]),
        );
        let report = build_report(&[
            (PathBuf::from("activation.json"), act),
            (PathBuf::from("configuration.json"), cfg),
        ]);
        let unsubscribed: Vec<_> = report
            .errors
            .iter()
            .filter_map(|e| match e {
                VerifyError::UnsubscribedStatusKey { key, .. } => Some(key.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(unsubscribed, vec!["passcode.is-compliant"]);
    }

    #[test]
    fn subscription_covers_predicate_no_error() {
        let act = decl(
            "com.apple.activation.simple",
            "com.acme.activation.x",
            pb(&[
                (
                    "StandardConfigurations",
                    Value::Array(vec![Value::String("com.acme.config.x".into())]),
                ),
                (
                    "Predicate",
                    Value::String("@status('passcode.is-compliant') == TRUE".into()),
                ),
            ]),
        );
        let cfg = decl(
            "com.apple.configuration.passcode.settings",
            "com.acme.config.x",
            pb(&[]),
        );
        let subs = decl(
            "com.apple.configuration.management.status-subscriptions",
            "com.acme.subscriptions.x",
            pb(&[(
                "StatusItems",
                Value::Array(vec![Value::Object({
                    let mut m = serde_json::Map::new();
                    m.insert(
                        "Name".to_string(),
                        Value::String("passcode.is-compliant".into()),
                    );
                    m
                })]),
            )]),
        );
        let report = build_report(&[
            (PathBuf::from("activation.json"), act),
            (PathBuf::from("configuration.json"), cfg),
            (PathBuf::from("subscriptions.json"), subs),
        ]);
        assert!(report.is_clean(), "errors: {:?}", report.errors);
    }

    #[test]
    fn server_token_authored_is_an_error() {
        let mut d = decl(
            "com.apple.configuration.passcode.settings",
            "com.acme.config.x",
            pb(&[]),
        );
        d.server_token = Some("abc".to_string());
        let report = build_report(&[(PathBuf::from("config.json"), d)]);
        assert!(matches!(
            report.errors[0],
            VerifyError::ServerTokenAuthored { .. }
        ));
    }

    #[test]
    fn orphan_asset_warns_but_does_not_error() {
        let asset = decl(
            "com.apple.asset.credential.userpassword",
            "com.acme.asset.lonely",
            pb(&[]),
        );
        let report = build_report(&[(PathBuf::from("asset.json"), asset)]);
        assert!(report.is_clean());
        assert!(matches!(
            report.warnings[0],
            VerifyWarning::OrphanAsset { .. }
        ));
        assert!(!report.is_clean_strict());
    }

    #[test]
    fn nested_asset_ref_is_detected() {
        // Mail account schema has nested IncomingServer / OutgoingServer
        // dicts. Verify recurses into objects.
        let mut server = serde_json::Map::new();
        server.insert(
            "AuthenticationCredentialsAssetReference".to_string(),
            Value::String("com.acme.asset.mail-creds".into()),
        );
        let cfg = decl(
            "com.apple.configuration.account.mail",
            "com.acme.config.mail",
            pb(&[("IncomingServer", Value::Object(server))]),
        );
        let report = build_report(&[(PathBuf::from("config.json"), cfg)]);
        // No asset present → dangling.
        assert!(matches!(
            report.errors[0],
            VerifyError::DanglingAssetReference { .. }
        ));
    }
}
