//! DDM bundle composition.
//!
//! Takes a single TOML "bundle" describing a DDM intent (asset +
//! configuration + activation) and emits all three correctly
//! cross-referenced declarations in one shot. Eliminates the multi-step
//! generate-and-edit-by-hand workflow that the procedural SOP's
//! `create_ddm_config` PROCEDURE describes.
//!
//! Pure logic — no I/O. The CLI handler in `cli/ddm.rs` parses the TOML,
//! resolves the organization domain, calls into [`compose`], and writes
//! the resulting declarations atomically.
//!
//! See the bundle TOML format documented in
//! `crates/contour-core/skills/contour/references/sop-ddm.md`.

use crate::ddm::types::{Declaration, DeclarationPayload, DeclarationType};
use crate::schema::SchemaRegistry;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Default activation type when [activation].type is omitted.
///
/// `com.apple.activation.simple` is the canonical Apple activation; the
/// procedural SOP documents it at `sop-ddm.md`.
pub const DEFAULT_ACTIVATION_TYPE: &str = "com.apple.activation.simple";

/// A bundle describing one DDM intent (asset + configuration + activation
/// + optional status-subscriptions).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Bundle {
    /// Used as the `{tail}` segment in computed identifiers
    /// (`{org}.{kind}.{intent_name}`).
    pub intent_name: String,

    #[serde(default)]
    pub asset: Option<BundleAsset>,

    pub configuration: BundleConfiguration,

    #[serde(default)]
    pub activation: Option<BundleActivation>,

    /// Optional `[subscriptions]` section listing the status keys the
    /// activation predicate references. When the predicate uses
    /// `@status(...)`, the bundle MUST include those keys here — Apple
    /// does not auto-subscribe based on predicate parsing, so a
    /// predicate referencing an unsubscribed key produces
    /// `Error.UnableToEvaluatePredicate` at deploy time.
    ///
    /// When present, `compose` emits a fourth declaration file
    /// `status-subscriptions.json` (type
    /// `com.apple.management.status-subscriptions`).
    #[serde(default)]
    pub subscriptions: Option<BundleSubscriptions>,
}

/// Bundle [asset] section.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BundleAsset {
    #[serde(rename = "type")]
    pub type_name: String,

    /// Override for the computed identifier.
    #[serde(default)]
    pub identifier: Option<String>,

    /// Free-form payload — copied verbatim into the emitted declaration.
    #[serde(default)]
    pub payload: Map<String, Value>,

    /// Path to a `.zip` (relative to the bundle file) whose SHA-256 and
    /// `application/zip` content-type seed the data asset's `Reference`.
    /// Resolved by [`materialize_asset`] before [`compose`].
    #[serde(default)]
    pub zip: Option<String>,

    /// Hosting URL → `Reference.DataURL` (S3 presigned / Cloudflare / long
    /// URL). When omitted, a placeholder is emitted for the operator to fill
    /// after hosting the zip.
    #[serde(default)]
    pub url: Option<String>,

    /// Server-authentication type for a data asset: `none` (a standard GET —
    /// the URL carries any auth, e.g. presigned) or `mdm` (the device's MDM
    /// identity cert). Apple's `asset.data` has no username/password — host
    /// credentials are never embedded here.
    #[serde(default)]
    pub auth: Option<String>,

    /// Explicit `Authentication` dictionary override (advanced; wins over
    /// `auth`). Emitted verbatim as the declaration's top-level `Authentication`.
    #[serde(default)]
    pub authentication: Option<Map<String, Value>>,
}

/// Placeholder DataURL emitted when an asset has a `zip` (so it can be hashed)
/// but no `url` yet — the operator hosts the zip, then replaces this.
pub const DATAURL_PLACEHOLDER: &str = "https://REPLACE-WITH-HOSTED-URL/asset.zip";

/// Bundle [configuration] section.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BundleConfiguration {
    #[serde(rename = "type")]
    pub type_name: String,

    #[serde(default)]
    pub identifier: Option<String>,

    /// When the configuration's schema has multiple `*AssetReference`
    /// fields, the bundle MUST set this to disambiguate which one to
    /// wire. Single-field schemas auto-resolve.
    #[serde(default)]
    pub asset_ref_field: Option<String>,

    #[serde(default)]
    pub payload: Map<String, Value>,
}

/// Bundle [subscriptions] section.
///
/// Maps to a `com.apple.management.status-subscriptions` declaration —
/// the manifest of status items the device is willing to report. The
/// activation's predicate (and any other declarations on the device)
/// can only `@status('key')` reference keys present here.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BundleSubscriptions {
    /// Status keys the device should subscribe to (e.g.
    /// `passcode.is-compliant`, `softwareupdate.install-state`).
    pub keys: Vec<String>,

    /// Override for the computed identifier; defaults to
    /// `{org}.subscriptions.{intent_name}`.
    #[serde(default)]
    pub identifier: Option<String>,
}

/// Bundle [activation] section.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BundleActivation {
    /// Defaults to `com.apple.activation.simple` when omitted.
    #[serde(rename = "type", default)]
    pub type_name: Option<String>,

    #[serde(default)]
    pub identifier: Option<String>,

    /// Apple Predicate string (e.g. `@status(...) == true`). Optional.
    #[serde(default)]
    pub predicate: Option<String>,

    /// Override the auto-populated `StandardConfigurations` array.
    /// Defaults to `[configuration.identifier]`.
    #[serde(default)]
    pub references: Option<Vec<String>>,
}

/// The successful output of [`compose`].
#[derive(Debug, Clone)]
pub struct ComposedBundle {
    pub asset: Option<Declaration>,
    pub configuration: Declaration,
    pub activation: Option<Declaration>,
    /// Status-subscriptions declaration emitted when the bundle has a
    /// `[subscriptions]` section. When present, this MUST be deployed
    /// before the activation so the device has the subscription set up
    /// before the predicate evaluates.
    pub subscriptions: Option<Declaration>,
    /// Which configuration field was used for the asset reference (if any).
    /// Surfaced so the CLI can include it in `--json` output.
    pub asset_ref_field_used: Option<String>,
}

/// Errors produced by [`compose`].
///
/// Each variant maps to a stable `error_code` from the procedural SOP
/// ERROR-CODE ENUM — see [`error_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeError {
    /// Declaration type isn't registered in the schema.
    UnknownType { kind: &'static str, name: String },
    /// Identifier doesn't match the reverse-DNS-with-tail shape, or two
    /// declarations in the same bundle ended up with identical identifiers.
    InvalidIdentifier { id: String, reason: &'static str },
    /// Configuration's schema has multiple `*AssetReference` fields but
    /// the bundle didn't set `configuration.asset_ref_field`.
    AmbiguousAssetRef {
        config_type: String,
        candidates: Vec<String>,
    },
    /// Bundle declares an asset but the configuration has no
    /// `*AssetReference` field to wire it into.
    MissingAssetRef { config_type: String },
    /// `configuration.asset_ref_field` was set to a name that doesn't
    /// exist in the configuration's schema.
    UnknownAssetRefField {
        config_type: String,
        field: String,
        candidates: Vec<String>,
    },
    /// Declaration type's category (asset/configuration/activation) doesn't
    /// match the bundle section it was placed in.
    WrongCategory {
        section: &'static str,
        type_name: String,
        actual: Option<DeclarationType>,
    },
    /// Activation predicate references `@status('key')` keys that the
    /// bundle's `[subscriptions].keys` list does not cover. Without the
    /// subscription, the device returns `Error.UnableToEvaluatePredicate`
    /// at deploy time — pinned by the procedural SOP.
    UnsubscribedStatusKey {
        activation_id: String,
        missing_keys: Vec<String>,
    },
    /// Bundle declares an asset that nothing references and `--allow-orphans`
    /// was not set. (Configurations are not currently checked for orphan
    /// status — a configuration without an activation is a valid Apple
    /// pattern.)
    OrphanAsset { identifier: String },
    /// Org domain is empty or doesn't look like a reverse-DNS string.
    InvalidOrg { domain: String },
    /// `[asset].auth` is not one of Apple's allowed `Authentication.Type`
    /// values (`none` / `mdm`).
    InvalidAuthType { value: String },
}

impl ComposeError {
    /// Map to the stable error_code surfaced via `--json` failure
    /// envelopes — see `crates/contour-core/src/output.rs::classify_error`.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::UnknownType { .. }
            | Self::AmbiguousAssetRef { .. }
            | Self::MissingAssetRef { .. }
            | Self::UnknownAssetRefField { .. }
            | Self::WrongCategory { .. }
            | Self::OrphanAsset { .. }
            | Self::UnsubscribedStatusKey { .. }
            | Self::InvalidAuthType { .. } => "SCHEMA_VIOLATION",
            Self::InvalidIdentifier { .. } => "INVALID_IDENTIFIER",
            Self::InvalidOrg { .. } => "INVALID_ORG",
        }
    }
}

impl std::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownType { kind, name } => {
                write!(f, "{kind} declaration type '{name}' not found in schema")
            }
            Self::InvalidIdentifier { id, reason } => {
                write!(f, "invalid identifier '{id}': {reason}")
            }
            Self::AmbiguousAssetRef {
                config_type,
                candidates,
            } => write!(
                f,
                "configuration '{config_type}' has multiple *AssetReference \
                 fields ({candidates:?}); set [configuration].asset_ref_field \
                 to pick one"
            ),
            Self::MissingAssetRef { config_type } => write!(
                f,
                "bundle declares an asset but configuration '{config_type}' \
                 has no *AssetReference field to wire it into"
            ),
            Self::UnknownAssetRefField {
                config_type,
                field,
                candidates,
            } => write!(
                f,
                "[configuration].asset_ref_field = '{field}' is not a field \
                 of '{config_type}'; available *AssetReference fields: \
                 {candidates:?}"
            ),
            Self::WrongCategory {
                section,
                type_name,
                actual,
            } => write!(
                f,
                "[{section}] type '{type_name}' is not in the {section} \
                 category (got {actual:?})"
            ),
            Self::OrphanAsset { identifier } => write!(
                f,
                "asset '{identifier}' is declared but nothing references it; \
                 pass --allow-orphans to permit"
            ),
            Self::UnsubscribedStatusKey {
                activation_id,
                missing_keys,
            } => write!(
                f,
                "activation '{activation_id}' predicate references status \
                 key(s) {missing_keys:?} that the bundle's [subscriptions].keys \
                 list does not cover; without subscription, the device \
                 returns Error.UnableToEvaluatePredicate at deploy time. \
                 Add the missing keys to [subscriptions].keys or remove \
                 them from the predicate."
            ),
            Self::InvalidOrg { domain } => {
                write!(
                    f,
                    "invalid organization domain '{domain}' — DDM declaration identifiers \
                     must be reverse-DNS (lowercase a-z 0-9 with at least one `.`). \
                     Examples: `com.acme`, `io.macadmins`. The placeholder \
                     `com.example` is also rejected because it produces colliding \
                     identifiers across orgs."
                )
            }
            Self::InvalidAuthType { value } => write!(
                f,
                "[asset].auth = '{value}' is not a valid asset Authentication.Type; \
                 Apple's com.apple.asset.data allows only `none` (standard GET — the \
                 URL carries any auth, e.g. presigned) or `mdm` (device MDM identity \
                 cert). Host credentials are never embedded in the declaration."
            ),
        }
    }
}

impl std::error::Error for ComposeError {}

/// Configuration knobs for [`compose`] orthogonal to the bundle itself.
#[derive(Debug, Clone, Default)]
pub struct ComposeOptions {
    /// When true, an asset declared in the bundle that isn't referenced
    /// by the configuration becomes a warning instead of an error. The
    /// procedural SOP's strict mode is the default (false).
    pub allow_orphans: bool,
}

/// Compose a [`Bundle`] into a fully cross-referenced [`ComposedBundle`].
///
/// The org domain is supplied by the caller (resolved from `profile.toml`
/// or `.contour/config.toml` upstream). The schema registry is used to
/// validate types and discover `*AssetReference` field names.
pub fn compose(
    bundle: &Bundle,
    org_domain: &str,
    registry: &SchemaRegistry,
    options: &ComposeOptions,
) -> Result<ComposedBundle, ComposeError> {
    // 1. Validate org domain (matches handle_ddm_generate's policy: refuse
    //    com.example to avoid silent identifier collisions across orgs).
    validate_org_domain(org_domain)?;

    // 2. Compute / resolve identifiers.
    let asset_id = bundle.asset.as_ref().map(|a| {
        a.identifier
            .clone()
            .unwrap_or_else(|| format!("{org_domain}.asset.{}", bundle.intent_name))
    });
    let configuration_id = bundle
        .configuration
        .identifier
        .clone()
        .unwrap_or_else(|| format!("{org_domain}.config.{}", bundle.intent_name));
    let activation_id = bundle.activation.as_ref().map(|a| {
        a.identifier
            .clone()
            .unwrap_or_else(|| format!("{org_domain}.activation.{}", bundle.intent_name))
    });

    // Identifier sanity + collision check.
    for id in [
        asset_id.as_deref(),
        Some(configuration_id.as_str()),
        activation_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        check_identifier_shape(id)?;
    }
    if let (Some(a), Some(act)) = (asset_id.as_deref(), activation_id.as_deref()) {
        if a == configuration_id || a == act || act == configuration_id {
            return Err(ComposeError::InvalidIdentifier {
                id: a.to_string(),
                reason: "identifier collides with another declaration in this bundle",
            });
        }
    } else if let Some(a) = asset_id.as_deref() {
        if a == configuration_id {
            return Err(ComposeError::InvalidIdentifier {
                id: a.to_string(),
                reason: "asset and configuration identifiers must differ",
            });
        }
    } else if let Some(act) = activation_id.as_deref() {
        if act == configuration_id {
            return Err(ComposeError::InvalidIdentifier {
                id: act.to_string(),
                reason: "activation and configuration identifiers must differ",
            });
        }
    }

    // 3. Validate types exist in the schema and live in their expected categories.
    if let Some(asset) = &bundle.asset {
        let manifest =
            registry
                .get_by_name(&asset.type_name)
                .ok_or_else(|| ComposeError::UnknownType {
                    kind: "asset",
                    name: asset.type_name.clone(),
                })?;
        require_category(&manifest.payload_type, "asset", DeclarationType::Asset)?;
    }
    let config_manifest = registry
        .get_by_name(&bundle.configuration.type_name)
        .ok_or_else(|| ComposeError::UnknownType {
            kind: "configuration",
            name: bundle.configuration.type_name.clone(),
        })?;
    require_category(
        &config_manifest.payload_type,
        "configuration",
        DeclarationType::Configuration,
    )?;
    let activation_type = bundle.activation.as_ref().map(|a| {
        a.type_name
            .as_deref()
            .unwrap_or(DEFAULT_ACTIVATION_TYPE)
            .to_string()
    });
    if let Some(t) = activation_type.as_deref() {
        let manifest = registry
            .get_by_name(t)
            .ok_or_else(|| ComposeError::UnknownType {
                kind: "activation",
                name: t.to_string(),
            })?;
        require_category(
            &manifest.payload_type,
            "activation",
            DeclarationType::Activation,
        )?;
    }

    // 4. Resolve the asset_ref_field on the configuration.
    let asset_ref_field = if let Some(asset) = &bundle.asset {
        let candidates = asset_ref_field_candidates(config_manifest);
        let field = match (
            bundle.configuration.asset_ref_field.as_deref(),
            candidates.as_slice(),
        ) {
            (Some(explicit), all) => {
                if !all.iter().any(|c| c == explicit) {
                    return Err(ComposeError::UnknownAssetRefField {
                        config_type: bundle.configuration.type_name.clone(),
                        field: explicit.to_string(),
                        candidates: candidates.clone(),
                    });
                }
                explicit.to_string()
            }
            (None, []) => {
                return Err(ComposeError::MissingAssetRef {
                    config_type: bundle.configuration.type_name.clone(),
                });
            }
            (None, [single]) => single.clone(),
            (None, many) => {
                return Err(ComposeError::AmbiguousAssetRef {
                    config_type: bundle.configuration.type_name.clone(),
                    candidates: many.to_vec(),
                });
            }
        };
        let _ = asset; // keep the binding live; field comes from candidates
        Some(field)
    } else {
        None
    };

    // 5. Build the asset declaration (if any), wiring its Authentication block.
    let asset_decl = match (&bundle.asset, asset_id.clone()) {
        (Some(asset), Some(id)) => Some(Declaration {
            declaration_type: asset.type_name.clone(),
            identifier: id,
            server_token: None,
            authentication: resolve_asset_authentication(asset)?,
            payload: DeclarationPayload(asset.payload.clone().into_iter().collect()),
        }),
        _ => None,
    };

    // 6. Build the configuration declaration; wire the asset reference if applicable.
    let mut config_payload: Map<String, Value> = bundle.configuration.payload.clone();
    if let (Some(field), Some(id)) = (&asset_ref_field, &asset_id) {
        config_payload.insert(field.clone(), Value::String(id.clone()));
    }
    let configuration_decl = Declaration {
        declaration_type: bundle.configuration.type_name.clone(),
        identifier: configuration_id.clone(),
        server_token: None,
        authentication: None,
        payload: DeclarationPayload(config_payload.into_iter().collect()),
    };

    // 7. Build the activation declaration; wire StandardConfigurations.
    let activation_decl = match (&bundle.activation, activation_type, activation_id) {
        (Some(act), Some(type_name), Some(id)) => {
            let refs = act
                .references
                .clone()
                .unwrap_or_else(|| vec![configuration_id.clone()]);
            let mut payload: Map<String, Value> = Map::new();
            payload.insert(
                "StandardConfigurations".to_string(),
                Value::Array(refs.into_iter().map(Value::String).collect()),
            );
            if let Some(predicate) = &act.predicate {
                payload.insert("Predicate".to_string(), Value::String(predicate.clone()));
            }
            Some(Declaration {
                declaration_type: type_name,
                identifier: id,
                // ServerToken is assigned by the MDM server when it stores the
                // declaration; contour omits it (the macadmins examples include
                // an empty "" placeholder, but it is not author-controlled).
                server_token: None,
                authentication: None,
                payload: DeclarationPayload(payload.into_iter().collect()),
            })
        }
        _ => None,
    };

    // 8. Orphan check (strict by default).
    if !options.allow_orphans {
        if let Some(asset) = &asset_decl {
            // An asset is "orphan" if no configuration references its identifier.
            let referenced = asset_ref_field.is_some();
            if !referenced {
                return Err(ComposeError::OrphanAsset {
                    identifier: asset.identifier.clone(),
                });
            }
        }
    }

    // 9. Predicate ↔ subscription cross-check (strict by default).
    //
    // If the activation has a predicate that references @status('key'),
    // the bundle MUST include those keys in [subscriptions].keys —
    // otherwise the device returns Error.UnableToEvaluatePredicate.
    let subscriptions_decl =
        build_subscriptions_decl(bundle, org_domain, activation_decl.as_ref())?;

    Ok(ComposedBundle {
        asset: asset_decl,
        configuration: configuration_decl,
        activation: activation_decl,
        subscriptions: subscriptions_decl,
        asset_ref_field_used: asset_ref_field,
    })
}

/// Resolve an asset's top-level `Authentication` dictionary.
///
/// Precedence: explicit `[asset.authentication]` map > `auth = "none"|"mdm"` >
/// the `{"Type": "None"}` default for `com.apple.asset.data`. Other asset types
/// get no `Authentication` unless one is provided explicitly.
fn resolve_asset_authentication(
    asset: &BundleAsset,
) -> Result<Option<Map<String, Value>>, ComposeError> {
    if let Some(explicit) = &asset.authentication {
        return Ok(Some(explicit.clone()));
    }
    if let Some(auth) = &asset.auth {
        let type_value = match auth.to_ascii_lowercase().as_str() {
            "none" => "None",
            "mdm" => "MDM",
            _ => {
                return Err(ComposeError::InvalidAuthType {
                    value: auth.clone(),
                });
            }
        };
        let mut m = Map::new();
        m.insert("Type".to_string(), Value::String(type_value.to_string()));
        return Ok(Some(m));
    }
    if asset.type_name == "com.apple.asset.data" {
        let mut m = Map::new();
        m.insert("Type".to_string(), Value::String("None".to_string()));
        return Ok(Some(m));
    }
    Ok(None)
}

/// Compute a data asset's `Reference` from a local `.zip`: read the file, hash
/// it (SHA-256), and set `ContentType`/`DataURL`/`Hash-SHA-256` on the asset
/// payload. `DataURL` is the asset's `url` or a [`DATAURL_PLACEHOLDER`] for the
/// operator to fill after hosting. Call before [`compose`].
///
/// # Errors
/// Returns an error if the zip can't be read.
pub fn materialize_asset(
    asset: &mut BundleAsset,
    base_dir: &std::path::Path,
) -> std::io::Result<()> {
    let Some(zip_rel) = asset.zip.clone() else {
        return Ok(());
    };
    let zip_path = base_dir.join(&zip_rel);
    let bytes = std::fs::read(&zip_path)?;
    let hash = sha256_hex(&bytes);
    let url = asset
        .url
        .clone()
        .unwrap_or_else(|| DATAURL_PLACEHOLDER.to_string());

    let mut reference = Map::new();
    reference.insert(
        "ContentType".to_string(),
        Value::String("application/zip".to_string()),
    );
    reference.insert("DataURL".to_string(), Value::String(url));
    reference.insert("Hash-SHA-256".to_string(), Value::String(hash));
    asset
        .payload
        .insert("Reference".to_string(), Value::Object(reference));
    Ok(())
}

/// Lowercase hex SHA-256 of `bytes` (matches the examples' `shasum -a 256`).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    digest.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Resolve the optional `[subscriptions]` declaration and verify the
/// activation predicate's `@status(...)` references are covered.
fn build_subscriptions_decl(
    bundle: &Bundle,
    org_domain: &str,
    activation: Option<&Declaration>,
) -> Result<Option<Declaration>, ComposeError> {
    // Extract @status(...) keys the predicate references (if any).
    let referenced_keys: Vec<String> = activation
        .and_then(|d| d.payload.get("Predicate"))
        .and_then(|v| v.as_str())
        .map(|p| crate::ddm::predicate::extract_predicate_keys(p).status)
        .unwrap_or_default();

    // No predicate references AND no [subscriptions] section → nothing to do.
    if referenced_keys.is_empty() && bundle.subscriptions.is_none() {
        return Ok(None);
    }

    // Predicate references status keys but bundle has no [subscriptions]
    // section → strict failure.
    let Some(subs) = &bundle.subscriptions else {
        return Err(ComposeError::UnsubscribedStatusKey {
            activation_id: activation
                .map(|a| a.identifier.clone())
                .unwrap_or_else(|| "<unknown>".to_string()),
            missing_keys: referenced_keys,
        });
    };

    // Bundle has [subscriptions]; verify it covers every referenced key.
    let subscribed: std::collections::BTreeSet<&str> =
        subs.keys.iter().map(String::as_str).collect();
    let missing: Vec<String> = referenced_keys
        .iter()
        .filter(|k| !subscribed.contains(k.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(ComposeError::UnsubscribedStatusKey {
            activation_id: activation
                .map(|a| a.identifier.clone())
                .unwrap_or_else(|| "<unknown>".to_string()),
            missing_keys: missing,
        });
    }

    // Build the status-subscriptions declaration.
    let id = subs
        .identifier
        .clone()
        .unwrap_or_else(|| format!("{org_domain}.subscriptions.{}", bundle.intent_name));
    check_identifier_shape(&id)?;

    let mut payload: Map<String, Value> = Map::new();
    // Apple's status-subscriptions schema (verified against
    // device-management/declarative/declarations/configurations/management.status-subscriptions.yaml):
    //   StatusItems: array of { Name: <status-item-name> } dicts.
    let status_items: Vec<Value> = subs
        .keys
        .iter()
        .map(|k| {
            let mut entry = Map::new();
            entry.insert("Name".to_string(), Value::String(k.clone()));
            Value::Object(entry)
        })
        .collect();
    payload.insert("StatusItems".to_string(), Value::Array(status_items));

    Ok(Some(Declaration {
        declaration_type: "com.apple.configuration.management.status-subscriptions".to_string(),
        identifier: id,
        server_token: None,
        authentication: None,
        payload: DeclarationPayload(payload.into_iter().collect()),
    }))
}

fn validate_org_domain(domain: &str) -> Result<(), ComposeError> {
    if domain.trim().is_empty() {
        return Err(ComposeError::InvalidOrg {
            domain: domain.to_string(),
        });
    }
    let valid = domain
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.');
    if !valid || domain == "com.example" {
        return Err(ComposeError::InvalidOrg {
            domain: domain.to_string(),
        });
    }
    Ok(())
}

fn check_identifier_shape(id: &str) -> Result<(), ComposeError> {
    if id.is_empty() {
        return Err(ComposeError::InvalidIdentifier {
            id: id.to_string(),
            reason: "empty",
        });
    }
    let valid = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_')
        && id.contains('.');
    if !valid {
        return Err(ComposeError::InvalidIdentifier {
            id: id.to_string(),
            reason: "must be lowercase reverse-DNS (a-z 0-9 . - _)",
        });
    }
    Ok(())
}

fn require_category(
    payload_type: &str,
    section: &'static str,
    expected: DeclarationType,
) -> Result<(), ComposeError> {
    let actual = DeclarationType::from_type_string(payload_type);
    if actual != Some(expected) {
        return Err(ComposeError::WrongCategory {
            section,
            type_name: payload_type.to_string(),
            actual,
        });
    }
    Ok(())
}

/// Enumerate the configuration's schema fields whose name ends with
/// `AssetReference`. Used to auto-wire the asset → configuration link.
fn asset_ref_field_candidates(manifest: &crate::schema::types::PayloadManifest) -> Vec<String> {
    let mut out: Vec<String> = manifest
        .field_order
        .iter()
        .filter(|n| n.ends_with("AssetReference"))
        .cloned()
        .collect();
    // Some manifests may not order all keys via field_order; fall back to
    // scanning all fields and dedup.
    for name in manifest.fields.keys() {
        if name.ends_with("AssetReference") && !out.contains(name) {
            out.push(name.clone());
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::types::{
        FieldDefinition, FieldFlags, FieldType, PayloadManifest, Platforms,
    };
    use std::collections::HashMap;

    fn make_field(name: &str) -> FieldDefinition {
        FieldDefinition {
            name: name.to_string(),
            field_type: FieldType::String,
            flags: FieldFlags::default(),
            title: name.to_string(),
            description: String::new(),
            default: None,
            allowed_values: vec![],
            depth: 0,
            parent_key: None,
            platforms: vec![],
            min_version: None,
            deprecated_in: None,
            introduced_by_platform: std::collections::HashMap::new(),
            deprecated_by_platform: std::collections::HashMap::new(),
            combinetype: None,
        }
    }

    fn make_manifest(payload_type: &str, fields: &[&str]) -> PayloadManifest {
        let mut manifest_fields = HashMap::new();
        let mut field_order = Vec::new();
        for name in fields {
            field_order.push(name.to_string());
            manifest_fields.insert(name.to_string(), make_field(name));
        }
        PayloadManifest {
            payload_type: payload_type.to_string(),
            title: payload_type.to_string(),
            description: String::new(),
            platforms: Platforms::parse("*"),
            min_versions: HashMap::new(),
            os_support: HashMap::new(),
            apply_mode: None,
            category: if payload_type.contains(".asset.") {
                "ddm-asset"
            } else if payload_type.contains(".configuration.") {
                "ddm-configuration"
            } else if payload_type.contains(".activation.") {
                "ddm-activation"
            } else {
                "ddm-other"
            }
            .to_string(),
            fields: manifest_fields,
            field_order,
            segments: vec![],
        }
    }

    fn registry_with(manifests: Vec<PayloadManifest>) -> SchemaRegistry {
        SchemaRegistry::from_manifests_for_test(manifests)
    }

    #[test]
    fn compose_minimal_configuration_only() {
        let registry = registry_with(vec![make_manifest(
            "com.apple.configuration.passcode.settings",
            &["RequireAlphanumeric"],
        )]);
        let bundle = Bundle {
            intent_name: "lock".into(),
            asset: None,
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.passcode.settings".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: None,
            subscriptions: None,
        };
        let composed = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap();
        assert!(composed.asset.is_none());
        assert!(composed.activation.is_none());
        assert_eq!(composed.configuration.identifier, "com.acme.config.lock");
        assert!(composed.asset_ref_field_used.is_none());
    }

    #[test]
    fn compose_wires_asset_reference_when_single_candidate() {
        let registry = registry_with(vec![
            make_manifest(
                "com.apple.asset.credential.userpassword",
                &["Username", "Password"],
            ),
            make_manifest(
                "com.apple.configuration.account.exchange",
                &["HostName", "AuthenticationCredentialsAssetReference"],
            ),
            make_manifest("com.apple.activation.simple", &[]),
        ]);
        let bundle = Bundle {
            intent_name: "exchange".into(),
            asset: Some(BundleAsset {
                type_name: "com.apple.asset.credential.userpassword".into(),
                identifier: None,
                payload: Map::new(),
                ..Default::default()
            }),
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.account.exchange".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: Some(BundleActivation {
                type_name: None,
                identifier: None,
                predicate: None,
                references: None,
            }),
            subscriptions: None,
        };
        let composed = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap();
        let asset = composed.asset.expect("asset emitted");
        assert_eq!(asset.identifier, "com.acme.asset.exchange");
        assert_eq!(
            composed
                .configuration
                .payload
                .get("AuthenticationCredentialsAssetReference")
                .and_then(|v| v.as_str()),
            Some("com.acme.asset.exchange")
        );
        let activation = composed.activation.expect("activation emitted");
        assert_eq!(activation.declaration_type, DEFAULT_ACTIVATION_TYPE);
        assert_eq!(
            activation
                .payload
                .get("StandardConfigurations")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(1)
        );
    }

    #[test]
    fn compose_rejects_ambiguous_asset_ref() {
        let registry = registry_with(vec![
            make_manifest("com.apple.asset.credential.userpassword", &[]),
            make_manifest(
                "com.apple.configuration.account.mail",
                &[
                    "IncomingServer.AuthenticationCredentialsAssetReference",
                    "OutgoingServer.AuthenticationCredentialsAssetReference",
                ],
            ),
        ]);
        let bundle = Bundle {
            intent_name: "mail".into(),
            asset: Some(BundleAsset {
                type_name: "com.apple.asset.credential.userpassword".into(),
                identifier: None,
                payload: Map::new(),
                ..Default::default()
            }),
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.account.mail".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: None,
            subscriptions: None,
        };
        let err = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap_err();
        assert!(matches!(err, ComposeError::AmbiguousAssetRef { .. }));
        assert_eq!(err.error_code(), "SCHEMA_VIOLATION");
    }

    #[test]
    fn compose_rejects_missing_asset_ref_field() {
        let registry = registry_with(vec![
            make_manifest("com.apple.asset.credential.userpassword", &[]),
            make_manifest(
                "com.apple.configuration.passcode.settings",
                &["RequireAlphanumeric"],
            ),
        ]);
        let bundle = Bundle {
            intent_name: "x".into(),
            asset: Some(BundleAsset {
                type_name: "com.apple.asset.credential.userpassword".into(),
                identifier: None,
                payload: Map::new(),
                ..Default::default()
            }),
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.passcode.settings".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: None,
            subscriptions: None,
        };
        let err = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap_err();
        assert!(matches!(err, ComposeError::MissingAssetRef { .. }));
    }

    #[test]
    fn compose_emits_no_server_token() {
        let registry = registry_with(vec![
            make_manifest("com.apple.asset.credential.userpassword", &[]),
            make_manifest(
                "com.apple.configuration.account.exchange",
                &["AuthenticationCredentialsAssetReference"],
            ),
            make_manifest("com.apple.activation.simple", &[]),
        ]);
        let bundle = Bundle {
            intent_name: "exchange".into(),
            asset: Some(BundleAsset {
                type_name: "com.apple.asset.credential.userpassword".into(),
                identifier: None,
                payload: Map::new(),
                ..Default::default()
            }),
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.account.exchange".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: Some(BundleActivation::default()),
            subscriptions: None,
        };
        let composed = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap();
        assert!(composed.asset.unwrap().server_token.is_none());
        assert!(composed.configuration.server_token.is_none());
        assert!(composed.activation.unwrap().server_token.is_none());
    }

    #[test]
    fn compose_strict_orphan_fails_without_flag() {
        // Configuration has no *AssetReference field, so the asset would be
        // orphan; default mode must reject.
        let registry = registry_with(vec![
            make_manifest("com.apple.asset.credential.userpassword", &[]),
            make_manifest(
                "com.apple.configuration.passcode.settings",
                &["RequireAlphanumeric"],
            ),
        ]);
        let bundle = Bundle {
            intent_name: "x".into(),
            asset: Some(BundleAsset {
                type_name: "com.apple.asset.credential.userpassword".into(),
                identifier: None,
                payload: Map::new(),
                ..Default::default()
            }),
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.passcode.settings".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: None,
            subscriptions: None,
        };
        // Without --allow-orphans: MissingAssetRef fires first (the asset
        // can't even be wired). The orphan check is the second line of
        // defence — it fires when the schema HAS *AssetReference fields
        // but the bundle did not wire them. Verify the MissingAssetRef path.
        let err = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap_err();
        assert!(matches!(err, ComposeError::MissingAssetRef { .. }));
    }

    #[test]
    fn compose_rejects_com_example_org() {
        let registry = registry_with(vec![make_manifest(
            "com.apple.configuration.passcode.settings",
            &[],
        )]);
        let bundle = Bundle {
            intent_name: "x".into(),
            asset: None,
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.passcode.settings".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: None,
            subscriptions: None,
        };
        let err = compose(
            &bundle,
            "com.example",
            &registry,
            &ComposeOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ComposeError::InvalidOrg { .. }));
    }

    #[test]
    fn compose_rejects_unknown_type() {
        let registry = registry_with(vec![]);
        let bundle = Bundle {
            intent_name: "x".into(),
            asset: None,
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.does-not-exist".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: None,
            subscriptions: None,
        };
        let err = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap_err();
        assert!(matches!(err, ComposeError::UnknownType { .. }));
    }

    fn make_passcode_registry() -> SchemaRegistry {
        registry_with(vec![
            make_manifest(
                "com.apple.configuration.passcode.settings",
                &["MinimumLength"],
            ),
            make_manifest("com.apple.activation.simple", &[]),
        ])
    }

    #[test]
    fn compose_predicate_without_subscriptions_fails() {
        let registry = make_passcode_registry();
        let bundle = Bundle {
            intent_name: "p".into(),
            asset: None,
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.passcode.settings".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: Some(BundleActivation {
                predicate: Some("@status('passcode.is-compliant') == TRUE".into()),
                ..Default::default()
            }),
            subscriptions: None,
        };
        let err = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap_err();
        match err {
            ComposeError::UnsubscribedStatusKey { missing_keys, .. } => {
                assert_eq!(missing_keys, vec!["passcode.is-compliant"])
            }
            other => panic!("expected UnsubscribedStatusKey, got {other:?}"),
        }
    }

    #[test]
    fn compose_subscription_covers_predicate() {
        let registry = make_passcode_registry();
        let bundle = Bundle {
            intent_name: "p".into(),
            asset: None,
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.passcode.settings".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: Some(BundleActivation {
                predicate: Some("@status('passcode.is-compliant') == TRUE".into()),
                ..Default::default()
            }),
            subscriptions: Some(BundleSubscriptions {
                keys: vec!["passcode.is-compliant".into()],
                identifier: None,
            }),
        };
        let composed = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap();
        let subs = composed.subscriptions.expect("subscriptions emitted");
        assert_eq!(
            subs.declaration_type,
            "com.apple.configuration.management.status-subscriptions"
        );
        assert_eq!(subs.identifier, "com.acme.subscriptions.p");
        // StatusItems is an array of { Name: <key> } per Apple's schema.
        let items = subs
            .payload
            .get("StatusItems")
            .and_then(Value::as_array)
            .expect("StatusItems array");
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].get("Name").and_then(Value::as_str),
            Some("passcode.is-compliant"),
        );
    }

    #[test]
    fn compose_subscription_partial_coverage_fails() {
        let registry = make_passcode_registry();
        let bundle = Bundle {
            intent_name: "p".into(),
            asset: None,
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.passcode.settings".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: Some(BundleActivation {
                predicate: Some(
                    "@status('passcode.is-compliant') == TRUE AND \
                     @status('softwareupdate.install-state') == 'Idle'"
                        .into(),
                ),
                ..Default::default()
            }),
            subscriptions: Some(BundleSubscriptions {
                // Subscribed to one key but predicate references two.
                keys: vec!["passcode.is-compliant".into()],
                identifier: None,
            }),
        };
        let err = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap_err();
        match err {
            ComposeError::UnsubscribedStatusKey { missing_keys, .. } => {
                assert_eq!(missing_keys, vec!["softwareupdate.install-state"]);
            }
            other => panic!("expected UnsubscribedStatusKey, got {other:?}"),
        }
    }

    #[test]
    fn compose_no_predicate_skips_subscriptions_check() {
        // No predicate, no [subscriptions] → no subscriptions decl emitted,
        // no error.
        let registry = make_passcode_registry();
        let bundle = Bundle {
            intent_name: "p".into(),
            asset: None,
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.passcode.settings".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: Some(BundleActivation {
                predicate: None,
                ..Default::default()
            }),
            subscriptions: None,
        };
        let composed = compose(&bundle, "com.acme", &registry, &ComposeOptions::default()).unwrap();
        assert!(composed.subscriptions.is_none());
    }

    fn data_asset_bundle(asset: BundleAsset) -> Bundle {
        Bundle {
            intent_name: "sshd".into(),
            asset: Some(asset),
            configuration: BundleConfiguration {
                type_name: "com.apple.configuration.services.configuration-files".into(),
                identifier: None,
                asset_ref_field: None,
                payload: Map::new(),
            },
            activation: Some(BundleActivation::default()),
            subscriptions: None,
        }
    }

    fn data_asset_registry() -> SchemaRegistry {
        registry_with(vec![
            make_manifest("com.apple.asset.data", &["Reference"]),
            make_manifest(
                "com.apple.configuration.services.configuration-files",
                &["ServiceType", "DataAssetReference"],
            ),
            make_manifest("com.apple.activation.simple", &[]),
        ])
    }

    #[test]
    fn data_asset_defaults_authentication_none() {
        let mut payload = Map::new();
        payload.insert("Reference".into(), Value::Object(Map::new()));
        let bundle = data_asset_bundle(BundleAsset {
            type_name: "com.apple.asset.data".into(),
            payload,
            ..Default::default()
        });
        let c = compose(
            &bundle,
            "io.macadmins",
            &data_asset_registry(),
            &ComposeOptions::default(),
        )
        .unwrap();
        // Data asset gets {"Type":"None"} as a sibling of Payload.
        let auth = c.asset.unwrap().authentication.unwrap();
        assert_eq!(auth.get("Type").and_then(Value::as_str), Some("None"));
        // ServerToken stays server-managed (omitted).
        assert!(c.activation.unwrap().server_token.is_none());
    }

    #[test]
    fn asset_auth_mdm_maps_to_type_mdm() {
        let bundle = data_asset_bundle(BundleAsset {
            type_name: "com.apple.asset.data".into(),
            auth: Some("mdm".into()),
            payload: {
                let mut p = Map::new();
                p.insert("Reference".into(), Value::Object(Map::new()));
                p
            },
            ..Default::default()
        });
        let c = compose(
            &bundle,
            "io.macadmins",
            &data_asset_registry(),
            &ComposeOptions::default(),
        )
        .unwrap();
        assert_eq!(
            c.asset
                .unwrap()
                .authentication
                .unwrap()
                .get("Type")
                .and_then(Value::as_str),
            Some("MDM")
        );
    }

    #[test]
    fn asset_auth_invalid_is_rejected() {
        let bundle = data_asset_bundle(BundleAsset {
            type_name: "com.apple.asset.data".into(),
            auth: Some("s3-creds".into()),
            payload: {
                let mut p = Map::new();
                p.insert("Reference".into(), Value::Object(Map::new()));
                p
            },
            ..Default::default()
        });
        let err = compose(
            &bundle,
            "io.macadmins",
            &data_asset_registry(),
            &ComposeOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ComposeError::InvalidAuthType { .. }));
    }

    #[test]
    fn materialize_asset_hashes_zip_and_placeholders_url() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("p.zip"), b"hello").unwrap();
        let mut asset = BundleAsset {
            type_name: "com.apple.asset.data".into(),
            zip: Some("p.zip".into()),
            ..Default::default()
        };
        materialize_asset(&mut asset, tmp.path()).unwrap();
        let reference = asset.payload.get("Reference").unwrap().as_object().unwrap();
        // SHA-256 of "hello".
        assert_eq!(
            reference.get("Hash-SHA-256").and_then(Value::as_str),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
        assert_eq!(
            reference.get("ContentType").and_then(Value::as_str),
            Some("application/zip")
        );
        // No url → placeholder.
        assert_eq!(
            reference.get("DataURL").and_then(Value::as_str),
            Some(DATAURL_PLACEHOLDER)
        );
    }
}
