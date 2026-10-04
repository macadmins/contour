//! Delivery-scope checking for declarations and profiles.
//!
//! Apple states `allowed-scopes` in two places that can disagree. A payload
//! says which scopes the declaration as a whole may be delivered in; a key
//! may declare its own, and five keys on the 27.0 release branch contradict
//! the payload that contains them:
//!
//! | Payload | Key | Payload says | Key says |
//! |---|---|---|---|
//! | `app.settings` | `Privacy` | system, user | **user** |
//! | `app.settings` | `Allowed.AllowedBinaries` | system, user | **system** |
//! | `app.settings` | `Allowed.DeniedBinaries` | system, user | **system** |
//! | `app.settings` | `Allowed.AlwaysAllowManagedApps` | system, user | **system** |
//! | `extensible-sso` | `PlatformSSO.UseSharedDeviceKeys` | system, user | **system** |
//!
//! So one `app.settings` declaration can hold keys that cannot both be
//! delivered on any single channel — [`unsatisfiable_pairs`] finds that
//! without knowing the channel at all, which is why it is the check that
//! earns this module.
//!
//! Nothing here fails a declaration for being *unusual*. A scope mismatch
//! means the device accepts the declaration and ignores the part it cannot
//! apply; the messages say that rather than calling the input invalid.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Platform;
use crate::types::{FieldDefinition, PayloadManifest};

/// Where a declaration or profile is delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    System,
    User,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Scope> {
        match s.trim().to_ascii_lowercase().as_str() {
            "system" | "device" => Some(Scope::System),
            "user" => Some(Scope::User),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::System => "system",
            Scope::User => "user",
        }
    }

    /// The spelling Fleet expects in a top-level `PayloadScope`.
    ///
    /// Capitalised: Fleet documents `"System"` and `"User"`, and an
    /// unrecognised value falls back to System silently.
    pub fn payload_scope_value(self) -> &'static str {
        match self {
            Scope::System => "System",
            Scope::User => "User",
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Normalise a raw `allowed-scopes` array into a set.
///
/// **Order is not meaningful and must not be compared.** Apple writes both
/// spellings: on macOS, 100 payload types say `["system","user"]` and 17 say
/// `["user","system"]`. A string comparison answers wrongly on a sixth of
/// the data, so everything here goes through a set.
pub fn scope_set(raw: &[String]) -> BTreeSet<Scope> {
    raw.iter()
        .filter_map(|s| Scope::parse(s))
        .collect::<BTreeSet<_>>()
}

impl Ord for Scope {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}
impl PartialOrd for Scope {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The payload-level classification FormSpec §4 calls "the topmost rule":
/// what Apple permits for a declaration on one platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeClass {
    /// Apple permits only the user channel — a fact to force, not a choice.
    UserOnly,
    /// Both legal; offer a choice only if a key narrows it.
    Either,
    /// Only the device channel.
    SystemOnly,
    /// The schema says nothing.
    Unspecified,
}

impl ScopeClass {
    pub fn classify(set: Option<&BTreeSet<Scope>>) -> Self {
        match set {
            None => ScopeClass::Unspecified,
            Some(s) => match (s.contains(&Scope::User), s.contains(&Scope::System)) {
                (true, true) => ScopeClass::Either,
                (true, false) => ScopeClass::UserOnly,
                (false, true) => ScopeClass::SystemOnly,
                (false, false) => ScopeClass::Unspecified,
            },
        }
    }
}

/// The scopes a payload permits on a platform, if it says.
pub fn payload_scopes(manifest: &PayloadManifest, platform: Platform) -> Option<BTreeSet<Scope>> {
    manifest
        .os_support
        .get(&platform)
        .and_then(|os| os.allowed_scopes.as_ref())
        .map(|v| scope_set(v))
}

/// The scopes a key permits on a platform, if it declares any of its own.
///
/// `None` means the key inherits the payload there — never "unrestricted".
/// Per-platform because a key may restrict one platform and not another:
/// `safari.settings/Privacy` is user-only on macOS and system-only on iOS.
pub fn key_scopes(field: &FieldDefinition, platform: Platform) -> Option<BTreeSet<Scope>> {
    field.allowed_scopes.get(&platform).map(|v| scope_set(v))
}

/// A key whose own scope excludes the delivery scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeConflict {
    pub key: String,
    pub key_scopes: BTreeSet<Scope>,
    pub delivered_in: Scope,
}

impl std::fmt::Display for ScopeConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is {}-scope only; delivered in {} scope it is accepted and ignored",
            self.key,
            join(&self.key_scopes),
            self.delivered_in
        )
    }
}

/// Two keys in one payload whose scopes cannot both be satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsatisfiablePair {
    pub first: String,
    pub first_scopes: BTreeSet<Scope>,
    pub second: String,
    pub second_scopes: BTreeSet<Scope>,
}

impl std::fmt::Display for UnsatisfiablePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is {}-scope only and {} is {}-scope only — no single channel \
             delivers both, so whichever scope you choose, the other is accepted \
             and ignored. Split them into two declarations.",
            self.first,
            join(&self.first_scopes),
            self.second,
            join(&self.second_scopes),
        )
    }
}

fn join(scopes: &BTreeSet<Scope>) -> String {
    scopes
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Keys present in the payload whose own scope excludes `delivered_in`.
///
/// `present` names the keys the declaration actually sets, by the name the
/// schema uses. A key the declaration does not carry cannot conflict.
pub fn key_conflicts(
    manifest: &PayloadManifest,
    platform: Platform,
    present: &BTreeSet<String>,
    delivered_in: Scope,
) -> Vec<ScopeConflict> {
    let mut out = Vec::new();
    for key in manifest.fields.values() {
        if !present.contains(&key.name) {
            continue;
        }
        let Some(scopes) = key_scopes(key, platform) else {
            continue; // inherits the payload
        };
        if !scopes.is_empty() && !scopes.contains(&delivered_in) {
            out.push(ScopeConflict {
                key: key.name.clone(),
                key_scopes: scopes,
                delivered_in,
            });
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// Pairs of present keys whose scopes have no scope in common.
///
/// Needs no delivery scope: if two keys' scope sets are disjoint, no channel
/// satisfies both. This is the check with no false-positive risk from
/// guessing a channel, and the only signal that an `app.settings`
/// declaration carrying both `Privacy` and `Allowed.DeniedBinaries` cannot
/// work as written.
pub fn unsatisfiable_pairs(
    manifest: &PayloadManifest,
    platform: Platform,
    present: &BTreeSet<String>,
) -> Vec<UnsatisfiablePair> {
    let mut scoped: Vec<(&str, BTreeSet<Scope>)> = manifest
        .fields
        .values()
        .filter(|k| present.contains(&k.name))
        .filter_map(|k| key_scopes(k, platform).map(|s| (k.name.as_str(), s)))
        .filter(|(_, s)| !s.is_empty())
        .collect();
    // Deterministic output regardless of map iteration order.
    scoped.sort_by(|a, b| a.0.cmp(b.0));

    let mut out = Vec::new();
    for (i, (a_name, a)) in scoped.iter().enumerate() {
        for (b_name, b) in scoped.iter().skip(i + 1) {
            if a.is_disjoint(b) {
                out.push(UnsatisfiablePair {
                    first: (*a_name).to_string(),
                    first_scopes: a.clone(),
                    second: (*b_name).to_string(),
                    second_scopes: b.clone(),
                });
            }
        }
    }
    out
}

/// Whether the payload as a whole is outside the delivery scope.
pub fn payload_out_of_scope(
    manifest: &PayloadManifest,
    platform: Platform,
    delivered_in: Scope,
) -> Option<BTreeSet<Scope>> {
    let scopes = payload_scopes(manifest, platform)?;
    (!scopes.is_empty() && !scopes.contains(&delivered_in)).then_some(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> crate::SchemaRegistry {
        crate::SchemaRegistry::embedded().expect("embedded registry")
    }

    fn manifest(reg: &crate::SchemaRegistry, name: &str) -> PayloadManifest {
        reg.get(name)
            .unwrap_or_else(|| panic!("{name} missing"))
            .clone()
    }

    #[test]
    fn order_does_not_affect_comparison() {
        // The flagged bug: 100 macOS payload types spell it
        // ["system","user"] and 17 spell it ["user","system"].
        let a = scope_set(&["system".into(), "user".into()]);
        let b = scope_set(&["user".into(), "system".into()]);
        assert_eq!(a, b, "scope comparison must be order-independent");
        assert!(a.contains(&Scope::System) && a.contains(&Scope::User));
    }

    #[test]
    fn key_level_scopes_are_read_from_the_embedded_data() {
        let reg = registry();
        let app = manifest(&reg, "com.apple.configuration.app.settings");

        let privacy = app.fields.get("Privacy").expect("Privacy field");
        assert_eq!(
            key_scopes(privacy, Platform::MacOS),
            Some([Scope::User].into_iter().collect()),
            "app.settings/Privacy is macOS user-only"
        );

        // ...inside a payload that permits either.
        assert_eq!(
            payload_scopes(&app, Platform::MacOS),
            Some([Scope::System, Scope::User].into_iter().collect()),
        );

        // Every key that does not declare one reads as None — inherit, not
        // unrestricted.
        let inherited = app
            .fields
            .values()
            .filter(|f| key_scopes(f, Platform::MacOS).is_none())
            .count();
        assert!(inherited > 0, "most keys inherit their payload");
    }

    #[test]
    fn exactly_eight_key_level_scopes_survive_the_read() {
        // 8 rows in the parquet, and all 8 must reach the type. They very
        // nearly did not: one PayloadKey merges the per-(platform, key) rows,
        // so a single Option<Vec<String>> kept whichever platform was read
        // first and silently dropped macOS for 5 of the 8.
        let reg = registry();
        let total: usize = reg
            .all()
            .flat_map(|m| m.fields.values())
            .map(|f| f.allowed_scopes.len())
            .sum();
        assert_eq!(
            total, 8,
            "the 27.0 release branch has 8 key-level allowed-scopes; a change \
             here means Apple moved and the scope checks need re-reading"
        );
    }

    #[test]
    fn a_key_restricted_on_one_platform_only_is_platform_correct() {
        // safari.settings/Privacy: user-only on macOS, system-only on iOS.
        // A non-platform-aware read would answer one of these wrongly.
        let reg = registry();
        let safari = manifest(&reg, "com.apple.configuration.safari.settings");
        let privacy = safari.fields.get("Privacy").expect("Privacy field");
        assert_eq!(
            key_scopes(privacy, Platform::MacOS),
            Some([Scope::User].into_iter().collect())
        );
        assert_eq!(
            key_scopes(privacy, Platform::Ios),
            Some([Scope::System].into_iter().collect())
        );
    }

    #[test]
    fn opposite_keys_in_one_payload_are_unsatisfiable() {
        let reg = registry();
        let app = manifest(&reg, "com.apple.configuration.app.settings");
        let present: BTreeSet<String> = ["Privacy".to_string(), "DeniedBinaries".to_string()]
            .into_iter()
            .collect();

        let pairs = unsatisfiable_pairs(&app, Platform::MacOS, &present);
        assert_eq!(pairs.len(), 1, "got {pairs:?}");
        let text = pairs[0].to_string();
        assert!(
            text.contains("Privacy") && text.contains("DeniedBinaries"),
            "{text}"
        );
        assert!(
            text.contains("no single channel"),
            "the message must say why it cannot work: {text}"
        );
    }

    #[test]
    fn a_key_outside_the_delivery_scope_is_reported() {
        let reg = registry();
        let app = manifest(&reg, "com.apple.configuration.app.settings");
        let present: BTreeSet<String> = ["Privacy".to_string()].into_iter().collect();

        // Privacy is user-only; delivered system it does nothing.
        let conflicts = key_conflicts(&app, Platform::MacOS, &present, Scope::System);
        assert_eq!(conflicts.len(), 1);
        assert!(
            conflicts[0].to_string().contains("accepted and ignored"),
            "the message must name the effect, not call it invalid: {}",
            conflicts[0]
        );

        // Delivered user, it is fine.
        assert!(key_conflicts(&app, Platform::MacOS, &present, Scope::User).is_empty());
    }

    #[test]
    fn a_user_only_payload_is_flagged_on_the_system_channel() {
        let reg = registry();
        let math = manifest(&reg, "com.apple.configuration.math.settings");
        assert!(
            payload_out_of_scope(&math, Platform::MacOS, Scope::System).is_some(),
            "math.settings is macOS user-only"
        );
        assert!(
            payload_out_of_scope(&math, Platform::MacOS, Scope::User).is_none(),
            "...and clean on the user channel"
        );
    }

    #[test]
    fn keys_the_declaration_does_not_set_cannot_conflict() {
        let reg = registry();
        let app = manifest(&reg, "com.apple.configuration.app.settings");
        // Privacy is user-only, but this declaration does not carry it.
        let present: BTreeSet<String> = ["AllowedBinaries".to_string()].into_iter().collect();
        assert!(key_conflicts(&app, Platform::MacOS, &present, Scope::System).is_empty());
        assert!(unsatisfiable_pairs(&app, Platform::MacOS, &present).is_empty());
    }
}
