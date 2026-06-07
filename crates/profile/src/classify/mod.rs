//! Classify a configuration profile from its payloads into a friendly,
//! scope-aware display name (`System - Kind (detail)` or `AppName (aspect)`),
//! using an editable [`map::NamingMap`].

pub mod collision;
pub mod map;
pub mod scan;

use serde::Serialize;

use crate::profile::{ConfigurationProfile, PayloadContent};
use map::NamingMap;

/// Outcome of classifying one profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Classification {
    /// The proposed friendly display name (None when unclassified).
    pub new_name: Option<String>,
    /// Distinct friendly Kind labels, in map order.
    pub kinds: Vec<String>,
    /// The derived subject, if any.
    pub subject: Option<String>,
    /// Classification status.
    pub status: Status,
}

/// Why a profile did or did not get a new name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// A friendly name was produced.
    Classified,
    /// No payload type matched the map; name left untouched.
    Unclassified,
    /// Classified, but an app subject fell back to a raw (unmapped) bundle id.
    AppUnmapped,
}

/// Separators between name segments, stripped between/around tokens.
const NAME_SEPARATORS: [char; 3] = [' ', '-', ':'];

/// Subject derivation outcome for one profile.
struct Derived {
    subject: Option<String>,
    /// Leading keep codes to prepend before the formatted name.
    leading: Vec<String>,
    /// Trailing site/keep codes to append after the formatted name.
    trailing: Vec<String>,
    /// The subject came from a payload-derived app name (drives app-format).
    used_app_name: bool,
    status: Status,
}

/// Classify a profile against the naming map.
pub fn classify_profile(profile: &ConfigurationProfile, map: &NamingMap) -> Classification {
    // Distinct Kind labels in map order.
    let mut kinds: Vec<String> = Vec::new();
    for (ptype, label) in &map.kinds {
        if profile
            .payload_content
            .iter()
            .any(|p| &p.payload_type == ptype)
            && !kinds.contains(label)
        {
            kinds.push(label.clone());
        }
    }

    if kinds.is_empty() {
        return Classification {
            new_name: None,
            kinds,
            subject: None,
            status: Status::Unclassified,
        };
    }

    let kind_str = kinds.join(&map.multi_kind_join);
    // Lead prefix for idempotent stripping uses the system label; `strip_leading_default`
    // declares the scope words (System/App/User/…) so app/user names still strip cleanly.
    let lead_prefix = format!("{} - {kind_str}", map.scope.system_label);
    let d = derive_subject(profile, map, &lead_prefix, &kinds);

    // Scope (checked in order): App (app-config payloads + a derived app name) →
    // User (`PayloadScope == "User"`) → System. App leads with the subject; User
    // and System share the kind-first system format. The `{scope}` placeholder is
    // filled with the matching label.
    let is_app_format = is_app_scope(profile, map) && d.used_app_name && d.subject.is_some();
    let scope_label = if is_app_format {
        &map.scope.app_label
    } else if is_user_scope(profile) {
        &map.scope.user_label
    } else {
        &map.scope.system_label
    };
    let new_name = render(
        map,
        is_app_format,
        scope_label,
        &kind_str,
        d.subject.as_deref(),
        &d.leading,
        &d.trailing,
    );

    Classification {
        new_name: Some(new_name),
        kinds,
        subject: d.subject,
        status: d.status,
    }
}

/// True when the profile envelope declares `PayloadScope == "User"`.
fn is_user_scope(profile: &ConfigurationProfile) -> bool {
    profile
        .additional_fields
        .get("PayloadScope")
        .and_then(plist::Value::as_string)
        == Some("User")
}

/// True when every payload that contributes a kind is an app-config type.
fn is_app_scope(profile: &ConfigurationProfile, map: &NamingMap) -> bool {
    let mut any = false;
    for p in &profile.payload_content {
        if map.kinds.contains_key(&p.payload_type) {
            any = true;
            if !map
                .scope
                .app_payload_types
                .iter()
                .any(|t| t == &p.payload_type)
            {
                return false;
            }
        }
    }
    any
}

/// Render the display name with the scope-appropriate template, dropping the
/// `({subject})` group when empty and appending any trailing keep-codes.
fn render(
    map: &NamingMap,
    is_app: bool,
    scope_label: &str,
    kind: &str,
    subject: Option<&str>,
    leading: &[String],
    trailing: &[String],
) -> String {
    let tmpl = if is_app {
        &map.app_format
    } else {
        &map.system_format
    };
    let with_kind = tmpl.replace("{scope}", scope_label).replace("{kind}", kind);
    let filled = match subject.filter(|s| !s.is_empty()) {
        Some(s) => with_kind.replace("{subject}", s),
        None => with_kind
            .replace("{subject}", "")
            .replace(" ()", "")
            .replace("()", ""),
    };
    let mut out = filled.trim().to_string();
    for code in trailing {
        out.push_str(" - ");
        out.push_str(code);
    }
    // Re-prepend any leading keep-codes as a `{code} - ` prefix, in order.
    let mut prefix = String::new();
    for code in leading {
        prefix.push_str(code);
        prefix.push_str(" - ");
    }
    format!("{prefix}{out}")
}

/// Derive the subject, trailing codes and status by walking payloads in map order.
///
/// `lead_prefix` is the rendered `{scope} - {kind}` lead; `from_existing` strips
/// it (or the parenthetical) so renaming stays idempotent.
fn derive_subject(
    profile: &ConfigurationProfile,
    map: &NamingMap,
    lead_prefix: &str,
    kind_labels: &[String],
) -> Derived {
    for (ptype, rule) in &map.subjects {
        let Some(payload) = profile
            .payload_content
            .iter()
            .find(|p| &p.payload_type == ptype)
        else {
            continue;
        };

        if let Some(field) = &rule.field {
            if let Some(s) = payload.content.get(field).and_then(plist::Value::as_string) {
                if !s.is_empty() {
                    return Derived {
                        subject: Some(s.to_string()),
                        leading: Vec::new(),
                        trailing: Vec::new(),
                        used_app_name: false,
                        status: Status::Classified,
                    };
                }
            }
        }

        if rule.cert_subject_cn {
            if let Some(plist::Value::Data(der)) = payload.content.get("PayloadContent") {
                if let Some(info) = crate::audit::cert::classify_der(der) {
                    if let Some(cn) = info.subject_cn {
                        return Derived {
                            subject: Some(cn),
                            leading: Vec::new(),
                            trailing: Vec::new(),
                            used_app_name: false,
                            status: Status::Classified,
                        };
                    }
                }
            }
        }

        if rule.app_name {
            if let Some(bundle) = app_bundle_id(payload) {
                let (subject, status) = match map.apps.get(&bundle) {
                    Some(friendly) => (friendly.clone(), Status::Classified),
                    None => (bundle, Status::AppUnmapped),
                };
                return Derived {
                    subject: Some(subject),
                    leading: Vec::new(),
                    trailing: Vec::new(),
                    used_app_name: true,
                    status,
                };
            }
        }

        if let Some(fe) = &rule.from_existing {
            let (subject, leading, trailing) = extract_from_existing(
                &profile.payload_display_name,
                fe,
                lead_prefix,
                kind_labels,
                &map.strip_leading_default,
                &map.strip_tokens_default,
                &map.keep_leading,
                &map.keep_trailing,
            );
            if subject.is_some() {
                return Derived {
                    subject,
                    leading,
                    trailing,
                    used_app_name: false,
                    status: Status::Classified,
                };
            }
        }
    }
    Derived {
        subject: None,
        leading: Vec::new(),
        trailing: Vec::new(),
        used_app_name: false,
        status: Status::Classified,
    }
}

/// Recover `(detail, trailing_codes)` from an existing display name.
///
/// Pulls keep-codes out first (re-appended as a suffix later), then takes the
/// first `(...)` group as the detail, or — for legacy names without parens —
/// strips the rendered `{scope} - {kind}` lead plus leading scope/cluster
/// tokens. Always preferring the parenthetical keeps renaming idempotent:
/// `Scope - Kind (detail)` recovers `detail` on a second pass.
#[allow(
    clippy::too_many_arguments,
    reason = "naming-map knobs threaded explicitly"
)]
fn extract_from_existing(
    name: &str,
    rule: &map::FromExisting,
    lead_prefix: &str,
    kind_labels: &[String],
    strip_leading_default: &[String],
    strip_tokens_default: &[String],
    keep_leading: &[String],
    keep_trailing: &[String],
) -> (Option<String>, Vec<String>, Vec<String>) {
    // Ignore a trailing collision suffix so re-classification is idempotent.
    let trimmed = collision::strip_suffix(name.trim());
    // Pull leading keep-codes first, then trailing, from what remains.
    let (after_leading, leading) = extract_keep_codes(trimmed, keep_leading);
    let (remainder, codes) = extract_keep_codes(&after_leading, keep_trailing);

    let detail = match first_parenthetical(&remainder) {
        Some(p) => p,
        None => {
            let after = strip_literal_prefix(&remainder, lead_prefix);
            // Strip leading scope/cluster tokens plus the individual kind labels
            // (so a bare-kind legacy name like "Fonts" empties out).
            let tokens: Vec<&str> = strip_leading_default
                .iter()
                .chain(rule.strip_leading.iter())
                .chain(kind_labels.iter())
                .map(String::as_str)
                .collect();
            strip_leading_tokens(after, &tokens)
        }
    };

    // Remove cluster/tenant tags wherever they appear (trailing, mid-name).
    let cleaned = strip_tokens_anywhere(&detail, strip_tokens_default);
    ((!cleaned.is_empty()).then_some(cleaned), leading, codes)
}

/// Pull whole-word keep-codes out of `s` (anywhere), returning the remaining
/// text and the codes in order. Cleans up separators orphaned by removal.
fn extract_keep_codes(s: &str, keep: &[String]) -> (String, Vec<String>) {
    if keep.is_empty() {
        return (s.to_string(), Vec::new());
    }
    let lower: Vec<String> = keep.iter().map(|t| t.to_lowercase()).collect();
    let mut out: Vec<&str> = Vec::new();
    let mut codes: Vec<String> = Vec::new();
    for word in s.split_whitespace() {
        if lower.iter().any(|t| t == &word.to_lowercase()) {
            codes.push(word.to_string());
            if out.last() == Some(&"-") {
                out.pop();
            }
            continue;
        }
        if word == "-" && out.is_empty() {
            continue;
        }
        out.push(word);
    }
    while out.last() == Some(&"-") {
        out.pop();
    }
    (out.join(" "), codes)
}

/// Remove whole-word `tokens` (case-insensitive) from anywhere in `s`, cleaning
/// up separators orphaned by the removal.
fn strip_tokens_anywhere(s: &str, tokens: &[String]) -> String {
    if tokens.is_empty() {
        return s.trim().to_string();
    }
    let lower: Vec<String> = tokens.iter().map(|t| t.to_lowercase()).collect();
    let mut out: Vec<&str> = Vec::new();
    for word in s.split_whitespace() {
        if lower.iter().any(|t| t == &word.to_lowercase()) {
            // Drop a separator orphaned by removing this token.
            if out.last() == Some(&"-") {
                out.pop();
            }
            continue;
        }
        if word == "-" && out.is_empty() {
            continue;
        }
        out.push(word);
    }
    while out.last() == Some(&"-") {
        out.pop();
    }
    out.join(" ")
}

/// Strip `prefix` (case-insensitive, whole-word) and trailing separators from
/// the start of `s`. Returns `s` unchanged when it does not lead with `prefix`.
fn strip_literal_prefix<'a>(s: &'a str, prefix: &str) -> &'a str {
    if prefix.is_empty() {
        return s;
    }
    if let Some(p) = s.get(..prefix.len()) {
        if p.eq_ignore_ascii_case(prefix) {
            let after = &s[prefix.len()..];
            if after.is_empty() || after.starts_with(NAME_SEPARATORS) {
                return after.trim_start_matches(NAME_SEPARATORS);
            }
        }
    }
    s
}

/// The trimmed content of the first balanced `(...)` group, if non-empty.
fn first_parenthetical(s: &str) -> Option<String> {
    let open = s.find('(')?;
    let rest = &s[open + 1..];
    let close = rest.find(')')?;
    let content = rest[..close].trim();
    (!content.is_empty()).then(|| content.to_string())
}

/// Strip leading whole-word `tokens` (case-insensitive) and separators from the
/// start of `name`, returning the remaining detail.
fn strip_leading_tokens(name: &str, tokens: &[&str]) -> String {
    let mut s = name.trim_start_matches(NAME_SEPARATORS);
    loop {
        let mut matched = false;
        for tok in tokens {
            if tok.is_empty() {
                continue;
            }
            // `get` guards against slicing a non-char-boundary for non-ASCII names.
            if let Some(prefix) = s.get(..tok.len()) {
                if prefix.eq_ignore_ascii_case(tok) {
                    let after = &s[tok.len()..];
                    // Whole-word: the token must end at a separator or string end,
                    // so "App" does not match inside "AppStore".
                    if after.is_empty() || after.starts_with(NAME_SEPARATORS) {
                        s = after.trim_start_matches(NAME_SEPARATORS);
                        matched = true;
                        break;
                    }
                }
            }
        }
        if !matched {
            break;
        }
    }
    s.trim().to_string()
}

/// Extract an app bundle id / preference domain from an app-config payload.
///
/// `ManagedClient.preferences` nests the domain as the first key of
/// `PayloadContent`; other app payloads carry a `BundleIdentifier` /
/// `ServiceProviderBundleIdentifier` field.
fn app_bundle_id(payload: &PayloadContent) -> Option<String> {
    // ManagedClient.preferences: the inner preference domain is the first key.
    if let Some(plist::Value::Dictionary(dict)) = payload.content.get("PayloadContent") {
        if let Some((domain, _)) = dict.iter().next() {
            return Some(domain.clone());
        }
    }
    // notificationsettings: the target app is NotificationSettings[0].BundleIdentifier.
    if let Some(plist::Value::Array(arr)) = payload.content.get("NotificationSettings") {
        if let Some(plist::Value::Dictionary(first)) = arr.first() {
            if let Some(id) = first
                .get("BundleIdentifier")
                .and_then(plist::Value::as_string)
            {
                return Some(id.to_string());
            }
        }
    }
    // TCC privacy: the target app is the first service entry's Identifier.
    if let Some(plist::Value::Dictionary(services)) = payload.content.get("Services") {
        if let Some(plist::Value::Array(arr)) = services.values().next() {
            if let Some(plist::Value::Dictionary(first)) = arr.first() {
                if let Some(id) = first.get("Identifier").and_then(plist::Value::as_string) {
                    return Some(id.to_string());
                }
            }
        }
    }
    for key in ["BundleIdentifier", "ServiceProviderBundleIdentifier"] {
        if let Some(id) = payload.content.get(key).and_then(plist::Value::as_string) {
            return Some(id.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const ROOT_DER: &[u8] = include_bytes!("../../tests/fixtures/audit/certs/root.der");

    fn map() -> NamingMap {
        NamingMap::embedded().unwrap()
    }

    fn payload(payload_type: &str, content: &[(&str, plist::Value)]) -> PayloadContent {
        PayloadContent {
            payload_type: payload_type.to_string(),
            payload_version: 1,
            payload_identifier: format!("{payload_type}.test"),
            payload_uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            content: content
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        }
    }

    fn profile(display_name: &str, payloads: Vec<PayloadContent>) -> ConfigurationProfile {
        ConfigurationProfile {
            payload_type: "Configuration".to_string(),
            payload_version: 1,
            payload_display_name: display_name.to_string(),
            payload_identifier: "com.test.profile".to_string(),
            payload_uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            payload_content: payloads,
            additional_fields: BTreeMap::new(),
        }
    }

    #[test]
    fn wifi_renders_kind_and_subject() {
        let p = profile(
            "old",
            vec![payload(
                "com.apple.wifi.managed",
                &[("SSID_STR", plist::Value::String("Corporate".into()))],
            )],
        );
        let c = classify_profile(&p, &map());
        assert_eq!(c.status, Status::Classified);
        assert_eq!(c.new_name.as_deref(), Some("System - Wi-Fi (Corporate)"));
    }

    #[test]
    fn restriction_with_only_scope_kind_words_is_bare_kind() {
        // A name made only of stripped scope/kind tokens leaves no detail.
        let p = profile("System - Restrictions", vec![payload("com.apple.MCX", &[])]);
        let c = classify_profile(&p, &map());
        assert_eq!(c.new_name.as_deref(), Some("System - Restriction"));
    }

    #[test]
    fn multi_payload_joins_distinct_kinds() {
        let p = profile(
            "old",
            vec![
                payload(
                    "com.apple.wifi.managed",
                    &[("SSID_STR", plist::Value::String("Corporate".into()))],
                ),
                payload("com.apple.security.root", &[]),
            ],
        );
        let c = classify_profile(&p, &map());
        // Map order: wifi (Wi-Fi) before security.root (Certificate).
        assert_eq!(
            c.kinds,
            vec!["Wi-Fi".to_string(), "Certificate".to_string()]
        );
        assert!(
            c.new_name
                .as_deref()
                .unwrap()
                .starts_with("System - Wi-Fi + Certificate (")
        );
    }

    #[test]
    fn unknown_payload_is_unclassified() {
        let p = profile("keep me", vec![payload("com.example.unknown", &[])]);
        let c = classify_profile(&p, &map());
        assert_eq!(c.status, Status::Unclassified);
        assert_eq!(c.new_name, None);
    }

    #[test]
    fn root_cert_subject_is_common_name() {
        let p = profile(
            "old",
            vec![payload(
                "com.apple.security.root",
                &[("PayloadContent", plist::Value::Data(ROOT_DER.to_vec()))],
            )],
        );
        let c = classify_profile(&p, &map());
        assert_eq!(
            c.new_name.as_deref(),
            Some("System - Certificate (Acme Root CA)")
        );
    }

    #[test]
    fn managed_prefs_subject_maps_bundle_to_friendly_name() {
        let mut inner = plist::Dictionary::new();
        inner.insert(
            "com.microsoft.Edge".into(),
            plist::Value::Dictionary(plist::Dictionary::new()),
        );
        let p = profile(
            "old",
            vec![payload(
                "com.apple.ManagedClient.preferences",
                &[("PayloadContent", plist::Value::Dictionary(inner))],
            )],
        );
        let c = classify_profile(&p, &map());
        assert_eq!(
            c.new_name.as_deref(),
            Some("App - Microsoft Edge (Settings)")
        );
        assert_eq!(c.status, Status::Classified);
    }

    #[test]
    fn unmapped_app_falls_back_to_raw_id() {
        let mut inner = plist::Dictionary::new();
        inner.insert(
            "de.acme.customapp".into(),
            plist::Value::Dictionary(plist::Dictionary::new()),
        );
        let p = profile(
            "old",
            vec![payload(
                "com.apple.ManagedClient.preferences",
                &[("PayloadContent", plist::Value::Dictionary(inner))],
            )],
        );
        let c = classify_profile(&p, &map());
        assert_eq!(
            c.new_name.as_deref(),
            Some("App - de.acme.customapp (Settings)")
        );
        assert_eq!(c.status, Status::AppUnmapped);
    }

    #[test]
    fn font_reuses_existing_name_stripped_of_kind_prefix() {
        let p = profile(
            "Fonts - Acme Corp - Office",
            vec![payload("com.apple.font", &[])],
        );
        let c = classify_profile(&p, &map());
        assert_eq!(
            c.new_name.as_deref(),
            Some("System - Fonts (Acme Corp - Office)")
        );
    }

    #[test]
    fn font_classify_is_idempotent() {
        // Re-running on an already-classified font name yields the same name.
        let p = profile(
            "System - Fonts (Calibri)",
            vec![payload("com.apple.font", &[])],
        );
        let c = classify_profile(&p, &map());
        assert_eq!(c.new_name.as_deref(), Some("System - Fonts (Calibri)"));
    }

    #[test]
    fn font_named_only_for_its_kind_has_no_subject() {
        // A profile literally named "Fonts" has nothing distinguishing to reuse.
        let p = profile("Fonts", vec![payload("com.apple.font", &[])]);
        let c = classify_profile(&p, &map());
        assert_eq!(c.new_name.as_deref(), Some("System - Fonts"));
    }

    #[test]
    fn restriction_recovers_detail_from_legacy_name() {
        let p = profile(
            "System - Restrictions - USB Drives Allowed",
            vec![payload("com.apple.MCX", &[])],
        );
        let c = classify_profile(&p, &map());
        assert_eq!(
            c.new_name.as_deref(),
            Some("System - Restriction (USB Drives Allowed)")
        );
    }

    #[test]
    fn restriction_detail_recovery_is_idempotent() {
        let p = profile(
            "System - Restriction (USB Drives Allowed)",
            vec![payload("com.apple.MCX", &[])],
        );
        let c = classify_profile(&p, &map());
        assert_eq!(
            c.new_name.as_deref(),
            Some("System - Restriction (USB Drives Allowed)")
        );
    }

    #[test]
    fn notifications_prefers_parenthetical_detail() {
        let p = profile(
            "App - Notifications (disabled)",
            vec![payload("com.apple.notificationsettings", &[])],
        );
        let c = classify_profile(&p, &map());
        assert_eq!(
            c.new_name.as_deref(),
            Some("System - Notification (disabled)")
        );
    }

    #[test]
    fn strip_tokens_anywhere_removes_with_separator_cleanup() {
        let toks = vec!["SITE".to_string()];
        // Trailing token: removed along with its orphaned separator.
        assert_eq!(
            strip_tokens_anywhere("alpha beta - SITE", &toks),
            "alpha beta"
        );
        // Mid-string token: removed, surrounding words rejoined.
        assert_eq!(
            strip_tokens_anywhere("alpha SITE beta gamma", &toks),
            "alpha beta gamma"
        );
        // Whole-word only: a substring match is not touched.
        assert_eq!(strip_tokens_anywhere("SITEx detail", &toks), "SITEx detail");
        // No tokens configured → unchanged.
        assert_eq!(strip_tokens_anywhere("a - b", &[]), "a - b");
    }

    #[test]
    fn multi_kind_from_existing_is_idempotent() {
        // A Privacy + System Extension profile must strip the FULL kind prefix on
        // a second pass, not just one payload's label (else it doubles).
        let payloads = vec![
            payload("com.apple.TCC.configuration-profile-policy", &[]),
            payload("com.apple.system-extension-policy", &[]),
        ];
        let first = profile("App - Settings - Zoom - PPPCSysExt", payloads.clone());
        let c1 = classify_profile(&first, &map());
        let name1 = c1.new_name.unwrap();
        assert!(
            name1.starts_with("System - Privacy Control + System Extension ("),
            "got {name1}"
        );

        // Feed the rendered name back in — must reproduce itself.
        let second = profile(&name1, payloads);
        let c2 = classify_profile(&second, &map());
        assert_eq!(c2.new_name.as_deref(), Some(name1.as_str()));
    }
}
