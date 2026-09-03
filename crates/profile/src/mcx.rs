//! Managed-preference (MCX) domain inspection and surgical renaming.
//!
//! An MCX payload nests its settings under the **preference domain as a
//! dictionary key**:
//!
//! ```text
//! com.apple.ManagedClient.preferences
//!   └── PayloadContent
//!         └── de.example.legacy.restrictions   ← the domain, a KEY
//!               └── Forced[] → mcx_preference_settings → { … }
//! ```
//!
//! Renaming that domain is not the same operation as renaming an identifier:
//! it is a key, not a value, so the reference-rewriting used elsewhere (which
//! deliberately never touches keys) cannot do it.
//!
//! ## Why this is surgical rather than a parse-and-reserialise
//!
//! Round-tripping a profile through a plist writer reorders and reformats
//! every key in the file, producing a diff nobody can review and churning
//! files that did not need to change. Instead this module **parses to verify
//! scope**, then edits the raw XML at exactly the `<key>…</key>` occurrences
//! the parse accounted for — so everything else stays byte-for-byte.
//!
//! The parse-verification is what makes the text edit safe. A domain string
//! can easily also appear inside a *value* — a support path like
//! `/Library/Application Support/com.acme.legacy/…` — and a blind substitution
//! would corrupt it.

use serde::Serialize;

use crate::profile::ConfigurationProfile;

/// The MCX container payload type whose `PayloadContent` is keyed by domain.
pub const MCX_PAYLOAD_TYPE: &str = "com.apple.ManagedClient.preferences";

/// One managed-preference domain found in a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McxDomainRef {
    /// Index of the MCX payload within `PayloadContent`.
    pub payload_index: usize,
    /// That payload's identifier, so a finding is locatable.
    pub payload_identifier: String,
    /// The preference domain (the dictionary key).
    pub domain: String,
    /// Setting keys nested under `mcx_preference_settings`, for context.
    pub setting_keys: Vec<String>,
}

/// Every managed-preference domain in a profile, in payload order.
pub fn find_domains(profile: &ConfigurationProfile) -> Vec<McxDomainRef> {
    let mut out = Vec::new();
    for (payload_index, payload) in profile.payload_content.iter().enumerate() {
        if payload.payload_type != MCX_PAYLOAD_TYPE {
            continue;
        }
        let Some(plist::Value::Dictionary(domains)) = payload.content.get("PayloadContent") else {
            continue;
        };
        for (domain, body) in domains {
            out.push(McxDomainRef {
                payload_index,
                payload_identifier: payload.payload_identifier.clone(),
                domain: domain.clone(),
                setting_keys: setting_keys(body),
            });
        }
    }
    out
}

/// Collect the keys under `Forced[]`/`Set[]` → `mcx_preference_settings`.
fn setting_keys(body: &plist::Value) -> Vec<String> {
    let mut keys = Vec::new();
    let Some(body) = body.as_dictionary() else {
        return keys;
    };
    for mode in ["Forced", "Set"] {
        let Some(entries) = body.get(mode).and_then(plist::Value::as_array) else {
            continue;
        };
        for entry in entries {
            if let Some(settings) = entry
                .as_dictionary()
                .and_then(|d| d.get("mcx_preference_settings"))
                .and_then(plist::Value::as_dictionary)
            {
                keys.extend(settings.keys().cloned());
            }
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

/// How to rewrite managed-preference domains.
#[derive(Debug, Clone, Copy)]
pub enum DomainRewrite<'a> {
    /// Rename one exact domain.
    Exact { from: &'a str, to: &'a str },
    /// Rename every domain carrying this prefix. Matches the prefix itself or
    /// a dot-separated child (`de.example.app` also renames
    /// `de.example.app.restrictions`), never a partial component, so
    /// `de.example.apple` is untouched by a `de.example.app` prefix.
    Prefix { from: &'a str, to: &'a str },
}

impl DomainRewrite<'_> {
    /// The rewritten domain, or `None` when this rule does not apply.
    pub fn apply(&self, domain: &str) -> Option<String> {
        match *self {
            DomainRewrite::Exact { from, to } => (domain == from).then(|| to.to_string()),
            DomainRewrite::Prefix { from, to } => {
                let rest = domain.strip_prefix(from)?;
                (rest.is_empty() || rest.starts_with('.')).then(|| format!("{to}{rest}"))
            }
        }
    }
}

/// Why a rename was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenameRefusal {
    /// No managed-preference payload declares a matching domain.
    DomainNotPresent,
    /// The raw XML holds a different number of `<key>domain</key>` tags than
    /// the parse accounted for — editing would touch something unverified.
    OccurrenceMismatch {
        domain: String,
        parsed: usize,
        in_text: usize,
    },
    /// The target domain already exists in the same payload; renaming would
    /// produce two identical keys and silently lose one set of settings.
    TargetAlreadyPresent {
        payload_index: usize,
        domain: String,
    },
}

impl std::fmt::Display for RenameRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenameRefusal::DomainNotPresent => {
                write!(
                    f,
                    "no managed-preference payload declares a matching domain"
                )
            }
            RenameRefusal::OccurrenceMismatch {
                domain,
                parsed,
                in_text,
            } => write!(
                f,
                "refusing to edit '{domain}': the parse found {parsed} domain key(s) but the \
                 file text holds {in_text} <key> tag(s) with that name — one of them is not a \
                 managed-preference domain, so a text edit could corrupt it"
            ),
            RenameRefusal::TargetAlreadyPresent {
                payload_index,
                domain,
            } => write!(
                f,
                "refusing to edit: payload {payload_index} already declares '{domain}', so the \
                 rename would produce two identical keys and one set of settings would be lost \
                 (this profile is already partly migrated)"
            ),
        }
    }
}

/// Apply `rewrite` to every matching managed-preference domain in the raw XML.
///
/// `profile` is the parsed form of `text`; it is used only to verify that each
/// domain really is a managed-preference domain, to count occurrences, and to
/// detect collisions. The edit replaces `<key>…</key>` tags, leaving every
/// other byte — including a *value* containing the same string — untouched.
///
/// Returns the new text and the `(old, new)` pairs applied.
///
/// # Errors
/// See [`RenameRefusal`]: nothing matched, an unverified occurrence, or a
/// target domain that already exists in the same payload.
pub fn rename_domains(
    text: &str,
    profile: &ConfigurationProfile,
    rewrite: &DomainRewrite<'_>,
) -> Result<(String, Vec<(String, String)>), RenameRefusal> {
    let found = find_domains(profile);
    let planned: Vec<(McxDomainRef, String)> = found
        .iter()
        .filter_map(|d| rewrite.apply(&d.domain).map(|new| (d.clone(), new)))
        .collect();
    if planned.is_empty() {
        return Err(RenameRefusal::DomainNotPresent);
    }

    // Collision: the target must not already exist in the same payload.
    for (d, new) in &planned {
        if found
            .iter()
            .any(|other| other.payload_index == d.payload_index && other.domain == *new)
        {
            return Err(RenameRefusal::TargetAlreadyPresent {
                payload_index: d.payload_index,
                domain: new.clone(),
            });
        }
    }

    let mut out = text.to_string();
    let mut applied = Vec::new();
    for (d, new) in &planned {
        let needle = format!("<key>{}</key>", d.domain);
        let parsed = planned.iter().filter(|(o, _)| o.domain == d.domain).count();
        let in_text = out.matches(&needle).count();
        if in_text != parsed {
            return Err(RenameRefusal::OccurrenceMismatch {
                domain: d.domain.clone(),
                parsed,
                in_text,
            });
        }
        out = out.replace(&needle, &format!("<key>{new}</key>"));
        if !applied
            .iter()
            .any(|(o, _): &(String, String)| *o == d.domain)
        {
            applied.push((d.domain.clone(), new.clone()));
        }
    }

    Ok((out, applied))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::parser::parse_profile_from_bytes;

    /// A profile with one MCX domain plus a *value* containing the same
    /// string — the shape that makes a blind substitution dangerous.
    fn sample() -> String {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDisplayName</key><string>Desktop</string>
            <key>PayloadIdentifier</key><string>com.acme.desktop</string>
            <key>PayloadType</key><string>com.apple.desktop</string>
            <key>PayloadUUID</key><string>13310D84-56D2-444C-8069-2837AC3064B3</string>
            <key>PayloadVersion</key><integer>1</integer>
            <key>override-picture-path</key>
            <string>/Library/Application Support/de.example.legacy.restrictions/bg.png</string>
        </dict>
        <dict>
            <key>PayloadContent</key>
            <dict>
                <key>de.example.legacy.restrictions</key>
                <dict>
                    <key>Forced</key>
                    <array><dict><key>mcx_preference_settings</key><dict>
                        <key>Restrictions</key><array/>
                        <key>Banner</key><string>hello</string>
                    </dict></dict></array>
                </dict>
            </dict>
            <key>PayloadDisplayName</key><string>Custom Settings</string>
            <key>PayloadIdentifier</key><string>com.acme.custom</string>
            <key>PayloadType</key><string>com.apple.ManagedClient.preferences</string>
            <key>PayloadUUID</key><string>CAA01E12-67D7-4062-A9AF-EDC0F1C51681</string>
            <key>PayloadVersion</key><integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key><string>Legacy Restrictions</string>
    <key>PayloadIdentifier</key><string>com.acme.profile</string>
    <key>PayloadType</key><string>Configuration</string>
    <key>PayloadUUID</key><string>A0700903-5F5F-43C9-9F26-39F3BBC95682</string>
    <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>"#
            .to_string()
    }

    fn parsed(text: &str) -> ConfigurationProfile {
        parse_profile_from_bytes(text.as_bytes()).expect("fixture parses")
    }

    #[test]
    fn finds_domain_with_payload_context_and_setting_keys() {
        let text = sample();
        let found = find_domains(&parsed(&text));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].domain, "de.example.legacy.restrictions");
        assert_eq!(found[0].payload_index, 1);
        assert_eq!(found[0].payload_identifier, "com.acme.custom");
        assert_eq!(
            found[0].setting_keys,
            vec!["Banner".to_string(), "Restrictions".to_string()],
            "setting keys give the reviewer context for what moves"
        );
    }

    /// The headline safety property: the domain KEY is renamed, and the
    /// value containing the same string is left alone.
    #[test]
    fn renames_the_key_and_never_a_value() {
        let text = sample();
        let (out, applied) = rename_domains(
            &text,
            &parsed(&text),
            &DomainRewrite::Exact {
                from: "de.example.legacy.restrictions",
                to: "com.acme.restrictions",
            },
        )
        .expect("rename applies");

        assert_eq!(applied.len(), 1);
        assert!(out.contains("<key>com.acme.restrictions</key>"));
        assert!(!out.contains("<key>de.example.legacy.restrictions</key>"));
        assert!(
            out.contains(
                "<string>/Library/Application Support/de.example.legacy.restrictions/bg.png</string>"
            ),
            "a VALUE containing the domain string must be untouched"
        );
    }

    /// Everything outside the renamed tag stays byte-for-byte — no
    /// reordering, no reformatting, a reviewable one-line diff.
    #[test]
    fn edit_is_byte_minimal() {
        let text = sample();
        let (out, _) = rename_domains(
            &text,
            &parsed(&text),
            &DomainRewrite::Exact {
                from: "de.example.legacy.restrictions",
                to: "com.acme.restrictions",
            },
        )
        .unwrap();

        let before: Vec<&str> = text.lines().collect();
        let after: Vec<&str> = out.lines().collect();
        assert_eq!(before.len(), after.len(), "line count unchanged");
        let differing: Vec<usize> = before
            .iter()
            .zip(&after)
            .enumerate()
            .filter(|(_, (b, a))| b != a)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(differing.len(), 1, "exactly one line changes");
    }

    /// Identity fields must never move — renaming a domain is not a
    /// re-identification.
    #[test]
    fn leaves_identifiers_and_uuids_untouched() {
        let text = sample();
        let (out, _) = rename_domains(
            &text,
            &parsed(&text),
            &DomainRewrite::Exact {
                from: "de.example.legacy.restrictions",
                to: "com.acme.restrictions",
            },
        )
        .unwrap();
        for pin in [
            "<string>com.acme.custom</string>",
            "<string>com.acme.profile</string>",
            "<string>CAA01E12-67D7-4062-A9AF-EDC0F1C51681</string>",
            "<string>A0700903-5F5F-43C9-9F26-39F3BBC95682</string>",
        ] {
            assert!(out.contains(pin), "must preserve {pin}");
        }
    }

    /// The output still parses, and the domain is where it should be.
    #[test]
    fn output_still_parses_as_a_profile() {
        let text = sample();
        let (out, _) = rename_domains(
            &text,
            &parsed(&text),
            &DomainRewrite::Exact {
                from: "de.example.legacy.restrictions",
                to: "com.acme.restrictions",
            },
        )
        .unwrap();
        let reparsed = parse_profile_from_bytes(out.as_bytes()).expect("output parses");
        let domains = find_domains(&reparsed);
        assert_eq!(domains[0].domain, "com.acme.restrictions");
        assert_eq!(
            domains[0].setting_keys,
            vec!["Banner".to_string(), "Restrictions".to_string()],
            "settings survive the rename"
        );
    }

    /// A domain nothing declares is an operator error, not a silent no-op.
    #[test]
    fn refuses_when_domain_absent() {
        let text = sample();
        let err = rename_domains(
            &text,
            &parsed(&text),
            &DomainRewrite::Exact {
                from: "com.nope.absent",
                to: "com.acme.x",
            },
        )
        .unwrap_err();
        assert_eq!(err, RenameRefusal::DomainNotPresent);
    }

    /// If the text holds more `<key>` tags with that name than the parse
    /// accounted for, one of them is not a domain — refuse rather than guess.
    #[test]
    fn refuses_on_occurrence_mismatch() {
        let mut text = sample();
        // A same-named key inside a non-MCX payload's dictionary.
        text = text.replace(
            "<key>override-picture-path</key>",
            "<key>de.example.legacy.restrictions</key><string>x</string>\n            <key>override-picture-path</key>",
        );
        let err = rename_domains(
            &text,
            &parsed(&text),
            &DomainRewrite::Exact {
                from: "de.example.legacy.restrictions",
                to: "com.acme.restrictions",
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RenameRefusal::OccurrenceMismatch {
                parsed: 1,
                in_text: 2,
                ..
            }
        ));
    }

    /// Real estates keep many sibling domains under one prefix, so prefix mode
    /// is the operation that actually migrates a namespace.
    #[test]
    fn prefix_renames_every_sibling_domain() {
        let text = sample().replace(
            "<key>de.example.legacy.restrictions</key>",
            "<key>de.example.legacy.restrictions</key>\n                <dict/>\n                <key>de.example.legacy.checkFirewall</key>",
        );
        let (out, applied) = rename_domains(
            &text,
            &parsed(&text),
            &DomainRewrite::Prefix {
                from: "de.example.legacy",
                to: "com.acme",
            },
        )
        .expect("prefix rename applies");
        assert_eq!(applied.len(), 2, "both siblings renamed: {applied:?}");
        assert!(out.contains("<key>com.acme.restrictions</key>"));
        assert!(out.contains("<key>com.acme.checkFirewall</key>"));
    }

    /// A prefix must not catch a partial component.
    #[test]
    fn prefix_respects_dot_boundaries() {
        assert_eq!(
            DomainRewrite::Prefix {
                from: "de.example.app",
                to: "com.acme"
            }
            .apply("de.example.apple.thing"),
            None,
            "de.example.apple must not match a de.example.app prefix"
        );
        assert_eq!(
            DomainRewrite::Prefix {
                from: "de.example.app",
                to: "com.acme"
            }
            .apply("de.example.app"),
            Some("com.acme".to_string()),
            "the prefix itself renames"
        );
    }

    /// Partly-migrated estates are the dangerous case: if the target domain
    /// already exists in the same payload, renaming would produce two
    /// identical keys and silently drop one set of settings.
    #[test]
    fn refuses_when_target_domain_already_present() {
        let text = sample().replace(
            "<key>de.example.legacy.restrictions</key>",
            "<key>com.acme.restrictions</key>\n                <dict/>\n                <key>de.example.legacy.restrictions</key>",
        );
        let err = rename_domains(
            &text,
            &parsed(&text),
            &DomainRewrite::Exact {
                from: "de.example.legacy.restrictions",
                to: "com.acme.restrictions",
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, RenameRefusal::TargetAlreadyPresent { .. }),
            "got {err:?}"
        );
    }

    /// Unrelated managed-preference domains in the same profile (a vendor
    /// domain, an Apple domain) must never be renamed.
    #[test]
    fn leaves_unrelated_domains_alone() {
        let text = sample().replace(
            "<key>de.example.legacy.restrictions</key>",
            "<key>corp.vendor.tool</key>\n                <dict/>\n                <key>de.example.legacy.restrictions</key>",
        );
        let (out, applied) = rename_domains(
            &text,
            &parsed(&text),
            &DomainRewrite::Prefix {
                from: "de.example.legacy",
                to: "com.acme",
            },
        )
        .unwrap();
        assert_eq!(applied.len(), 1);
        assert!(
            out.contains("<key>corp.vendor.tool</key>"),
            "vendor domain untouched"
        );
    }
}
