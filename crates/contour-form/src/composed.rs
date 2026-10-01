//! Composed identifiers — the nine keys where Apple attaches signing
//! evidence to a bundle ID, and the two spellings that evidence takes.
//!
//! # This table is the source; the SOP is rendered from it
//!
//! `REGISTRY` below is the ONE statement of which keys take a composed
//! identifier, in which form, and on which platforms. The validator's
//! `composed-identifier` rule reads it. The registry table in
//! `skills/contour/references/sop-composed-identifiers.md` is rendered from
//! it by [`registry_markdown`], and `the_sop_table_is_rendered_from_this_registry`
//! fails when the two differ — so the prose cannot drift from the code the
//! way a hand-copied list drifts from its YAML.
//!
//! Every `apple` field is Apple's own sentence from the key's description in
//! `apple/device-management`, quoted so the form is evidence, not memory.
//!
//! # The two spellings
//!
//! ```text
//! "Bundle-ID {Designated-Requirement}"   braces      — a predicate over the certificate chain
//! "Bundle-ID (Team-ID)"                  parentheses — one field of the leaf certificate
//! ```
//!
//! They are not interchangeable: a requirement in parentheses, or a Team ID
//! in braces, is schema-valid (Apple types every one of these as a string)
//! and matches nothing on the device. The declaration reports Verified.
//!
//! # Platform decides
//!
//! The composed identifier is a macOS construction. For most of these keys
//! Apple writes "In iOS … the identifier is a bundle ID", so a composed
//! identifier targeted at iOS is as wrong as a bare one targeted at macOS.
//! Not for all of them: Safari's managed-extension key is composed on every
//! platform, `app.managed` documents both forms without naming a platform,
//! and `Filter.Packets` says nothing about non-macOS at all. `off_macos`
//! carries exactly what Apple states, including "unstated".

use crate::types::Platform;

/// Which spelling the key takes on macOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// `"Bundle-ID {Designated-Requirement}"`.
    DesignatedRequirement,
    /// `"Bundle-ID (Team-ID)"`.
    TeamId,
}

impl Form {
    pub fn spelling(self) -> &'static str {
        match self {
            Form::DesignatedRequirement => "\"Bundle-ID {Designated-Requirement}\"",
            Form::TeamId => "\"Bundle-ID (Team-ID)\"",
        }
    }
    fn short(self) -> &'static str {
        match self {
            Form::DesignatedRequirement => "DR `{…}`",
            Form::TeamId => "Team `(…)`",
        }
    }
}

/// Where the identifier sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// The identifier is a dictionary KEY the operator names; `path` is the
    /// dictionary.
    Key,
    /// The identifier is a string VALUE; `path` is the key holding it.
    Value,
}

/// What Apple states for platforms other than macOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffMacOs {
    /// "In iOS … the identifier is a bundle ID" — bare, and composed is wrong.
    Bare,
    /// Composed everywhere (Safari: "for other platforms, request this
    /// information from the app developer").
    Composed,
    /// Both forms documented with no platform named (`app.managed`).
    Either,
    /// Apple says nothing; no platform-based finding is made.
    Unstated,
}

#[derive(Debug, Clone, Copy)]
pub struct Entry {
    pub type_id: &'static str,
    /// The dictionary (for `Position::Key`) or the key (for `Position::Value`).
    pub path: &'static str,
    pub position: Position,
    pub form: Form,
    /// Apple documents `"Bundle-ID"` alone as accepted on the same key.
    pub bare_ok: bool,
    pub off_macos: OffMacOs,
    /// A literal `"*"` key is documented as "match any".
    pub wildcard: bool,
    /// Apple's sentence, verbatim from the key's description.
    pub apple: &'static str,
}

pub const REGISTRY: &[Entry] = &[
    Entry {
        type_id: "com.apple.configuration.app.settings",
        path: "Privacy.PermissionDefaults",
        position: Position::Key,
        form: Form::DesignatedRequirement,
        bare_ok: false,
        off_macos: OffMacOs::Bare,
        wildcard: false,
        apple: "In iOS, the app identifier is a bundle ID, for example, \"com.example.app\". In macOS, the app identifier is a composed identifier. The format of the composed identifier is \"Bundle-ID {Designated-Requirement}\".",
    },
    Entry {
        type_id: "com.apple.configuration.webcontent-filter.plugin",
        path: "Filter.Sockets.ProviderComposedIdentifier",
        position: Position::Value,
        form: Form::DesignatedRequirement,
        bare_ok: false,
        off_macos: OffMacOs::Bare,
        wildcard: false,
        apple: "In iOS and visionOS, the identifier is a bundle ID, for example, \"com.example.app\". In macOS, the identifier is a composed identifier. The format of the composed identifier is \"Bundle-ID {Designated-Requirement}\".",
    },
    Entry {
        type_id: "com.apple.configuration.webcontent-filter.plugin",
        path: "Filter.Packets.ProviderComposedIdentifier",
        position: Position::Value,
        form: Form::DesignatedRequirement,
        bare_ok: false,
        off_macos: OffMacOs::Unstated,
        wildcard: false,
        apple: "The identifier is a composed identifier. The format of the composed identifier is \"Bundle-ID {Designated-Requirement}\".",
    },
    Entry {
        type_id: "com.apple.configuration.webcontent-filter.plugin",
        path: "Filter.URLs.Parameters.ProviderComposedIdentifier",
        position: Position::Value,
        form: Form::DesignatedRequirement,
        bare_ok: false,
        off_macos: OffMacOs::Bare,
        wildcard: false,
        apple: "In iOS, the identifier is a bundle ID, for example, \"com.example.app\". In macOS, the identifier is a composed identifier. The format of the composed identifier is \"Bundle-ID {Designated-Requirement}\".",
    },
    Entry {
        type_id: "com.apple.configuration.network.dns-proxy",
        path: "ProviderComposedIdentifier",
        position: Position::Value,
        form: Form::DesignatedRequirement,
        bare_ok: true,
        off_macos: OffMacOs::Bare,
        wildcard: false,
        apple: "In iOS and visionOS, the identifier is a bundle ID, for example, \"com.example.app\". In macOS, the identifier is a composed identifier. The format of the composed identifier is either \"Bundle-ID\" or \"Bundle-ID {Designated-Requirement}\".",
    },
    Entry {
        type_id: "com.apple.configuration.network.vpn.vpn-plugin",
        path: "Provider.ComposedIdentifier",
        position: Position::Value,
        form: Form::DesignatedRequirement,
        bare_ok: true,
        off_macos: OffMacOs::Bare,
        wildcard: false,
        apple: "In iOS, tvOS, and visionOS, the identifier is a bundle ID, for example, \"com.example.app\". In macOS, the identifier is a composed identifier. The format of the composed identifier is either \"Bundle-ID\" or \"Bundle-ID {Designated-Requirement}\".",
    },
    Entry {
        type_id: "com.apple.configuration.app.managed",
        path: "AppComposedIdentifier",
        position: Position::Value,
        form: Form::TeamId,
        bare_ok: true,
        off_macos: OffMacOs::Either,
        wildcard: false,
        apple: "The format of the composed identifier is either \"Bundle-ID\" or \"Bundle-ID (Team-ID)\". For example, \"com.example.app\" for the bundle ID format, or \"com.example.app (ABCD1234)\" for the team ID format.",
    },
    Entry {
        type_id: "com.apple.configuration.app.managed",
        path: "ExtensionConfigs",
        position: Position::Key,
        form: Form::TeamId,
        bare_ok: true,
        off_macos: OffMacOs::Either,
        wildcard: false,
        apple: "A dictionary mapping extension composed identifiers to the extension config data and credentials. The format of the composed identifier is either \"Bundle-ID\" or \"Bundle-ID (Team-ID)\".",
    },
    Entry {
        type_id: "com.apple.configuration.extensible-sso",
        path: "ExtensionComposedIdentifier",
        position: Position::Value,
        form: Form::TeamId,
        bare_ok: false,
        off_macos: OffMacOs::Bare,
        wildcard: false,
        apple: "In iOS and visionOS, the identifier is a bundle ID, for example, \"com.example.app.sso-extension\". In macOS, the identifier is a composed identifier. The format of the composed identifier is \"Bundle-ID (Team-ID)\".",
    },
    Entry {
        type_id: "com.apple.configuration.safari.extensions.settings",
        path: "ManagedExtensions",
        position: Position::Key,
        form: Form::TeamId,
        bare_ok: true,
        off_macos: OffMacOs::Composed,
        wildcard: true,
        apple: "Each key in the dictionary represents a composed identifier for a specific managed extension, or you can specify a single \"*\" character to match any extension. The composed identifier of a managed extension uses the format \"Identifier (TeamIdentifier)\", for example \"com.example.app (ABCD1234)\". […] For other platforms, request this information from the app developer.",
    },
];

/// The entry whose dictionary is `parent_path`, when its keys are identifiers.
pub fn key_entry(type_id: &str, parent_path: &str) -> Option<&'static Entry> {
    REGISTRY
        .iter()
        .find(|e| e.position == Position::Key && e.type_id == type_id && e.path == parent_path)
}

/// The entry whose value at `path` is an identifier.
pub fn value_entry(type_id: &str, path: &str) -> Option<&'static Entry> {
    REGISTRY
        .iter()
        .find(|e| e.position == Position::Value && e.type_id == type_id && e.path == path)
}

/// How a string is spelled, before asking whether that spelling is right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spelling<'a> {
    Wildcard,
    Bare,
    /// `Bundle-ID {inner}`.
    Braced(&'a str),
    /// `Bundle-ID (inner)`.
    Parenthesised(&'a str),
}

pub fn spelling(s: &str) -> Spelling<'_> {
    let t = s.trim();
    if t == "*" {
        return Spelling::Wildcard;
    }
    if let Some((_, rest)) = t.split_once('{')
        && let Some(inner) = rest.strip_suffix('}')
    {
        return Spelling::Braced(inner.trim());
    }
    if let Some((_, rest)) = t.split_once('(')
        && let Some(inner) = rest.strip_suffix(')')
    {
        return Spelling::Parenthesised(inner.trim());
    }
    Spelling::Bare
}

fn looks_like_team_id(s: &str) -> bool {
    (5..=12).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// What the rule found. `blocks` is true when a target platform was given
/// and the spelling cannot be right for it — Apple states the form, and a
/// wrong one produces a declaration that reports Verified and matches
/// nothing, so with a target this refuses rather than warns. Without a
/// target it says which platform each form is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub blocks: bool,
    pub message: String,
}

pub fn check(e: &Entry, s: &str, platform: Option<Platform>) -> Option<Finding> {
    let targeted = platform.is_some();
    let on_macos = platform == Some(Platform::MacOS);
    let off = platform.is_some_and(|p| p != Platform::MacOS);
    let form = e.form.spelling();
    let finding = |blocks: bool, m: String| Some(Finding { blocks, message: m });

    match spelling(s) {
        Spelling::Wildcard => {
            if e.wildcard {
                None
            } else {
                finding(
                    targeted,
                    format!("\"*\" is not documented for this key; it takes {form}"),
                )
            }
        }
        // Wrong delimiter: the evidence is there, in the other form's clothes.
        Spelling::Parenthesised(inner) if e.form == Form::DesignatedRequirement => finding(
            targeted,
            format!(
                "wraps \"{inner}\" in parentheses — that is the Team-ID form; this key takes a \
                 designated requirement, {form}, and a Team ID matches a different set of code \
                 than a requirement does"
            ),
        ),
        Spelling::Braced(inner) if e.form == Form::TeamId => finding(
            targeted,
            format!(
                "wraps \"{inner}\" in braces — that is the designated-requirement form; this key \
                 takes {form}"
            ),
        ),
        Spelling::Parenthesised(inner) if !looks_like_team_id(inner) => finding(
            targeted,
            format!(
                "\"{inner}\" is not a Team ID (5–12 uppercase letters and digits from the leaf \
                 certificate); this key takes {form}"
            ),
        ),
        // Correct delimiter: is composed right for the target?
        Spelling::Braced(_) | Spelling::Parenthesised(_) => match (e.off_macos, platform) {
            (OffMacOs::Bare, Some(p)) if off => finding(
                true,
                format!(
                    "is a composed identifier; Apple documents a bare bundle ID on {} — the \
                     composed form is a macOS construction and matches nothing here",
                    p.as_str()
                ),
            ),
            (OffMacOs::Bare, None) => finding(
                false,
                format!(
                    "is a composed identifier — correct for macOS; on iOS the key is the bare \
                     bundle ID. Pass a target platform to check the right form"
                ),
            ),
            _ => None,
        },
        Spelling::Bare => {
            if on_macos || (platform.is_none() && e.off_macos != OffMacOs::Bare) {
                if e.bare_ok {
                    finding(
                        false,
                        format!(
                            "is a bare bundle ID; Apple accepts it here, and it matches ANY code \
                             signed with this bundle ID. Supply {form} to pin the app"
                        ),
                    )
                } else {
                    finding(
                        targeted,
                        format!(
                            "is a bare bundle ID; on macOS the key is {form} and a bare ID matches \
                             no app. `contour app manifest` reads the identity from the installed app"
                        ),
                    )
                }
            } else if off {
                match e.off_macos {
                    OffMacOs::Composed => finding(
                        false,
                        format!(
                            "is a bare bundle ID; Apple documents {form} on every platform for this \
                             key. Settings that apply only to a composed identifier will not take \
                             effect"
                        ),
                    ),
                    _ => None,
                }
            } else {
                // No target, and Apple says iOS is bare.
                if e.bare_ok {
                    finding(
                        false,
                        format!(
                            "is a bare bundle ID — correct for iOS; on macOS it matches any code \
                             with this bundle ID unless {form} is supplied"
                        ),
                    )
                } else {
                    finding(
                        false,
                        format!(
                            "is a bare bundle ID — correct for iOS; on macOS the key must be {form} \
                             or it matches no app. Pass a target platform to check the right form"
                        ),
                    )
                }
            }
        }
    }
}

/// The registry as the SOP prints it. Rendered, not hand-written, so the
/// prose and the rule cannot disagree.
pub fn registry_markdown() -> String {
    let mut out = String::from(
        "| Declaration | Key | Position | Form | Bare OK | Off macOS | Apple says |\n\
         |---|---|---|---|---|---|---|\n",
    );
    for e in REGISTRY {
        let decl = e
            .type_id
            .strip_prefix("com.apple.configuration.")
            .unwrap_or(e.type_id);
        let pos = match e.position {
            Position::Key => "the dictionary key",
            Position::Value => "value",
        };
        let off = match e.off_macos {
            OffMacOs::Bare => "bare bundle ID",
            OffMacOs::Composed => "composed too",
            OffMacOs::Either => "either form",
            OffMacOs::Unstated => "unstated",
        };
        let bare = match (e.bare_ok, e.wildcard) {
            (true, true) => "yes, and `\"*\"`",
            (true, false) => "yes",
            (false, _) => "no",
        };
        let apple = e.apple.replace('|', "\\|");
        out.push_str(&format!(
            "| `{decl}` | `{}` | {pos} | **{}** | {bare} | {off} | {apple} |\n",
            e.path,
            e.form.short()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SOP's registry is this table, rendered. If this fails, run the
    /// test with `--nocapture`, paste the printed table between the
    /// `registry:generated` markers in the SOP, and nothing else.
    #[test]
    fn the_sop_table_is_rendered_from_this_registry() {
        const SOP: &str = include_str!(
            "../../contour-core/skills/contour/references/sop-composed-identifiers.md"
        );
        let want = registry_markdown();
        let begin = "<!-- registry:generated:begin -->\n";
        let end = "<!-- registry:generated:end -->";
        let (Some(b), Some(e)) = (SOP.find(begin), SOP.find(end)) else {
            panic!("the SOP has lost its registry:generated markers");
        };
        let have = &SOP[b + begin.len()..e];
        assert!(
            have == want,
            "sop-composed-identifiers.md's registry table differs from `composed::REGISTRY`. \
             The code is the source; paste this between the markers:\n\n{want}"
        );
    }

    #[test]
    fn every_entry_quotes_apple_and_names_its_form() {
        for e in REGISTRY {
            assert!(
                !e.apple.is_empty(),
                "{}::{} has no Apple sentence",
                e.type_id,
                e.path
            );
            let expects = match e.form {
                Form::DesignatedRequirement => "Designated-Requirement",
                Form::TeamId => "Team",
            };
            assert!(
                e.apple.contains(expects),
                "{}::{}: Apple's sentence does not mention {expects}: {}",
                e.type_id,
                e.path,
                e.apple
            );
        }
        assert_eq!(
            REGISTRY.len(),
            10,
            "nine keys, one of them (webcontent-filter) three times"
        );
    }

    #[test]
    fn spelling_classifies_the_four_shapes() {
        assert_eq!(spelling("*"), Spelling::Wildcard);
        assert_eq!(spelling("com.example.app"), Spelling::Bare);
        assert_eq!(
            spelling("com.example.app {anchor apple generic}"),
            Spelling::Braced("anchor apple generic")
        );
        assert_eq!(
            spelling("com.example.app (ABCD1234)"),
            Spelling::Parenthesised("ABCD1234")
        );
    }
}
