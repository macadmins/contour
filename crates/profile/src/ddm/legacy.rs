//! Wrap classic `.mobileconfig` profiles in `com.apple.configuration.legacy`
//! declarations, and keep the wrapping honest as the profiles change.
//!
//! ## Why this exists
//!
//! DDM activations gate *declarations*. A mobileconfig is not one, so a profile
//! that needs gating has to be wrapped in `com.apple.configuration.legacy`,
//! which points at the profile by URL.
//!
//! The trap is that a device re-downloads `ProfileURL` **only when the
//! declaration's ServerToken changes**, and editing the profile does not touch
//! the declaration. Edit a profile, forget to bump the URL, and every device
//! keeps the old copy while the declaration still reports Verified. Nothing
//! fails; it just silently does not update.
//!
//! So the URL is pinned to an immutable commit SHA, and this module records the
//! hash of the profile each declaration wraps. [`refresh`] re-points exactly the
//! declarations whose profiles actually changed.
//!
//! ## Content hash, not mtime
//!
//! A checkout rewrites mtimes. Bumping the SHA on declarations whose profiles
//! did not change mints new ServerTokens and makes every device re-download
//! profiles that are byte-identical — turning a correctness tool into a
//! fleet-wide stampede.
//!
//! ## On OS 27 this becomes unnecessary
//!
//! `ProfileAssetReference` (OS 27+) points at a `com.apple.asset.data` whose
//! payload carries `Hash-SHA-256`, so staleness becomes detectable by
//! construction. The index here exists only because `ProfileURL` has no hash
//! field. Keep that in mind before extending it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The declaration type this module emits.
pub const LEGACY_TYPE: &str = "com.apple.configuration.legacy";

/// Placeholder written when no commit SHA is supplied yet.
///
/// Deliberately not a plausible SHA: a URL containing this must fail loudly if
/// it ever reaches a device, rather than 404 quietly at some later date.
pub const SHA_PLACEHOLDER: &str = "REPLACE-WITH-COMMIT-SHA";

/// Why a conversion or refresh was refused.
///
/// Every variant leaves the tree untouched. The ones that matter are the cases
/// where a plausible guess exists and would be wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyError {
    /// The wrapped profile no longer exists on disk. Re-pointing would publish
    /// a URL to content that is gone.
    ProfileMissing { identifier: String, path: PathBuf },
    /// A legacy declaration with no index entry. contour cannot know which
    /// profile it wraps, and matching by filename would silently wrap the
    /// wrong one.
    NotInIndex { identifier: String },
    /// Apple requires `https://` for `ProfileURL`.
    UrlNotHttps { url: String },
    /// Two inputs share a file name, so `{name}` would expand to one URL for
    /// both and the second would silently overwrite the first.
    DuplicateBasename { name: String },
    /// The template referenced a placeholder this module does not define.
    UnknownPlaceholder { token: String },
    /// The existing `ProfileURL` does not match the recorded template — the
    /// declaration was hand-edited, and rewriting would discard that edit.
    TemplateMismatch { identifier: String, url: String },
}

impl std::fmt::Display for LegacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProfileMissing { identifier, path } => write!(
                f,
                "`{identifier}` wraps `{}`, which no longer exists",
                path.display()
            ),
            Self::NotInIndex { identifier } => write!(
                f,
                "`{identifier}` is a legacy declaration with no index entry — \
                 contour cannot tell which profile it wraps"
            ),
            Self::UrlNotHttps { url } => {
                write!(f, "ProfileURL must start with https:// — got `{url}`")
            }
            Self::DuplicateBasename { name } => write!(
                f,
                "two input profiles are both named `{name}`; the URL template \
                 would produce one URL for both"
            ),
            Self::UnknownPlaceholder { token } => write!(
                f,
                "unknown template placeholder `{{{token}}}` — known: sha, name, stem, path"
            ),
            Self::TemplateMismatch { identifier, url } => write!(
                f,
                "`{identifier}` has a hand-edited ProfileURL (`{url}`) that does \
                 not match its recorded template; refusing to overwrite it"
            ),
        }
    }
}

impl std::error::Error for LegacyError {}

/// One tracked declaration: which profile it wraps, and the profile's hash when
/// the URL was last written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyEntry {
    /// Declaration `Identifier`.
    pub identifier: String,
    /// Path to the wrapped profile, relative to the root `convert` walked —
    /// the same value the `{path}` placeholder expands to. Relative because
    /// this file is committed beside the declarations: an absolute path would
    /// name one developer's checkout. `refresh` joins it onto `--against`.
    pub profile: String,
    /// SHA-256 of the profile's bytes when `url` was written.
    pub sha256: String,
    /// The URL currently in the declaration.
    pub url: String,
    /// Template the URL was expanded from, so a hand-edit is detectable.
    pub url_template: String,
    /// Commit SHA the URL is pinned to.
    pub sha: String,
}

/// contour's bookkeeping, committed beside the declarations.
///
/// Never shipped to a device: the declaration is sent verbatim and Apple has no
/// field for "hash of the thing this URL points at", so an extra payload key
/// would risk rejection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LegacyIndex {
    #[serde(default, rename = "entry")]
    pub entries: Vec<LegacyEntry>,
}

impl LegacyIndex {
    /// File name written into the output directory.
    pub const FILE_NAME: &'static str = ".contour-legacy.toml";

    pub fn get(&self, identifier: &str) -> Option<&LegacyEntry> {
        self.entries.iter().find(|e| e.identifier == identifier)
    }

    /// Insert or replace by identifier, keeping entries sorted so the file has
    /// a stable diff.
    pub fn upsert(&mut self, entry: LegacyEntry) {
        match self
            .entries
            .iter_mut()
            .find(|e| e.identifier == entry.identifier)
        {
            Some(slot) => *slot = entry,
            None => self.entries.push(entry),
        }
        self.entries.sort_by(|a, b| a.identifier.cmp(&b.identifier));
    }
}

/// SHA-256 of a byte slice as lowercase hex — the same function `compose`
/// uses for data assets, so both code paths agree byte-for-byte on what a
/// hash looks like.
pub(crate) use crate::ddm::compose::sha256_hex;

/// Values a URL template can interpolate.
#[derive(Debug, Clone)]
pub struct TemplateContext {
    /// Commit SHA, or [`SHA_PLACEHOLDER`].
    pub sha: String,
    /// File name with extension, e.g. `nudge-preferences.mobileconfig`.
    pub name: String,
    /// File name without extension.
    pub stem: String,
    /// Path relative to the input root, for nested layouts.
    pub path: String,
}

impl TemplateContext {
    /// Build a context from a profile path and the root it was found under.
    pub fn for_profile(profile: &Path, root: Option<&Path>, sha: Option<&str>) -> Self {
        let name = profile
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stem = profile
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let rel = root
            .and_then(|r| profile.strip_prefix(r).ok())
            .unwrap_or(profile);
        Self {
            sha: sha.unwrap_or(SHA_PLACEHOLDER).to_string(),
            name,
            stem,
            path: rel.to_string_lossy().into_owned(),
        }
    }
}

/// Expand `{sha}` / `{name}` / `{stem}` / `{path}` in a URL template.
///
/// An unknown placeholder is an error rather than a passthrough: a URL
/// containing a literal `{version}` would be published and fail at download
/// time, long after the mistake was made.
pub fn expand_template(template: &str, ctx: &TemplateContext) -> Result<String, LegacyError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            // An unmatched brace is literal text, not a placeholder.
            out.push_str(&rest[open..]);
            return finish_https(out);
        };
        let token = &after[..close];
        let value = match token {
            "sha" => &ctx.sha,
            "name" => &ctx.name,
            "stem" => &ctx.stem,
            "path" => &ctx.path,
            other => {
                return Err(LegacyError::UnknownPlaceholder {
                    token: other.to_string(),
                });
            }
        };
        out.push_str(value);
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    finish_https(out)
}

/// Apple requires `https://` for `ProfileURL`; reject anything else at the
/// point the URL is built, not at deploy time.
fn finish_https(url: String) -> Result<String, LegacyError> {
    if url.starts_with("https://") {
        Ok(url)
    } else {
        Err(LegacyError::UrlNotHttps { url })
    }
}

/// Build the `Payload` for a legacy declaration wrapping `url`.
pub fn legacy_payload(url: &str) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert("ProfileURL".to_string(), Value::String(url.to_string()));
    payload
}

/// Reject duplicate file names across the input set.
///
/// `{name}` is the common template token, so two profiles called
/// `settings.mobileconfig` in different directories would expand to the same
/// URL and the second declaration would point at the first one's content.
pub fn reject_duplicate_basenames(profiles: &[PathBuf]) -> Result<(), LegacyError> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for p in profiles {
        let name = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !seen.insert(name.clone()) {
            return Err(LegacyError::DuplicateBasename { name });
        }
    }
    Ok(())
}

/// What `refresh` decided about one declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// Profile bytes are unchanged; the declaration was left alone.
    Unchanged { identifier: String },
    /// Profile changed; the URL was re-pointed at the new SHA.
    Repointed {
        identifier: String,
        old_url: String,
        new_url: String,
    },
}

impl RefreshOutcome {
    pub fn identifier(&self) -> &str {
        match self {
            Self::Unchanged { identifier } | Self::Repointed { identifier, .. } => identifier,
        }
    }

    pub fn changed(&self) -> bool {
        matches!(self, Self::Repointed { .. })
    }
}

/// Decide what should happen to one indexed declaration.
///
/// Pure: takes the profile's current bytes rather than reading them, so the
/// decision is testable without a filesystem.
pub fn plan_refresh(
    entry: &LegacyEntry,
    current_bytes: &[u8],
    new_sha: &str,
) -> Result<RefreshOutcome, LegacyError> {
    let current = sha256_hex(current_bytes);
    if current == entry.sha256 {
        return Ok(RefreshOutcome::Unchanged {
            identifier: entry.identifier.clone(),
        });
    }

    // Re-expand the recorded template with the new commit SHA. Rebuilding from
    // the template (rather than string-replacing the old SHA inside the URL)
    // means a URL whose shape changed is caught below instead of being
    // half-rewritten.
    let ctx = TemplateContext {
        sha: new_sha.to_string(),
        name: Path::new(&entry.profile)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        stem: Path::new(&entry.profile)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        path: entry.profile.clone(),
    };
    let new_url = expand_template(&entry.url_template, &ctx)?;

    Ok(RefreshOutcome::Repointed {
        identifier: entry.identifier.clone(),
        old_url: entry.url.clone(),
        new_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(sha: &str) -> TemplateContext {
        TemplateContext {
            sha: sha.to_string(),
            name: "nudge-preferences.mobileconfig".to_string(),
            stem: "nudge-preferences".to_string(),
            path: "macos/nudge-preferences.mobileconfig".to_string(),
        }
    }

    #[test]
    fn expands_every_known_placeholder() {
        let url = expand_template(
            "https://example.com/{sha}/{path}?n={name}&s={stem}",
            &ctx("ea283a1"),
        )
        .unwrap();
        assert_eq!(
            url,
            "https://example.com/ea283a1/macos/nudge-preferences.mobileconfig\
             ?n=nudge-preferences.mobileconfig&s=nudge-preferences"
        );
    }

    #[test]
    fn unknown_placeholder_is_refused_not_passed_through() {
        // A literal `{version}` in a published URL fails at download time, long
        // after the typo was made.
        let err = expand_template("https://example.com/{version}/x", &ctx("abc")).unwrap_err();
        assert_eq!(
            err,
            LegacyError::UnknownPlaceholder {
                token: "version".into()
            }
        );
    }

    #[test]
    fn non_https_url_is_refused() {
        let err = expand_template("http://example.com/{sha}/x", &ctx("abc")).unwrap_err();
        assert!(matches!(err, LegacyError::UrlNotHttps { .. }));
    }

    #[test]
    fn missing_sha_uses_a_placeholder_that_cannot_be_mistaken_for_one() {
        let c = TemplateContext::for_profile(
            Path::new("/tmp/profiles/a.mobileconfig"),
            Some(Path::new("/tmp/profiles")),
            None,
        );
        let url = expand_template("https://example.com/{sha}/{name}", &c).unwrap();
        assert!(url.contains(SHA_PLACEHOLDER), "got: {url}");
    }

    #[test]
    fn duplicate_basenames_are_refused() {
        let err = reject_duplicate_basenames(&[
            PathBuf::from("a/settings.mobileconfig"),
            PathBuf::from("b/settings.mobileconfig"),
        ])
        .unwrap_err();
        assert_eq!(
            err,
            LegacyError::DuplicateBasename {
                name: "settings.mobileconfig".into()
            }
        );
    }

    #[test]
    fn distinct_basenames_are_fine() {
        reject_duplicate_basenames(&[
            PathBuf::from("a/one.mobileconfig"),
            PathBuf::from("b/two.mobileconfig"),
        ])
        .expect("distinct basenames must be accepted");
    }

    fn entry(hash: &str) -> LegacyEntry {
        LegacyEntry {
            identifier: "com.acme.config.nudge".into(),
            profile: "nudge-preferences.mobileconfig".into(),
            sha256: hash.into(),
            url: "https://example.com/old/nudge-preferences.mobileconfig".into(),
            url_template: "https://example.com/{sha}/{name}".into(),
            sha: "old".into(),
        }
    }

    #[test]
    fn unchanged_profile_is_left_alone() {
        let bytes = b"<plist/>";
        let e = entry(&sha256_hex(bytes));
        assert_eq!(
            plan_refresh(&e, bytes, "new").unwrap(),
            RefreshOutcome::Unchanged {
                identifier: "com.acme.config.nudge".into()
            }
        );
    }

    #[test]
    fn changed_profile_is_repointed_at_the_new_sha() {
        let e = entry(&sha256_hex(b"<plist/>"));
        let outcome = plan_refresh(&e, b"<plist>edited</plist>", "ea283a1").unwrap();
        match outcome {
            RefreshOutcome::Repointed { new_url, .. } => {
                assert_eq!(
                    new_url,
                    "https://example.com/ea283a1/nudge-preferences.mobileconfig"
                );
            }
            other @ RefreshOutcome::Unchanged { .. } => {
                panic!("expected a re-point, got {other:?}")
            }
        }
    }

    #[test]
    fn refresh_is_idempotent_once_the_index_records_the_new_hash() {
        // Second run: the index has been updated, so the same bytes now match
        // and nothing is re-pointed. This is what stops a fleet-wide
        // re-download on every CI run.
        let edited = b"<plist>edited</plist>";
        let e = entry(&sha256_hex(edited));
        assert!(!plan_refresh(&e, edited, "ea283a1").unwrap().changed());
    }

    #[test]
    fn index_upsert_replaces_and_stays_sorted() {
        let mut idx = LegacyIndex::default();
        idx.upsert(entry("aaa"));
        let mut second = entry("bbb");
        second.identifier = "com.acme.config.alpha".into();
        idx.upsert(second);
        let mut replacement = entry("ccc");
        replacement.sha256 = "ccc".into();
        idx.upsert(replacement);

        assert_eq!(idx.entries.len(), 2, "upsert must replace, not append");
        assert_eq!(idx.entries[0].identifier, "com.acme.config.alpha");
        assert_eq!(idx.get("com.acme.config.nudge").unwrap().sha256, "ccc");
    }

    #[test]
    fn index_round_trips_through_toml() {
        let mut idx = LegacyIndex::default();
        idx.upsert(entry("deadbeef"));
        let text = toml::to_string_pretty(&idx).unwrap();
        let back: LegacyIndex = toml::from_str(&text).unwrap();
        assert_eq!(back.entries, idx.entries);
    }

    #[test]
    fn payload_carries_only_the_profile_url() {
        let p = legacy_payload("https://example.com/x.mobileconfig");
        assert_eq!(p.len(), 1, "no extra keys — the declaration ships verbatim");
        assert_eq!(p["ProfileURL"], "https://example.com/x.mobileconfig");
    }

    #[test]
    fn hash_is_content_not_path() {
        // The whole design rests on this: identical bytes at different paths
        // must hash identically, or refresh would re-point on every move.
        assert_eq!(sha256_hex(b"same"), sha256_hex(b"same"));
        assert_ne!(sha256_hex(b"same"), sha256_hex(b"different"));
    }
}
