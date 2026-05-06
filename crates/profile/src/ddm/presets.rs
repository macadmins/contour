//! Built-in DDM presets — TOML bundles embedded in the binary.
//!
//! Mirror of the `--recipe` pattern for MDM mobileconfig generation:
//! end users (who only have the binary, no source tree) reach common
//! authoring intents by name via
//! `contour profile ddm compose --preset <NAME>`.
//!
//! Each preset is a `ddm compose` bundle TOML embedded at compile time
//! via `include_str!`. The composer parses the embedded body the same
//! way it parses a user-supplied bundle — no special-case logic in the
//! compose pipeline.
//!
//! Adding a new preset:
//! 1. Drop the TOML in `crates/profile/recipes/ddm/<name>.toml`
//! 2. Add a `(name, description, include_str!(...))` row to `PRESETS`.
//! 3. Add a trap covering the embedded preset's intent.

/// All built-in DDM presets — `(name, short description, embedded TOML body)`.
///
/// Names match the TOML filename (without `.toml`). Sorted alphabetically.
pub const PRESETS: &[(&str, &str, &str)] = &[
    (
        "disable-apple-intelligence-ios",
        "Disable Apple Intelligence on iOS / iPadOS (intelligence.settings)",
        include_str!("../../recipes/ddm/disable-apple-intelligence-ios.toml"),
    ),
    (
        "disable-apple-intelligence-macos",
        "Disable Apple Intelligence on macOS (intelligence.settings)",
        include_str!("../../recipes/ddm/disable-apple-intelligence-macos.toml"),
    ),
];

/// Look up a preset's TOML body by name. Returns `None` for unknown names.
pub fn body(name: &str) -> Option<&'static str> {
    PRESETS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, _, b)| *b)
}

/// Iterate preset metadata for `--list-presets`.
pub fn list() -> impl Iterator<Item = (&'static str, &'static str)> {
    PRESETS.iter().map(|(n, d, _)| (*n, *d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_load_and_parse() {
        for (name, _desc, body) in PRESETS {
            let bundle: crate::ddm::compose::Bundle = toml::from_str(body)
                .unwrap_or_else(|e| panic!("preset '{name}' fails to parse as Bundle: {e}"));
            assert!(
                !bundle.intent_name.is_empty(),
                "preset '{name}' has empty intent_name"
            );
        }
    }

    #[test]
    fn presets_lookup_returns_known_name() {
        assert!(body("disable-apple-intelligence-macos").is_some());
        assert!(body("nope-unknown").is_none());
    }

    #[test]
    fn list_returns_all_presets() {
        let count = list().count();
        assert_eq!(count, PRESETS.len());
    }
}
