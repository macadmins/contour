//! DDM presets — embedded TOML bundles + external library support.
//!
//! Mirror of the `--recipe` pattern for MDM mobileconfig generation:
//! end users reach common authoring intents by name via
//! `contour profile ddm compose --preset <NAME>` — no source-tree path
//! needed.
//!
//! ## Library extensibility
//!
//! Anyone can build a preset library: just a directory of `.toml`
//! bundle files (one preset per file, filename = preset name). Point
//! contour at it via `--preset-path <DIR>` or drop files into
//! `~/.contour/presets/`. Resolution order:
//!
//! 1. Explicit `--preset-path` (file or directory)
//! 2. `~/.contour/presets/`
//! 3. Embedded (this file's `EMBEDDED` table)
//!
//! External presets win on name collisions — users can override
//! built-ins. Listings flag overrides via the `source` field
//! (`"<path>  (overrides embedded)"`).
//!
//! ## Adding a built-in preset
//!
//! 1. Drop the TOML in `crates/profile/recipes/ddm/<name>.toml`
//! 2. Add a `(name, description, include_str!(...))` row to `EMBEDDED`.
//! 3. Add a trap covering the embedded preset's intent.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Built-in DDM presets — `(name, short description, embedded TOML body)`.
///
/// Names match the TOML filename (without `.toml`). Sorted alphabetically.
pub const EMBEDDED: &[(&str, &str, &str)] = &[
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

/// Listing entry returned by [`list`]. Fields are agent-friendly so JSON
/// output can stream straight from the iterator.
#[derive(Debug, Clone)]
pub struct PresetSummary {
    /// Preset name (filename without `.toml`).
    pub name: String,
    /// Short human-readable description (first comment block of the TOML
    /// for external presets, or the embedded description text).
    pub description: String,
    /// Origin label: `"embedded"`, an absolute path, or
    /// `"<path>  (overrides embedded)"` when an external preset shadows
    /// a built-in.
    pub source: String,
}

/// Resolve a preset by name and return its TOML body.
///
/// Resolution order: explicit `preset_path` (file or directory) →
/// `~/.contour/presets/` → embedded. Returns owned `String` because
/// external file contents aren't `'static`.
pub fn load(name: &str, preset_path: Option<&str>) -> Option<String> {
    // 1. Explicit --preset-path (file or directory)
    if let Some(rp) = preset_path {
        let path = Path::new(rp);
        if path.is_file()
            && path.file_stem().and_then(|s| s.to_str()) == Some(name)
            && path.extension().and_then(|s| s.to_str()) == Some("toml")
            && let Ok(s) = std::fs::read_to_string(path)
        {
            return Some(s);
        }
        if path.is_dir() {
            let f = path.join(format!("{name}.toml"));
            if f.exists()
                && let Ok(s) = std::fs::read_to_string(&f)
            {
                return Some(s);
            }
        }
    }

    // 2. ~/.contour/presets/
    if let Some(home) = dirs::home_dir() {
        let f = home.join(".contour/presets").join(format!("{name}.toml"));
        if f.exists()
            && let Ok(s) = std::fs::read_to_string(&f)
        {
            return Some(s);
        }
    }

    // 3. Embedded
    EMBEDDED
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, _, body)| (*body).to_string())
}

/// List every available preset (external + embedded), sorted by name.
///
/// External entries shadow embedded ones on name collisions; the
/// `source` label includes `"(overrides embedded)"` so the shadowing
/// is visible in listings.
pub fn list(preset_path: Option<&str>) -> Vec<PresetSummary> {
    let mut presets: Vec<PresetSummary> = Vec::new();
    let embedded_names: HashSet<&str> = EMBEDDED.iter().map(|(n, _, _)| *n).collect();

    // 1. External from explicit --preset-path (highest precedence)
    if let Some(rp) = preset_path {
        collect_external(Path::new(rp), &mut presets, &embedded_names);
    }

    // 2. External from ~/.contour/presets/
    if let Some(home) = dirs::home_dir() {
        let user_dir = home.join(".contour/presets");
        if user_dir.is_dir() {
            collect_external(&user_dir, &mut presets, &embedded_names);
        }
    }

    // 3. Embedded — only when no external entry has claimed the name.
    for (name, desc, _body) in EMBEDDED {
        if presets.iter().any(|p| p.name == *name) {
            continue;
        }
        presets.push(PresetSummary {
            name: (*name).to_string(),
            description: (*desc).to_string(),
            source: "embedded".to_string(),
        });
    }

    presets.sort_by(|a, b| a.name.cmp(&b.name));
    presets
}

/// Walk a directory of `.toml` presets and append entries to `presets`.
///
/// Skips names already present (so explicit `--preset-path` wins over
/// `~/.contour/presets/`). Source label includes
/// `"(overrides embedded)"` when a preset shadows a built-in.
fn collect_external(dir: &Path, presets: &mut Vec<PresetSummary>, embedded_names: &HashSet<&str>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("toml"))
        .collect();
    paths.sort();
    for path in paths {
        let Some(stem) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if presets.iter().any(|p| p.name == stem) {
            continue;
        }
        let description = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| extract_leading_description(&s))
            .unwrap_or_else(|| "(no description)".to_string());
        let mut source = path.display().to_string();
        if embedded_names.contains(stem.as_str()) {
            source.push_str("  (overrides embedded)");
        }
        presets.push(PresetSummary {
            name: stem,
            description,
            source,
        });
    }
}

/// Pull the first meaningful comment block from the top of a TOML file
/// as a description. Stops at the first non-comment, non-blank line.
fn extract_leading_description(toml_body: &str) -> Option<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in toml_body.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            if lines.is_empty() {
                continue;
            }
            break;
        }
        if let Some(rest) = trimmed.strip_prefix('#') {
            let cleaned = rest.trim_start_matches([' ', '#']).trim_end();
            if !cleaned.is_empty() {
                lines.push(cleaned.to_string());
            }
        } else {
            break;
        }
    }
    if lines.is_empty() {
        None
    } else {
        let joined = lines.join(" ");
        let snippet: String = joined.chars().take(200).collect();
        Some(snippet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_presets_parse_as_bundles() {
        for (name, _desc, body) in EMBEDDED {
            let bundle: crate::ddm::compose::Bundle = toml::from_str(body)
                .unwrap_or_else(|e| panic!("preset '{name}' fails to parse as Bundle: {e}"));
            assert!(
                !bundle.intent_name.is_empty(),
                "preset '{name}' has empty intent_name"
            );
        }
    }

    #[test]
    fn load_returns_embedded_when_no_external() {
        assert!(load("disable-apple-intelligence-macos", None).is_some());
        assert!(load("nope-unknown", None).is_none());
    }

    #[test]
    fn list_returns_all_embedded_when_no_external_path() {
        let presets = list(None);
        assert_eq!(presets.len(), EMBEDDED.len());
        let names: Vec<&str> = presets.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "disable-apple-intelligence-ios",
                "disable-apple-intelligence-macos"
            ]
        );
        for p in &presets {
            assert_eq!(p.source, "embedded");
        }
    }

    #[test]
    fn external_preset_overrides_embedded() {
        let tmp = tempfile::tempdir().unwrap();
        let body = r#"
intent_name = "test-override"

[configuration]
type = "com.apple.configuration.intelligence.settings"

  [configuration.payload]
  AllowGenmoji = false
"#;
        std::fs::write(
            tmp.path().join("disable-apple-intelligence-macos.toml"),
            body,
        )
        .unwrap();
        let path_str = tmp.path().to_str().unwrap();

        let loaded = load("disable-apple-intelligence-macos", Some(path_str)).unwrap();
        assert!(
            loaded.contains("test-override"),
            "external preset must win on load: got {loaded:?}"
        );

        let listed = list(Some(path_str));
        let entry = listed
            .iter()
            .find(|p| p.name == "disable-apple-intelligence-macos")
            .unwrap();
        assert!(
            entry.source.contains("overrides embedded"),
            "override label missing: source={}",
            entry.source
        );
    }

    #[test]
    fn extract_description_pulls_first_comment_block() {
        let toml = "# First line of description.\n\
                    # Continues on second line.\n\
                    \n\
                    # Should NOT be included (separated).\n\
                    intent_name = \"x\"\n";
        let desc = extract_leading_description(toml).unwrap();
        assert!(desc.starts_with("First line"));
        assert!(desc.contains("Continues"));
        assert!(!desc.contains("Should NOT"));
    }
}
