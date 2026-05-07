//! Recipe loader with embedded and external recipe support.

use super::Recipe;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Embedded recipes compiled into the binary.
const EMBEDDED_OKTA: &str = include_str!("../../recipes/okta.toml");
const EMBEDDED_ENTRA_PSSO: &str = include_str!("../../recipes/entra-psso.toml");
const EMBEDDED_SANTA: &str = include_str!("../../recipes/santa.toml");
const EMBEDDED_HARDENING_MACOS: &str = include_str!("../../recipes/hardening-macos-baseline.toml");

/// Built-in recipes as `(name, raw TOML body)`. Single source of truth
/// for both `load_recipe` (embedded fallback) and `list_recipes`
/// (embedded enumeration). Adding a recipe here also flows into the
/// library scaffolder via the same slice.
pub const EMBEDDED_RECIPES: &[(&str, &str)] = &[
    ("okta", EMBEDDED_OKTA),
    ("entra-psso", EMBEDDED_ENTRA_PSSO),
    ("santa", EMBEDDED_SANTA),
    ("hardening-macos-baseline", EMBEDDED_HARDENING_MACOS),
];

/// Summary of an available recipe.
#[derive(Debug)]
pub struct RecipeSummary {
    pub name: String,
    pub description: String,
    pub vendor: Option<String>,
    pub profile_count: usize,
    pub source: String,
    pub placeholders: Vec<String>,
    pub secrets: Vec<String>,
}

/// Load a recipe by name, checking external paths first, then embedded.
/// Resolve a CLI `--recipe` value to a loaded recipe and its
/// canonical name. Accepts either:
///
/// - a **file path** (`./recipes/crowdstrike.toml`,
///   `/abs/path/to.toml`) — loaded directly, name taken from
///   `[recipe].name`
/// - a **bare name** (`crowdstrike`) — resolved through the standard
///   3-tier lookup (`--recipe-path` → `~/.contour/recipes/` →
///   embedded)
///
/// The selector is treated as a path when it contains a `/`, ends
/// with `.toml`, or `Path::is_file()` returns true. Names that
/// happen to share characters with paths still resolve correctly
/// because the bare-name path is a fallback.
pub fn load_recipe_smart(selector: &str, recipe_path: Option<&str>) -> Result<(String, Recipe)> {
    let p = Path::new(selector);
    let looks_path = selector.contains('/') || selector.ends_with(".toml") || p.is_file();
    if looks_path {
        if !p.is_file() {
            anyhow::bail!(
                "Recipe path '{selector}' is not a file. Pass a `.toml` path or a bare recipe name (use `--list-recipes` to see options)."
            );
        }
        let recipe = load_recipe_file(p)?;
        let name = recipe.recipe.name.clone();
        return Ok((name, recipe));
    }
    let recipe = load_recipe(selector, recipe_path)?;
    Ok((selector.to_string(), recipe))
}

pub fn load_recipe(name: &str, recipe_path: Option<&str>) -> Result<Recipe> {
    // 1. Explicit path (file or directory)
    if let Some(rp) = recipe_path {
        let path = Path::new(rp);
        if path.is_file() {
            return load_recipe_file(path);
        }
        if path.is_dir() {
            let file = path.join(format!("{name}.toml"));
            if file.exists() {
                return load_recipe_file(&file);
            }
        }
    }

    // 2. ~/.contour/recipes/
    if let Some(home) = dirs::home_dir() {
        let user_recipe = home.join(".contour/recipes").join(format!("{name}.toml"));
        if user_recipe.exists() {
            return load_recipe_file(&user_recipe);
        }
    }

    // 3. Embedded
    if let Some((_, body)) = EMBEDDED_RECIPES.iter().find(|(n, _)| *n == name) {
        return parse_recipe_toml(body, "embedded");
    }
    anyhow::bail!(
        "Recipe '{name}' not found.\nUse 'contour profile generate --list-recipes' to see available recipes."
    );
}

/// List all available recipes (external + embedded).
///
/// External recipes win when names collide with built-ins — symmetric
/// with `load_recipe`'s precedence (explicit path → `~/.contour/recipes/`
/// → embedded). When an external recipe shadows a built-in, its
/// `source` label includes `"(overrides embedded)"` so the override is
/// visible.
///
/// Output is sorted by recipe name for deterministic listing.
pub fn list_recipes(recipe_path: Option<&str>) -> Vec<RecipeSummary> {
    let mut recipes: Vec<RecipeSummary> = Vec::new();
    let embedded_names: std::collections::HashSet<&str> =
        EMBEDDED_RECIPES.iter().map(|(n, _)| *n).collect();

    // 1. External from explicit --recipe-path (highest precedence)
    if let Some(rp) = recipe_path {
        collect_external_recipes(Path::new(rp), &mut recipes, &embedded_names);
    }

    // 2. External from ~/.contour/recipes/ — skip names already in #1
    if let Some(home) = dirs::home_dir() {
        let user_dir = home.join(".contour/recipes");
        if user_dir.is_dir() {
            collect_external_recipes(&user_dir, &mut recipes, &embedded_names);
        }
    }

    // 3. Embedded — only when no external entry has shadowed the name.
    for (_, toml_str) in EMBEDDED_RECIPES {
        let Ok(r) = parse_recipe_toml(toml_str, "embedded") else {
            continue;
        };
        if recipes.iter().any(|x| x.name == r.recipe.name) {
            continue;
        }
        let placeholders = recipe_placeholders(&r);
        let secrets = r.recipe.secrets.clone().unwrap_or_default();
        recipes.push(RecipeSummary {
            name: r.recipe.name,
            description: r.recipe.description,
            vendor: r.recipe.vendor,
            profile_count: r.profiles.len(),
            source: "embedded".to_string(),
            placeholders,
            secrets,
        });
    }

    recipes.sort_by(|a, b| a.name.cmp(&b.name));
    recipes
}

/// Get required placeholders for a recipe.
/// Uses the declared `[recipe.variables]` if present, otherwise scans all `{{...}}`.
fn recipe_placeholders(recipe: &Recipe) -> Vec<String> {
    match &recipe.recipe.variables {
        Some(vars) => vars.clone(),
        None => extract_placeholders(recipe),
    }
}

/// Extract `{{...}}` placeholders from all string values in a recipe (fallback scanner).
fn extract_placeholders(recipe: &Recipe) -> Vec<String> {
    let mut placeholders = Vec::new();
    let toml_str = toml::to_string(recipe).unwrap_or_default();
    let mut pos = 0;
    let bytes = toml_str.as_bytes();
    while pos + 3 < bytes.len() {
        if bytes[pos] == b'{' && bytes[pos + 1] == b'{' {
            if let Some(end) = toml_str[pos + 2..].find("}}") {
                let name = &toml_str[pos + 2..pos + 2 + end];
                let name = name.to_string();
                if !placeholders.contains(&name) {
                    placeholders.push(name);
                }
                pos += 2 + end + 2;
                continue;
            }
        }
        pos += 1;
    }
    placeholders
}

fn load_recipe_file(path: &Path) -> Result<Recipe> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read recipe file: {}", path.display()))?;
    parse_recipe_toml(&content, &path.display().to_string())
}

fn parse_recipe_toml(content: &str, source: &str) -> Result<Recipe> {
    toml::from_str(content).with_context(|| format!("Failed to parse recipe from {source}"))
}

/// Walk a directory of `.toml` recipes, appending each to `recipes`.
///
/// Skips names already present in `recipes` (so the explicit
/// `--recipe-path` wins over `~/.contour/recipes/`).
///
/// When a recipe's name matches a built-in, the source label flags
/// the override so listings make the shadowing obvious.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_with_no_external_returns_only_embedded() {
        let recipes = list_recipes(None);
        // Anchor on the embedded slice — no manual count drift when a
        // new built-in lands.
        assert_eq!(recipes.len(), EMBEDDED_RECIPES.len());
        for r in &recipes {
            assert_eq!(r.source, "embedded");
        }
        // Sorted alphabetically.
        let mut expected: Vec<&str> = EMBEDDED_RECIPES.iter().map(|(n, _)| *n).collect();
        expected.sort_unstable();
        let names: Vec<&str> = recipes.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, expected);
    }

    /// Minimal but well-formed Recipe TOML matching the `[[profile]]`
    /// shape — see `crates/profile/recipes/okta.toml` for reference.
    fn override_okta_body() -> &'static str {
        r#"
[recipe]
name = "okta"
description = "user-overridden okta recipe"
vendor = "MyOrg"

[[profile]]
filename = "custom-okta.mobileconfig"
payload_type = "com.apple.extensiblesso"
display_name = "Custom Okta"
description = "User override"

[profile.fields]
Type = "Redirect"
TeamIdentifier = "DEADBEEF"
ExtensionIdentifier = "com.okta.mobile.auth-service-extension"
"#
    }

    #[test]
    fn external_recipe_overrides_embedded_in_listing() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("okta.toml"), override_okta_body()).unwrap();
        let listed = list_recipes(Some(tmp.path().to_str().unwrap()));
        let okta = listed.iter().find(|r| r.name == "okta").unwrap();
        assert!(
            okta.source.contains("overrides embedded"),
            "external recipe must claim override label; source={}",
            okta.source
        );
        assert_eq!(okta.description, "user-overridden okta recipe");
        assert_eq!(
            listed.iter().filter(|r| r.name == "okta").count(),
            1,
            "exactly one okta entry — external must shadow embedded"
        );
    }

    #[test]
    fn external_recipe_loads_from_explicit_path() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("okta.toml"), override_okta_body()).unwrap();
        let r = load_recipe("okta", Some(tmp.path().to_str().unwrap())).unwrap();
        assert_eq!(r.recipe.description, "user-overridden okta recipe");
    }
}

fn collect_external_recipes(
    dir: &Path,
    recipes: &mut Vec<RecipeSummary>,
    embedded_names: &std::collections::HashSet<&str>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    paths.sort();

    for path in paths {
        let Ok(r) = load_recipe_file(&path) else {
            continue;
        };
        // Higher-priority external entry already claimed this name.
        if recipes.iter().any(|x| x.name == r.recipe.name) {
            continue;
        }
        let mut source = path.display().to_string();
        if embedded_names.contains(r.recipe.name.as_str()) {
            source.push_str("  (overrides embedded)");
        }
        let placeholders = recipe_placeholders(&r);
        let secrets = r.recipe.secrets.clone().unwrap_or_default();
        recipes.push(RecipeSummary {
            name: r.recipe.name,
            description: r.recipe.description,
            vendor: r.recipe.vendor,
            profile_count: r.profiles.len(),
            source,
            placeholders,
            secrets,
        });
    }
}
