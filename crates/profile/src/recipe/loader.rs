//! Recipe loader with embedded and external recipe support.

use super::Recipe;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Embedded recipes compiled into the binary.
const EMBEDDED_OKTA: &str = include_str!("../../recipes/okta.toml");
const EMBEDDED_ENTRA_PSSO: &str = include_str!("../../recipes/entra-psso.toml");
const EMBEDDED_SANTA: &str = include_str!("../../recipes/santa.toml");

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
    match name {
        "okta" => parse_recipe_toml(EMBEDDED_OKTA, "embedded"),
        "entra-psso" => parse_recipe_toml(EMBEDDED_ENTRA_PSSO, "embedded"),
        "santa" => parse_recipe_toml(EMBEDDED_SANTA, "embedded"),
        _ => anyhow::bail!(
            "Recipe '{name}' not found.\nUse 'contour profile generate --list-recipes' to see available recipes."
        ),
    }
}

/// List all available recipes (embedded + external).
pub fn list_recipes(recipe_path: Option<&str>) -> Vec<RecipeSummary> {
    let mut recipes = Vec::new();

    // Embedded recipes
    for (toml_str, label) in [
        (EMBEDDED_OKTA, "embedded"),
        (EMBEDDED_ENTRA_PSSO, "embedded"),
        (EMBEDDED_SANTA, "embedded"),
    ] {
        if let Ok(r) = parse_recipe_toml(toml_str, label) {
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
    }

    // External recipes from explicit path
    if let Some(rp) = recipe_path {
        collect_external_recipes(Path::new(rp), &mut recipes);
    }

    // External recipes from ~/.contour/recipes/
    if let Some(home) = dirs::home_dir() {
        let user_dir = home.join(".contour/recipes");
        if user_dir.is_dir() {
            collect_external_recipes(&user_dir, &mut recipes);
        }
    }

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

fn collect_external_recipes(dir: &Path, recipes: &mut Vec<RecipeSummary>) {
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
        if let Ok(r) = load_recipe_file(&path) {
            // Skip if already present (embedded takes precedence for same name)
            if recipes
                .iter()
                .any(|existing| existing.name == r.recipe.name)
            {
                continue;
            }
            let placeholders = recipe_placeholders(&r);
            let secrets = r.recipe.secrets.clone().unwrap_or_default();
            recipes.push(RecipeSummary {
                name: r.recipe.name,
                description: r.recipe.description,
                vendor: r.recipe.vendor,
                profile_count: r.profiles.len(),
                source: path.display().to_string(),
                placeholders,
                secrets,
            });
        }
    }
}
