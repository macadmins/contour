//! Recipe data model for multi-profile generation.
//!
//! Recipes define bundles of related profiles (e.g., Okta SSO setup)
//! that can be generated together from a single command.

pub mod loader;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A recipe defines a bundle of related profiles to generate together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    pub recipe: RecipeMeta,
    #[serde(rename = "profile")]
    pub profiles: Vec<ProfileSpec>,
}

/// Recipe metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeMeta {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub vendor: Option<String>,
    /// Required variables that must be set via `--set KEY=VALUE`.
    /// If present (even empty), only listed vars are shown as required.
    /// If absent, all `{{...}}` placeholders are auto-discovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<Vec<String>>,
    /// Secret variables that should come from `op://`, `env:`, or `file:` sources.
    /// Advisory — shown in `--list-recipes` with `op://` hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
}

/// Specification for a single profile within a recipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSpec {
    pub filename: String,
    pub payload_type: String,
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub removal_disallowed: bool,
    /// Field overrides matching schema field names
    #[serde(default)]
    pub fields: HashMap<String, toml::Value>,
    /// Extra fields NOT in schema (vendor-specific, dot notation for nesting)
    #[serde(default)]
    pub extra_fields: HashMap<String, toml::Value>,
}
