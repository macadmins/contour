//! Recipe data model for multi-profile generation.
//!
//! Recipes define bundles of related profiles (e.g., Okta SSO setup)
//! that can be generated together from a single command.

pub mod loader;

use crate::ddm::compose::Bundle;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A recipe defines a bundle of related profiles to generate together.
///
/// Optional `[[ddm]]` blocks let a single recipe emit DDM declarations
/// alongside its mobileconfig profiles — used for hardening/baseline
/// intents that need both delivery channels (e.g. the embedded
/// `hardening-macos-baseline`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    pub recipe: RecipeMeta,
    #[serde(rename = "profile", default)]
    pub profiles: Vec<ProfileSpec>,
    /// DDM bundles emitted under `<output_dir>/<intent_name>/` per
    /// entry. Same shape as a standalone DDM preset bundle.
    #[serde(rename = "ddm", default, skip_serializing_if = "Vec::is_empty")]
    pub ddm: Vec<Bundle>,
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
    /// Field overrides matching schema field names.
    ///
    /// `BTreeMap` (not `HashMap`) so iteration is sorted and serialized
    /// output is byte-stable across runs — without this, every CI
    /// regeneration produces a spurious diff from re-ordered keys
    /// (semantically harmless since Apple parses dicts by key, not
    /// position, but creates churn).
    #[serde(default)]
    pub fields: BTreeMap<String, toml::Value>,
    /// Extra fields NOT in schema (vendor-specific, dot notation for nesting).
    /// Same `BTreeMap` rationale as `fields`.
    #[serde(default)]
    pub extra_fields: BTreeMap<String, toml::Value>,
}
