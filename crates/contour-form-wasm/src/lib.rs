//! The wasm face of `contour-form`.
//!
//! A separate crate so `contour-form` itself stays free of `wasm-bindgen`.
//! The ABI is JSON strings in both directions: one dependency, no
//! serialiser bridge to keep in step, and every value crosses the boundary
//! in the shape the contract already documents.
//!
//! The schema dataset is **not** compiled in. The host fetches the two
//! Parquet tables as assets and hands them to [`Registry::new`], so a
//! schema refresh is a file swap, not a rebuild.

use wasm_bindgen::prelude::*;

use contour_form::form::Target;
use contour_form::formspec::{Document, Nesting};
use contour_form::{EmitOptions, Platform, SchemaRegistry};

/// The contract version this module emits.
#[wasm_bindgen]
pub fn spec_version() -> String {
    contour_form::formspec::SPEC_VERSION.to_string()
}

/// A loaded schema registry.
#[wasm_bindgen]
pub struct Registry {
    inner: SchemaRegistry,
    annotations: Option<contour_form::Annotations>,
}

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn platform(p: Option<String>) -> Result<Option<Platform>, JsError> {
    match p {
        None => Ok(None),
        Some(s) => Platform::from_cli_str(&s)
            .map(Some)
            .ok_or_else(|| JsError::new(&format!("unknown platform '{s}'"))),
    }
}

#[wasm_bindgen]
impl Registry {
    /// `capabilities.parquet`, as bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(capabilities: &[u8]) -> Result<Registry, JsError> {
        Ok(Registry {
            inner: SchemaRegistry::from_parquet(capabilities).map_err(err)?,
            annotations: None,
        })
    }

    /// Supply `source_versions.parquet` so `source.upstream_ref` names the
    /// upstream commit each table came from.
    pub fn set_provenance(&mut self, source_versions: &[u8]) -> Result<usize, JsError> {
        let inner = std::mem::replace(&mut self.inner, SchemaRegistry::from_manifests(Vec::new()));
        self.inner = inner.with_provenance(source_versions).map_err(err)?;
        Ok(self.inner.provenance().len())
    }

    /// Supply the three mSCP tables so `form` attaches `annotations[]` to
    /// top-level keys: `rule_capability_links`, `baseline_edges`,
    /// `rule_meta`, as bytes. Returns the number of annotated keys.
    pub fn annotate(
        &mut self,
        links: &[u8],
        edges: &[u8],
        meta: &[u8],
        controls: &[u8],
    ) -> Result<usize, JsError> {
        let a = contour_form::Annotations::from_parquet_with_controls(links, edges, meta, controls)
            .map_err(err)?;
        let n = a.len();
        self.annotations = Some(a);
        Ok(n)
    }

    /// Number of payload types loaded.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// One FormSpec, as JSON.
    pub fn form(
        &self,
        type_id: &str,
        platform: Option<String>,
        os_version: Option<String>,
    ) -> Result<String, JsError> {
        let target = Target {
            platform: platform_arg(platform)?,
            os_version,
        };
        let spec =
            contour_form::form_with(&self.inner, type_id, &target, self.annotations.as_ref())
                .map_err(err)?;
        serde_json::to_string(&spec).map_err(err)
    }

    /// Every authorable type, as a FormSpec v1 `Document` in JSON.
    pub fn form_all(
        &self,
        platform: Option<String>,
        os_version: Option<String>,
    ) -> Result<String, JsError> {
        let target = Target {
            platform: platform_arg(platform)?,
            os_version,
        };
        let specs = contour_form::form_all_with(&self.inner, &target, self.annotations.as_ref())
            .into_iter()
            .filter_map(Result::ok)
            .collect();
        serde_json::to_string(&Document::new(specs, None)).map_err(err)
    }

    /// An existing declaration or .mobileconfig (bytes) back into values,
    /// as a JSON array of `{type_id, spec, values, envelope, root?, nesting?, scope?}`.
    pub fn parse(&self, document: &[u8], platform: Option<String>) -> Result<String, JsError> {
        let target = Target {
            platform: platform_arg(platform)?,
            os_version: None,
        };
        let parsed = contour_form::parse(&self.inner, document, &target).map_err(err)?;
        serde_json::to_string(&parsed).map_err(err)
    }

    /// Diagnostics for `values_json` against `type_id`, as a JSON array.
    pub fn validate(&self, type_id: &str, values_json: &str) -> Result<String, JsError> {
        let values: serde_json::Value = serde_json::from_str(values_json).map_err(err)?;
        serde_json::to_string(&contour_form::validate(&self.inner, type_id, &values)).map_err(err)
    }

    /// The deployable document(s) for `values_json`, as a JSON array of
    /// `{label?, identifier, filename, format, scope?, body}`.
    pub fn emit(
        &self,
        type_id: &str,
        values_json: &str,
        org: &str,
        intent: &str,
        platform: Option<String>,
        nesting: Option<String>,
        os_version: Option<String>,
    ) -> Result<String, JsError> {
        let values: serde_json::Value = serde_json::from_str(values_json).map_err(err)?;
        let opts = EmitOptions {
            org: org.to_string(),
            intent: intent.to_string(),
            format: None,
            nesting: match nesting.as_deref() {
                None => None,
                Some("mcx") => Some(Nesting::McxWrapped),
                Some("direct") => Some(Nesting::Direct),
                Some(other) => {
                    return Err(JsError::new(&format!(
                        "nesting must be 'mcx' or 'direct', got '{other}'"
                    )));
                }
            },
            platform: platform_arg(platform)?,
            // With a platform, a key Apple removed by this version is refused
            // rather than written into a document the device ignores.
            os_version,
            display_name: None,
        };
        let docs = contour_form::emit(&self.inner, type_id, &values, &opts).map_err(err)?;
        serde_json::to_string(&docs).map_err(err)
    }
}

fn platform_arg(p: Option<String>) -> Result<Option<Platform>, JsError> {
    platform(p)
}
