//! The wasm face of `contour-form`.
//!
//! A separate crate so `contour-form` itself stays free of `wasm-bindgen`.
//! The ABI is JSON strings in both directions: one dependency, no
//! serialiser bridge to keep in step, and every value crosses the boundary
//! in the shape the contract already documents.
//!
//! The schema dataset is **not** compiled in. The host fetches the Parquet
//! tables as assets: `capabilities.parquet` goes to [`Registry::new`],
//! `source_versions.parquet` to [`Registry::set_provenance`]. A schema
//! refresh is a file swap, not a rebuild.

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
#[derive(Debug)]
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

    /// Supply the four mSCP tables so `form` attaches `annotations[]` to
    /// top-level keys: `rule_capability_links`, `baseline_edges`,
    /// `rule_meta`, `rule_control_edges` (`controls`), as bytes. Returns the
    /// number of annotated keys.
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

    /// Whether no payload types are loaded.
    #[wasm_bindgen(js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
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

    /// Fields ranked against a phrase ("turn off airdrop"), best first, as a
    /// JSON array of `{type_id, path, type, title, description, score}`. Only
    /// types a form can author.
    pub fn search(&self, query: &str, limit: usize) -> Result<String, JsError> {
        let hits: Vec<serde_json::Value> = self
            .inner
            .rank_fields(query)
            .into_iter()
            .filter(|h| h.manifest.is_authorable())
            .take(limit)
            .map(|h| {
                serde_json::json!({
                    "type_id": h.manifest.payload_type,
                    "path": h.field.path,
                    "type": h.field.field_type.as_str(),
                    "title": h.field.title,
                    "description": h.field.description,
                    "score": h.score,
                })
            })
            .collect();
        serde_json::to_string(&hits).map_err(err)
    }

    /// Diagnostics for `values_json` against `type_id`, as a JSON array.
    pub fn validate(&self, type_id: &str, values_json: &str) -> Result<String, JsError> {
        let values: serde_json::Value = serde_json::from_str(values_json).map_err(err)?;
        serde_json::to_string(&contour_form::validate(&self.inner, type_id, &values)).map_err(err)
    }

    /// What a session can start from, as JSON `{baselines, recipes, os_coverage}`:
    /// every macOS baseline with how much of it a profile can carry.
    /// `recipes` is empty: recipes are rendered by the native tools only.
    pub fn catalogue(&self) -> Result<String, JsError> {
        let baselines: Vec<serde_json::Value> = contour_form::mscp_rules::baselines()
            .iter()
            .filter_map(|name| contour_form::intent::sort_baseline(&self.inner, name).ok())
            .map(|b| {
                serde_json::json!({
                    "name": b.name,
                    "rules": b.rules,
                    "by_profile": b.by_profile.len(),
                    "not_by_profile": b.not_by_profile.len(),
                    "scripts": b.scripted,
                })
            })
            .collect();
        serde_json::to_string(&serde_json::json!({
            "baselines": baselines,
            "recipes": [],
            "os_coverage": contour_form::intent::os_coverage(),
        }))
        .map_err(err)
    }

    /// One baseline as JSON: its report (`by_profile`, `not_by_profile`,
    /// `not_in_schema`) plus `settings`, every setting a profile can carry.
    pub fn baseline(&self, name: &str) -> Result<String, JsError> {
        let sorted = contour_form::intent::sort_baseline(&self.inner, name).map_err(err)?;
        let mut report = sorted.report();
        report["settings"] = serde_json::to_value(&sorted.settings).map_err(err)?;
        serde_json::to_string(&report).map_err(err)
    }

    /// The remediation scripts of the baselines named in `baselines_json`
    /// (a JSON array), as a JSON array of `{filename, format, baseline,
    /// rule_id, title, body}`.
    pub fn scripts(&self, baselines_json: &str) -> Result<String, JsError> {
        let names: Vec<String> = serde_json::from_str(baselines_json).map_err(err)?;
        serde_json::to_string(&contour_form::intent::script_documents(&names)).map_err(err)
    }

    /// An intent, given as JSON, as the TOML text of an intent file.
    pub fn intent_to_toml(&self, intent_json: &str) -> Result<String, JsError> {
        let intent: contour_form::intent::Intent = serde_json::from_str(intent_json).map_err(err)?;
        intent.to_toml().map_err(err)
    }

    /// An intent file's TOML text as JSON.
    pub fn intent_from_toml(&self, text: &str) -> Result<String, JsError> {
        serde_json::to_string(&contour_form::intent::Intent::parse(text).map_err(err)?).map_err(err)
    }

    /// Step one of request-to-document: the candidate keys for `request`
    /// and the prompt for a model, as JSON `{system, user, schema, candidates}`.
    /// The host makes the model call, constraining the reply to `schema`
    /// where it can.
    pub fn ask_prepare(
        &self,
        request: &str,
        platform: Option<String>,
        limit: usize,
        prefer_declarations: bool,
    ) -> Result<String, JsError> {
        let opts = contour_form::ask::AskOptions {
            platform: platform_arg(platform)?,
            limit,
            prefer_declarations,
        };
        serde_json::to_string(&contour_form::ask::prepare(&self.inner, request, &opts)).map_err(err)
    }

    /// Step two: the model's `reply` against the `candidates_json` that
    /// `ask_prepare` returned. JSON with `outcome` of `documents`, `declined`,
    /// or `retry` (send `message` back to the model and resolve again).
    pub fn ask_resolve(
        &self,
        candidates_json: &str,
        reply: &str,
        org: &str,
        platform: Option<String>,
    ) -> Result<String, JsError> {
        let candidates: Vec<contour_form::ask::Candidate> =
            serde_json::from_str(candidates_json).map_err(err)?;
        let opts = EmitOptions {
            org: org.to_string(),
            platform: platform_arg(platform)?,
            ..Default::default()
        };
        serde_json::to_string(&contour_form::ask::resolve(&self.inner, &candidates, reply, &opts))
            .map_err(err)
    }

    /// Documents for a flat list of settings across payload types, as JSON
    /// `{documents, refused}`. `settings_json` is `[{type, path, value}]`;
    /// text values are typed from the schema, and every refusal says what
    /// would fix it.
    pub fn emit_settings(
        &self,
        settings_json: &str,
        org: &str,
        platform: Option<String>,
        os_version: Option<String>,
    ) -> Result<String, JsError> {
        let settings: Vec<contour_form::Setting> =
            serde_json::from_str(settings_json).map_err(err)?;
        let opts = EmitOptions {
            org: org.to_string(),
            platform: platform_arg(platform)?,
            os_version,
            ..Default::default()
        };
        serde_json::to_string(&contour_form::emit_settings(&self.inner, &settings, &opts))
            .map_err(err)
    }

    /// The deployable document(s) for `values_json`, as a JSON array of
    /// `{label?, identifier, filename, format, scope?, requirements, body}`.
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
