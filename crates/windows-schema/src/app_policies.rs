//! Parquet reader for third-party app policies (`windows_app_policies`).
//!
//! One row per (template, policy, element) in the file; one
//! [`WindowsAppPolicy`] per (template, policy) out, elements in document
//! order — the order a payload lists them in. Zero-length bytes read as no
//! policies: the table is optional in the build, and a dataset without it
//! carries a placeholder.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::{AdmxElement, AdmxEnumItem, WindowsAppPolicy};

fn col<'a>(
    batch: &'a arrow::record_batch::RecordBatch,
    name: &str,
) -> Result<&'a arrow::array::ArrayRef> {
    batch
        .column_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("missing column '{name}' in Parquet schema"))
}

fn opt_str(arr: &arrow::array::StringArray, row: usize) -> Option<String> {
    if arr.is_null(row) {
        None
    } else {
        Some(arr.value(row).to_string())
    }
}

/// Read the table. Empty bytes are an empty table, not an error.
pub fn read(bytes: &[u8]) -> Result<Vec<WindowsAppPolicy>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building windows_app_policies Parquet reader")?;
    let mut policies: BTreeMap<(String, String), WindowsAppPolicy> = BTreeMap::new();
    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let s = |name: &str| -> Result<&arrow::array::StringArray> {
            Ok(col(&batch, name)?.as_string::<i32>())
        };
        let templates = s("template")?;
        let app_names = s("app_name")?;
        let vendors = s("vendor")?;
        let provenances = s("provenance")?;
        let source_labels = s("source_label")?;
        let source_urls = s("source_url")?;
        let admx_files = s("admx_file")?;
        let policy_names = s("policy_name")?;
        let classes = s("class")?;
        let category_paths = s("category_path")?;
        let areas = s("area")?;
        let device_uris = s("device_loc_uri")?;
        let user_uris = s("user_loc_uri")?;
        let install_uris = s("admx_install_loc_uri")?;
        let supported_ons = s("supported_on")?;
        let registry_keys = s("registry_key")?;
        let registry_values = s("registry_value")?;
        let enabled_values = s("enabled_value")?;
        let disabled_values = s("disabled_value")?;
        let display_names = s("display_name")?;
        let explain_texts = s("explain_text")?;
        let ingestables = col(&batch, "ingestable")?.as_boolean();
        let ingest_reasons = s("ingest_reason")?;
        let ingest_evidences = s("ingest_evidence")?;
        let in_box_areas = s("in_box_area")?;
        let element_ids = s("element_id")?;
        let element_kinds = s("element_kind")?;
        let element_labels = s("element_label")?;
        let element_required = col(&batch, "element_required")?.as_boolean();
        let element_mins =
            col(&batch, "element_min")?.as_primitive::<arrow::datatypes::Float64Type>();
        let element_maxs =
            col(&batch, "element_max")?.as_primitive::<arrow::datatypes::Float64Type>();
        let element_max_lengths =
            col(&batch, "element_max_length")?.as_primitive::<arrow::datatypes::UInt32Type>();
        let element_true_values = s("element_true_value")?;
        let element_false_values = s("element_false_value")?;
        let element_explicit = col(&batch, "element_explicit_value")?.as_boolean();
        let element_items = s("element_items")?;
        let element_value_names = s("element_value_name")?;
        let element_keys = s("element_key")?;

        for row in 0..batch.num_rows() {
            let id = (
                templates.value(row).to_string(),
                policy_names.value(row).to_string(),
            );
            let policy = policies.entry(id).or_insert_with(|| WindowsAppPolicy {
                template: templates.value(row).to_string(),
                app_name: app_names.value(row).to_string(),
                vendor: vendors.value(row).to_string(),
                provenance: provenances.value(row).to_string(),
                source_label: source_labels.value(row).to_string(),
                source_url: source_urls.value(row).to_string(),
                admx_file: admx_files.value(row).to_string(),
                policy_name: policy_names.value(row).to_string(),
                class: classes.value(row).to_string(),
                category_path: category_paths.value(row).to_string(),
                area: areas.value(row).to_string(),
                device_loc_uri: device_uris.value(row).to_string(),
                user_loc_uri: user_uris.value(row).to_string(),
                admx_install_loc_uri: install_uris.value(row).to_string(),
                supported_on: opt_str(supported_ons, row),
                registry_key: opt_str(registry_keys, row),
                registry_value: opt_str(registry_values, row),
                enabled_value: opt_str(enabled_values, row),
                disabled_value: opt_str(disabled_values, row),
                display_name: opt_str(display_names, row),
                explain_text: opt_str(explain_texts, row),
                ingestable: !ingestables.is_null(row) && ingestables.value(row),
                ingest_reason: opt_str(ingest_reasons, row),
                ingest_evidence: ingest_evidences.value(row).to_string(),
                in_box_area: opt_str(in_box_areas, row),
                elements: Vec::new(),
            });
            let Some(element_id) = opt_str(element_ids, row) else {
                continue;
            };
            let items = opt_str(element_items, row)
                .map(|json| {
                    serde_json::from_str::<Vec<AdmxEnumItem>>(&json)
                        .with_context(|| format!("parsing element_items for {element_id}"))
                })
                .transpose()?
                .unwrap_or_default();
            policy.elements.push(AdmxElement {
                id: element_id,
                kind: opt_str(element_kinds, row).unwrap_or_default(),
                label: opt_str(element_labels, row),
                required: (!element_required.is_null(row)).then(|| element_required.value(row)),
                min: (!element_mins.is_null(row)).then(|| element_mins.value(row)),
                max: (!element_maxs.is_null(row)).then(|| element_maxs.value(row)),
                max_length: (!element_max_lengths.is_null(row))
                    .then(|| element_max_lengths.value(row)),
                true_value: opt_str(element_true_values, row),
                false_value: opt_str(element_false_values, row),
                explicit_value: (!element_explicit.is_null(row))
                    .then(|| element_explicit.value(row)),
                items,
                value_name: opt_str(element_value_names, row),
                key: opt_str(element_keys, row),
            });
        }
    }
    Ok(policies.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_read_as_no_policies() {
        assert!(read(&[]).unwrap().is_empty());
    }

    /// Chrome's policies live under `Chrome~Policy~googlechrome…`, as Google
    /// documents, and the dataset carries both delivery steps.
    #[test]
    fn chrome_policies_carry_both_delivery_steps() {
        let all = read(crate::embedded_windows_app_policies()).unwrap();
        let p = all
            .iter()
            .find(|p| p.template == "chrome" && p.policy_name == "DefaultCookiesSetting")
            .unwrap_or_else(|| {
                panic!(
                    "no Chrome DefaultCookiesSetting — this dataset predates windows_app_policies \
                     ; republish, do not skip ({} policies read)",
                    all.len()
                )
            });
        assert!(
            p.device_loc_uri
                .starts_with("./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome")
        );
        assert!(
            p.user_loc_uri
                .starts_with("./User/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome")
        );
        assert_eq!(
            p.admx_install_loc_uri,
            "./Device/Vendor/MSFT/Policy/ConfigOperations/ADMXInstall/Chrome/Policy/chrome"
        );
        assert!(p.ingestable);
        assert_eq!(p.elements.len(), 1);
        assert_eq!(p.elements[0].kind, "enum");
        assert!(p.elements[0].items.len() >= 2, "{:?}", p.elements[0].items);
        assert!(
            p.payload(None)
                .starts_with("<enabled/><data id=\"DefaultCookiesSetting\"")
        );
    }

    /// Windows blocks MDM ingestion under Software\Policies\Microsoft\ unless
    /// the location is allow-listed; the dataset says so with its evidence.
    #[test]
    fn non_ingestable_policies_carry_the_reason_and_the_document() {
        let all = read(crate::embedded_windows_app_policies()).unwrap();
        if all.is_empty() {
            panic!("dataset predates windows_app_policies; republish, do not skip");
        }
        // Not a count: which policies Windows blocks is a judgement refined
        // against Microsoft's documentation, and a threshold here would call
        // a correction a regression. The property is what matters: the set
        // is non-empty, and every member says why and on what authority.
        let blocked: Vec<_> = all.iter().filter(|p| !p.ingestable).collect();
        assert!(
            !blocked.is_empty(),
            "no blocked policies at all — EdgeUpdate writes under \
             Software\\Policies\\Microsoft\\, which MDM ingestion blocks"
        );
        assert!(
            blocked.iter().any(|p| p.template == "edge-update"),
            "EdgeUpdate is the clearest blocked case and is missing"
        );
        for p in &blocked {
            assert!(
                p.ingest_reason.is_some(),
                "{}/{} blocked without a reason",
                p.template,
                p.policy_name
            );
            // Microsoft's document for the blocked roots, or the dataset row
            // that shows Windows ships the template natively.
            assert!(
                p.ingest_evidence.starts_with("https://")
                    || p.ingest_evidence.starts_with("windows_capabilities:"),
                "{}/{}: {}",
                p.template,
                p.policy_name,
                p.ingest_evidence
            );
        }
    }
}
