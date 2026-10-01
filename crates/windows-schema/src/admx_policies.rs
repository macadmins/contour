//! Parquet reader for the ADMX policies behind ADMX-backed CSP nodes.
//!
//! A DDF node only says a setting is ADMX-backed; the element schema a
//! SyncML payload needs — element ids, kinds, enum values, ranges — lives in
//! Microsoft's Administrative Templates. The dataset resolves the two and
//! ships the result here, one row per (node, element).
//!
//! [`read`] returns one [`AdmxPolicy`] per node with its elements collected,
//! so callers see a policy rather than a row set.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::{AdmxElement, AdmxEnumItem, AdmxPolicy};

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

/// Read ADMX policies from Parquet bytes, one entry per CSP node.
///
/// Elements keep their document order, which is the order a payload must
/// list them in.
///
/// # Errors
///
/// Returns an error when the bytes are not the expected Parquet layout.
pub fn read(bytes: &[u8]) -> Result<Vec<AdmxPolicy>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building windows_admx_policies Parquet reader")?;

    // Keyed by (payload_type, key_name); BTreeMap keeps the output stable.
    let mut policies: BTreeMap<(String, String), AdmxPolicy> = BTreeMap::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let payload_types = col(&batch, "payload_type")?.as_string::<i32>();
        let key_names = col(&batch, "key_name")?.as_string::<i32>();
        let admx_files = col(&batch, "admx_file")?.as_string::<i32>();
        let admx_areas = col(&batch, "admx_area")?.as_string::<i32>();
        let policy_names = col(&batch, "policy_name")?.as_string::<i32>();
        let classes = col(&batch, "class")?.as_string::<i32>();
        let registry_keys = col(&batch, "registry_key")?.as_string::<i32>();
        let registry_values = col(&batch, "registry_value")?.as_string::<i32>();
        let enabled_values = col(&batch, "enabled_value")?.as_string::<i32>();
        let disabled_values = col(&batch, "disabled_value")?.as_string::<i32>();
        let display_names = col(&batch, "display_name")?.as_string::<i32>();
        let explain_texts = col(&batch, "explain_text")?.as_string::<i32>();
        let element_ids = col(&batch, "element_id")?.as_string::<i32>();
        let element_kinds = col(&batch, "element_kind")?.as_string::<i32>();
        let element_labels = col(&batch, "element_label")?.as_string::<i32>();
        let element_required = col(&batch, "element_required")?.as_boolean();
        let element_mins =
            col(&batch, "element_min")?.as_primitive::<arrow::datatypes::Float64Type>();
        let element_maxs =
            col(&batch, "element_max")?.as_primitive::<arrow::datatypes::Float64Type>();
        let element_max_lengths =
            col(&batch, "element_max_length")?.as_primitive::<arrow::datatypes::UInt32Type>();
        let element_true_values = col(&batch, "element_true_value")?.as_string::<i32>();
        let element_false_values = col(&batch, "element_false_value")?.as_string::<i32>();
        let element_explicit = col(&batch, "element_explicit_value")?.as_boolean();
        let element_items = col(&batch, "element_items")?.as_string::<i32>();
        // Absent in older datasets.
        let element_value_names = batch
            .column_by_name("element_value_name")
            .map(|c| c.as_string::<i32>());
        let element_keys = batch
            .column_by_name("element_key")
            .map(|c| c.as_string::<i32>());

        for row in 0..batch.num_rows() {
            let id = (
                payload_types.value(row).to_string(),
                key_names.value(row).to_string(),
            );
            let policy = policies.entry(id).or_insert_with(|| AdmxPolicy {
                payload_type: payload_types.value(row).to_string(),
                key_name: key_names.value(row).to_string(),
                admx_file: admx_files.value(row).to_string(),
                admx_area: admx_areas.value(row).to_string(),
                policy_name: policy_names.value(row).to_string(),
                class: classes.value(row).to_string(),
                registry_key: opt_str(registry_keys, row),
                registry_value: opt_str(registry_values, row),
                enabled_value: opt_str(enabled_values, row),
                disabled_value: opt_str(disabled_values, row),
                display_name: opt_str(display_names, row),
                explain_text: opt_str(explain_texts, row),
                elements: Vec::new(),
            });

            // A policy with no elements is one row with the element columns
            // null: enable/disable only, no <data> children.
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
                value_name: element_value_names.and_then(|c| opt_str(c, row)),
                key: element_keys.and_then(|c| opt_str(c, row)),
            });
        }
    }

    Ok(policies.into_values().collect())
}
