use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::RuleVersioned;

fn col<'a>(
    batch: &'a arrow::record_batch::RecordBatch,
    name: &str,
) -> Result<&'a arrow::array::ArrayRef> {
    batch
        .column_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("missing column '{name}' in Parquet schema"))
}

pub fn schema() -> Schema {
    Schema::new(vec![
        Field::new("rule_id", DataType::Utf8, false),
        Field::new("platform", DataType::Utf8, false),
        Field::new("os_version", DataType::Utf8, false),
        Field::new("title", DataType::Utf8, false),
        Field::new("severity", DataType::Utf8, true),
        Field::new("has_check", DataType::Boolean, false),
        Field::new("has_fix", DataType::Boolean, false),
        Field::new("has_result", DataType::Boolean, false),
        Field::new("content_hash", DataType::Utf8, false),
        Field::new("mobileconfig", DataType::Boolean, false),
        Field::new("has_ddm_info", DataType::Boolean, false),
        Field::new("enforcement_type", DataType::Utf8, true),
        Field::new(
            "tags",
            DataType::List(Field::new("item", DataType::Utf8, true).into()),
            true,
        ),
        Field::new("check_mechanism", DataType::Utf8, true),
        Field::new("osquery_checkable", DataType::Boolean, false),
        Field::new("osquery_table", DataType::Utf8, true),
        Field::new("baseline_count", DataType::Int32, false),
        Field::new("control_count", DataType::Int32, false),
        Field::new("weight", DataType::Float64, false),
        Field::new("odv_default", DataType::Utf8, true),
        Field::new("distro", DataType::Utf8, true),
    ])
}

pub fn read(bytes: &[u8]) -> Result<Vec<RuleVersioned>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building rules_versioned Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let rule_ids = col(&batch, "rule_id")?.as_string::<i32>();
        let platforms = col(&batch, "platform")?.as_string::<i32>();
        let os_versions = col(&batch, "os_version")?.as_string::<i32>();
        let titles = col(&batch, "title")?.as_string::<i32>();
        let severities = col(&batch, "severity")?.as_string::<i32>();
        let has_checks = col(&batch, "has_check")?.as_boolean();
        let has_fixes = col(&batch, "has_fix")?.as_boolean();
        let has_results = col(&batch, "has_result")?.as_boolean();
        let content_hashes = col(&batch, "content_hash")?.as_string::<i32>();
        let mobileconfigs = col(&batch, "mobileconfig")?.as_boolean();
        let has_ddm_infos = col(&batch, "has_ddm_info")?.as_boolean();
        let enforcement_types = col(&batch, "enforcement_type")?.as_string::<i32>();
        let tags_col = col(&batch, "tags")?.as_list::<i32>();
        let check_mechanisms = col(&batch, "check_mechanism")?.as_string::<i32>();
        let osquery_checkables = col(&batch, "osquery_checkable")?.as_boolean();
        let osquery_tables = col(&batch, "osquery_table")?.as_string::<i32>();
        let baseline_counts =
            col(&batch, "baseline_count")?.as_primitive::<arrow::datatypes::Int32Type>();
        let control_counts =
            col(&batch, "control_count")?.as_primitive::<arrow::datatypes::Int32Type>();
        let weights = col(&batch, "weight")?.as_primitive::<arrow::datatypes::Float64Type>();
        let odv_defaults = col(&batch, "odv_default")?.as_string::<i32>();
        let distros = col(&batch, "distro")?.as_string::<i32>();

        for row in 0..batch.num_rows() {
            let tags = if tags_col.is_null(row) {
                Vec::new()
            } else {
                let list_value = tags_col.value(row);
                let string_arr = list_value.as_string::<i32>();
                (0..string_arr.len())
                    .filter(|&i| !string_arr.is_null(i))
                    .map(|i| string_arr.value(i).to_string())
                    .collect()
            };

            out.push(RuleVersioned {
                rule_id: rule_ids.value(row).to_string(),
                platform: platforms.value(row).to_string(),
                os_version: os_versions.value(row).to_string(),
                title: titles.value(row).to_string(),
                severity: if severities.is_null(row) {
                    None
                } else {
                    Some(severities.value(row).to_string())
                },
                has_check: has_checks.value(row),
                has_fix: has_fixes.value(row),
                has_result: has_results.value(row),
                content_hash: content_hashes.value(row).to_string(),
                mobileconfig: mobileconfigs.value(row),
                has_ddm_info: has_ddm_infos.value(row),
                enforcement_type: if enforcement_types.is_null(row) {
                    None
                } else {
                    Some(enforcement_types.value(row).to_string())
                },
                tags,
                check_mechanism: if check_mechanisms.is_null(row) {
                    None
                } else {
                    Some(check_mechanisms.value(row).to_string())
                },
                osquery_checkable: osquery_checkables.value(row),
                osquery_table: if osquery_tables.is_null(row) {
                    None
                } else {
                    Some(osquery_tables.value(row).to_string())
                },
                baseline_count: baseline_counts.value(row),
                control_count: control_counts.value(row),
                weight: weights.value(row),
                odv_default: if odv_defaults.is_null(row) {
                    None
                } else {
                    Some(odv_defaults.value(row).to_string())
                },
                distro: if distros.is_null(row) {
                    None
                } else {
                    Some(distros.value(row).to_string())
                },
            });
        }
    }

    Ok(out)
}
