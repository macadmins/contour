use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::RulePayload;

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
        Field::new("check_script", DataType::Utf8, true),
        Field::new("fix_script", DataType::Utf8, true),
        Field::new("expected_result", DataType::Utf8, true),
        Field::new("odv_options", DataType::Utf8, true),
        Field::new("mobileconfig_info", DataType::Utf8, true),
        Field::new("ddm_declaration_type", DataType::Utf8, true),
        Field::new("ddm_key", DataType::Utf8, true),
        Field::new("ddm_value", DataType::Utf8, true),
        Field::new("ddm_service", DataType::Utf8, true),
        Field::new("ddm_config_file", DataType::Utf8, true),
        Field::new("ddm_configuration_key", DataType::Utf8, true),
        Field::new("ddm_configuration_value", DataType::Utf8, true),
    ])
}

pub fn read(bytes: &[u8]) -> Result<Vec<RulePayload>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building rule_payloads Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let rule_ids = col(&batch, "rule_id")?.as_string::<i32>();
        let check_scripts = col(&batch, "check_script")?.as_string::<i32>();
        let fix_scripts = col(&batch, "fix_script")?.as_string::<i32>();
        let expected_results = col(&batch, "expected_result")?.as_string::<i32>();
        let odv_options = col(&batch, "odv_options")?.as_string::<i32>();
        let mobileconfig_infos = col(&batch, "mobileconfig_info")?.as_string::<i32>();
        let ddm_declaration_types = col(&batch, "ddm_declaration_type")?.as_string::<i32>();
        let ddm_keys = col(&batch, "ddm_key")?.as_string::<i32>();
        let ddm_values = col(&batch, "ddm_value")?.as_string::<i32>();
        let ddm_services = col(&batch, "ddm_service")?.as_string::<i32>();
        let ddm_config_files = col(&batch, "ddm_config_file")?.as_string::<i32>();
        let ddm_configuration_keys = col(&batch, "ddm_configuration_key")?.as_string::<i32>();
        let ddm_configuration_values = col(&batch, "ddm_configuration_value")?.as_string::<i32>();

        for row in 0..batch.num_rows() {
            out.push(RulePayload {
                rule_id: rule_ids.value(row).to_string(),
                check_script: if check_scripts.is_null(row) {
                    None
                } else {
                    Some(check_scripts.value(row).to_string())
                },
                fix_script: if fix_scripts.is_null(row) {
                    None
                } else {
                    Some(fix_scripts.value(row).to_string())
                },
                expected_result: if expected_results.is_null(row) {
                    None
                } else {
                    Some(expected_results.value(row).to_string())
                },
                odv_options: if odv_options.is_null(row) {
                    None
                } else {
                    Some(odv_options.value(row).to_string())
                },
                mobileconfig_info: if mobileconfig_infos.is_null(row) {
                    None
                } else {
                    Some(mobileconfig_infos.value(row).to_string())
                },
                ddm_declaration_type: if ddm_declaration_types.is_null(row) {
                    None
                } else {
                    Some(ddm_declaration_types.value(row).to_string())
                },
                ddm_key: if ddm_keys.is_null(row) {
                    None
                } else {
                    Some(ddm_keys.value(row).to_string())
                },
                ddm_value: if ddm_values.is_null(row) {
                    None
                } else {
                    Some(ddm_values.value(row).to_string())
                },
                ddm_service: if ddm_services.is_null(row) {
                    None
                } else {
                    Some(ddm_services.value(row).to_string())
                },
                ddm_config_file: if ddm_config_files.is_null(row) {
                    None
                } else {
                    Some(ddm_config_files.value(row).to_string())
                },
                ddm_configuration_key: if ddm_configuration_keys.is_null(row) {
                    None
                } else {
                    Some(ddm_configuration_keys.value(row).to_string())
                },
                ddm_configuration_value: if ddm_configuration_values.is_null(row) {
                    None
                } else {
                    Some(ddm_configuration_values.value(row).to_string())
                },
            });
        }
    }

    Ok(out)
}
