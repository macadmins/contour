use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::RuleMeta;

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
        Field::new("title", DataType::Utf8, false),
        Field::new("discussion", DataType::Utf8, true),
        Field::new("severity", DataType::Utf8, true),
        Field::new("has_check", DataType::Boolean, false),
        Field::new("has_fix", DataType::Boolean, false),
        Field::new("mobileconfig", DataType::Boolean, false),
        Field::new("has_ddm_info", DataType::Boolean, false),
        Field::new("distro", DataType::Utf8, true),
    ])
}

pub fn read(bytes: &[u8]) -> Result<Vec<RuleMeta>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building rule_meta Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let rule_ids = col(&batch, "rule_id")?.as_string::<i32>();
        let titles = col(&batch, "title")?.as_string::<i32>();
        let discussions = col(&batch, "discussion")?.as_string::<i32>();
        let severities = col(&batch, "severity")?.as_string::<i32>();
        let has_checks = col(&batch, "has_check")?.as_boolean();
        let has_fixes = col(&batch, "has_fix")?.as_boolean();
        let mobileconfigs = col(&batch, "mobileconfig")?.as_boolean();
        let has_ddm_infos = col(&batch, "has_ddm_info")?.as_boolean();
        // distro column may be absent in older data
        let distros = batch.column_by_name("distro").map(|c| c.as_string::<i32>());

        for row in 0..batch.num_rows() {
            out.push(RuleMeta {
                rule_id: rule_ids.value(row).to_string(),
                title: titles.value(row).to_string(),
                discussion: if discussions.is_null(row) {
                    None
                } else {
                    Some(discussions.value(row).to_string())
                },
                severity: if severities.is_null(row) {
                    None
                } else {
                    Some(severities.value(row).to_string())
                },
                has_check: has_checks.value(row),
                has_fix: has_fixes.value(row),
                mobileconfig: mobileconfigs.value(row),
                has_ddm_info: has_ddm_infos.value(row),
                distro: match distros {
                    Some(col) if !col.is_null(row) => Some(col.value(row).to_string()),
                    _ => None,
                },
            });
        }
    }

    Ok(out)
}
