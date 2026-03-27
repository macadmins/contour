use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::BaselineEdge;

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
        Field::new("baseline", DataType::Utf8, false),
        Field::new("platform", DataType::Utf8, true),
        Field::new("os_version", DataType::Utf8, true),
        Field::new("section", DataType::Utf8, false),
        Field::new("rule_id", DataType::Utf8, false),
        Field::new("parent_values", DataType::Utf8, false),
    ])
}

pub fn read(bytes: &[u8]) -> Result<Vec<BaselineEdge>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building baseline_edges Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let baselines = col(&batch, "baseline")?.as_string::<i32>();
        let platforms = col(&batch, "platform")?.as_string::<i32>();
        let os_versions = col(&batch, "os_version")?.as_string::<i32>();
        let sections = col(&batch, "section")?.as_string::<i32>();
        let rule_ids = col(&batch, "rule_id")?.as_string::<i32>();
        let parent_values = col(&batch, "parent_values")?.as_string::<i32>();

        for row in 0..batch.num_rows() {
            out.push(BaselineEdge {
                baseline: baselines.value(row).to_string(),
                platform: if platforms.is_null(row) {
                    None
                } else {
                    Some(platforms.value(row).to_string())
                },
                os_version: if os_versions.is_null(row) {
                    None
                } else {
                    Some(os_versions.value(row).to_string())
                },
                section: sections.value(row).to_string(),
                rule_id: rule_ids.value(row).to_string(),
                parent_values: parent_values.value(row).to_string(),
            });
        }
    }

    Ok(out)
}
