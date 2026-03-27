use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::EnvelopePattern;

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
        Field::new("nesting_pattern", DataType::Utf8, false),
        Field::new("description", DataType::Utf8, false),
        Field::new("inner_payload_type", DataType::Utf8, true),
        Field::new("envelope_template", DataType::Utf8, false),
        Field::new("default_scope", DataType::Utf8, false),
    ])
}

pub fn read(bytes: &[u8]) -> Result<Vec<EnvelopePattern>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building envelope_patterns Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let nesting_patterns = col(&batch, "nesting_pattern")?.as_string::<i32>();
        let descriptions = col(&batch, "description")?.as_string::<i32>();
        let inner_payload_types = col(&batch, "inner_payload_type")?.as_string::<i32>();
        let envelope_templates = col(&batch, "envelope_template")?.as_string::<i32>();
        let default_scopes = col(&batch, "default_scope")?.as_string::<i32>();

        for row in 0..batch.num_rows() {
            out.push(EnvelopePattern {
                nesting_pattern: nesting_patterns.value(row).to_string(),
                description: descriptions.value(row).to_string(),
                inner_payload_type: if inner_payload_types.is_null(row) {
                    None
                } else {
                    Some(inner_payload_types.value(row).to_string())
                },
                envelope_template: envelope_templates.value(row).to_string(),
                default_scope: default_scopes.value(row).to_string(),
            });
        }
    }

    Ok(out)
}
