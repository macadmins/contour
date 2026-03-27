use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::EnvelopeMetaKey;

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
        Field::new("layer", DataType::Utf8, false),
        Field::new("key_name", DataType::Utf8, false),
        Field::new("value_type", DataType::Utf8, false),
        Field::new("required", DataType::Boolean, false),
        Field::new("default_value", DataType::Utf8, true),
        Field::new("description", DataType::Utf8, false),
    ])
}

pub fn read(bytes: &[u8]) -> Result<Vec<EnvelopeMetaKey>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building envelope_meta_keys Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let layers = col(&batch, "layer")?.as_string::<i32>();
        let key_names = col(&batch, "key_name")?.as_string::<i32>();
        let value_types = col(&batch, "value_type")?.as_string::<i32>();
        let requireds = col(&batch, "required")?.as_boolean();
        let default_values = col(&batch, "default_value")?.as_string::<i32>();
        let descriptions = col(&batch, "description")?.as_string::<i32>();

        for row in 0..batch.num_rows() {
            out.push(EnvelopeMetaKey {
                layer: layers.value(row).to_string(),
                key_name: key_names.value(row).to_string(),
                value_type: value_types.value(row).to_string(),
                required: requireds.value(row),
                default_value: if default_values.is_null(row) {
                    None
                } else {
                    Some(default_values.value(row).to_string())
                },
                description: descriptions.value(row).to_string(),
            });
        }
    }

    Ok(out)
}
