use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::Section;

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
        Field::new("name", DataType::Utf8, false),
        Field::new("description", DataType::Utf8, true),
    ])
}

pub fn read(bytes: &[u8]) -> Result<Vec<Section>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building sections Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let names = col(&batch, "name")?.as_string::<i32>();
        let descriptions = col(&batch, "description")?.as_string::<i32>();

        for row in 0..batch.num_rows() {
            out.push(Section {
                name: names.value(row).to_string(),
                description: if descriptions.is_null(row) {
                    String::new()
                } else {
                    descriptions.value(row).to_string()
                },
            });
        }
    }

    Ok(out)
}
