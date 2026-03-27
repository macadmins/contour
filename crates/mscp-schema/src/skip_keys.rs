use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::SkipKey;

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
        Field::new("key", DataType::Utf8, false),
        Field::new("title", DataType::Utf8, false),
        Field::new("description", DataType::Utf8, true),
        Field::new("platform", DataType::Utf8, false),
        Field::new("introduced", DataType::Utf8, true),
        Field::new("deprecated", DataType::Utf8, true),
        Field::new("removed", DataType::Utf8, true),
        Field::new("always_skippable", DataType::Boolean, true),
    ])
}

pub fn read(bytes: &[u8]) -> Result<Vec<SkipKey>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building skip_keys Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let keys = col(&batch, "key")?.as_string::<i32>();
        let titles = col(&batch, "title")?.as_string::<i32>();
        let descriptions = col(&batch, "description")?.as_string::<i32>();
        let platforms = col(&batch, "platform")?.as_string::<i32>();
        let introduceds = col(&batch, "introduced")?.as_string::<i32>();
        let deprecateds = col(&batch, "deprecated")?.as_string::<i32>();
        let removeds = col(&batch, "removed")?.as_string::<i32>();
        let always_skippables = col(&batch, "always_skippable")?.as_boolean();

        for row in 0..batch.num_rows() {
            out.push(SkipKey {
                key: keys.value(row).to_string(),
                title: titles.value(row).to_string(),
                description: if descriptions.is_null(row) {
                    None
                } else {
                    Some(descriptions.value(row).to_string())
                },
                platform: platforms.value(row).to_string(),
                introduced: if introduceds.is_null(row) {
                    None
                } else {
                    Some(introduceds.value(row).to_string())
                },
                deprecated: if deprecateds.is_null(row) {
                    None
                } else {
                    Some(deprecateds.value(row).to_string())
                },
                removed: if removeds.is_null(row) {
                    None
                } else {
                    Some(removeds.value(row).to_string())
                },
                always_skippable: if always_skippables.is_null(row) {
                    None
                } else {
                    Some(always_skippables.value(row))
                },
            });
        }
    }

    Ok(out)
}
