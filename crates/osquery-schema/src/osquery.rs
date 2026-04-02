use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::OsqueryEntry;

fn col<'a>(
    batch: &'a arrow::record_batch::RecordBatch,
    name: &str,
) -> Result<&'a arrow::array::ArrayRef> {
    batch
        .column_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("missing column '{name}' in Parquet schema"))
}

/// Arrow schema for the osquery table/column Parquet file.
pub fn schema() -> Schema {
    Schema::new(vec![
        Field::new("table_name", DataType::Utf8, false),
        Field::new("table_description", DataType::Utf8, true),
        Field::new("platforms", DataType::Utf8, false),
        Field::new("evented", DataType::Boolean, false),
        Field::new("column_name", DataType::Utf8, false),
        Field::new("column_description", DataType::Utf8, true),
        Field::new("column_type", DataType::Utf8, false),
        Field::new("required", DataType::Boolean, false),
        Field::new("hidden", DataType::Boolean, false),
    ])
}

/// Read osquery entries from Parquet bytes.
pub fn read(bytes: &[u8]) -> Result<Vec<OsqueryEntry>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building osquery Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let table_names = col(&batch, "table_name")?.as_string::<i32>();
        let table_descriptions = col(&batch, "table_description")?.as_string::<i32>();
        let platforms = col(&batch, "platforms")?.as_string::<i32>();
        let eventeds = col(&batch, "evented")?.as_boolean();
        let column_names = col(&batch, "column_name")?.as_string::<i32>();
        let column_descriptions = col(&batch, "column_description")?.as_string::<i32>();
        let column_types = col(&batch, "column_type")?.as_string::<i32>();
        let requireds = col(&batch, "required")?.as_boolean();
        let hiddens = col(&batch, "hidden")?.as_boolean();

        for row in 0..batch.num_rows() {
            out.push(OsqueryEntry {
                table_name: table_names.value(row).to_string(),
                table_description: if table_descriptions.is_null(row) {
                    None
                } else {
                    Some(table_descriptions.value(row).to_string())
                },
                platforms: platforms.value(row).to_string(),
                evented: eventeds.value(row),
                column_name: column_names.value(row).to_string(),
                column_description: if column_descriptions.is_null(row) {
                    None
                } else {
                    Some(column_descriptions.value(row).to_string())
                },
                column_type: column_types.value(row).to_string(),
                required: requireds.value(row),
                hidden: hiddens.value(row),
            });
        }
    }

    Ok(out)
}
