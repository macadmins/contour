//! Reader for the embedded `examples.parquet` (Apple example configs).

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

/// One Apple example config/declaration JSON keyed to its owning payload type.
#[derive(Debug, Clone)]
pub struct ExampleConfig {
    pub payload_type: String,
    pub kind: String,
    pub index: u32,
    pub tab: Option<String>,
    pub description: Option<String>,
    pub json: String,
    pub source_file: String,
}

/// Read example configs from Parquet bytes.
pub fn read(bytes: &[u8]) -> Result<Vec<ExampleConfig>> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))?
        .build()
        .context("building examples Parquet reader")?;

    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.context("reading examples record batch")?;
        let pt = batch.column_by_name("payload_type").unwrap().as_string::<i32>();
        let kind = batch.column_by_name("kind").unwrap().as_string::<i32>();
        let idx = batch
            .column_by_name("index")
            .unwrap()
            .as_primitive::<arrow::datatypes::UInt32Type>();
        let tab = batch.column_by_name("tab").unwrap().as_string::<i32>();
        let desc = batch
            .column_by_name("description")
            .unwrap()
            .as_string::<i32>();
        let json = batch.column_by_name("json").unwrap().as_string::<i32>();
        let src = batch
            .column_by_name("source_file")
            .unwrap()
            .as_string::<i32>();

        for row in 0..batch.num_rows() {
            out.push(ExampleConfig {
                payload_type: pt.value(row).to_string(),
                kind: kind.value(row).to_string(),
                index: idx.value(row),
                tab: if tab.is_null(row) {
                    None
                } else {
                    Some(tab.value(row).to_string())
                },
                description: if desc.is_null(row) {
                    None
                } else {
                    Some(desc.value(row).to_string())
                },
                json: json.value(row).to_string(),
                source_file: src.value(row).to_string(),
            });
        }
    }
    Ok(out)
}
