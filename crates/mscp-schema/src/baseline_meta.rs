use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::BaselineMeta;

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
        Field::new("title", DataType::Utf8, false),
        Field::new("preamble", DataType::Utf8, true),
        Field::new("authors", DataType::Utf8, true), // JSON array of strings
    ])
}

pub fn read(bytes: &[u8]) -> Result<Vec<BaselineMeta>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building baseline_meta Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let baselines = col(&batch, "baseline")?.as_string::<i32>();
        let titles = col(&batch, "title")?.as_string::<i32>();
        let preambles = col(&batch, "preamble")?.as_string::<i32>();
        let authors_col = col(&batch, "authors")?.as_string::<i32>();
        // platforms column may be absent in older data
        let platforms_col = batch
            .column_by_name("platforms")
            .map(|c| c.as_string::<i32>());

        for row in 0..batch.num_rows() {
            let platforms = match platforms_col {
                Some(col) if !col.is_null(row) => {
                    let raw: Vec<String> = serde_json::from_str(col.value(row)).unwrap_or_default();
                    raw.iter()
                        .filter_map(|s| {
                            let mut parts = s.splitn(2, '/');
                            match (parts.next(), parts.next()) {
                                (Some(p), Some(v)) => Some((p.to_string(), v.to_string())),
                                _ => None,
                            }
                        })
                        .collect()
                }
                _ => Vec::new(),
            };

            out.push(BaselineMeta {
                baseline: baselines.value(row).to_string(),
                title: titles.value(row).to_string(),
                preamble: if preambles.is_null(row) {
                    None
                } else {
                    Some(preambles.value(row).to_string())
                },
                authors: if authors_col.is_null(row) {
                    Vec::new()
                } else {
                    serde_json::from_str(authors_col.value(row)).unwrap_or_default()
                },
                platforms,
            });
        }
    }

    Ok(out)
}
