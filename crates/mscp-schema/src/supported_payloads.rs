//! `supported_payloads.parquet` — the payload and declaration types the
//! rule corpus enforces through, with the kind and how many rules use each.
//!
//! mSCP 1.x shipped a hand-maintained list; 2.0 dropped it, so this is
//! derived from the rules themselves.

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::SupportedPayload;

/// Read the table; empty bytes read as an empty table.
pub fn read(bytes: &[u8]) -> Result<Vec<SupportedPayload>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))?
        .build()
        .context("building supported_payloads Parquet reader")?;

    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let col = |n: &str| -> Result<&arrow::array::ArrayRef> {
            batch
                .column_by_name(n)
                .ok_or_else(|| anyhow::anyhow!("missing column '{n}' in Parquet schema"))
        };
        let types = col("payload_type")?.as_string::<i32>();
        let kinds = col("kind")?.as_string::<i32>();
        let counts = col("rule_count")?.as_primitive::<arrow::datatypes::UInt32Type>();
        for row in 0..batch.num_rows() {
            out.push(SupportedPayload {
                payload_type: types.value(row).to_string(),
                kind: kinds.value(row).to_string(),
                rule_count: if counts.is_null(row) {
                    0
                } else {
                    counts.value(row)
                },
            });
        }
    }
    Ok(out)
}
