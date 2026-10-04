//! `mdm_errors.parquet` — the error codes Apple documents, per platform.

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::MdmErrorCode;

/// Read the table. Empty bytes read as an empty table: the build script
/// writes a zero-length placeholder when the published dataset predates
/// this file, so an older dataset means no rows rather than no build.
pub fn read(bytes: &[u8]) -> Result<Vec<MdmErrorCode>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))?
        .build()
        .context("building mdm_errors Parquet reader")?;

    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let col = |n: &str| -> Result<&arrow::array::GenericStringArray<i32>> {
            Ok(batch
                .column_by_name(n)
                .ok_or_else(|| anyhow::anyhow!("missing column '{n}' in Parquet schema"))?
                .as_string::<i32>())
        };
        let opt = |a: &arrow::array::GenericStringArray<i32>, row: usize| {
            (!a.is_null(row)).then(|| a.value(row).to_string())
        };
        let json = |a: &arrow::array::GenericStringArray<i32>, row: usize| -> Option<Vec<String>> {
            (!a.is_null(row))
                .then(|| serde_json::from_str(a.value(row)).ok())
                .flatten()
        };
        let _ = &json;
        let c_error_code = col("error_code")?;
        let c_title = col("title")?;
        let c_description = col("description")?;
        let c_platform = col("platform")?;
        let c_introduced = col("introduced")?;
        for row in 0..batch.num_rows() {
            out.push(MdmErrorCode {
                error_code: c_error_code.value(row).to_string(),
                title: c_title.value(row).to_string(),
                description: c_description.value(row).to_string(),
                platform: c_platform.value(row).to_string(),
                introduced: opt(c_introduced, row),
            });
        }
    }
    Ok(out)
}
