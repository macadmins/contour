//! `status_items.parquet` — the DDM status surface. What a device reports back, as opposed to
//! what a declaration configures: 216 item types with value types, scopes
//! and enrollments.

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::StatusItem;

/// Read the table. Empty bytes read as an empty table: the build script
/// writes a zero-length placeholder when the published dataset predates
/// this file, so an older dataset means no rows rather than no build.
pub fn read(bytes: &[u8]) -> Result<Vec<StatusItem>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))?
        .build()
        .context("building status_items Parquet reader")?;

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
        let c_status_item_type = col("status_item_type")?;
        let c_title = col("title")?;
        let c_description = col("description")?;
        let c_platform = col("platform")?;
        let c_introduced = col("introduced")?;
        let c_deprecated = col("deprecated")?;
        let c_allowed_enrollments = col("allowed_enrollments")?;
        let c_allowed_scopes = col("allowed_scopes")?;
        let c_value_type = col("value_type")?;
        let c_value_description = col("value_description")?;
        let c_rangelist = col("rangelist")?;
        for row in 0..batch.num_rows() {
            out.push(StatusItem {
                status_item_type: c_status_item_type.value(row).to_string(),
                title: c_title.value(row).to_string(),
                description: c_description.value(row).to_string(),
                platform: c_platform.value(row).to_string(),
                introduced: opt(c_introduced, row),
                deprecated: opt(c_deprecated, row),
                allowed_enrollments: json(c_allowed_enrollments, row),
                allowed_scopes: json(c_allowed_scopes, row),
                value_type: opt(c_value_type, row),
                value_description: opt(c_value_description, row),
                rangelist: json(c_rangelist, row),
            });
        }
    }
    Ok(out)
}
