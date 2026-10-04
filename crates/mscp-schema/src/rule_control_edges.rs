//! `rule_control_edges.parquet` — rule → framework → control. One row per (rule, framework, control_id):
//! the compliance language above baselines.

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::RuleControlEdge;

/// Read the table. Empty bytes read as an empty table: the build script
/// writes a zero-length placeholder when the published dataset predates
/// this file, so an older dataset means no rows rather than no build.
pub fn read(bytes: &[u8]) -> Result<Vec<RuleControlEdge>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))?
        .build()
        .context("building rule_control_edges Parquet reader")?;

    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let col = |n: &str| -> Result<&arrow::array::GenericStringArray<i32>> {
            Ok(batch
                .column_by_name(n)
                .ok_or_else(|| anyhow::anyhow!("missing column '{n}' in Parquet schema"))?
                .as_string::<i32>())
        };
        let _opt = |a: &arrow::array::GenericStringArray<i32>, row: usize| {
            (!a.is_null(row)).then(|| a.value(row).to_string())
        };
        let json = |a: &arrow::array::GenericStringArray<i32>, row: usize| -> Option<Vec<String>> {
            (!a.is_null(row))
                .then(|| serde_json::from_str(a.value(row)).ok())
                .flatten()
        };
        let _ = &json;
        let c_rule_id = col("rule_id")?;
        let c_framework = col("framework")?;
        let c_control_id = col("control_id")?;
        for row in 0..batch.num_rows() {
            out.push(RuleControlEdge {
                rule_id: c_rule_id.value(row).to_string(),
                framework: c_framework.value(row).to_string(),
                control_id: c_control_id.value(row).to_string(),
            });
        }
    }
    Ok(out)
}
