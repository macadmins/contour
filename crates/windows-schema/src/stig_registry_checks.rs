//! Parquet reader for Windows STIG registry checks.
//!
//! One row per registry-backed STIG check, sourced from MITRE's InSpec
//! baseline: the registry location + expected value, plus a generated
//! osquery query — usable directly as a Fleet compliance policy. Joins
//! to `windows_rules` on `rule_id`.

use anyhow::{Context, Result};
use arrow::array::AsArray;
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::StigRegistryCheck;

fn col<'a>(
    batch: &'a arrow::record_batch::RecordBatch,
    name: &str,
) -> Result<&'a arrow::array::ArrayRef> {
    batch
        .column_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("missing column '{name}' in Parquet schema"))
}

/// Read STIG registry checks from Parquet bytes.
pub fn read(bytes: &[u8]) -> Result<Vec<StigRegistryCheck>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building stig_registry_checks Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let rule_ids = col(&batch, "rule_id")?.as_string::<i32>();
        let hives = col(&batch, "hive")?.as_string::<i32>();
        let paths = col(&batch, "path")?.as_string::<i32>();
        let value_names = col(&batch, "value_name")?.as_string::<i32>();
        let value_types = col(&batch, "value_type")?.as_string::<i32>();
        let expected_values = col(&batch, "expected_value")?.as_string::<i32>();
        let osquery_sqls = col(&batch, "osquery_sql")?.as_string::<i32>();

        for row in 0..batch.num_rows() {
            out.push(StigRegistryCheck {
                rule_id: rule_ids.value(row).to_string(),
                hive: hives.value(row).to_string(),
                path: paths.value(row).to_string(),
                value_name: value_names.value(row).to_string(),
                value_type: value_types.value(row).to_string(),
                expected_value: expected_values.value(row).to_string(),
                osquery_sql: osquery_sqls.value(row).to_string(),
            });
        }
    }

    Ok(out)
}
