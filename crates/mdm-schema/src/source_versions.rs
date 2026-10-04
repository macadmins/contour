//! `source_versions.parquet` — which upstream each table was read from, and
//! at which commit.
//!
//! One row per source: the release label the upstream calls itself
//! (`Release-v27.0`, `2.0`) and the `revision` it actually was. FormSpec's `source.upstream_ref` reads the
//! latter.

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::SourceVersion;

pub fn schema() -> Schema {
    Schema::new(vec![
        Field::new("source", DataType::Utf8, false),
        Field::new("os", DataType::Utf8, false),
        Field::new("platform", DataType::Utf8, false),
        Field::new("version", DataType::Utf8, false),
        Field::new("cpe", DataType::Utf8, true),
        Field::new("date", DataType::Utf8, true),
        Field::new("revision", DataType::Utf8, true),
    ])
}

/// Read the table. Empty bytes read as an empty table — the build script
/// writes a zero-length placeholder when the published dataset predates
/// this file — and a dataset from before the `revision` column reads with
/// `revision: None` rather than failing.
pub fn read(bytes: &[u8]) -> Result<Vec<SourceVersion>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building source_versions Parquet reader")?;

    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let req = |name: &str| -> Result<&arrow::array::GenericStringArray<i32>> {
            Ok(batch
                .column_by_name(name)
                .ok_or_else(|| anyhow::anyhow!("missing column '{name}' in Parquet schema"))?
                .as_string::<i32>())
        };
        let opt = |a: &arrow::array::GenericStringArray<i32>, row: usize| {
            (!a.is_null(row)).then(|| a.value(row).to_string())
        };
        let sources = req("source")?;
        let oses = req("os")?;
        let platforms = req("platform")?;
        let versions = req("version")?;
        let cpes = req("cpe")?;
        let dates = req("date")?;
        let revisions = batch
            .column_by_name("revision")
            .map(|c| c.as_string::<i32>());

        for row in 0..batch.num_rows() {
            out.push(SourceVersion {
                source: sources.value(row).to_string(),
                os: oses.value(row).to_string(),
                platform: platforms.value(row).to_string(),
                version: versions.value(row).to_string(),
                cpe: opt(cpes, row),
                date: opt(dates, row),
                revision: revisions.and_then(|r| opt(r, row)),
            });
        }
    }
    Ok(out)
}
