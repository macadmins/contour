//! `rule_capability_links.parquet` — which mSCP rule enforces through which
//! payload key, and how sure the match is.
//!
//! One row per `(rule_id, platform, os_version, capability_ref,
//! capability_key)`. `confidence` is `Exact` when the rule's own
//! `mobileconfig_info` / `ddm_info` names the type, `Heuristic` when it was
//! inferred; `enforcement_preference` says which of Apple's two mechanisms
//! the rule actually ships (`ProfileCapable` / `DeclarativeReady`).

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::RuleCapabilityLink;

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
        Field::new("rule_id", DataType::Utf8, false),
        Field::new("platform", DataType::Utf8, true),
        Field::new("os_version", DataType::Utf8, true),
        Field::new("capability_ref", DataType::Utf8, false),
        Field::new("capability_key", DataType::Utf8, true),
        Field::new("capability_kind", DataType::Utf8, true),
        Field::new("confidence", DataType::Utf8, false),
        Field::new("evidence", DataType::Utf8, true),
        Field::new("enforcement_preference", DataType::Utf8, true),
    ])
}

/// Read the table. **Empty bytes read as an empty table**: the build script
/// writes a zero-length placeholder when the published dataset predates
/// this file, so a consumer on that dataset gets no annotations rather
/// than no build.
pub fn read(bytes: &[u8]) -> Result<Vec<RuleCapabilityLink>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building rule_capability_links Parquet reader")?;

    let opt = |a: &arrow::array::GenericStringArray<i32>, row: usize| -> Option<String> {
        if a.is_null(row) {
            None
        } else {
            Some(a.value(row).to_string())
        }
    };

    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let rule_ids = col(&batch, "rule_id")?.as_string::<i32>();
        let platforms = col(&batch, "platform")?.as_string::<i32>();
        let os_versions = col(&batch, "os_version")?.as_string::<i32>();
        let refs = col(&batch, "capability_ref")?.as_string::<i32>();
        let keys = col(&batch, "capability_key")?.as_string::<i32>();
        let kinds = col(&batch, "capability_kind")?.as_string::<i32>();
        let confidences = col(&batch, "confidence")?.as_string::<i32>();
        let evidence = col(&batch, "evidence")?.as_string::<i32>();
        let prefs = col(&batch, "enforcement_preference")?.as_string::<i32>();

        for row in 0..batch.num_rows() {
            out.push(RuleCapabilityLink {
                rule_id: rule_ids.value(row).to_string(),
                platform: opt(platforms, row),
                os_version: opt(os_versions, row),
                capability_ref: refs.value(row).to_string(),
                capability_key: opt(keys, row),
                capability_kind: opt(kinds, row),
                confidence: confidences.value(row).to_string(),
                evidence: opt(evidence, row),
                enforcement_preference: opt(prefs, row),
            });
        }
    }
    Ok(out)
}
