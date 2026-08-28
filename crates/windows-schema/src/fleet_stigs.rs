//! Parquet reader for Fleet-deployable STIG policies.
//!
//! One row per policy: the CSP enforcement side (OMA-URI + SyncML
//! fragment) and the compliance side (osquery query over `mdm_bridge`).
//! `enforcement_status` is `generated`, `blocked` (see `block_reason`),
//! or `unmapped`.

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::FleetStig;

fn col<'a>(
    batch: &'a arrow::record_batch::RecordBatch,
    name: &str,
) -> Result<&'a arrow::array::ArrayRef> {
    batch
        .column_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("missing column '{name}' in Parquet schema"))
}

fn opt_str(arr: &arrow::array::StringArray, row: usize) -> Option<String> {
    if arr.is_null(row) {
        None
    } else {
        Some(arr.value(row).to_string())
    }
}

/// Read Fleet STIG policies from Parquet bytes.
pub fn read(bytes: &[u8]) -> Result<Vec<FleetStig>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building fleet_stigs Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let stig_profiles = col(&batch, "stig_profile")?.as_string::<i32>();
        let oma_uris = col(&batch, "oma_uri")?.as_string::<i32>();
        let enforcement_statuses = col(&batch, "enforcement_status")?.as_string::<i32>();
        let compliance_statuses = col(&batch, "compliance_status")?.as_string::<i32>();
        let enforcement_xmls = col(&batch, "enforcement_xml")?.as_string::<i32>();
        let enforcement_formats = col(&batch, "enforcement_format")?.as_string::<i32>();
        let enforcement_datas = col(&batch, "enforcement_data")?.as_string::<i32>();
        let compliance_queries = col(&batch, "compliance_query")?.as_string::<i32>();
        let policy_names = col(&batch, "policy_name")?.as_string::<i32>();
        let policy_tags = col(&batch, "policy_tags")?.as_string::<i32>();
        let csp_areas = col(&batch, "csp_area")?.as_string::<i32>();
        let is_admxs = col(&batch, "is_admx")?.as_boolean();
        let block_reasons = col(&batch, "block_reason")?.as_string::<i32>();

        for row in 0..batch.num_rows() {
            out.push(FleetStig {
                stig_profile: stig_profiles.value(row).to_string(),
                oma_uri: oma_uris.value(row).to_string(),
                enforcement_status: enforcement_statuses.value(row).to_string(),
                compliance_status: compliance_statuses.value(row).to_string(),
                enforcement_xml: opt_str(enforcement_xmls, row),
                enforcement_format: opt_str(enforcement_formats, row),
                enforcement_data: opt_str(enforcement_datas, row),
                compliance_query: opt_str(compliance_queries, row),
                policy_name: opt_str(policy_names, row).unwrap_or_default(),
                // Stored as a comma-joined string in the parquet.
                policy_tags: opt_str(policy_tags, row)
                    .map(|s| {
                        s.split(',')
                            .map(|t| t.trim().to_string())
                            .filter(|t| !t.is_empty())
                            .collect()
                    })
                    .unwrap_or_default(),
                csp_area: opt_str(csp_areas, row),
                is_admx: is_admxs.value(row),
                block_reason: opt_str(block_reasons, row),
            });
        }
    }

    Ok(out)
}
