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

#[cfg(test)]
mod dataset_holds_against_the_ddf {
    use super::*;
    use std::collections::HashMap;

    /// Split an OMA-URI into (CSP area, node path as the DDF spells it).
    ///
    /// The URI nests with slashes and the DDF's `key_path` nests with dots —
    /// `MdmStore/PublicProfile/EnableFirewall` against
    /// `MdmStore.PublicProfile.EnableFirewall`. Comparing them unconverted
    /// reports fourteen Firewall and PassportForWork policies as unresolvable
    /// when every one of them resolves.
    fn split(uri: &str) -> Option<(String, String)> {
        for marker in ["/Policy/Config/", "/Vendor/MSFT/"] {
            if let Some(i) = uri.find(marker) {
                let rest = &uri[i + marker.len()..];
                let (area, path) = rest.split_once('/')?;
                return Some((area.to_string(), path.replace('/', ".")));
            }
        }
        None
    }

    /// The DDF node each STIG policy targets, keyed as the policy names it.
    fn ddf_nodes() -> HashMap<(String, String), mdm_schema::PayloadKey> {
        let caps = mdm_schema::capabilities::read(mdm_schema::embedded_windows_capabilities())
            .expect("embedded Windows capabilities");
        let mut out = HashMap::new();
        for cap in caps {
            for key in cap.keys {
                if let Some(path) = key.key_path.clone() {
                    out.insert((cap.payload_type.clone(), path), key);
                }
            }
        }
        out
    }

    /// The SyncML `Format` a DDF type calls for.
    ///
    /// `boolean` is `bool`, not `int`. Assuming otherwise reports eight
    /// Firewall and PassportForWork policies as mistyped — contour's own
    /// `windows generate` emits `bool` for those same nodes.
    fn expected_format(data_type: &str) -> Option<&'static str> {
        match data_type.to_ascii_lowercase().as_str() {
            "integer" | "int" => Some("int"),
            "boolean" => Some("bool"),
            "string" => Some("chr"),
            _ => None,
        }
    }

    /// Every generated STIG policy targets a node Microsoft describes, with a
    /// value that node accepts.
    ///
    /// `fleet_stigs` comes from tux234/windows-fleet-stigs — a third-party
    /// repository that pairs DISA's STIG content with Microsoft's DDF by
    /// machine. It is pinned and vendored, but it is derived, not published,
    /// so its agreement with the DDF is a property to check rather than
    /// assume. contour embeds the DDF anyway; holding one against the other
    /// costs nothing and is the only reason this data is worth surfacing.
    ///
    /// A refresh of the upstream logs that drifts from the DDF fails here
    /// rather than shipping policies that target nodes Windows does not have.
    #[test]
    fn every_generated_policy_matches_the_ddf() {
        let nodes = ddf_nodes();
        let stigs = read(crate::embedded_fleet_stigs()).expect("embedded fleet STIGs");
        let generated: Vec<_> = stigs
            .iter()
            .filter(|s| s.enforcement_status == "generated")
            .collect();
        assert!(
            !generated.is_empty(),
            "no generated policies — the dataset did not load"
        );

        let (mut unresolved, mut wrong_format, mut not_in_enum, mut out_of_range) =
            (vec![], vec![], vec![], vec![]);

        for s in &generated {
            let Some((area, path)) = split(&s.oma_uri) else {
                unresolved.push(format!("{} (unparsable URI)", s.oma_uri));
                continue;
            };
            let Some(node) = nodes.get(&(area.clone(), path.clone())) else {
                unresolved.push(format!("{area}/{path}"));
                continue;
            };

            // ADMX-backed policies carry policy-XML, not a scalar, so the
            // node's scalar type says nothing about their `Data`.
            if s.is_admx {
                continue;
            }
            let Some(data) = s.enforcement_data.as_deref() else {
                continue;
            };

            if let (Some(want), Some(got)) = (
                expected_format(&node.data_type),
                s.enforcement_format.as_deref(),
            ) && want != got
            {
                wrong_format.push(format!(
                    "{area}/{path}: DDF says {}, policy sends {got}",
                    node.data_type
                ));
            }

            if let Some(allowed) = node.range_list.as_ref()
                && !allowed.is_empty()
                && !allowed.iter().any(|v| v == data)
            {
                not_in_enum.push(format!("{area}/{path}: {data} not in {allowed:?}"));
            }

            if let (Some(lo), Some(hi), Ok(v)) =
                (node.range_min, node.range_max, data.parse::<f64>())
                && (v < lo || v > hi)
            {
                out_of_range.push(format!("{area}/{path}: {data} outside {lo}..={hi}"));
            }
        }

        let report = |label: &str, v: &[String]| {
            if v.is_empty() {
                String::new()
            } else {
                format!(
                    "\n{label} ({}):\n  {}",
                    v.len(),
                    v.iter().take(10).cloned().collect::<Vec<_>>().join("\n  ")
                )
            }
        };
        let problems = format!(
            "{}{}{}{}",
            report("targets a node the DDF does not describe", &unresolved),
            report("sends the wrong SyncML format", &wrong_format),
            report("sends a value outside the node's enum", &not_in_enum),
            report("sends a value outside the node's range", &out_of_range),
        );
        assert!(
            problems.is_empty(),
            "fleet_stigs disagrees with the embedded DDF. The STIG logs were \
             refreshed against a different DDF drop, or the DDF moved under \
             them:{problems}"
        );
    }

    /// The dataset says where it could not do the job.
    ///
    /// A generator that silently emitted only what it managed would look
    /// complete. This one records `unmapped` and `blocked` rows with a
    /// reason, which is why the verified `generated` subset can be trusted as
    /// a subset rather than as the whole STIG.
    #[test]
    fn the_gaps_are_declared_rather_than_dropped() {
        let stigs = read(crate::embedded_fleet_stigs()).expect("embedded fleet STIGs");
        let blocked: Vec<_> = stigs
            .iter()
            .filter(|s| s.enforcement_status == "blocked")
            .collect();
        assert!(
            stigs.iter().any(|s| s.enforcement_status == "unmapped"),
            "no unmapped rows — a generator that maps everything is suspicious"
        );
        for s in &blocked {
            assert!(
                s.block_reason
                    .as_deref()
                    .is_some_and(|r| !r.trim().is_empty()),
                "{} is blocked with no reason given",
                s.oma_uri
            );
        }
    }
}
