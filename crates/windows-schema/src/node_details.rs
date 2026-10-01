//! Parquet reader for `windows_node_details`: what the DDF says about a CSP
//! node beyond its type — the meaning of each allowed value, the nodes it
//! depends on, and whether it must be delivered inside `<Atomic>`.
//!
//! Joins `windows_capabilities` on `(payload_type, key_path)`. Zero-length
//! bytes read as no rows (optional table; placeholder on older datasets).

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::{NodeDependency, NodeDetail, ValueDescription};

fn opt_str(arr: &arrow::array::StringArray, row: usize) -> Option<String> {
    if arr.is_null(row) {
        None
    } else {
        Some(arr.value(row).to_string())
    }
}

pub fn read(bytes: &[u8]) -> Result<Vec<NodeDetail>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building windows_node_details Parquet reader")?;
    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let s = |name: &str| -> Result<&arrow::array::StringArray> {
            Ok(batch
                .column_by_name(name)
                .ok_or_else(|| anyhow::anyhow!("missing column '{name}'"))?
                .as_string::<i32>())
        };
        let b = |name: &str| -> Result<&arrow::array::BooleanArray> {
            Ok(batch
                .column_by_name(name)
                .ok_or_else(|| anyhow::anyhow!("missing column '{name}'"))?
                .as_boolean())
        };
        let payload_types = s("payload_type")?;
        let key_paths = s("key_path")?;
        let key_names = s("key_name")?;
        let csp_versions = s("csp_version")?;
        let editions = s("editions")?;
        let home = b("home_supported")?;
        let pro = b("pro_supported")?;
        let value_descriptions = s("value_descriptions")?;
        let dependencies = s("dependencies")?;
        let atomic = b("atomic_required")?;
        for row in 0..batch.num_rows() {
            let vd: Vec<ValueDescription> = opt_str(value_descriptions, row)
                .map(|j| serde_json::from_str(&j).context("parsing value_descriptions"))
                .transpose()?
                .unwrap_or_default();
            let deps: Vec<NodeDependency> = opt_str(dependencies, row)
                .map(|j| serde_json::from_str(&j).context("parsing dependencies"))
                .transpose()?
                .unwrap_or_default();
            out.push(NodeDetail {
                payload_type: payload_types.value(row).to_string(),
                key_path: key_paths.value(row).to_string(),
                key_name: key_names.value(row).to_string(),
                csp_version: opt_str(csp_versions, row),
                editions: opt_str(editions, row),
                home_supported: (!home.is_null(row)).then(|| home.value(row)),
                pro_supported: (!pro.is_null(row)).then(|| pro.value(row)),
                value_descriptions: vd,
                dependencies: deps,
                atomic_required: !atomic.is_null(row) && atomic.value(row),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_read_as_no_rows() {
        assert!(read(&[]).unwrap().is_empty());
    }

    /// The DDF facts a scraper cannot see: value meanings, dependencies,
    /// Atomic. Microsoft states them; the dataset carries them; this reads
    /// them.
    #[test]
    fn value_meanings_dependencies_and_atomic_are_carried() {
        let all = read(crate::embedded_windows_node_details()).unwrap();
        if all.is_empty() {
            panic!("dataset predates windows_node_details; republish, do not skip");
        }
        let described = all
            .iter()
            .filter(|d| !d.value_descriptions.is_empty())
            .count();
        let dependent = all.iter().filter(|d| !d.dependencies.is_empty()).count();
        let atomic = all.iter().filter(|d| d.atomic_required).count();
        assert!(
            described > 1000 && dependent > 100 && atomic > 200,
            "{described} {dependent} {atomic}"
        );
        let bl = all
            .iter()
            .find(|d| d.payload_type == "BitLocker" && d.key_path == "AllowStandardUserEncryption")
            .expect("BitLocker.AllowStandardUserEncryption");
        assert!(
            bl.dependencies
                .iter()
                .any(|d| d.uri.contains("AllowWarningForOtherDiskEncryption")),
            "{:?}",
            bl.dependencies
        );
    }
}
