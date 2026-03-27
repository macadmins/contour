//! Arrow schema and Parquet reader for ProfileCreator/PayloadSchemas data.

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema, UInt8Type};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::*;

fn col<'a>(
    batch: &'a arrow::record_batch::RecordBatch,
    name: &str,
) -> Result<&'a arrow::array::ArrayRef> {
    batch
        .column_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("missing column '{name}' in Parquet schema"))
}

/// Arrow schema for `profilecreator.parquet`.
///
/// One row per (payload_type, key) combination.
pub fn schema() -> Schema {
    Schema::new(vec![
        // Manifest identity
        Field::new("payload_type", DataType::Utf8, false),
        Field::new("category", DataType::Utf8, false),
        Field::new("title", DataType::Utf8, false),
        Field::new("description", DataType::Utf8, true),
        // Platform support
        Field::new("macos", DataType::Boolean, false),
        Field::new("ios", DataType::Boolean, false),
        Field::new("tvos", DataType::Boolean, false),
        Field::new("watchos", DataType::Boolean, false),
        Field::new("visionos", DataType::Boolean, false),
        // Min versions
        Field::new("min_version_macos", DataType::Utf8, true),
        Field::new("min_version_ios", DataType::Utf8, true),
        Field::new("min_version_tvos", DataType::Utf8, true),
        Field::new("min_version_watchos", DataType::Utf8, true),
        Field::new("min_version_visionos", DataType::Utf8, true),
        // Key identity
        Field::new("key_name", DataType::Utf8, false),
        Field::new("key_type", DataType::Utf8, false),
        Field::new("key_title", DataType::Utf8, true),
        Field::new("key_description", DataType::Utf8, true),
        // Key flags
        Field::new("required", DataType::Boolean, false),
        Field::new("supervised", DataType::Boolean, false),
        Field::new("sensitive", DataType::Boolean, false),
        // Key metadata
        Field::new("default_value", DataType::Utf8, true),
        Field::new("allowed_values", DataType::Utf8, true),
        Field::new("depth", DataType::UInt8, false),
        Field::new("key_platforms", DataType::Utf8, true),
        Field::new("key_min_version", DataType::Utf8, true),
    ])
}

/// Read profile manifests from Parquet bytes into domain types.
///
/// Groups rows by payload_type into PayloadSchema structs.
pub fn read(bytes: &[u8]) -> Result<Vec<PayloadSchema>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("Failed to build profilecreator Parquet reader")?;

    let mut manifests_map: indexmap::IndexMap<String, PayloadSchema> = indexmap::IndexMap::new();

    for batch in reader {
        let batch = batch.context("Failed to read record batch")?;
        let num_rows = batch.num_rows();

        let payload_types = col(&batch, "payload_type")?.as_string::<i32>();
        let categories = col(&batch, "category")?.as_string::<i32>();
        let titles = col(&batch, "title")?.as_string::<i32>();
        let descriptions = col(&batch, "description")?.as_string::<i32>();
        let macos_col = col(&batch, "macos")?.as_boolean();
        let ios_col = col(&batch, "ios")?.as_boolean();
        let tvos_col = col(&batch, "tvos")?.as_boolean();
        let watchos_col = col(&batch, "watchos")?.as_boolean();
        let visionos_col = col(&batch, "visionos")?.as_boolean();
        let mv_macos = col(&batch, "min_version_macos")?.as_string::<i32>();
        let mv_ios = col(&batch, "min_version_ios")?.as_string::<i32>();
        let mv_tvos = col(&batch, "min_version_tvos")?.as_string::<i32>();
        let mv_watchos = col(&batch, "min_version_watchos")?.as_string::<i32>();
        let mv_visionos = col(&batch, "min_version_visionos")?.as_string::<i32>();
        let key_names = col(&batch, "key_name")?.as_string::<i32>();
        let key_types = col(&batch, "key_type")?.as_string::<i32>();
        let key_titles = col(&batch, "key_title")?.as_string::<i32>();
        let key_descs = col(&batch, "key_description")?.as_string::<i32>();
        let required_col = col(&batch, "required")?.as_boolean();
        let supervised_col = col(&batch, "supervised")?.as_boolean();
        let sensitive_col = col(&batch, "sensitive")?.as_boolean();
        let defaults = col(&batch, "default_value")?.as_string::<i32>();
        let allowed = col(&batch, "allowed_values")?.as_string::<i32>();
        let depths = col(&batch, "depth")?.as_primitive::<UInt8Type>();
        let key_platforms = col(&batch, "key_platforms")?.as_string::<i32>();
        let key_min_vers = col(&batch, "key_min_version")?.as_string::<i32>();

        for row in 0..num_rows {
            let pt = payload_types.value(row);

            let manifest = manifests_map
                .entry(pt.to_string())
                .or_insert_with(|| PayloadSchema {
                    payload_type: pt.to_string(),
                    category: categories.value(row).to_string(),
                    title: titles.value(row).to_string(),
                    description: if descriptions.is_null(row) {
                        String::new()
                    } else {
                        descriptions.value(row).to_string()
                    },
                    platforms: PlatformFlags {
                        macos: macos_col.value(row),
                        ios: ios_col.value(row),
                        tvos: tvos_col.value(row),
                        watchos: watchos_col.value(row),
                        visionos: visionos_col.value(row),
                    },
                    min_versions: MinVersions {
                        macos: if mv_macos.is_null(row) {
                            None
                        } else {
                            Some(mv_macos.value(row).to_string())
                        },
                        ios: if mv_ios.is_null(row) {
                            None
                        } else {
                            Some(mv_ios.value(row).to_string())
                        },
                        tvos: if mv_tvos.is_null(row) {
                            None
                        } else {
                            Some(mv_tvos.value(row).to_string())
                        },
                        watchos: if mv_watchos.is_null(row) {
                            None
                        } else {
                            Some(mv_watchos.value(row).to_string())
                        },
                        visionos: if mv_visionos.is_null(row) {
                            None
                        } else {
                            Some(mv_visionos.value(row).to_string())
                        },
                    },
                    fields: Vec::new(),
                });

            manifest.fields.push(ManifestField {
                name: key_names.value(row).to_string(),
                field_type: key_types.value(row).to_string(),
                title: if key_titles.is_null(row) {
                    String::new()
                } else {
                    key_titles.value(row).to_string()
                },
                description: if key_descs.is_null(row) {
                    String::new()
                } else {
                    key_descs.value(row).to_string()
                },
                required: required_col.value(row),
                supervised: supervised_col.value(row),
                sensitive: sensitive_col.value(row),
                default_value: if defaults.is_null(row) {
                    None
                } else {
                    Some(defaults.value(row).to_string())
                },
                allowed_values: if allowed.is_null(row) {
                    None
                } else {
                    Some(allowed.value(row).to_string())
                },
                depth: depths.value(row),
                platforms: if key_platforms.is_null(row) {
                    None
                } else {
                    Some(key_platforms.value(row).to_string())
                },
                min_version: if key_min_vers.is_null(row) {
                    None
                } else {
                    Some(key_min_vers.value(row).to_string())
                },
            });
        }
    }

    Ok(manifests_map.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_has_expected_columns() {
        let s = schema();
        assert!(s.field_with_name("payload_type").is_ok());
        assert!(s.field_with_name("category").is_ok());
        assert!(s.field_with_name("key_name").is_ok());
        assert!(s.field_with_name("sensitive").is_ok());
        assert!(s.field_with_name("allowed_values").is_ok());
        assert_eq!(s.fields().len(), 26);
    }
}
