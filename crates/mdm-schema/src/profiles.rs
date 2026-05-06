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
///
/// **Schema version 2026.05.06.1** added 9 nullable columns
/// (`kind`, `manifest_source`, `apply_mode`, `deprecated_macos`,
/// `parent_key`, `subtype`, `format`, `device_channel`,
/// `user_channel`) drawn from the upstream pfm_* metadata that the
/// older 26-column schema discarded. All additions are nullable so
/// older parquets without these columns won't fail compat-check —
/// readers must `is_null(row)` defensively.
pub fn schema() -> Schema {
    Schema::new(vec![
        // Manifest identity
        Field::new("payload_type", DataType::Utf8, false),
        // `kind` is 100% populated in current data ("MdmProfile" /
        // "MdmConfig") but kept nullable for compat-check tolerance
        // when consumers pin to older schemas.
        Field::new("kind", DataType::Utf8, true),
        Field::new("manifest_source", DataType::Utf8, true),
        Field::new("apply_mode", DataType::Utf8, true),
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
        // macOS-only deprecation marker — extracted from
        // pfm_macos_deprecated. Other OSes lack the equivalent in
        // ProfileCreator's source data so only macOS is tracked here.
        Field::new("deprecated_macos", DataType::Utf8, true),
        // MDM channel (derived from pfm_targets).
        Field::new("device_channel", DataType::Boolean, true),
        Field::new("user_channel", DataType::Boolean, true),
        // Key identity
        Field::new("key_name", DataType::Utf8, false),
        Field::new("key_type", DataType::Utf8, false),
        Field::new("key_title", DataType::Utf8, true),
        Field::new("key_description", DataType::Utf8, true),
        // Key flags
        Field::new("required", DataType::Boolean, false),
        Field::new("supervised", DataType::Boolean, false),
        // `sensitive` is non-nullable to preserve schema compat with
        // pre-2026.05.06.1 consumers; the producer now reads
        // pfm_sensitive (default false) instead of hardcoding false.
        Field::new("sensitive", DataType::Boolean, false),
        // Key metadata
        Field::new("default_value", DataType::Utf8, true),
        Field::new("allowed_values", DataType::Utf8, true),
        Field::new("depth", DataType::UInt8, false),
        Field::new("parent_key", DataType::Utf8, true),
        Field::new("key_platforms", DataType::Utf8, true),
        Field::new("key_min_version", DataType::Utf8, true),
        Field::new("subtype", DataType::Utf8, true),
        Field::new("format", DataType::Utf8, true),
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
        let kinds = col(&batch, "kind")?.as_string::<i32>();
        let manifest_sources = col(&batch, "manifest_source")?.as_string::<i32>();
        let apply_modes = col(&batch, "apply_mode")?.as_string::<i32>();
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
        let deprecated_macos_col = col(&batch, "deprecated_macos")?.as_string::<i32>();
        let device_ch_col = col(&batch, "device_channel")?.as_boolean();
        let user_ch_col = col(&batch, "user_channel")?.as_boolean();
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
        let parent_keys = col(&batch, "parent_key")?.as_string::<i32>();
        let key_platforms = col(&batch, "key_platforms")?.as_string::<i32>();
        let key_min_vers = col(&batch, "key_min_version")?.as_string::<i32>();
        let subtypes = col(&batch, "subtype")?.as_string::<i32>();
        let formats = col(&batch, "format")?.as_string::<i32>();

        for row in 0..num_rows {
            let pt = payload_types.value(row);

            let manifest = manifests_map
                .entry(pt.to_string())
                .or_insert_with(|| PayloadSchema {
                    payload_type: pt.to_string(),
                    kind: if kinds.is_null(row) {
                        None
                    } else {
                        Some(kinds.value(row).to_string())
                    },
                    manifest_source: if manifest_sources.is_null(row) {
                        None
                    } else {
                        Some(manifest_sources.value(row).to_string())
                    },
                    apply_mode: if apply_modes.is_null(row) {
                        None
                    } else {
                        Some(apply_modes.value(row).to_string())
                    },
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
                    deprecated_macos: if deprecated_macos_col.is_null(row) {
                        None
                    } else {
                        Some(deprecated_macos_col.value(row).to_string())
                    },
                    device_channel: if device_ch_col.is_null(row) {
                        None
                    } else {
                        Some(device_ch_col.value(row))
                    },
                    user_channel: if user_ch_col.is_null(row) {
                        None
                    } else {
                        Some(user_ch_col.value(row))
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
                parent_key: if parent_keys.is_null(row) {
                    None
                } else {
                    Some(parent_keys.value(row).to_string())
                },
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
                subtype: if subtypes.is_null(row) {
                    None
                } else {
                    Some(subtypes.value(row).to_string())
                },
                format: if formats.is_null(row) {
                    None
                } else {
                    Some(formats.value(row).to_string())
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
        // 2026.05.06.1 schema additions — assert each one so a future
        // accidental drop fails the test loudly instead of silently
        // breaking downstream consumers.
        assert!(s.field_with_name("kind").is_ok());
        assert!(s.field_with_name("manifest_source").is_ok());
        assert!(s.field_with_name("apply_mode").is_ok());
        assert!(s.field_with_name("deprecated_macos").is_ok());
        assert!(s.field_with_name("parent_key").is_ok());
        assert!(s.field_with_name("subtype").is_ok());
        assert!(s.field_with_name("format").is_ok());
        assert!(s.field_with_name("device_channel").is_ok());
        assert!(s.field_with_name("user_channel").is_ok());
        assert_eq!(s.fields().len(), 35);
    }
}
