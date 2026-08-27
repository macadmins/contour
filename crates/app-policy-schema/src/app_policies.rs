//! Parquet reader for `app_policies.parquet` (AI-tool policy keys).

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::{AppPolicyKey, PolicyChannels};

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

fn opt_str_list(arr: &arrow::array::GenericListArray<i32>, row: usize) -> Option<Vec<String>> {
    if arr.is_null(row) {
        return None;
    }
    let list_value = arr.value(row);
    let string_arr = list_value.as_string::<i32>();
    Some(
        (0..string_arr.len())
            .filter(|&i| !string_arr.is_null(i))
            .map(|i| string_arr.value(i).to_string())
            .collect(),
    )
}

/// Read app policy keys from Parquet bytes. One row per (tool, key).
pub fn read(bytes: &[u8]) -> Result<Vec<AppPolicyKey>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building app_policies Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;

        let tool_ids = col(&batch, "tool_id")?.as_string::<i32>();
        let tool_names = col(&batch, "tool_name")?.as_string::<i32>();
        let vendors = col(&batch, "vendor")?.as_string::<i32>();
        let categories = col(&batch, "category")?.as_string::<i32>();
        let source_kinds = col(&batch, "source_kind")?.as_string::<i32>();
        let source_urls = col(&batch, "source_url")?.as_string::<i32>();
        let source_versions = col(&batch, "source_version")?.as_string::<i32>();
        let source_hashes = col(&batch, "source_hash")?.as_string::<i32>();
        let key_paths = col(&batch, "key_path")?.as_string::<i32>();
        let key_names = col(&batch, "key_name")?.as_string::<i32>();
        let parent_keys = col(&batch, "parent_key")?.as_string::<i32>();
        let depths = col(&batch, "depth")?.as_primitive::<arrow::datatypes::UInt8Type>();
        let key_types = col(&batch, "key_type")?.as_string::<i32>();
        let item_types = col(&batch, "item_type")?.as_string::<i32>();
        let titles = col(&batch, "title")?.as_string::<i32>();
        let descriptions = col(&batch, "description")?.as_string::<i32>();
        let default_values = col(&batch, "default_value")?.as_string::<i32>();
        let example_values = col(&batch, "example_value")?.as_string::<i32>();
        let allowed_values_col = col(&batch, "allowed_values")?.as_list::<i32>();
        let scopes = col(&batch, "scope")?.as_string::<i32>();
        let managed_onlys = col(&batch, "managed_only")?.as_boolean();
        let merge_strategies = col(&batch, "merge_strategy")?.as_string::<i32>();
        let invalid_behaviors = col(&batch, "invalid_behavior")?.as_string::<i32>();
        let security_relevants = col(&batch, "security_relevant")?.as_boolean();
        let introduceds = col(&batch, "introduced")?.as_string::<i32>();
        let deprecateds = col(&batch, "deprecated")?.as_string::<i32>();
        let provenances = col(&batch, "provenance")?.as_string::<i32>();
        let ch_macos_plist = col(&batch, "ch_macos_plist")?.as_boolean();
        let ch_json_file = col(&batch, "ch_json_file")?.as_boolean();
        let ch_dropin_dir = col(&batch, "ch_dropin_dir")?.as_boolean();
        let ch_win_registry = col(&batch, "ch_win_registry")?.as_boolean();
        let ch_toml_file = col(&batch, "ch_toml_file")?.as_boolean();
        let ch_cloud = col(&batch, "ch_cloud")?.as_boolean();
        let ch_managed_app_config = col(&batch, "ch_managed_app_config")?.as_boolean();
        let macos_domains = col(&batch, "macos_domain")?.as_string::<i32>();
        let channel_names_col = col(&batch, "channel_names")?.as_list::<i32>();
        let channels_col = col(&batch, "channels")?.as_string::<i32>();
        let controls_col = col(&batch, "controls")?.as_list::<i32>();
        let control_ids_col = col(&batch, "control_ids")?.as_list::<i32>();
        let frameworks_col = col(&batch, "frameworks")?.as_list::<i32>();

        for row in 0..batch.num_rows() {
            out.push(AppPolicyKey {
                tool_id: tool_ids.value(row).to_string(),
                tool_name: tool_names.value(row).to_string(),
                vendor: vendors.value(row).to_string(),
                category: categories.value(row).to_string(),
                source_kind: source_kinds.value(row).to_string(),
                source_url: source_urls.value(row).to_string(),
                source_version: opt_str(source_versions, row),
                source_hash: source_hashes.value(row).to_string(),
                key_path: key_paths.value(row).to_string(),
                key_name: key_names.value(row).to_string(),
                parent_key: opt_str(parent_keys, row),
                depth: depths.value(row),
                key_type: key_types.value(row).to_string(),
                item_type: opt_str(item_types, row),
                title: opt_str(titles, row),
                description: opt_str(descriptions, row),
                default_value: opt_str(default_values, row),
                example_value: opt_str(example_values, row),
                allowed_values: opt_str_list(allowed_values_col, row),
                scope: scopes.value(row).to_string(),
                managed_only: managed_onlys.value(row),
                merge_strategy: opt_str(merge_strategies, row),
                invalid_behavior: opt_str(invalid_behaviors, row),
                security_relevant: security_relevants.value(row),
                introduced: opt_str(introduceds, row),
                deprecated: opt_str(deprecateds, row),
                provenance: provenances.value(row).to_string(),
                channels: PolicyChannels {
                    macos_plist: ch_macos_plist.value(row),
                    json_file: ch_json_file.value(row),
                    dropin_dir: ch_dropin_dir.value(row),
                    win_registry: ch_win_registry.value(row),
                    toml_file: ch_toml_file.value(row),
                    cloud: ch_cloud.value(row),
                    managed_app_config: ch_managed_app_config.value(row),
                },
                macos_domain: opt_str(macos_domains, row),
                channel_names: opt_str_list(channel_names_col, row),
                channels_summary: channels_col.value(row).to_string(),
                controls: opt_str_list(controls_col, row),
                control_ids: opt_str_list(control_ids_col, row),
                frameworks: opt_str_list(frameworks_col, row),
            });
        }
    }

    Ok(out)
}
