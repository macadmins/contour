//! Arrow schema and Parquet reader for Apple device-management capabilities.

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use arrow::datatypes::{DataType, Field, Schema};
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

/// Read a per-key `supportedOS` string column. The producer writes the
/// `n/a` sentinel when a key is unsupported on a platform; treat that —
/// and SQL NULL — alike as "absent" so the key gets no map entry there.
fn key_os_value(arr: &arrow::array::StringArray, row: usize) -> Option<String> {
    if arr.is_null(row) {
        return None;
    }
    match arr.value(row) {
        "n/a" => None,
        v => Some(v.to_string()),
    }
}

/// Arrow schema for `capabilities.parquet`.
///
/// One row per (payload_type, platform, key) combination.
pub fn schema() -> Schema {
    Schema::new(vec![
        // Capability identity
        Field::new("payload_type", DataType::Utf8, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("title", DataType::Utf8, false),
        Field::new("description", DataType::Utf8, true),
        Field::new("apply_mode", DataType::Utf8, true),
        Field::new("ddm_category", DataType::Utf8, true),
        // OS support
        Field::new("platform", DataType::Utf8, false),
        Field::new("introduced", DataType::Utf8, true),
        Field::new("deprecated", DataType::Utf8, true),
        Field::new("removed", DataType::Utf8, true),
        Field::new("allowed_enrollments", DataType::Utf8, true),
        Field::new("allowed_scopes", DataType::Utf8, true),
        Field::new("supervised", DataType::Boolean, true),
        Field::new("user_channel", DataType::Boolean, true),
        Field::new("device_channel", DataType::Boolean, true),
        Field::new("requires_dep", DataType::Boolean, true),
        Field::new("user_approved_mdm", DataType::Boolean, true),
        Field::new("allow_manual_install", DataType::Boolean, true),
        Field::new("shared_ipad_mode", DataType::Utf8, true),
        Field::new("user_enrollment_mode", DataType::Utf8, true),
        // Key identity
        Field::new("key_name", DataType::Utf8, false),
        Field::new("key_data_type", DataType::Utf8, false),
        Field::new("key_presence", DataType::Utf8, true),
        Field::new("key_default", DataType::Utf8, true),
        Field::new("key_range_min", DataType::Float64, true),
        Field::new("key_range_max", DataType::Float64, true),
        // Key hierarchy
        Field::new("parent_key", DataType::Utf8, true),
        Field::new("depth", DataType::UInt32, false),
        // Key metadata
        Field::new("combinetype", DataType::Utf8, true),
        Field::new("key_title", DataType::Utf8, true),
        Field::new("key_description", DataType::Utf8, true),
        Field::new("subtype", DataType::Utf8, true),
        Field::new("asset_types", DataType::Utf8, true),
        Field::new("format", DataType::Utf8, true),
        // Per-key supportedOS — the key's own introduced/deprecated/
        // supervised, distinct from the payload-level columns above.
        // `key_introduced`/`key_deprecated` carry the `n/a` sentinel when
        // the key is unsupported on a platform.
        Field::new("key_introduced", DataType::Utf8, true),
        Field::new("key_deprecated", DataType::Utf8, true),
        Field::new("key_supervised", DataType::Boolean, true),
        // Windows CSP / manifest provenance
        Field::new("csp_name", DataType::Utf8, true),
        Field::new("manifest_source", DataType::Utf8, true),
    ])
}

/// Read capabilities from Parquet bytes into domain types.
///
/// Groups rows by payload_type into Capability structs.
/// Each row contains one (payload_type, platform, key) tuple.
pub fn read(bytes: &[u8]) -> Result<Vec<Capability>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("Failed to build capabilities Parquet reader")?;

    // Use (payload_type) as grouping key. Accumulate OS support and keys.
    let mut cap_map: indexmap::IndexMap<String, Capability> = indexmap::IndexMap::new();
    // Track which (payload_type, platform) combos we've already added OsSupport for
    let mut seen_os: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for batch in reader {
        let batch = batch.context("Failed to read record batch")?;
        let num_rows = batch.num_rows();

        // Extract columns
        let payload_types = col(&batch, "payload_type")?.as_string::<i32>();
        let kinds = col(&batch, "kind")?.as_string::<i32>();
        let titles_col = col(&batch, "title")?.as_string::<i32>();
        let descs = col(&batch, "description")?.as_string::<i32>();
        let apply_modes = col(&batch, "apply_mode")?.as_string::<i32>();
        let ddm_cats = col(&batch, "ddm_category")?.as_string::<i32>();
        let platforms_col = col(&batch, "platform")?.as_string::<i32>();
        let introduced = col(&batch, "introduced")?.as_string::<i32>();
        let deprecated = col(&batch, "deprecated")?.as_string::<i32>();
        let removed = col(&batch, "removed")?.as_string::<i32>();
        let enrollments = col(&batch, "allowed_enrollments")?.as_string::<i32>();
        let scopes = col(&batch, "allowed_scopes")?.as_string::<i32>();
        let supervised = col(&batch, "supervised")?.as_boolean();
        let user_ch = col(&batch, "user_channel")?.as_boolean();
        let device_ch = col(&batch, "device_channel")?.as_boolean();
        let requires_dep_col = col(&batch, "requires_dep")?.as_boolean();
        let user_approved_mdm_col = col(&batch, "user_approved_mdm")?.as_boolean();
        let allow_manual_install_col = col(&batch, "allow_manual_install")?.as_boolean();
        let shared_ipad_col = col(&batch, "shared_ipad_mode")?.as_string::<i32>();
        let user_enrollment_col = col(&batch, "user_enrollment_mode")?.as_string::<i32>();
        let key_names = col(&batch, "key_name")?.as_string::<i32>();
        let key_types = col(&batch, "key_data_type")?.as_string::<i32>();
        let key_presences = col(&batch, "key_presence")?.as_string::<i32>();
        let key_defaults = col(&batch, "key_default")?.as_string::<i32>();
        let range_mins =
            col(&batch, "key_range_min")?.as_primitive::<arrow::datatypes::Float64Type>();
        let range_maxs =
            col(&batch, "key_range_max")?.as_primitive::<arrow::datatypes::Float64Type>();
        let parent_keys = col(&batch, "parent_key")?.as_string::<i32>();
        let depths = col(&batch, "depth")?.as_primitive::<arrow::datatypes::UInt32Type>();
        let combinetypes = col(&batch, "combinetype")?.as_string::<i32>();
        let key_titles = col(&batch, "key_title")?.as_string::<i32>();
        let key_descs = col(&batch, "key_description")?.as_string::<i32>();
        let subtypes = col(&batch, "subtype")?.as_string::<i32>();
        let asset_types = col(&batch, "asset_types")?.as_string::<i32>();
        let formats = col(&batch, "format")?.as_string::<i32>();
        // Per-key supportedOS columns — the key's own metadata.
        let key_introduced_col = col(&batch, "key_introduced")?.as_string::<i32>();
        let key_deprecated_col = col(&batch, "key_deprecated")?.as_string::<i32>();
        let key_supervised_col = col(&batch, "key_supervised")?.as_boolean();
        // csp_name / manifest_source may be absent in older data
        let csp_names = batch
            .column_by_name("csp_name")
            .map(|c| c.as_string::<i32>());
        let manifest_sources = batch
            .column_by_name("manifest_source")
            .map(|c| c.as_string::<i32>());
        // key_rangelist (JSON string array) is absent in parquets generated
        // before posture-ingest added it (40-column layout); those keys read
        // as range_list: None.
        let key_rangelists = batch
            .column_by_name("key_rangelist")
            .map(|c| c.as_string::<i32>());

        for row in 0..num_rows {
            let pt = payload_types.value(row);
            let platform_str = platforms_col.value(row);

            let cap = cap_map.entry(pt.to_string()).or_insert_with(|| {
                let kind = match kinds.value(row) {
                    "MdmProfile" => PayloadKind::MdmProfile,
                    "DdmDeclaration" => PayloadKind::DdmDeclaration,
                    "MdmCommand" => PayloadKind::MdmCommand,
                    "MdmCheckin" => PayloadKind::MdmCheckin,
                    _ => PayloadKind::MdmProfile,
                };
                Capability {
                    payload_type: pt.to_string(),
                    kind,
                    title: titles_col.value(row).to_string(),
                    description: if descs.is_null(row) {
                        String::new()
                    } else {
                        descs.value(row).to_string()
                    },
                    supported_os: Vec::new(),
                    keys: Vec::new(),
                    apply_mode: if apply_modes.is_null(row) {
                        None
                    } else {
                        ApplyMode::parse(apply_modes.value(row))
                    },
                    ddm_category: if ddm_cats.is_null(row) {
                        None
                    } else {
                        match ddm_cats.value(row) {
                            "configuration" => Some(DdmCategory::Configuration),
                            "asset" => Some(DdmCategory::Asset),
                            "activation" => Some(DdmCategory::Activation),
                            "management" => Some(DdmCategory::Management),
                            _ => None,
                        }
                    },
                    csp_name: match csp_names {
                        Some(col) if !col.is_null(row) => Some(col.value(row).to_string()),
                        _ => None,
                    },
                    manifest_source: match manifest_sources {
                        Some(col) if !col.is_null(row) => Some(col.value(row).to_string()),
                        _ => None,
                    },
                }
            });

            // Add OsSupport if not already seen for this (payload_type, platform)
            let os_key = (pt.to_string(), platform_str.to_string());
            if seen_os.insert(os_key) {
                let parse_json_vec =
                    |col: &arrow::array::StringArray, row: usize| -> Option<Vec<String>> {
                        if col.is_null(row) {
                            return None;
                        }
                        let s = col.value(row);
                        serde_json::from_str(s).ok()
                    };

                let platform = match platform_str {
                    "macOS" => Platform::MacOS,
                    "iOS" => Platform::IOS,
                    "tvOS" => Platform::TvOS,
                    "visionOS" => Platform::VisionOS,
                    "watchOS" => Platform::WatchOS,
                    _ => Platform::MacOS,
                };

                cap.supported_os.push(OsSupport {
                    platform,
                    introduced: if introduced.is_null(row) {
                        None
                    } else {
                        Some(introduced.value(row).to_string())
                    },
                    deprecated: if deprecated.is_null(row) {
                        None
                    } else {
                        Some(deprecated.value(row).to_string())
                    },
                    removed: if removed.is_null(row) {
                        None
                    } else {
                        Some(removed.value(row).to_string())
                    },
                    allowed_enrollments: parse_json_vec(enrollments, row),
                    allowed_scopes: parse_json_vec(scopes, row),
                    supervised: if supervised.is_null(row) {
                        None
                    } else {
                        Some(supervised.value(row))
                    },
                    requires_dep: if requires_dep_col.is_null(row) {
                        None
                    } else {
                        Some(requires_dep_col.value(row))
                    },
                    user_approved_mdm: if user_approved_mdm_col.is_null(row) {
                        None
                    } else {
                        Some(user_approved_mdm_col.value(row))
                    },
                    allow_manual_install: if allow_manual_install_col.is_null(row) {
                        None
                    } else {
                        Some(allow_manual_install_col.value(row))
                    },
                    device_channel: if device_ch.is_null(row) {
                        None
                    } else {
                        Some(device_ch.value(row))
                    },
                    user_channel: if user_ch.is_null(row) {
                        None
                    } else {
                        Some(user_ch.value(row))
                    },
                    shared_ipad_mode: if shared_ipad_col.is_null(row) {
                        None
                    } else {
                        Some(shared_ipad_col.value(row).to_string())
                    },
                    user_enrollment_mode: if user_enrollment_col.is_null(row) {
                        None
                    } else {
                        Some(user_enrollment_col.value(row).to_string())
                    },
                    multiple: None,
                    beta: None,
                });
            }

            // Merge PayloadKey across the parquet's per-(payload_type,
            // platform, key) rows. The first sighting seeds the entry;
            // subsequent rows accumulate introduced/deprecated into
            // per-platform maps so callers can answer "when did this key
            // land on iOS vs macOS?".
            let key_name = key_names.value(row).to_string();
            let row_platform = match platform_str {
                "macOS" => Platform::MacOS,
                "iOS" => Platform::IOS,
                "tvOS" => Platform::TvOS,
                "visionOS" => Platform::VisionOS,
                "watchOS" => Platform::WatchOS,
                _ => Platform::MacOS,
            };
            // Per-key supportedOS — the key's OWN introduced/deprecated/
            // supervised, NOT the payload-level `introduced`/`deprecated`
            // columns (those feed `OsSupport` above). `key_os_value`
            // drops the `n/a` sentinel so a platform on which the key is
            // unsupported gets no map entry at all.
            let row_introduced = key_os_value(key_introduced_col, row);
            let row_deprecated = key_os_value(key_deprecated_col, row);
            let row_supervised = if key_supervised_col.is_null(row) {
                None
            } else {
                Some(key_supervised_col.value(row))
            };

            if let Some(existing) = cap.keys.iter_mut().find(|k| k.name == key_name) {
                if let Some(v) = row_introduced {
                    existing.introduced.entry(row_platform).or_insert(v);
                }
                if let Some(v) = row_deprecated {
                    existing.deprecated.entry(row_platform).or_insert(v);
                }
                if let Some(s) = row_supervised {
                    existing.supervised.entry(row_platform).or_insert(s);
                }
                continue;
            }

            let mut introduced_map = std::collections::HashMap::new();
            if let Some(v) = row_introduced {
                introduced_map.insert(row_platform, v);
            }
            let mut deprecated_map = std::collections::HashMap::new();
            if let Some(v) = row_deprecated {
                deprecated_map.insert(row_platform, v);
            }
            let mut supervised_map = std::collections::HashMap::new();
            if let Some(s) = row_supervised {
                supervised_map.insert(row_platform, s);
            }

            cap.keys.push(PayloadKey {
                name: key_name,
                data_type: key_types.value(row).to_string(),
                presence: if key_presences.is_null(row) {
                    String::new()
                } else {
                    key_presences.value(row).to_string()
                },
                default_value: if key_defaults.is_null(row) {
                    None
                } else {
                    // The column stores scalar defaults JSON-encoded ("Allowed"
                    // arrives as the text `"Allowed"`, booleans as `true`).
                    // Decode; anything that isn't valid JSON is a plain string.
                    let raw = key_defaults.value(row);
                    Some(
                        serde_json::from_str(raw)
                            .unwrap_or_else(|_| serde_json::Value::String(raw.to_string())),
                    )
                },
                range_min: if range_mins.is_null(row) {
                    None
                } else {
                    Some(range_mins.value(row))
                },
                range_max: if range_maxs.is_null(row) {
                    None
                } else {
                    Some(range_maxs.value(row))
                },
                range_list: key_rangelists.and_then(|arr| {
                    if arr.is_null(row) {
                        None
                    } else {
                        serde_json::from_str(arr.value(row)).ok()
                    }
                }),
                introduced: introduced_map,
                deprecated: deprecated_map,
                supervised: supervised_map,
                parent_key: if parent_keys.is_null(row) {
                    None
                } else {
                    Some(parent_keys.value(row).to_string())
                },
                depth: depths.value(row),
                combinetype: if combinetypes.is_null(row) {
                    None
                } else {
                    Some(combinetypes.value(row).to_string())
                },
                key_title: if key_titles.is_null(row) {
                    None
                } else {
                    Some(key_titles.value(row).to_string())
                },
                key_description: if key_descs.is_null(row) {
                    None
                } else {
                    Some(key_descs.value(row).to_string())
                },
                subtype: if subtypes.is_null(row) {
                    None
                } else {
                    Some(subtypes.value(row).to_string())
                },
                asset_types: if asset_types.is_null(row) {
                    None
                } else {
                    serde_json::from_str(asset_types.value(row)).ok()
                },
                format: if formats.is_null(row) {
                    None
                } else {
                    Some(formats.value(row).to_string())
                },
            });
        }
    }

    Ok(cap_map.into_values().collect())
}
