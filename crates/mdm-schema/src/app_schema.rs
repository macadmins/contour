//! Parquet readers for App Schema facts about managed-preference domains.
//!
//! Some domains are described from an App Schema v1 document — an app's own
//! source, or a vendor-published schema — rather than from ProfileManifests. The settable keys arrive in `capabilities`; these two
//! datasets carry what the capability columns cannot hold:
//!
//! - [`keys::read`] — keys that must **not** appear in a profile (the app
//!   writes them, a script writes them, or the app stopped reading them),
//!   keys read from another domain, and deprecated keys with what replaced
//!   them.
//! - [`rules::read`] — conditions across keys and on the delivery context,
//!   with predicates kept as JSON in the format's grammar.
//!
//! Both join `capabilities` on `domain = payload_type`.

use anyhow::{Context, Result};
use arrow::array::{Array, AsArray};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::{AppSchemaKey, AppSchemaRule};

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

/// Keys a document lists outside its settable properties.
pub mod keys {
    use super::*;

    /// Read App Schema key rows from Parquet bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not the expected Parquet layout.
    pub fn read(bytes: &[u8]) -> Result<Vec<AppSchemaKey>> {
        let bytes = Bytes::copy_from_slice(bytes);
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
            .build()
            .context("building app_schema_keys Parquet reader")?;

        let mut out = Vec::new();
        for batch in reader {
            let batch = batch.context("reading record batch")?;
            let domains = col(&batch, "domain")?.as_string::<i32>();
            let kinds = col(&batch, "kind")?.as_string::<i32>();
            let key_names = col(&batch, "key")?.as_string::<i32>();
            let plist_types = col(&batch, "plist_type")?.as_string::<i32>();
            let defaults = col(&batch, "default_value")?.as_string::<i32>();
            let descriptions = col(&batch, "description")?.as_string::<i32>();
            let templates = col(&batch, "template")?.as_string::<i32>();
            let placeholders = col(&batch, "placeholders")?.as_string::<i32>();
            let removed_in = col(&batch, "removed_in")?.as_string::<i32>();
            let replacement_domains = col(&batch, "replacement_domain")?.as_string::<i32>();
            let replacement_keys = col(&batch, "replacement_key")?.as_string::<i32>();

            for row in 0..batch.num_rows() {
                out.push(AppSchemaKey {
                    domain: domains.value(row).to_string(),
                    kind: kinds.value(row).to_string(),
                    key: key_names.value(row).to_string(),
                    plist_type: opt_str(plist_types, row),
                    default_value: opt_str(defaults, row),
                    description: opt_str(descriptions, row),
                    template: opt_str(templates, row),
                    placeholders: opt_str(placeholders, row),
                    removed_in: opt_str(removed_in, row),
                    replacement_domain: opt_str(replacement_domains, row),
                    replacement_key: opt_str(replacement_keys, row),
                });
            }
        }
        Ok(out)
    }
}

/// Rules a document states.
pub mod rules {
    use super::*;

    /// Read App Schema rules from Parquet bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not the expected Parquet layout.
    pub fn read(bytes: &[u8]) -> Result<Vec<AppSchemaRule>> {
        let bytes = Bytes::copy_from_slice(bytes);
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
            .build()
            .context("building app_schema_rules Parquet reader")?;

        let mut out = Vec::new();
        for batch in reader {
            let batch = batch.context("reading record batch")?;
            let domains = col(&batch, "domain")?.as_string::<i32>();
            let rule_ids = col(&batch, "rule_id")?.as_string::<i32>();
            let severities = col(&batch, "severity")?.as_string::<i32>();
            let scopes = col(&batch, "scope")?.as_string::<i32>();
            let whens = col(&batch, "when_predicate")?.as_string::<i32>();
            let asserts = col(&batch, "assert_predicate")?.as_string::<i32>();
            let effects = col(&batch, "effect")?.as_string::<i32>();
            let messages = col(&batch, "message")?.as_string::<i32>();
            let details = col(&batch, "detail")?.as_string::<i32>();
            let origins = col(&batch, "origin")?.as_string::<i32>();

            for row in 0..batch.num_rows() {
                out.push(AppSchemaRule {
                    domain: domains.value(row).to_string(),
                    rule_id: rule_ids.value(row).to_string(),
                    severity: severities.value(row).to_string(),
                    scope: opt_str(scopes, row),
                    when_predicate: opt_str(whens, row),
                    assert_predicate: opt_str(asserts, row),
                    effect: opt_str(effects, row),
                    message: messages.value(row).to_string(),
                    detail: opt_str(details, row),
                    origin: origins.value(row).to_string(),
                });
            }
        }
        Ok(out)
    }
}
