use anyhow::{Context, Result};
use arrow::array::AsArray;
use arrow::datatypes::{DataType, Field, Schema};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::types::ControlTier;

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
        Field::new("control_id", DataType::Utf8, false),
        Field::new("tier", DataType::Utf8, false),
    ])
}

pub fn read(bytes: &[u8]) -> Result<Vec<ControlTier>> {
    let bytes = Bytes::copy_from_slice(bytes);
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?
        .build()
        .context("building control_tiers Parquet reader")?;

    let mut out = Vec::new();

    for batch in reader {
        let batch = batch.context("reading record batch")?;
        let control_ids = col(&batch, "control_id")?.as_string::<i32>();
        let tiers = col(&batch, "tier")?.as_string::<i32>();

        for row in 0..batch.num_rows() {
            out.push(ControlTier {
                control_id: control_ids.value(row).to_string(),
                tier: tiers.value(row).to_string(),
            });
        }
    }

    Ok(out)
}
