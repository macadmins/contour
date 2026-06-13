//! Look up embedded example configs by declaration type.

use anyhow::{Result, anyhow};
use mdm_schema::examples::{self, ExampleConfig};

/// Return all embedded examples for a given payload type, sorted by index.
pub fn for_type(payload_type: &str, beta: bool) -> Result<Vec<ExampleConfig>> {
    let bytes = if beta {
        mdm_schema::embedded_examples_beta()
    } else {
        mdm_schema::embedded_examples()
    };
    let mut v: Vec<_> = examples::read(bytes)?
        .into_iter()
        .filter(|e| e.payload_type == payload_type)
        .collect();
    v.sort_by_key(|e| e.index);
    Ok(v)
}

/// Return one specific example by type + index.
pub fn pick(payload_type: &str, index: u32, beta: bool) -> Result<ExampleConfig> {
    for_type(payload_type, beta)?
        .into_iter()
        .find(|e| e.index == index)
        .ok_or_else(|| {
            anyhow!("no example #{index} for {payload_type} (try `ddm examples {payload_type}`)")
        })
}
