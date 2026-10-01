//! Fleet label naming for santa's ring editions, used by
//! `cli::fleet::run_fragment` — the one emitter `santa fleet` runs, with or
//! without `--fragment`.

use crate::models::Ring;

/// The Fleet labels a ring's profiles target.
///
/// A ring with explicit `fleet_labels` uses them; otherwise `ring:<priority>`.
/// The emitter writes a label definition for every name returned here, so a
/// profile never targets a label that does not exist — which is the other
/// half of what the removed emitter got wrong.
pub fn ring_to_fleet_labels(ring: &Ring) -> Vec<String> {
    if ring.fleet_labels.is_empty() {
        // Default label format
        vec![format!("ring:{}", ring.priority)]
    } else {
        ring.fleet_labels.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_to_fleet_labels() {
        let ring = Ring::new("ring0", 0);
        let labels = ring_to_fleet_labels(&ring);
        assert_eq!(labels, vec!["ring:0"]);

        let ring_with_labels = Ring::new("canary", 0)
            .with_fleet_labels(vec!["deployment:canary".to_string(), "ring:0".to_string()]);
        let labels = ring_to_fleet_labels(&ring_with_labels);
        assert_eq!(labels.len(), 2);
    }
}
