//! Shared mSCP (macOS Security Compliance Project) metadata and embedded Parquet data.
//!
//! Nine datasets:
//! - `baseline_meta` — baseline names, titles, preambles, authors
//! - `sections` — mSCP section names and descriptions
//! - `control_tiers` — NIST 800-53 control → impact tier mappings
//! - `rule_meta` — lightweight rule metadata (no scripts/fixes)
//! - `baseline_edges` — baseline → section → rule membership
//! - `rules_versioned` — full versioned rules with enforcement metadata
//! - `rule_payloads` — rule enforcement payloads (scripts, mobileconfig, DDM)
//! - `envelope_patterns` — XML envelope nesting patterns for mobileconfig
//! - `envelope_meta_keys` — required metadata keys for envelope layers

pub mod baseline_edges;
pub mod baseline_meta;
pub mod control_tiers;
pub mod envelope_meta_keys;
pub mod envelope_patterns;
pub mod rule_meta;
pub mod rule_payloads;
pub mod rules_versioned;
pub mod sections;
pub mod types;

pub use types::*;

/// Embedded baseline metadata Parquet data.
pub fn embedded_baseline_meta() -> &'static [u8] {
    include_bytes!("../data/baseline_meta.parquet")
}

/// Embedded sections Parquet data.
pub fn embedded_sections() -> &'static [u8] {
    include_bytes!("../data/sections.parquet")
}

/// Embedded NIST control tiers Parquet data.
pub fn embedded_control_tiers() -> &'static [u8] {
    include_bytes!("../data/control_tiers.parquet")
}

/// Embedded rule metadata Parquet data.
pub fn embedded_rule_meta() -> &'static [u8] {
    include_bytes!("../data/rule_meta.parquet")
}

/// Embedded baseline edges Parquet data.
pub fn embedded_baseline_edges() -> &'static [u8] {
    include_bytes!("../data/baseline_edges.parquet")
}

/// Embedded versioned rules Parquet data.
pub fn embedded_rules_versioned() -> &'static [u8] {
    include_bytes!("../data/rules_versioned.parquet")
}

/// Embedded rule payloads Parquet data.
pub fn embedded_rule_payloads() -> &'static [u8] {
    include_bytes!("../data/rule_payloads.parquet")
}

/// Embedded envelope patterns Parquet data.
pub fn embedded_envelope_patterns() -> &'static [u8] {
    include_bytes!("../data/envelope_patterns.parquet")
}

/// Embedded envelope meta keys Parquet data.
pub fn embedded_envelope_meta_keys() -> &'static [u8] {
    include_bytes!("../data/envelope_meta_keys.parquet")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_read_embedded_baseline_meta() {
        let metas = baseline_meta::read(embedded_baseline_meta())
            .expect("Failed to read embedded baseline_meta");
        assert!(
            metas.len() >= 10,
            "Expected at least 10 baselines, got {}",
            metas.len()
        );
        for m in &metas {
            assert!(!m.baseline.is_empty());
            assert!(!m.title.is_empty());
        }
    }

    #[test]
    fn test_read_embedded_sections() {
        let sections =
            sections::read(embedded_sections()).expect("Failed to read embedded sections");
        assert!(
            sections.len() >= 5,
            "Expected at least 5 sections, got {}",
            sections.len()
        );
    }

    #[test]
    fn test_read_embedded_control_tiers() {
        let tiers = control_tiers::read(embedded_control_tiers())
            .expect("Failed to read embedded control_tiers");
        assert!(
            tiers.len() >= 100,
            "Expected at least 100 control tiers, got {}",
            tiers.len()
        );
    }

    #[test]
    fn test_read_embedded_rule_meta() {
        let rules =
            rule_meta::read(embedded_rule_meta()).expect("Failed to read embedded rule_meta");
        assert!(
            rules.len() >= 100,
            "Expected at least 100 rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_read_embedded_baseline_edges() {
        let edges = baseline_edges::read(embedded_baseline_edges())
            .expect("Failed to read embedded baseline_edges");
        assert!(
            edges.len() >= 100,
            "Expected at least 100 edges, got {}",
            edges.len()
        );
    }

    #[test]
    fn test_read_embedded_rules_versioned() {
        let rules = rules_versioned::read(embedded_rules_versioned())
            .expect("Failed to read embedded rules_versioned");
        assert!(
            rules.len() >= 100,
            "Expected at least 100 versioned rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_read_embedded_rule_payloads() {
        let payloads = rule_payloads::read(embedded_rule_payloads())
            .expect("Failed to read embedded rule_payloads");
        assert!(
            payloads.len() >= 100,
            "Expected at least 100 rule payloads, got {}",
            payloads.len()
        );
    }

    #[test]
    fn test_read_embedded_envelope_patterns() {
        let patterns = envelope_patterns::read(embedded_envelope_patterns())
            .expect("Failed to read embedded envelope_patterns");
        assert!(
            patterns.len() >= 3,
            "Expected at least 3 envelope patterns, got {}",
            patterns.len()
        );
    }

    #[test]
    fn test_read_embedded_envelope_meta_keys() {
        let keys = envelope_meta_keys::read(embedded_envelope_meta_keys())
            .expect("Failed to read embedded envelope_meta_keys");
        assert!(
            keys.len() >= 10,
            "Expected at least 10 envelope meta keys, got {}",
            keys.len()
        );
    }

    #[test]
    fn test_edges_have_platform_distinction() {
        let edges = baseline_edges::read(embedded_baseline_edges())
            .expect("Failed to read embedded baseline_edges");
        let platforms: HashSet<&str> = edges.iter().filter_map(|e| e.platform.as_deref()).collect();
        assert!(
            platforms.contains("macOS")
                && platforms.contains("iOS")
                && platforms.contains("visionOS"),
            "Expected macOS + iOS + visionOS, got: {platforms:?}"
        );
    }
}
