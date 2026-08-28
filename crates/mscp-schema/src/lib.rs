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

// ── Beta channel ────────────────────────────────────────────────────────
//
// Built from the mSCP OS-preview branch (e.g. `dev_27`) and published to
// `data/beta/` by the posture pipeline — same layout as the stable set,
// plus preview-only rules (Apple Intelligence PCC, visual intelligence,
// Siri AI, …). Consumers opt in explicitly via `--beta` so the stable
// channel is never affected. Mirrors mdm-schema's `*_beta` accessors.

/// Embedded **beta** baseline metadata Parquet data.
pub fn embedded_baseline_meta_beta() -> &'static [u8] {
    include_bytes!("../data/beta/baseline_meta.parquet")
}

/// Embedded **beta** sections Parquet data.
pub fn embedded_sections_beta() -> &'static [u8] {
    include_bytes!("../data/beta/sections.parquet")
}

/// Embedded **beta** NIST control tiers Parquet data.
pub fn embedded_control_tiers_beta() -> &'static [u8] {
    include_bytes!("../data/beta/control_tiers.parquet")
}

/// Embedded **beta** rule metadata Parquet data.
pub fn embedded_rule_meta_beta() -> &'static [u8] {
    include_bytes!("../data/beta/rule_meta.parquet")
}

/// Embedded **beta** baseline edges Parquet data.
pub fn embedded_baseline_edges_beta() -> &'static [u8] {
    include_bytes!("../data/beta/baseline_edges.parquet")
}

/// Embedded **beta** versioned rules Parquet data.
pub fn embedded_rules_versioned_beta() -> &'static [u8] {
    include_bytes!("../data/beta/rules_versioned.parquet")
}

/// Embedded **beta** rule payloads Parquet data.
pub fn embedded_rule_payloads_beta() -> &'static [u8] {
    include_bytes!("../data/beta/rule_payloads.parquet")
}

/// Embedded **beta** envelope patterns Parquet data.
pub fn embedded_envelope_patterns_beta() -> &'static [u8] {
    include_bytes!("../data/beta/envelope_patterns.parquet")
}

/// Embedded **beta** envelope meta keys Parquet data.
pub fn embedded_envelope_meta_keys_beta() -> &'static [u8] {
    include_bytes!("../data/beta/envelope_meta_keys.parquet")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The beta channel is the mSCP OS-preview branch — it must carry
    /// preview-only rules (Apple Intelligence PCC) that stable does not,
    /// or `--beta` adds nothing.
    #[test]
    fn beta_rules_carry_os_preview_only_rules() {
        let beta = rules_versioned::read(embedded_rules_versioned_beta())
            .expect("read beta rules_versioned");
        assert!(
            beta.iter()
                .any(|r| r.rule_id == "os_apple_intelligence_pcc_disable"),
            "beta channel should carry os_apple_intelligence_pcc_disable"
        );

        let stable =
            rules_versioned::read(embedded_rules_versioned()).expect("read stable rules_versioned");
        assert!(
            !stable
                .iter()
                .any(|r| r.rule_id == "os_apple_intelligence_pcc_disable"),
            "stable channel should NOT carry the OS-preview rule — if it does, \
             the preview graduated and this pin needs a new preview-only rule"
        );
    }

    /// Hard platform separation: the mSCP corpus is Apple-only. Windows
    /// STIG rules live in the windows-schema crate — a Windows row here
    /// means the pipelines re-merged and the separation regressed.
    #[test]
    fn rules_versioned_is_apple_only() {
        let rules =
            rules_versioned::read(embedded_rules_versioned()).expect("read stable rules_versioned");
        assert!(
            rules.iter().all(|r| r.platform != "Windows"),
            "rules_versioned must not carry Windows rows (hard platform separation)"
        );
    }

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
    fn test_rules_have_platform_distinction() {
        // mSCP 2.0 stamps platform on the rule (`rules_versioned`), not the
        // baseline edge — V2 edges carry a null platform.
        let rules = rules_versioned::read(embedded_rules_versioned())
            .expect("Failed to read embedded rules_versioned");
        let platforms: HashSet<&str> = rules.iter().map(|r| r.platform.as_str()).collect();
        assert!(
            platforms.contains("macOS")
                && platforms.contains("iOS")
                && platforms.contains("visionOS"),
            "Expected macOS + iOS + visionOS, got: {platforms:?}"
        );
    }
}
