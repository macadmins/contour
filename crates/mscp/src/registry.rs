use anyhow::Result;
use mscp_schema::{BaselineEdge, BaselineMeta, ControlTier, RuleMeta, Section};

/// In-memory registry of all embedded mSCP metadata.
#[derive(Debug)]
pub struct MscpRegistry {
    pub baselines: Vec<BaselineMeta>,
    pub sections: Vec<Section>,
    pub control_tiers: Vec<ControlTier>,
    pub rules: Vec<RuleMeta>,
    pub edges: Vec<BaselineEdge>,
}

/// Filter for platform and OS version when querying edges.
#[derive(Debug)]
pub struct PlatformFilter<'a> {
    pub platform: &'a str,
    pub os_version: Option<&'a str>,
}

impl MscpRegistry {
    /// Load all 5 datasets from embedded Parquet.
    ///
    /// Normalizes edge baseline names to match baseline_meta keys where
    /// they differ (e.g. `DISA-STIG` → `stig`).
    pub fn embedded() -> Result<Self> {
        let baselines = mscp_schema::baseline_meta::read(mscp_schema::embedded_baseline_meta())?;
        let mut edges = mscp_schema::baseline_edges::read(mscp_schema::embedded_baseline_edges())?;

        // Build a set of canonical baseline names from metadata
        let meta_names: Vec<&str> = baselines.iter().map(|b| b.baseline.as_str()).collect();

        // Find edge baseline names that don't match any metadata key
        let mut edge_names: Vec<String> = edges.iter().map(|e| e.baseline.clone()).collect();
        edge_names.sort();
        edge_names.dedup();

        // Build normalization map for unmatched edge names
        let alias_map = build_alias_map(&meta_names, &edge_names);

        // Apply normalization
        if !alias_map.is_empty() {
            for edge in &mut edges {
                if let Some(canonical) = alias_map.get(&edge.baseline) {
                    edge.baseline = canonical.clone();
                }
            }
        }

        Ok(Self {
            baselines,
            sections: mscp_schema::sections::read(mscp_schema::embedded_sections())?,
            control_tiers: mscp_schema::control_tiers::read(mscp_schema::embedded_control_tiers())?,
            rules: mscp_schema::rule_meta::read(mscp_schema::embedded_rule_meta())?,
            edges,
        })
    }

    /// Look up a baseline by name.
    pub fn baseline(&self, name: &str) -> Option<&BaselineMeta> {
        self.baselines.iter().find(|b| b.baseline == name)
    }

    /// Get distinct platforms available in the edge data.
    pub fn platforms(&self) -> Vec<String> {
        let mut seen = Vec::new();
        for e in &self.edges {
            if let Some(p) = &e.platform {
                if !seen.contains(p) {
                    seen.push(p.clone());
                }
            }
        }
        seen
    }

    /// Get distinct (platform, os_version) pairs available.
    pub fn platform_versions(&self) -> Vec<(String, String)> {
        let mut seen = Vec::new();
        for e in &self.edges {
            if let (Some(p), Some(v)) = (&e.platform, &e.os_version) {
                let pair = (p.clone(), v.clone());
                if !seen.contains(&pair) {
                    seen.push(pair);
                }
            }
        }
        seen.sort();
        seen
    }

    /// Get all rule IDs for a baseline, optionally filtered by platform/os.
    pub fn rule_ids_for_baseline(
        &self,
        name: &str,
        filter: Option<&PlatformFilter>,
    ) -> Vec<String> {
        let mut ids: Vec<String> = self
            .edges
            .iter()
            .filter(|e| e.baseline == name && matches_filter(e, filter))
            .map(|e| e.rule_id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Get rules belonging to a baseline, optionally filtered by platform/os.
    pub fn rules_for_baseline(
        &self,
        name: &str,
        filter: Option<&PlatformFilter>,
    ) -> Vec<&RuleMeta> {
        let rule_ids = self.rule_ids_for_baseline(name, filter);
        self.rules
            .iter()
            .filter(|r| rule_ids.iter().any(|id| id == &r.rule_id))
            .collect()
    }

    /// Get sections and their rule IDs for a baseline, optionally filtered.
    pub fn sections_for_baseline(
        &self,
        name: &str,
        filter: Option<&PlatformFilter>,
    ) -> Vec<(String, Vec<String>)> {
        let mut section_map: Vec<(String, Vec<String>)> = Vec::new();

        for edge in self
            .edges
            .iter()
            .filter(|e| e.baseline == name && matches_filter(e, filter))
        {
            if let Some(entry) = section_map.iter_mut().find(|(s, _)| s == &edge.section) {
                if !entry.1.contains(&edge.rule_id) {
                    entry.1.push(edge.rule_id.clone());
                }
            } else {
                section_map.push((edge.section.clone(), vec![edge.rule_id.clone()]));
            }
        }

        section_map
    }

    /// Count unique rules across all platforms for a baseline (for display).
    pub fn unique_rule_count_for_baseline(&self, name: &str) -> usize {
        let mut ids: Vec<&str> = self
            .edges
            .iter()
            .filter(|e| e.baseline == name)
            .map(|e| e.rule_id.as_str())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }
}

/// Build a map from edge baseline names that don't exist in metadata
/// to their canonical metadata key.
///
/// Handles known patterns like `DISA-STIG` → `stig`.
fn build_alias_map(
    meta_names: &[&str],
    edge_names: &[String],
) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();

    for edge_name in edge_names {
        // Already matches metadata — no alias needed
        if meta_names.contains(&edge_name.as_str()) {
            continue;
        }

        // Try lowercase match
        let lower = edge_name.to_lowercase();
        if let Some(&canonical) = meta_names.iter().find(|&&m| m == lower) {
            map.insert(edge_name.clone(), canonical.to_string());
            continue;
        }

        // Try stripping common prefixes (e.g. "DISA-STIG" → "stig")
        for prefix in &["DISA-", "disa-", "NIST-", "nist-"] {
            if let Some(stripped) = edge_name.strip_prefix(prefix) {
                let normalized = stripped.to_lowercase();
                if let Some(&canonical) = meta_names.iter().find(|&&m| m == normalized) {
                    map.insert(edge_name.clone(), canonical.to_string());
                    break;
                }
            }
        }
    }

    map
}

fn matches_filter(edge: &BaselineEdge, filter: Option<&PlatformFilter>) -> bool {
    match filter {
        None => true,
        Some(f) => {
            let platform_match = edge.platform.as_deref().is_some_and(|p| p == f.platform);
            let os_match = match f.os_version {
                None => true,
                Some(v) => edge.os_version.as_deref().is_some_and(|ov| ov == v),
            };
            platform_match && os_match
        }
    }
}
