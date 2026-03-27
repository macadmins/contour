//! Bundle discovery through pattern mining.
//!
//! This module analyzes Fleet CSV data to discover common patterns
//! and suggest bundle definitions.

mod patterns;

pub use patterns::{DiscoveredPattern, PatternType, SigningIdInfo, VendorInfo};

use crate::bundle::{Bundle, BundleSet, DiscoveryConfig};
use crate::cel::{AppRecord, AppRecordSet};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::Read;

/// Default column names for Fleet CSV without headers.
/// Format: device_name, version, sha256, app_name, signing_id, team_id
const DEFAULT_COLUMNS: &[&str] = &[
    "device_name",
    "version",
    "sha256",
    "app_name",
    "signing_id",
    "team_id",
];

/// Parse Fleet CSV data into AppRecords.
///
/// Supports both CSV with headers and headerless CSV (assumes Fleet default column order).
pub fn parse_fleet_csv<R: Read>(reader: R) -> Result<AppRecordSet> {
    let mut apps = AppRecordSet::new();
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(reader);

    let mut records = rdr.records();
    let first_record = records.next();

    // Check if first row looks like headers (contains known column names)
    let (headers, first_data_row) = match first_record {
        Some(Ok(record)) => {
            let first_val = record.get(0).unwrap_or("");
            // If first column looks like a header name, use it
            if is_likely_header(first_val) {
                let headers: Vec<String> = record
                    .iter()
                    .map(|h| h.to_lowercase().replace([' ', '-'], "_"))
                    .collect();
                (headers, None)
            } else {
                // No headers - use defaults
                (
                    DEFAULT_COLUMNS.iter().map(|s| (*s).to_string()).collect(),
                    Some(record),
                )
            }
        }
        Some(Err(e)) => return Err(anyhow::anyhow!("Failed to read first CSV record: {}", e)),
        None => return Ok(apps),
    };

    // Process the first data row if we have one
    if let Some(record) = first_data_row {
        let row: HashMap<String, String> = headers
            .iter()
            .zip(record.iter())
            .map(|(h, v)| (h.clone(), v.to_string()))
            .collect();
        let app = AppRecord::from_csv_row(&row);
        apps.add(app);
    }

    // Process remaining records
    for result in records {
        let record = result.context("Failed to read CSV record")?;
        let row: HashMap<String, String> = headers
            .iter()
            .zip(record.iter())
            .map(|(h, v)| (h.clone(), v.to_string()))
            .collect();

        let app = AppRecord::from_csv_row(&row);
        apps.add(app);
    }

    Ok(apps)
}

/// Check if a string looks like a CSV header name.
fn is_likely_header(s: &str) -> bool {
    let s_lower = s.to_lowercase();
    // Known header patterns
    let header_patterns = [
        "device",
        "host",
        "name",
        "version",
        "sha",
        "hash",
        "app",
        "sign",
        "team",
        "bundle",
        "identifier",
        "vendor",
    ];
    header_patterns.iter().any(|p| s_lower.contains(p))
}

/// Parse Fleet CSV from a file path.
pub fn parse_fleet_csv_file(path: &std::path::Path) -> Result<AppRecordSet> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open CSV file: {}", path.display()))?;
    parse_fleet_csv(file)
}

/// Discovery engine for analyzing app data and suggesting bundles.
#[derive(Debug)]
pub struct DiscoveryEngine {
    config: DiscoveryConfig,
    total_devices: usize,
}

impl DiscoveryEngine {
    /// Create a new discovery engine with the given configuration.
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            config,
            total_devices: 0,
        }
    }

    /// Create a discovery engine with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(DiscoveryConfig::default())
    }

    /// Analyze apps and discover patterns for bundle suggestions.
    ///
    /// Discovers both:
    /// - TeamID-based patterns (vendor level - one rule per vendor)
    /// - SigningID-based patterns (app level - one rule per app)
    pub fn discover(&mut self, apps: &AppRecordSet) -> DiscoveryResult {
        // Calculate total unique devices
        let all_devices: std::collections::HashSet<_> =
            apps.apps().iter().flat_map(|a| a.devices.iter()).collect();
        self.total_devices = all_devices.len().max(1);

        let mut result = DiscoveryResult::new(self.total_devices);

        // Discover vendor patterns (by TeamID) - fewer rules, vendor-level control
        let vendor_patterns = self.discover_vendor_patterns(apps);
        for pattern in vendor_patterns {
            if self.meets_threshold(&pattern) {
                result.add_pattern(pattern);
            }
        }

        // Sort by device coverage
        result.sort_by_coverage();

        result
    }

    /// Analyze apps and discover SigningID-based patterns.
    ///
    /// This produces more granular rules - one rule per unique SigningID.
    /// Better for fine-grained control but more rules to manage.
    pub fn discover_signing_ids(&mut self, apps: &AppRecordSet) -> DiscoveryResult {
        let all_devices: std::collections::HashSet<_> =
            apps.apps().iter().flat_map(|a| a.devices.iter()).collect();
        self.total_devices = all_devices.len().max(1);

        let mut result = DiscoveryResult::new(self.total_devices);

        // Group by SigningID
        let mut by_signing_id: HashMap<String, SigningIdInfo> = HashMap::new();

        for app in apps.apps() {
            if let Some(signing_id) = &app.signing_id {
                if !crate::cel::is_valid_signing_id(signing_id) {
                    continue;
                }

                let entry = by_signing_id
                    .entry(signing_id.clone())
                    .or_insert_with(|| SigningIdInfo::new(signing_id.clone()));
                entry.add_app(app);
            }
        }

        for info in by_signing_id.into_values() {
            let pattern = info.into_pattern();
            if self.meets_threshold(&pattern) {
                result.add_pattern(pattern);
            }
        }

        result.sort_by_coverage();
        result
    }

    /// Discover vendor-level patterns by grouping on TeamID.
    fn discover_vendor_patterns(&self, apps: &AppRecordSet) -> Vec<DiscoveredPattern> {
        let mut by_team_id: HashMap<String, VendorInfo> = HashMap::new();

        for app in apps.apps() {
            if let Some(team_id) = &app.team_id {
                if !patterns::is_valid_team_id(team_id) {
                    continue;
                }

                let entry = by_team_id
                    .entry(team_id.clone())
                    .or_insert_with(|| VendorInfo::new(team_id.clone()));

                entry.add_app(app);
            }
        }

        by_team_id
            .into_values()
            .filter(|v| v.app_count() >= self.config.min_apps)
            .map(|v| v.into_pattern(self.total_devices))
            .collect()
    }

    /// Check if a pattern meets the coverage threshold.
    fn meets_threshold(&self, pattern: &DiscoveredPattern) -> bool {
        let coverage = pattern.device_count as f64 / self.total_devices as f64;
        coverage >= self.config.threshold || pattern.device_count >= 10
    }
}

/// Result of the discovery process.
#[derive(Debug, Default)]
pub struct DiscoveryResult {
    /// Total unique devices in the dataset.
    pub total_devices: usize,
    /// Discovered patterns.
    patterns: Vec<DiscoveredPattern>,
}

impl DiscoveryResult {
    /// Create a new discovery result.
    pub fn new(total_devices: usize) -> Self {
        Self {
            total_devices,
            patterns: Vec::new(),
        }
    }

    /// Add a discovered pattern.
    pub fn add_pattern(&mut self, pattern: DiscoveredPattern) {
        self.patterns.push(pattern);
    }

    /// Get all discovered patterns.
    pub fn patterns(&self) -> &[DiscoveredPattern] {
        &self.patterns
    }

    /// Number of patterns discovered.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Check if no patterns were discovered.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Sort patterns by device coverage (descending).
    pub fn sort_by_coverage(&mut self) {
        self.patterns
            .sort_by(|a, b| b.device_count.cmp(&a.device_count));
    }

    /// Convert patterns to bundle suggestions.
    pub fn to_bundles(&self) -> BundleSet {
        let bundles: Vec<Bundle> = self.patterns.iter().map(|p| p.to_bundle()).collect();
        BundleSet::from_bundles(bundles)
    }

    /// Get patterns as an iterator.
    pub fn iter(&self) -> impl Iterator<Item = &DiscoveredPattern> {
        self.patterns.iter()
    }
}

impl IntoIterator for DiscoveryResult {
    type Item = DiscoveredPattern;
    type IntoIter = std::vec::IntoIter<DiscoveredPattern>;

    fn into_iter(self) -> Self::IntoIter {
        self.patterns.into_iter()
    }
}

/// Generate a suggested bundle name from vendor/team info.
pub fn suggest_bundle_name(vendor: Option<&str>, team_id: &str) -> String {
    if let Some(vendor) = vendor {
        // Extract company name from vendor string
        let name = vendor
            .split(&[',', '(', '-'][..])
            .next()
            .unwrap_or(vendor)
            .trim()
            .to_lowercase()
            .replace(' ', "-")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect::<String>();

        if !name.is_empty() && name.len() <= 30 {
            return name;
        }
    }

    // Fall back to team_id-based name
    format!("vendor-{}", team_id.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fleet_csv() {
        let csv_data = r"name,version,team_id,signing_id,device_name
Google Chrome,120.0,EQHXZ8M8AV,EQHXZ8M8AV:com.google.Chrome,device1
Slack,4.35,BQR82RBBHL,BQR82RBBHL:com.tinyspeck.slackmacgap,device1
Google Chrome,120.0,EQHXZ8M8AV,EQHXZ8M8AV:com.google.Chrome,device2
";

        let apps = parse_fleet_csv(csv_data.as_bytes()).unwrap();
        assert_eq!(apps.len(), 3);
    }

    #[test]
    fn test_discovery_engine() {
        let csv_data = r"name,version,team_id,device_name
App1,1.0,EQHXZ8M8AV,device1
App2,1.0,EQHXZ8M8AV,device1
App3,1.0,EQHXZ8M8AV,device2
App4,1.0,UBF8T346G9,device1
";

        let apps = parse_fleet_csv(csv_data.as_bytes()).unwrap();
        let mut engine = DiscoveryEngine::with_defaults();
        let result = engine.discover(&apps);

        // Should discover EQHXZ8M8AV pattern (3 apps)
        assert!(!result.is_empty());
    }

    #[test]
    fn test_suggest_bundle_name() {
        // Names with spaces become hyphenated
        assert_eq!(
            suggest_bundle_name(Some("Google LLC"), "EQHXZ8M8AV"),
            "google-llc"
        );
        assert_eq!(
            suggest_bundle_name(Some("Microsoft Corporation"), "UBF8T346G9"),
            "microsoft-corporation"
        );
        // Commas split the name, so we get just the first part
        assert_eq!(
            suggest_bundle_name(Some("Zoom Video Communications, Inc."), "BJ4HAAB9B3"),
            "zoom-video-communications"
        );
        // No vendor falls back to team_id
        assert_eq!(suggest_bundle_name(None, "ABC1234567"), "vendor-abc1234567");
    }
}
