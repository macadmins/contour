//! Pattern detection algorithms for bundle discovery.

use crate::bundle::Bundle;
use crate::cel::AppRecord;
use crate::models::RuleType;
use std::collections::HashSet;

/// Type of discovered pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternType {
    /// Vendor-level pattern (by TeamID)
    Vendor,
    /// App-level pattern (by SigningID)
    App,
    /// Name-based pattern (by app name similarity)
    NamePattern,
}

impl PatternType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PatternType::Vendor => "vendor",
            PatternType::App => "app",
            PatternType::NamePattern => "name_pattern",
        }
    }
}

/// A discovered pattern from analyzing app data.
#[derive(Debug, Clone)]
pub struct DiscoveredPattern {
    /// Suggested bundle name.
    pub name: String,
    /// Description of the pattern.
    pub description: String,
    /// Type of pattern.
    pub pattern_type: PatternType,
    /// CEL expression to match this pattern.
    pub cel_expression: String,
    /// Primary identifier (TeamID, SigningID, etc.)
    pub identifier: String,
    /// Rule type to use for this pattern.
    pub rule_type: RuleType,
    /// Number of unique devices this pattern covers.
    pub device_count: usize,
    /// Number of unique apps matching this pattern.
    pub app_count: usize,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Sample app names for reference.
    pub sample_apps: Vec<String>,
    /// Vendor/publisher name if known.
    pub vendor: Option<String>,
}

impl DiscoveredPattern {
    /// Create a new vendor pattern.
    pub fn vendor(
        name: String,
        team_id: &str,
        vendor: Option<String>,
        device_count: usize,
        app_count: usize,
        sample_apps: Vec<String>,
    ) -> Self {
        let description = match &vendor {
            Some(v) => format!("{} (TeamID: {})", v, team_id),
            None => format!("Vendor with TeamID: {}", team_id),
        };

        let cel = format!(r#"has(app.team_id) && app.team_id == "{}""#, team_id);

        // Confidence based on app count and device coverage
        let confidence =
            (app_count as f64 / 10.0).min(1.0) * 0.5 + (device_count as f64 / 100.0).min(1.0) * 0.5;

        Self {
            name,
            description,
            pattern_type: PatternType::Vendor,
            cel_expression: cel,
            identifier: team_id.to_string(),
            rule_type: RuleType::TeamId,
            device_count,
            app_count,
            confidence,
            sample_apps,
            vendor,
        }
    }

    /// Create a new app pattern.
    pub fn app(
        name: String,
        signing_id: &str,
        app_name: Option<String>,
        device_count: usize,
    ) -> Self {
        let description = match &app_name {
            Some(n) => format!("{} (SigningID: {})", n, signing_id),
            None => format!("App with SigningID: {}", signing_id),
        };

        let cel = format!(
            r#"has(app.signing_id) && app.signing_id == "{}""#,
            signing_id
        );

        Self {
            name,
            description,
            pattern_type: PatternType::App,
            cel_expression: cel,
            identifier: signing_id.to_string(),
            rule_type: RuleType::SigningId,
            device_count,
            app_count: 1,
            confidence: (device_count as f64 / 50.0).min(1.0),
            sample_apps: app_name.into_iter().collect(),
            vendor: None,
        }
    }

    /// Convert this pattern to a bundle definition.
    pub fn to_bundle(&self) -> Bundle {
        Bundle::new(&self.name, &self.cel_expression)
            .with_description(&self.description)
            .with_rule_type(self.rule_type)
            .with_device_coverage(self.device_count)
            .with_app_count(self.app_count)
            .with_confidence(self.confidence)
    }

    /// Get coverage percentage relative to total devices.
    pub fn coverage_percentage(&self, total_devices: usize) -> f64 {
        if total_devices == 0 {
            0.0
        } else {
            (self.device_count as f64 / total_devices as f64) * 100.0
        }
    }
}

/// Collected information about a vendor (by TeamID).
#[derive(Debug)]
pub struct VendorInfo {
    /// The TeamID.
    pub team_id: String,
    /// Vendor/publisher names seen.
    pub vendor_names: HashSet<String>,
    /// App names from this vendor.
    pub app_names: Vec<String>,
    /// Unique devices with apps from this vendor.
    pub devices: HashSet<String>,
}

impl VendorInfo {
    /// Create a new vendor info collector.
    pub fn new(team_id: String) -> Self {
        Self {
            team_id,
            vendor_names: HashSet::new(),
            app_names: Vec::new(),
            devices: HashSet::new(),
        }
    }

    /// Add an app to this vendor's info.
    pub fn add_app(&mut self, app: &AppRecord) {
        if let Some(name) = &app.app_name {
            if !self.app_names.contains(name) {
                self.app_names.push(name.clone());
            }
        }
        if let Some(vendor) = &app.vendor {
            self.vendor_names.insert(vendor.clone());
        }
        for device in &app.devices {
            self.devices.insert(device.clone());
        }
    }

    /// Number of unique apps from this vendor.
    pub fn app_count(&self) -> usize {
        self.app_names.len()
    }

    /// Number of unique devices with apps from this vendor.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Get the best vendor name.
    pub fn best_vendor_name(&self) -> Option<String> {
        // Prefer longer names (more descriptive)
        self.vendor_names.iter().max_by_key(|n| n.len()).cloned()
    }

    /// Convert to a discovered pattern.
    pub fn into_pattern(self, _total_devices: usize) -> DiscoveredPattern {
        let vendor = self.best_vendor_name();
        let name = super::suggest_bundle_name(vendor.as_deref(), &self.team_id);
        let device_count = self.devices.len();
        let app_count = self.app_names.len();
        let sample_apps: Vec<String> = self.app_names.into_iter().take(5).collect();

        DiscoveredPattern::vendor(
            name,
            &self.team_id,
            vendor,
            device_count,
            app_count.max(1),
            sample_apps,
        )
    }
}

/// Collected information about a SigningID (app level).
#[derive(Debug)]
pub struct SigningIdInfo {
    /// The SigningID (e.g., "EQHXZ8M8AV:com.google.Chrome").
    pub signing_id: String,
    /// App name if known.
    pub app_name: Option<String>,
    /// Team ID extracted from SigningID.
    pub team_id: Option<String>,
    /// Unique devices with this app.
    pub devices: HashSet<String>,
}

impl SigningIdInfo {
    /// Create a new SigningID info collector.
    pub fn new(signing_id: String) -> Self {
        let team_id = signing_id.split(':').next().map(|s| s.to_string());
        Self {
            signing_id,
            app_name: None,
            team_id,
            devices: HashSet::new(),
        }
    }

    /// Add an app record to this SigningID's info.
    pub fn add_app(&mut self, app: &AppRecord) {
        if self.app_name.is_none() {
            self.app_name.clone_from(&app.app_name);
        }
        for device in &app.devices {
            self.devices.insert(device.clone());
        }
    }

    /// Number of unique devices with this app.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Convert to a discovered pattern.
    pub fn into_pattern(self) -> DiscoveredPattern {
        DiscoveredPattern::app(
            self.app_name.clone().unwrap_or_else(|| {
                // Extract bundle ID from signing ID as fallback name
                self.signing_id
                    .split(':')
                    .nth(1)
                    .unwrap_or(&self.signing_id)
                    .to_string()
            }),
            &self.signing_id,
            self.app_name,
            self.devices.len(),
        )
    }
}

/// Check if a string is a valid Apple TeamID.
pub fn is_valid_team_id(s: &str) -> bool {
    s.len() == 10 && s.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Check if a string is a valid SigningID.
#[allow(dead_code, reason = "reserved for future use")]
pub fn is_valid_signing_id(s: &str) -> bool {
    if let Some((team_part, bundle_part)) = s.split_once(':') {
        (is_valid_team_id(team_part) || team_part == "platform") && !bundle_part.is_empty()
    } else {
        false
    }
}

/// Normalize an app name for grouping.
#[allow(dead_code, reason = "reserved for future use")]
pub fn normalize_app_name(name: &str) -> String {
    name.to_lowercase()
        .replace(|c: char| !c.is_ascii_alphanumeric(), " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovered_pattern_vendor() {
        let pattern = DiscoveredPattern::vendor(
            "google".to_string(),
            "EQHXZ8M8AV",
            Some("Google LLC".to_string()),
            100,
            5,
            vec!["Chrome".to_string(), "Drive".to_string()],
        );

        assert_eq!(pattern.pattern_type, PatternType::Vendor);
        assert_eq!(pattern.rule_type, RuleType::TeamId);
        assert!(pattern.cel_expression.contains("EQHXZ8M8AV"));
    }

    #[test]
    fn test_pattern_to_bundle() {
        let pattern = DiscoveredPattern::vendor(
            "microsoft".to_string(),
            "UBF8T346G9",
            Some("Microsoft Corporation".to_string()),
            500,
            10,
            vec!["Word".to_string()],
        );

        let bundle = pattern.to_bundle();
        assert_eq!(bundle.name, "microsoft");
        assert_eq!(bundle.rule_type, RuleType::TeamId);
        assert!(bundle.device_coverage.is_some());
    }

    #[test]
    fn test_vendor_info() {
        let mut info = VendorInfo::new("EQHXZ8M8AV".to_string());

        info.add_app(
            &AppRecord::new()
                .with_app_name("Chrome")
                .with_vendor("Google LLC")
                .with_device("device1"),
        );

        info.add_app(
            &AppRecord::new()
                .with_app_name("Drive")
                .with_vendor("Google LLC")
                .with_device("device2"),
        );

        assert_eq!(info.app_count(), 2);
        assert_eq!(info.device_count(), 2);
        assert_eq!(info.best_vendor_name(), Some("Google LLC".to_string()));
    }

    #[test]
    fn test_normalize_app_name() {
        assert_eq!(normalize_app_name("Google Chrome"), "google chrome");
        assert_eq!(
            normalize_app_name("Microsoft Word 2021"),
            "microsoft word 2021"
        );
        assert_eq!(normalize_app_name("App-Name_v2.1"), "app name v2 1");
    }
}
