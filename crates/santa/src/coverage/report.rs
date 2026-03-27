//! Coverage reporting and output formatting.

use super::CoverageAnalysis;
use crate::cel::AppRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A formatted coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Total apps analyzed.
    pub total_apps: usize,
    /// Apps successfully classified.
    pub classified_apps: usize,
    /// Apps that matched no bundle.
    pub orphan_count: usize,
    /// Apps that matched multiple bundles.
    pub conflict_count: usize,
    /// Coverage percentage.
    pub coverage_percentage: f64,
    /// Per-bundle statistics.
    pub bundle_stats: Vec<BundleStats>,
    /// Orphan details (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphan_report: Option<OrphanReport>,
    /// Conflict details (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict_report: Option<ConflictReport>,
}

impl CoverageReport {
    /// Create a report from coverage analysis.
    pub fn from_analysis(analysis: &CoverageAnalysis) -> Self {
        let bundle_stats: Vec<BundleStats> = analysis
            .summary
            .bundles_used
            .iter()
            .map(|(name, count)| BundleStats {
                name: name.clone(),
                app_count: *count,
                percentage: (*count as f64 / analysis.total_apps as f64) * 100.0,
            })
            .collect();

        let orphan_report = if !analysis.orphans.is_empty() {
            Some(OrphanReport::from_apps(&analysis.orphans))
        } else {
            None
        };

        let conflict_report = if !analysis.conflicts.is_empty() {
            Some(ConflictReport::from_conflicts(&analysis.conflicts))
        } else {
            None
        };

        Self {
            total_apps: analysis.total_apps,
            classified_apps: analysis.summary.classified_apps,
            orphan_count: analysis.orphans.len(),
            conflict_count: analysis.conflicts.len(),
            coverage_percentage: analysis.coverage_percentage(),
            bundle_stats,
            orphan_report,
            conflict_report,
        }
    }

    /// Format as a human-readable string.
    pub fn to_human_readable(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("Coverage Report\n{}\n\n", "=".repeat(50)));

        output.push_str(&format!("Total apps:        {}\n", self.total_apps));
        output.push_str(&format!("Classified:        {}\n", self.classified_apps));
        output.push_str(&format!("Orphans:           {}\n", self.orphan_count));
        output.push_str(&format!("Conflicts:         {}\n", self.conflict_count));
        output.push_str(&format!(
            "Coverage:          {:.1}%\n",
            self.coverage_percentage
        ));

        if !self.bundle_stats.is_empty() {
            output.push_str(&format!("\nBundle Statistics\n{}\n", "-".repeat(40)));

            let mut sorted_stats = self.bundle_stats.clone();
            sorted_stats.sort_by(|a, b| b.app_count.cmp(&a.app_count));

            for stat in &sorted_stats {
                output.push_str(&format!(
                    "  {:<25} {:>5} apps ({:.1}%)\n",
                    stat.name, stat.app_count, stat.percentage
                ));
            }
        }

        if let Some(orphan) = &self.orphan_report {
            output.push_str(&format!(
                "\nOrphan Apps (no bundle match)\n{}\n",
                "-".repeat(40)
            ));
            for app in orphan.sample_apps.iter().take(10) {
                output.push_str(&format!("  - {}\n", app));
            }
            if orphan.total_count > 10 {
                output.push_str(&format!("  ... and {} more\n", orphan.total_count - 10));
            }
        }

        if let Some(conflict) = &self.conflict_report {
            output.push_str(&format!(
                "\nConflicts (multiple bundle matches)\n{}\n",
                "-".repeat(40)
            ));
            for (i, item) in conflict.items.iter().enumerate().take(5) {
                output.push_str(&format!(
                    "  {}. {} matched: {:?} -> {}\n",
                    i + 1,
                    item.app_name,
                    item.matching_bundles,
                    item.selected_bundle
                ));
            }
            if conflict.total_count > 5 {
                output.push_str(&format!("  ... and {} more\n", conflict.total_count - 5));
            }
        }

        output
    }
}

/// Statistics for a single bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleStats {
    /// Bundle name.
    pub name: String,
    /// Number of apps in this bundle.
    pub app_count: usize,
    /// Percentage of total apps.
    pub percentage: f64,
}

/// Report on orphan apps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanReport {
    /// Total orphan count.
    pub total_count: usize,
    /// Sample of orphan app names.
    pub sample_apps: Vec<String>,
    /// Orphan apps grouped by team_id (for suggestion).
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub by_team_id: HashMap<String, Vec<String>>,
    /// Orphan apps with no team_id.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unsigned: Vec<String>,
}

impl OrphanReport {
    /// Create an orphan report from app records.
    pub fn from_apps(apps: &[AppRecord]) -> Self {
        let mut by_team_id: HashMap<String, Vec<String>> = HashMap::new();
        let mut unsigned: Vec<String> = Vec::new();
        let mut sample_apps: Vec<String> = Vec::new();

        for app in apps {
            let name = app.display_name();
            sample_apps.push(name.clone());

            if let Some(team_id) = &app.team_id {
                by_team_id.entry(team_id.clone()).or_default().push(name);
            } else {
                unsigned.push(name);
            }
        }

        Self {
            total_count: apps.len(),
            sample_apps,
            by_team_id,
            unsigned,
        }
    }

    /// Suggest new bundles based on orphan patterns.
    pub fn suggest_bundles(&self) -> Vec<SuggestedBundle> {
        self.by_team_id
            .iter()
            .filter(|(_, apps)| apps.len() >= 2)
            .map(|(team_id, apps)| SuggestedBundle {
                name: format!("orphan-{}", team_id.to_lowercase()),
                team_id: team_id.clone(),
                app_count: apps.len(),
                sample_apps: apps.iter().take(3).cloned().collect(),
            })
            .collect()
    }
}

/// A suggested bundle from orphan analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedBundle {
    /// Suggested name.
    pub name: String,
    /// Team ID to match.
    pub team_id: String,
    /// Number of orphan apps this would catch.
    pub app_count: usize,
    /// Sample app names.
    pub sample_apps: Vec<String>,
}

/// Report on classification conflicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictReport {
    /// Total conflict count.
    pub total_count: usize,
    /// Conflict details.
    pub items: Vec<ConflictItem>,
}

impl ConflictReport {
    /// Create a conflict report from conflict info.
    pub fn from_conflicts(conflicts: &[super::ConflictInfo]) -> Self {
        let items: Vec<ConflictItem> = conflicts
            .iter()
            .map(|c| ConflictItem {
                app_name: c.app.display_name(),
                matching_bundles: c.matching_bundles.clone(),
                selected_bundle: c.selected_bundle.clone(),
            })
            .collect();

        Self {
            total_count: conflicts.len(),
            items,
        }
    }
}

/// A single conflict item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictItem {
    /// App name.
    pub app_name: String,
    /// Bundles that matched.
    pub matching_bundles: Vec<String>,
    /// Bundle that was selected.
    pub selected_bundle: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orphan_report_suggestions() {
        let apps = vec![
            AppRecord::new()
                .with_app_name("App1")
                .with_team_id("ABC1234567"),
            AppRecord::new()
                .with_app_name("App2")
                .with_team_id("ABC1234567"),
            AppRecord::new()
                .with_app_name("App3")
                .with_team_id("ABC1234567"),
            AppRecord::new()
                .with_app_name("Single")
                .with_team_id("XYZ9876543"),
        ];

        let report = OrphanReport::from_apps(&apps);
        let suggestions = report.suggest_bundles();

        // Should suggest bundle for ABC1234567 (3 apps) but not XYZ9876543 (1 app)
        assert_eq!(suggestions.len(), 1);
        assert!(suggestions[0].team_id == "ABC1234567");
    }

    #[test]
    fn test_coverage_report_human_readable() {
        let report = CoverageReport {
            total_apps: 100,
            classified_apps: 85,
            orphan_count: 15,
            conflict_count: 3,
            coverage_percentage: 85.0,
            bundle_stats: vec![
                BundleStats {
                    name: "google".to_string(),
                    app_count: 50,
                    percentage: 50.0,
                },
                BundleStats {
                    name: "microsoft".to_string(),
                    app_count: 35,
                    percentage: 35.0,
                },
            ],
            orphan_report: None,
            conflict_report: None,
        };

        let output = report.to_human_readable();
        assert!(output.contains("Coverage Report"));
        assert!(output.contains("85.0%"));
        assert!(output.contains("google"));
    }
}
