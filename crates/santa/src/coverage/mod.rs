//! Coverage analysis and reporting for bundle classification.
//!
//! This module provides tools to analyze how well bundles cover
//! a set of apps, detect orphans and conflicts, and generate reports.

mod report;

pub use report::{ConflictReport, CoverageReport, OrphanReport};

use crate::bundle::{Bundle, BundleSet, ConflictPolicy, OrphanPolicy};
use crate::cel::{AppRecord, BundleEvaluator, ClassificationResult, ClassificationSummary};
use anyhow::{Result, bail};

/// Coverage analyzer for evaluating bundle effectiveness.
#[derive(Debug)]
pub struct CoverageAnalyzer {
    orphan_policy: OrphanPolicy,
    conflict_policy: ConflictPolicy,
}

impl CoverageAnalyzer {
    /// Create a new coverage analyzer with the specified policies.
    pub fn new(orphan_policy: OrphanPolicy, conflict_policy: ConflictPolicy) -> Self {
        Self {
            orphan_policy,
            conflict_policy,
        }
    }

    /// Create an analyzer with default policies.
    pub fn with_defaults() -> Self {
        Self::new(OrphanPolicy::default(), ConflictPolicy::default())
    }

    /// Analyze coverage of bundles against apps.
    pub fn analyze(&self, bundles: &BundleSet, apps: &[AppRecord]) -> Result<CoverageAnalysis> {
        let evaluator = BundleEvaluator::new(bundles.bundles().to_vec())?;

        let mut results: Vec<ClassificationResult> = Vec::new();
        let mut orphans: Vec<AppRecord> = Vec::new();
        let mut conflicts: Vec<ConflictInfo> = Vec::new();

        for app in apps {
            let matches = evaluator.matching_bundles(app);

            match matches.len() {
                0 => {
                    results.push(ClassificationResult::orphan(app.clone()));
                    orphans.push(app.clone());
                }
                1 => {
                    results.push(ClassificationResult::single_match(
                        app.clone(),
                        matches[0].bundle.name.clone(),
                    ));
                }
                _ => {
                    let bundle_names: Vec<String> =
                        matches.iter().map(|b| b.bundle.name.clone()).collect();

                    // Resolve conflict based on policy
                    let selected = self.resolve_conflict(&matches, app)?;

                    results.push(ClassificationResult::multi_match(
                        app.clone(),
                        bundle_names.clone(),
                        selected.clone(),
                    ));

                    conflicts.push(ConflictInfo {
                        app: app.clone(),
                        matching_bundles: bundle_names,
                        selected_bundle: selected,
                    });
                }
            }
        }

        // Check orphan policy
        self.check_orphan_policy(&orphans)?;

        let summary = ClassificationSummary::from_results(&results);

        Ok(CoverageAnalysis {
            results,
            orphans,
            conflicts,
            summary,
            total_apps: apps.len(),
        })
    }

    /// Resolve a conflict when an app matches multiple bundles.
    fn resolve_conflict(
        &self,
        matches: &[&crate::cel::CompiledBundle],
        app: &AppRecord,
    ) -> Result<String> {
        match self.conflict_policy {
            ConflictPolicy::FirstMatch => Ok(matches[0].bundle.name.clone()),
            ConflictPolicy::Priority => {
                let best = matches
                    .iter()
                    .max_by_key(|b| b.bundle.priority)
                    .expect("invariant: resolve_conflict called with non-empty matches");
                Ok(best.bundle.name.clone())
            }
            ConflictPolicy::MostSpecific => {
                // Prefer more specific rule types, then higher priority as tiebreaker
                let best = matches
                    .iter()
                    .max_by_key(|b| (specificity_score(&b.bundle), b.bundle.priority))
                    .expect("invariant: resolve_conflict called with non-empty matches");
                Ok(best.bundle.name.clone())
            }
            ConflictPolicy::Error => {
                let names: Vec<_> = matches.iter().map(|b| &b.bundle.name).collect();
                bail!(
                    "App '{}' matches multiple bundles: {:?}. Use --conflict-policy to resolve.",
                    app.display_name(),
                    names
                );
            }
        }
    }

    /// Check orphan policy and potentially fail.
    fn check_orphan_policy(&self, orphans: &[AppRecord]) -> Result<()> {
        if orphans.is_empty() {
            return Ok(());
        }

        match self.orphan_policy {
            OrphanPolicy::Ignore => Ok(()),
            OrphanPolicy::Warn => {
                tracing::warn!("{} apps did not match any bundle (orphans)", orphans.len());
                Ok(())
            }
            OrphanPolicy::CatchAll => {
                // CatchAll is handled at a higher level by adding a catch-all bundle
                Ok(())
            }
            OrphanPolicy::Error => {
                let sample: Vec<_> = orphans.iter().take(5).map(|a| a.display_name()).collect();
                bail!(
                    "{} apps did not match any bundle. Sample: {:?}. Use --orphan-policy to handle.",
                    orphans.len(),
                    sample
                );
            }
        }
    }
}

/// Score indicating how specific a bundle's rule type is.
fn specificity_score(bundle: &Bundle) -> i32 {
    use crate::models::RuleType;
    match bundle.rule_type {
        RuleType::Binary => 100,
        RuleType::Cdhash => 90,
        RuleType::SigningId => 80,
        RuleType::Certificate => 70,
        RuleType::TeamId => 60,
    }
}

/// Result of coverage analysis.
#[derive(Debug)]
pub struct CoverageAnalysis {
    /// Classification results for all apps.
    pub results: Vec<ClassificationResult>,
    /// Apps that matched no bundle.
    pub orphans: Vec<AppRecord>,
    /// Apps that matched multiple bundles.
    pub conflicts: Vec<ConflictInfo>,
    /// Summary statistics.
    pub summary: ClassificationSummary,
    /// Total number of apps analyzed.
    pub total_apps: usize,
}

impl CoverageAnalysis {
    /// Get coverage percentage.
    pub fn coverage_percentage(&self) -> f64 {
        self.summary.coverage_percentage()
    }

    /// Check if there are any orphans.
    pub fn has_orphans(&self) -> bool {
        !self.orphans.is_empty()
    }

    /// Check if there are any conflicts.
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }

    /// Get apps classified under a specific bundle.
    pub fn apps_for_bundle(&self, bundle_name: &str) -> Vec<&AppRecord> {
        self.results
            .iter()
            .filter(|r| r.selected_bundle.as_deref() == Some(bundle_name))
            .map(|r| &r.app)
            .collect()
    }

    /// Generate a coverage report.
    pub fn to_report(&self) -> CoverageReport {
        CoverageReport::from_analysis(self)
    }
}

/// Information about a classification conflict.
#[derive(Debug, Clone)]
pub struct ConflictInfo {
    /// The app that caused the conflict.
    pub app: AppRecord,
    /// All bundles that matched.
    pub matching_bundles: Vec<String>,
    /// The bundle that was selected.
    pub selected_bundle: String,
}

/// Create a catch-all bundle for orphan apps.
pub fn create_catch_all_bundle() -> Bundle {
    Bundle::new(
        "uncategorized",
        "true", // Matches everything
    )
    .with_description("Apps that don't match any other bundle")
    .with_priority(-1000) // Lowest priority
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundles() -> BundleSet {
        let mut set = BundleSet::new();
        set.add(Bundle::for_team_id("google", "EQHXZ8M8AV"));
        set.add(Bundle::for_team_id("microsoft", "UBF8T346G9"));
        set
    }

    fn sample_apps() -> Vec<AppRecord> {
        vec![
            AppRecord::new()
                .with_app_name("Chrome")
                .with_team_id("EQHXZ8M8AV"),
            AppRecord::new()
                .with_app_name("Word")
                .with_team_id("UBF8T346G9"),
            AppRecord::new()
                .with_app_name("Unknown App")
                .with_team_id("ZZZZZZZZZZ"),
        ]
    }

    #[test]
    fn test_coverage_analyzer_basic() {
        let analyzer = CoverageAnalyzer::new(OrphanPolicy::Warn, ConflictPolicy::FirstMatch);
        let bundles = sample_bundles();
        let apps = sample_apps();

        let analysis = analyzer.analyze(&bundles, &apps).unwrap();

        assert_eq!(analysis.total_apps, 3);
        assert_eq!(analysis.summary.classified_apps, 2);
        assert_eq!(analysis.orphans.len(), 1);
    }

    #[test]
    fn test_coverage_analyzer_orphan_error() {
        let analyzer = CoverageAnalyzer::new(OrphanPolicy::Error, ConflictPolicy::FirstMatch);
        let bundles = sample_bundles();
        let apps = sample_apps();

        let result = analyzer.analyze(&bundles, &apps);
        assert!(result.is_err());
    }

    #[test]
    fn test_catch_all_bundle() {
        let bundle = create_catch_all_bundle();
        assert_eq!(bundle.name, "uncategorized");
        assert_eq!(bundle.priority, -1000);
    }
}
