//! CEL (Common Expression Language) evaluation for app classification.
//!
//! This module provides CEL expression evaluation against app records
//! from Fleet CSV exports.

pub mod codegen;
mod context;
pub mod dryrun;
pub mod validate;

pub use context::{AppRecord, AppRecordSet, is_valid_signing_id, is_valid_team_id};

use crate::bundle::Bundle;
use anyhow::{Context, Result};
use cel_interpreter::Program;
use std::collections::HashMap;

/// A compiled CEL program ready for evaluation.
#[derive(Debug)]
pub struct CompiledExpression {
    program: Program,
    source: String,
}

impl CompiledExpression {
    /// Compile a CEL expression.
    pub fn compile(expression: &str) -> Result<Self> {
        let program = Program::compile(expression)
            .map_err(|e| anyhow::anyhow!("Failed to compile CEL expression: {e}"))?;
        Ok(Self {
            program,
            source: expression.to_string(),
        })
    }

    /// Evaluate the expression against an app record.
    pub fn evaluate(&self, app: &AppRecord) -> Result<bool> {
        let ctx = app.to_cel_context();
        match self.program.execute(&ctx) {
            Ok(cel_interpreter::Value::Bool(b)) => Ok(b),
            Ok(other) => Err(anyhow::anyhow!(
                "CEL expression returned non-boolean value: {:?}",
                other
            )),
            Err(e) => Err(anyhow::anyhow!("CEL evaluation error: {}", e)),
        }
    }

    /// Get the original source expression.
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// A bundle with its compiled CEL expression.
#[derive(Debug)]
pub struct CompiledBundle {
    pub bundle: Bundle,
    expression: CompiledExpression,
}

impl CompiledBundle {
    /// Compile a bundle's CEL expression.
    pub fn compile(bundle: Bundle) -> Result<Self> {
        let expression =
            CompiledExpression::compile(&bundle.cel_expression).with_context(|| {
                format!("Failed to compile bundle '{}' CEL expression", bundle.name)
            })?;
        Ok(Self { bundle, expression })
    }

    /// Check if an app matches this bundle.
    pub fn matches(&self, app: &AppRecord) -> Result<bool> {
        self.expression.evaluate(app)
    }

    /// Get the bundle name.
    pub fn name(&self) -> &str {
        &self.bundle.name
    }
}

/// Evaluate a set of bundles against a set of apps.
#[derive(Debug)]
pub struct BundleEvaluator {
    bundles: Vec<CompiledBundle>,
}

impl BundleEvaluator {
    /// Create a new evaluator with compiled bundles.
    pub fn new(bundles: Vec<Bundle>) -> Result<Self> {
        let compiled: Result<Vec<_>> = bundles.into_iter().map(CompiledBundle::compile).collect();
        Ok(Self { bundles: compiled? })
    }

    /// Find all bundles that match an app.
    pub fn matching_bundles(&self, app: &AppRecord) -> Vec<&CompiledBundle> {
        self.bundles
            .iter()
            .filter(|b| b.matches(app).unwrap_or(false))
            .collect()
    }

    /// Find the first bundle that matches an app.
    pub fn first_match(&self, app: &AppRecord) -> Option<&CompiledBundle> {
        self.bundles
            .iter()
            .find(|b| b.matches(app).unwrap_or(false))
    }

    /// Find the highest priority bundle that matches an app.
    pub fn best_match(&self, app: &AppRecord) -> Option<&CompiledBundle> {
        self.bundles
            .iter()
            .filter(|b| b.matches(app).unwrap_or(false))
            .max_by_key(|b| b.bundle.priority)
    }

    /// Get the number of compiled bundles.
    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    /// Check if there are no bundles.
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Get all compiled bundles.
    pub fn bundles(&self) -> &[CompiledBundle] {
        &self.bundles
    }
}

/// Result of classifying an app against bundles.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// The app that was classified.
    pub app: AppRecord,
    /// Bundles that matched the app.
    pub matching_bundles: Vec<String>,
    /// The selected bundle (after conflict resolution).
    pub selected_bundle: Option<String>,
    /// Whether this is an orphan (no matches).
    pub is_orphan: bool,
    /// Whether there was a conflict (multiple matches).
    pub has_conflict: bool,
}

impl ClassificationResult {
    /// Create a classification result for an orphan app.
    pub fn orphan(app: AppRecord) -> Self {
        Self {
            app,
            matching_bundles: Vec::new(),
            selected_bundle: None,
            is_orphan: true,
            has_conflict: false,
        }
    }

    /// Create a classification result for a single match.
    pub fn single_match(app: AppRecord, bundle_name: String) -> Self {
        Self {
            app,
            matching_bundles: vec![bundle_name.clone()],
            selected_bundle: Some(bundle_name),
            is_orphan: false,
            has_conflict: false,
        }
    }

    /// Create a classification result for multiple matches.
    pub fn multi_match(app: AppRecord, bundles: Vec<String>, selected: String) -> Self {
        Self {
            app,
            matching_bundles: bundles,
            selected_bundle: Some(selected),
            is_orphan: false,
            has_conflict: true,
        }
    }
}

/// Batch classification of apps against bundles.
pub fn classify_apps(evaluator: &BundleEvaluator, apps: &[AppRecord]) -> Vec<ClassificationResult> {
    apps.iter()
        .map(|app| {
            let matches = evaluator.matching_bundles(app);
            match matches.len() {
                0 => ClassificationResult::orphan(app.clone()),
                1 => {
                    ClassificationResult::single_match(app.clone(), matches[0].bundle.name.clone())
                }
                _ => {
                    let bundle_names: Vec<String> =
                        matches.iter().map(|b| b.bundle.name.clone()).collect();
                    let best = evaluator
                        .best_match(app)
                        .map(|b| b.bundle.name.clone())
                        .unwrap_or_else(|| bundle_names[0].clone());
                    ClassificationResult::multi_match(app.clone(), bundle_names, best)
                }
            }
        })
        .collect()
}

/// Summary of classification results.
#[derive(Debug, Default)]
pub struct ClassificationSummary {
    pub total_apps: usize,
    pub classified_apps: usize,
    pub orphan_apps: usize,
    pub conflict_apps: usize,
    pub bundles_used: HashMap<String, usize>,
}

impl ClassificationSummary {
    /// Build a summary from classification results.
    pub fn from_results(results: &[ClassificationResult]) -> Self {
        let mut summary = Self {
            total_apps: results.len(),
            ..Default::default()
        };

        for result in results {
            if result.is_orphan {
                summary.orphan_apps += 1;
            } else {
                summary.classified_apps += 1;
                if let Some(bundle) = &result.selected_bundle {
                    *summary.bundles_used.entry(bundle.clone()).or_insert(0) += 1;
                }
            }
            if result.has_conflict {
                summary.conflict_apps += 1;
            }
        }

        summary
    }

    /// Get coverage percentage.
    pub fn coverage_percentage(&self) -> f64 {
        if self.total_apps == 0 {
            0.0
        } else {
            (self.classified_apps as f64 / self.total_apps as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_expression() {
        let expr = CompiledExpression::compile(r#"has(app.team_id) && app.team_id == "ABC""#);
        assert!(expr.is_ok());
    }

    #[test]
    fn test_evaluate_team_id_match() {
        let expr =
            CompiledExpression::compile(r#"has(app.team_id) && app.team_id == "EQHXZ8M8AV""#)
                .unwrap();

        let app = AppRecord::new().with_team_id("EQHXZ8M8AV");
        assert!(expr.evaluate(&app).unwrap());

        let app2 = AppRecord::new().with_team_id("OTHER");
        assert!(!expr.evaluate(&app2).unwrap());
    }

    #[test]
    fn test_bundle_evaluator() {
        let bundles = vec![
            Bundle::for_team_id("google", "EQHXZ8M8AV"),
            Bundle::for_team_id("microsoft", "UBF8T346G9"),
        ];

        let evaluator = BundleEvaluator::new(bundles).unwrap();

        let google_app = AppRecord::new()
            .with_team_id("EQHXZ8M8AV")
            .with_app_name("Chrome");
        let matches = evaluator.matching_bundles(&google_app);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name(), "google");
    }

    #[test]
    fn test_classification_summary() {
        let results = vec![
            ClassificationResult::single_match(AppRecord::new(), "google".to_string()),
            ClassificationResult::single_match(AppRecord::new(), "google".to_string()),
            ClassificationResult::single_match(AppRecord::new(), "microsoft".to_string()),
            ClassificationResult::orphan(AppRecord::new()),
        ];

        let summary = ClassificationSummary::from_results(&results);
        assert_eq!(summary.total_apps, 4);
        assert_eq!(summary.classified_apps, 3);
        assert_eq!(summary.orphan_apps, 1);
        assert_eq!(summary.bundles_used.get("google"), Some(&2));
        assert_eq!(summary.bundles_used.get("microsoft"), Some(&1));
    }
}
