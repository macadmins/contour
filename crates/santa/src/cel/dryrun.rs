//! CEL dry-run: evaluate CEL expressions against test cases from a file.

use crate::cel::{AppRecord, CompiledExpression};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level structure for a dry-run test file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunFile {
    /// The list of test cases.
    pub dry_run: Vec<TestCase>,
}

/// A single test case: expression + app record + expected result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Human-readable name for this test case.
    pub name: String,
    /// CEL expression to evaluate.
    pub expression: String,
    /// App record fields to populate the CEL context.
    #[serde(default)]
    pub app: AppRecord,
    /// Expected boolean result of the expression.
    pub expect: bool,
}

/// Result of evaluating a single test case.
#[derive(Debug, Clone, Serialize)]
pub struct DryRunResult {
    /// Name of the test case.
    pub name: String,
    /// CEL expression that was evaluated.
    pub expression: String,
    /// Expected boolean result.
    pub expected: bool,
    /// Actual boolean result (if evaluation succeeded).
    pub actual: Option<bool>,
    /// Pass, Fail, or Error.
    pub status: DryRunStatus,
    /// Error message (if compilation or evaluation failed).
    pub error: Option<String>,
}

/// Status of a dry-run test case.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DryRunStatus {
    /// Expression evaluated and result matched expectation.
    Pass,
    /// Expression evaluated but result did not match expectation.
    Fail,
    /// Expression failed to compile or evaluate.
    Error,
}

/// Load test cases from a YAML or TOML file.
pub fn load_test_cases(path: &Path) -> Result<DryRunFile> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read test cases file: {}", path.display()))?;
    match path.extension().and_then(|e| e.to_str()) {
        Some("toml") => toml::from_str(&content).context("parsing TOML test cases"),
        _ => yaml_serde::from_str(&content).context("parsing YAML test cases"),
    }
}

/// Run all test cases and return results.
pub fn run_dry_run(cases: &[TestCase]) -> Vec<DryRunResult> {
    cases
        .iter()
        .map(|tc| match CompiledExpression::compile(&tc.expression) {
            Ok(expr) => match expr.evaluate(&tc.app) {
                Ok(actual) => DryRunResult {
                    name: tc.name.clone(),
                    expression: tc.expression.clone(),
                    expected: tc.expect,
                    actual: Some(actual),
                    status: if actual == tc.expect {
                        DryRunStatus::Pass
                    } else {
                        DryRunStatus::Fail
                    },
                    error: None,
                },
                Err(e) => DryRunResult {
                    name: tc.name.clone(),
                    expression: tc.expression.clone(),
                    expected: tc.expect,
                    actual: None,
                    status: DryRunStatus::Error,
                    error: Some(e.to_string()),
                },
            },
            Err(e) => DryRunResult {
                name: tc.name.clone(),
                expression: tc.expression.clone(),
                expected: tc.expect,
                actual: None,
                status: DryRunStatus::Error,
                error: Some(e.to_string()),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dry_run_pass() {
        let cases = vec![TestCase {
            name: "chrome-should-allow".to_string(),
            expression: r#"has(app.team_id) && app.team_id == "EQHXZ8M8AV""#.to_string(),
            app: AppRecord::new()
                .with_team_id("EQHXZ8M8AV")
                .with_app_name("Chrome"),
            expect: true,
        }];

        let results = run_dry_run(&cases);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, DryRunStatus::Pass);
        assert_eq!(results[0].actual, Some(true));
        assert!(results[0].error.is_none());
    }

    #[test]
    fn test_dry_run_fail() {
        let cases = vec![TestCase {
            name: "wrong-team-expects-true".to_string(),
            expression: r#"has(app.team_id) && app.team_id == "EQHXZ8M8AV""#.to_string(),
            app: AppRecord::new().with_team_id("OTHER12345"),
            expect: true,
        }];

        let results = run_dry_run(&cases);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, DryRunStatus::Fail);
        assert_eq!(results[0].actual, Some(false));
        assert!(results[0].error.is_none());
    }

    #[test]
    fn test_dry_run_compile_error() {
        let cases = vec![TestCase {
            name: "bad-expression".to_string(),
            expression: "this is not valid CEL !!!".to_string(),
            app: AppRecord::new(),
            expect: true,
        }];

        let results = run_dry_run(&cases);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, DryRunStatus::Error);
        assert!(results[0].actual.is_none());
        assert!(results[0].error.is_some());
    }

    #[test]
    fn test_load_yaml_cases() {
        let yaml = r#"
dry_run:
  - name: "chrome-should-allow"
    expression: 'has(app.team_id) && app.team_id == "EQHXZ8M8AV"'
    app:
      team_id: "EQHXZ8M8AV"
      app_name: "Chrome"
    expect: true

  - name: "old-binary-should-block"
    expression: 'has(app.team_id) && app.team_id == "EQHXZ8M8AV"'
    app:
      team_id: "OTHER12345"
    expect: false
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yaml");
        std::fs::write(&path, yaml).unwrap();

        let file = load_test_cases(&path).unwrap();
        assert_eq!(file.dry_run.len(), 2);
        assert_eq!(file.dry_run[0].name, "chrome-should-allow");
        assert!(file.dry_run[0].expect);
        assert_eq!(file.dry_run[1].name, "old-binary-should-block");
        assert!(!file.dry_run[1].expect);

        // Verify that running them produces expected results.
        let results = run_dry_run(&file.dry_run);
        assert_eq!(results[0].status, DryRunStatus::Pass);
        assert_eq!(results[1].status, DryRunStatus::Pass);
    }
}
