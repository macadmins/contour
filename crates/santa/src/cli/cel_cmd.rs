//! CEL expression tools: check, evaluate, list fields, classify apps, compile conditions, dry-run.

use crate::bundle::BundleSet;
use crate::cel::codegen::{CelResult, Condition, Logic, compile_conditions};
use crate::cel::validate::{Severity, validate_expression};
use crate::cel::{
    AppRecord, BundleEvaluator, ClassificationSummary, CompiledExpression, classify_apps,
};
use crate::discovery::parse_fleet_csv;
use crate::output::{
    OutputMode, print_error, print_info, print_json, print_kv, print_success, print_warning,
};
use anyhow::{Context, Result};
use std::path::Path;

/// List all available CEL context fields and operators.
pub fn handle_cel_fields(mode: OutputMode) -> Result<()> {
    let classification_fields = vec![
        ("app.app_name", "string", "Application display name"),
        (
            "app.signing_id",
            "string",
            "Full signing ID (TeamID:BundleID)",
        ),
        ("app.team_id", "string", "Apple Team ID (10 chars)"),
        ("app.sha256", "string", "SHA-256 hash of the binary"),
        ("app.version", "string", "Application version string"),
        (
            "app.bundle_id",
            "string",
            "Bundle identifier (e.g., com.google.Chrome)",
        ),
        ("app.vendor", "string", "Publisher/vendor name"),
        ("app.path", "string", "File path on device"),
        (
            "app.device_count",
            "uint",
            "Number of devices app was seen on",
        ),
    ];

    let static_fields = vec![
        (
            "target.signing_id",
            "string",
            "TEAMID:SigningID or platform:SigningID",
        ),
        ("target.team_id", "string", "10-char Apple Team ID"),
        ("target.signing_time", "timestamp", "Code signing timestamp"),
        (
            "target.secure_signing_time",
            "timestamp",
            "Apple-verified signing timestamp",
        ),
        (
            "target.is_platform_binary",
            "bool",
            "Signed with Apple platform certificate",
        ),
    ];

    let dynamic_fields = vec![
        ("args", "list<string>", "Command-line arguments"),
        ("envs", "map<string,string>", "Environment variables"),
        ("euid", "int", "Effective user ID"),
        ("cwd", "string", "Current working directory"),
        ("path", "string", "Executable file path"),
    ];

    let v2_only_fields = vec![
        (
            "ancestors",
            "list<Ancestor>",
            "Process ancestors (.signing_id, .team_id, .path, .cdhash)",
        ),
        ("fds", "list<FD>", "File descriptors (.fd, .type)"),
    ];

    let functions = "has(), startsWith(), endsWith(), contains(), matches(), size(), exists()";
    let operators = "&&, ||, !, ==, !=, <, >, <=, >=, in";

    let to_json_fields = |fields: &[(&str, &str, &str)]| -> Vec<serde_json::Value> {
        fields
            .iter()
            .map(|(name, typ, desc)| {
                serde_json::json!({
                    "name": name,
                    "type": typ,
                    "description": desc,
                })
            })
            .collect()
    };

    let print_field_table = |fields: &[(&str, &str, &str)]| {
        for (name, typ, desc) in fields {
            println!("  {:<30} {:<20} {}", name, typ, desc);
        }
    };

    match mode {
        OutputMode::Json => {
            let output = serde_json::json!({
                "classification_fields": to_json_fields(&classification_fields),
                "execution_fields": {
                    "static": to_json_fields(&static_fields),
                    "dynamic": to_json_fields(&dynamic_fields),
                    "v2_only": to_json_fields(&v2_only_fields),
                },
                "operators": operators,
                "functions": functions,
            });
            print_json(&output)?;
        }
        OutputMode::Human => {
            print_info("Classification fields (app.*):");
            println!();
            println!("  {:<30} {:<20} Description", "Field", "Type");
            println!("  {}", "\u{2500}".repeat(76));
            print_field_table(&classification_fields);

            println!();
            print_info("Execution context fields - static (target.*):");
            println!();
            println!("  {:<30} {:<20} Description", "Field", "Type");
            println!("  {}", "\u{2500}".repeat(76));
            print_field_table(&static_fields);

            println!();
            print_info("Execution context fields - dynamic (per-execution):");
            println!();
            println!("  {:<30} {:<20} Description", "Field", "Type");
            println!("  {}", "\u{2500}".repeat(76));
            print_field_table(&dynamic_fields);

            println!();
            print_info("Execution context fields - v2 only:");
            println!();
            println!("  {:<30} {:<20} Description", "Field", "Type");
            println!("  {}", "\u{2500}".repeat(76));
            print_field_table(&v2_only_fields);

            println!();
            print_info("Available functions:");
            println!("  {functions}");
            println!();
            print_info("Available operators:");
            println!("  {operators}");
        }
    }

    Ok(())
}

/// Check if a CEL expression compiles and validate field references.
pub fn handle_cel_check(expression: &str, allow_v2: bool, mode: OutputMode) -> Result<()> {
    // 1. Syntax check
    let syntax_ok = CompiledExpression::compile(expression).is_ok();

    let syntax_error = if syntax_ok {
        None
    } else {
        // Re-compile to capture the error message
        CompiledExpression::compile(expression)
            .err()
            .map(|e| e.to_string())
    };

    // 2. Semantic validation (even if syntax fails, still useful feedback)
    let issues = validate_expression(expression, allow_v2);
    let has_errors = !syntax_ok || issues.iter().any(|i| matches!(i.severity, Severity::Error));

    // 3. Output
    match mode {
        OutputMode::Json => {
            let json_issues: Vec<serde_json::Value> = issues
                .iter()
                .map(|issue| {
                    let mut obj = serde_json::json!({
                        "severity": match issue.severity {
                            Severity::Error => "error",
                            Severity::Warning => "warning",
                        },
                        "message": issue.message,
                    });
                    if let Some(suggestion) = &issue.suggestion {
                        obj["suggestion"] = serde_json::Value::String(suggestion.clone());
                    }
                    obj
                })
                .collect();

            let mut output = serde_json::json!({
                "valid": !has_errors,
                "expression": expression,
                "syntax_ok": syntax_ok,
                "issues": json_issues,
            });

            if let Some(err) = &syntax_error {
                output["syntax_error"] = serde_json::Value::String(err.clone());
            }

            print_json(&output)?;
        }
        OutputMode::Human => {
            if syntax_ok {
                print_success("Syntax OK");
            } else if let Some(err) = &syntax_error {
                print_error(&format!("Syntax error: {err}"));
            }

            print_kv("Expression", expression);

            if !issues.is_empty() {
                println!();
                print_info("Semantic issues:");
                for issue in &issues {
                    match issue.severity {
                        Severity::Error => print_error(&issue.message),
                        Severity::Warning => print_warning(&issue.message),
                    }
                    if let Some(suggestion) = &issue.suggestion {
                        print_info(&format!("  hint: {suggestion}"));
                    }
                }
            }

            if !has_errors {
                print_success("Expression is valid");
            }
        }
    }

    Ok(())
}

/// Evaluate a CEL expression against an app record built from field pairs.
pub fn handle_cel_evaluate(expression: &str, fields: &[String], mode: OutputMode) -> Result<()> {
    let mut app = AppRecord::new();

    for field in fields {
        let (key, value) = field
            .split_once('=')
            .with_context(|| format!("Invalid field format '{field}', expected KEY=VALUE"))?;

        match key {
            "team_id" => app = app.with_team_id(value),
            "app_name" => app = app.with_app_name(value),
            "signing_id" => app = app.with_signing_id(value),
            "sha256" => app = app.with_sha256(value),
            "version" => app = app.with_version(value),
            "bundle_id" => app = app.with_bundle_id(value),
            "vendor" => app = app.with_vendor(value),
            "path" => app = app.with_path(value),
            "device_count" => {
                let count: usize = value
                    .parse()
                    .with_context(|| format!("Invalid device_count value '{value}'"))?;
                app = app.with_device_count(count);
            }
            other => {
                anyhow::bail!("Unknown field '{other}'. Run `cel fields` to see available fields.")
            }
        }
    }

    let compiled =
        CompiledExpression::compile(expression).context("Failed to compile CEL expression")?;

    let result = compiled.evaluate(&app)?;

    match mode {
        OutputMode::Json => {
            print_json(&serde_json::json!({
                "result": result,
                "expression": expression,
                "app": app,
            }))?;
        }
        OutputMode::Human => {
            if result {
                print_success("Expression matched");
            } else {
                print_info("Expression did not match");
            }
            print_kv("Expression", expression);
            print_kv("Result", &result.to_string());
        }
    }

    Ok(())
}

/// Classify apps from a CSV file against bundle definitions.
pub fn handle_cel_classify(bundles_path: &Path, input: &Path, mode: OutputMode) -> Result<()> {
    // Load bundles
    print_info(&format!("Loading bundles: {}", bundles_path.display()));
    let bundle_set = BundleSet::from_toml_file(bundles_path)?;
    print_kv("Bundles loaded", &bundle_set.len().to_string());

    if bundle_set.is_empty() {
        anyhow::bail!("No bundles defined in {}", bundles_path.display());
    }

    // Load apps from CSV
    print_info(&format!("Loading apps: {}", input.display()));
    let file = std::fs::File::open(input)
        .with_context(|| format!("Failed to open CSV file: {}", input.display()))?;
    let app_set = parse_fleet_csv(file)?;
    print_kv("Apps loaded", &app_set.len().to_string());

    if app_set.is_empty() {
        anyhow::bail!("No apps found in {}", input.display());
    }

    // Build evaluator and classify
    let evaluator = BundleEvaluator::new(bundle_set.into_bundles())?;
    let results = classify_apps(&evaluator, app_set.apps());
    let summary = ClassificationSummary::from_results(&results);

    match mode {
        OutputMode::Json => {
            let json_results: Vec<serde_json::Value> = results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "app_name": r.app.display_name(),
                        "selected_bundle": r.selected_bundle,
                        "matching_bundles": r.matching_bundles,
                        "is_orphan": r.is_orphan,
                    })
                })
                .collect();
            print_json(&json_results)?;
        }
        OutputMode::Human => {
            println!();
            print_info("Classification summary:");
            print_kv("Total apps", &summary.total_apps.to_string());
            print_kv("Classified", &summary.classified_apps.to_string());
            print_kv("Orphans", &summary.orphan_apps.to_string());
            print_kv("Conflicts", &summary.conflict_apps.to_string());
            print_kv(
                "Coverage",
                &format!("{:.1}%", summary.coverage_percentage()),
            );

            if !summary.bundles_used.is_empty() {
                println!();
                print_info("Bundle breakdown:");
                let mut bundle_counts: Vec<_> = summary.bundles_used.iter().collect();
                bundle_counts.sort_by(|a, b| b.1.cmp(a.1));
                for (name, count) in &bundle_counts {
                    print_kv(&format!("  {name}"), &count.to_string());
                }
            }

            if summary.orphan_apps > 0 {
                println!();
                print_info("Orphaned apps (no bundle match):");
                for r in results.iter().filter(|r| r.is_orphan) {
                    println!("  - {}", r.app.display_name());
                }
            }

            print_success(&format!(
                "Classified {} of {} apps ({:.1}% coverage)",
                summary.classified_apps,
                summary.total_apps,
                summary.coverage_percentage(),
            ));
        }
    }

    Ok(())
}

/// Compile structured conditions into a CEL expression string.
pub fn handle_cel_compile(
    conditions: &[String],
    logic: &str,
    result: &str,
    else_result: &str,
    mode: OutputMode,
) -> Result<()> {
    if conditions.is_empty() {
        anyhow::bail!("At least one condition is required");
    }

    let parsed_conditions: Vec<Condition> = conditions
        .iter()
        .map(|c| parse_condition_string(c))
        .collect::<Result<Vec<_>>>()?;

    let logic = match logic {
        "all" => Logic::All,
        "any" => Logic::Any,
        other => anyhow::bail!("Invalid logic '{other}', expected 'all' or 'any'"),
    };

    let cel_result = CelResult::from_name(result)?;
    let cel_else_result = CelResult::from_name(else_result)?;

    let expression = compile_conditions(
        &parsed_conditions,
        logic,
        &cel_result,
        Some(&cel_else_result),
    )?;

    match mode {
        OutputMode::Json => {
            print_json(&serde_json::json!({
                "expression": expression,
                "conditions": parsed_conditions.iter().map(|c| {
                    serde_json::json!({
                        "field": c.field,
                        "op": c.op,
                        "value": c.value,
                    })
                }).collect::<Vec<_>>(),
                "logic": format!("{logic:?}").to_lowercase(),
                "result": result,
                "else_result": else_result,
            }))?;
        }
        OutputMode::Human => {
            print_success("Compiled CEL expression:");
            println!();
            print_kv("Expression", &expression);
            println!();
            print_info("Conditions:");
            for cond in &parsed_conditions {
                println!("  {} {} {}", cond.field, cond.op, cond.value);
            }
            print_kv("Logic", &format!("{logic:?}"));
            print_kv("Result", result);
            print_kv("Else result", else_result);
        }
    }

    Ok(())
}

/// Known operators for parsing condition strings, ordered longest first to avoid
/// prefix-matching (e.g., `>=` before `>`).
const CONDITION_OPERATORS: &[&str] = &[
    ">=",
    "<=",
    "!=",
    "==",
    ">",
    "<",
    "contains",
    "matches",
    "starts_with",
    "ends_with",
    "in",
    "exists",
];

/// Parse a condition string like "field op value" into a [`Condition`].
fn parse_condition_string(s: &str) -> Result<Condition> {
    let trimmed = s.trim();

    for op in CONDITION_OPERATORS {
        // For word operators, ensure they are bounded by whitespace
        if op.chars().next().is_some_and(|c| c.is_alphabetic()) {
            let pattern = format!(" {op} ");
            if let Some(idx) = trimmed.find(&pattern) {
                let field = trimmed[..idx].trim().to_string();
                let value = trimmed[idx + pattern.len()..].trim().to_string();
                if field.is_empty() || value.is_empty() {
                    continue;
                }
                return Ok(Condition {
                    field,
                    op: (*op).to_string(),
                    value,
                });
            }
        } else if let Some(idx) = trimmed.find(op) {
            // For symbolic operators, allow optional surrounding whitespace
            let field = trimmed[..idx].trim().to_string();
            let value = trimmed[idx + op.len()..].trim().to_string();
            if field.is_empty() || value.is_empty() {
                continue;
            }
            return Ok(Condition {
                field,
                op: (*op).to_string(),
                value,
            });
        }
    }

    anyhow::bail!(
        "Could not parse condition '{trimmed}'. Expected format: 'field op value' \
         (e.g., 'target.team_id == EQHXZ8M8AV')"
    )
}

/// Run CEL expressions against test cases from a file (dry-run simulation).
pub fn handle_cel_dry_run(input: &Path, mode: OutputMode) -> Result<()> {
    use crate::cel::dryrun::{DryRunStatus, load_test_cases, run_dry_run};

    let file = load_test_cases(input)?;
    let results = run_dry_run(&file.dry_run);

    let passed = results
        .iter()
        .filter(|r| matches!(r.status, DryRunStatus::Pass))
        .count();
    let failed = results
        .iter()
        .filter(|r| matches!(r.status, DryRunStatus::Fail))
        .count();
    let errors = results
        .iter()
        .filter(|r| matches!(r.status, DryRunStatus::Error))
        .count();
    let total = results.len();

    match mode {
        OutputMode::Json => {
            print_json(&serde_json::json!({
                "results": results.iter().map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "expression": r.expression,
                        "expected": r.expected,
                        "actual": r.actual,
                        "status": r.status,
                        "error": r.error,
                    })
                }).collect::<Vec<_>>(),
                "summary": {
                    "total": total,
                    "passed": passed,
                    "failed": failed,
                    "errors": errors,
                },
            }))?;
        }
        OutputMode::Human => {
            print_info(&format!(
                "Running {} test case(s) from {}",
                total,
                input.display()
            ));
            println!();

            for r in &results {
                let icon = match r.status {
                    DryRunStatus::Pass => "PASS",
                    DryRunStatus::Fail => "FAIL",
                    DryRunStatus::Error => "ERR ",
                };
                println!("  [{icon}] {}", r.name);
                if let Some(ref err) = r.error {
                    println!("         error: {err}");
                } else if matches!(r.status, DryRunStatus::Fail) {
                    println!(
                        "         expected={}, actual={}",
                        r.expected,
                        r.actual.map_or("none".to_string(), |v| v.to_string())
                    );
                }
            }

            println!();
            print_kv("Total", &total.to_string());
            print_kv("Passed", &passed.to_string());
            print_kv("Failed", &failed.to_string());
            print_kv("Errors", &errors.to_string());

            if failed == 0 && errors == 0 {
                print_success(&format!("All {total} test case(s) passed"));
            }
        }
    }

    if failed > 0 || errors > 0 {
        anyhow::bail!("{failed} failed, {errors} errors out of {total} test cases");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_cel_check_valid() {
        let result = handle_cel_check(
            r#"has(app.team_id) && app.team_id == "EQHXZ8M8AV""#,
            false,
            OutputMode::Human,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cel_check_invalid() {
        let result = handle_cel_check("this is not valid CEL !!!", false, OutputMode::Human);
        assert!(result.is_ok()); // Returns Ok even for invalid - just prints error
    }

    #[test]
    fn test_handle_cel_evaluate_match() {
        let result = handle_cel_evaluate(
            r#"has(app.team_id) && app.team_id == "EQHXZ8M8AV""#,
            &["team_id=EQHXZ8M8AV".to_string()],
            OutputMode::Human,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cel_evaluate_no_match() {
        let result = handle_cel_evaluate(
            r#"has(app.team_id) && app.team_id == "EQHXZ8M8AV""#,
            &["team_id=OTHER12345".to_string()],
            OutputMode::Human,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cel_evaluate_invalid_field() {
        let result = handle_cel_evaluate(
            r#"has(app.team_id)"#,
            &["unknown_field=value".to_string()],
            OutputMode::Human,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_cel_evaluate_invalid_format() {
        let result = handle_cel_evaluate(
            r#"has(app.team_id)"#,
            &["no_equals_sign".to_string()],
            OutputMode::Human,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_cel_fields() {
        let result = handle_cel_fields(OutputMode::Human);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cel_fields_json() {
        let result = handle_cel_fields(OutputMode::Json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_condition_string_eq() {
        let cond = parse_condition_string("target.team_id == EQHXZ8M8AV").unwrap();
        assert_eq!(cond.field, "target.team_id");
        assert_eq!(cond.op, "==");
        assert_eq!(cond.value, "EQHXZ8M8AV");
    }

    #[test]
    fn test_parse_condition_string_lt_timestamp() {
        let cond = parse_condition_string("target.signing_time < 2025-01-01T00:00:00Z").unwrap();
        assert_eq!(cond.field, "target.signing_time");
        assert_eq!(cond.op, "<");
        assert_eq!(cond.value, "2025-01-01T00:00:00Z");
    }

    #[test]
    fn test_parse_condition_string_contains() {
        let cond = parse_condition_string("path contains /Applications/").unwrap();
        assert_eq!(cond.field, "path");
        assert_eq!(cond.op, "contains");
        assert_eq!(cond.value, "/Applications/");
    }

    #[test]
    fn test_parse_condition_string_invalid() {
        let result = parse_condition_string("no operator here");
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_cel_compile_single() {
        let result = handle_cel_compile(
            &["target.team_id == EQHXZ8M8AV".to_string()],
            "all",
            "blocklist",
            "allowlist",
            OutputMode::Human,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cel_compile_multiple() {
        let result = handle_cel_compile(
            &[
                "target.signing_time < 2025-01-01T00:00:00Z".to_string(),
                "target.team_id == EQHXZ8M8AV".to_string(),
            ],
            "all",
            "blocklist",
            "allowlist",
            OutputMode::Json,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_cel_compile_no_conditions() {
        let result = handle_cel_compile(&[], "all", "blocklist", "allowlist", OutputMode::Human);
        assert!(result.is_err());
    }
}
