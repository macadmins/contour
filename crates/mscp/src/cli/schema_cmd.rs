//! Handlers for the `contour mscp schema` subcommand.
//!
//! These commands query the embedded mSCP schema dataset (baselines, rules,
//! statistics) without requiring a local mSCP repository checkout.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;
use contour_core::output::{OutputMode, print_info, print_kv, print_success, print_warning};

/// List every baseline in the embedded schema.
pub fn handle_schema_baselines(mode: OutputMode) -> Result<()> {
    let baselines = crate::api::list_baselines()?;

    match mode {
        OutputMode::Human => {
            print_info(&format!("Found {} baselines in schema", baselines.len()));
            println!();
            for b in &baselines {
                let platforms: Vec<String> = b
                    .platforms
                    .iter()
                    .map(|(p, v)| format!("{p}/{v}"))
                    .collect();
                print_kv(&b.baseline, &b.title);
                print_kv("  platforms", &platforms.join(", "));
                println!();
            }
            print_success(&format!("{} baselines total", baselines.len()));
        }
        OutputMode::Json => {
            // BaselineMeta derives Serialize, so we can serialize directly.
            let json = serde_json::to_string_pretty(&baselines)?;
            println!("{json}");
        }
    }
    Ok(())
}

/// List rules belonging to a specific baseline (optionally filtered by platform).
pub fn handle_schema_rules(baseline: &str, platform: &str, mode: OutputMode) -> Result<()> {
    let rules = crate::api::list_baseline_rules(baseline, platform)?;

    match mode {
        OutputMode::Human => {
            print_info(&format!(
                "Baseline \"{baseline}\" on {platform}: {} rules",
                rules.len()
            ));
            println!();
            for r in &rules {
                let enforcement = r.enforcement_type.as_deref().unwrap_or("unknown");
                let odv_marker = if r.odv_default.is_some() {
                    " ⚙ ODV"
                } else {
                    ""
                };
                print_kv(
                    &r.rule_id,
                    &format!("{} [{}]{}", r.title, enforcement, odv_marker),
                );
            }
            println!();
            print_success(&format!("{} rules listed", rules.len()));
        }
        OutputMode::Json => {
            // RuleVersioned does not derive Serialize, so build JSON manually.
            let items: Vec<serde_json::Value> = rules
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "rule_id": r.rule_id,
                        "title": r.title,
                        "platform": r.platform,
                        "os_version": r.os_version,
                        "severity": r.severity,
                        "enforcement_type": r.enforcement_type,
                        "mobileconfig": r.mobileconfig,
                        "has_check": r.has_check,
                        "has_fix": r.has_fix,
                        "has_ddm_info": r.has_ddm_info,
                        "has_odv": r.odv_default.is_some(),
                        "odv_default": r.odv_default,
                        "tags": r.tags,
                    })
                })
                .collect();
            let json = serde_json::to_string_pretty(&items)?;
            println!("{json}");
        }
    }
    Ok(())
}

/// Print high-level dataset counts from the embedded schema.
pub fn handle_schema_stats(mode: OutputMode) -> Result<()> {
    let stats = crate::api::schema_stats()?;

    match mode {
        OutputMode::Human => {
            print_info("Embedded mSCP schema statistics");
            println!();
            print_kv("baselines", &stats.baselines.to_string());
            print_kv("rules", &stats.rules.to_string());
            print_kv("rules_versioned", &stats.rules_versioned.to_string());
            print_kv("sections", &stats.sections.to_string());
            print_kv("control_tiers", &stats.control_tiers.to_string());
            print_kv("baseline_edges", &stats.baseline_edges.to_string());
            println!();
            print_success("Schema loaded successfully");
        }
        OutputMode::Json => {
            // SchemaStats may not derive Serialize, so build JSON manually.
            let json = serde_json::to_string_pretty(&serde_json::json!({
                "baselines": stats.baselines,
                "rules": stats.rules,
                "rules_versioned": stats.rules_versioned,
                "sections": stats.sections,
                "control_tiers": stats.control_tiers,
                "baseline_edges": stats.baseline_edges,
            }))?;
            println!("{json}");
        }
    }
    Ok(())
}

/// A single field-level difference between the embedded and disk version of a rule.
#[derive(Debug)]
struct RuleDiff {
    rule_id: String,
    field: String,
}

/// Compatibility report comparing embedded parquet data against YAML on disk.
#[derive(Debug)]
struct CompatReport {
    baseline: String,
    platform: String,
    embedded_count: usize,
    disk_count: usize,
    matched_count: usize,
    only_embedded: Vec<String>,
    only_disk: Vec<String>,
    script_diffs: Vec<RuleDiff>,
    mobileconfig_diffs: Vec<String>,
    title_diffs: Vec<String>,
    severity_diffs: Vec<String>,
}

/// Compare embedded parquet rule data against mSCP YAML rules on disk.
pub fn handle_schema_compare(
    mscp_repo: &Path,
    baseline: &str,
    platform: &str,
    mode: OutputMode,
) -> Result<()> {
    // 1. Load rules from embedded parquet data.
    let embedded_rules = crate::extractors::rules_from_embedded(baseline, platform)?;

    // 2. Load rules from YAML files on disk.
    let disk_rules =
        crate::extractors::RuleExtractor::new(mscp_repo).extract_rules_for_baseline(baseline)?;

    // 3. Index both sets by rule_id.
    let embedded_ids: BTreeSet<&str> = embedded_rules.iter().map(|r| r.id.as_str()).collect();
    let disk_ids: BTreeSet<&str> = disk_rules.iter().map(|r| r.id.as_str()).collect();

    let only_embedded: Vec<String> = embedded_ids
        .difference(&disk_ids)
        .map(|s| (*s).to_owned())
        .collect();
    let only_disk: Vec<String> = disk_ids
        .difference(&embedded_ids)
        .map(|s| (*s).to_owned())
        .collect();

    // Build lookup maps for rules present in both sets.
    let embedded_map: std::collections::HashMap<&str, &crate::models::MscpRule> =
        embedded_rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let disk_map: std::collections::HashMap<&str, &crate::models::MscpRule> =
        disk_rules.iter().map(|r| (r.id.as_str(), r)).collect();

    let common_ids: BTreeSet<&str> = embedded_ids.intersection(&disk_ids).copied().collect();

    let mut script_diffs = Vec::new();
    let mut mobileconfig_diffs = Vec::new();
    let mut title_diffs = Vec::new();
    let mut severity_diffs = Vec::new();

    for rule_id in &common_ids {
        let emb = embedded_map[rule_id];
        let dsk = disk_map[rule_id];

        // Compare check scripts (normalize trailing whitespace).
        if normalize_opt(&emb.check) != normalize_opt(&dsk.check) {
            script_diffs.push(RuleDiff {
                rule_id: (*rule_id).to_owned(),
                field: "check".to_owned(),
            });
        }

        // Compare fix scripts.
        if normalize_opt(&emb.fix) != normalize_opt(&dsk.fix) {
            script_diffs.push(RuleDiff {
                rule_id: (*rule_id).to_owned(),
                field: "fix".to_owned(),
            });
        }

        // Compare mobileconfig flag.
        if emb.mobileconfig != dsk.mobileconfig {
            mobileconfig_diffs.push((*rule_id).to_owned());
        }

        // Compare title.
        if emb.title.trim() != dsk.title.trim() {
            title_diffs.push((*rule_id).to_owned());
        }

        // Compare severity.
        if emb.severity != dsk.severity {
            severity_diffs.push((*rule_id).to_owned());
        }
    }

    let report = CompatReport {
        baseline: baseline.to_owned(),
        platform: platform.to_owned(),
        embedded_count: embedded_rules.len(),
        disk_count: disk_rules.len(),
        matched_count: common_ids.len(),
        only_embedded,
        only_disk,
        script_diffs,
        mobileconfig_diffs,
        title_diffs,
        severity_diffs,
    };

    match mode {
        OutputMode::Human => print_human_report(&report),
        OutputMode::Json => print_json_report(&report)?,
    }

    Ok(())
}

/// Normalize an optional string for comparison: trim trailing whitespace per line.
fn normalize_opt(s: &Option<String>) -> Option<String> {
    s.as_ref()
        .map(|v| v.lines().map(str::trim_end).collect::<Vec<_>>().join("\n"))
}

/// Render the compatibility report as human-readable colored output.
fn print_human_report(report: &CompatReport) {
    use colored::Colorize;

    println!();
    print_info(&format!(
        "Compatibility check: {} ({})",
        report.baseline, report.platform
    ));
    print_kv("  Embedded rules", &report.embedded_count.to_string());
    print_kv("  Disk rules", &report.disk_count.to_string());
    println!();

    let total = report.embedded_count.max(report.disk_count).max(1);
    let pct = (report.matched_count as f64 / total as f64) * 100.0;
    print_success(&format!("Matched: {} ({:.1}%)", report.matched_count, pct));

    if report.only_embedded.is_empty() {
        print_kv("  Only embedded", "0");
    } else {
        print_warning(&format!(
            "Only embedded: {} ({})",
            report.only_embedded.len(),
            report.only_embedded.join(", ")
        ));
    }

    if report.only_disk.is_empty() {
        print_kv("  Only disk", "0");
    } else {
        print_warning(&format!(
            "Only disk: {} ({})",
            report.only_disk.len(),
            report.only_disk.join(", ")
        ));
    }

    println!();

    // Script diffs
    let script_diff_count = report.script_diffs.len();
    print_kv("  Script diffs", &script_diff_count.to_string());
    if script_diff_count > 0 {
        for diff in &report.script_diffs {
            println!(
                "    {}: {} script differs",
                diff.rule_id.yellow(),
                diff.field
            );
        }
    }

    // Mobileconfig flag diffs
    print_kv(
        "  Mobileconfig flag diffs",
        &report.mobileconfig_diffs.len().to_string(),
    );
    for rule_id in &report.mobileconfig_diffs {
        println!("    {}", rule_id.yellow());
    }

    // Title diffs
    print_kv("  Title diffs", &report.title_diffs.len().to_string());
    for rule_id in &report.title_diffs {
        println!("    {}", rule_id.yellow());
    }

    // Severity diffs
    print_kv("  Severity diffs", &report.severity_diffs.len().to_string());
    for rule_id in &report.severity_diffs {
        println!("    {}", rule_id.yellow());
    }

    println!();
}

/// Render the compatibility report as structured JSON.
fn print_json_report(report: &CompatReport) -> Result<()> {
    let script_diff_entries: Vec<serde_json::Value> = report
        .script_diffs
        .iter()
        .map(|d| {
            serde_json::json!({
                "rule_id": d.rule_id,
                "field": d.field,
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&serde_json::json!({
        "baseline": report.baseline,
        "platform": report.platform,
        "embedded_count": report.embedded_count,
        "disk_count": report.disk_count,
        "matched_count": report.matched_count,
        "only_embedded": report.only_embedded,
        "only_disk": report.only_disk,
        "script_diffs": script_diff_entries,
        "mobileconfig_diffs": report.mobileconfig_diffs,
        "title_diffs": report.title_diffs,
        "severity_diffs": report.severity_diffs,
    }))?;
    println!("{json}");
    Ok(())
}

/// Search rules by keyword and display matching results.
pub fn handle_schema_search(query: &str, platform: Option<&str>, mode: OutputMode) -> Result<()> {
    let rules = crate::api::search_rules(query, platform)?;

    match mode {
        OutputMode::Human => {
            print_info(&format!(
                "Search results for \"{query}\": {} rules",
                rules.len()
            ));
            println!();

            if rules.is_empty() {
                print_warning("No rules matched your query.");
            } else {
                // Table header
                println!(
                    "{:<35} {:<50} {:<15} {:<12} {:<5} TAGS",
                    "RULE_ID", "TITLE", "ENFORCEMENT", "MOBILECONFIG", "ODV"
                );
                println!("{}", "-".repeat(140));

                for r in &rules {
                    let enforcement = r.enforcement_type.as_deref().unwrap_or("unknown");
                    let mobileconfig = if r.mobileconfig { "yes" } else { "no" };
                    let odv = if r.odv_default.is_some() { "yes" } else { "" };
                    let tags = r.tags.join(", ");
                    let title: String = r.title.chars().take(48).collect();
                    println!(
                        "{:<35} {:<50} {:<15} {:<12} {:<5} {}",
                        r.rule_id, title, enforcement, mobileconfig, odv, tags
                    );
                }
                println!();
                print_success(&format!("{} rules found", rules.len()));
            }
        }
        OutputMode::Json => {
            let items: Vec<serde_json::Value> = rules
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "rule_id": r.rule_id,
                        "title": r.title,
                        "platform": r.platform,
                        "os_version": r.os_version,
                        "severity": r.severity,
                        "enforcement_type": r.enforcement_type,
                        "mobileconfig": r.mobileconfig,
                        "has_check": r.has_check,
                        "has_fix": r.has_fix,
                        "has_ddm_info": r.has_ddm_info,
                        "has_odv": r.odv_default.is_some(),
                        "odv_default": r.odv_default,
                        "tags": r.tags,
                    })
                })
                .collect();
            let json = serde_json::to_string_pretty(&items)?;
            println!("{json}");
        }
    }
    Ok(())
}

/// Truncate a multi-line string to the first N lines, appending "..." if truncated.
fn truncate_lines(s: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = s.lines().take(max_lines + 1).collect();
    if lines.len() > max_lines {
        let mut result: String = lines[..max_lines].join("\n");
        result.push_str("\n  ...");
        result
    } else {
        lines.join("\n")
    }
}

/// Show full detail for a specific rule.
pub fn handle_schema_rule(rule_id: &str, mode: OutputMode) -> Result<()> {
    let detail = crate::api::get_rule_detail(rule_id)?;

    let Some(detail) = detail else {
        match mode {
            OutputMode::Human => {
                print_warning(&format!("Rule \"{rule_id}\" not found in embedded schema."));
            }
            OutputMode::Json => {
                println!("null");
            }
        }
        return Ok(());
    };

    match mode {
        OutputMode::Human => {
            let r = &detail.rule;
            print_info(&format!("Rule: {}", r.rule_id));
            println!();

            print_kv("title", &r.title);
            print_kv("platform", &r.platform);
            print_kv("os_version", &r.os_version);
            print_kv("severity", r.severity.as_deref().unwrap_or("unspecified"));
            print_kv(
                "enforcement_type",
                r.enforcement_type.as_deref().unwrap_or("unknown"),
            );
            print_kv("mobileconfig", &r.mobileconfig.to_string());
            print_kv("has_check", &r.has_check.to_string());
            print_kv("has_fix", &r.has_fix.to_string());
            print_kv("has_ddm_info", &r.has_ddm_info.to_string());
            print_kv("tags", &r.tags.join(", "));
            println!();

            // Baselines
            if detail.baselines.is_empty() {
                print_kv("baselines", "(none)");
            } else {
                print_kv("baselines", &detail.baselines.join(", "));
            }
            println!();

            // Payload details
            if let Some(ref p) = detail.payload {
                if let Some(ref check) = p.check_script {
                    print_kv("check_script (first 10 lines)", "");
                    println!("{}", truncate_lines(check, 10));
                    println!();
                }
                if let Some(ref fix) = p.fix_script {
                    print_kv("fix_script (first 10 lines)", "");
                    println!("{}", truncate_lines(fix, 10));
                    println!();
                }
                if let Some(ref mc) = p.mobileconfig_info {
                    print_kv("mobileconfig_info", mc);
                }
                if let Some(ref dt) = p.ddm_declaration_type {
                    print_kv("ddm_declaration_type", dt);
                }
                if let Some(ref dk) = p.ddm_key {
                    print_kv("ddm_key", dk);
                }
                if let Some(ref dv) = p.ddm_value {
                    print_kv("ddm_value", dv);
                }
                if let Some(ref ds) = p.ddm_service {
                    print_kv("ddm_service", ds);
                }
                if let Some(ref dcf) = p.ddm_config_file {
                    print_kv("ddm_config_file", dcf);
                }
                if let Some(ref dck) = p.ddm_configuration_key {
                    print_kv("ddm_configuration_key", dck);
                }
                if let Some(ref dcv) = p.ddm_configuration_value {
                    print_kv("ddm_configuration_value", dcv);
                }
                if let Some(ref odv) = p.odv_options {
                    print_kv("odv_options", odv);
                }
            }
            println!();
            print_success("Rule detail loaded");
        }
        OutputMode::Json => {
            let r = &detail.rule;
            let mut rule_json = serde_json::json!({
                "rule_id": r.rule_id,
                "title": r.title,
                "platform": r.platform,
                "os_version": r.os_version,
                "severity": r.severity,
                "enforcement_type": r.enforcement_type,
                "mobileconfig": r.mobileconfig,
                "has_check": r.has_check,
                "has_fix": r.has_fix,
                "has_ddm_info": r.has_ddm_info,
                "tags": r.tags,
                "content_hash": r.content_hash,
                "has_result": r.has_result,
                "check_mechanism": r.check_mechanism,
                "osquery_checkable": r.osquery_checkable,
                "osquery_table": r.osquery_table,
                "baseline_count": r.baseline_count,
                "control_count": r.control_count,
                "weight": r.weight,
                "odv_default": r.odv_default,
                "distro": r.distro,
            });

            let payload_json = if let Some(ref p) = detail.payload {
                serde_json::json!({
                    "rule_id": p.rule_id,
                    "check_script": p.check_script,
                    "fix_script": p.fix_script,
                    "expected_result": p.expected_result,
                    "odv_options": p.odv_options,
                    "mobileconfig_info": p.mobileconfig_info,
                    "ddm_declaration_type": p.ddm_declaration_type,
                    "ddm_key": p.ddm_key,
                    "ddm_value": p.ddm_value,
                    "ddm_service": p.ddm_service,
                    "ddm_config_file": p.ddm_config_file,
                    "ddm_configuration_key": p.ddm_configuration_key,
                    "ddm_configuration_value": p.ddm_configuration_value,
                })
            } else {
                serde_json::Value::Null
            };

            rule_json["payload"] = payload_json;
            rule_json["baselines"] = serde_json::json!(detail.baselines);

            let json = serde_json::to_string_pretty(&rule_json)?;
            println!("{json}");
        }
    }
    Ok(())
}
