//! Scan command CLI handler - preview profile metadata and simulate normalize

use crate::cli::glob_utils::{collect_profile_files_multi_with_depth, should_batch_process_multi};
use crate::config::ProfileConfig;
use crate::migrate::mapping::MigrationRegistry;
use crate::output::OutputMode;
use crate::profile::ConfigurationProfile;
use crate::profile::deprecation::{
    self, DeprecationFinding, DeprecationReport, DeprecationSeverity,
};
use crate::schema::SchemaRegistry;
use crate::signing;
use anyhow::{Context, Result};
use colored::Colorize;
use rayon::prelude::*;
use std::path::Path;
use walkdir::WalkDir;

/// Profile scan result for JSON output
#[derive(serde::Serialize)]
struct ScanResult {
    path: String,
    signed: bool,
    envelope: EnvelopeInfo,
    payloads: Vec<PayloadInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    simulation: Option<SimulationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deprecations: Option<DeprecationReport>,
}

#[derive(serde::Serialize)]
struct EnvelopeInfo {
    display_name: String,
    identifier: String,
    organization: Option<String>,
    uuid: String,
}

#[derive(serde::Serialize)]
struct PayloadInfo {
    index: usize,
    r#type: String,
    identifier: String,
    display_name: Option<String>,
}

#[derive(serde::Serialize)]
struct SimulationInfo {
    domain: String,
    envelope_identifier: IdentifierChange,
    payloads: Vec<IdentifierChange>,
}

#[derive(serde::Serialize)]
struct IdentifierChange {
    original: String,
    normalized: String,
}

/// Handle `form scan` command
pub fn handle_scan(
    paths: &[String],
    simulate: bool,
    domain: Option<&str>,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    deprecations: bool,
    md_report: Option<&str>,
    fail_on_deprecations: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    // `--md-report` implies `--deprecations`.
    let deprecations = deprecations || md_report.is_some();

    // Build the deprecation registries once when scanning is requested.
    let registries = if deprecations {
        let migration = MigrationRegistry::new();
        let schema = SchemaRegistry::embedded()
            .context("Failed to load embedded schema for deprecation scan")?;
        Some((migration, schema))
    } else {
        None
    };
    let registry_refs = registries.as_ref().map(|(m, s)| (m, s));

    // Resolve simulation domain: CLI → profile.toml → .contour/config.toml.
    // Only required when --simulate is set (otherwise sim_domain is unused;
    // see line ~150 where the simulation block is gated on `simulate`).
    let resolved_domain = domain
        .map(std::string::ToString::to_string)
        .or_else(|| config.map(|c| c.organization.domain.clone()))
        .or_else(|| {
            contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.domain)
        });
    let sim_domain = if simulate {
        resolved_domain.ok_or_else(|| {
            anyhow::anyhow!(
                "--org is required with --simulate (e.g., --org com.yourorg)\n\
                 Alternatively, set organization.domain in profile.toml or .contour/config.toml"
            )
        })?
    } else {
        // Read-only scan — domain is unused; placeholder is fine.
        resolved_domain.unwrap_or_default()
    };

    // Check if we should use batch processing
    let all_results: Vec<ScanResult> = if should_batch_process_multi(paths) {
        let files = collect_profile_files_multi_with_depth(paths, recursive, max_depth)?;
        if files.is_empty() {
            if output_mode == OutputMode::Human {
                println!("{}", "No .mobileconfig files found".yellow());
            } else {
                let result = serde_json::json!({
                    "total": 0,
                    "profiles": [],
                    "message": "No .mobileconfig files found"
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            return Ok(());
        }

        let results = scan_files(&files, simulate, &sim_domain, parallel, registry_refs);
        output_scan_results(&results, output_mode);
        results
    } else {
        // Single file mode
        let input = &paths[0];
        let path = Path::new(input);

        if !path.exists() {
            anyhow::bail!("Path not found: {input}");
        }
        if !path.is_file() {
            anyhow::bail!("Path is not a file: {input}");
        }

        let result = scan_single_file(path, simulate, &sim_domain, registry_refs)?;
        output_scan_result(&result, output_mode);
        vec![result]
    };

    if let Some(md_path) = md_report {
        let md = render_markdown_report(&all_results);
        std::fs::write(md_path, md)
            .with_context(|| format!("Failed to write Markdown report to {md_path}"))?;
        if output_mode == OutputMode::Human {
            println!("  {} Markdown report → {}", "→".green(), md_path);
        }
    }

    // Gate: fail the run when deprecations are found and the gate is on.
    // Runs after all output so the operator sees the full report first.
    if deprecations {
        let total: usize = all_results
            .iter()
            .filter_map(|r| r.deprecations.as_ref())
            .map(|r| r.findings.len())
            .sum();
        let gate = fail_on_deprecations
            || contour_core::config::resolve_validation_with_anchor(None).fail_on_deprecations;
        if gate && total > 0 {
            anyhow::bail!(
                "deprecation scan failed: {total} deprecation(s) found \
                 (--fail-on-deprecations / [validation].fail_on_deprecations)"
            );
        }
    }

    Ok(())
}

/// Scan a single profile file
fn scan_single_file(
    path: &Path,
    simulate: bool,
    sim_domain: &str,
    registries: Option<(&MigrationRegistry, &SchemaRegistry)>,
) -> Result<ScanResult> {
    // Check if profile is signed
    let is_signed = signing::is_signed_profile(path).unwrap_or(false);

    // Load profile (remove signature if needed)
    let profile: ConfigurationProfile = if is_signed {
        let data = signing::remove_signature(path)
            .with_context(|| format!("Failed to remove signature from: {}", path.display()))?;
        plist::from_bytes(&data)
            .with_context(|| format!("Failed to parse profile: {}", path.display()))?
    } else {
        plist::from_file(path)
            .with_context(|| format!("Failed to parse profile: {}", path.display()))?
    };

    // Get organization from profile
    let current_org = profile
        .additional_fields
        .get("PayloadOrganization")
        .and_then(|v| v.as_string())
        .map(std::string::ToString::to_string);

    // Build payload info
    let payloads: Vec<PayloadInfo> = profile
        .payload_content
        .iter()
        .enumerate()
        .map(|(i, p)| PayloadInfo {
            index: i,
            r#type: p.payload_type.clone(),
            identifier: p.payload_identifier.clone(),
            display_name: p.payload_display_name(),
        })
        .collect();

    // Build simulation if requested
    let simulation = if simulate {
        let sim_envelope_id = format!(
            "{}.profile.{}",
            sim_domain,
            sanitize_name(&profile.payload_display_name)
        );
        let sim_payloads: Vec<IdentifierChange> = profile
            .payload_content
            .iter()
            .map(|p| IdentifierChange {
                original: p.payload_identifier.clone(),
                normalized: format!(
                    "{}.{}",
                    sim_domain,
                    p.payload_type.split('.').next_back().unwrap_or("payload")
                ),
            })
            .collect();

        Some(SimulationInfo {
            domain: sim_domain.to_string(),
            envelope_identifier: IdentifierChange {
                original: profile.payload_identifier.clone(),
                normalized: sim_envelope_id,
            },
            payloads: sim_payloads,
        })
    } else {
        None
    };

    let deprecations = registries.map(|(migration, schema)| {
        let value = profile.to_plist_value();
        deprecation::scan_deprecations(&value, path, migration, schema)
    });

    Ok(ScanResult {
        path: path.display().to_string(),
        signed: is_signed,
        envelope: EnvelopeInfo {
            display_name: profile.payload_display_name.clone(),
            identifier: profile.payload_identifier.clone(),
            organization: current_org,
            uuid: profile.payload_uuid.clone(),
        },
        payloads,
        simulation,
        deprecations,
    })
}

/// Scan multiple files (for glob pattern support)
fn scan_files(
    files: &[std::path::PathBuf],
    simulate: bool,
    sim_domain: &str,
    parallel: bool,
    registries: Option<(&MigrationRegistry, &SchemaRegistry)>,
) -> Vec<ScanResult> {
    if parallel {
        let outcomes: Vec<Result<ScanResult, (String, String)>> = files
            .par_iter()
            .map(|path| {
                scan_single_file(path, simulate, sim_domain, registries)
                    .map_err(|e| (path.display().to_string(), e.to_string()))
            })
            .collect();

        let mut results = Vec::new();
        for outcome in outcomes {
            match outcome {
                Ok(result) => results.push(result),
                Err((path, err)) => {
                    eprintln!("{} {}: {}", "Warning:".yellow(), path, err);
                }
            }
        }

        results
    } else {
        let mut results = Vec::new();
        let mut errors = Vec::new();

        for path in files {
            match scan_single_file(path, simulate, sim_domain, registries) {
                Ok(result) => results.push(result),
                Err(e) => errors.push((path.display().to_string(), e.to_string())),
            }
        }

        // Report errors to stderr
        for (path, err) in &errors {
            eprintln!("{} {}: {}", "Warning:".yellow(), path, err);
        }

        results
    }
}

/// Scan a directory for profile files
#[expect(dead_code, reason = "reserved for future use")]
fn scan_directory(
    dir: &Path,
    recursive: bool,
    simulate: bool,
    sim_domain: &str,
    parallel: bool,
) -> Result<Vec<ScanResult>> {
    let walker = if recursive {
        WalkDir::new(dir).follow_links(true)
    } else {
        WalkDir::new(dir).max_depth(1).follow_links(true)
    };

    // Collect all profile files first
    let files: Vec<std::path::PathBuf> = walker
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file() && is_profile_file(entry.path()))
        .map(|entry| entry.path().to_path_buf())
        .collect();

    Ok(scan_files(&files, simulate, sim_domain, parallel, None))
}

/// Check if a file is a profile file
fn is_profile_file(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("mobileconfig"))
}

/// Output a single scan result
fn output_scan_result(result: &ScanResult, output_mode: OutputMode) {
    if output_mode == OutputMode::Json {
        println!("{}", serde_json::to_string_pretty(result).unwrap());
    } else {
        print_scan_result_human(result);
    }
}

/// Output multiple scan results
fn output_scan_results(results: &[ScanResult], output_mode: OutputMode) {
    if output_mode == OutputMode::Json {
        let output = serde_json::json!({
            "total": results.len(),
            "profiles": results,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!(
            "{}",
            format!("Scanned {} profiles", results.len()).cyan().bold()
        );
        println!();

        for result in results {
            print_scan_result_human(result);
            println!("{}", "─".repeat(60).dimmed());
        }

        // Summary
        let signed_count = results.iter().filter(|r| r.signed).count();
        let total_payloads: usize = results.iter().map(|r| r.payloads.len()).sum();

        println!();
        println!("{}", "Summary".white().bold());
        println!("  {} {} profiles", "Total:".cyan(), results.len());
        println!("  {} {} signed", "Signed:".cyan(), signed_count);
        println!("  {} {} payloads", "Payloads:".cyan(), total_payloads);

        if results.iter().any(|r| r.deprecations.is_some()) {
            let dep_total: usize = results
                .iter()
                .filter_map(|r| r.deprecations.as_ref())
                .map(|r| r.findings.len())
                .sum();
            println!("  {} {} deprecations", "Deprecated:".cyan(), dep_total);
        }
    }
}

/// Print a single scan result in human-readable format
fn print_scan_result_human(result: &ScanResult) {
    println!("{}", result.path.bold());
    println!();

    // Envelope info
    println!("  {}", "Envelope".white().bold());
    println!(
        "    {} {}",
        "Display Name:".cyan(),
        result.envelope.display_name
    );
    println!(
        "    {} {}",
        "Identifier:".cyan(),
        result.envelope.identifier
    );
    if let Some(org) = &result.envelope.organization {
        println!("    {} {}", "Organization:".cyan(), org);
    }
    if result.signed {
        println!("    {} {}", "Signed:".cyan(), "Yes".yellow());
    }
    println!();

    // Payloads
    println!(
        "  {} ({})",
        "Payloads".white().bold(),
        result.payloads.len()
    );
    for p in &result.payloads {
        let display = p.display_name.as_deref().unwrap_or("");
        println!(
            "    {}. {} {}",
            p.index + 1,
            p.r#type.green(),
            format!("({display})").dimmed()
        );
        println!("       {}", p.identifier.dimmed());
    }

    // Simulation
    if let Some(sim) = &result.simulation {
        println!();
        println!("  {}", "Normalize Simulation".yellow().bold());
        println!("    {} {}", "Target Domain:".cyan(), sim.domain);
        println!();
        println!("    {} Envelope Identifier", "→".yellow());
        println!(
            "      {} {}",
            "From:".dimmed(),
            sim.envelope_identifier.original
        );
        println!(
            "      {} {}",
            "To:".green(),
            sim.envelope_identifier.normalized
        );
        println!();
        println!("    {} Payload Identifiers", "→".yellow());
        for change in &sim.payloads {
            println!("      {} {}", "From:".dimmed(), change.original);
            println!("      {} {}", "To:".green(), change.normalized);
        }
    }

    if let Some(report) = &result.deprecations {
        println!();
        print_deprecations(&report.findings);
    }

    println!();
}

/// Print the deprecation findings for one scanned profile.
fn print_deprecations(findings: &[DeprecationFinding]) {
    if findings.is_empty() {
        println!("  {} {}", "Deprecations".white().bold(), "none".green());
        return;
    }
    println!("  {} ({})", "Deprecations".white().bold(), findings.len());
    for f in findings {
        let (marker, sev) = match f.severity {
            DeprecationSeverity::Critical => ("✗".red(), "critical".red()),
            DeprecationSeverity::Warning => ("⚠".yellow(), "warning".yellow()),
        };
        let since = f
            .deprecated_in
            .as_deref()
            .map(|d| format!(" (deprecated {d})"))
            .unwrap_or_default();
        let repl = f
            .replacement
            .as_deref()
            .map(|r| format!(" → {r}"))
            .unwrap_or_default();
        println!(
            "    {} [{}] {}{}{}",
            marker,
            sev,
            f.locator.cyan(),
            since.dimmed(),
            repl.green()
        );
    }
}

/// Render a Markdown deprecation report for the scanned profiles.
fn render_markdown_report(results: &[ScanResult]) -> String {
    use std::fmt::Write as _;

    let mut md = String::new();
    md.push_str("# Deprecation Report\n\n");

    let scanned: Vec<&ScanResult> = results
        .iter()
        .filter(|r| r.deprecations.is_some())
        .collect();
    let with_findings: Vec<&ScanResult> = scanned
        .iter()
        .copied()
        .filter(|r| r.deprecations.as_ref().is_some_and(|d| !d.is_empty()))
        .collect();

    let _ = writeln!(
        md,
        "{} profile(s) scanned, {} with deprecations.\n",
        scanned.len(),
        with_findings.len()
    );

    md.push_str("| Profile | Critical | Warning |\n");
    md.push_str("|---|---|---|\n");
    for r in &scanned {
        let report = r.deprecations.as_ref().unwrap();
        let _ = writeln!(
            md,
            "| {} | {} | {} |",
            r.path,
            report.critical_count(),
            report.warning_count()
        );
    }
    md.push('\n');

    for r in &with_findings {
        let report = r.deprecations.as_ref().unwrap();
        let _ = writeln!(md, "## {}\n", r.path);
        for sev in [DeprecationSeverity::Critical, DeprecationSeverity::Warning] {
            let group: Vec<&DeprecationFinding> = report
                .findings
                .iter()
                .filter(|f| f.severity == sev)
                .collect();
            if group.is_empty() {
                continue;
            }
            let label = match sev {
                DeprecationSeverity::Critical => "Critical",
                DeprecationSeverity::Warning => "Warning",
            };
            let _ = writeln!(md, "### {label}\n");
            for f in group {
                let since = f
                    .deprecated_in
                    .as_deref()
                    .map(|d| format!(" (deprecated {d})"))
                    .unwrap_or_default();
                let repl = f
                    .replacement
                    .as_deref()
                    .map(|r| format!(" → `{r}`"))
                    .unwrap_or_default();
                let _ = writeln!(md, "- `{}`{}{}", f.locator, since, repl);
                let _ = writeln!(md, "  - {}", f.detail);
            }
            md.push('\n');
        }
    }
    md
}

/// Sanitize a name for use in identifier
fn sanitize_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
        .to_lowercase()
        .replace(' ', "-")
}
