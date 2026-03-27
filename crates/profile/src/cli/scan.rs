//! Scan command CLI handler - preview profile metadata and simulate normalize

use crate::cli::glob_utils::{collect_profile_files_multi_with_depth, should_batch_process_multi};
use crate::config::ProfileConfig;
use crate::output::OutputMode;
use crate::profile::ConfigurationProfile;
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
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    // Determine simulation domain: CLI → profile.toml → .contour/config.toml → "com.example"
    let sim_domain = domain
        .map(std::string::ToString::to_string)
        .or_else(|| config.map(|c| c.organization.domain.clone()))
        .or_else(|| {
            contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.domain)
        })
        .unwrap_or_else(|| "com.example".to_string());

    // Check if we should use batch processing
    if should_batch_process_multi(paths) {
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

        let results = scan_files(&files, simulate, &sim_domain, parallel);
        output_scan_results(&results, output_mode);
        return Ok(());
    }

    // Single file mode
    let input = &paths[0];
    let path = Path::new(input);

    if !path.exists() {
        anyhow::bail!("Path not found: {input}");
    }

    if path.is_file() {
        let result = scan_single_file(path, simulate, &sim_domain)?;
        output_scan_result(&result, output_mode);
    } else {
        anyhow::bail!("Path is not a file: {input}");
    }

    Ok(())
}

/// Scan a single profile file
fn scan_single_file(path: &Path, simulate: bool, sim_domain: &str) -> Result<ScanResult> {
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
    })
}

/// Scan multiple files (for glob pattern support)
fn scan_files(
    files: &[std::path::PathBuf],
    simulate: bool,
    sim_domain: &str,
    parallel: bool,
) -> Vec<ScanResult> {
    if parallel {
        let outcomes: Vec<Result<ScanResult, (String, String)>> = files
            .par_iter()
            .map(|path| {
                scan_single_file(path, simulate, sim_domain)
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
            match scan_single_file(path, simulate, sim_domain) {
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
#[allow(dead_code, reason = "reserved for future use")]
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

    Ok(scan_files(&files, simulate, sim_domain, parallel))
}

/// Check if a file is a profile file
#[allow(dead_code, reason = "reserved for future use")]
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

    println!();
}

/// Sanitize a name for use in identifier
fn sanitize_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
        .to_lowercase()
        .replace(' ', "-")
}
