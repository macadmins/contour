//! Local application scanning via santactl fileinfo.
//!
//! For users without Fleet, this provides an alternative way to gather
//! app inventory data by scanning local applications.

use crate::bundle::{Bundle, BundleSet};
use crate::cli::{ScanOutputFormat, ScanRuleType};
use crate::generator::{self, GeneratorOptions};
use crate::models::{Policy, Rule, RuleSet, RuleType};
use crate::output::{print_error, print_info, print_kv, print_success};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Result of scanning an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedApp {
    pub name: String,
    pub path: String,
    pub version: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub sha256: Option<String>,
    pub cdhash: Option<String>,
    pub bundle_id: Option<String>,
}

/// JSON output from santactl fileinfo --json
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[expect(dead_code, reason = "reserved for future use")]
struct SantactlJson {
    path: Option<String>,
    #[serde(rename = "SHA-256")]
    sha256: Option<String>,
    #[serde(rename = "SHA-1")]
    sha1: Option<String>,
    #[serde(rename = "Bundle Name")]
    bundle_name: Option<String>,
    #[serde(rename = "Bundle Version")]
    bundle_version: Option<String>,
    #[serde(rename = "Bundle Version Str")]
    bundle_version_str: Option<String>,
    #[serde(rename = "Team ID")]
    team_id: Option<String>,
    #[serde(rename = "Signing ID")]
    signing_id: Option<String>,
    #[serde(rename = "CDHash")]
    cdhash: Option<String>,
    #[serde(rename = "Type")]
    file_type: Option<String>,
}

/// Scan options.
#[derive(Debug)]
pub struct ScanOptions {
    /// Directories to scan
    pub paths: Vec<PathBuf>,
    /// Output CSV path
    pub output: PathBuf,
    /// Include unsigned apps
    pub include_unsigned: bool,
    /// Verbose output
    pub verbose: bool,
    /// Device name for CSV output
    pub device_name: String,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            paths: vec![PathBuf::from("/Applications")],
            output: PathBuf::from("local-apps.csv"),
            include_unsigned: false,
            verbose: false,
            device_name: get_hostname(),
        }
    }
}

/// Get the local hostname.
fn get_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "localhost".to_string())
}

/// Run the scan command.
pub fn run(
    paths: &[PathBuf],
    output: Option<&Path>,
    output_format: ScanOutputFormat,
    include_unsigned: bool,
    org: &str,
    rule_type: ScanRuleType,
    verbose: bool,
    json_output: bool,
) -> Result<()> {
    let device_name = get_hostname();

    // Determine output path based on format if not specified
    let output_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| default_output_path(output_format));

    if !json_output {
        print_info("Scanning local applications with santactl...");
        print_kv("Device", &device_name);
        print_kv(
            "Paths",
            &paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        print_kv(
            "Output format",
            &format!("{:?}", output_format).to_lowercase(),
        );
    }

    // Check if santactl is available
    if !is_santactl_available() {
        print_error("santactl not found. Please install Santa first.");
        print_info("Install Santa from: https://github.com/northpolesec/santa/releases");
        anyhow::bail!("santactl not available");
    }

    // Find all .app bundles
    let mut apps_to_scan: Vec<PathBuf> = Vec::new();
    for path in paths {
        if !path.exists() {
            if verbose && !json_output {
                print_info(&format!("Skipping non-existent path: {}", path.display()));
            }
            continue;
        }
        find_apps_recursive(path, &mut apps_to_scan)?;
    }

    if !json_output {
        print_kv("Apps found", &apps_to_scan.len().to_string());
    }

    // Scan each app
    let mut scanned: Vec<ScannedApp> = Vec::new();
    let mut unsigned_apps: Vec<String> = Vec::new();
    let mut errored_apps: Vec<(String, String)> = Vec::new();

    for (i, app_path) in apps_to_scan.iter().enumerate() {
        if verbose && !json_output && i % 50 == 0 {
            print_info(&format!("Scanning {}/{}...", i + 1, apps_to_scan.len()));
        }

        let app_name = app_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| app_path.display().to_string());

        match scan_app(app_path) {
            Ok(Some(app)) => {
                if app.team_id.is_some() || include_unsigned {
                    scanned.push(app);
                } else {
                    unsigned_apps.push(app_name);
                }
            }
            Ok(None) => {
                unsigned_apps.push(app_name);
            }
            Err(e) => {
                errored_apps.push((app_name, e.to_string()));
            }
        }
    }

    let unsigned_count = unsigned_apps.len();
    let error_count = errored_apps.len();

    // Ensure output directory exists
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write output in the specified format
    let mut baseline_summary: Option<BaselineMergeSummary> = None;
    match output_format {
        ScanOutputFormat::Csv => {
            write_csv(&scanned, &output_path, &device_name)?;
        }
        ScanOutputFormat::Bundles => {
            write_bundles(&scanned, &output_path)?;
        }
        ScanOutputFormat::Rules => {
            write_rules(&scanned, &output_path, rule_type)?;
        }
        ScanOutputFormat::Mobileconfig => {
            write_mobileconfig(&scanned, &output_path, org, rule_type)?;
        }
        ScanOutputFormat::Baseline => {
            baseline_summary = Some(write_baseline(&scanned, &output_path, rule_type)?);
        }
        ScanOutputFormat::AppSettings => {
            write_app_settings(&scanned, &output_path, org, rule_type, json_output)?;
        }
    }

    if json_output {
        let result = ScanResult {
            device_name,
            apps_found: apps_to_scan.len(),
            apps_scanned: scanned.len(),
            unsigned_skipped: unsigned_count,
            unsigned_apps: unsigned_apps.clone(),
            errors: error_count,
            errored_apps: errored_apps
                .iter()
                .map(|(name, err)| format!("{}: {}", name, err))
                .collect(),
            output_path: output_path.display().to_string(),
            output_format: format!("{:?}", output_format).to_lowercase(),
        };
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!();
        print_success(&format!(
            "Scan complete! {} apps written to {}",
            scanned.len(),
            output_path.display()
        ));
        if let Some(summary) = &baseline_summary {
            print_kv("Baseline added", &summary.added.to_string());
            print_kv(
                "Baseline already present",
                &summary.already_present.to_string(),
            );
            print_kv(
                "Baseline conflicts (deny-wins)",
                &summary.conflicts.to_string(),
            );
        }
        if unsigned_count > 0 {
            print_kv("Unsigned skipped", &unsigned_count.to_string());
            for name in &unsigned_apps {
                println!("    - {}", name);
            }
        }
        if error_count > 0 {
            print_kv("Errors", &error_count.to_string());
            for (name, err) in &errored_apps {
                println!("    - {}: {}", name, err);
            }
        }
        println!();
        print_next_steps(output_format, &output_path);
    }

    Ok(())
}

/// Get default output path based on format.
fn default_output_path(format: ScanOutputFormat) -> PathBuf {
    match format {
        ScanOutputFormat::Csv => PathBuf::from("local-apps.csv"),
        ScanOutputFormat::Bundles => PathBuf::from("bundles.toml"),
        ScanOutputFormat::Rules => PathBuf::from("rules.yaml"),
        ScanOutputFormat::Mobileconfig => PathBuf::from("santa-rules.mobileconfig"),
        ScanOutputFormat::Baseline => PathBuf::from("baseline.toml"),
        ScanOutputFormat::AppSettings => PathBuf::from("app-settings.json"),
    }
}

/// Print next steps based on output format.
fn print_next_steps(format: ScanOutputFormat, output: &Path) {
    match format {
        ScanOutputFormat::Csv => {
            print_info("Next steps:");
            println!("  1. contour santa allow --input {}", output.display());
            println!("     (quick: allow all scanned apps)");
            println!("  2. contour santa select --input {}", output.display());
            println!("     (interactive: pick which apps to allow)");
            println!(
                "  3. contour santa discover --input {} --output bundles.toml",
                output.display()
            );
            println!("     (advanced: bundle-based pipeline for fleet-wide management)");
        }
        ScanOutputFormat::Bundles => {
            print_info("Next steps:");
            println!("  1. Review and edit {}", output.display());
            println!(
                "  2. contour santa generate {} --output santa-rules.mobileconfig",
                output.display()
            );
        }
        ScanOutputFormat::Rules => {
            print_info("Next steps:");
            println!("  1. Review {}", output.display());
            println!(
                "  2. contour santa generate {} --output santa-rules.mobileconfig",
                output.display()
            );
        }
        ScanOutputFormat::Mobileconfig => {
            print_info("Next steps:");
            println!("  1. Review the generated profile");
            println!("  2. Deploy {} via MDM", output.display());
        }
        ScanOutputFormat::Baseline => {
            print_info("Next steps:");
            println!("  1. Review {}", output.display());
            println!(
                "  2. contour santa rings generate <rules> --baseline {} -o rings/",
                output.display()
            );
            println!("     (or `santa fleet` for Fleet GitOps)");
            println!("  3. Re-run this command to grow the baseline across machines");
        }
        ScanOutputFormat::AppSettings => {
            print_info("Next steps:");
            println!("  1. Review {}", output.display());
            println!(
                "  2. contour profile ddm validate --beta {}",
                output.display()
            );
            println!("  3. Deploy the declaration via your MDM (macOS 27+)");
        }
    }
}

#[derive(Debug, Serialize)]
struct ScanResult {
    device_name: String,
    apps_found: usize,
    apps_scanned: usize,
    unsigned_skipped: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unsigned_apps: Vec<String>,
    errors: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errored_apps: Vec<String>,
    output_path: String,
    output_format: String,
}

/// Check if santactl is available.
fn is_santactl_available() -> bool {
    Command::new("santactl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Find all .app bundles recursively.
fn find_apps_recursive(path: &Path, apps: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        // Check if this is an .app bundle
        if path.extension().map(|e| e == "app").unwrap_or(false) {
            apps.push(path.to_path_buf());
            return Ok(()); // Don't recurse into .app bundles
        }

        // Recurse into subdirectories
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                find_apps_recursive(&entry_path, apps)?;
            }
        }
    }
    Ok(())
}

/// Scan a single app using santactl fileinfo --json.
fn scan_app(app_path: &Path) -> Result<Option<ScannedApp>> {
    // Find the main executable in the app bundle
    let executable = find_main_executable(app_path)?;

    let exec_str = executable
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("path contains invalid UTF-8: {}", executable.display()))?;
    let output = Command::new("santactl")
        .args(["fileinfo", "--json", exec_str])
        .output()
        .context("Failed to run santactl")?;

    if !output.status.success() {
        anyhow::bail!(
            "santactl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // santactl --json outputs an array
    let infos: Vec<SantactlJson> =
        serde_json::from_str(&stdout).context("Failed to parse santactl JSON output")?;

    if infos.is_empty() {
        return Ok(None);
    }

    let info = &infos[0];

    // Skip if no team ID and no signing ID
    if info.team_id.is_none() && info.signing_id.is_none() {
        return Ok(None);
    }

    let name = info
        .bundle_name
        .clone()
        .or_else(|| {
            app_path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "Unknown".to_string());

    Ok(Some(ScannedApp {
        name,
        path: app_path.display().to_string(),
        version: info
            .bundle_version_str
            .clone()
            .or(info.bundle_version.clone()),
        team_id: clean_optional(&info.team_id),
        signing_id: clean_optional(&info.signing_id),
        sha256: clean_optional(&info.sha256),
        cdhash: clean_optional(&info.cdhash),
        bundle_id: extract_bundle_id(&info.signing_id),
    }))
}

/// Clean optional string - convert "None" or empty to None.
fn clean_optional(value: &Option<String>) -> Option<String> {
    value.as_ref().and_then(|v| {
        if v.is_empty() || v == "None" || v == "null" {
            None
        } else {
            Some(v.clone())
        }
    })
}

/// Extract bundle ID from signing ID (format: TeamID:BundleID).
fn extract_bundle_id(signing_id: &Option<String>) -> Option<String> {
    signing_id
        .as_ref()
        .and_then(|s| s.split_once(':').map(|(_, bundle)| bundle.to_string()))
}

/// Find the main executable in an .app bundle.
///
/// Handles three bundle layouts:
/// 1. Standard macOS: `Contents/MacOS/<executable>`
/// 2. iOS-on-Mac (Designed for iPad): `Wrapper/<inner>.app/<executable>`
/// 3. Empty bundles: bail with descriptive error
fn find_main_executable(app_path: &Path) -> Result<PathBuf> {
    let contents = app_path.join("Contents");
    let macos = contents.join("MacOS");

    // Standard macOS layout: Contents/MacOS/<executable>
    if contents.exists() {
        // Try to read Info.plist to get the executable name
        let info_plist = contents.join("Info.plist");
        if info_plist.exists() {
            if let Ok(exec_name) = get_executable_from_plist(&info_plist) {
                let exec_path = macos.join(&exec_name);
                if exec_path.exists() {
                    return Ok(exec_path);
                }
            }
        }

        // Fallback: use the app name as executable name
        if let Some(app_name) = app_path.file_stem() {
            let exec_path = macos.join(app_name);
            if exec_path.exists() {
                return Ok(exec_path);
            }
        }

        // Last resort: find any executable in MacOS folder
        if macos.exists() {
            for entry in std::fs::read_dir(&macos)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    return Ok(path);
                }
            }
        }
    }

    // iOS-on-Mac layout: Wrapper/<inner>.app/<executable>
    let wrapper = app_path.join("Wrapper");
    if wrapper.exists() {
        // Find the inner .app bundle
        for entry in std::fs::read_dir(&wrapper)? {
            let entry = entry?;
            let inner_app = entry.path();
            if inner_app.extension().map(|e| e == "app").unwrap_or(false) && inner_app.is_dir() {
                // Read Info.plist from inner app
                let inner_plist = inner_app.join("Info.plist");
                if inner_plist.exists() {
                    if let Ok(exec_name) = get_executable_from_plist(&inner_plist) {
                        let exec_path = inner_app.join(&exec_name);
                        if exec_path.exists() {
                            return Ok(exec_path);
                        }
                    }
                }

                // Fallback: find any executable file in inner app
                for file in std::fs::read_dir(&inner_app)? {
                    let file = file?;
                    let path = file.path();
                    if path.is_file() && is_executable(&path) {
                        return Ok(path);
                    }
                }
            }
        }
    }

    // Check if this is an empty bundle (no Contents, no Wrapper)
    let entry_count = std::fs::read_dir(app_path)
        .map(|entries| entries.count())
        .unwrap_or(0);
    if entry_count == 0 {
        anyhow::bail!("Empty app bundle (no contents)")
    } else {
        anyhow::bail!("No executable found (unrecognized bundle layout)")
    }
}

/// Check if a file is executable (has execute permission).
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Get executable name from Info.plist.
fn get_executable_from_plist(plist_path: &Path) -> Result<String> {
    let content = std::fs::read(plist_path)?;
    let plist: plist::Value = plist::from_bytes(&content)?;

    if let Some(dict) = plist.as_dictionary() {
        if let Some(exec) = dict.get("CFBundleExecutable") {
            if let Some(name) = exec.as_string() {
                return Ok(name.to_string());
            }
        }
    }

    anyhow::bail!("CFBundleExecutable not found in Info.plist")
}

/// Write scanned apps to CSV in Fleet-compatible format.
fn write_csv(apps: &[ScannedApp], output: &Path, device_name: &str) -> Result<()> {
    let mut wtr = csv::Writer::from_path(output)?;

    // Write header matching Fleet CSV format
    wtr.write_record([
        "name",
        "version",
        "team_id",
        "signing_id",
        "sha256",
        "device_name",
        "bundle_id",
        "path",
    ])?;

    for app in apps {
        wtr.write_record([
            &app.name,
            app.version.as_deref().unwrap_or(""),
            app.team_id.as_deref().unwrap_or(""),
            app.signing_id.as_deref().unwrap_or(""),
            app.sha256.as_deref().unwrap_or(""),
            device_name,
            app.bundle_id.as_deref().unwrap_or(""),
            &app.path,
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

/// Write scanned apps to bundles.toml format, grouped by TeamID.
fn write_bundles(apps: &[ScannedApp], output: &Path) -> Result<()> {
    // Group apps by TeamID
    let mut by_team_id: HashMap<String, Vec<&ScannedApp>> = HashMap::new();

    for app in apps {
        if let Some(team_id) = &app.team_id {
            by_team_id.entry(team_id.clone()).or_default().push(app);
        }
    }

    // Convert to bundle definitions
    let mut bundle_set = BundleSet::new();

    // Sort by team_id for deterministic output
    let mut team_ids: Vec<_> = by_team_id.keys().collect();
    team_ids.sort();

    for team_id in team_ids {
        let team_apps = &by_team_id[team_id];
        let app_count = team_apps.len();

        // Try to derive a name from the apps
        let name = derive_bundle_name(team_apps, team_id);

        let bundle = Bundle::for_team_id(&name, team_id).with_app_count(app_count);

        bundle_set.add(bundle);
    }

    // Write to file
    bundle_set.to_toml_file(output)?;

    Ok(())
}

/// Derive a bundle name from a list of apps with the same TeamID.
fn derive_bundle_name(apps: &[&ScannedApp], team_id: &str) -> String {
    // Try to find a common prefix in app names
    if let Some(first_app) = apps.first() {
        let name = &first_app.name;
        // Use the first word as a simple heuristic
        let first_word = name
            .split_whitespace()
            .next()
            .unwrap_or(name)
            .to_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect::<String>();

        if !first_word.is_empty() && first_word.len() <= 20 {
            return first_word;
        }
    }

    // Fall back to team_id-based name
    format!("vendor-{}", team_id.to_lowercase())
}

/// Summary of a baseline write: how the scan merged with what was already there.
struct BaselineMergeSummary {
    added: usize,
    already_present: usize,
    conflicts: usize,
}

/// Write scanned apps to baseline.toml. If the file already exists, merge
/// with deny-wins; otherwise write fresh.
fn write_baseline(
    apps: &[ScannedApp],
    output: &Path,
    rule_type: ScanRuleType,
) -> Result<BaselineMergeSummary> {
    use crate::merge::{Strategy, merge};
    use crate::parser::{BaselineFile, parse_baseline_file};
    use std::collections::HashSet;

    let scanned_rules = apps_to_rules(apps, rule_type);

    let (existing_rules, existing_keys): (crate::models::RuleSet, HashSet<String>) =
        if output.exists() {
            let existing = parse_baseline_file(output)?;
            let keys: HashSet<String> = existing.iter().map(crate::models::Rule::key).collect();
            (existing, keys)
        } else {
            (crate::models::RuleSet::new(), HashSet::new())
        };

    let scanned_keys: HashSet<String> =
        scanned_rules.iter().map(crate::models::Rule::key).collect();
    let already_present = scanned_keys.intersection(&existing_keys).count();
    let added = scanned_keys.difference(&existing_keys).count();

    let merged = merge(&[existing_rules, scanned_rules], Strategy::DenyWins)?;
    let conflicts = merged
        .conflicts
        .iter()
        .filter(|c| crate::cli::rings_output::has_policy_disagreement(c))
        .count();

    let mut rules: Vec<crate::models::Rule> = merged.rules.iter().cloned().collect();
    rules.sort_by_key(|r| r.key());

    let file = BaselineFile { version: 1, rules };
    let toml = toml::to_string_pretty(&file).context("Failed to serialize baseline TOML")?;
    std::fs::write(output, toml)
        .with_context(|| format!("Failed to write baseline to {}", output.display()))?;

    Ok(BaselineMergeSummary {
        added,
        already_present,
        conflicts,
    })
}

/// Write scanned apps to rules.yaml format (direct Santa rules).
fn write_rules(apps: &[ScannedApp], output: &Path, rule_type: ScanRuleType) -> Result<()> {
    let rules = apps_to_rules(apps, rule_type);

    // Serialize to YAML
    let yaml = yaml_serde::to_string(rules.rules())?;
    std::fs::write(output, yaml)
        .with_context(|| format!("Failed to write rules to {}", output.display()))?;

    Ok(())
}

/// Write scanned apps as a `com.apple.configuration.app.settings` declaration.
///
/// A scan is an inventory, so every app is emitted as an **allow** entry
/// (`Allowed.AllowedBinaries`) by its code-signing identifier. Use the standalone
/// `santa app-settings` command (with `--from-rules` or `--policy`) for deny
/// entries and privacy defaults. Invalid identifiers (per the schema's allow
/// rules) are dropped with a count.
fn write_app_settings(
    apps: &[ScannedApp],
    output: &Path,
    org: &str,
    rule_type: ScanRuleType,
    json_output: bool,
) -> Result<()> {
    use crate::app_settings::{AppSettings, BinaryPolicy, map, partition_binaries};

    let entries: Vec<_> = apps
        .iter()
        .filter_map(|a| map::from_scanned_app(a, rule_type, BinaryPolicy::Allow))
        .collect();
    let (valid, violations) = partition_binaries(entries);

    if !violations.is_empty() && !json_output {
        print_info(&format!(
            "Dropped {} app(s) with no schema-valid allow identifier (need CDHash or TeamID)",
            violations.len()
        ));
    }

    let settings = AppSettings {
        binaries: valid,
        ..Default::default()
    };
    let declaration = settings.to_declaration(org, "scan");
    let json = serde_json::to_string_pretty(&declaration)?;
    std::fs::write(output, json)
        .with_context(|| format!("Failed to write app.settings to {}", output.display()))?;

    Ok(())
}

/// Write scanned apps to mobileconfig format (ready for MDM deployment).
fn write_mobileconfig(
    apps: &[ScannedApp],
    output: &Path,
    org: &str,
    rule_type: ScanRuleType,
) -> Result<()> {
    let rules = apps_to_rules(apps, rule_type);

    let options = GeneratorOptions::new(org)
        .with_identifier(&format!("{}.santa.scan-rules", org))
        .with_display_name("Santa Rules (Scanned)")
        .with_description("Santa binary authorization rules generated from local application scan")
        .with_deterministic_uuids(true);

    generator::write_to_file(&rules, &options, output)?;

    Ok(())
}

/// Convert scanned apps to Santa rules based on the selected rule type.
fn apps_to_rules(apps: &[ScannedApp], rule_type: ScanRuleType) -> RuleSet {
    let mut rules = RuleSet::new();

    match rule_type {
        ScanRuleType::TeamId => {
            // Group by TeamID to create vendor-level rules
            let mut seen_team_ids: HashMap<String, &ScannedApp> = HashMap::new();
            for app in apps {
                if let Some(team_id) = &app.team_id {
                    seen_team_ids.entry(team_id.clone()).or_insert(app);
                }
            }

            // Create sorted rules for deterministic output
            let mut team_ids: Vec<_> = seen_team_ids.keys().cloned().collect();
            team_ids.sort();

            for team_id in team_ids {
                let app = seen_team_ids[&team_id];
                let rule = Rule::new(RuleType::TeamId, &team_id, Policy::Allowlist)
                    .with_description(&app.name);
                rules.add(rule);
            }
        }
        ScanRuleType::SigningId => {
            // Create one rule per unique SigningID
            let mut seen_signing_ids: HashMap<String, &ScannedApp> = HashMap::new();
            for app in apps {
                if let Some(signing_id) = &app.signing_id {
                    seen_signing_ids.entry(signing_id.clone()).or_insert(app);
                }
            }

            // Create sorted rules for deterministic output
            let mut signing_ids: Vec<_> = seen_signing_ids.keys().cloned().collect();
            signing_ids.sort();

            for signing_id in signing_ids {
                let app = seen_signing_ids[&signing_id];
                let rule = Rule::new(RuleType::SigningId, &signing_id, Policy::Allowlist)
                    .with_description(&app.name);
                rules.add(rule);
            }
        }
        ScanRuleType::Cdhash => {
            // One rule per unique, valid CDHash (40 hex chars).
            let mut seen_cdhashes: HashMap<String, &ScannedApp> = HashMap::new();
            for app in apps {
                if let Some(cdhash) = &app.cdhash {
                    if crate::cel::is_valid_cdhash(cdhash) {
                        seen_cdhashes.entry(cdhash.clone()).or_insert(app);
                    }
                }
            }
            let mut cdhashes: Vec<_> = seen_cdhashes.keys().cloned().collect();
            cdhashes.sort();
            for cdhash in cdhashes {
                let app = seen_cdhashes[&cdhash];
                let rule = Rule::new(RuleType::Cdhash, &cdhash, Policy::Allowlist)
                    .with_description(&app.name);
                rules.add(rule);
            }
        }
        ScanRuleType::Auto => {
            // Per-row: prefer SigningID when present, else synthesize from
            // team_id + bundle_id, else fall back to TeamID-only.
            let mut seen_signing: HashMap<String, &ScannedApp> = HashMap::new();
            let mut seen_team: HashMap<String, &ScannedApp> = HashMap::new();
            for app in apps {
                let signing_id = app.signing_id.clone().or_else(|| {
                    let team = app.team_id.as_deref()?;
                    let bundle = app.bundle_id.as_deref()?;
                    let candidate = format!("{team}:{bundle}");
                    crate::cel::is_valid_signing_id(&candidate).then_some(candidate)
                });
                if let Some(sid) = signing_id {
                    seen_signing.entry(sid).or_insert(app);
                    continue;
                }
                if let Some(team_id) = &app.team_id {
                    if crate::cel::is_valid_team_id(team_id) {
                        seen_team.entry(team_id.clone()).or_insert(app);
                    }
                }
            }

            let mut signing_ids: Vec<_> = seen_signing.keys().cloned().collect();
            signing_ids.sort();
            for sid in signing_ids {
                let app = seen_signing[&sid];
                let rule = Rule::new(RuleType::SigningId, &sid, Policy::Allowlist)
                    .with_description(&app.name);
                rules.add(rule);
            }

            let mut team_ids: Vec<_> = seen_team.keys().cloned().collect();
            team_ids.sort();
            for tid in team_ids {
                let app = seen_team[&tid];
                let rule = Rule::new(RuleType::TeamId, &tid, Policy::Allowlist)
                    .with_description(&app.name);
                rules.add(rule);
            }
        }
    }

    rules
}

/// Merge multiple scan CSVs into one (for aggregating from multiple machines).
/// Read scanned apps from one or more scan CSV files, deduplicated by
/// `signing_id`/`sha256`/`name`. The CSV has no `cdhash` column, so `cdhash`
/// is always `None` on the result (re-scan locally for CDHash identifiers).
pub fn read_scan_csvs(inputs: &[PathBuf]) -> Result<Vec<ScannedApp>> {
    let mut all_apps: HashMap<String, ScannedApp> = HashMap::new();

    for input in inputs {
        let mut rdr = csv::Reader::from_path(input)
            .with_context(|| format!("opening scan CSV {}", input.display()))?;

        for result in rdr.deserialize() {
            let record: HashMap<String, String> = result?;

            // Deduplicate by signing_id, then sha256, then name.
            let key = record
                .get("signing_id")
                .filter(|s| !s.is_empty())
                .or_else(|| record.get("sha256"))
                .cloned()
                .unwrap_or_else(|| record.get("name").cloned().unwrap_or_default());

            if let std::collections::hash_map::Entry::Vacant(e) = all_apps.entry(key) {
                e.insert(ScannedApp {
                    name: record.get("name").cloned().unwrap_or_default(),
                    path: record.get("path").cloned().unwrap_or_default(),
                    version: record.get("version").cloned().filter(|s| !s.is_empty()),
                    team_id: record.get("team_id").cloned().filter(|s| !s.is_empty()),
                    signing_id: record.get("signing_id").cloned().filter(|s| !s.is_empty()),
                    sha256: record.get("sha256").cloned().filter(|s| !s.is_empty()),
                    cdhash: None,
                    bundle_id: record.get("bundle_id").cloned().filter(|s| !s.is_empty()),
                });
            }
        }
    }

    Ok(all_apps.into_values().collect())
}

pub fn merge_scans(inputs: &[PathBuf], output: &Path) -> Result<()> {
    // Collect device names for the merged CSV header.
    let mut device_names: Vec<String> = Vec::new();
    for input in inputs {
        let mut rdr = csv::Reader::from_path(input)?;
        for result in rdr.deserialize() {
            let record: HashMap<String, String> = result?;
            if let Some(device) = record.get("device_name") {
                if !device.is_empty() && !device_names.contains(device) {
                    device_names.push(device.clone());
                }
            }
        }
    }

    let apps = read_scan_csvs(inputs)?;
    let device_str = device_names.join(",");
    write_csv(&apps, output, &device_str)?;

    Ok(())
}
