//! PPPC scan command — GitOps workflow step 1.
//!
//! Scans for applications, extracts code requirements, and writes a pppc.toml file.

use crate::cli::{OutputMode, print_error, print_info, print_kv, print_success, print_warning};
use crate::codesign::{find_main_executable, get_app_name, get_bundle_id, get_code_requirement};
use crate::pppc::{AppInfo, PppcAppEntry, PppcConfig, PppcConfigMeta, PppcService};
use anyhow::{Context, Result};
use colored::Colorize;
use inquire::MultiSelect;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// Categorized reason for skipping an app during scan.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SkipReason {
    /// Empty or stub .app directory (no Contents/ directory)
    EmptyBundle,
    /// Has Contents/ but missing Info.plist
    MissingInfoPlist,
    /// App is not code-signed
    Unsigned,
    /// No executable found in the bundle
    NoExecutable,
    /// Other extraction error
    Other(String),
}

impl SkipReason {
    fn label(&self) -> &str {
        match self {
            SkipReason::EmptyBundle => "Empty/stub bundle (no Contents directory)",
            SkipReason::MissingInfoPlist => "Missing Info.plist",
            SkipReason::Unsigned => "Not code-signed",
            SkipReason::NoExecutable => "No executable found",
            SkipReason::Other(_) => "Other error",
        }
    }
}

/// Diagnose why an app bundle can't be scanned and return a categorized reason.
fn diagnose_app_bundle(app_path: &Path) -> SkipReason {
    let contents = app_path.join("Contents");
    if !contents.exists() || !contents.is_dir() {
        return SkipReason::EmptyBundle;
    }

    let info_plist = contents.join("Info.plist");
    if !info_plist.exists() {
        return SkipReason::MissingInfoPlist;
    }

    let macos = contents.join("MacOS");
    if !macos.exists() || !macos.is_dir() {
        return SkipReason::NoExecutable;
    }

    // If we got here, the structure looks OK — the error was likely from codesign
    SkipReason::Other("unknown".to_string())
}

/// Classify a scan error into a SkipReason by inspecting both the app bundle structure
/// and the error message from the extraction attempt.
fn classify_scan_error(app_path: &Path, error: &anyhow::Error) -> SkipReason {
    let structural = diagnose_app_bundle(app_path);
    if structural != SkipReason::Other("unknown".to_string()) {
        return structural;
    }

    // Fall back to error message heuristics
    let msg = format!("{error:#}");
    if msg.contains("not signed") {
        SkipReason::Unsigned
    } else if msg.contains("No executable") {
        SkipReason::NoExecutable
    } else if msg.contains("Info.plist") {
        SkipReason::MissingInfoPlist
    } else {
        SkipReason::Other(msg)
    }
}

/// Deduplicate apps by bundle_id, keeping the first occurrence.
///
/// This handles cases like Adobe CC frameworks where the recursive scan
/// follows both `Versions/A/` and `Versions/Current/` symlinks, producing
/// duplicate entries with the same bundle_id.
pub fn deduplicate_apps(apps: Vec<AppInfo>, output_mode: OutputMode) -> Vec<AppInfo> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::with_capacity(apps.len());
    let mut dup_count = 0usize;

    for app in apps {
        if seen.insert(app.bundle_id.clone()) {
            deduped.push(app);
        } else {
            dup_count += 1;
            if output_mode == OutputMode::Human {
                // Only print at debug level — summarize below
            }
        }
    }

    if dup_count > 0 && output_mode == OutputMode::Human {
        print_warning(&format!(
            "Deduplicated {dup_count} app(s) with the same bundle ID (kept first occurrence)"
        ));
    }

    deduped
}

/// Print a grouped summary of skipped apps.
fn print_skipped_summary(skipped: &BTreeMap<SkipReason, Vec<String>>) {
    let total: usize = skipped.values().map(std::vec::Vec::len).sum();
    println!();
    print_warning(&format!("Skipped {total} app(s):"));

    for (reason, apps) in skipped {
        println!(
            "  {} {} ({})",
            "▸".dimmed(),
            reason.label().yellow(),
            apps.len()
        );
        for app in apps {
            println!("    {} {}", "·".dimmed(), app.dimmed());
        }
    }
}

/// Run the scan subcommand.
///
/// Scans for applications, extracts code requirements, and writes a pppc.toml file.
/// Can scan directories or read app paths from a CSV file.
pub fn run(
    paths: &[PathBuf],
    from_csv: Option<&Path>,
    output: &Path,
    org: &str,
    interactive: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        print_info("Scanning applications for PPPC policy generation...");
        print_kv("Organization", org);
    }

    // Find all .app bundles (either from paths or CSV)
    let apps_to_scan: Vec<PathBuf> = if let Some(csv_path) = from_csv {
        if output_mode == OutputMode::Human {
            print_kv("Reading apps from", &csv_path.display().to_string());
        }
        read_apps_from_csv(csv_path, output_mode)?
    } else {
        if output_mode == OutputMode::Human {
            print_kv(
                "Paths",
                &paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }

        let mut apps = Vec::new();
        for path in paths {
            if !path.exists() {
                if output_mode == OutputMode::Human {
                    print_warning(&format!("Skipping non-existent path: {}", path.display()));
                }
                continue;
            }

            if path.extension().is_some_and(|e| e == "app") {
                apps.push(path.clone());
            } else {
                find_apps_recursive(path, &mut apps)?;
            }
        }
        apps
    };

    if apps_to_scan.is_empty() {
        if output_mode == OutputMode::Human {
            print_error("No applications found to scan");
        }
        anyhow::bail!("No applications found");
    }

    if output_mode == OutputMode::Human {
        print_kv("Apps found", &apps_to_scan.len().to_string());
    }

    // Extract app info from each bundle
    let mut apps_info: Vec<AppInfo> = Vec::new();
    let mut skipped: BTreeMap<SkipReason, Vec<String>> = BTreeMap::new();

    for app_path in &apps_to_scan {
        match extract_app_info(app_path) {
            Ok(info) => apps_info.push(info),
            Err(e) => {
                let reason = classify_scan_error(app_path, &e);
                let app_name = app_path.file_stem().map_or_else(
                    || app_path.display().to_string(),
                    |s| s.to_string_lossy().to_string(),
                );
                skipped.entry(reason).or_default().push(app_name);
            }
        }
    }

    if apps_info.is_empty() {
        if output_mode == OutputMode::Human {
            print_error("No signed applications found");
        }
        anyhow::bail!("No signed applications found");
    }

    if output_mode == OutputMode::Human && !skipped.is_empty() {
        print_skipped_summary(&skipped);
    }

    // Deduplicate by bundle_id (e.g., Adobe CC symlinks)
    let apps_info = deduplicate_apps(apps_info, output_mode);

    // Build entries (with or without interactive service selection)
    let entries: Vec<PppcAppEntry> = if interactive {
        interactive_scan_selection(&apps_info)?
    } else {
        // Non-interactive: include all apps with no services (user edits TOML)
        apps_info.iter().map(PppcAppEntry::from).collect()
    };

    if entries.is_empty() {
        if output_mode == OutputMode::Human {
            print_info("No applications selected");
        }
        return Ok(());
    }

    // Build config
    let config = PppcConfig {
        config: PppcConfigMeta {
            org: org.to_string(),
            display_name: None,
        },
        apps: entries,
    };

    // Write to file
    config.save(output)?;

    if output_mode == OutputMode::Human {
        println!();
        print_success(&format!("PPPC policy written to {}", output.display()));
        println!();
        print_info("Next steps:");
        println!(
            "  1. Edit {} to configure services per app",
            output.display()
        );
        println!(
            "  2. Run: contour pppc generate {} --output pppc.mobileconfig",
            output.display()
        );
    }

    Ok(())
}

/// Read app paths from a CSV file.
///
/// Expected CSV format (header optional):
/// ```csv
/// name,path
/// "osquery","/opt/osquery/osquery.app"
/// "Zoom","/Applications/zoom.us.app"
/// ```
///
/// Or just paths:
/// ```csv
/// path
/// /opt/osquery/osquery.app
/// /Applications/zoom.us.app
/// ```
pub fn read_apps_from_csv(csv_path: &Path, output_mode: OutputMode) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(csv_path)
        .with_context(|| format!("Failed to open CSV file: {}", csv_path.display()))?;

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(file);

    let headers = reader
        .headers()
        .with_context(|| "Failed to read CSV headers")?
        .clone();

    // Find the path column (could be "path", "app_path", or index 0/1)
    let path_idx = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("path") || h.eq_ignore_ascii_case("app_path"))
        .or_else(|| {
            // If no path column, check if first column looks like a path
            if headers.len() == 1
                || headers.get(0).is_some_and(|h| {
                    h.starts_with('/')
                        || std::path::Path::new(h)
                            .extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
                })
            {
                Some(0)
            } else if headers.len() >= 2 {
                // Try second column
                Some(1)
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("CSV must have a 'path' column or contain app paths"))?;

    let mut apps = Vec::new();
    let mut missing_count = 0;

    for result in reader.records() {
        let record = result.with_context(|| "Failed to read CSV record")?;

        if let Some(path_str) = record.get(path_idx) {
            let path_str = path_str.trim();
            if path_str.is_empty() {
                continue;
            }

            let path = PathBuf::from(path_str);
            if path.exists() {
                // Validate it's an app bundle
                if path.extension().is_some_and(|e| e == "app") {
                    apps.push(path);
                } else if output_mode == OutputMode::Human {
                    print_warning(&format!("Not an app bundle: {}", path.display()));
                }
            } else {
                missing_count += 1;
                if output_mode == OutputMode::Human {
                    print_warning(&format!("App not found: {path_str}"));
                }
            }
        }
    }

    if missing_count > 0 && output_mode == OutputMode::Human {
        print_kv("Apps not found", &missing_count.to_string());
    }

    Ok(apps)
}

/// Find all .app bundles recursively in a directory.
///
/// Delegates to `contour_core::find_apps_recursive`.
pub fn find_apps_recursive(path: &Path, apps: &mut Vec<PathBuf>) -> Result<()> {
    contour_core::find_apps_recursive(path, apps)
}

/// Extract application info (name, bundle ID, code requirement) from an app bundle.
pub fn extract_app_info(app_path: &Path) -> Result<AppInfo> {
    let name = get_app_name(app_path);
    let bundle_id = get_bundle_id(app_path)?;

    // Get code requirement from the main executable
    let executable = find_main_executable(app_path)?;
    let code_requirement = get_code_requirement(&executable)?;

    Ok(AppInfo {
        name,
        bundle_id,
        code_requirement,
        identifier_type: "bundleID".to_string(),
        path: app_path.to_path_buf(),
    })
}

/// Interactive selection for scan mode.
///
/// Allows selecting apps and optionally services for each app.
fn interactive_scan_selection(apps: &[AppInfo]) -> Result<Vec<PppcAppEntry>> {
    println!();
    println!("{}", "PPPC Scan - Application Selection".bold().cyan());
    println!("{}", "=".repeat(50));
    println!();
    println!("Select which applications to include in your PPPC policy.");
    println!("You can configure services now or edit the TOML file later.");
    println!();

    // Step 1: Select apps
    let app_options: Vec<String> = apps
        .iter()
        .map(|a| format!("{} ({})", a.name, a.bundle_id))
        .collect();

    let selected_apps = MultiSelect::new("Select applications to include:", app_options.clone())
        .with_page_size(15)
        .with_help_message("Space to select, Enter to confirm")
        .prompt()?;

    if selected_apps.is_empty() {
        return Ok(Vec::new());
    }

    // Build list of selected AppInfo
    let selected_app_infos: Vec<&AppInfo> = selected_apps
        .iter()
        .filter_map(|selection| {
            apps.iter().find(|a| {
                app_options
                    .iter()
                    .any(|opt| opt == selection && opt.contains(&a.bundle_id))
            })
        })
        .collect();

    // Deduplicate
    let mut seen_bundle_ids = std::collections::HashSet::new();
    let selected_app_infos: Vec<&AppInfo> = selected_app_infos
        .into_iter()
        .filter(|a| seen_bundle_ids.insert(&a.bundle_id))
        .collect();

    // Ask if user wants to configure services now
    println!();
    let configure_now = inquire::Confirm::new("Configure services for each app now?")
        .with_default(true)
        .with_help_message("No = save with empty services, edit TOML later")
        .prompt()?;

    if !configure_now {
        return Ok(selected_app_infos
            .iter()
            .map(|a| PppcAppEntry::from(*a))
            .collect());
    }

    // Step 2: For each selected app, choose services
    let all_services = PppcService::all();
    let mut service_options: Vec<String> = Vec::with_capacity(all_services.len() + 1);
    service_options.push(super::ALL_SERVICES_LABEL.to_string());
    service_options.extend(all_services.iter().map(|s| s.display_name().to_string()));

    let mut entries = Vec::new();

    for app in selected_app_infos {
        println!();
        println!("{} {}", "Configuring:".bold(), app.name.cyan());
        println!("  Bundle ID: {}", app.bundle_id.dimmed());

        let selected_services = MultiSelect::new(
            &format!("Select permissions for {}:", app.name),
            service_options.clone(),
        )
        .with_page_size(10)
        .with_help_message("Space to toggle, Enter to confirm (first item selects all)")
        .prompt()?;

        // Map selected service names back to PppcService
        let services: Vec<PppcService> = if selected_services
            .iter()
            .any(|name| name == super::ALL_SERVICES_LABEL)
        {
            all_services.to_vec()
        } else {
            selected_services
                .iter()
                .filter_map(|name| {
                    all_services
                        .iter()
                        .find(|s| s.display_name() == name)
                        .copied()
                })
                .collect()
        };

        if services.is_empty() {
            println!(
                "  {} No permissions selected (can edit later)",
                "→".dimmed()
            );
        } else {
            println!(
                "  {} Selected {} permission(s)",
                "✓".green(),
                services.len()
            );
        }

        let mut entry = PppcAppEntry::from(app);
        entry.services = services;
        entries.push(entry);
    }

    Ok(entries)
}

/// Run the one-shot mode (no subcommand).
pub fn run_oneshot(
    paths: &[PathBuf],
    output: Option<&Path>,
    org: &str,
    interactive: bool,
    services: Option<Vec<PppcService>>,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    use crate::pppc::{PppcPolicy, generate_pppc_profile};

    if output_mode == OutputMode::Human {
        print_info("Scanning applications for PPPC profile generation...");
        print_kv("Organization", org);
        print_kv(
            "Paths",
            &paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    // Find all .app bundles
    let mut apps_to_scan: Vec<PathBuf> = Vec::new();
    for path in paths {
        if !path.exists() {
            if output_mode == OutputMode::Human {
                print_warning(&format!("Skipping non-existent path: {}", path.display()));
            }
            continue;
        }

        // Check if path is a single .app or a directory to scan
        if path.extension().is_some_and(|e| e == "app") {
            apps_to_scan.push(path.clone());
        } else {
            find_apps_recursive(path, &mut apps_to_scan)?;
        }
    }

    if apps_to_scan.is_empty() {
        if output_mode == OutputMode::Human {
            print_error("No applications found to scan");
        }
        anyhow::bail!("No applications found");
    }

    if output_mode == OutputMode::Human {
        print_kv("Apps found", &apps_to_scan.len().to_string());
    }

    // Extract app info from each bundle
    let mut apps_info: Vec<AppInfo> = Vec::new();
    let mut skipped: BTreeMap<SkipReason, Vec<String>> = BTreeMap::new();

    for app_path in &apps_to_scan {
        match extract_app_info(app_path) {
            Ok(info) => apps_info.push(info),
            Err(e) => {
                let reason = classify_scan_error(app_path, &e);
                let app_name = app_path.file_stem().map_or_else(
                    || app_path.display().to_string(),
                    |s| s.to_string_lossy().to_string(),
                );
                skipped.entry(reason).or_default().push(app_name);
            }
        }
    }

    if apps_info.is_empty() {
        if output_mode == OutputMode::Human {
            print_error("No signed applications found");
        }
        anyhow::bail!("No signed applications found");
    }

    if output_mode == OutputMode::Human && !skipped.is_empty() {
        print_skipped_summary(&skipped);
    }

    // Deduplicate by bundle_id (e.g., Adobe CC symlinks)
    let apps_info = deduplicate_apps(apps_info, output_mode);

    // Build policies
    let policies = if interactive {
        interactive_selection(&apps_info)?
    } else {
        // Non-interactive: apply specified services to all apps
        let services_to_apply = services.unwrap_or_else(|| vec![PppcService::SystemPolicyAllFiles]);
        apps_info
            .into_iter()
            .map(|app| PppcPolicy {
                app,
                services: services_to_apply.clone(),
            })
            .collect()
    };

    if policies.is_empty() {
        if output_mode == OutputMode::Human {
            print_info("No policies to generate");
        }
        return Ok(());
    }

    // Generate or preview profile
    if dry_run {
        print_policies(&policies, output_mode);
    } else {
        let output_path = output.map_or_else(
            || PathBuf::from("pppc.mobileconfig"),
            std::path::Path::to_path_buf,
        );

        let content = generate_pppc_profile(&policies, org, None, None)?;
        std::fs::write(&output_path, &content)
            .with_context(|| format!("Failed to write profile to {}", output_path.display()))?;

        if output_mode == OutputMode::Human {
            println!();
            print_success(&format!(
                "PPPC profile written to {}",
                output_path.display()
            ));
            println!();
            print_info("Profile summary:");
            print_kv("Apps configured", &policies.len().to_string());

            // Count services
            let mut service_counts: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for policy in &policies {
                for service in &policy.services {
                    *service_counts.entry(service.key()).or_default() += 1;
                }
            }
            for (service, count) in &service_counts {
                print_kv(&format!("  {service}"), &count.to_string());
            }

            println!();
            print_info("Next steps:");
            println!("  1. Validate: plutil -lint {}", output_path.display());
            println!("  2. Deploy via MDM to grant permissions automatically");
        }
    }

    Ok(())
}

/// Interactive app and service selection.
fn interactive_selection(apps: &[AppInfo]) -> Result<Vec<crate::pppc::PppcPolicy>> {
    println!();
    println!("{}", "PPPC Profile Builder".bold().cyan());
    println!("{}", "=".repeat(50));
    println!();
    println!("This wizard helps you create a Privacy Preferences Policy Control (PPPC)");
    println!("profile to grant macOS privacy permissions to applications via MDM.");
    println!();

    // Step 1: Select apps
    let app_options: Vec<String> = apps
        .iter()
        .map(|a| format!("{} ({})", a.name, a.bundle_id))
        .collect();

    let selected_apps = MultiSelect::new("Select applications to configure:", app_options.clone())
        .with_page_size(15)
        .with_help_message("Space to select, Enter to confirm")
        .prompt()?;

    if selected_apps.is_empty() {
        return Ok(Vec::new());
    }

    // Build list of selected AppInfo
    let selected_app_infos: Vec<&AppInfo> = selected_apps
        .iter()
        .filter_map(|selection| {
            apps.iter().find(|a| {
                app_options
                    .iter()
                    .any(|opt| opt == selection && opt.contains(&a.bundle_id))
            })
        })
        .collect();

    // Deduplicate
    let mut seen_bundle_ids = std::collections::HashSet::new();
    let selected_app_infos: Vec<&AppInfo> = selected_app_infos
        .into_iter()
        .filter(|a| seen_bundle_ids.insert(&a.bundle_id))
        .collect();

    // Step 2: For each selected app, choose services
    let all_services = PppcService::all();
    let mut service_options: Vec<String> = Vec::with_capacity(all_services.len() + 1);
    service_options.push(super::ALL_SERVICES_LABEL.to_string());
    service_options.extend(all_services.iter().map(|s| s.display_name().to_string()));

    let mut policies = Vec::new();

    for app in selected_app_infos {
        println!();
        println!("{} {}", "Configuring:".bold(), app.name.cyan());
        println!("  Bundle ID: {}", app.bundle_id.dimmed());

        let selected_services = MultiSelect::new(
            &format!("Select permissions for {}:", app.name),
            service_options.clone(),
        )
        .with_page_size(10)
        .with_help_message("Space to toggle, Enter to confirm (first item selects all)")
        .prompt()?;

        if selected_services.is_empty() {
            println!("  {} No permissions selected, skipping", "→".dimmed());
            continue;
        }

        // Map selected service names back to PppcService
        let services: Vec<PppcService> = if selected_services
            .iter()
            .any(|name| name == super::ALL_SERVICES_LABEL)
        {
            all_services.to_vec()
        } else {
            selected_services
                .iter()
                .filter_map(|name| {
                    all_services
                        .iter()
                        .find(|s| s.display_name() == name)
                        .copied()
                })
                .collect()
        };

        println!(
            "  {} Selected {} permission(s)",
            "✓".green(),
            services.len()
        );

        policies.push(crate::pppc::PppcPolicy {
            app: app.clone(),
            services,
        });
    }

    Ok(policies)
}

/// Print policies for dry-run preview.
fn print_policies(policies: &[crate::pppc::PppcPolicy], output_mode: OutputMode) {
    if output_mode == OutputMode::Json {
        // JSON output
        let json_policies: Vec<_> = policies
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.app.name,
                    "bundle_id": p.app.bundle_id,
                    "code_requirement": p.app.code_requirement,
                    "path": p.app.path.display().to_string(),
                    "services": p.services.iter().map(super::super::pppc::PppcService::key).collect::<Vec<_>>(),
                })
            })
            .collect();

        if let Ok(json) = serde_json::to_string_pretty(&json_policies) {
            println!("{json}");
        }
        return;
    }

    println!();
    println!("{}", "Dry Run - PPPC Profile Preview".bold());
    println!("{}", "=".repeat(50));
    println!();

    for policy in policies {
        println!("{} {}", "App:".bold(), policy.app.name.cyan());
        println!("  Bundle ID: {}", policy.app.bundle_id);
        println!("  Path: {}", policy.app.path.display());
        println!(
            "  Code Requirement: {}",
            truncate_string(&policy.app.code_requirement, 60).dimmed()
        );
        println!("  Services:");
        for service in &policy.services {
            println!(
                "    {} {} ({})",
                "•".green(),
                service.display_name(),
                service.key()
            );
        }
        println!();
    }

    println!("{}", "-".repeat(50));
    println!("Total apps: {}", policies.len());

    let total_entries: usize = policies.iter().map(|p| p.services.len()).sum();
    println!("Total TCC entries: {total_entries}");
}

/// Truncate a string to a maximum length with ellipsis.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("short", 10), "short");
        assert_eq!(truncate_string("this is a long string", 10), "this is...");
    }

    #[test]
    fn test_diagnose_empty_bundle() {
        let tmp = TempDir::new().unwrap();
        let app = tmp.path().join("Dummy.app");
        fs::create_dir(&app).unwrap();

        assert_eq!(diagnose_app_bundle(&app), SkipReason::EmptyBundle);
    }

    #[test]
    fn test_diagnose_missing_info_plist() {
        let tmp = TempDir::new().unwrap();
        let app = tmp.path().join("Broken.app");
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();

        assert_eq!(diagnose_app_bundle(&app), SkipReason::MissingInfoPlist);
    }

    #[test]
    fn test_diagnose_no_executable() {
        let tmp = TempDir::new().unwrap();
        let app = tmp.path().join("NoExec.app");
        let contents = app.join("Contents");
        fs::create_dir_all(&contents).unwrap();
        fs::write(contents.join("Info.plist"), "<plist></plist>").unwrap();
        // No MacOS directory

        assert_eq!(diagnose_app_bundle(&app), SkipReason::NoExecutable);
    }

    #[test]
    fn test_classify_unsigned_error() {
        let tmp = TempDir::new().unwrap();
        let app = tmp.path().join("Unsigned.app");
        let contents = app.join("Contents");
        fs::create_dir_all(contents.join("MacOS")).unwrap();
        fs::write(contents.join("Info.plist"), "<plist></plist>").unwrap();

        let err = anyhow::anyhow!("Application is not signed");
        assert_eq!(classify_scan_error(&app, &err), SkipReason::Unsigned);
    }

    #[test]
    fn test_skip_reason_label() {
        assert_eq!(
            SkipReason::EmptyBundle.label(),
            "Empty/stub bundle (no Contents directory)"
        );
        assert_eq!(SkipReason::Unsigned.label(), "Not code-signed");
    }
}
