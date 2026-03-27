use crate::cli::glob_utils::{BatchResult, output_batch_json, print_batch_summary};
use crate::config::ProfileConfig;
use crate::config::renaming::ProfileRenamer;
use crate::output::OutputMode;
use crate::profile::{normalizer, parser, validator};
use crate::signing;
use crate::uuid::{self, UuidConfig};
use anyhow::Result;
use colored::Colorize;
use inquire::{Confirm, MultiSelect, Select};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ── Data structures ──────────────────────────────────────────────────

struct DiscoveredProfile {
    path: PathBuf,
    display_name: String,
    identifier: String,
    description: Option<String>,
    payload_types: Vec<String>,
    signed: bool,
    parse_error: Option<String>,
}

struct PayloadTypeGroup {
    payload_type: String,
    friendly_name: String,
    profiles: Vec<usize>, // indices into discovered vec
}

#[derive(Debug, Clone, Copy)]
enum SelectionMode {
    ByPayloadType,
    BrowseAll,
    ImportAll,
}

impl std::fmt::Display for SelectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectionMode::ByPayloadType => write!(
                f,
                "By payload type — Browse profiles grouped by configuration type (Recommended)"
            ),
            SelectionMode::BrowseAll => {
                write!(
                    f,
                    "Browse all — See every profile and cherry-pick individually"
                )
            }
            SelectionMode::ImportAll => {
                write!(f, "Import all — Import every parseable profile")
            }
        }
    }
}

// ── Main entry point ─────────────────────────────────────────────────

#[expect(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "CLI handler requires many parameters"
)]
pub fn handle_import(
    source: &str,
    output_dir: Option<&str>,
    org_domain: Option<&str>,
    org_name: Option<&str>,
    config: Option<&ProfileConfig>,
    validate: bool,
    regen_uuid: bool,
    max_depth: Option<usize>,
    dry_run: bool,
    import_all: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let source_path = Path::new(source);
    if !source_path.is_dir() {
        anyhow::bail!("Source must be a directory: {source}");
    }

    // Phase 1: Discovery
    let discovered = discover_profiles(source_path, max_depth)?;

    let parsed_count = discovered
        .iter()
        .filter(|p| p.parse_error.is_none())
        .count();
    let failed_count = discovered
        .iter()
        .filter(|p| p.parse_error.is_some())
        .count();
    let signed_count = discovered.iter().filter(|p| p.signed).count();

    // Collect unique payload types
    let mut unique_types = HashSet::new();
    for p in &discovered {
        if p.parse_error.is_none() {
            for pt in &p.payload_types {
                unique_types.insert(pt.clone());
            }
        }
    }

    if output_mode == OutputMode::Human {
        println!();
        println!("{}", "=".repeat(66));
        println!(
            "{}",
            "  Profile Import — Interactive Cherry-Picker".bold().cyan()
        );
        println!("{}", "=".repeat(66));
        println!();
        println!("Scanning: {}", source.cyan());
        println!();
        println!("{}", "Discovery:".bold());
        println!(
            "  {} .mobileconfig files found",
            discovered.len().to_string().green()
        );
        println!("  {} parsed successfully", parsed_count.to_string().green());
        if failed_count > 0 {
            println!(
                "  {} failed to parse (skipped):",
                failed_count.to_string().red()
            );
            for p in discovered.iter().filter(|p| p.parse_error.is_some()) {
                println!(
                    "    {} {} — {}",
                    "✗".red(),
                    p.path.display(),
                    p.parse_error.as_deref().unwrap_or("unknown error")
                );
            }
        }
        if signed_count > 0 {
            println!(
                "  {} are signed (will be auto-unsigned on import)",
                signed_count.to_string().yellow()
            );
        }
        println!(
            "  {} unique payload types detected",
            unique_types.len().to_string().cyan()
        );
        println!();
    }

    if parsed_count == 0 {
        if output_mode == OutputMode::Json {
            let result = serde_json::json!({
                "success": false,
                "total_found": discovered.len(),
                "parsed": 0,
                "failed": failed_count,
                "message": "No parseable profiles found"
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!("{}", "No parseable profiles found.".yellow());
        }
        return Ok(());
    }

    // JSON mode or --all: skip interactive selection
    let use_all = import_all || output_mode == OutputMode::Json;

    // Phase 2-3: Selection
    let selected_indices = if use_all {
        // --all or --json: select all parseable profiles without prompting
        discovered
            .iter()
            .enumerate()
            .filter(|(_, p)| p.parse_error.is_none())
            .map(|(i, _)| i)
            .collect()
    } else {
        // Interactive selection
        let groups = build_payload_type_groups(&discovered);

        let mode = Select::new(
            "How would you like to select profiles to import?",
            vec![
                SelectionMode::ByPayloadType,
                SelectionMode::BrowseAll,
                SelectionMode::ImportAll,
            ],
        )
        .with_help_message("Use arrow keys to navigate, Enter to select")
        .prompt()?;

        match mode {
            SelectionMode::ByPayloadType => select_by_payload_type(&discovered, &groups)?,
            SelectionMode::BrowseAll => select_browse_all(&discovered)?,
            SelectionMode::ImportAll => {
                let indices: Vec<usize> = discovered
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.parse_error.is_none())
                    .map(|(i, _)| i)
                    .collect();

                let confirm =
                    Confirm::new(&format!("Import all {} parseable profiles?", indices.len()))
                        .with_default(true)
                        .prompt()?;

                if !confirm {
                    println!("{}", "Import cancelled.".yellow());
                    return Ok(());
                }

                indices
            }
        }
    };

    if selected_indices.is_empty() {
        if output_mode == OutputMode::Human {
            println!("{}", "No profiles selected. Nothing to import.".yellow());
        }
        return Ok(());
    }

    // Resolve output directory
    let effective_output = output_dir.unwrap_or("./imported");

    // Resolve org domain: CLI --org → profile.toml → .contour/config.toml
    let contour_domain;
    let effective_org = if org_domain.is_some() {
        org_domain
    } else if let Some(cfg) = config {
        Some(cfg.organization.domain.as_str())
    } else if let Some(cfg) = contour_core::config::ContourConfig::load_nearest() {
        contour_domain = cfg.organization.domain;
        Some(contour_domain.as_str())
    } else {
        None
    };

    // Resolve org name
    let effective_org_name = org_name
        .map(String::from)
        .or_else(|| config.map(super::super::config::ProfileConfig::org_name))
        .or_else(|| {
            contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.name)
        });

    // Phase 4: Preview
    if output_mode == OutputMode::Human {
        println!();
        println!("{}", "Import Preview".bold());
        println!("{}", "-".repeat(50));
        println!(
            "  Profiles to import:  {}",
            selected_indices.len().to_string().green()
        );
        println!("  Output directory:    {}", effective_output);
        if let Some(org) = effective_org {
            println!("  Organization:        {}", org);
        }
        if let Some(name) = effective_org_name.as_deref() {
            println!("  Organization name:   {}", name);
        }
        println!();
        println!("  Pipeline (per profile):");
        println!("    1. Auto-unsign (if signed)");
        if effective_org.is_some() {
            println!("    2. Normalize identifiers");
        }
        if regen_uuid {
            println!("    3. Regenerate UUIDs");
        }
        if validate {
            println!("    4. Validate structure");
        }
        println!();
    }

    if dry_run {
        if output_mode == OutputMode::Human {
            println!("{}", "Dry run — no files will be written.".yellow());
            println!();
            for &idx in &selected_indices {
                let p = &discovered[idx];
                let filename = p.path.file_name().unwrap_or_default().to_string_lossy();
                println!(
                    "  Would import: {} → {}/{}",
                    p.path.display(),
                    effective_output,
                    filename
                );
            }
        } else {
            let items: Vec<_> = selected_indices
                .iter()
                .map(|&idx| {
                    let p = &discovered[idx];
                    let filename = p.path.file_name().unwrap_or_default().to_string_lossy();
                    serde_json::json!({
                        "source": p.path.to_string_lossy(),
                        "output": format!("{}/{}", effective_output, filename),
                        "display_name": p.display_name,
                        "identifier": p.identifier,
                        "signed": p.signed,
                        "payload_types": p.payload_types,
                    })
                })
                .collect();
            let result = serde_json::json!({
                "dry_run": true,
                "total_selected": selected_indices.len(),
                "would_import": items,
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    // Confirm (interactive only, non-all)
    if output_mode == OutputMode::Human && !use_all {
        let confirm = Confirm::new("Proceed with import?")
            .with_default(true)
            .prompt()?;

        if !confirm {
            println!("{}", "Import cancelled.".yellow());
            return Ok(());
        }
    }

    // Create output directory
    fs::create_dir_all(effective_output)?;

    // Build renamer if config has renaming rules
    let renamer = config.map(ProfileRenamer::new);

    // Phase 5: Execute pipeline
    let total = selected_indices.len();
    let mut batch = BatchResult::new();
    batch.total = total;

    // Track filenames to detect collisions and disambiguate
    let mut filename_counts: HashMap<String, usize> = HashMap::new();

    for (seq, &idx) in selected_indices.iter().enumerate() {
        let p = &discovered[idx];
        let original_filename = p
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Disambiguate colliding filenames
        let count = filename_counts
            .entry(original_filename.clone())
            .or_insert(0);
        *count += 1;
        let filename = if *count > 1 {
            let stem = Path::new(&original_filename)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy();
            let ext = Path::new(&original_filename)
                .extension()
                .unwrap_or_default()
                .to_string_lossy();
            let disambiguated = format!("{}-{}.{}", stem, *count - 1, ext);
            if output_mode == OutputMode::Human {
                println!(
                    "\n  {} Filename collision: {} → {}",
                    "!".yellow(),
                    original_filename,
                    disambiguated
                );
            }
            disambiguated
        } else {
            original_filename.clone()
        };

        let fallback_path = Path::new(effective_output).join(&filename);

        if output_mode == OutputMode::Human {
            println!(
                "\n{}",
                format!("[{}/{}] {}", seq + 1, total, original_filename).cyan()
            );
        }

        match import_single_profile(
            &p.path,
            &fallback_path,
            effective_output,
            renamer.as_ref(),
            effective_org,
            effective_org_name.as_deref(),
            config,
            validate,
            regen_uuid,
            output_mode,
        ) {
            Ok(actual_path) => {
                batch.success += 1;
                if output_mode == OutputMode::Human {
                    println!("  {} {}", "→".green(), actual_path.display());
                }
            }
            Err(e) => {
                let err_msg = format!("{e:#}");
                batch.failures.push((p.path.clone(), err_msg.clone()));
                batch.failed += 1;
                if output_mode == OutputMode::Human {
                    println!("  {} {}", "✗".red(), err_msg);
                }
            }
        }
    }

    // Phase 6: Summary
    if output_mode == OutputMode::Human {
        print_batch_summary(&batch, "Import");
    } else {
        output_batch_json(&batch, "import")?;
    }

    if batch.failed > 0 {
        anyhow::bail!("{} file(s) failed to import", batch.failed);
    }

    Ok(())
}

// ── Discovery ────────────────────────────────────────────────────────

fn discover_profiles(source: &Path, max_depth: Option<usize>) -> Result<Vec<DiscoveredProfile>> {
    let mut profiles = Vec::new();

    let mut walker = WalkDir::new(source).follow_links(true);
    if let Some(depth) = max_depth {
        walker = walker.max_depth(depth);
    }

    for entry in walker.into_iter().filter_map(std::result::Result::ok) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !ext.eq_ignore_ascii_case("mobileconfig") {
            continue;
        }

        // Check if signed
        let signed = signing::is_signed_profile(path).unwrap_or(false);

        // Try to parse
        let path_str = path.to_string_lossy().to_string();
        match parser::parse_profile_auto_unsign(&path_str) {
            Ok(profile) => {
                let payload_types: Vec<String> = profile
                    .payload_content
                    .iter()
                    .map(|c| c.payload_type.clone())
                    .collect();

                profiles.push(DiscoveredProfile {
                    path: path.to_path_buf(),
                    display_name: profile.payload_display_name.clone(),
                    identifier: profile.payload_identifier.clone(),
                    description: profile.payload_description(),
                    payload_types,
                    signed,
                    parse_error: None,
                });
            }
            Err(e) => {
                profiles.push(DiscoveredProfile {
                    path: path.to_path_buf(),
                    display_name: String::new(),
                    identifier: String::new(),
                    description: None,
                    payload_types: Vec::new(),
                    signed,
                    parse_error: Some(format!("{e:#}")),
                });
            }
        }
    }

    // Sort by filename for consistent ordering
    profiles.sort_by(|a, b| a.path.file_name().cmp(&b.path.file_name()));

    Ok(profiles)
}

// ── Payload type grouping ────────────────────────────────────────────

fn build_payload_type_groups(discovered: &[DiscoveredProfile]) -> Vec<PayloadTypeGroup> {
    let mut type_map: HashMap<String, Vec<usize>> = HashMap::new();

    for (idx, profile) in discovered.iter().enumerate() {
        if profile.parse_error.is_some() {
            continue;
        }
        for pt in &profile.payload_types {
            type_map.entry(pt.clone()).or_default().push(idx);
        }
    }

    let mut groups: Vec<PayloadTypeGroup> = type_map
        .into_iter()
        .map(|(payload_type, profiles)| {
            let friendly_name = friendly_payload_type_name(&payload_type).to_string();
            PayloadTypeGroup {
                payload_type,
                friendly_name,
                profiles,
            }
        })
        .collect();

    // Sort by profile count descending
    groups.sort_by(|a, b| b.profiles.len().cmp(&a.profiles.len()));

    groups
}

fn friendly_payload_type_name(payload_type: &str) -> &str {
    match payload_type {
        "com.apple.applicationaccess" => "Application Restrictions",
        "com.apple.TCC.configuration-profile-policy" => "Privacy (TCC/PPPC)",
        "com.apple.wifi.managed" => "WiFi",
        "com.apple.vpn.managed" => "VPN",
        "com.apple.MCX" => "Managed Preferences (MCX)",
        "com.apple.dock" => "Dock",
        "com.apple.notificationsettings" => "Notifications",
        "com.apple.screensaver" => "Screensaver",
        "com.apple.security.firewall" => "Firewall",
        "com.apple.MCX.FileVault2" => "FileVault",
        "com.apple.loginwindow" => "Login Window",
        "com.apple.SoftwareUpdate" => "Software Update",
        "com.apple.ManagedClient.preferences" => "Managed Client Preferences",
        "com.apple.dnsSettings.managed" => "DNS Settings",
        "com.apple.security.passcode" => "Passcode",
        "com.apple.mail.managed" => "Mail",
        "com.apple.caldav.account" => "Calendar (CalDAV)",
        "com.apple.carddav.account" => "Contacts (CardDAV)",
        "com.apple.ews.account" => "Exchange (EWS)",
        "com.apple.configurationprofile.identification" => "Identification",
        "com.apple.system.logging" => "System Logging",
        "com.apple.finder" => "Finder",
        "com.apple.SetupAssistant.managed" => "Setup Assistant",
        "com.apple.safari" => "Safari",
        "com.apple.preference.security" => "Security Preferences",
        "com.apple.systempolicy.control" => "Gatekeeper",
        "com.apple.syspolicy.kernel-extension-policy" => "Kernel Extensions",
        "com.apple.system-extension-policy" => "System Extensions",
        "com.apple.webcontent-filter" => "Web Content Filter",
        _ => {
            // Can't return a dynamically created string from a &str function,
            // so just return the raw payload type for unknown types
            payload_type
        }
    }
}

/// Format a profile for display in interactive selection lists.
/// Shows: filename — "Display Name" (signed) — description
fn format_profile_option(p: &DiscoveredProfile) -> String {
    let filename = p.path.file_name().unwrap_or_default().to_string_lossy();
    let signed_tag = if p.signed { " (signed)" } else { "" };
    let desc_tag = match &p.description {
        Some(d) if !d.is_empty() => format!(" — {}", d),
        _ => String::new(),
    };
    let name = if p.display_name.is_empty() {
        filename.to_string()
    } else {
        format!("{} — \"{}\"", filename, p.display_name)
    };
    format!("{}{}{}", name, signed_tag, desc_tag)
}

// ── Interactive selection ────────────────────────────────────────────

fn select_by_payload_type(
    discovered: &[DiscoveredProfile],
    groups: &[PayloadTypeGroup],
) -> Result<Vec<usize>> {
    if groups.is_empty() {
        println!("{}", "No payload types found.".yellow());
        return Ok(Vec::new());
    }

    // Stage 1: Select payload types to browse
    let type_options: Vec<String> = groups
        .iter()
        .map(|g| {
            let sample_names: Vec<&str> = g
                .profiles
                .iter()
                .take(3)
                .filter_map(|&idx| {
                    let name = &discovered[idx].display_name;
                    if name.is_empty() {
                        None
                    } else {
                        Some(name.as_str())
                    }
                })
                .collect();
            let samples = if sample_names.is_empty() {
                String::new()
            } else {
                let more = if g.profiles.len() > 3 {
                    format!(", +{} more", g.profiles.len() - 3)
                } else {
                    String::new()
                };
                format!(" ({}{})", sample_names.join(", "), more)
            };
            format!(
                "{} ({}) — {} profiles{}",
                g.friendly_name,
                g.payload_type,
                g.profiles.len(),
                samples
            )
        })
        .collect();

    let selected_types = MultiSelect::new(
        "Select payload types to browse (Space to toggle, Enter to confirm):",
        type_options.clone(),
    )
    .with_page_size(15)
    .with_help_message("Use arrow keys, Space to select/deselect, Enter to confirm")
    .prompt()?;

    if selected_types.is_empty() {
        return Ok(Vec::new());
    }

    // Stage 2: For each selected type, cherry-pick profiles
    let mut all_selected: HashSet<usize> = HashSet::new();

    for type_label in &selected_types {
        // Find the group by matching the label
        let group_idx = type_options.iter().position(|o| o == type_label).unwrap();
        let group = &groups[group_idx];

        println!();
        println!(
            "{}",
            format!("━━ {} ({}) ━━", group.friendly_name, group.payload_type).bold()
        );

        let profile_options: Vec<String> = group
            .profiles
            .iter()
            .map(|&idx| format_profile_option(&discovered[idx]))
            .collect();

        // Default all to selected
        let defaults: Vec<usize> = (0..profile_options.len()).collect();

        let selected_profiles = MultiSelect::new(
            "Select profiles to import (Space to toggle):",
            profile_options,
        )
        .with_page_size(15)
        .with_default(&defaults)
        .with_help_message("All pre-selected. Deselect any you don't want.")
        .prompt()?;

        // Map selected items back to discovered indices
        for selected_label in &selected_profiles {
            for &discovered_idx in &group.profiles {
                let label = format_profile_option(&discovered[discovered_idx]);
                if &label == selected_label {
                    all_selected.insert(discovered_idx);
                    break;
                }
            }
        }
    }

    let mut result: Vec<usize> = all_selected.into_iter().collect();
    result.sort_unstable();
    Ok(result)
}

fn select_browse_all(discovered: &[DiscoveredProfile]) -> Result<Vec<usize>> {
    let parseable: Vec<(usize, &DiscoveredProfile)> = discovered
        .iter()
        .enumerate()
        .filter(|(_, p)| p.parse_error.is_none())
        .collect();

    if parseable.is_empty() {
        return Ok(Vec::new());
    }

    let options: Vec<String> = parseable
        .iter()
        .map(|(_, p)| {
            let base = format_profile_option(p);
            let types = if p.payload_types.is_empty() {
                String::new()
            } else {
                let friendly: Vec<&str> = p
                    .payload_types
                    .iter()
                    .map(|t| friendly_payload_type_name(t))
                    .collect();
                format!(" [{}]", friendly.join(", "))
            };
            format!("{}{}", base, types)
        })
        .collect();

    let selected = MultiSelect::new(
        "Select profiles to import (Space to toggle, Enter to confirm):",
        options.clone(),
    )
    .with_page_size(20)
    .with_help_message("Use arrow keys, Space to select/deselect, Enter to confirm")
    .prompt()?;

    // Map back to indices
    let mut result = Vec::new();
    for selected_label in &selected {
        if let Some(pos) = options.iter().position(|o| o == selected_label) {
            result.push(parseable[pos].0);
        }
    }

    result.sort_unstable();
    Ok(result)
}

// ── Single-profile import pipeline ───────────────────────────────────

#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
fn import_single_profile(
    source: &Path,
    output: &Path,
    output_dir: &str,
    renamer: Option<&ProfileRenamer<'_>>,
    org_domain: Option<&str>,
    org_name: Option<&str>,
    config: Option<&ProfileConfig>,
    validate: bool,
    regen_uuid: bool,
    output_mode: OutputMode,
) -> Result<PathBuf> {
    let path_str = source.to_string_lossy().to_string();

    // 1. Parse (auto-unsign)
    let mut profile = parser::parse_profile_auto_unsign(&path_str)?;
    if output_mode == OutputMode::Human {
        println!("  {} Parsed (auto-unsigned)", "✓".green());
    }

    // 2. Normalize (org_domain and org_name are already resolved by caller)
    if org_domain.is_some() || org_name.is_some() {
        let normalizer_config = normalizer::NormalizerConfig {
            org_domain: org_domain.map(String::from),
            org_name: org_name.map(String::from),
            naming_convention: normalizer::NamingConvention::OrgDomainPrefix,
        };

        normalizer::normalize_profile(&mut profile, &normalizer_config)?;
        if output_mode == OutputMode::Human {
            if org_domain.is_some() {
                println!(
                    "  {} Normalized → {}",
                    "✓".green(),
                    profile.payload_identifier
                );
            } else {
                println!("  {} Normalized", "✓".green());
            }
        }
    }

    // 3. UUID regeneration
    if regen_uuid {
        let predictable = config.is_some_and(|c| c.uuid.predictable);
        let uuid_config = UuidConfig {
            org_domain: org_domain.map(String::from),
            predictable,
        };

        profile.payload_uuid = uuid::regenerate_uuid(
            &profile.payload_uuid,
            &uuid_config,
            &profile.payload_identifier,
        )?;

        for content in &mut profile.payload_content {
            content.payload_uuid = uuid::regenerate_uuid(
                &content.payload_uuid,
                &uuid_config,
                &content.payload_identifier,
            )?;
        }

        if output_mode == OutputMode::Human {
            println!("  {} UUIDs regenerated", "✓".green());
        }
    }

    // 4. Validate
    if validate {
        let validation = validator::validate_profile(&profile)?;
        if !validation.valid {
            let detail = validation.errors.join("; ");
            anyhow::bail!("Validation failed: {detail}");
        }
        if output_mode == OutputMode::Human {
            println!("  {} Validated", "✓".green());
        }
    }

    // 5. Compute final output path (renamer overrides default filename)
    let final_output = if let Some(r) = renamer {
        let renamed = r.generate_filename(&profile, Some(source));
        Path::new(output_dir).join(renamed)
    } else {
        output.to_path_buf()
    };

    // 6. Write
    if let Some(parent) = final_output.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }

    parser::write_profile(&profile, &final_output)?;

    Ok(final_output)
}
