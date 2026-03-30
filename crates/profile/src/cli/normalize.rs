use crate::cli::glob_utils::{
    BatchResult, collect_profile_files_multi_with_depth, compute_batch_output_path,
    output_batch_json, print_batch_summary, print_dry_run_preview, should_batch_process_multi,
};
use crate::config::{ProfileConfig, renaming::ProfileRenamer};
use crate::output::OutputMode;
use crate::profile::{normalizer, parser, validator};
use crate::uuid::{self, UuidConfig};
use anyhow::Result;
use colored::Colorize;
use rayon::prelude::*;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Restore placeholder sentinels and XML comments in a written profile file.
///
/// Called after `parser::write_profile()` to undo the lossy plist round-trip for
/// placeholders and comments that the plist crate cannot represent.
fn restore_and_rewrite(
    path: &Path,
    placeholder_mapping: &[(String, String)],
    comments: &[parser::XmlComment],
) -> Result<()> {
    if placeholder_mapping.is_empty() && comments.is_empty() {
        return Ok(());
    }
    let mut content = fs::read(path)?;
    if !placeholder_mapping.is_empty() {
        content = parser::restore_placeholders(&content, placeholder_mapping);
    }
    if !comments.is_empty() {
        let text = String::from_utf8_lossy(&content);
        let restored = parser::restore_comments(&text, comments);
        content = restored.into_bytes();
    }
    fs::write(path, content)?;
    Ok(())
}

pub fn handle_normalize_pasteboard(
    output: Option<&str>,
    org_domain: Option<&str>,
    org_name: Option<&str>,
    config: Option<&ProfileConfig>,
    validate: bool,
    regen_uuid: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        println!("{}", "Reading profile from pasteboard...".cyan());
    }

    let pasteboard_bytes = parser::read_pasteboard_bytes()?;
    let fixup_result = parser::parse_profile_lenient_from_bytes(&pasteboard_bytes)?;
    let placeholder_mapping = fixup_result.placeholder_mapping;
    let extracted_comments = fixup_result.comments;
    let mut profile = fixup_result.profile;

    if output_mode == OutputMode::Human {
        if !fixup_result.fixups.is_empty() {
            for fixup in &fixup_result.fixups {
                println!("  {} {}", "~".yellow(), fixup);
            }
        }
        if !fixup_result.placeholders.is_empty() {
            println!(
                "  {} Preserved {} placeholder(s)",
                "~".yellow(),
                fixup_result.placeholders.len()
            );
        }
        println!("{}", "✓ Profile parsed from pasteboard".green());
    }

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

    // Resolve org name: CLI --name → profile.toml → .contour/config.toml
    let effective_org_name = org_name
        .map(String::from)
        .or_else(|| config.map(super::super::config::ProfileConfig::org_name))
        .or_else(|| {
            contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.name)
        });

    let normalizer_config = normalizer::NormalizerConfig {
        org_domain: effective_org.map(String::from),
        org_name: effective_org_name,
        naming_convention: normalizer::NamingConvention::OrgDomainPrefix,
    };

    normalizer::normalize_profile(&mut profile, &normalizer_config)?;

    if output_mode == OutputMode::Human {
        println!("{}", "✓ Profile normalized".green());
    }

    // Regenerate UUIDs — default to predictable for pasteboard input
    if regen_uuid {
        let predictable = config.is_some_and(|c| c.uuid.predictable);

        let uuid_config = UuidConfig {
            org_domain: effective_org.map(String::from),
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
            println!("{}", "✓ UUIDs regenerated (deterministic)".green());
        }
    }

    // Validate after normalization and UUID regeneration
    if validate {
        let validation = validator::validate_profile(&profile)?;
        if !validation.valid {
            if output_mode == OutputMode::Human {
                println!("{}", "Validation errors (after normalization):".red());
                for error in &validation.errors {
                    println!("  {} {}", "✗".red(), error);
                }
            }
            let detail = validation.errors.join("; ");
            anyhow::bail!("Validation failed after normalization: {detail}");
        }

        if !validation.warnings.is_empty() && output_mode == OutputMode::Human {
            println!("{}", "Validation warnings:".yellow());
            for warning in &validation.warnings {
                println!("  {} {}", "!".yellow(), warning);
            }
        }

        if output_mode == OutputMode::Human {
            println!("{}", "✓ Profile validated successfully".green());
        }
    }

    // Determine output path
    let output_path = if let Some(output_file) = output {
        output_file.to_string()
    } else if let Some(cfg) = config {
        let renamer = crate::config::renaming::ProfileRenamer::new(cfg);
        let path = renamer.generate_output_path(&profile, None);
        path.to_string_lossy().to_string()
    } else {
        "normalized.mobileconfig".to_string()
    };

    // Create parent directory if it doesn't exist
    let output_path_ref = Path::new(&output_path);
    if let Some(parent) = output_path_ref.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }

    parser::write_profile(&profile, output_path_ref)?;
    restore_and_rewrite(output_path_ref, &placeholder_mapping, &extracted_comments)?;

    if output_mode == OutputMode::Human {
        println!(
            "{}",
            format!("✓ Profile normalized successfully: {output_path}").green()
        );
    }

    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "CLI handler requires many parameters"
)]
pub fn handle_normalize(
    paths: &[String],
    output: Option<&str>,
    org_domain: Option<&str>,
    org_name: Option<&str>,
    config: Option<&ProfileConfig>,
    validate: bool,
    regen_uuid: bool,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    dry_run: bool,
    report: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    // Fall back to .contour/config.toml when no --org and no profile.toml org
    let contour_domain;
    let effective_org = if org_domain.is_some() || config.is_some() {
        org_domain
    } else if let Some(cfg) = contour_core::config::ContourConfig::load_nearest() {
        contour_domain = cfg.organization.domain;
        Some(contour_domain.as_str())
    } else {
        None
    };

    if should_batch_process_multi(paths) {
        handle_normalize_batch(
            paths,
            output,
            effective_org,
            org_name,
            config,
            validate,
            regen_uuid,
            recursive,
            max_depth,
            parallel,
            dry_run,
            report,
            output_mode,
        )
    } else {
        let path = &paths[0];
        if dry_run {
            if output_mode == OutputMode::Human {
                println!("{}", "Dry run mode - no files will be written\n".yellow());
                println!("Would normalize: {path}");
            } else {
                let result = serde_json::json!({
                    "dry_run": true,
                    "would_process": [path],
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            return Ok(());
        }
        handle_normalize_single(
            path,
            output,
            effective_org,
            org_name,
            config,
            validate,
            regen_uuid,
            output_mode,
        )
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "CLI handler requires many parameters"
)]
fn handle_normalize_batch(
    paths: &[String],
    output_dir: Option<&str>,
    org_domain: Option<&str>,
    org_name: Option<&str>,
    config: Option<&ProfileConfig>,
    validate: bool,
    regen_uuid: bool,
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    dry_run: bool,
    report: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let files = collect_profile_files_multi_with_depth(paths, recursive, max_depth)?;

    if files.is_empty() {
        if output_mode == OutputMode::Human {
            println!("{}", "No .mobileconfig files found".yellow());
        } else {
            let result = serde_json::json!({
                "success": true,
                "total": 0,
                "message": "No .mobileconfig files found"
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    if output_mode == OutputMode::Human && !dry_run {
        println!(
            "{}",
            format!("Normalizing {} profile(s)...", files.len()).cyan()
        );
    }

    if dry_run {
        print_dry_run_preview(&files, output_dir, "-normalized", output_mode);
        return Ok(());
    }

    // Create output directory if specified
    if let Some(dir) = output_dir {
        fs::create_dir_all(dir)?;
    }

    let config_clone = config.cloned();
    let org_domain_owned = org_domain.map(String::from);
    let org_name_owned = org_name.map(String::from);

    let normalize_file = |input: &Path, output_path: &Path| -> Result<Vec<String>> {
        normalize_single_file_internal(
            input,
            output_path,
            org_domain_owned.as_deref(),
            org_name_owned.as_deref(),
            config_clone.as_ref(),
            validate,
            regen_uuid,
        )
    };

    let result = if parallel {
        process_parallel_with_output(
            &files,
            output_dir,
            "-normalized",
            normalize_file,
            output_mode,
        )
    } else {
        process_sequential_with_output(
            &files,
            output_dir,
            "-normalized",
            normalize_file,
            output_mode,
        )
    };

    // Output summary
    if output_mode == OutputMode::Human {
        print_batch_summary(&result, "Normalize");
    } else {
        output_batch_json(&result, "normalize")?;
    }

    // Write markdown report if requested
    if let Some(report_path) = report {
        let md = generate_normalize_report(&result);
        fs::write(report_path, &md)?;
        if output_mode == OutputMode::Human {
            println!("{}", format!("Report written to {report_path}").green());
        }
    }

    if result.failed > 0 {
        anyhow::bail!("{} file(s) failed to normalize", result.failed);
    }

    Ok(())
}

/// Returns Ok(fixups) on success — the list of fixups applied during parsing and normalization.
fn normalize_single_file_internal(
    input: &Path,
    output: &Path,
    org_domain: Option<&str>,
    org_name: Option<&str>,
    config: Option<&ProfileConfig>,
    validate: bool,
    regen_uuid: bool,
) -> Result<Vec<String>> {
    let file = input.to_str().unwrap_or_default();
    let fixup_result = parser::parse_profile_lenient(file)?;
    let placeholder_mapping = fixup_result.placeholder_mapping;
    let extracted_comments = fixup_result.comments;
    let mut profile = fixup_result.profile;
    let mut fixups = fixup_result.fixups;
    if !fixup_result.placeholders.is_empty() {
        fixups.push(format!(
            "preserved {} placeholder(s): {}",
            fixup_result.placeholders.len(),
            fixup_result.placeholders.join(", ")
        ));
    }

    // Get org domain from config or CLI (config takes precedence)
    let effective_org_domain = if let Some(cfg) = config {
        Some(cfg.organization.domain.as_str())
    } else {
        org_domain
    };
    // CLI --name → profile.toml → .contour/config.toml
    let effective_org_name = org_name
        .map(String::from)
        .or_else(|| config.map(super::super::config::ProfileConfig::org_name))
        .or_else(|| {
            contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.name)
        });

    let normalizer_config = normalizer::NormalizerConfig {
        org_domain: effective_org_domain.map(String::from),
        org_name: effective_org_name,
        naming_convention: normalizer::NamingConvention::OrgDomainPrefix,
    };

    normalizer::normalize_profile(&mut profile, &normalizer_config)?;

    // Regenerate UUIDs if requested
    if regen_uuid {
        let predictable = config.is_some_and(|c| c.uuid.predictable);

        let uuid_config = UuidConfig {
            org_domain: effective_org_domain.map(String::from),
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
    }

    // Validate after normalization and UUID regeneration — normalize is a fixer,
    // so we validate the output, not the input (which may have invalid UUIDs etc.)
    if validate {
        let validation = validator::validate_profile(&profile)?;
        if !validation.valid {
            let detail = validation.errors.join("; ");
            anyhow::bail!("Validation failed after normalization: {detail}");
        }
    }

    // Create parent directory if it doesn't exist
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }

    parser::write_profile(&profile, output)?;
    restore_and_rewrite(output, &placeholder_mapping, &extracted_comments)?;

    Ok(fixups)
}

#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
fn handle_normalize_single(
    file: &str,
    output: Option<&str>,
    org_domain: Option<&str>,
    org_name: Option<&str>,
    config: Option<&ProfileConfig>,
    validate: bool,
    regen_uuid: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Human {
        println!("{}", "Normalizing configuration profile...".cyan());
    }

    let fixup_result = parser::parse_profile_lenient(file)?;
    let placeholder_mapping = fixup_result.placeholder_mapping;
    let extracted_comments = fixup_result.comments;
    let mut profile = fixup_result.profile;

    if output_mode == OutputMode::Human {
        if !fixup_result.fixups.is_empty() {
            for fixup in &fixup_result.fixups {
                println!("  {} {}", "~".yellow(), fixup);
            }
        }
        if !fixup_result.placeholders.is_empty() {
            println!(
                "  {} Preserved {} placeholder(s)",
                "~".yellow(),
                fixup_result.placeholders.len()
            );
        }
        println!("{}", "✓ Profile parsed successfully".green());
    }

    // Get org domain from config or CLI (config takes precedence)
    let effective_org_domain = if let Some(cfg) = config {
        Some(cfg.organization.domain.as_str())
    } else {
        org_domain
    };
    // CLI --name → profile.toml → .contour/config.toml
    let effective_org_name = org_name
        .map(String::from)
        .or_else(|| config.map(super::super::config::ProfileConfig::org_name))
        .or_else(|| {
            contour_core::config::ContourConfig::load_nearest().map(|c| c.organization.name)
        });

    let normalizer_config = normalizer::NormalizerConfig {
        org_domain: effective_org_domain.map(String::from),
        org_name: effective_org_name,
        naming_convention: normalizer::NamingConvention::OrgDomainPrefix,
    };

    normalizer::normalize_profile(&mut profile, &normalizer_config)?;

    if output_mode == OutputMode::Human {
        println!("{}", "✓ Profile normalized".green());
    }

    // Regenerate UUIDs if requested
    if regen_uuid {
        let predictable = config.is_some_and(|c| c.uuid.predictable);

        let uuid_config = UuidConfig {
            org_domain: effective_org_domain.map(String::from),
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
            println!("{}", "✓ UUIDs regenerated".green());
        }
    }

    // Validate after normalization and UUID regeneration — normalize is a fixer,
    // so we validate the output, not the input (which may have invalid UUIDs etc.)
    if validate {
        let validation = validator::validate_profile(&profile)?;
        if !validation.valid {
            if output_mode == OutputMode::Human {
                println!("{}", "Validation errors (after normalization):".red());
                for error in &validation.errors {
                    println!("  {} {}", "✗".red(), error);
                }
            }
            let detail = validation.errors.join("; ");
            anyhow::bail!("Validation failed after normalization: {detail}");
        }

        if !validation.warnings.is_empty() && output_mode == OutputMode::Human {
            println!("{}", "Validation warnings:".yellow());
            for warning in &validation.warnings {
                println!("  {} {}", "!".yellow(), warning);
            }
        }

        if output_mode == OutputMode::Human {
            println!("{}", "✓ Profile validated successfully".green());
        }
    }

    // Determine output path using config renaming or CLI output
    let output_path = if let Some(output_file) = output {
        output_file.to_string()
    } else if let Some(cfg) = config {
        let renamer = ProfileRenamer::new(cfg);
        let path = renamer.generate_output_path(&profile, Some(Path::new(file)));
        path.to_string_lossy().to_string()
    } else {
        "output.mobileconfig".to_string()
    };

    // Create parent directory if it doesn't exist
    let output_path_ref = Path::new(&output_path);
    if let Some(parent) = output_path_ref.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }

    parser::write_profile(&profile, output_path_ref)?;
    restore_and_rewrite(output_path_ref, &placeholder_mapping, &extracted_comments)?;

    if output_mode == OutputMode::Human {
        println!(
            "{}",
            format!("✓ Profile normalized successfully: {output_path}").green()
        );
    }

    Ok(())
}

/// Generate a markdown normalize report from batch results.
fn generate_normalize_report(result: &BatchResult) -> String {
    use std::collections::HashMap;
    use std::fmt::Write;
    let mut md = String::with_capacity(8 * 1024);

    writeln!(md, "# Profile Normalize Report\n").unwrap();
    writeln!(
        md,
        "| Metric | Count |\n|---|---|\n| Total | {} |\n| Succeeded | {} |\n| Fixed during parse | {} |\n| Failed | {} |",
        result.total, result.success, result.with_warnings, result.failed
    )
    .unwrap();
    writeln!(md).unwrap();

    // Normalization rules reference — always included
    const TOPLEVEL_URL: &str =
        "https://github.com/apple/device-management/blob/release/mdm/profiles/TopLevel.yaml";
    const COMMON_URL: &str = "https://github.com/apple/device-management/blob/release/mdm/profiles/CommonPayloadKeys.yaml";

    writeln!(md, "## Normalization Rules\n").unwrap();
    writeln!(
        md,
        "Each fixup enforces requirements from Apple's device management specification:"
    )
    .unwrap();
    writeln!(
        md,
        "- [TopLevel.yaml]({TOPLEVEL_URL}) — top-level profile keys"
    )
    .unwrap();
    writeln!(
        md,
        "- [CommonPayloadKeys.yaml]({COMMON_URL}) — keys required on every payload\n"
    )
    .unwrap();
    writeln!(md, "| Rule | What normalize does | Spec |").unwrap();
    writeln!(md, "|---|---|---|").unwrap();
    writeln!(md, "| **PayloadType** must be `Configuration` at top level | Wraps bare payloads (e.g. PPPC/TCC fragments) in a Configuration envelope | [TopLevel]({TOPLEVEL_URL}) — `PayloadType: required, rangelist: [Configuration]` |").unwrap();
    writeln!(md, "| **PayloadVersion** required on every dict | Adds `<integer>1</integer>` when missing | [CommonPayloadKeys]({COMMON_URL}) — `PayloadVersion: required, type: <integer>, rangelist: [1]` |").unwrap();
    writeln!(md, "| **PayloadVersion** must be `<integer>` | Converts `<real>1</real>` to `<integer>1</integer>` | [CommonPayloadKeys]({COMMON_URL}) — `type: <integer>` |").unwrap();
    writeln!(md, "| **PayloadIdentifier** required, reverse-DNS | Adds identifier from PayloadType when missing; normalizer prefixes with org domain | [CommonPayloadKeys]({COMMON_URL}) — `PayloadIdentifier: required, type: <string>` |").unwrap();
    writeln!(md, "| **PayloadUUID** required, valid RFC 4122 | Generates v4 UUID when missing | [CommonPayloadKeys]({COMMON_URL}) — `PayloadUUID: required, type: <string>` |").unwrap();
    writeln!(md, "| **PayloadScope** must be `User` or `System` | Fixes capitalization (`system` → `System`) | [TopLevel]({TOPLEVEL_URL}) — `PayloadScope: rangelist: [User, System]` |").unwrap();
    writeln!(md, "| **MDM placeholders** preserved | Keeps `$VAR`, `{{{{var}}}}`, `%Var%` intact through normalization | N/A — MDM servers expand these at install time |").unwrap();
    writeln!(md).unwrap();

    // Fixups section — what was automatically corrected
    if !result.warnings.is_empty() {
        writeln!(md, "## Fixups Applied\n").unwrap();
        writeln!(
            md,
            "{} file(s) required automatic corrections before normalizing.\n",
            result.warnings.len()
        )
        .unwrap();

        // Aggregate fixup counts by type
        let mut fixup_counts: HashMap<&str, usize> = HashMap::new();
        for (_path, fixups) in &result.warnings {
            for fixup in fixups {
                let category = if fixup.contains("added missing PayloadVersion") {
                    "Added missing PayloadVersion=1"
                } else if fixup.contains("converted PayloadVersion") {
                    "Converted PayloadVersion from real to integer"
                } else if fixup.contains("added missing PayloadIdentifier") {
                    "Added missing PayloadIdentifier"
                } else if fixup.contains("added missing PayloadUUID") {
                    "Generated missing PayloadUUID"
                } else if fixup.contains("preserved") && fixup.contains("placeholder") {
                    "Preserved MDM placeholders"
                } else if fixup.contains("wrapped bare payload") {
                    "Wrapped bare payload in Configuration envelope"
                } else if fixup.contains("fixed PayloadScope") {
                    "Fixed PayloadScope capitalization"
                } else {
                    "Other fixup"
                };
                *fixup_counts.entry(category).or_insert(0) += 1;
            }
        }

        writeln!(md, "### Summary\n").unwrap();
        writeln!(md, "| Fixup | Count |").unwrap();
        writeln!(md, "|---|---|").unwrap();
        // Sort by count descending
        let mut sorted: Vec<_> = fixup_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (category, count) in &sorted {
            writeln!(md, "| {category} | {count} |").unwrap();
        }
        writeln!(md).unwrap();

        writeln!(md, "### Per-file details\n").unwrap();
        for (path, fixups) in &result.warnings {
            writeln!(md, "**`{}`**\n", path.display()).unwrap();
            for fixup in fixups {
                writeln!(md, "- {fixup}").unwrap();
            }
            writeln!(md).unwrap();
        }
    }

    if result.failed > 0 {
        writeln!(md, "## Failures\n").unwrap();

        // Group by category
        let mut malformed = Vec::new();
        let mut placeholders = Vec::new();
        let mut structure = Vec::new();
        let mut other = Vec::new();

        for (path, err) in &result.failures {
            let entry = format!("- `{}`", path.display());
            if err.contains("ExpectedEndOfEventStream") {
                malformed.push(entry);
            } else if err.contains("InvalidDataString") || err.contains("placeholder substitution")
            {
                placeholders.push(entry);
            } else if err.contains("Profile structure errors") {
                structure.push((path, err));
            } else {
                other.push((path.display().to_string(), err.clone()));
            }
        }

        if !malformed.is_empty() {
            writeln!(
                md,
                "### Malformed plist ({} file{})\n",
                malformed.len(),
                if malformed.len() == 1 { "" } else { "s" }
            )
            .unwrap();
            writeln!(
                md,
                "File is not valid XML/binary plist. Likely a test fixture or concatenated file.\n"
            )
            .unwrap();
            for entry in &malformed {
                writeln!(md, "{entry}").unwrap();
            }
            writeln!(md).unwrap();
        }

        if !placeholders.is_empty() {
            writeln!(
                md,
                "### Unrecognized placeholders ({} file{})\n",
                placeholders.len(),
                if placeholders.len() == 1 { "" } else { "s" }
            )
            .unwrap();
            writeln!(
                md,
                "File contains template variables (e.g. Go `%s`, custom tokens) that break plist parsing.\n"
            )
            .unwrap();
            for entry in &placeholders {
                writeln!(md, "{entry}").unwrap();
            }
            writeln!(md).unwrap();
        }

        if !structure.is_empty() {
            writeln!(
                md,
                "### Missing required fields ({} file{})\n",
                structure.len(),
                if structure.len() == 1 { "" } else { "s" }
            )
            .unwrap();
            for (path, err) in &structure {
                writeln!(md, "**`{}`**\n", path.display()).unwrap();
                // Extract the bullet points from "Profile structure errors:\n  - ..."
                for line in err.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("- ") || trimmed.starts_with("· ") {
                        writeln!(md, "- {}", &trimmed[2..]).unwrap();
                    }
                }
                writeln!(md).unwrap();
            }
        }

        if !other.is_empty() {
            writeln!(md, "### Other errors\n").unwrap();
            for (path, err) in &other {
                writeln!(md, "- `{path}`: {err}").unwrap();
            }
            writeln!(md).unwrap();
        }
    }

    md
}

// Helper functions for processing with output paths
fn process_parallel_with_output<F>(
    files: &[std::path::PathBuf],
    output_dir: Option<&str>,
    suffix: &str,
    processor: F,
    output_mode: OutputMode,
) -> BatchResult
where
    F: Fn(&Path, &Path) -> Result<Vec<String>> + Sync,
{
    let success_count = AtomicUsize::new(0);
    let failed_count = AtomicUsize::new(0);

    let results: Vec<(std::path::PathBuf, std::path::PathBuf, Result<Vec<String>>)> = files
        .par_iter()
        .map(|file| {
            let output_path = compute_batch_output_path(file, output_dir, suffix);
            let result = processor(file, &output_path);
            match &result {
                Ok(_) => {
                    success_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    failed_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            (file.clone(), output_path, result)
        })
        .collect();

    let mut failures = Vec::new();
    let mut warnings = Vec::new();
    let mut with_warnings = 0usize;
    for (file, output_path, result) in &results {
        match result {
            Ok(fixups) => {
                if output_mode == OutputMode::Human {
                    println!(
                        "{} {} -> {}",
                        "✓".green(),
                        file.display(),
                        output_path.display()
                    );
                }
                if !fixups.is_empty() {
                    with_warnings += 1;
                    warnings.push((file.clone(), fixups.clone()));
                }
            }
            Err(e) => {
                let err_msg = format!("{e:#}");
                failures.push((file.clone(), err_msg.clone()));
                if output_mode == OutputMode::Human {
                    println!("{} {}: {}", "✗".red(), file.display(), err_msg);
                }
            }
        }
    }

    BatchResult {
        total: files.len(),
        success: success_count.load(Ordering::Relaxed),
        failed: failed_count.load(Ordering::Relaxed),
        skipped: 0,
        with_warnings,
        failures,
        warnings,
    }
}

fn process_sequential_with_output<F>(
    files: &[std::path::PathBuf],
    output_dir: Option<&str>,
    suffix: &str,
    processor: F,
    output_mode: OutputMode,
) -> BatchResult
where
    F: Fn(&Path, &Path) -> Result<Vec<String>>,
{
    let mut result = BatchResult {
        total: files.len(),
        success: 0,
        failed: 0,
        skipped: 0,
        with_warnings: 0,
        failures: Vec::new(),
        warnings: Vec::new(),
    };

    for (idx, file) in files.iter().enumerate() {
        let output_path = compute_batch_output_path(file, output_dir, suffix);

        if output_mode == OutputMode::Human {
            println!(
                "{}",
                format!(
                    "[{}/{}] Normalizing: {}",
                    idx + 1,
                    files.len(),
                    file.display()
                )
                .cyan()
            );
        }

        match processor(file, &output_path) {
            Ok(fixups) => {
                result.success += 1;
                if output_mode == OutputMode::Human {
                    println!("{} -> {}", "✓".green(), output_path.display());
                }
                if !fixups.is_empty() {
                    result.with_warnings += 1;
                    result.warnings.push((file.clone(), fixups));
                }
            }
            Err(e) => {
                let err_msg = format!("{e:#}");
                result.failures.push((file.clone(), err_msg.clone()));
                result.failed += 1;
                if output_mode == OutputMode::Human {
                    println!("{}", format!("✗ Failed: {err_msg}").red());
                }
            }
        }
    }

    result
}
