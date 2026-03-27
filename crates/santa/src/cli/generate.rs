use crate::generator::{Format, GeneratorOptions, write_to_file_format};
use crate::output::{
    CommandResult, OutputMode, print_error, print_info, print_json, print_kv, print_success,
};
use crate::parser::parse_files;
use crate::validator::validate_ruleset;
use anyhow::Result;
use contour_core::fragment::{
    DefaultYmlEntries, FleetEntries, FragmentManifest, FragmentMeta, LibFiles, ProfileEntry,
    ScriptEntries,
};
use serde::Serialize;
use std::path::Path;

use super::OutputFormat;

#[derive(Debug, Serialize)]
struct GenerateOutput {
    rules_count: usize,
    output_path: Option<String>,
    identifier: String,
    format: String,
}

#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
pub fn run(
    inputs: &[impl AsRef<Path>],
    output: Option<&Path>,
    org: &str,
    identifier: Option<&str>,
    display_name: Option<&str>,
    deterministic_uuids: bool,
    output_format: OutputFormat,
    dry_run: bool,
    fragment: bool,
    mode: OutputMode,
) -> Result<()> {
    if fragment {
        return run_generate_fragment(
            inputs,
            output,
            org,
            identifier,
            display_name,
            deterministic_uuids,
            output_format,
            dry_run,
            mode,
        );
    }

    // Parse all input files
    let rules = parse_files(inputs)?;

    // Validate
    let validation = validate_ruleset(&rules);
    if !validation.valid {
        let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
        if mode == OutputMode::Json {
            print_json(&CommandResult::<()>::failure(errors))?;
        } else {
            for err in &errors {
                print_error(err);
            }
        }
        anyhow::bail!("Validation failed");
    }

    // Build options
    let mut options = GeneratorOptions::new(org);
    if let Some(id) = identifier {
        options = options.with_identifier(id);
    }
    if let Some(name) = display_name {
        options = options.with_display_name(name);
    }
    options = options.with_deterministic_uuids(deterministic_uuids);

    // Determine output extension and format
    let (format, default_ext) = match output_format {
        OutputFormat::Mobileconfig => (Format::Mobileconfig, "mobileconfig"),
        OutputFormat::Plist => (Format::Plist, "plist"),
        OutputFormat::PlistFull => (Format::PlistFull, "plist"),
    };

    let output_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new(&format!("santa-rules.{}", default_ext)).to_path_buf());

    let format_name = match output_format {
        OutputFormat::Mobileconfig => "mobileconfig",
        OutputFormat::Plist => "plist (WS1)",
        OutputFormat::PlistFull => "plist-full (Jamf)",
    };

    if dry_run {
        if mode == OutputMode::Human {
            print_info("Dry run - no files will be written");
            print_kv("Rules", &rules.len().to_string());
            print_kv("Output", &output_path.display().to_string());
            print_kv("Format", format_name);
            print_kv("Identifier", &options.identifier);
        } else {
            print_json(&CommandResult::success(GenerateOutput {
                rules_count: rules.len(),
                output_path: Some(output_path.display().to_string()),
                identifier: options.identifier.clone(),
                format: format_name.to_string(),
            }))?;
        }
        return Ok(());
    }

    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Generate and write
    write_to_file_format(&rules, &options, &output_path, format)?;

    if mode == OutputMode::Human {
        print_success(&format!(
            "Generated {} ({}) with {} rules",
            output_path.display(),
            format_name,
            rules.len()
        ));
    } else {
        print_json(&CommandResult::success(GenerateOutput {
            rules_count: rules.len(),
            output_path: Some(output_path.display().to_string()),
            identifier: options.identifier,
            format: format_name.to_string(),
        }))?;
    }

    Ok(())
}

/// Generate a Fleet fragment directory for Santa rules.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler requires many parameters"
)]
fn run_generate_fragment(
    inputs: &[impl AsRef<Path>],
    output: Option<&Path>,
    org: &str,
    identifier: Option<&str>,
    display_name: Option<&str>,
    deterministic_uuids: bool,
    output_format: OutputFormat,
    dry_run: bool,
    mode: OutputMode,
) -> Result<()> {
    let rules = parse_files(inputs)?;

    let validation = validate_ruleset(&rules);
    if !validation.valid {
        let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
        if mode == OutputMode::Json {
            print_json(&CommandResult::<()>::failure(errors))?;
        } else {
            for err in &errors {
                print_error(err);
            }
        }
        anyhow::bail!("Validation failed");
    }

    let mut options = GeneratorOptions::new(org);
    if let Some(id) = identifier {
        options = options.with_identifier(id);
    }
    if let Some(name) = display_name {
        options = options.with_display_name(name);
    }
    options = options.with_deterministic_uuids(deterministic_uuids);

    let (format, default_ext) = match output_format {
        OutputFormat::Mobileconfig => (Format::Mobileconfig, "mobileconfig"),
        OutputFormat::Plist => (Format::Plist, "plist"),
        OutputFormat::PlistFull => (Format::PlistFull, "plist"),
    };

    let output_dir = output.map_or_else(
        || std::path::PathBuf::from("santa-fragment"),
        std::path::Path::to_path_buf,
    );

    if mode == OutputMode::Human {
        print_kv("Rules", &rules.len().to_string());
        print_kv("Mode", "fragment");
        print_kv("Output directory", &output_dir.display().to_string());
    }

    if dry_run {
        if mode == OutputMode::Human {
            print_info("Dry run - no files will be written");
        }
        return Ok(());
    }

    let layout = contour_core::fleet_layout::FleetLayout::default();
    let profiles_dir = output_dir.join(layout.macos_profiles_subdir);
    let teams_dir = output_dir.join(layout.fleets_dir);
    std::fs::create_dir_all(&profiles_dir)?;
    std::fs::create_dir_all(&teams_dir)?;

    let filename = format!("santa-rules.{default_ext}");
    let output_path = profiles_dir.join(&filename);

    write_to_file_format(&rules, &options, &output_path, format)?;

    let relative_path = format!("{}/{filename}", layout.macos_profiles_subdir);
    let team_relative_path = format!("../{}/{filename}", layout.macos_profiles_subdir);

    let profile_entry = ProfileEntry {
        path: team_relative_path.clone(),
        labels_include_any: None,
        labels_include_all: None,
        labels_exclude_any: None,
    };

    // Generate fleets/reference-team.yml
    {
        use std::fmt::Write;
        let mut content = String::from(
            "# Fleet GitOps - Team Configuration: Santa Rules\n\
             #\n\
             # Santa allowlist/blocklist rules for MDM deployment.\n\
             #\n\
             # Generated by Contour CLI (santa fragment mode)\n\
             \n\
             name: santa-reference\n\
             controls:\n\
             \x20 macos_settings:\n\
             \x20   custom_settings:\n",
        );
        let _ = writeln!(content, "      - path: {}", team_relative_path);
        std::fs::write(teams_dir.join("reference-team.yml"), &content)?
    };

    // Generate fragment.toml
    {
        let manifest = FragmentManifest {
            fragment: FragmentMeta {
                name: "santa-rules".to_string(),
                version: "1.0.0".to_string(),
                description: format!("Santa rules profile with {} rules", rules.len()),
                generator: "contour-santa".to_string(),
            },
            default_yml: DefaultYmlEntries {
                label_paths: Vec::new(),
                report_paths: Vec::new(),
                policy_paths: Vec::new(),
            },
            fleet_entries: FleetEntries {
                profiles: vec![profile_entry],
                reports: Vec::new(),
                policies: Vec::new(),
                software: Vec::new(),
            },
            lib_files: LibFiles {
                copy: vec![relative_path],
            },
            scripts: ScriptEntries::default(),
        };

        manifest.save(&output_dir.join("fragment.toml"))?
    };

    if mode == OutputMode::Human {
        println!();
        print_success(&format!(
            "Generated Santa fragment with {} rules in {}",
            rules.len(),
            output_dir.display()
        ));
        print_kv("Fragment manifest", "fragment.toml");
        print_kv("Profile", &filename);

        println!();
        print_info("Next steps:");
        println!(
            "  1. Review the generated fragment in {}",
            output_dir.display()
        );
        println!("  2. Merge into your Fleet GitOps repository");
    }

    Ok(())
}
