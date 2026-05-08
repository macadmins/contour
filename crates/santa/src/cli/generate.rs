use crate::generator::{Format, GeneratorOptions, build_santa_payload, write_to_file_format};
use crate::models::RuleSet;
use crate::output::{
    CommandResult, OutputMode, print_error, print_info, print_json, print_kv, print_success,
};
use crate::parser::parse_files;
use crate::validator::validate_ruleset;
use anyhow::{Context, Result};
use contour_core::fragment::{
    DefaultYmlEntries, FleetEntries, FragmentManifest, FragmentMeta, LibFiles, ProfileEntry,
    ScriptEntries,
};
use contour_profiles::{
    IdentifierType, RecipeProfile, TccAuthorization, build_notification_entry,
    build_tcc_entry_with_authorization, write_recipe_toml,
};
use plist::{Dictionary, Value};
use serde::Serialize;
use std::path::Path;

/// Northpole's published Team ID for the Santa daemon — used by the
/// `--full-bundle` recipe path to author TCC + system-extension and
/// notification entries that match Santa's signed binaries. Vendor
/// forks would override these by editing the rendered recipe TOML
/// directly.
const NORTHPOLE_TEAM_ID: &str = "EQHXZ8M8AV";
const SANTA_DAEMON_BUNDLE: &str = "com.northpolesec.santa.daemon";
const SANTA_GUI_BUNDLE: &str = "com.northpolesec.santa";
/// Designated Code Requirement for Northpole-signed Santa binaries.
const NORTHPOLE_CODE_REQ: &str = "anchor apple generic and certificate \
    1[field.1.2.840.113635.100.6.2.6] /* exists */ and \
    certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and \
    certificate leaf[subject.OU] = EQHXZ8M8AV";

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
    full_bundle: bool,
    dry_run: bool,
    fragment: bool,
    mode: OutputMode,
) -> Result<()> {
    // Parse all input files
    let rules = parse_files(inputs)?;

    // Recipe TOML emission: drops into a contour preset/recipe library
    // for later `contour profile generate --recipe …` use. Default
    // shape is the single `com.northpolesec.santa` profile;
    // `--full-bundle` adds the satellite TCC/sysext/notifications
    // profiles using Northpole's published identities.
    //
    // Recipe + fragment is nonsensical (fragment is a Fleet GitOps
    // directory layout) — recipe wins.
    if matches!(output_format, OutputFormat::Recipe) {
        return run_recipe(&rules, output, org, full_bundle, mode);
    }

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

    // Determine output extension and format. The `Recipe` arm is
    // unreachable here because `run_recipe` returned above, but the
    // match must still be exhaustive.
    let (format, default_ext) = match output_format {
        OutputFormat::Mobileconfig | OutputFormat::Recipe => (Format::Mobileconfig, "mobileconfig"),
        OutputFormat::Plist => (Format::Plist, "plist"),
        OutputFormat::PlistFull => (Format::PlistFull, "plist"),
    };

    let output_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new(&format!("santa-rules.{}", default_ext)).to_path_buf());

    let format_name = match output_format {
        OutputFormat::Mobileconfig | OutputFormat::Recipe => "mobileconfig",
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

/// Emit a recipe TOML for the contour preset/recipe library.
///
/// Narrow shape (default): one `[[profile]]` block carrying the
/// `com.northpolesec.santa` payload built from `rules`. Operators
/// drop this into their recipe library and later render via
/// `contour profile generate --recipe …`.
///
/// `--full-bundle`: prepends three more `[[profile]]` blocks for a
/// complete Santa deployment — TCC (Full Disk Access), system
/// extension, and notification settings — using Northpole's published
/// identities. Vendor forks override by editing the resulting TOML.
fn run_recipe(
    rules: &RuleSet,
    output: Option<&Path>,
    org: &str,
    full_bundle: bool,
    mode: OutputMode,
) -> Result<()> {
    // Validate before authoring — recipe consumers shouldn't see a
    // half-broken ruleset round-trip cleanly.
    let validation = validate_ruleset(rules);
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

    let mut profiles: Vec<RecipeProfile> = Vec::new();

    if full_bundle {
        profiles.push(build_sysext_profile());
        profiles.push(build_tcc_profile());
        profiles.push(build_notifications_profile());
    }

    profiles.push(RecipeProfile {
        filename: "santa-rules.mobileconfig".to_string(),
        payload_type: "com.northpolesec.santa".to_string(),
        display_name: "Santa Rules".to_string(),
        description: "Santa binary authorization rules".to_string(),
        removal_disallowed: true,
        fields: build_santa_payload(rules),
    });

    let body = write_recipe_toml(
        "santa",
        "Santa rules recipe (com.northpolesec.santa) generated from rule files",
        Some(org),
        &profiles,
    )?;

    let output_path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new("santa.toml").to_path_buf());
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output_path, &body)
        .with_context(|| format!("Failed to write recipe TOML to {}", output_path.display()))?;

    if mode == OutputMode::Human {
        print_success(&format!(
            "Generated Santa recipe TOML with {} profile(s) and {} rules",
            profiles.len(),
            rules.rules().len()
        ));
        print_kv("Recipe", &output_path.display().to_string());
        if full_bundle {
            print_info(
                "Full bundle includes TCC (FDA), system extension, and notification settings",
            );
            print_info(&format!(
                "Identities default to Northpole (Team ID {NORTHPOLE_TEAM_ID}); edit the TOML for vendor forks"
            ));
        }
        print_info(&format!(
            "Render with: contour profile generate --recipe {} --org <YOUR_ORG> -o ./out",
            output_path.display()
        ));
    } else {
        print_json(&CommandResult::success(GenerateOutput {
            rules_count: rules.rules().len(),
            output_path: Some(output_path.display().to_string()),
            identifier: format!("{org}.santa.rules"),
            format: "recipe".to_string(),
        }))?;
    }
    Ok(())
}

/// Build the `com.apple.system-extension-policy` profile entry that
/// authorizes Santa's endpoint security extension.
fn build_sysext_profile() -> RecipeProfile {
    let mut allowed_team_ids = Dictionary::new();
    allowed_team_ids.insert(
        NORTHPOLE_TEAM_ID.to_string(),
        Value::Array(vec![Value::String("EndpointSecurity".to_string())]),
    );

    let mut fields = Dictionary::new();
    fields.insert("AllowUserOverrides".to_string(), Value::Boolean(false));
    fields.insert(
        "AllowedSystemExtensionTypes".to_string(),
        Value::Dictionary(allowed_team_ids),
    );
    fields.insert(
        "AllowedTeamIdentifiers".to_string(),
        Value::Array(vec![Value::String(NORTHPOLE_TEAM_ID.to_string())]),
    );

    RecipeProfile {
        filename: "santa-system-extension.mobileconfig".to_string(),
        payload_type: "com.apple.system-extension-policy".to_string(),
        display_name: "Santa System Extension".to_string(),
        description: "Authorizes Santa's Endpoint Security system extension".to_string(),
        removal_disallowed: true,
        fields,
    }
}

/// Build the `com.apple.TCC.configuration-profile-policy` profile
/// granting Full Disk Access to the Santa daemon.
fn build_tcc_profile() -> RecipeProfile {
    let entry = build_tcc_entry_with_authorization(
        SANTA_DAEMON_BUNDLE,
        NORTHPOLE_CODE_REQ,
        TccAuthorization::Allow,
        IdentifierType::BundleID,
    );

    let mut services = Dictionary::new();
    services.insert(
        "SystemPolicyAllFiles".to_string(),
        Value::Array(vec![entry]),
    );

    let mut fields = Dictionary::new();
    fields.insert("Services".to_string(), Value::Dictionary(services));

    RecipeProfile {
        filename: "santa-tcc.mobileconfig".to_string(),
        payload_type: "com.apple.TCC.configuration-profile-policy".to_string(),
        display_name: "Santa Privacy Preferences".to_string(),
        description: "Grants Santa daemon Full Disk Access".to_string(),
        removal_disallowed: true,
        fields,
    }
}

/// Build the `com.apple.notificationsettings` profile enabling alerts
/// for the Santa GUI.
fn build_notifications_profile() -> RecipeProfile {
    let entry = build_notification_entry(SANTA_GUI_BUNDLE);
    let mut fields = Dictionary::new();
    fields.insert(
        "NotificationSettings".to_string(),
        Value::Array(vec![Value::Dictionary(entry)]),
    );

    RecipeProfile {
        filename: "santa-notifications.mobileconfig".to_string(),
        payload_type: "com.apple.notificationsettings".to_string(),
        display_name: "Santa Notifications".to_string(),
        description: "Enables Santa block/allow notification banners".to_string(),
        removal_disallowed: true,
        fields,
    }
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

    // Recipe is unreachable for fragment mode (entry guards on
    // Recipe before reaching here), but the match must be exhaustive.
    let (format, default_ext) = match output_format {
        OutputFormat::Mobileconfig | OutputFormat::Recipe => (Format::Mobileconfig, "mobileconfig"),
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
    let fleets_dir = output_dir.join(layout.fleets_dir);
    std::fs::create_dir_all(&profiles_dir)?;
    std::fs::create_dir_all(&fleets_dir)?;

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

    // Generate fleets/reference-fleet.yml
    {
        use std::fmt::Write;
        let mut content = String::from(
            "# Fleet GitOps - Fleet Configuration: Santa Rules\n\
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
        std::fs::write(fleets_dir.join("reference-fleet.yml"), &content)?
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
