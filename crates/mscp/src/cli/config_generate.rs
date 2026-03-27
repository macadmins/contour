use crate::cli::generate::{PythonMethod, generate_baseline, switch_branch};
use crate::config::{Config, OutputStructure};
use crate::transformers::ScriptMode;
use anyhow::Result;

/// Generate baselines from config file
pub fn generate_from_config(config: Config) -> Result<()> {
    tracing::info!("Generating baselines from configuration");

    // Determine Python method
    let python_method = match config.settings.python_method.as_str() {
        "uv" => Some(PythonMethod::Uv),
        "python3" => Some(PythonMethod::Python3),
        _ => None, // Auto-detect
    };

    // Filter enabled baselines
    let enabled_baselines: Vec<_> = config.baselines.iter().filter(|b| b.enabled).collect();

    if enabled_baselines.is_empty() {
        println!("No enabled baselines found in configuration");
        return Ok(());
    }

    println!("Processing {} enabled baseline(s)", enabled_baselines.len());

    // Generate each baseline
    for (i, baseline_config) in enabled_baselines.iter().enumerate() {
        println!(
            "\n[{}/{}] Generating baseline: {}",
            i + 1,
            enabled_baselines.len(),
            baseline_config.name
        );

        // Optional: Show configuration details
        if let Some(ref branch) = baseline_config.branch {
            println!("  Branch: {branch}");
        }
        if !baseline_config.excluded_rules.is_empty() {
            println!("  Excluded rules: {}", baseline_config.excluded_rules.len());
        }
        if let Some(ref team) = baseline_config.team {
            println!("  Team: {team}");
        }

        // Switch branch if specified
        if let Some(ref target_branch) = baseline_config.branch {
            switch_branch(&config.settings.mscp_repo, target_branch)?;
        }

        // Build ProfileOptions from config (general profile transforms, apply in any mode)
        let has_profile_opts = !config.settings.organization.name.is_empty()
            || config.settings.jamf.remove_consent_text
            || config.settings.jamf.consent_text.is_some()
            || config.settings.jamf.deterministic_uuids;
        let profile_options = if has_profile_opts {
            Some(crate::transformers::ProfileOptions {
                org_name: if config.settings.organization.name.is_empty() {
                    None
                } else {
                    Some(config.settings.organization.name.clone())
                },
                remove_consent_text: config.settings.jamf.remove_consent_text,
                consent_text: config.settings.jamf.consent_text.clone(),
                deterministic_uuids: config.settings.jamf.deterministic_uuids,
            })
        } else {
            None
        };

        let structure = config.output.structure.clone();

        // Auto-enable Jamf options when structure is Flat (even without settings.jamf.enabled)
        let jamf_enabled = config.settings.jamf.enabled || structure == OutputStructure::Flat;

        // Build Jamf options from config
        let jamf_options = if jamf_enabled {
            Some(crate::transformers::JamfOptions {
                no_creation_date: config.settings.jamf.no_creation_date,
                identical_payload_uuid: config.settings.jamf.identical_payload_uuid,
                baseline: Some(baseline_config.name.clone()),
                domain: Some(config.settings.organization.domain.clone()),
                org_name: Some(config.settings.organization.name.clone()),
                description_format: config.settings.jamf.description_format.clone(),
            })
        } else {
            None
        };

        // Auto-enable Munki options when structure is Nested (even without explicit flags)
        let munki_compliance_enabled =
            config.settings.munki.compliance_flags || structure == OutputStructure::Nested;

        // Build Munki compliance options from config
        let munki_compliance_options = if munki_compliance_enabled {
            Some(crate::transformers::MunkiComplianceOptions {
                target_path: std::path::PathBuf::from(&config.settings.munki.compliance_path),
                flag_prefix: config.settings.munki.flag_prefix.clone(),
            })
        } else {
            None
        };

        let munki_script_enabled =
            config.settings.munki.script_nopkg || structure == OutputStructure::Nested;

        // Build Munki script options from config
        let munki_script_options = if munki_script_enabled {
            Some(crate::transformers::MunkiScriptOptions {
                catalog: config.settings.munki.catalog.clone(),
                category: config.settings.munki.category.clone(),
                display_name_prefix: "mSCP".to_string(),
                embed_fix_in_installcheck: !config.settings.munki.separate_postinstall,
            })
        } else {
            None
        };

        // Fleet mode is enabled when structure is pluggable or explicitly enabled
        let fleet_mode = config.settings.fleet.enabled || structure == OutputStructure::Pluggable;

        generate_baseline(
            config.settings.mscp_repo.clone(),
            baseline_config.name.clone(),
            config.settings.output_dir.clone(),
            python_method,
            profile_options,
            jamf_options,
            munki_compliance_options,
            munki_script_options,
            config.settings.fleet.no_labels,
            baseline_config.team.as_ref().map(|t| vec![t.clone()]), // team_names from config
            fleet_mode,
            config.settings.jamf.exclude_conflicts,
            config.settings.generate_ddm,     // generate_ddm from config
            false,                            // dry_run - always false for config-based generation
            crate::output::OutputMode::Human, // Always use human output for config-based generation
            false,               // batch_mode - false for config-based individual generation
            ScriptMode::Bundled, // Default to bundled mode for config-based generation
            None,                // exclude_categories - not supported in config-based generation
            false,               // fragment - not supported in config-based generation
            structure.clone(),
        )?;
    }

    println!("\n✓ All baselines generated successfully!");

    // Optional: Run validation if enabled
    if config.validation.check_conflicts {
        println!("\nRunning conflict detection...");
        // TODO: Implement cross-baseline conflict check
    }

    Ok(())
}
