use crate::cli::generate::{PythonMethod, generate_baseline, switch_branch};
use crate::config::{BaselineConfig, Config, OutputStructure};
use crate::transformers::{
    JamfOptions, MunkiComplianceOptions, MunkiScriptOptions, ProfileOptions, ScriptMode,
};
use anyhow::Result;

/// Bundle of options derived from a [`Config`] + [`BaselineConfig`] for a single baseline.
#[derive(Debug)]
pub struct ConfigDerivedOptions {
    pub profile_options: Option<ProfileOptions>,
    pub jamf_options: Option<JamfOptions>,
    pub munki_compliance_options: Option<MunkiComplianceOptions>,
    pub munki_script_options: Option<MunkiScriptOptions>,
    pub fleet_mode: bool,
    pub no_labels: bool,
    pub structure: OutputStructure,
    pub jamf_exclude_conflicts: bool,
    pub generate_ddm: bool,
    pub team_names: Option<Vec<String>>,
}

/// Build option bundle from config for a single baseline.
/// Mirrors the per-baseline mapping in [`generate_from_config`], factored out
/// so the single-baseline `Generate` command can reuse it.
pub fn build_options_from_config(
    config: &Config,
    baseline_config: &BaselineConfig,
) -> ConfigDerivedOptions {
    let structure = config.output.structure.clone();

    let has_profile_opts = !config.settings.organization.name.is_empty()
        || config.settings.jamf.remove_consent_text
        || config.settings.jamf.consent_text.is_some()
        || config.settings.jamf.deterministic_uuids;
    let profile_options = if has_profile_opts {
        Some(ProfileOptions {
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

    // Auto-enable Jamf options when structure is Flat (even without settings.jamf.enabled)
    let jamf_enabled = config.settings.jamf.enabled || structure == OutputStructure::Flat;
    let jamf_options = if jamf_enabled {
        Some(JamfOptions {
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
    let munki_compliance_options = if munki_compliance_enabled {
        Some(MunkiComplianceOptions {
            target_path: std::path::PathBuf::from(&config.settings.munki.compliance_path),
            flag_prefix: config.settings.munki.flag_prefix.clone(),
        })
    } else {
        None
    };

    let munki_script_enabled =
        config.settings.munki.script_nopkg || structure == OutputStructure::Nested;
    let munki_script_options = if munki_script_enabled {
        Some(MunkiScriptOptions {
            catalog: config.settings.munki.catalog.clone(),
            category: config.settings.munki.category.clone(),
            display_name_prefix: "mSCP".to_string(),
            embed_fix_in_installcheck: !config.settings.munki.separate_postinstall,
        })
    } else {
        None
    };

    // Fleet mode enabled when structure is pluggable or explicitly enabled
    let fleet_mode = config.settings.fleet.enabled || structure == OutputStructure::Pluggable;

    ConfigDerivedOptions {
        profile_options,
        jamf_options,
        munki_compliance_options,
        munki_script_options,
        fleet_mode,
        no_labels: config.settings.fleet.no_labels,
        structure,
        jamf_exclude_conflicts: config.settings.jamf.exclude_conflicts,
        generate_ddm: config.settings.generate_ddm,
        team_names: baseline_config.team.as_ref().map(|t| vec![t.clone()]),
    }
}

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

        let opts = build_options_from_config(&config, baseline_config);

        generate_baseline(
            config.settings.mscp_repo.clone(),
            baseline_config.name.clone(),
            config.settings.output_dir.clone(),
            python_method,
            opts.profile_options,
            opts.jamf_options,
            opts.munki_compliance_options,
            opts.munki_script_options,
            opts.no_labels,
            opts.team_names,
            opts.fleet_mode,
            opts.jamf_exclude_conflicts,
            opts.generate_ddm,
            false, // dry_run - always false for config-based generation
            crate::output::OutputMode::Human, // Always use human output for config-based generation
            false, // batch_mode - false for config-based individual generation
            ScriptMode::Bundled, // Default to bundled mode for config-based generation
            None,  // exclude_categories - not supported in config-based generation
            false, // fragment - not supported in config-based generation
            opts.structure,
            Some(baseline_config.gitops_glob.clone()),
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
