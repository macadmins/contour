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
    pub fleet_names: Option<Vec<String>>,
    /// osquery detection, from `[settings.osquery]`.
    ///
    /// `None` when the section is absent or `enabled = false`. Config-driven
    /// generation reads no CLI flags, so without this there was no way to ask
    /// for osquery output at all — `generate-all --config` simply never
    /// emitted any, and said nothing about it.
    pub osquery_options: Option<crate::osquery::OsqueryGenOptions>,
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
            org_domain: None,
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

    // The Fleet updater only fires when we're producing Fleet output —
    // i.e. `[settings.fleet] enabled = true` OR `[output] structure = "pluggable"`.
    // A bare `[[baselines]] fleet = "..."` field should NOT pull the updater
    // in when the user targeted Jamf (`flat`) or Munki (`nested`), otherwise
    // a missing `fleets/<name>.yml` aborts the whole run for an MDM that
    // doesn't even consume that file.
    let fleet_names = if fleet_mode {
        baseline_config.fleet.as_ref().map(|t| vec![t.clone()])
    } else {
        None
    };

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
        fleet_names,
        // No CLI flags reach this path, so the config section alone decides.
        osquery_options: resolve_osquery_options(config, None),
    }
}

/// Decide whether a config-driven run emits osquery detection, and how.
///
/// Config-driven generation has two possible sources and had neither wired:
/// `generate --config … --osquery` passed the flag into a hardcoded `None`,
/// and `generate-all --config` had no flag to pass. Both call this now, so
/// the precedence is written once instead of three times differently.
///
/// - `cli` is `Some` only when `--osquery` was actually passed. It wins, and
///   carries the `--osquery-format` / `--osquery-audit` values with it.
/// - Otherwise `[settings.osquery] enabled` decides, with the format and
///   audit from that section.
/// - The org is the CLI `--org` when given, else `[settings.organization]
///   domain`. An empty result is left empty on purpose: `--osquery` refuses a
///   run with no org rather than inventing one, and that refusal is the right
///   place for it to surface.
pub fn resolve_osquery_options(
    config: &Config,
    cli: Option<crate::osquery::OsqueryGenOptions>,
) -> Option<crate::osquery::OsqueryGenOptions> {
    let from_config = || config.settings.organization.domain.clone();
    match cli {
        Some(mut opts) => {
            if opts.org.as_deref().is_none_or(str::is_empty) {
                opts.org = Some(from_config());
            }
            Some(opts)
        }
        None => config
            .settings
            .osquery
            .enabled
            .then(|| crate::osquery::OsqueryGenOptions {
                format: config.settings.osquery.format.clone(),
                audit: config.settings.osquery.audit.clone(),
                org: Some(from_config()),
            }),
    }
}

/// Generate baselines from config file
pub fn generate_from_config(config: Config) -> Result<()> {
    tracing::info!("Generating baselines from configuration");

    warn_dual_mdm_enabled(&config);

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
        // process_baseline reports what the exclusion actually did — rules
        // matched, profiles dropped, scripts suppressed — which is the number
        // worth seeing, not the count of ids in the config.
        if let Some(ref fleet) = baseline_config.fleet {
            println!("  Fleet: {fleet}");
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
            opts.fleet_names,
            false, // fleet_glob — --glob is a CLI-flag-mode option
            None,  // fleet_label
            opts.fleet_mode,
            opts.jamf_exclude_conflicts,
            opts.generate_ddm,
            false, // dry_run - always false for config-based generation
            crate::output::OutputMode::Human, // Always use human output for config-based generation
            false, // batch_mode - false for config-based individual generation
            ScriptMode::Bundled, // Default to bundled mode for config-based generation
            None,  // exclude_categories - not supported in config-based generation
            // The setting this whole path exists to honour. It was parsed,
            // counted and printed here, and then not passed — see the note
            // where it is applied in process.rs.
            Some(baseline_config.excluded_rules.clone()),
            // [baselines.labels] — the other setting this path parsed and dropped.
            Some(baseline_config.labels.clone()),
            false, // fragment - not supported in config-based generation
            opts.structure,
            Some(baseline_config.gitops_glob.clone()),
            "macos".to_string(), // os
            None,                // os_version
            None,                // odv_path — auto-detects odv_<baseline>.yaml per baseline
            opts.osquery_options,
        )?;
    }

    println!("\n✓ All baselines generated successfully!");

    Ok(())
}

/// Emit a one-line stderr warning when both `[settings.jamf] enabled` and
/// `[settings.fleet] enabled` are true. The two flags are orthogonal —
/// `jamf` shapes profile content, `fleet` shapes output bundling — and a
/// user can legitimately want both. But the combination is rarely
/// intentional, so we surface the resulting layout so a misconfiguration
/// becomes obvious in the build log instead of producing surprising output.
fn warn_dual_mdm_enabled(config: &Config) {
    if config.settings.jamf.enabled && config.settings.fleet.enabled {
        tracing::warn!(
            "Both `[settings.jamf] enabled` and `[settings.fleet] enabled` are true. \
             Producing Jamf-shaped profiles inside the `{}` GitOps layout. \
             Disable one in mscp.toml if that's not what you want.",
            config.output.structure
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GitopsGlobConfig, LabelConfig};
    use std::collections::HashMap;

    /// Build a minimal `BaselineConfig` for tests — `BaselineConfig` has
    /// no `Default`, so each test would otherwise repeat this scaffold.
    fn baseline_with_fleet(fleet: Option<&str>) -> BaselineConfig {
        BaselineConfig {
            name: "cis_lvl1".to_string(),
            enabled: true,
            branch: None,
            fleet: fleet.map(str::to_string),
            labels: LabelConfig::default(),
            excluded_rules: vec![],
            metadata: HashMap::default(),
            gitops_glob: GitopsGlobConfig::default(),
        }
    }

    #[test]
    fn fleet_names_dropped_when_structure_is_flat_and_fleet_disabled() {
        // Jamf-typical setup: `output.structure = "flat"`, fleet disabled.
        // Even with a per-baseline `fleet = "workstations"` set, the
        // Fleet updater must not fire — otherwise a Jamf-only run aborts
        // on a missing `fleets/workstations.yml`.
        let mut config = Config::default();
        config.output.structure = OutputStructure::Flat;
        config.settings.fleet.enabled = false;

        let opts = build_options_from_config(&config, &baseline_with_fleet(Some("workstations")));

        assert!(
            opts.fleet_names.is_none(),
            "fleet_names must be None when fleet_mode is off; got {:?}",
            opts.fleet_names
        );
        assert!(!opts.fleet_mode);
    }

    #[test]
    fn fleet_names_propagated_when_structure_is_pluggable() {
        // Default Pluggable structure means fleet_mode is on, so the
        // per-baseline fleet field must propagate.
        let mut config = Config::default();
        config.output.structure = OutputStructure::Pluggable;

        let opts = build_options_from_config(&config, &baseline_with_fleet(Some("workstations")));

        assert_eq!(
            opts.fleet_names.as_deref(),
            Some(&["workstations".to_string()][..])
        );
        assert!(opts.fleet_mode);
    }

    #[test]
    fn fleet_names_propagated_when_flat_but_fleet_explicitly_enabled() {
        // Edge case: user picked Flat structure but also set
        // `[settings.fleet] enabled = true`. They asked for both — let
        // the updater run.
        let mut config = Config::default();
        config.output.structure = OutputStructure::Flat;
        config.settings.fleet.enabled = true;

        let opts = build_options_from_config(&config, &baseline_with_fleet(Some("workstations")));

        assert_eq!(
            opts.fleet_names.as_deref(),
            Some(&["workstations".to_string()][..])
        );
        assert!(opts.fleet_mode);
    }

    #[test]
    fn fleet_names_none_when_baseline_fleet_field_unset() {
        let config = Config::default();
        let opts = build_options_from_config(&config, &baseline_with_fleet(None));
        assert!(opts.fleet_names.is_none());
    }
}

#[cfg(test)]
mod osquery_plumbing_tests {
    use super::*;
    use crate::osquery::OsqueryGenOptions;

    fn config_with(enabled: bool, domain: &str) -> Config {
        let mut c = Config::default();
        c.settings.organization.domain = domain.to_string();
        c.settings.osquery.enabled = enabled;
        c
    }

    fn cli(format: &str, audit: &str, org: Option<&str>) -> OsqueryGenOptions {
        OsqueryGenOptions {
            format: format.to_string(),
            audit: audit.to_string(),
            org: org.map(str::to_string),
        }
    }

    /// The flag must survive the config path.
    ///
    /// This is the bug. `generate --config mscp.toml --osquery` built the
    /// options and then passed a hardcoded `None` into `generate_baseline` at
    /// two call sites. The command succeeded, wrote no osquery tree, and said
    /// nothing — a flag accepted and discarded.
    #[test]
    fn the_cli_flag_is_not_dropped_on_the_config_path() {
        let opts = resolve_osquery_options(
            &config_with(false, "com.acme"),
            Some(cli("pack", "full", Some("com.cli"))),
        )
        .expect("--osquery was passed; it must reach the generator");
        assert_eq!(opts.format, "pack");
        assert_eq!(opts.audit, "full");
        assert_eq!(opts.org.as_deref(), Some("com.cli"));
    }

    /// `[settings.osquery]` is the only way `generate-all --config` can ask.
    ///
    /// That path reads no flags at all, so without the section there was no
    /// way to get osquery output from a config-driven run of any size.
    #[test]
    fn the_config_section_drives_a_run_with_no_flags() {
        let mut c = config_with(true, "com.acme");
        c.settings.osquery.format = "pack".into();
        c.settings.osquery.audit = "full".into();
        let opts = resolve_osquery_options(&c, None).expect("enabled = true must emit");
        assert_eq!(opts.format, "pack");
        assert_eq!(opts.audit, "full");
        assert_eq!(opts.org.as_deref(), Some("com.acme"));
    }

    /// Off by default, and off is off.
    #[test]
    fn nothing_is_emitted_when_neither_asks() {
        assert!(resolve_osquery_options(&config_with(false, "com.acme"), None).is_none());
        assert!(
            !Config::default().settings.osquery.enabled,
            "the section must default to off — enabling osquery for every existing \
             mscp.toml on upgrade would be a silent change in what gets written"
        );
    }

    /// The flag wins over the section, including when the section says off.
    ///
    /// Stated as its own test because the opposite rule is just as plausible
    /// and would be just as quiet: an operator adding `--osquery` to a run
    /// whose config says `enabled = false` is asking for it this once.
    #[test]
    fn the_flag_overrides_the_section_in_both_directions() {
        let on = config_with(true, "com.acme");
        let from_flag =
            resolve_osquery_options(&on, Some(cli("pack", "full", None))).expect("flag present");
        assert_eq!(
            from_flag.format, "pack",
            "the flag's format must win over the section's"
        );

        let off = config_with(false, "com.acme");
        assert!(
            resolve_osquery_options(&off, Some(cli("fleet", "slim", None))).is_some(),
            "--osquery must work against a config that has the section off"
        );
    }

    /// A missing org falls through to the refusal, rather than being invented.
    ///
    /// `--osquery` errors downstream when no org resolves, and that is the
    /// right place for it: the message names the three ways to supply one.
    /// Filling in a placeholder here would produce artifacts under a launchd
    /// label and plist path that belong to nobody.
    #[test]
    fn an_absent_org_is_carried_through_empty_not_invented() {
        let mut c = config_with(true, "");
        c.settings.osquery.enabled = true;
        let opts = resolve_osquery_options(&c, None).expect("enabled");
        assert_eq!(
            opts.org.as_deref(),
            Some(""),
            "an empty domain must stay empty so the downstream refusal fires"
        );

        // The CLI's own empty org is backfilled from config, which is the
        // only substitution this function makes.
        let filled = resolve_osquery_options(
            &config_with(false, "com.acme"),
            Some(cli("fleet", "slim", None)),
        )
        .expect("flag present");
        assert_eq!(filled.org.as_deref(), Some("com.acme"));
    }
}
