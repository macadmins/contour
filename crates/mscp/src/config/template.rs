//! Configuration template generation.

use crate::cli::init::InitOptions;
use crate::config::{
    BaselineConfig, Config, FleetSettings, GitopsGlobConfig, JamfSettings, LabelConfig,
    MunkiSettings, OrganizationSettings, OsquerySettings, OutputConfig, OutputStructure, Settings,
    ValidationConfig,
};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Generate a template configuration file (legacy, uses defaults)
#[allow(dead_code, reason = "reserved for future use")]
pub fn generate_template<P: AsRef<Path>>(output_path: P) -> Result<()> {
    let options = InitOptions {
        domain: None,
        name: None,
        fleet: false,
        jamf: false,
        munki: false,
        baselines: None,
    };
    generate_template_with_options(output_path, &options).map(|_| ())
}

/// Generate a template configuration file with organization options.
///
/// Returns the [`Config`] that was serialized to disk so callers can
/// introspect it (e.g. `mscp init` scaffolds a `fleets/<name>.yml` stub
/// for each unique `[[baselines]].fleet` value the template ended up
/// with).
pub fn generate_template_with_options<P: AsRef<Path>>(
    output_path: P,
    options: &InitOptions,
) -> Result<Config> {
    let output_path = output_path.as_ref();

    let template = create_template_config(options);
    let toml_str = toml::to_string_pretty(&template)?;

    // Add comments to make it more user-friendly
    let commented_toml = add_comments(&toml_str);

    fs::write(output_path, commented_toml)?;
    tracing::info!("Generated template config at: {}", output_path.display());

    Ok(template)
}

/// Unique, sorted fleet names referenced by `[[baselines]].fleet` in the
/// given config. Used by `mscp init` to scaffold matching stub files in
/// `output/fleets/` so `mscp generate` doesn't trip the FleetUpdater
/// validation on the first run.
pub fn referenced_fleet_names(config: &Config) -> Vec<String> {
    let mut names: Vec<String> = config
        .baselines
        .iter()
        .filter_map(|b| b.fleet.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

// `baseline_label(domain, name)` built `com.acme.mscp.cis-lvl1` for the
// template's `[baselines.labels] include_all`. It is gone with its only
// caller: contour generates `mscp-<baseline>` labels, never org-prefixed
// ones, so the name it produced matched nothing in Fleet. That was invisible
// while the section was never read.

/// Create a template configuration with examples
fn create_template_config(options: &InitOptions) -> Config {
    let domain = options
        .domain
        .clone()
        .unwrap_or_else(|| "com.example".to_string());
    let name = options
        .name
        .clone()
        .unwrap_or_else(|| "Example Organization".to_string());

    // Build baseline entries — either from the user-selected list or the static template.
    let baselines = if let Some(ref selected) = options.baselines {
        selected
            .iter()
            .map(|baseline_name| BaselineConfig {
                name: baseline_name.clone(),
                enabled: true,
                branch: None,
                fleet: None,
                labels: LabelConfig {
                    // Empty, deliberately. contour creates `mscp-<baseline>` and
                    // `mscp-<baseline>-remediate`, and a static template cannot
                    // know the other labels in someone's Fleet instance: a label
                    // that does not exist would make every profile reach no
                    // hosts at all.
                    include_all: vec![],
                    include_any: vec![],
                    exclude_any: vec![],
                },
                excluded_rules: vec![],
                metadata: HashMap::new(),
                gitops_glob: GitopsGlobConfig::default(),
            })
            .collect()
    } else {
        // Static template with hardcoded examples (legacy behaviour)
        vec![
            BaselineConfig {
                name: "cis_lvl1".to_string(),
                enabled: true,
                branch: None,
                // Default: no Fleet aggregation. Set to a fleet name (e.g.
                // "workstations") to have `mscp generate` append this
                // baseline's profiles + scripts to `fleets/<name>.yml`.
                // Re-run `mscp init` after editing so a matching stub gets
                // scaffolded in `output/fleets/`.
                fleet: None,
                labels: LabelConfig {
                    include_all: vec![],
                    include_any: vec![],
                    // Was `vec!["cis-exemption"]`, which the run now refuses:
                    // Fleet allows one label field per entry and the baseline
                    // label holds it. Nothing surfaced that while the section
                    // was never read.
                    exclude_any: vec![],
                },
                excluded_rules: vec![],
                metadata: HashMap::new(),
                gitops_glob: GitopsGlobConfig::default(),
            },
            BaselineConfig {
                name: "800-53r5_moderate".to_string(),
                enabled: false,
                branch: None,
                fleet: None,
                labels: LabelConfig {
                    include_all: vec![],
                    include_any: vec![],
                    exclude_any: vec![],
                },
                // Empty, deliberately. An unknown id fails the run, and a
                // static template cannot keep a rule id correct across mSCP
                // releases, where ids are renamed and retagged. The comment
                // block below says how to find real ones.
                excluded_rules: vec![],
                metadata: HashMap::new(),
                gitops_glob: GitopsGlobConfig::default(),
            },
        ]
    };

    Config {
        settings: Settings {
            organization: OrganizationSettings {
                domain: domain.clone(),
                name,
            },
            mscp_repo: PathBuf::from("./macos_security"),
            output_dir: PathBuf::from("./output"),
            python_method: "auto".to_string(),
            verbose: false,
            generate_ddm: false,
            jamf: JamfSettings {
                enabled: options.jamf,
                deterministic_uuids: true,
                no_creation_date: true,
                identical_payload_uuid: false,
                exclude_conflicts: true,
                remove_consent_text: true,
                consent_text: None,
                description_format: Some("mSCP {baseline} - {payload_type}".to_string()),
            },
            fleet: FleetSettings {
                enabled: options.fleet,
                no_labels: false,
            },
            osquery: OsquerySettings::default(),
            munki: MunkiSettings {
                compliance_flags: options.munki,
                compliance_path:
                    crate::transformers::munki_compliance::DEFAULT_COMPLIANCE_PLIST_PATH.to_string(),
                flag_prefix: crate::transformers::munki_compliance::DEFAULT_FLAG_PREFIX.to_string(),
                script_nopkg: options.munki,
                catalog: crate::transformers::munki_compliance::DEFAULT_MUNKI_CATALOG.to_string(),
                category: crate::transformers::munki_compliance::DEFAULT_MUNKI_CATEGORY.to_string(),
                separate_postinstall: false,
            },
        },
        baselines,
        output: OutputConfig {
            structure: if options.munki {
                OutputStructure::Nested
            } else if options.jamf {
                OutputStructure::Flat
            } else {
                OutputStructure::Pluggable
            },
            separate_baselines: None,
            generate_diffs: None,
            versions_to_keep: None,
        },
        validation: ValidationConfig {
            // None, deliberately. This shipped `Some("./schemas")`, a
            // directory nothing creates. It was harmless while `[validation]`
            // was unreachable; now `mscp validate --config` reads it, and a
            // schema path with no schema in it fails the run — so every
            // freshly generated config would have failed its first validate.
            // Fleet's schema has to be fetched deliberately; the comment
            // block says from where.
            schemas_path: None,
            strict: false,
            check_conflicts: None,
            validate_paths: true,
        },
    }
}

/// Add helpful comments to the TOML
fn add_comments(toml_str: &str) -> String {
    format!(
        r#"# mSCP Configuration
# Generated by: contour mscp init
# Documentation: https://github.com/macadmins/contour

{toml_str}
# Configuration Guide:
#
# [settings.organization]
#   domain: Reverse-domain identifier for PayloadIdentifier (e.g., "me.macadmin")
#   name: Organization display name for PayloadOrganization (e.g., "Macadmin")
#
# settings.mscp_repo: Path to a local macos_security checkout.
#   `contour mscp init --sync` clones the mSCP 2.0 layout (the `main`
#   branch) here; `mscp generate` auto-detects 1.x vs 2.0 from the repo.
#
# settings.python_method: "auto" | "uv" | "python3"
#   - auto: Automatically detect (prefers uv if available)
#   - uv: Force use of uv run
#   - python3: Force use of python3
#
# settings.generate_ddm: true | false
#   - Enable to pass --ddm to mSCP for declarative-management artifacts
#
# MDM Modes (can be combined):
#   [settings.fleet] enabled = true — Enable Fleet GitOps mode
#   [settings.jamf]  enabled = true — Enable Jamf Pro mode
#   [settings.munki] compliance_flags = true — Enable Munki integration
#   [settings.osquery] enabled = true — Emit osquery detection
#
# osquery detection ([settings.osquery]):
#   enabled: false (default) | true — the config form of `--osquery`.
#     Config-driven runs read no CLI flags, so this is the only way to ask for
#     osquery output from `generate-all --config`. A `--osquery` flag on a
#     `generate --config` run wins over this setting.
#   format: "fleet" (default) | "pack" — same values as --osquery-format
#   audit: "slim" (default) | "full" — same values as --osquery-audit
#   Requires [output] structure = "pluggable" and a non-empty
#   settings.organization.domain; the run refuses rather than emitting nothing.
#
# Jamf Pro Profile Customization:
#   settings.jamf.remove_consent_text: Remove ConsentText from profiles
#   settings.jamf.consent_text: Custom ConsentText (overrides remove_consent_text)
#   settings.jamf.description_format: Custom PayloadDescription format
#     Placeholders: {{baseline}}, {{payload_type}}, {{org_name}}
#
# [[baselines]]
#   name: Baseline name from mSCP baselines/ directory
#   enabled: true | false
#   branch: Optional git branch — the rule source. "main" (default) carries
#     every platform; an OS-preview branch such as "dev_28" carries the next
#     release early. Not the target platform: use os/os_version for that.
#   fleet: Optional fleet name. When set, `mscp generate` appends this
#     baseline's profiles + scripts to `output/fleets/<name>.yml`. The
#     stub file is scaffolded by `contour mscp init` (or `init --sync`)
#     when [settings.fleet] is enabled — fill in agent_options, secrets,
#     and host labels before running `fleetctl gitops`.
#   [baselines.labels]: Label targeting for progressive rollout
#     include_all: extra labels every profile in this baseline must ALSO
#       carry. They join the generated `mscp-<baseline>` label in Fleet's
#       labels_include_all, so the profile reaches hosts in this baseline AND
#       in every listed label — which is what a staged rollout wants.
#     include_any / exclude_any: NOT emitted, and the run fails if set. Fleet
#       allows one label field per profile entry, and the baseline label
#       already occupies labels_include_all; honouring these would mean
#       dropping it and targeting a different set of hosts. Set them on the
#       entries in the generated team YAML if that is really what you want.
#   excluded_rules: List of rule IDs to skip. Exact ids, as `mscp schema
#     search <term>` prints them — an id that is not in the baseline fails
#     the run rather than being ignored. A profile is dropped only when every
#     rule feeding it is excluded; a partial exclusion keeps the profile and
#     warns. Needs the mSCP repo, which config-driven runs already have.
#
# [validation] — read by `contour mscp validate --config mscp.toml`
#   schemas_path: directory holding Fleet's GitOps JSON Schema,
#     `generated-schema.json` from fleetdm/fleet at
#     tools/gitops-auto-complete/. Unset uses the pinned copy that
#     this build embeds; a build without one says so, and --strict fails.
#     Set to a directory with no schema in it, validate FAILS rather than
#     quietly skipping the check you asked for. Relative paths resolve
#     against this file, not the shell's working directory.
#   strict: fail on warnings. `--strict` turns it on too; neither can turn
#     off what the other asked for.
#   validate_paths: check that every path a team YAML references exists.
#
# [output]
#   structure: "pluggable" | "flat" | "nested"
#     - pluggable: Fleet GitOps layout (v4.83+)
#         platforms/macos/configuration-profiles/<baseline>/, scripts/<baseline>/,
#         policies/<baseline>/, labels/, fleets/<baseline>.yml,
#         mscp/<baseline>/baseline.toml, default.yml
#     - flat: Jamf Pro layout
#         <baseline>/profiles/, scripts/, declarative/
#         No Fleet artifacts. Jamf postprocessing applied from [settings.jamf].
#     - nested: Munki layout
#         <baseline>/profiles/, scripts/, munki/
#         Generates Munki nopkg items from [settings.munki].
"#
    )
}
