//! Configuration template generation.

use crate::cli::init::InitOptions;
use crate::config::{
    BaselineConfig, Config, FleetSettings, GitopsGlobConfig, JamfSettings, LabelConfig,
    MunkiSettings, OrganizationSettings, OutputConfig, OutputStructure, Settings,
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
    generate_template_with_options(output_path, &options)
}

/// Generate a template configuration file with organization options
pub fn generate_template_with_options<P: AsRef<Path>>(
    output_path: P,
    options: &InitOptions,
) -> Result<()> {
    let output_path = output_path.as_ref();

    let template = create_template_config(options);
    let toml_str = toml::to_string_pretty(&template)?;

    // Add comments to make it more user-friendly
    let commented_toml = add_comments(&toml_str);

    fs::write(output_path, commented_toml)?;
    tracing::info!("Generated template config at: {}", output_path.display());

    Ok(())
}

/// Build a label name from domain and baseline name.
///
/// Replaces `_` with `-` in the baseline name:
///   `("com.acme", "cis_lvl1")` → `"com.acme.mscp.cis-lvl1"`
fn baseline_label(domain: &str, baseline_name: &str) -> String {
    format!("{domain}.mscp.{}", baseline_name.replace('_', "-"))
}

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
                team: None,
                labels: LabelConfig {
                    include_all: vec![baseline_label(&domain, baseline_name)],
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
                team: Some("workstations".to_string()),
                labels: LabelConfig {
                    include_all: vec![format!("{domain}.mscp.cis-lvl1")],
                    include_any: vec![],
                    exclude_any: vec!["cis-exemption".to_string()],
                },
                excluded_rules: vec![],
                metadata: {
                    let mut map = HashMap::new();
                    map.insert(
                        "description".to_string(),
                        "CIS Level 1 for workstations".to_string(),
                    );
                    map
                },
                gitops_glob: GitopsGlobConfig::default(),
            },
            BaselineConfig {
                name: "800-53r5_moderate".to_string(),
                enabled: false,
                branch: None,
                team: Some("servers".to_string()),
                labels: LabelConfig {
                    include_all: vec![format!("{domain}.mscp.800-53-moderate")],
                    include_any: vec![],
                    exclude_any: vec![],
                },
                excluded_rules: vec!["os_sshd_permit_root_login".to_string()],
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
            separate_baselines: true,
            generate_diffs: true,
            versions_to_keep: 5,
        },
        validation: ValidationConfig {
            schemas_path: Some(PathBuf::from("./schemas")),
            strict: false,
            check_conflicts: true,
            validate_paths: true,
        },
    }
}

/// Add helpful comments to the TOML
fn add_comments(toml_str: &str) -> String {
    format!(
        r#"# mSCP Configuration
# Generated by: contour mscp init
# Documentation: https://github.com/headmin/contour

{toml_str}
# Configuration Guide:
#
# [settings.organization]
#   domain: Reverse-domain identifier for PayloadIdentifier (e.g., "me.macadmin")
#   name: Organization display name for PayloadOrganization (e.g., "Macadmin")
#
# settings.python_method: "auto" | "uv" | "python3"
#   - auto: Automatically detect (prefers uv if available)
#   - uv: Force use of uv run
#   - python3: Force use of python3
#
# settings.generate_ddm: true | false
#   - Enable to pass -D flag to mSCP for DDM artifacts
#
# MDM Modes (can be combined):
#   [settings.fleet] enabled = true — Enable Fleet GitOps mode
#   [settings.jamf]  enabled = true — Enable Jamf Pro mode
#   [settings.munki] compliance_flags = true — Enable Munki integration
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
#   branch: Optional git branch (e.g., "sequoia", "ios_18")
#   team: Optional team name for Fleet
#   [baselines.labels]: Label targeting for progressive rollout
#     include_all: All these labels must be present
#     include_any: At least one of these labels must be present
#     exclude_any: None of these labels can be present
#   excluded_rules: List of rule IDs to skip
#
# [output]
#   structure: "pluggable" | "flat" | "nested"
#     - pluggable: Fleet GitOps layout
#         lib/mscp/<baseline>/profiles/, scripts/, policies/
#         lib/all/labels/, fleets/<baseline>.yml, default.yml
#     - flat: Jamf Pro layout
#         <baseline>/profiles/, scripts/, declarative/
#         No Fleet artifacts. Jamf postprocessing applied from [settings.jamf].
#     - nested: Munki layout
#         <baseline>/profiles/, scripts/, munki/
#         Generates Munki nopkg items from [settings.munki].
"#
    )
}
