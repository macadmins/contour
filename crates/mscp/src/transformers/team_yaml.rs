// Team YAML transformers - public API
#![allow(dead_code, reason = "module under development")]

use crate::models::{
    BaselineReference, Controls, CustomSetting, FleetTeamConfig, MscpBaseline, Platform,
    PlatformSettings, Script,
};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Generator for `FleetDM` team YAML files and baseline components
#[derive(Debug)]
pub struct TeamYamlGenerator {
    output_base: PathBuf,
}

impl TeamYamlGenerator {
    pub fn new<P: AsRef<Path>>(output_base: P) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
        }
    }

    /// Generate a composable baseline component (lib/mscp/{baseline}/baseline.yml)
    /// This creates a reusable baseline definition that fleets can reference
    pub fn generate_baseline_component(
        &self,
        baseline: &MscpBaseline,
        profile_paths: &[PathBuf],
        script_paths: &[(PathBuf, Option<PathBuf>)], // (audit, remediate)
    ) -> Result<FleetTeamConfig> {
        // Create custom settings for each profile
        let mut custom_settings = Vec::new();
        for profile_path in profile_paths {
            let relative_path = self.get_relative_path_from_lib(profile_path, &baseline.name)?;
            custom_settings.push(CustomSetting {
                path: relative_path,
                labels_include_all: Some(vec![format!("mscp-{}", baseline.name)]),
                labels_include_any: None,
                labels_exclude_any: None,
            });
        }

        // Create script references
        // NOTE: Fleet GitOps scripts only support path (no label targeting)
        let mut scripts = Vec::new();
        for (audit_path, remediate_path) in script_paths {
            let audit_relative = self.get_relative_path_from_lib(audit_path, &baseline.name)?;
            scripts.push(Script {
                path: audit_relative,
            });

            if let Some(remediate) = remediate_path {
                let remediate_relative =
                    self.get_relative_path_from_lib(remediate, &baseline.name)?;
                scripts.push(Script {
                    path: remediate_relative,
                });
            }
        }

        // Use appropriate settings field based on platform
        let (macos_settings, ios_settings) = match baseline.platform {
            Platform::MacOS => (
                Some(PlatformSettings {
                    custom_settings: if custom_settings.is_empty() {
                        None
                    } else {
                        Some(custom_settings)
                    },
                }),
                None,
            ),
            Platform::Ios | Platform::VisionOS => (
                None,
                Some(PlatformSettings {
                    custom_settings: if custom_settings.is_empty() {
                        None
                    } else {
                        Some(custom_settings)
                    },
                }),
            ),
        };

        let config = FleetTeamConfig {
            name: None, // No team name in baseline component
            controls: Some(Controls {
                macos_settings,
                ios_settings,
                scripts: if scripts.is_empty() {
                    None
                } else {
                    Some(scripts)
                },
            }),
            policies: None,      // Not needed in baseline component
            reports: None,       // Not needed in baseline component
            agent_options: None, // Not needed in baseline component
            settings: None,      // Not needed in baseline component
            software: None,      // Not needed in baseline component
        };

        Ok(config)
    }

    /// Write the baseline component to mscp/{baseline}/baseline.toml (Fleet v4.83+ top-level)
    pub fn write_baseline_component(
        &self,
        config: &FleetTeamConfig,
        baseline_name: &str,
        platform: Platform,
    ) -> Result<PathBuf> {
        let baseline_dir = self.output_base.join("mscp").join(baseline_name);
        std::fs::create_dir_all(&baseline_dir)?;

        let file_path = baseline_dir.join("baseline.toml");

        // Convert FleetTeamConfig to BaselineReference (TOML format)
        let baseline_ref =
            self.fleet_config_to_baseline_reference(config, baseline_name, platform)?;
        let toml_content = baseline_ref.to_toml_string()?;

        std::fs::write(&file_path, toml_content)?;

        tracing::info!("Wrote baseline component: {:?}", file_path);
        Ok(file_path)
    }

    /// Convert `FleetTeamConfig` to `BaselineReference` (TOML format)
    fn fleet_config_to_baseline_reference(
        &self,
        config: &FleetTeamConfig,
        baseline_name: &str,
        platform: Platform,
    ) -> Result<BaselineReference> {
        let mut baseline_ref = BaselineReference::new(
            baseline_name.to_string(),
            platform.to_string().to_lowercase(),
        );

        // Extract profiles from controls
        if let Some(ref controls) = config.controls {
            // macOS profiles
            if let Some(ref macos_settings) = controls.macos_settings
                && let Some(ref custom_settings) = macos_settings.custom_settings
            {
                for setting in custom_settings {
                    baseline_ref.add_profile(
                        setting.path.clone(),
                        setting.labels_include_all.clone().unwrap_or_default(),
                    );
                }
            }

            // iOS/iPadOS profiles
            if let Some(ref ios_settings) = controls.ios_settings
                && let Some(ref custom_settings) = ios_settings.custom_settings
            {
                for setting in custom_settings {
                    baseline_ref.add_profile(
                        setting.path.clone(),
                        setting.labels_include_all.clone().unwrap_or_default(),
                    );
                }
            }

            // Scripts
            // NOTE: Fleet scripts don't support labels, so we infer type from filename
            if let Some(ref scripts) = controls.scripts {
                for script in scripts {
                    // Determine script type from path/filename
                    let script_type = if script.path.contains("remediate") {
                        Some("remediate".to_string())
                    } else {
                        Some("audit".to_string())
                    };

                    // For TOML manifest, we still track the label for documentation
                    let labels = if script.path.contains("remediate") {
                        vec![format!("mscp-{}-remediate", baseline_name)]
                    } else {
                        vec![format!("mscp-{}", baseline_name)]
                    };

                    baseline_ref.add_script(script.path.clone(), labels, script_type);
                }
            }
        }

        Ok(baseline_ref)
    }

    /// Generate team YAML content for a baseline
    ///
    /// Creates a deployable team configuration that references the baseline's
    /// profiles and scripts with correct relative paths from fleets/ directory.
    pub fn generate_team_yaml(&self, baseline_name: &str) -> Result<String> {
        let team_name = baseline_name.replace('_', "-");
        let label_name = format!("mscp-{baseline_name}");
        let remediate_label = format!("mscp-{baseline_name}-remediate");
        let secret_var = format!(
            "FLEET_{}_ENROLL_SECRET",
            baseline_name.to_uppercase().replace('-', "_")
        );

        let layout = contour_core::fleet_layout::FleetLayout::default();
        let content = format!(
            r#"# Fleet GitOps - Fleet Configuration: {team_name} (Fleet v4.82+)
#
# mSCP Baseline: {baseline_name}
# Profiles and scripts are in: {platforms_dir}/mscp/{baseline_name}/
#
# Required environment variables:
#   - ${secret_var}
#
# Available labels for this baseline:
#   - {label_name}           (for audit profiles/targeting)
#   - {remediate_label}  (for remediation targeting via policies)
#
# Generated by contour mscp - https://github.com/headmin/contour

name: {team_name}

policies:

reports:

agent_options:
  path: ../{agent_options_path}

settings:
  secrets:
    - secret: "${secret_var}"
  features:
    enable_host_users: true
    enable_software_inventory: true

software:

controls:
  macos_settings:
    custom_settings:
      # Add profile paths here after generating the baseline
      # Example:
      # - path: ../{platforms_dir}/mscp/{baseline_name}/profiles/com.apple.applicationaccess.mobileconfig
      #   labels_include_all:
      #     - {label_name}
  scripts:
    # Add script paths here after generating the baseline
    # Example:
    # - path: ../{platforms_dir}/mscp/{baseline_name}/scripts/{baseline_name}_audit.sh
"#,
            platforms_dir = layout.platforms_dir,
            agent_options_path = layout.agent_options_path,
        );

        Ok(content)
    }

    /// Write team YAML to fleets/{baseline}.yml
    ///
    /// Places the team file directly in fleets/ directory (not fleets/examples/)
    /// with proper relative paths to ../lib/mscp/{baseline}/
    pub fn write_team_yml(&self, baseline_name: &str) -> Result<PathBuf> {
        let fleets_dir = self.output_base.join("fleets");
        std::fs::create_dir_all(&fleets_dir)?;

        let filename = format!("{baseline_name}.yml");
        let file_path = fleets_dir.join(&filename);

        let content = self.generate_team_yaml(baseline_name)?;
        std::fs::write(&file_path, content)?;

        tracing::info!("Wrote team configuration: {:?}", file_path);
        Ok(file_path)
    }

    /// Write team YAML with actual profiles and scripts populated
    pub fn write_team_yml_with_content(
        &self,
        baseline_name: &str,
        profile_paths: &[PathBuf],
        script_paths: &[(PathBuf, Option<PathBuf>)],
    ) -> Result<PathBuf> {
        use crate::generators::FleetGitOpsGenerator;

        let generator = FleetGitOpsGenerator::new_default(&self.output_base);
        generator.generate_team_yml(baseline_name, profile_paths, script_paths)
    }

    /// Deprecated: Keep for backward compatibility
    #[deprecated(since = "0.2.0", note = "Use write_team_yml instead")]
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn write_example_team(&self, baseline_name: &str) -> Result<PathBuf> {
        self.write_team_yml(baseline_name)
    }

    /// Generate relative path from mscp/{baseline}/baseline.toml to an artifact
    /// under output_base. baseline.toml is two directories deep (mscp/{baseline}/),
    /// so we prepend `../../` to the output-base-relative path.
    fn get_relative_path_from_lib(
        &self,
        absolute_path: &Path,
        _baseline_name: &str,
    ) -> Result<String> {
        let relative = absolute_path
            .strip_prefix(&self.output_base)
            .unwrap_or(absolute_path);

        Ok(format!("../../{}", relative.display()))
    }

    /// Generate relative path from output base (for backward compatibility)
    fn get_relative_path(&self, absolute_path: &Path) -> Result<String> {
        let relative = absolute_path
            .strip_prefix(&self.output_base)
            .unwrap_or(absolute_path);

        Ok(format!("./{}", relative.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_team_yaml_generator() {
        let generator = TeamYamlGenerator::new("/tmp/test");
        assert!(generator.output_base.to_str().unwrap().contains("test"));
    }
}
