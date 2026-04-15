use crate::models::Platform;
use anyhow::Result;
use contour_core::fleet_layout::FleetLayout;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Fleet labels file wrapper (used when labels need to be wrapped in a key)
#[allow(dead_code, reason = "reserved for future use")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetLabelsFile {
    pub labels: Vec<LabelSpec>,
}

/// Fleet label definition structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetLabel {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub spec: LabelSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelSpec {
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    pub label_membership_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
}

/// Generator for Fleet label YAML files
#[derive(Debug)]
pub struct LabelGenerator {
    output_base: PathBuf,
    layout: FleetLayout,
}

impl LabelGenerator {
    pub fn new<P: AsRef<Path>>(output_base: P) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
            layout: FleetLayout::default(),
        }
    }

    /// Generate label definitions for a baseline
    pub fn generate_baseline_labels(
        &self,
        baseline_name: &str,
        platform: Platform,
    ) -> Result<Vec<FleetLabel>> {
        let platform_str = platform.to_fleet_label_platform();

        let label_name = format!("mscp-{baseline_name}");
        let remediate_label_name = format!("mscp-{baseline_name}-remediate");

        let labels = vec![
            FleetLabel {
                api_version: "v1".to_string(),
                kind: "label".to_string(),
                spec: LabelSpec {
                    name: label_name.clone(),
                    description: format!(
                        "Hosts enrolled in mSCP {baseline_name} baseline compliance program"
                    ),
                    platform: Some(platform_str.to_string()),
                    label_membership_type: "manual".to_string(),
                    query: None,
                    hosts: None,
                },
            },
            FleetLabel {
                api_version: "v1".to_string(),
                kind: "label".to_string(),
                spec: LabelSpec {
                    name: remediate_label_name.clone(),
                    description: format!(
                        "Hosts authorized for automatic remediation of mSCP {baseline_name} baseline violations"
                    ),
                    platform: Some(platform_str.to_string()),
                    label_membership_type: "manual".to_string(),
                    query: None,
                    hosts: None,
                },
            },
        ];

        Ok(labels)
    }

    /// Write labels to {layout.labels_dir}/mscp-{baseline}.labels.yml
    pub fn write_labels(&self, baseline_name: &str, labels: &[FleetLabel]) -> Result<PathBuf> {
        let labels_dir = self.output_base.join(self.layout.labels_dir);
        std::fs::create_dir_all(&labels_dir)?;

        let filename = format!("mscp-{baseline_name}.labels.yml");
        let file_path = labels_dir.join(&filename);

        // When using path references, Fleet expects just the array (not wrapped in 'labels:' key)
        let specs: Vec<LabelSpec> = labels.iter().map(|l| l.spec.clone()).collect();
        let yaml_content = yaml_serde::to_string(&specs)?;
        std::fs::write(&file_path, yaml_content)?;

        tracing::info!("Wrote label definitions: {:?}", file_path);
        Ok(file_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_baseline_labels() {
        let generator = LabelGenerator::new("/tmp/test");
        let labels = generator
            .generate_baseline_labels("800-53r5_high", Platform::MacOS)
            .unwrap();

        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].spec.name, "mscp-800-53r5_high");
        assert_eq!(labels[1].spec.name, "mscp-800-53r5_high-remediate");
        assert_eq!(labels[0].spec.platform, Some("darwin".to_string()));
    }
}
