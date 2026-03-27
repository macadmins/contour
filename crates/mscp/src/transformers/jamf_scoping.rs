use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Jamf Smart Group scoping template generator
#[derive(Debug)]
pub struct JamfScopingGenerator {
    output_base: PathBuf,
}

/// Smart Group scoping information for a baseline
#[derive(Debug, Clone)]
pub struct JamfScopingManifest {
    pub baseline_name: String,
    pub smart_groups: Vec<SmartGroupTemplate>,
    pub profiles: Vec<ProfileScoping>,
}

/// Smart Group template (XML + documentation)
#[derive(Debug, Clone)]
pub struct SmartGroupTemplate {
    pub name: String,
    pub description: String,
    pub xml_criteria: String,
    pub ui_instructions: String,
}

/// Profile scoping information
#[derive(Debug, Clone)]
pub struct ProfileScoping {
    pub filename: String,
    pub smart_groups: Vec<String>,
    pub is_shared: bool,
    pub shared_with_baselines: Vec<String>,
}

impl JamfScopingGenerator {
    pub fn new<P: AsRef<Path>>(output_base: P) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
        }
    }

    /// Generate scoping manifest for a baseline
    pub fn generate_manifest(
        &self,
        baseline_name: &str,
        profile_filenames: &[String],
        shared_profiles: &HashMap<String, Vec<String>>, // filename -> baselines
    ) -> Result<JamfScopingManifest> {
        let mut manifest = JamfScopingManifest {
            baseline_name: baseline_name.to_string(),
            smart_groups: Vec::new(),
            profiles: Vec::new(),
        };

        // Create main baseline Smart Group
        manifest
            .smart_groups
            .push(self.create_baseline_smart_group(baseline_name));

        // Add profile scoping
        for filename in profile_filenames {
            let is_shared = shared_profiles.contains_key(filename);
            let shared_with = if is_shared {
                shared_profiles.get(filename).cloned().unwrap_or_default()
            } else {
                vec![baseline_name.to_string()]
            };

            manifest.profiles.push(ProfileScoping {
                filename: filename.clone(),
                smart_groups: vec![baseline_name.to_string()],
                is_shared,
                shared_with_baselines: shared_with,
            });
        }

        Ok(manifest)
    }

    /// Create Smart Group template for a baseline
    fn create_baseline_smart_group(&self, baseline_name: &str) -> SmartGroupTemplate {
        let group_name = format!("mSCP - {}", baseline_name.replace('_', " ").to_uppercase());

        let xml_criteria = format!(
            r"<criteria>
    <criterion>
        <name>Application Title</name>
        <priority>0</priority>
        <and_or>and</and_or>
        <search_type>is</search_type>
        <value>mSCP Compliance - {baseline_name}</value>
    </criterion>
    <criterion>
        <name>Extension Attribute</name>
        <priority>1</priority>
        <and_or>or</and_or>
        <search_type>is</search_type>
        <value>mscp-baseline</value>
        <opening_paren>false</opening_paren>
        <closing_paren>false</closing_paren>
        <and_or>and</and_or>
        <search_type>is</search_type>
        <value>{baseline_name}</value>
    </criterion>
</criteria>"
        );

        let ui_instructions = format!(
            r"## Creating Smart Group in Jamf Pro UI

1. Navigate to: **Computers > Smart Computer Groups**
2. Click **+ New**
3. Enter Name: **{group_name}**
4. Enter Description: **Computers that should receive {baseline_name} baseline profiles**

### Criteria (Option 1 - Extension Attribute):
- Extension Attribute: **mscp-baseline**
- Operator: **is**
- Value: **{baseline_name}**

### Criteria (Option 2 - Application Title):
- Application Title: **is**
- Value: **mSCP Compliance - {baseline_name}**

### Criteria (Option 3 - Label/Tag):
- Create a tag for the baseline and scope by tag

**Recommendation**: Use Extension Attribute method for automated assignment via enrollment script.
"
        );

        SmartGroupTemplate {
            name: group_name,
            description: format!(
                "Computers that should receive {baseline_name} baseline configuration profiles"
            ),
            xml_criteria,
            ui_instructions,
        }
    }

    /// Write scoping manifest to disk
    pub fn write_manifest(&self, manifest: &JamfScopingManifest) -> Result<()> {
        let jamf_dir = self
            .output_base
            .join("lib/jamf")
            .join(&manifest.baseline_name);

        std::fs::create_dir_all(&jamf_dir)?;

        // Write XML snippets
        self.write_xml_snippets(&jamf_dir, manifest)?;

        // Write markdown documentation
        self.write_scoping_docs(&jamf_dir, manifest)?;

        tracing::info!(
            "Generated Jamf scoping templates for: {}",
            manifest.baseline_name
        );
        Ok(())
    }

    /// Write XML snippets for Smart Groups
    fn write_xml_snippets(&self, jamf_dir: &Path, manifest: &JamfScopingManifest) -> Result<()> {
        let xml_file = jamf_dir.join("smart-groups.xml");

        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<!-- Jamf Pro Smart Group XML Snippets -->\n");
        xml.push_str(
            "<!-- Copy these criteria sections into Jamf Pro Advanced Computer Search -->\n\n",
        );

        for group in &manifest.smart_groups {
            xml.push_str(&format!("<!-- {} -->\n", group.name));
            xml.push_str(&group.xml_criteria);
            xml.push_str("\n\n");
        }

        std::fs::write(&xml_file, xml)?;
        tracing::debug!("  Wrote XML snippets: {}", xml_file.display());

        Ok(())
    }

    /// Write markdown documentation
    fn write_scoping_docs(&self, jamf_dir: &Path, manifest: &JamfScopingManifest) -> Result<()> {
        let md_file = jamf_dir.join("SCOPING.md");

        let mut md = format!("# Jamf Pro Scoping Guide: {}\n\n", manifest.baseline_name);

        md.push_str("This document provides instructions for scoping configuration profiles in Jamf Pro.\n\n");
        md.push_str("## Smart Groups\n\n");

        for group in &manifest.smart_groups {
            md.push_str(&format!("### {}\n\n", group.name));
            md.push_str(&format!("{}\n\n", group.description));
            md.push_str(&group.ui_instructions);
            md.push_str("\n---\n\n");
        }

        md.push_str("## Profile Scoping Summary\n\n");
        md.push_str("| Profile | Smart Groups | Shared | Notes |\n");
        md.push_str("|---------|--------------|--------|-------|\n");

        for profile in &manifest.profiles {
            let shared_info = if profile.is_shared {
                format!("Yes ({})", profile.shared_with_baselines.join(", "))
            } else {
                "No".to_string()
            };

            md.push_str(&format!(
                "| {} | {} | {} | |\n",
                profile.filename,
                profile.smart_groups.join(", "),
                shared_info
            ));
        }

        md.push_str("\n## Deployment Steps\n\n");
        md.push_str("1. Create the Smart Groups listed above\n");
        md.push_str("2. Upload configuration profiles to Jamf Pro\n");
        md.push_str("3. Scope each profile to its designated Smart Groups\n");
        md.push_str("4. Set deployment priority if needed (lower number = higher priority)\n");
        md.push_str("5. Test on a pilot group before full deployment\n\n");

        md.push_str("## Notes\n\n");
        md.push_str("- Shared profiles are used by multiple baselines\n");
        md.push_str("- Scope shared profiles to ALL applicable Smart Groups\n");
        md.push_str("- Use Extension Attributes for automated baseline assignment\n");
        md.push_str("- Review Jamf constraints in `jamf-constraints.yml` before deployment\n");

        std::fs::write(&md_file, md)?;
        tracing::debug!("  Wrote scoping docs: {}", md_file.display());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_baseline_smart_group() {
        let generator = JamfScopingGenerator::new("/tmp");
        let group = generator.create_baseline_smart_group("800-53r5_high");

        assert!(group.name.contains("800-53R5 HIGH"));
        assert!(group.xml_criteria.contains("800-53r5_high"));
        assert!(group.ui_instructions.contains("Extension Attribute"));
    }
}
