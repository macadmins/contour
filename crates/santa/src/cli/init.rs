use crate::config::SantaProjectConfig;
use crate::output::{CommandResult, OutputMode, print_json, print_success};
use anyhow::Result;
use std::path::Path;

pub fn run(
    output: &Path,
    org: Option<&str>,
    name: Option<&str>,
    force: bool,
    mode: OutputMode,
) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "Configuration file already exists: {}. Use --force to overwrite.",
            output.display()
        );
    }

    let mut config = SantaProjectConfig::default();
    if let Some(org) = org {
        config.organization.domain = org.to_string();
    }
    if let Some(name) = name {
        config.organization.name = name.to_string();
    }
    config.save(output)?;

    if mode == OutputMode::Human {
        print_success(&format!("Created configuration file: {}", output.display()));
        println!();
        println!("Edit santa.toml to customize your configuration:");
        println!("  - Set your organization domain and name");
        println!("  - Configure ring count and labels");
        println!("  - Set profile naming and output directories");
        println!("  - Enable Fleet GitOps integration if needed");
    } else {
        print_json(&CommandResult::success(serde_json::json!({
            "path": output.display().to_string(),
            "created": true
        })))?;
    }

    Ok(())
}
