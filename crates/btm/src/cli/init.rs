//! BTM init command — create a blank btm.toml.

use crate::cli::{OutputMode, print_json, print_success};
use crate::config::{BtmConfig, BtmSettings};
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

/// JSON output for the init command.
#[derive(Serialize)]
struct InitResult {
    path: String,
    created: bool,
}

/// Run the BTM init command.
///
/// Creates a btm.toml pre-configured for service management work.
pub fn run(
    output: &Path,
    org: Option<&str>,
    name: Option<&str>,
    force: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "File already exists: {}. Use --force to overwrite.",
            output.display()
        );
    }

    let org = org.unwrap_or("com.example");

    let config = BtmConfig {
        settings: BtmSettings {
            org: org.to_string(),
            display_name: name.map(String::from),
        },
        apps: vec![],
    };

    config.save(output)?;

    if output_mode == OutputMode::Json {
        print_json(&InitResult {
            path: output.display().to_string(),
            created: true,
        })?;
    }

    if output_mode == OutputMode::Human {
        print_success(&format!("Created BTM policy file: {}", output.display()));
        println!();
        println!("Next steps:");
        println!(
            "  1. Scan launch items: contour btm scan --org {} -o {}",
            org,
            output.display()
        );
        println!(
            "  2. Generate profiles: contour btm generate {}",
            output.display()
        );
    }

    Ok(())
}
