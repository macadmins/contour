//! Handler for the `pppc init` command.
//!
//! Creates a blank pppc.toml policy file with sensible defaults.

use crate::cli::{OutputMode, print_json, print_success};
use crate::pppc::{PppcConfig, PppcConfigMeta};
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct InitResult {
    path: String,
    created: bool,
}

pub fn run(
    output: &Path,
    org: Option<&str>,
    name: Option<&str>,
    force: bool,
    mode: OutputMode,
) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "File already exists: {}. Use --force to overwrite.",
            output.display()
        );
    }

    let org = org.unwrap_or("com.example");

    let config = PppcConfig {
        config: PppcConfigMeta {
            org: org.to_string(),
            display_name: name.map(String::from),
        },
        apps: vec![],
    };

    config.save(output)?;

    if mode == OutputMode::Json {
        print_json(&InitResult {
            path: output.display().to_string(),
            created: true,
        })?;
    }

    if mode == OutputMode::Human {
        print_success(&format!("Created policy file: {}", output.display()));
        println!();
        println!("Edit {} to add applications:", output.display());
        println!(
            "  1. Scan apps:      contour pppc scan --org {} -o {}",
            org,
            output.display()
        );
        println!(
            "  2. Configure:      contour pppc configure {}",
            output.display()
        );
        println!(
            "  3. Generate:       contour pppc generate {}",
            output.display()
        );
    }

    Ok(())
}
