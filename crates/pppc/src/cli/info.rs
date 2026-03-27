//! Handler for the `pppc info` command.
//!
//! Displays CLI version, available TCC services, and local config summary.

use crate::cli::{OutputMode, print_json};
use crate::pppc::{PppcConfig, PppcService};
use anyhow::Result;
use colored::Colorize;

pub fn run(mode: OutputMode) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let build_timestamp = env!("BUILD_TIMESTAMP");
    let all_services = PppcService::all();

    // Try loading pppc.toml from cwd
    let local_config = PppcConfig::load(std::path::Path::new("pppc.toml")).ok();

    if mode == OutputMode::Json {
        output_json(
            version,
            build_timestamp,
            all_services,
            local_config.as_ref(),
        )?;
    } else {
        output_human(
            version,
            build_timestamp,
            all_services,
            local_config.as_ref(),
        );
    }

    Ok(())
}

fn output_json(
    version: &str,
    build_timestamp: &str,
    services: &[PppcService],
    config: Option<&PppcConfig>,
) -> Result<()> {
    let config_json = config.map(|c| {
        serde_json::json!({
            "org": c.config.org,
            "app_count": c.apps.len(),
            "services_summary": c.apps.iter().map(|a| {
                serde_json::json!({
                    "name": a.name,
                    "services": a.services.len(),
                })
            }).collect::<Vec<_>>(),
        })
    });

    let result = serde_json::json!({
        "version": version,
        "build": build_timestamp,
        "available_services": services.iter().map(|s| {
            serde_json::json!({
                "key": s.key(),
                "name": s.display_name(),
            })
        }).collect::<Vec<_>>(),
        "config": config_json,
    });

    print_json(&result)?;
    Ok(())
}

fn output_human(
    version: &str,
    build_timestamp: &str,
    services: &[PppcService],
    config: Option<&PppcConfig>,
) {
    println!("{}", "PPPC/TCC Toolkit".bold());
    println!("  Version: {}", version.cyan());
    println!("  Build:   {}", build_timestamp.dimmed());
    println!();

    println!("{}", "Available TCC Services".bold());
    println!(
        "  {} services supported:",
        services.len().to_string().cyan()
    );
    for s in services {
        println!(
            "    {} {:<30} ({})",
            "•".dimmed(),
            s.display_name(),
            s.key().dimmed()
        );
    }
    println!();

    println!("{}", "Local Configuration".bold());
    if let Some(c) = config {
        println!("  File:    {}", "pppc.toml".green());
        println!("  Org:     {}", c.config.org.cyan());
        println!("  Apps:    {}", c.apps.len());

        let with_services = c.apps.iter().filter(|a| !a.services.is_empty()).count();
        println!("    • With TCC services: {with_services}");
    } else {
        println!("  {}", "No pppc.toml found in current directory".dimmed());
    }
}
