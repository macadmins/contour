//! BTM info command — show available scan modes, rule types, and local config summary.

use crate::cli::{OutputMode, print_json};
use crate::config::BtmConfig;
use anyhow::Result;
use colored::Colorize;
use std::path::Path;

/// Run the BTM info command.
///
/// Shows available scan modes, rule types, and BTM summary from local config.
pub fn run(output_mode: OutputMode) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let build_timestamp = env!("BUILD_TIMESTAMP");

    let rule_types = [
        ("TeamIdentifier", "Match by developer team ID"),
        ("BundleIdentifier", "Match by exact bundle identifier"),
        ("BundleIdentifierPrefix", "Match by bundle ID prefix"),
        ("Label", "Match by exact launchd label"),
        ("LabelPrefix", "Match by launchd label prefix"),
    ];

    let scan_modes = [
        (
            "launch-items",
            "Scan /Library/LaunchDaemons and /Library/LaunchAgents",
        ),
        ("apps", "Scan inside .app bundles for embedded launch items"),
    ];

    let local_config = BtmConfig::load(Path::new("btm.toml")).ok();

    if output_mode == OutputMode::Json {
        let config_json = local_config.as_ref().map(|c| {
            let btm_rules: usize = c.apps.iter().map(|a| a.rules.len()).sum();
            serde_json::json!({
                "org": c.settings.org,
                "btm_apps": c.apps.len(),
                "btm_rules": btm_rules,
            })
        });

        print_json(&serde_json::json!({
            "version": version,
            "build": build_timestamp,
            "rule_types": rule_types.iter().map(|(k, v)| serde_json::json!({"type": k, "description": v})).collect::<Vec<_>>(),
            "scan_modes": scan_modes.iter().map(|(k, v)| serde_json::json!({"mode": k, "description": v})).collect::<Vec<_>>(),
            "config": config_json,
        }))?;
    } else {
        println!("{}", "BTM (Background Task Management)".bold());
        println!("  Version: {}", version.cyan());
        println!("  Build:   {}", build_timestamp.dimmed());
        println!();

        println!("{}", "Scan Modes".bold());
        for (mode, desc) in &scan_modes {
            println!("  {} {:<15} {}", "•".dimmed(), mode, desc.dimmed());
        }
        println!();

        println!("{}", "Rule Types".bold());
        for (rtype, desc) in &rule_types {
            println!("  {} {:<25} {}", "•".dimmed(), rtype, desc.dimmed());
        }
        println!();

        println!("{}", "Local Configuration".bold());
        if let Some(c) = &local_config {
            let btm_rules: usize = c.apps.iter().map(|a| a.rules.len()).sum();

            println!("  File:      {}", "btm.toml".green());
            println!("  Org:       {}", c.settings.org.cyan());
            println!("  BTM apps:  {}", c.apps.len());
            println!("  BTM rules: {btm_rules}");
        } else {
            println!("  {}", "No btm.toml found in current directory".dimmed());
        }
    }

    Ok(())
}
