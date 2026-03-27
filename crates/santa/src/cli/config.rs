pub use crate::config::ClientMode;
use crate::config::{SantaConfig, write_config_to_file};
use crate::output::{CommandResult, OutputMode, print_info, print_json, print_kv, print_success};
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct ConfigOutput {
    mode: String,
    sync_url: Option<String>,
    block_usb: bool,
    output_path: Option<String>,
}

pub fn run(
    output: Option<&Path>,
    mode: ClientMode,
    sync_url: Option<&str>,
    machine_owner_plist: Option<&str>,
    block_usb: bool,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let config = SantaConfig {
        mode,
        sync_url: sync_url.map(|s| s.to_string()),
        machine_owner_plist: machine_owner_plist.map(|s| s.to_string()),
        block_usb,
        ..Default::default()
    };

    let output_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new("santa-config.mobileconfig").to_path_buf());

    let mode_str = match mode {
        ClientMode::Monitor => "monitor",
        ClientMode::Lockdown => "lockdown",
    };

    if output_mode == OutputMode::Human {
        if dry_run {
            print_info("Dry run - no files will be written");
        }

        print_kv("Mode", mode_str);
        if let Some(url) = &config.sync_url {
            print_kv("Sync URL", url);
        }
        print_kv("Block USB", &block_usb.to_string());
        print_kv("Output", &output_path.display().to_string());

        if !dry_run {
            write_config_to_file(&config, &output_path)?;
            print_success(&format!("Generated {}", output_path.display()));
        }
    } else {
        print_json(&CommandResult::success(ConfigOutput {
            mode: mode_str.to_string(),
            sync_url: config.sync_url.clone(),
            block_usb,
            output_path: if dry_run {
                None
            } else {
                Some(output_path.display().to_string())
            },
        }))?;

        if !dry_run {
            write_config_to_file(&config, &output_path)?;
        }
    }

    Ok(())
}
