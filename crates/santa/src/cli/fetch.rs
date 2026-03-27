use crate::output::{CommandResult, OutputMode, print_json, print_success};
use crate::transform;
use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum FetchCommands {
    /// Parse osquery santa_rules JSON
    Osquery {
        /// Input JSON file
        input: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Extract rules from existing mobileconfig
    Mobileconfig {
        /// Input mobileconfig file
        input: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Parse santactl fileinfo output
    Santactl {
        /// Input file (santactl output)
        input: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Extract TeamIDs from Installomator labels
    Installomator {
        /// Input Installomator script
        input: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Extract rules from Fleet software CSV export
    ///
    /// Supports flexible column names:
    ///   team_identifier, team_id, teamid
    ///   name, software_name, app_name
    ///   bundle_identifier, bundleid, bundle_id
    #[command(visible_alias = "fleet")]
    FleetCsv {
        /// Input CSV file
        input: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Serialize)]
struct FetchOutput {
    source_type: String,
    rules_count: usize,
    output_path: Option<String>,
}

pub fn run(command: FetchCommands, mode: OutputMode) -> Result<()> {
    let (source_type, rules, output_path) = match command {
        FetchCommands::Osquery { input, output } => {
            let content = std::fs::read_to_string(&input)
                .with_context(|| format!("Failed to read: {}", input.display()))?;
            let rules = transform::parse_osquery(&content)?;
            let output_path = output.unwrap_or_else(|| PathBuf::from("osquery-rules.yaml"));
            ("osquery", rules, output_path)
        }

        FetchCommands::Mobileconfig { input, output } => {
            let rules = transform::mobileconfig::parse_mobileconfig_file(&input)?;
            let output_path = output.unwrap_or_else(|| PathBuf::from("extracted-rules.yaml"));
            ("mobileconfig", rules, output_path)
        }

        FetchCommands::Santactl { input, output } => {
            let content = std::fs::read_to_string(&input)
                .with_context(|| format!("Failed to read: {}", input.display()))?;
            let rules = transform::parse_santactl(&content)?;
            let output_path = output.unwrap_or_else(|| PathBuf::from("santactl-rules.yaml"));
            ("santactl", rules, output_path)
        }

        FetchCommands::Installomator { input, output } => {
            let content = std::fs::read_to_string(&input)
                .with_context(|| format!("Failed to read: {}", input.display()))?;
            let rules = transform::parse_installomator(&content)?;
            let output_path = output.unwrap_or_else(|| PathBuf::from("installomator-rules.yaml"));
            ("installomator", rules, output_path)
        }

        FetchCommands::FleetCsv { input, output } => {
            let rules = transform::parse_fleet_csv_file(&input)?;
            let output_path = output.unwrap_or_else(|| PathBuf::from("fleet-rules.yaml"));
            ("fleet-csv", rules, output_path)
        }
    };

    // Write output as YAML
    let yaml = yaml_serde::to_string(rules.rules())?;
    std::fs::write(&output_path, &yaml)?;

    if mode == OutputMode::Human {
        print_success(&format!(
            "Extracted {} rules from {} to {}",
            rules.len(),
            source_type,
            output_path.display()
        ));
    } else {
        print_json(&CommandResult::success(FetchOutput {
            source_type: source_type.to_string(),
            rules_count: rules.len(),
            output_path: Some(output_path.display().to_string()),
        }))?;
    }

    Ok(())
}
