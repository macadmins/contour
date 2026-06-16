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

    /// Generate Santa rules + DDM app.settings from the fleet-maintained-apps
    /// `app_security_info.json` catalog (signing-info per app).
    ///
    /// Source: https://github.com/allenhouchins/fleet-maintained-apps-growth-tracker
    /// Emits a Santa `.mobileconfig` and a DDM `com.apple.configuration.app.settings`
    /// declaration from the same catalog. Download the JSON first (offline by design).
    FleetApps {
        /// Path to app_security_info.json
        input: PathBuf,

        /// Identifier to rule on
        #[arg(long = "match", value_enum, default_value_t = MatchArg::SigningId)]
        match_on: MatchArg,

        /// Allow (known-good catalog) or deny
        #[arg(long, value_enum, default_value_t = PolicyArg::Allow)]
        policy: PolicyArg,

        /// Organization reverse-domain for generated identifiers
        #[arg(long)]
        org: Option<String>,

        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// What to emit (comma-separated; default: santa,ddm)
        #[arg(long, value_enum, value_delimiter = ',')]
        emit: Vec<EmitArg>,
    },
}

/// Which signing identifier `fetch fleet-apps` rules on.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum MatchArg {
    #[value(name = "signingid", alias = "signing-id")]
    SigningId,
    #[value(name = "teamid", alias = "team-id")]
    TeamId,
    #[value(name = "cdhash")]
    Cdhash,
}

impl From<MatchArg> for transform::MatchOn {
    fn from(m: MatchArg) -> Self {
        match m {
            MatchArg::SigningId => transform::MatchOn::SigningId,
            MatchArg::TeamId => transform::MatchOn::TeamId,
            MatchArg::Cdhash => transform::MatchOn::Cdhash,
        }
    }
}

/// Allow vs. deny for `fetch fleet-apps`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum PolicyArg {
    Allow,
    Deny,
}

impl From<PolicyArg> for crate::models::Policy {
    fn from(p: PolicyArg) -> Self {
        match p {
            PolicyArg::Allow => crate::models::Policy::Allowlist,
            PolicyArg::Deny => crate::models::Policy::Blocklist,
        }
    }
}

/// Artifacts `fetch fleet-apps` can write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum EmitArg {
    /// Santa `.mobileconfig`.
    Santa,
    /// DDM `com.apple.configuration.app.settings` declaration.
    Ddm,
    /// Normalized rule set (YAML).
    Rules,
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

        // fleet-apps is richer than the YAML-only adapters: it emits Santa
        // and/or DDM artifacts, so it fully handles its own output.
        FetchCommands::FleetApps {
            input,
            match_on,
            policy,
            org,
            output,
            emit,
        } => {
            return run_fleet_apps(&input, match_on, policy, org, output, &emit, mode);
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

#[derive(Debug, Serialize)]
struct FleetAppsOutput {
    rules_count: usize,
    artifacts: Vec<String>,
}

/// Handle `fetch fleet-apps`: catalog → Santa rules → Santa `.mobileconfig`
/// and/or DDM `app.settings`, writing into `output` (default: cwd).
fn run_fleet_apps(
    input: &std::path::Path,
    match_on: MatchArg,
    policy: PolicyArg,
    org: Option<String>,
    output: Option<PathBuf>,
    emit: &[EmitArg],
    mode: OutputMode,
) -> Result<()> {
    let rules = transform::parse_fleet_apps_file(input, match_on.into(), policy.into())?;
    if rules.rules().is_empty() {
        anyhow::bail!(
            "no apps with a usable identifier in {} — try a different --match",
            input.display()
        );
    }

    let out_dir = output.unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    // Default: emit both Santa and DDM.
    let targets: Vec<EmitArg> = if emit.is_empty() {
        vec![EmitArg::Santa, EmitArg::Ddm]
    } else {
        emit.to_vec()
    };

    let mut artifacts: Vec<PathBuf> = Vec::new();

    if targets.contains(&EmitArg::Rules) {
        let path = out_dir.join("fleet-apps-rules.yaml");
        std::fs::write(&path, yaml_serde::to_string(rules.rules())?)?;
        artifacts.push(path);
    }

    // Org is only needed for the deployable artifacts.
    let need_org = targets
        .iter()
        .any(|t| matches!(t, EmitArg::Santa | EmitArg::Ddm));
    let org = if need_org {
        contour_core::resolve_org(org.filter(|s| !s.is_empty() && s != "com.example"))?
    } else {
        String::new()
    };

    if targets.contains(&EmitArg::Santa) {
        let opts = crate::generator::GeneratorOptions::new(&org);
        let path = out_dir.join("santa-rules.mobileconfig");
        crate::generator::write_to_file(&rules, &opts, &path)?;
        artifacts.push(path);
    }

    if targets.contains(&EmitArg::Ddm) {
        let mut binaries = Vec::new();
        for rule in rules.rules() {
            // Unmappable rules (e.g. CEL/FAA) are skipped, not fatal.
            if let Ok(entry) = crate::app_settings::map::from_santa_rule(rule) {
                binaries.push(entry);
            }
        }
        let settings = crate::app_settings::AppSettings {
            binaries,
            apps: Vec::new(),
            privacy: Vec::new(),
            always_allow_managed: false,
        };
        if !settings.is_empty() {
            let declaration = settings.to_declaration(&org, "santa");
            let path = out_dir.join("app-settings.json");
            std::fs::write(&path, serde_json::to_string_pretty(&declaration)?)?;
            artifacts.push(path);
        }
    }

    if mode == OutputMode::Human {
        print_success(&format!(
            "Generated {} rules from fleet-apps → {}",
            rules.len(),
            artifacts
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    } else {
        print_json(&CommandResult::success(FleetAppsOutput {
            rules_count: rules.len(),
            artifacts: artifacts.iter().map(|p| p.display().to_string()).collect(),
        }))?;
    }
    Ok(())
}
