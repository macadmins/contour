//! Project information command.

use anyhow::Result;
use colored::Colorize;
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::output::OutputMode;

/// Information about the mSCP CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MscpCliInfo {
    pub version: String,
    pub build_timestamp: String,
    pub copyright: String,
}

/// Configuration information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigInfo {
    pub path: String,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<OrganizationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub python_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationInfo {
    pub domain: String,
    pub name: String,
}

/// Constraint files status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintsInfo {
    pub fleet: bool,
    pub jamf: bool,
}

/// Platform settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformsInfo {
    pub jamf: JamfPlatformInfo,
    pub fleet: FleetPlatformInfo,
    pub munki: MunkiPlatformInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JamfPlatformInfo {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deterministic_uuids: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_creation_date: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identical_payload_uuid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_conflicts: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPlatformInfo {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_labels: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MunkiPlatformInfo {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_flags: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_nopkg: Option<bool>,
}

/// Configured baseline information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfiguredBaselineInfo {
    pub name: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
}

/// mSCP repository information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MscpRepoInfo {
    pub path: String,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Output directory information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputInfo {
    pub path: String,
    pub exists: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub generated_baselines: Vec<GeneratedBaselineInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedBaselineInfo {
    pub name: String,
    pub profiles: usize,
    pub scripts: usize,
}

/// Complete project information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub cli: MscpCliInfo,
    pub config: ConfigInfo,
    pub constraints: ConstraintsInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<PlatformsInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub configured_baselines: Vec<ConfiguredBaselineInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mscp: Option<MscpRepoInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputInfo>,
}

/// Display project information and status
pub fn info_command(config_path: &Path, output_mode: OutputMode) -> Result<()> {
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));

    // Gather all information
    let info = gather_project_info(config_path, config_dir)?;

    match output_mode {
        OutputMode::Json => {
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        OutputMode::Human => {
            print_human_output(&info, config_dir);
        }
    }

    Ok(())
}

fn gather_project_info(config_path: &Path, config_dir: &Path) -> Result<ProjectInfo> {
    let cli_info = MscpCliInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_timestamp: env!("BUILD_TIMESTAMP").to_string(),
        copyright: "Created by Mac Admins Open Source".to_string(),
    };

    // Try to load config
    let config = load_config_if_exists(config_path);

    let config_info = ConfigInfo {
        path: config_path.display().to_string(),
        exists: config.is_some(),
        organization: config.as_ref().map(|c| OrganizationInfo {
            domain: c.settings.organization.domain.clone(),
            name: c.settings.organization.name.clone(),
        }),
        python_method: config.as_ref().map(|c| c.settings.python_method.clone()),
    };

    // Check constraint files
    let constraints = ConstraintsInfo {
        fleet: config_dir.join("fleet-constraints.yml").exists(),
        jamf: config_dir.join("jamf-constraints.yml").exists(),
    };

    // Platform settings
    let platforms = config.as_ref().map(|c| PlatformsInfo {
        jamf: JamfPlatformInfo {
            enabled: c.settings.jamf.enabled,
            deterministic_uuids: if c.settings.jamf.enabled {
                Some(c.settings.jamf.deterministic_uuids)
            } else {
                None
            },
            no_creation_date: if c.settings.jamf.enabled {
                Some(c.settings.jamf.no_creation_date)
            } else {
                None
            },
            identical_payload_uuid: if c.settings.jamf.enabled {
                Some(c.settings.jamf.identical_payload_uuid)
            } else {
                None
            },
            exclude_conflicts: if c.settings.jamf.enabled {
                Some(c.settings.jamf.exclude_conflicts)
            } else {
                None
            },
        },
        fleet: FleetPlatformInfo {
            enabled: c.settings.fleet.enabled,
            no_labels: if c.settings.fleet.enabled {
                Some(c.settings.fleet.no_labels)
            } else {
                None
            },
        },
        munki: MunkiPlatformInfo {
            enabled: c.settings.munki.compliance_flags || c.settings.munki.script_nopkg,
            compliance_flags: if c.settings.munki.compliance_flags || c.settings.munki.script_nopkg
            {
                Some(c.settings.munki.compliance_flags)
            } else {
                None
            },
            script_nopkg: if c.settings.munki.compliance_flags || c.settings.munki.script_nopkg {
                Some(c.settings.munki.script_nopkg)
            } else {
                None
            },
        },
    });

    // Configured baselines
    let configured_baselines: Vec<ConfiguredBaselineInfo> = config
        .as_ref()
        .map(|c| {
            c.baselines
                .iter()
                .map(|b| ConfiguredBaselineInfo {
                    name: b.name.clone(),
                    enabled: b.enabled,
                    branch: b.branch.clone(),
                    team: b.team.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    // mSCP repository info
    let mscp = config.as_ref().map(|c| {
        let mscp_path = resolve_path(config_dir, &c.settings.mscp_repo);
        get_mscp_info(&mscp_path)
    });

    // Output directory info
    let output = config.as_ref().map(|c| {
        let output_path = resolve_path(config_dir, &c.settings.output_dir);
        get_output_info(&output_path)
    });

    Ok(ProjectInfo {
        cli: cli_info,
        config: config_info,
        constraints,
        platforms,
        configured_baselines,
        mscp,
        output,
    })
}

fn load_config_if_exists(path: &Path) -> Option<Config> {
    if !path.exists() {
        return None;
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|content| toml::from_str(&content).ok())
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn get_mscp_info(path: &PathBuf) -> MscpRepoInfo {
    let path_str = path.display().to_string();

    if !path.exists() {
        return MscpRepoInfo {
            path: path_str,
            exists: false,
            branch: None,
            commit: None,
            status: Some("not found".to_string()),
        };
    }

    match Repository::open(path) {
        Ok(repo) => {
            let branch = repo
                .head()
                .ok()
                .and_then(|h| h.shorthand().map(String::from));

            let commit = repo
                .head()
                .ok()
                .and_then(|h| h.peel_to_commit().ok())
                .map(|c| c.id().to_string()[..7].to_string());

            let status = if repo.state() == git2::RepositoryState::Clean {
                // Check if working directory is clean
                let statuses = repo.statuses(None).ok();
                if statuses.is_none_or(|s| s.is_empty()) {
                    Some("clean".to_string())
                } else {
                    Some("modified".to_string())
                }
            } else {
                Some(format!("{:?}", repo.state()).to_lowercase())
            };

            MscpRepoInfo {
                path: path_str,
                exists: true,
                branch,
                commit,
                status,
            }
        }
        Err(_) => MscpRepoInfo {
            path: path_str,
            exists: true,
            branch: None,
            commit: None,
            status: Some("not a git repository".to_string()),
        },
    }
}

fn get_output_info(path: &PathBuf) -> OutputInfo {
    let path_str = path.display().to_string();

    if !path.exists() {
        return OutputInfo {
            path: path_str,
            exists: false,
            generated_baselines: Vec::new(),
        };
    }

    let mut generated_baselines = Vec::new();

    // Scan for baseline directories (look for lib/baselines or just baselines)
    let baselines_dir = if path.join("lib/baselines").is_dir() {
        path.join("lib/baselines")
    } else if path.join("baselines").is_dir() {
        path.join("baselines")
    } else {
        // Try looking for platform subdirectories like macOS/baselines
        let macos_baselines = path.join("macOS/baselines");
        if macos_baselines.is_dir() {
            macos_baselines
        } else {
            path.clone()
        }
    };

    if let Ok(entries) = std::fs::read_dir(&baselines_dir) {
        for entry in entries.filter_map(Result::ok) {
            let entry_path = entry.path();
            if entry_path.is_dir()
                && let Some(name) = entry_path.file_name().and_then(|n| n.to_str())
            {
                // Count profiles and scripts
                let profiles = count_files(&entry_path.join("profiles"), "mobileconfig");
                let scripts = count_files(&entry_path.join("scripts"), "sh");

                if profiles > 0 || scripts > 0 {
                    generated_baselines.push(GeneratedBaselineInfo {
                        name: name.to_string(),
                        profiles,
                        scripts,
                    });
                }
            }
        }
    }

    OutputInfo {
        path: path_str,
        exists: true,
        generated_baselines,
    }
}

fn count_files(dir: &Path, extension: &str) -> usize {
    if !dir.exists() {
        return 0;
    }

    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file() && e.path().extension().is_some_and(|ext| ext == extension)
        })
        .count()
}

fn print_human_output(info: &ProjectInfo, config_dir: &Path) {
    // Header
    println!(
        "{} v{}+{}",
        "Contour mSCP".cyan().bold(),
        info.cli.version,
        info.cli.build_timestamp
    );
    println!("{}", info.cli.copyright.dimmed());
    println!();

    // Configuration
    println!("{}:", "Configuration".cyan().bold());
    if info.config.exists {
        println!("  {} {}", "File:".dimmed(), info.config.path.green());
        if let Some(org) = &info.config.organization {
            println!(
                "  {} {} ({})",
                "Organization:".dimmed(),
                org.name,
                org.domain.dimmed()
            );
        }
        if let Some(python) = &info.config.python_method {
            println!("  {} {python}", "Python:".dimmed());
        }
    } else {
        println!(
            "  {} {}",
            "File:".dimmed(),
            format!("{} (not found)", info.config.path).yellow()
        );
    }
    println!();

    // Constraint Files
    println!("{}:", "Constraint Files".cyan().bold());
    print_status("fleet-constraints.yml", info.constraints.fleet, config_dir);
    print_status("jamf-constraints.yml", info.constraints.jamf, config_dir);
    println!();

    // MDM Platforms
    if let Some(platforms) = &info.platforms {
        println!("{}:", "MDM Platforms".cyan().bold());
        print_platform_jamf(&platforms.jamf);
        print_platform_fleet(&platforms.fleet);
        print_platform_munki(&platforms.munki);
        println!();
    }

    // Configured Baselines
    if !info.configured_baselines.is_empty() {
        println!("{}:", "Configured Baselines".cyan().bold());
        for baseline in &info.configured_baselines {
            let status = if baseline.enabled {
                "✓".green()
            } else {
                "✗".red()
            };
            let mut details = Vec::new();
            if let Some(branch) = &baseline.branch {
                details.push(format!("branch: {branch}"));
            }
            if let Some(team) = &baseline.team {
                details.push(format!("team: {team}"));
            }
            if !baseline.enabled {
                details.push("disabled".to_string());
            }
            let detail_str = if details.is_empty() {
                String::new()
            } else {
                format!(" ({})", details.join(", ")).dimmed().to_string()
            };
            println!("  {status} {}{detail_str}", baseline.name);
        }
        println!();
    }

    // mSCP Repository
    if let Some(mscp) = &info.mscp {
        println!("{}:", "mSCP Repository".cyan().bold());
        if mscp.exists {
            println!("  {} {}", "Path:".dimmed(), mscp.path);
            if let Some(branch) = &mscp.branch {
                println!("  {} {branch}", "Branch:".dimmed());
            }
            if let Some(commit) = &mscp.commit {
                println!("  {} {commit}", "Commit:".dimmed());
            }
            if let Some(status) = &mscp.status {
                let status_colored = match status.as_str() {
                    "clean" => status.green().to_string(),
                    "modified" => status.yellow().to_string(),
                    _ => status.dimmed().to_string(),
                };
                println!("  {} {status_colored}", "Status:".dimmed());
            }
        } else {
            println!(
                "  {} {}",
                "Path:".dimmed(),
                format!("{} (not found)", mscp.path).yellow()
            );
        }
        println!();
    }

    // Output Directory
    if let Some(output) = &info.output {
        println!("{}:", "Output Directory".cyan().bold());
        if output.exists {
            println!("  {} {}", "Path:".dimmed(), output.path);
            if output.generated_baselines.is_empty() {
                println!("  {} {}", "Generated:".dimmed(), "none".dimmed());
            } else {
                println!(
                    "  {} {} baseline(s)",
                    "Generated:".dimmed(),
                    output.generated_baselines.len()
                );
                for baseline in &output.generated_baselines {
                    println!(
                        "    - {} ({} profiles, {} scripts)",
                        baseline.name, baseline.profiles, baseline.scripts
                    );
                }
            }
        } else {
            println!(
                "  {} {}",
                "Path:".dimmed(),
                format!("{} (not created)", output.path).dimmed()
            );
        }
    }
}

fn print_status(name: &str, exists: bool, _config_dir: &Path) {
    if exists {
        println!("  {} {name}", "✓".green());
    } else {
        println!("  {} {}", "✗".red(), format!("{name} (missing)").dimmed());
    }
}

fn print_platform_jamf(jamf: &JamfPlatformInfo) {
    let status = if jamf.enabled {
        "enabled".green()
    } else {
        "disabled".dimmed()
    };
    print!("  Jamf Pro: {status}");

    if jamf.enabled {
        let mut features = Vec::new();
        if jamf.deterministic_uuids.unwrap_or(false) {
            features.push("deterministic UUIDs");
        }
        if jamf.no_creation_date.unwrap_or(false) {
            features.push("no creation dates");
        }
        if jamf.identical_payload_uuid.unwrap_or(false) {
            features.push("identical payload UUID");
        }
        if jamf.exclude_conflicts.unwrap_or(false) {
            features.push("exclude conflicts");
        }
        if !features.is_empty() {
            print!(" ({})", features.join(", ").dimmed());
        }
    }
    println!();
}

fn print_platform_fleet(fleet: &FleetPlatformInfo) {
    let status = if fleet.enabled {
        "enabled".green()
    } else {
        "disabled".dimmed()
    };
    print!("  Fleet: {status}");

    if fleet.enabled && fleet.no_labels.unwrap_or(false) {
        print!(" ({})", "no labels".dimmed());
    }
    println!();
}

fn print_platform_munki(munki: &MunkiPlatformInfo) {
    let status = if munki.enabled {
        "enabled".green()
    } else {
        "disabled".dimmed()
    };
    print!("  Munki: {status}");

    if munki.enabled {
        let mut features = Vec::new();
        if munki.compliance_flags.unwrap_or(false) {
            features.push("compliance flags");
        }
        if munki.script_nopkg.unwrap_or(false) {
            features.push("script nopkg");
        }
        if !features.is_empty() {
            print!(" ({})", features.join(", ").dimmed());
        }
    }
    println!();
}
