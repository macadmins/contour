//! Project initialization command.

use anyhow::{Context, Result};
use colored::Colorize;
use std::io::{self, Write};
use std::path::Path;

/// Options for project initialization
#[derive(Debug)]
pub struct InitOptions {
    pub domain: Option<String>,
    pub name: Option<String>,
    pub fleet: bool,
    pub jamf: bool,
    pub munki: bool,
    pub baselines: Option<Vec<String>>,
}

const MSCP_REPO_URL: &str = "https://github.com/usnistgov/macos_security.git";

/// Try to load existing config from mscp.toml
fn load_existing_config(output: &Path) -> Option<crate::config::Config> {
    let config_path = output.join("mscp.toml");
    if config_path.exists() {
        std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|content| toml::from_str(&content).ok())
    } else {
        None
    }
}

/// Prompt user for input with a default value
fn prompt(message: &str, default: Option<&str>) -> Result<String> {
    if let Some(def) = default {
        print!("{} [{}]: ", message, def.dimmed());
    } else {
        print!("{message}: ");
    }
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_string();

    if input.is_empty() {
        Ok(default.unwrap_or("").to_string())
    } else {
        Ok(input)
    }
}

/// Prompt for yes/no with default
fn prompt_bool(message: &str, default: bool) -> Result<bool> {
    let default_str = if default { "Y/n" } else { "y/N" };
    print!("{message} [{default_str}]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    if input.is_empty() {
        Ok(default)
    } else {
        Ok(input == "y" || input == "yes")
    }
}

/// Discover available baselines from an mSCP repository.
///
/// Reads `{mscp_path}/baselines/*.yaml`, filters out template/example files,
/// and returns `(name, description)` pairs sorted alphabetically.
pub fn discover_baselines(mscp_path: &Path) -> Result<Vec<(String, String)>> {
    let baselines_dir = mscp_path.join("baselines");
    if !baselines_dir.exists() {
        anyhow::bail!(
            "Baselines directory not found at: {}",
            baselines_dir.display()
        );
    }

    let mut baselines = Vec::new();
    for entry in std::fs::read_dir(&baselines_dir).context(format!(
        "Failed to read baselines directory: {}",
        baselines_dir.display()
    ))? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            if let Some(basename) = path.file_stem().and_then(|s| s.to_str()) {
                // Skip template/example files
                if basename.contains("template") || basename.contains("example") {
                    continue;
                }

                let description = read_baseline_description(&path).unwrap_or_default();
                baselines.push((basename.to_string(), description));
            }
        }
    }

    baselines.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(baselines)
}

/// Read baseline title or description from a YAML file (simple line-based parse).
fn read_baseline_description(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("title:") {
            return Some(
                line.strip_prefix("title:")?
                    .trim()
                    .trim_matches('"')
                    .to_string(),
            );
        }
        if line.starts_with("description:") {
            return Some(
                line.strip_prefix("description:")?
                    .trim()
                    .trim_matches('"')
                    .to_string(),
            );
        }
    }
    None
}

/// Initialize an mscp project with configuration files
pub fn init_project<P: AsRef<Path>>(
    output_dir: P,
    domain: Option<String>,
    name: Option<String>,
    force: bool,
    fleet: bool,
    jamf: bool,
    munki: bool,
    sync: bool,
    branch: &str,
    baselines: Option<Vec<String>>,
    json_mode: bool,
) -> Result<()> {
    let output = output_dir.as_ref();

    // Check for existing config file (skip if --force)
    let existing_config = if force {
        None
    } else {
        load_existing_config(output)
    };

    // Fall back to .contour/config.toml for domain/name defaults
    let contour_cfg = contour_core::config::ContourConfig::load_nearest();
    let domain = domain.or_else(|| contour_cfg.as_ref().map(|c| c.organization.domain.clone()));
    let name = name.or_else(|| contour_cfg.as_ref().map(|c| c.organization.name.clone()));

    // Determine if we'll enter interactive mode (before domain/name are consumed)
    let is_interactive =
        existing_config.is_none() && !(domain.is_some() && name.is_some()) && !json_mode;

    let final_domain: String;
    let final_name: String;
    let final_fleet: bool;
    let final_jamf: bool;
    let final_munki: bool;
    let use_constraints: bool;
    let config_existed: bool;

    if let Some(config) = existing_config {
        // Use existing config values
        config_existed = true;
        final_domain = domain.unwrap_or(config.settings.organization.domain);
        final_name = name.unwrap_or(config.settings.organization.name);
        final_fleet = fleet || config.settings.fleet.enabled;
        final_jamf = jamf || config.settings.jamf.enabled;
        final_munki =
            munki || config.settings.munki.compliance_flags || config.settings.munki.script_nopkg;
        use_constraints = true; // Keep existing constraints

        if !json_mode {
            println!("{} Using existing configuration from mscp.toml", "→".cyan());
            println!("  Domain: {}", final_domain.green());
            println!("  Name: {}", final_name.green());
        }
    } else if (domain.is_some() && name.is_some()) || json_mode {
        // Non-interactive mode - use args or defaults
        config_existed = false;
        final_domain = domain.unwrap_or_else(|| "com.example".to_string());
        final_name = name.unwrap_or_else(|| "Example Organization".to_string());
        final_fleet = fleet;
        final_jamf = jamf;
        final_munki = munki;
        use_constraints = true;
    } else {
        // Interactive mode - no existing config
        config_existed = false;
        println!("{}", "Initializing mscp configuration...".cyan().bold());
        println!();

        // Ask for domain
        final_domain = if let Some(d) = domain {
            d
        } else {
            prompt("Organization domain (e.g., com.acme)", None)?
        };

        if final_domain.is_empty() {
            anyhow::bail!("Domain is required");
        }

        // Validate domain format
        if !final_domain.contains('.') {
            println!(
                "{} Domain '{}' doesn't look like a reverse domain (e.g., com.acme)",
                "Warning:".yellow(),
                final_domain
            );
        }

        // Suggest name from domain
        let suggested_name = final_domain
            .split('.')
            .next_back()
            .unwrap_or("myorg")
            .to_string();
        let suggested_name = suggested_name
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string() + &suggested_name[1..])
            .unwrap_or(suggested_name);

        final_name = if let Some(n) = name {
            n
        } else {
            prompt("Organization name", Some(&suggested_name))?
        };

        println!();
        println!("{}", "MDM Platform Selection".cyan().bold());
        println!(
            "{}",
            "(Select which MDM platforms you want to generate output for)".dimmed()
        );
        println!();

        // Ask about MDM platforms
        final_jamf = if jamf {
            true
        } else {
            prompt_bool("Enable Jamf Pro mode", false)?
        };

        final_fleet = if fleet {
            true
        } else {
            prompt_bool("Enable Fleet GitOps mode", false)?
        };

        final_munki = if munki {
            true
        } else {
            prompt_bool("Enable Munki integration", false)?
        };

        println!();
        println!("{}", "Constraint Files".cyan().bold());
        println!(
            "{}",
            "(Constraint files define MDM-native settings that conflict with mSCP profiles)"
                .dimmed()
        );
        println!();

        use_constraints = prompt_bool("Generate constraint files (recommended)", true)?;
    }

    let _ = config_existed; // Suppress unused warning for now

    // Create directory structure
    std::fs::create_dir_all(output)?;

    // Clone/sync mSCP repository if requested
    if sync {
        let mscp_path = output.join("macos_security");
        sync_mscp_repo(&mscp_path, branch)?;
    }

    // Detect mSCP repo (synced or pre-existing) and pick baselines
    let mscp_path = output.join("macos_security");
    let selected_baselines = if mscp_path.join("baselines").exists() && !json_mode {
        if let Some(cli_baselines) = baselines {
            // Non-interactive: baselines provided via --baselines arg
            Some(cli_baselines)
        } else if is_interactive {
            // Interactive mode: present a picker
            pick_baselines(&mscp_path, branch).ok()
        } else {
            None
        }
    } else {
        baselines
    };

    // Write constraint files if requested (only for enabled platforms)
    if use_constraints {
        if final_fleet {
            let fleet_constraints = include_str!("../../fleet-constraints.yml");
            std::fs::write(output.join("fleet-constraints.yml"), fleet_constraints)?;
        }

        if final_jamf {
            let jamf_constraints = include_str!("../../jamf-constraints.yml");
            std::fs::write(output.join("jamf-constraints.yml"), jamf_constraints)?;
        }
    }

    // Write config template with organization settings
    let options = InitOptions {
        domain: Some(final_domain.clone()),
        name: Some(final_name.clone()),
        fleet: final_fleet,
        jamf: final_jamf,
        munki: final_munki,
        baselines: selected_baselines.clone(),
    };
    crate::config::generate_template_with_options(output.join("mscp.toml"), &options)?;

    if json_mode {
        let result = serde_json::json!({
            "success": true,
            "path": output.display().to_string(),
            "domain": final_domain,
            "name": final_name,
            "fleet": final_fleet,
            "jamf": final_jamf,
            "munki": final_munki,
            "baselines": selected_baselines,
            "constraints": {
                "fleet": use_constraints && final_fleet,
                "jamf": use_constraints && final_jamf,
            },
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!();
        println!(
            "{} Initialized mscp project at: {}",
            "✓".green(),
            output.display()
        );
        println!();
        println!("{}:", "Configuration".cyan());
        println!("  Domain: {}", final_domain.green());
        println!("  Name: {}", final_name.green());
        println!(
            "  Jamf Pro: {}",
            if final_jamf {
                "enabled".green()
            } else {
                "disabled".dimmed()
            }
        );
        println!(
            "  Fleet: {}",
            if final_fleet {
                "enabled".green()
            } else {
                "disabled".dimmed()
            }
        );
        println!(
            "  Munki: {}",
            if final_munki {
                "enabled".green()
            } else {
                "disabled".dimmed()
            }
        );
        if let Some(ref baselines) = selected_baselines {
            if !baselines.is_empty() {
                println!("  Baselines: {}", baselines.join(", ").green());
            }
        }
        println!();
        println!("{}:", "Created files".cyan());
        println!("  - mscp.toml (baseline configuration)");
        if use_constraints && final_fleet {
            println!("  - fleet-constraints.yml (Fleet conflict definitions)");
        }
        if use_constraints && final_jamf {
            println!("  - jamf-constraints.yml (Jamf conflict definitions)");
        }
        if sync {
            println!("  - macos_security/ (mSCP repository, branch: {branch})");
        }
        println!();
        println!("{}:", "Next steps".cyan());
        if sync {
            let example_baseline = selected_baselines
                .as_ref()
                .and_then(|b| b.first())
                .map(|s| s.as_str())
                .unwrap_or("cis_lvl1");
            println!("  1. Review and edit mscp.toml");
            if final_jamf {
                println!(
                    "  2. Run: {} generate --mscp-repo ./macos_security --baseline {} --output ./output --jamf-mode",
                    "contour mscp".cyan(),
                    example_baseline
                );
            } else {
                println!(
                    "  2. Run: {} generate --mscp-repo ./macos_security --baseline {} --output ./output",
                    "contour mscp".cyan(),
                    example_baseline
                );
            }
        } else {
            println!("  1. Clone mSCP: git clone https://github.com/usnistgov/macos_security.git");
            println!("  2. Or re-run with: contour mscp init --sync --branch {branch}");
            println!("  3. Configure baselines in mscp.toml");
        }
    }

    Ok(())
}

/// Present an interactive baseline picker using `inquire::MultiSelect`.
///
/// Returns the list of selected baseline names. Falls back on error/cancel.
fn pick_baselines(mscp_path: &Path, branch: &str) -> Result<Vec<String>> {
    use inquire::MultiSelect;

    let available = discover_baselines(mscp_path)?;
    if available.is_empty() {
        anyhow::bail!("No baselines found in {}", mscp_path.display());
    }

    // Build display strings: "name — description"
    let options: Vec<String> = available
        .iter()
        .map(|(name, desc)| {
            if desc.is_empty() {
                name.clone()
            } else {
                format!("{name} — {desc}")
            }
        })
        .collect();

    // Pre-select cis_lvl1 if present
    let defaults: Vec<usize> = available
        .iter()
        .enumerate()
        .filter_map(
            |(i, (name, _))| {
                if name == "cis_lvl1" { Some(i) } else { None }
            },
        )
        .collect();

    let (platform, version) = super::generate::parse_branch_info(branch);
    let platform_info = if platform != "Unknown" {
        if version.is_empty() {
            format!(" - {platform}")
        } else {
            format!(" - {platform} {version}")
        }
    } else {
        String::new()
    };
    let branch_label = format!("Available baselines ({branch}{platform_info}):");
    println!();
    println!("{}", branch_label.cyan().bold());

    let selected = match MultiSelect::new("Select baselines to enable:", options)
        .with_default(&defaults)
        .prompt()
    {
        Ok(sel) => sel,
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => {
            println!(
                "{}",
                "  Baseline selection cancelled, using defaults.".dimmed()
            );
            return Err(anyhow::anyhow!("cancelled"));
        }
        Err(e) => return Err(e.into()),
    };

    // Extract baseline names by splitting on " — "
    let names: Vec<String> = selected
        .into_iter()
        .map(|s| s.split(" — ").next().unwrap_or(&s).to_string())
        .collect();

    if names.is_empty() {
        println!(
            "{} No baselines selected — config will use example template.",
            "→".cyan()
        );
        return Err(anyhow::anyhow!("no baselines selected"));
    }

    println!("  {} Selected: {}", "✓".green(), names.join(", ").green());

    Ok(names)
}

/// Clone or update mSCP repository
fn sync_mscp_repo(path: &Path, branch: &str) -> Result<()> {
    use git2::{FetchOptions, Repository, build::RepoBuilder};

    if path.exists() {
        // Repository exists, fetch and checkout branch
        println!("→ Updating mSCP repository...");
        let repo = Repository::open(path).context("Failed to open existing mSCP repository")?;

        // Fetch from origin
        let mut remote = repo.find_remote("origin")?;
        let mut fetch_options = FetchOptions::new();
        remote.fetch(&[branch], Some(&mut fetch_options), None)?;

        // Checkout the branch
        let refname = format!("refs/remotes/origin/{branch}");
        let reference = repo.find_reference(&refname)?;
        let commit = reference.peel_to_commit()?;
        repo.checkout_tree(commit.as_object(), None)?;
        repo.set_head_detached(commit.id())?;

        println!("  ✓ Updated to branch: {branch}");
    } else {
        // Clone repository
        println!("→ Cloning mSCP repository (branch: {branch})...");
        println!("  This may take a moment...");

        let mut builder = RepoBuilder::new();
        builder.branch(branch);

        builder
            .clone(MSCP_REPO_URL, path)
            .context("Failed to clone mSCP repository")?;

        println!("  ✓ Cloned successfully");
    }

    Ok(())
}
