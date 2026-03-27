//! `contour init` — interactive wizard for shared org configuration.
//!
//! Creates `.contour/config.toml` with organization identity and defaults.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use colored::Colorize;
use contour_core::config::{
    ContourConfig, DefaultsConfig, OrgConfig, derive_domain_from_name, derive_server_url_from_name,
};

pub fn run(
    path: &Path,
    name: Option<String>,
    domain: Option<String>,
    server_url: Option<String>,
    platforms: Option<Vec<String>>,
    deterministic_uuids: Option<bool>,
    yes: bool,
    json: bool,
) -> Result<()> {
    // Resolve to absolute path
    let root = if path == Path::new(".") {
        std::env::current_dir().context("Cannot determine current directory")?
    } else {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Cannot create directory {}", path.display()))?;
        std::fs::canonicalize(path)
            .with_context(|| format!("Cannot resolve path {}", path.display()))?
    };

    // Load existing config as defaults for update flow
    let existing = ContourConfig::load(&root);

    if yes {
        run_noninteractive(
            &root,
            existing,
            name,
            domain,
            server_url,
            platforms,
            deterministic_uuids,
            json,
        )
    } else {
        run_interactive(
            &root,
            existing,
            name,
            domain,
            server_url,
            platforms,
            deterministic_uuids,
            json,
        )
    }
}

fn run_noninteractive(
    root: &Path,
    existing: Option<ContourConfig>,
    name: Option<String>,
    domain: Option<String>,
    server_url: Option<String>,
    platforms: Option<Vec<String>>,
    deterministic_uuids: Option<bool>,
    json: bool,
) -> Result<()> {
    // For non-interactive, name and domain must come from flags or existing config
    let org_name = name
        .or_else(|| existing.as_ref().map(|c| c.organization.name.clone()))
        .unwrap_or_else(|| "My Organization".to_string());

    let org_domain = domain
        .or_else(|| existing.as_ref().map(|c| c.organization.domain.clone()))
        .unwrap_or_else(|| derive_domain_from_name(&org_name));

    let org_server_url = server_url.or_else(|| {
        existing
            .as_ref()
            .and_then(|c| c.organization.server_url.clone())
    });

    let plat = platforms.or_else(|| existing.as_ref().and_then(|c| c.defaults.platforms.clone()));

    let det_uuids = deterministic_uuids
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|c| c.defaults.deterministic_uuids)
        })
        .or(Some(true)); // Default to true for non-interactive

    let config = ContourConfig {
        organization: OrgConfig {
            name: org_name,
            domain: org_domain,
            server_url: org_server_url,
        },
        defaults: DefaultsConfig {
            platforms: plat,
            deterministic_uuids: det_uuids,
            manifests_path: None,
        },
    };

    config.save(root)?;
    let wrote_agent_md = write_agent_md(root)?;
    print_summary(root, &config, wrote_agent_md, json);
    Ok(())
}

fn run_interactive(
    root: &Path,
    existing: Option<ContourConfig>,
    cli_name: Option<String>,
    cli_domain: Option<String>,
    cli_server_url: Option<String>,
    cli_platforms: Option<Vec<String>>,
    cli_deterministic_uuids: Option<bool>,
    json: bool,
) -> Result<()> {
    if !json {
        println!();
        println!("  {}", "Contour Init".bold());
        println!("  {}", "════════════".dimmed());
        if existing.is_some() {
            println!("  {}", "Updating existing .contour/config.toml".dimmed());
        }
        println!();
    }

    // Organization name
    let org_name = if let Some(n) = cli_name {
        n
    } else {
        let default = existing
            .as_ref()
            .map(|c| c.organization.name.clone())
            .unwrap_or_default();
        let mut prompt = inquire::Text::new("Organization name:")
            .with_help_message("Your company or organization name");
        if !default.is_empty() {
            prompt = prompt.with_default(&default);
        }
        prompt.prompt().context("Cancelled")?
    };

    if org_name.trim().is_empty() {
        bail!("Organization name is required");
    }

    // Domain
    let org_domain = if let Some(d) = cli_domain {
        d
    } else {
        let default = existing
            .as_ref()
            .map(|c| c.organization.domain.clone())
            .unwrap_or_else(|| derive_domain_from_name(&org_name));
        inquire::Text::new("Reverse-domain identifier:")
            .with_default(&default)
            .with_help_message("e.g., com.acme — used for profile identifiers")
            .prompt()
            .context("Cancelled")?
    };

    // Server URL
    let org_server_url = if let Some(u) = cli_server_url {
        Some(u)
    } else {
        let default = existing
            .as_ref()
            .and_then(|c| c.organization.server_url.clone())
            .unwrap_or_else(|| derive_server_url_from_name(&org_name));
        let url = inquire::Text::new("Fleet server URL (leave empty to skip):")
            .with_default(&default)
            .prompt()
            .context("Cancelled")?;
        if url.trim().is_empty() {
            None
        } else {
            Some(url)
        }
    };

    // Platforms
    let plat = if let Some(p) = cli_platforms {
        Some(p)
    } else {
        let options = vec!["macos", "windows", "linux", "ios"];
        let existing_plat = existing
            .as_ref()
            .and_then(|c| c.defaults.platforms.as_ref());

        let defaults: Vec<usize> = if let Some(plats) = existing_plat {
            options
                .iter()
                .enumerate()
                .filter(|(_, o)| plats.iter().any(|p| p == *o))
                .map(|(i, _)| i)
                .collect()
        } else {
            vec![0] // macOS selected by default
        };

        let selected = inquire::MultiSelect::new("Platforms:", options.clone())
            .with_default(&defaults)
            .with_vim_mode(true)
            .with_help_message("Space to toggle, Enter to confirm")
            .prompt()
            .context("Cancelled")?;

        if selected.is_empty() {
            None
        } else {
            Some(selected.into_iter().map(|s| s.to_string()).collect())
        }
    };

    // Deterministic UUIDs
    let det_uuids = if let Some(v) = cli_deterministic_uuids {
        Some(v)
    } else {
        let default = existing
            .as_ref()
            .and_then(|c| c.defaults.deterministic_uuids)
            .unwrap_or(true);
        let answer = inquire::Confirm::new("Use predictable UUIDs (recommended for GitOps)?")
            .with_default(default)
            .with_help_message("Generates deterministic UUIDs from identifiers instead of random")
            .prompt()
            .context("Cancelled")?;
        Some(answer)
    };

    let config = ContourConfig {
        organization: OrgConfig {
            name: org_name,
            domain: org_domain,
            server_url: org_server_url,
        },
        defaults: DefaultsConfig {
            platforms: plat,
            deterministic_uuids: det_uuids,
            manifests_path: None,
        },
    };

    config.save(root)?;
    let wrote_agent_md = write_agent_md(root)?;
    print_summary(root, &config, wrote_agent_md, json);
    Ok(())
}

fn print_summary(root: &Path, config: &ContourConfig, wrote_agent_md: bool, json: bool) {
    if json {
        let result = serde_json::json!({
            "path": ContourConfig::config_path(root),
            "agent_md": if wrote_agent_md { Some(root.join("AGENT.md")) } else { None },
            "organization": {
                "name": config.organization.name,
                "domain": config.organization.domain,
                "server_url": config.organization.server_url,
            },
            "defaults": {
                "platforms": config.defaults.platforms,
                "deterministic_uuids": config.defaults.deterministic_uuids,
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .expect("invariant: serde_json::Value literal is always serializable")
        );
        return;
    }

    println!();
    println!(
        "  {} Wrote {}",
        "✓".green(),
        ContourConfig::config_path(root).display()
    );
    if wrote_agent_md {
        println!("  {} Wrote AGENT.md", "✓".green());
    }
    println!();
    println!(
        "  {}: {}",
        "Organization".dimmed(),
        config.organization.name
    );
    println!("  {}: {}", "Domain".dimmed(), config.organization.domain);
    if let Some(url) = &config.organization.server_url {
        println!("  {}: {}", "Server URL".dimmed(), url);
    }
    if let Some(plats) = &config.defaults.platforms {
        println!("  {}: {}", "Platforms".dimmed(), plats.join(", "));
    }
    if let Some(det) = config.defaults.deterministic_uuids {
        println!(
            "  {}: {}",
            "Deterministic UUIDs".dimmed(),
            if det { "yes" } else { "no" }
        );
    }
    println!();
    println!(
        "  {}",
        "Other commands (profile, pppc, santa, mscp, fleet) will read from this config.".dimmed()
    );
    println!();
}

/// Write `AGENT.md` in the project root if it doesn't already exist.
/// Returns `true` if the file was written, `false` if it was skipped.
fn write_agent_md(root: &Path) -> Result<bool> {
    let path = root.join("AGENT.md");
    if path.exists() {
        return Ok(false);
    }

    let content = "\
# Contour CLI — Agent Reference

This project uses [Contour](https://github.com/talkingtoaj/contour) for macOS MDM configuration management.

## CLI Discovery

Run `contour help-ai` to get the full CLI reference (command index, flags, domain data).

Progressive discovery:
- `contour help-ai` — agent guide + command index (~120 lines)
- `contour help-ai --command <dotted.path>` — full detail for one command
- `contour help-ai --section <name>` — full tool section (profile, pppc, santa, mscp, btm, notifications)
- `contour help-ai --full` — complete reference

## Project Config

Organization config is in `.contour/config.toml`. Tool-specific policy files (pppc.toml, santa.toml, etc.) \
live in the project root or subdirectories.
";

    fs::write(&path, content).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(true)
}
