//! `contour init` — interactive wizard for shared org configuration.
//!
//! Creates `.contour/config.toml` with organization identity and defaults.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use colored::Colorize;
use contour_core::config::{
    ContourConfig, DefaultsConfig, MdmVariablesConfig, OrgConfig, SecretsConfig, ValidationConfig,
    derive_domain_from_name, derive_server_url_from_name,
};
use profile::mdm_vars::{self, MdmFlavour};

/// Build the `[mdm_variables]` config value for a chosen flavour.
fn mdm_config(flavour: Option<MdmFlavour>) -> MdmVariablesConfig {
    MdmVariablesConfig {
        mdm: flavour.map(|f| f.as_str().to_string()),
        pool: std::collections::BTreeMap::new(),
    }
}

/// Append a commented `[mdm_variables.pool]` template to the written
/// config — the flavour's catalogue, ready for the operator to
/// uncomment and reference as `var:NAME`.
fn append_mdm_template(root: &Path, flavour: MdmFlavour) -> Result<()> {
    use std::fmt::Write as _;

    let mut block = String::from("\n");
    let _ = writeln!(
        block,
        "# Available {} variables — uncomment an entry under",
        flavour.as_str()
    );
    let _ = writeln!(
        block,
        "# [mdm_variables.pool] and reference it in recipes as `var:NAME`."
    );
    let _ = writeln!(block, "# [mdm_variables.pool]");
    match flavour {
        MdmFlavour::Fleet => {
            for v in mdm_vars::FLEET_EXACT {
                let name = v.strip_prefix("FLEET_VAR_").unwrap_or(v);
                let _ = writeln!(block, "# {name} = \"{v}\"");
            }
            for p in mdm_vars::FLEET_PREFIXES {
                let name = p
                    .strip_prefix("FLEET_VAR_")
                    .unwrap_or(p)
                    .trim_end_matches('_');
                let _ = writeln!(block, "# {name} = \"{p}<suffix>\"");
            }
        }
        MdmFlavour::Jamf => {
            for v in mdm_vars::JAMF_VARS {
                let name = v.strip_prefix('$').unwrap_or(v);
                let _ = writeln!(block, "# {name} = \"{v}\"");
            }
            for p in mdm_vars::JAMF_PREFIXES {
                let name = p.strip_prefix('$').unwrap_or(p).trim_end_matches('_');
                let _ = writeln!(block, "# {name} = \"{p}<id>\"");
            }
        }
        MdmFlavour::Apple => {
            let _ = writeln!(
                block,
                "# (no built-in Apple catalogue — add NAME = \"token\" entries yourself)"
            );
        }
    }

    let path = ContourConfig::config_path(root);
    let mut content =
        fs::read_to_string(&path).with_context(|| format!("Cannot read {}", path.display()))?;
    content.push_str(&block);
    fs::write(&path, content).with_context(|| format!("Cannot write {}", path.display()))?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "init wizard mirrors all CLI flags"
)]
pub fn run(
    path: &Path,
    name: Option<String>,
    domain: Option<String>,
    server_url: Option<String>,
    platforms: Option<Vec<String>>,
    deterministic_uuids: Option<bool>,
    library_path: Option<String>,
    mdm: Option<String>,
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

    // Resolve the MDM flavour: explicit --mdm flag, else carry over an
    // existing config's setting.
    let mdm_flag = mdm.or_else(|| existing.as_ref().and_then(|c| c.mdm_variables.mdm.clone()));
    let mdm_flavour = match mdm_flag.as_deref() {
        Some(s) => Some(
            MdmFlavour::parse(s)
                .with_context(|| format!("invalid --mdm '{s}' (expected fleet|jamf|apple)"))?,
        ),
        None => None,
    };

    if yes {
        run_noninteractive(
            &root,
            existing,
            name,
            domain,
            server_url,
            platforms,
            deterministic_uuids,
            library_path,
            mdm_flavour,
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
            library_path,
            mdm_flavour,
            json,
        )
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "init wizard mirrors all CLI flags"
)]
fn run_noninteractive(
    root: &Path,
    existing: Option<ContourConfig>,
    name: Option<String>,
    domain: Option<String>,
    server_url: Option<String>,
    platforms: Option<Vec<String>>,
    deterministic_uuids: Option<bool>,
    library_path: Option<String>,
    mdm_flavour: Option<MdmFlavour>,
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

    let lib_path = library_path
        .as_deref()
        .map(|s| s.to_string())
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|c| c.defaults.library_path.as_ref())
                .map(|p| p.display().to_string())
        })
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);

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
            library_path: lib_path,
        },
        vars: std::collections::BTreeMap::new(),
        signing: None,
        validation: ValidationConfig::default(),
        secrets: SecretsConfig::default(),
        mdm_variables: mdm_config(mdm_flavour),
    };

    config.save(root)?;
    if let Some(flavour) = mdm_flavour {
        append_mdm_template(root, flavour)?;
    }
    let wrote_agent_md = write_agent_md(root)?;
    print_summary(root, &config, wrote_agent_md, json);
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "init wizard mirrors all CLI flags"
)]
fn run_interactive(
    root: &Path,
    existing: Option<ContourConfig>,
    cli_name: Option<String>,
    cli_domain: Option<String>,
    cli_server_url: Option<String>,
    cli_platforms: Option<Vec<String>>,
    cli_deterministic_uuids: Option<bool>,
    cli_library_path: Option<String>,
    mdm_flavour: Option<MdmFlavour>,
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

    // Library path (preset/recipe directory). Optional. When set,
    // commands like `library import --into`, `library validate`,
    // `library normalize`, and `--recipe-path` resolution fall back
    // to this when no flag is given.
    let lib_path: Option<std::path::PathBuf> = if let Some(p) = cli_library_path {
        if p.trim().is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(p))
        }
    } else {
        let default = existing
            .as_ref()
            .and_then(|c| c.defaults.library_path.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "./contour-presets".to_string());
        let answer = inquire::Text::new("Preset/recipe library path (leave empty to skip):")
            .with_default(&default)
            .with_help_message(
                "Default --recipe-path / --into / library validate target. Run `contour profile library new <PATH>` to scaffold one if it doesn't exist yet.",
            )
            .prompt()
            .context("Cancelled")?;
        if answer.trim().is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(answer))
        }
    };

    // MDM platform — the --mdm flag wins; otherwise ask.
    let mdm_flavour: Option<MdmFlavour> = if mdm_flavour.is_some() {
        mdm_flavour
    } else {
        let choices = vec!["skip", "fleet", "jamf", "apple"];
        let answer = inquire::Select::new(
            "MDM platform (for the [mdm_variables] section):",
            choices,
        )
        .with_help_message(
            "Writes the platform's variable catalogue into config.toml as a commented template.",
        )
        .prompt()
        .context("Cancelled")?;
        MdmFlavour::parse(answer)
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
            library_path: lib_path,
        },
        vars: std::collections::BTreeMap::new(),
        signing: None,
        validation: ValidationConfig::default(),
        secrets: SecretsConfig::default(),
        mdm_variables: mdm_config(mdm_flavour),
    };

    config.save(root)?;
    if let Some(flavour) = mdm_flavour {
        append_mdm_template(root, flavour)?;
    }
    let wrote_agent_md = write_agent_md(root)?;
    print_summary(root, &config, wrote_agent_md, json);
    Ok(())
}

fn print_summary(root: &Path, config: &ContourConfig, wrote_agent_md: bool, json: bool) {
    if json {
        let result = serde_json::json!({
            "path": ContourConfig::config_path(root),
            "agents_md": if wrote_agent_md { Some(root.join("AGENTS.md")) } else { None },
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
        println!("  {} Wrote AGENTS.md", "✓".green());
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

/// Write `AGENTS.md` in the project root if it doesn't already exist.
/// Returns `true` if the file was written, `false` if it was skipped.
fn write_agent_md(root: &Path) -> Result<bool> {
    let path = root.join("AGENTS.md");
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
