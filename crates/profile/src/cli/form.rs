//! `profile form` — the FormSpec contract and the emitter, from the CLI.
//!
//! Thin: reads files, resolves the registry and org, and calls
//! `contour_form`. Nothing here decides a control, a scope or a format.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use colored::Colorize;

use crate::config::ProfileConfig;
use crate::output::OutputMode;
use crate::schema::Platform;
use crate::schema::form::{Target, form_all_with, form_with};
use crate::schema::formspec::{Document, Nesting};

/// `profile form spec [TYPE]`
pub fn handle_spec(
    name: Option<&str>,
    os: Option<&str>,
    os_version: Option<&str>,
    annotate: bool,
    schema_path: Option<&str>,
    channel: crate::schema::Channel,
    output: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = crate::cli::generate::load_registry_channel(schema_path, channel)?;
    let annotations = if annotate {
        let a = crate::schema::Annotations::embedded()?;
        if a.is_empty() && output_mode == OutputMode::Human {
            eprintln!(
                "{} this build's dataset has no rule_capability_links table; nothing to annotate",
                "!".yellow()
            );
        }
        Some(a)
    } else {
        None
    };
    let target = Target {
        platform: match os {
            Some(o) => Some(
                Platform::from_cli_str(o)
                    .ok_or_else(|| anyhow::anyhow!("unknown platform '{o}'"))?,
            ),
            None => None,
        },
        os_version: os_version.map(str::to_string),
    };

    let specs = match name {
        Some(n) => vec![
            form_with(&registry, n, &target, annotations.as_ref())
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        ],
        None => {
            let mut ok = Vec::new();
            for r in form_all_with(&registry, &target, annotations.as_ref()) {
                match r {
                    Ok(s) => ok.push(s),
                    Err(e) => eprintln!("{} {e}", "!".yellow()),
                }
            }
            ok
        }
    };

    if output_mode == OutputMode::Human && name.is_some() && output.is_none() {
        print_tree(&specs[0]);
        return Ok(());
    }

    let doc = Document::new(specs, Some(chrono::Utc::now().to_rfc3339()));
    let text = serde_json::to_string_pretty(&doc)?;
    match output {
        Some(p) => {
            std::fs::write(p, &text).with_context(|| format!("writing {p}"))?;
            if output_mode == OutputMode::Human {
                println!("{} {} ({} spec(s))", "✓".green(), p, doc.specs.len());
            }
        }
        None => println!("{text}"),
    }
    Ok(())
}

fn print_tree(spec: &crate::schema::formspec::FormSpec) {
    println!("{}  {}", spec.title.bold(), spec.id.dimmed());
    println!(
        "  kind {:?}  scope {:?}  platforms {}",
        spec.kind,
        spec.scope_class,
        spec.platforms
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    for (p, c) in &spec.scope_class_by_platform {
        println!("    {:<9} {:?}", p.as_str(), c);
    }
    fn walk(nodes: &[crate::schema::formspec::FormNode], indent: usize) {
        for n in nodes {
            let ctl = format!("{:?}", n.control).to_lowercase();
            let opts = n
                .options
                .as_ref()
                .map(|o| format!("  [{}]", o.join("|")))
                .unwrap_or_default();
            let badges = n
                .annotations
                .as_ref()
                .map(|a| {
                    let bl: std::collections::BTreeSet<&str> = a
                        .iter()
                        .flat_map(|x| x.baselines.iter().map(String::as_str))
                        .collect();
                    let ctrl: std::collections::BTreeSet<&str> = a
                        .iter()
                        .flat_map(|x| x.controls.iter().map(String::as_str))
                        .collect();
                    format!(
                        "  ◆ {} rule(s) · {}{}",
                        a.len(),
                        bl.into_iter().collect::<Vec<_>>().join(" "),
                        if ctrl.is_empty() {
                            String::new()
                        } else {
                            format!(" · {} control(s)", ctrl.len())
                        }
                    )
                })
                .unwrap_or_default();
            let not_on = n
                .availability
                .as_ref()
                .and_then(|a| a.unavailable.as_ref())
                .map(|u| {
                    format!(
                        "  ✗ not on {}",
                        u.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", ")
                    )
                })
                .unwrap_or_default();
            println!(
                "{}{:<10} {}{}{}{}",
                "  ".repeat(indent + 1),
                ctl.dimmed(),
                n.key,
                opts.dimmed(),
                badges.magenta(),
                not_on.yellow()
            );
            if let Some(c) = &n.children {
                walk(c, indent + 1);
            }
            if let Some(i) = &n.item {
                walk(std::slice::from_ref(i.as_ref()), indent + 1);
            }
        }
    }
    println!("  {}", "keys:".cyan());
    walk(&spec.nodes, 1);
}

/// `profile form emit TYPE --values FILE`
pub fn handle_emit(
    name: &str,
    values_path: &str,
    org: Option<&str>,
    intent: &str,
    os: Option<&str>,
    os_version: Option<&str>,
    mcx: bool,
    direct: bool,
    output: Option<&str>,
    write: bool,
    config: Option<&ProfileConfig>,
    schema_path: Option<&str>,
    channel: crate::schema::Channel,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = crate::cli::generate::load_registry_channel(schema_path, channel)?;
    let text =
        std::fs::read_to_string(values_path).with_context(|| format!("reading {values_path}"))?;
    let values: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {values_path}"))?;

    let Some(org) = crate::cli::ddm::resolve_ddm_org_domain(org, config) else {
        bail!(
            "organization domain is required\n  \
             • --org <domain>\n  \
             • CONTOUR_ORG\n  \
             • organization.domain in profile.toml or .contour/config.toml"
        );
    };

    let opts = crate::schema::emit::EmitOptions {
        org,
        intent: intent.to_string(),
        format: None,
        nesting: match (mcx, direct) {
            (true, false) => Some(Nesting::McxWrapped),
            (false, true) => Some(Nesting::Direct),
            _ => None,
        },
        platform: match os {
            Some(o) => Some(
                Platform::from_cli_str(o)
                    .ok_or_else(|| anyhow::anyhow!("unknown platform '{o}'"))?,
            ),
            None => None,
        },
        os_version: os_version.map(str::to_string),
        display_name: None,
    };

    // emit() refuses on blocking diagnostics; the non-blocking ones would
    // otherwise never reach the operator, and "matches no app" is one of
    // them.
    let warnings: Vec<_> = crate::schema::validate_target(
        &registry,
        name,
        &values,
        &crate::schema::form::Target {
            platform: opts.platform,
            os_version: opts.os_version.clone(),
            ..Default::default()
        },
    )
    .into_iter()
    .filter(|d| !d.blocks_emit)
    .collect();

    let emitted = crate::schema::emit::emit(&registry, name, &values, &opts)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if output_mode == OutputMode::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "type": name,
                "documents": emitted,
                "warnings": warnings,
                "written": write,
            }))?
        );
    } else {
        for w in &warnings {
            println!("  {} {w}", "!".yellow());
        }
    }

    let dir = PathBuf::from(output.unwrap_or("."));
    for e in &emitted {
        let dest: PathBuf = Path::new(&dir).join(&e.filename);
        if write {
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
            std::fs::write(&dest, &e.body)
                .with_context(|| format!("writing {}", dest.display()))?;
        }
        if output_mode == OutputMode::Human {
            let tag = e
                .label
                .as_deref()
                .map(|l| format!("  [{l}]"))
                .unwrap_or_default();
            if write {
                println!("{} {}{}", "✓".green(), dest.display(), tag.dimmed());
            } else {
                println!("{} {}{}", "→".cyan(), e.filename, tag.dimmed());
                println!("{}", e.body);
            }
        }
    }
    if output_mode == OutputMode::Human && !write {
        println!("\n{}", "Dry run — pass --write to save.".dimmed());
    }
    Ok(())
}

/// `profile form parse FILE`
pub fn handle_parse(
    file: &str,
    os: Option<&str>,
    schema_path: Option<&str>,
    channel: crate::schema::Channel,
    output_mode: OutputMode,
) -> Result<()> {
    let registry = crate::cli::generate::load_registry_channel(schema_path, channel)?;
    let bytes = std::fs::read(file).with_context(|| format!("reading {file}"))?;
    let target = Target {
        platform: match os {
            Some(o) => Some(
                Platform::from_cli_str(o)
                    .ok_or_else(|| anyhow::anyhow!("unknown platform '{o}'"))?,
            ),
            None => None,
        },
        os_version: None,
    };
    let parsed =
        crate::schema::parse(&registry, &bytes, &target).map_err(|e| anyhow::anyhow!("{e}"))?;

    if output_mode == OutputMode::Json {
        println!("{}", serde_json::to_string_pretty(&parsed)?);
        return Ok(());
    }
    for p in &parsed {
        let nesting = p.nesting.map(|n| format!("  {n:?}")).unwrap_or_default();
        println!(
            "{}  {}{}",
            p.spec.title.bold(),
            p.type_id.dimmed(),
            nesting.dimmed()
        );
        if let Some(s) = p.scope {
            println!("  scope: {}", s.payload_scope_value());
        }
        println!("  values:");
        for line in serde_json::to_string_pretty(&p.values)?.lines() {
            println!("    {line}");
        }
    }
    Ok(())
}
