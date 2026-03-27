//! Batch update TCC services for apps in a pppc.toml.

use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::cli::OutputMode;
use crate::pppc::{PppcConfig, PppcService};

/// Per-app change summary.
struct AppChanges {
    name: String,
    added_services: Vec<PppcService>,
    removed_services: Vec<PppcService>,
    set_services: Option<Vec<PppcService>>,
}

impl AppChanges {
    fn has_changes(&self) -> bool {
        !self.added_services.is_empty()
            || !self.removed_services.is_empty()
            || self.set_services.is_some()
    }
}

/// Short CLI-style name for a service (matches serde/clap value names).
fn service_short_name(svc: PppcService) -> String {
    // serde_json gives us the rename value (e.g. "fda", "desktop", "screen-capture")
    serde_json::to_value(svc)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{svc:?}"))
}

pub fn run(
    input: &Path,
    add_services: &[PppcService],
    remove_services: &[PppcService],
    set_services: &Option<Vec<PppcService>>,
    apps_filter: &[String],
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    // Validate conflicting flags
    if set_services.is_some() && (!add_services.is_empty() || !remove_services.is_empty()) {
        anyhow::bail!("--set-services conflicts with --add-services / --remove-services");
    }

    let no_op = add_services.is_empty() && remove_services.is_empty() && set_services.is_none();
    if no_op {
        anyhow::bail!(
            "Nothing to do. Provide at least one of --add-services, --remove-services, or --set-services"
        );
    }

    let mut config = PppcConfig::load(input)?;

    let filter_lower: Vec<String> = apps_filter.iter().map(|s| s.to_lowercase()).collect();
    let total_apps = config.apps.len();
    let mut changes: Vec<AppChanges> = Vec::new();

    for app in &mut config.apps {
        // Apply filter: case-insensitive substring match
        if !filter_lower.is_empty()
            && !filter_lower
                .iter()
                .any(|f| app.name.to_lowercase().contains(f))
        {
            changes.push(AppChanges {
                name: app.name.clone(),
                added_services: vec![],
                removed_services: vec![],
                set_services: None,
            });
            continue;
        }

        let mut ac = AppChanges {
            name: app.name.clone(),
            added_services: vec![],
            removed_services: vec![],
            set_services: None,
        };

        // Services
        if let Some(new_set) = set_services {
            if app.services != *new_set {
                ac.set_services = Some(new_set.clone());
                new_set.clone_into(&mut app.services);
            }
        } else {
            // Add services (skip duplicates)
            for svc in add_services {
                if !app.services.contains(svc) {
                    app.services.push(*svc);
                    ac.added_services.push(*svc);
                }
            }
            // Remove services
            for svc in remove_services {
                if app.services.contains(svc) {
                    app.services.retain(|s| s != svc);
                    ac.removed_services.push(*svc);
                }
            }
        }

        changes.push(ac);
    }

    // Print summary
    let mut updated_count = 0usize;
    for ac in &changes {
        if !ac.has_changes() {
            if output_mode == OutputMode::Human {
                println!("{} {}: no changes", "→".dimmed(), ac.name);
            }
            continue;
        }
        updated_count += 1;

        if output_mode == OutputMode::Human {
            let mut parts: Vec<String> = Vec::new();

            if let Some(ref svcs) = ac.set_services {
                let names: Vec<String> = svcs.iter().copied().map(service_short_name).collect();
                parts.push(format!("services={}", names.join(",")));
            } else {
                for svc in &ac.added_services {
                    parts.push(format!("+{}", service_short_name(*svc)));
                }
                for svc in &ac.removed_services {
                    parts.push(format!("-{}", service_short_name(*svc)));
                }
            }

            println!("{} {}: {}", "✓".green(), ac.name, parts.join(", "));
        }
    }

    if output_mode == OutputMode::Human {
        if dry_run {
            println!(
                "\n{} {} of {} apps in {} (dry run — no changes written)",
                "Would update".yellow(),
                updated_count,
                total_apps,
                input.display()
            );
        } else {
            println!(
                "\nUpdated {} of {} apps in {}",
                updated_count,
                total_apps,
                input.display()
            );
        }
    }

    if !dry_run {
        config.save(input)?;
    }

    Ok(())
}
