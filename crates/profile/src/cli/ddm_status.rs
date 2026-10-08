//! `profile ddm status` — the other half of DDM.
//!
//! A declaration says what a device should be; a **status item** is what the
//! device reports back: item types with value types, scopes and
//! enrollments.
//!
//! Read-only: Apple defines the item types, an MDM subscribes to them. This
//! lists and searches what a device can report.

use anyhow::Result;
use colored::Colorize;

use crate::output::OutputMode;

/// `profile ddm status [QUERY] [--platform NAME]`
pub fn handle_status(
    query: Option<&str>,
    platform: Option<&str>,
    errors: bool,
    channel: crate::schema::Channel,
    output_mode: OutputMode,
) -> Result<()> {
    if errors {
        return handle_errors(query, platform, output_mode);
    }
    let bytes = if channel.is_beta() {
        if !mdm_schema::beta_dataset_is_carried() {
            anyhow::bail!(mdm_schema::BETA_DISABLED_MESSAGE);
        }
        mdm_schema::embedded_status_items_beta()
    } else {
        mdm_schema::embedded_status_items()
    };
    let items = mdm_schema::status_items::read(bytes)?;
    if items.is_empty() {
        anyhow::bail!(
            "this build's dataset carries no status_items table — republish the schema \
             (the dataset publishes it in the mdm set)"
        );
    }

    let q = query.map(str::to_lowercase);
    let p = platform.map(str::to_lowercase);
    let mut hits: Vec<_> = items
        .iter()
        .filter(|i| {
            q.as_deref().is_none_or(|q| {
                i.status_item_type.to_lowercase().contains(q)
                    || i.title.to_lowercase().contains(q)
                    || i.description.to_lowercase().contains(q)
            })
        })
        .filter(|i| p.as_deref().is_none_or(|p| i.platform.to_lowercase() == p))
        .collect();
    hits.sort_by(|a, b| {
        a.status_item_type
            .cmp(&b.status_item_type)
            .then(a.platform.cmp(&b.platform))
    });

    if output_mode == OutputMode::Json {
        println!("{}", serde_json::to_string_pretty(&hits)?);
        return Ok(());
    }

    if hits.is_empty() {
        println!("{} no status item matched", "!".yellow());
        return Ok(());
    }
    for i in &hits {
        let scopes = i
            .allowed_scopes
            .as_ref()
            .map(|s| format!("  scopes=[{}]", s.join(",")))
            .unwrap_or_default();
        println!(
            "{}  {}{}",
            i.status_item_type.bold(),
            i.platform.green(),
            scopes.dimmed()
        );
        println!(
            "  {} {}",
            i.value_type.as_deref().unwrap_or("?").cyan(),
            i.description.lines().next().unwrap_or(&i.description)
        );
    }
    println!();
    println!(
        "{} item(s) — a device reports these; subscribe with a status subscription.",
        hits.len()
    );
    Ok(())
}

/// `profile ddm status --errors` — the error codes Apple documents.
///
/// The failure side of the same channel: when a declaration cannot be
/// applied, this is the vocabulary the device answers in.
fn handle_errors(
    query: Option<&str>,
    platform: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let all = mdm_schema::mdm_errors::read(mdm_schema::embedded_mdm_errors())?;
    if all.is_empty() {
        anyhow::bail!(
            "this build's dataset carries no mdm_errors table — republish the schema \
             (the dataset publishes it in the mdm set)"
        );
    }
    let q = query.map(str::to_lowercase);
    let p = platform.map(str::to_lowercase);
    let mut hits: Vec<_> = all
        .iter()
        .filter(|e| {
            q.as_deref().is_none_or(|q| {
                e.error_code.to_lowercase().contains(q) || e.description.to_lowercase().contains(q)
            })
        })
        .filter(|e| p.as_deref().is_none_or(|p| e.platform.to_lowercase() == p))
        .collect();
    hits.sort_by(|a, b| {
        a.error_code
            .cmp(&b.error_code)
            .then(a.platform.cmp(&b.platform))
    });

    if output_mode == OutputMode::Json {
        println!("{}", serde_json::to_string_pretty(&hits)?);
        return Ok(());
    }
    for e in &hits {
        let since = e
            .introduced
            .as_deref()
            .map(|v| format!("  since {v}"))
            .unwrap_or_default();
        println!(
            "{}  {}{}",
            e.error_code.bold(),
            e.platform.green(),
            since.dimmed()
        );
        println!(
            "  {}",
            e.description.lines().next().unwrap_or(&e.description)
        );
    }
    println!("\n{} error code(s)", hits.len());
    Ok(())
}
