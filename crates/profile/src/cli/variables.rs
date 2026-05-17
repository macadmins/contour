//! `profile variables` — list MDM deploy-time variables.

use crate::mdm_vars::{self, MdmFlavour};
use crate::output::OutputMode;
use anyhow::Result;
use colored::Colorize;

/// List the built-in MDM variable catalogues plus the config pool.
pub fn handle_variables(mdm: Option<&str>, output_mode: OutputMode) -> Result<()> {
    let cfg = contour_core::config::resolve_mdm_variables_with_anchor(None);
    let selected = mdm.or(cfg.mdm.as_deref()).and_then(MdmFlavour::parse);
    let flavours: Vec<MdmFlavour> = match selected {
        Some(f) => vec![f],
        None => vec![MdmFlavour::Fleet, MdmFlavour::Jamf, MdmFlavour::Apple],
    };

    if output_mode == OutputMode::Json {
        let catalogues: Vec<_> = flavours
            .iter()
            .map(|f| {
                serde_json::json!({
                    "flavour": f.as_str(),
                    "variables": catalogue(*f),
                })
            })
            .collect();
        let out = serde_json::json!({
            "catalogues": catalogues,
            "pool": cfg.pool,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    for f in &flavours {
        println!("{}", format!("{} variables", f.as_str()).bold().cyan());
        let entries = catalogue(*f);
        if entries.is_empty() {
            println!(
                "  {}",
                "(none built in — extend via the config pool)".dimmed()
            );
        }
        for v in entries {
            println!("  {v}");
        }
        println!();
    }

    if cfg.pool.is_empty() {
        println!("{}", "config [mdm_variables.pool]: (empty)".dimmed());
    } else {
        println!("{}", "config [mdm_variables.pool]".bold().cyan());
        for (k, v) in &cfg.pool {
            println!("  {} = {}", k.green(), v);
        }
    }
    Ok(())
}

/// Catalogue entries for a flavour. Fleet prefix variables are shown
/// with a `<suffix>` marker for the required trailing part.
fn catalogue(flavour: MdmFlavour) -> Vec<String> {
    match flavour {
        MdmFlavour::Fleet => mdm_vars::FLEET_EXACT
            .iter()
            .map(|s| (*s).to_string())
            .chain(
                mdm_vars::FLEET_PREFIXES
                    .iter()
                    .map(|p| format!("{p}<suffix>")),
            )
            .collect(),
        MdmFlavour::Jamf => mdm_vars::JAMF_VARS
            .iter()
            .map(|s| (*s).to_string())
            .chain(mdm_vars::JAMF_PREFIXES.iter().map(|p| format!("{p}<id>")))
            .collect(),
        MdmFlavour::Apple => mdm_vars::APPLE_VARS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    }
}
