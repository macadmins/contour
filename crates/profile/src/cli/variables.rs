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
            .chain(
                mdm_vars::FLEET_LEGACY
                    .iter()
                    .map(|(name, _)| format!("{name}  (legacy — avoid)")),
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

/// A payload type's credential keys, each with the Fleet secret variable to
/// put in its place. A key counts when the dataset marks it sensitive
/// (`schema`) or its name reads as a credential (`name`; Apple's schema
/// marks none).
pub fn handle_secret_keys(payload_type: &str, output_mode: OutputMode) -> Result<()> {
    let registry = crate::schema::SchemaRegistry::embedded()?;
    let Some(m) = registry.get(payload_type).or_else(|| registry.get_by_name(payload_type)) else {
        anyhow::bail!("no payload type `{payload_type}` in the embedded schema");
    };
    let keys = secret_keys(m);
    if output_mode == OutputMode::Json {
        let out: Vec<_> = keys
            .iter()
            .map(|(path, by, var)| serde_json::json!({"path": path, "by": by, "fleet": var}))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"payload_type": m.payload_type, "keys": out}))?
        );
        return Ok(());
    }
    if keys.is_empty() {
        println!("{}: no key holds a credential", m.payload_type);
        return Ok(());
    }
    println!("{}", format!("{} credential keys", m.payload_type).bold().cyan());
    for (path, by, var) in &keys {
        println!("  {}  {}  ({by})", path.green(), var.dimmed());
    }
    Ok(())
}

/// `(path, "schema" | "name", "$FLEET_SECRET_<NAME>")`, in field order.
fn secret_keys(m: &crate::schema::PayloadManifest) -> Vec<(String, &'static str, String)> {
    m.field_order
        .iter()
        .filter_map(|p| m.fields.get(p))
        .filter(|f| !matches!(f.field_type, crate::schema::FieldType::Dictionary | crate::schema::FieldType::Array))
        .filter_map(|f| {
            let by = if f.flags.sensitive {
                "schema"
            } else if contour_form::sensitive::is_known_sensitive_name(&f.name)
                // A credential is free text or data: not a switch, not a
                // choice from a fixed set (SystemModeCredentialsSource).
                && matches!(f.field_type, crate::schema::FieldType::String | crate::schema::FieldType::Data)
                && f.allowed_values.is_empty()
            {
                "name"
            } else {
                return None;
            };
            let name: String = f
                .name
                .chars()
                .flat_map(|c| if c.is_ascii_alphanumeric() { c.to_uppercase().collect::<Vec<_>>() } else { vec!['_'] })
                .collect();
            Some((f.path.clone(), by, format!("$FLEET_SECRET_{name}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dataset's flag and the name list both count, each said so.
    #[test]
    fn secret_keys_come_from_the_schema_and_from_names() {
        let registry = crate::schema::SchemaRegistry::embedded().unwrap();
        let santa = secret_keys(registry.get("com.northpolesec.santa").unwrap());
        assert!(santa.iter().any(|(p, by, v)| p == "ClientAuthCertificatePassword"
            && *by == "schema"
            && v == "$FLEET_SECRET_CLIENTAUTHCERTIFICATEPASSWORD"));
        let claude = secret_keys(registry.get("com.anthropic.claudecode").unwrap());
        assert!(claude.iter().any(|(p, by, _)| p == "env.ANTHROPIC_API_KEY" && *by == "schema"));
    }
}
