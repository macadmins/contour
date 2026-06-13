//! `ddm transform` — turn an Apple example declaration into a working config.

use anyhow::{Context, Result, bail};
use std::path::Path;

use crate::cli::ddm::resolve_ddm_org_domain;
use crate::config::ProfileConfig;
use crate::example::{mobileconfig, transform, values};
use crate::output::OutputMode;

#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_ddm_transform(
    example_file: Option<&str>,
    values_file: Option<&str>,
    scan: &[String],
    permissions: Option<&str>,
    deny: bool,
    org: Option<&str>,
    output: Option<&str>,
    strict: bool,
    config: Option<&ProfileConfig>,
    _output_mode: OutputMode,
    type_name: Option<&str>,
    example_index: Option<u32>,
    beta: bool,
) -> Result<()> {
    // Phase 1: resolve raw text + source hint + type hint WITHOUT parsing.
    let (raw, source_hint, type_hint): (String, Option<String>, Option<String>) =
        if let Some(file) = example_file {
            let raw =
                std::fs::read_to_string(file).with_context(|| format!("reading example {file}"))?;
            (raw, Some(file.to_string()), None)
        } else if let (Some(ty), Some(n)) = (type_name, example_index) {
            let registry = crate::cli::ddm::load_registry_opts(None, beta)?;
            let manifest = registry
                .get_by_name(ty)
                .ok_or_else(|| anyhow::anyhow!("type '{ty}' not found"))?;
            let payload_type = manifest.payload_type.clone();
            let ex = crate::example::lookup::pick(&payload_type, n, beta)?;
            (ex.json, Some(ex.source_file), Some(payload_type))
        } else {
            bail!("provide <example-file> OR --type <TYPE> --example <N>");
        };

    let org_domain = resolve_ddm_org_domain(org, config).ok_or_else(|| {
        anyhow::anyhow!("organization domain required (--org / CONTOUR_ORG / config)")
    })?;

    // Phase 2: detect format.
    let is_plist = source_hint
        .as_deref()
        .is_some_and(|s| s.to_ascii_lowercase().ends_with(".plist"))
        || raw.trim_start().starts_with("<?xml")
        || raw.contains("<plist");

    if is_plist {
        // ── PLIST / mobileconfig path ─────────────────────────────────────────
        // Apply text find/replace first (if requested).
        let text = if let Some(vf) = values_file {
            let pairs = values::load_values(Path::new(vf))?;
            transform::apply_find_replace_text(&raw, &pairs)
        } else {
            raw
        };

        if !scan.is_empty() {
            eprintln!(
                "warning: --scan only fills com.apple.configuration.app.settings DDM declarations; \
                 ignored for mobileconfig examples"
            );
        }

        let result = mobileconfig::transform_mobileconfig(&text, &org_domain)?;

        // Check for residual Apple placeholders in the output text.
        if result.contains("com.example.") {
            let msg = "residual placeholder(s) remain (com.example.*)";
            if strict {
                bail!("{msg}");
            }
            eprintln!("warning: {msg}");
        }

        match output {
            Some(p) => {
                std::fs::write(p, &result).with_context(|| format!("writing {p}"))?;
                eprintln!("✓ wrote {p}");
            }
            None => print!("{result}"),
        }
    } else {
        // ── JSON / DDM path (original behavior) ───────────────────────────────
        let mut v: serde_json::Value =
            serde_json::from_str(&raw).with_context(|| "parsing example as JSON")?;

        let type_str: String = type_hint.unwrap_or_else(|| {
            v.get("Type")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string()
        });

        let short = transform::short_name_from_type(&type_str).to_string();

        transform::structural_fixups(&mut v, &org_domain, &short, example_index.unwrap_or(0));

        if !scan.is_empty() {
            if type_str == "com.apple.configuration.app.settings" {
                let paths: Vec<std::path::PathBuf> = scan.iter().map(Into::into).collect();
                crate::example::fill::fill_app_settings(
                    &mut v,
                    &paths,
                    permissions.map(std::path::Path::new),
                    deny,
                )?;
            } else {
                eprintln!(
                    "warning: --scan only fills com.apple.configuration.app.settings; ignored for {type_str}"
                );
            }
        }

        if let Some(vf) = values_file {
            let pairs = values::load_values(Path::new(vf))?;
            v = transform::apply_find_replace(&v, &pairs)?;
        }

        let remaining = transform::remaining_placeholders(&v);
        if !remaining.is_empty() {
            if strict {
                bail!("residual placeholders remain: {remaining:?}");
            }
            eprintln!("warning: residual placeholders remain: {remaining:?}");
        }

        let pretty = serde_json::to_string_pretty(&v)?;
        match output {
            Some(p) => {
                std::fs::write(p, pretty).with_context(|| format!("writing {p}"))?;
                eprintln!("✓ wrote {p}  (validate: contour profile ddm validate --beta {p})");
            }
            None => println!("{pretty}"),
        }
    }

    Ok(())
}
