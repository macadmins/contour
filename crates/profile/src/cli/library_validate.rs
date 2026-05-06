//! `profile library validate` — lint a preset/recipe library.
//!
//! Walks `<PATH>/recipes/` and `<PATH>/ddm/` and reports issues that
//! would break end-user `generate` / `compose` runs:
//!
//! - Recipe / preset TOML fails to parse
//! - Recipe references a payload type the schema doesn't know about
//! - DDM bundle (in a recipe `[[ddm]]` block or a standalone preset)
//!   fails `compose()` against a synthetic CI org
//!
//! Designed for CI: emits per-file findings, exits non-zero if any
//! finding is at error severity. Use the JSON output for structured
//! consumption by reviewers / dashboards.

use crate::cli::generate::load_registry;
use crate::ddm::compose::{Bundle, ComposeError, ComposeOptions, compose};
use crate::output::OutputMode;
use crate::recipe::Recipe;
use crate::schema::SchemaRegistry;
use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};

/// Synthetic org used for DDM compose checks. Anything in `com.example`
/// would be rejected by `validate_org_domain`, so use a clearly-CI
/// reverse-DNS namespace.
const CI_ORG: &str = "com.contour.libvalidate";

#[derive(Debug)]
pub struct LibraryValidateOptions<'a> {
    pub path: &'a Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Error,
    Warning,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

#[derive(Debug)]
struct Finding {
    file: PathBuf,
    severity: Severity,
    check: &'static str,
    message: String,
}

pub fn handle_library_validate(
    opts: LibraryValidateOptions<'_>,
    output_mode: OutputMode,
) -> Result<()> {
    if !opts.path.is_dir() {
        anyhow::bail!("Library path is not a directory: {}", opts.path.display());
    }

    let registry =
        load_registry(None).context("schema registry must load to validate payload types")?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut scanned = 0usize;

    let recipes_dir = opts.path.join("recipes");
    if recipes_dir.is_dir() {
        for path in toml_files_sorted(&recipes_dir)? {
            scanned += 1;
            validate_recipe_file(&path, &registry, &mut findings);
        }
    }

    let ddm_dir = opts.path.join("ddm");
    if ddm_dir.is_dir() {
        for path in toml_files_sorted(&ddm_dir)? {
            scanned += 1;
            validate_preset_file(&path, &registry, &mut findings);
        }
    }

    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();

    match output_mode {
        OutputMode::Json => {
            let payload = serde_json::json!({
                "success": errors == 0,
                "scanned": scanned,
                "errors": errors,
                "warnings": warnings,
                "findings": findings.iter().map(|f| serde_json::json!({
                    "file": f.file.display().to_string(),
                    "severity": f.severity.as_str(),
                    "check": f.check,
                    "message": f.message,
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputMode::Human => {
            if findings.is_empty() {
                println!("{} {} files validated, no findings.", "✓".green(), scanned);
            } else {
                println!(
                    "{} {} files validated, {} errors, {} warnings",
                    if errors == 0 {
                        "!".yellow()
                    } else {
                        "✗".red()
                    },
                    scanned,
                    errors,
                    warnings,
                );
                for f in &findings {
                    let label = match f.severity {
                        Severity::Error => "error".red().to_string(),
                        Severity::Warning => "warn ".yellow().to_string(),
                    };
                    println!(
                        "  {} {} [{}] {}",
                        label,
                        f.file.display(),
                        f.check,
                        f.message
                    );
                }
            }
        }
    }

    if errors > 0 {
        anyhow::bail!("{errors} error(s) found");
    }
    Ok(())
}

fn toml_files_sorted(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("toml"))
        .collect();
    paths.sort();
    Ok(paths)
}

fn validate_recipe_file(path: &Path, registry: &SchemaRegistry, findings: &mut Vec<Finding>) {
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            findings.push(Finding {
                file: path.to_path_buf(),
                severity: Severity::Error,
                check: "io",
                message: format!("read failed: {e}"),
            });
            return;
        }
    };
    let recipe: Recipe = match toml::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            findings.push(Finding {
                file: path.to_path_buf(),
                severity: Severity::Error,
                check: "toml-parse",
                message: format!("recipe failed to parse: {e}"),
            });
            return;
        }
    };

    // Each [[profile]] must reference a payload type the schema knows
    // about. Unknown types are warnings (might be vendor-specific) so
    // CI can opt-in to gating.
    for spec in &recipe.profiles {
        if registry.get_by_name(&spec.payload_type).is_none() {
            findings.push(Finding {
                file: path.to_path_buf(),
                severity: Severity::Warning,
                check: "unknown-payload-type",
                message: format!(
                    "profile '{}' uses payload_type '{}' not in the embedded schema",
                    spec.display_name, spec.payload_type
                ),
            });
        }
    }

    // Each [[ddm]] bundle must compose cleanly against a synthetic
    // CI org. Reuses the same compose path that `generate --recipe`
    // and `ddm compose` invoke at runtime.
    for bundle in &recipe.ddm {
        if let Err(e) = compose(bundle, CI_ORG, registry, &ComposeOptions::default()) {
            findings.push(Finding {
                file: path.to_path_buf(),
                severity: Severity::Error,
                check: compose_error_check(&e),
                message: format!("ddm bundle '{}': {e}", bundle.intent_name),
            });
        }
    }
}

fn validate_preset_file(path: &Path, registry: &SchemaRegistry, findings: &mut Vec<Finding>) {
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            findings.push(Finding {
                file: path.to_path_buf(),
                severity: Severity::Error,
                check: "io",
                message: format!("read failed: {e}"),
            });
            return;
        }
    };
    let bundle: Bundle = match toml::from_str(&body) {
        Ok(b) => b,
        Err(e) => {
            findings.push(Finding {
                file: path.to_path_buf(),
                severity: Severity::Error,
                check: "toml-parse",
                message: format!("preset failed to parse as a Bundle: {e}"),
            });
            return;
        }
    };
    if let Err(e) = compose(&bundle, CI_ORG, registry, &ComposeOptions::default()) {
        findings.push(Finding {
            file: path.to_path_buf(),
            severity: Severity::Error,
            check: compose_error_check(&e),
            message: format!("compose failed: {e}"),
        });
    }
}

fn compose_error_check(e: &ComposeError) -> &'static str {
    match e {
        ComposeError::UnknownType { .. } => "ddm-unknown-type",
        ComposeError::InvalidIdentifier { .. } => "ddm-invalid-identifier",
        _ => "ddm-compose",
    }
}
