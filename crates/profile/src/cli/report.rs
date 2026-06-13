//! `profile report` — one consolidated repo-hygiene markdown report.
//!
//! Runs four analyses over a profile repo and merges them into a single report:
//! **audit** (secrets / certs / binary), **collisions** (cross-profile payload-domain
//! splits), **deprecations**, and **validate** (schema). Reuses the existing analysis
//! cores rather than re-implementing them.

use std::fmt::Write as _;
use std::fs;

use anyhow::{Context, Result};
use colored::Colorize;

use crate::audit::audit_profile;
use crate::cli::collisions::{collect_config_files, config_format, parse_file};
use crate::collisions::{CollisionReport, Format, KeyVerdict, index_collisions};
use crate::migrate::mapping::MigrationRegistry;
use crate::output::OutputMode;
use crate::profile::deprecation;
use crate::profile::parser::parse_profile_auto_unsign;
use crate::schema::SchemaRegistry;
use crate::validation::SchemaValidator;

/// Per-mobileconfig health row.
#[derive(Debug, serde::Serialize)]
struct FileHealth {
    file: String,
    secrets: usize,
    cert_payloads: usize,
    binary_payloads: usize,
    deprecations_critical: usize,
    deprecations_warning: usize,
    valid: bool,
    validation_errors: usize,
}

impl FileHealth {
    fn is_clean(&self) -> bool {
        self.secrets == 0
            && self.deprecations_critical == 0
            && self.deprecations_warning == 0
            && self.valid
    }
}

/// The whole consolidated report.
#[derive(Debug, serde::Serialize)]
struct RepoReport {
    files_scanned: usize,
    files: Vec<FileHealth>,
    collisions: CollisionReport,
}

impl RepoReport {
    fn total_secrets(&self) -> usize {
        self.files.iter().map(|f| f.secrets).sum()
    }
    fn total_deprecations(&self) -> (usize, usize) {
        self.files.iter().fold((0, 0), |(c, w), f| {
            (c + f.deprecations_critical, w + f.deprecations_warning)
        })
    }
    fn validation_failures(&self) -> usize {
        self.files.iter().filter(|f| !f.valid).count()
    }
}

/// Handle `profile report`.
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_report(
    paths: &[String],
    recursive: bool,
    max_depth: Option<usize>,
    flat: bool,
    output: Option<&str>,
    fail_on_secrets: bool,
    fail_on_conflict: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let files = collect_config_files(paths, recursive, max_depth)?;
    let registry = SchemaRegistry::embedded()?;
    let migration = MigrationRegistry::new();

    // Collisions: build records from every file (mobileconfig + DDM).
    let mut records = Vec::new();
    let mut healths = Vec::new();

    for path in &files {
        records.extend(parse_file(path, flat));

        // Audit / deprecation / validate are mobileconfig-only.
        if config_format(path) != Some(Format::Mobileconfig) {
            continue;
        }
        let Ok(profile) = parse_profile_auto_unsign(path.to_str().unwrap_or_default()) else {
            continue;
        };

        let audit = audit_profile(path).ok();
        let (secrets, certs, bins) = audit
            .as_ref()
            .map(|a| {
                (
                    a.payloads.iter().map(|p| p.secrets.len()).sum(),
                    a.payloads.iter().filter(|p| p.cert.is_some()).count(),
                    a.payloads.iter().filter(|p| p.binary.present).count(),
                )
            })
            .unwrap_or((0, 0, 0));

        let dep =
            deprecation::scan_deprecations(&profile.to_plist_value(), path, &migration, &registry);

        let result = SchemaValidator::new(&registry).validate(&profile);

        healths.push(FileHealth {
            file: path.display().to_string(),
            secrets,
            cert_payloads: certs,
            binary_payloads: bins,
            deprecations_critical: dep.critical_count(),
            deprecations_warning: dep.warning_count(),
            valid: result.is_valid(),
            validation_errors: result.errors().len(),
        });
    }

    let collisions = CollisionReport {
        files_scanned: files.len(),
        payloads_scanned: records.len(),
        collisions: index_collisions(&records),
    };

    let report = RepoReport {
        files_scanned: files.len(),
        files: healths,
        collisions,
    };

    // Emit.
    let md = build_markdown(&report);
    match output {
        Some(path) => {
            fs::write(path, &md).with_context(|| format!("writing {path}"))?;
            if output_mode == OutputMode::Human {
                println!("{}", format!("Report written to {path}").green());
            }
        }
        None if output_mode == OutputMode::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        None => print!("{md}"),
    }

    // Gates.
    if fail_on_secrets && report.total_secrets() > 0 {
        anyhow::bail!("{} secret(s) found across the repo", report.total_secrets());
    }
    if fail_on_conflict && report.collisions.conflict_count() > 0 {
        anyhow::bail!(
            "{} payload domain(s) have value conflicts across profiles",
            report.collisions.conflict_count()
        );
    }
    Ok(())
}

fn build_markdown(report: &RepoReport) -> String {
    let mut md = String::with_capacity(8 * 1024);
    let (dep_crit, dep_warn) = report.total_deprecations();
    let conflicts = report.collisions.conflict_count();

    writeln!(md, "# Profile Repository Health Report\n").unwrap();
    writeln!(md, "| Metric | Count |\n|---|---|").unwrap();
    writeln!(md, "| Files scanned | {} |", report.files_scanned).unwrap();
    writeln!(md, "| Payloads | {} |", report.collisions.payloads_scanned).unwrap();
    writeln!(md, "| Secrets | {} |", report.total_secrets()).unwrap();
    writeln!(
        md,
        "| Colliding domains (conflicts) | {} ({conflicts}) |",
        report.collisions.collisions.len()
    )
    .unwrap();
    writeln!(
        md,
        "| Deprecations (critical / warning) | {dep_crit} / {dep_warn} |"
    )
    .unwrap();
    writeln!(
        md,
        "| Validation failures | {} |\n",
        report.validation_failures()
    )
    .unwrap();

    // 1. Secrets & content
    let with_findings: Vec<&FileHealth> = report
        .files
        .iter()
        .filter(|f| f.secrets > 0 || f.cert_payloads > 0 || f.binary_payloads > 0)
        .collect();
    writeln!(md, "## Audit — secrets, certs, binary\n").unwrap();
    if with_findings.is_empty() {
        writeln!(md, "No secrets, certificates, or binary payloads.\n").unwrap();
    } else {
        writeln!(
            md,
            "| Profile | Secrets | Cert payloads | Binary payloads |\n|---|---|---|---|"
        )
        .unwrap();
        for f in with_findings {
            writeln!(
                md,
                "| `{}` | {} | {} | {} |",
                short(&f.file),
                f.secrets,
                f.cert_payloads,
                f.binary_payloads
            )
            .unwrap();
        }
        writeln!(md).unwrap();
    }

    // 2. Collisions
    writeln!(md, "## Collisions — domains managed by 2+ profiles\n").unwrap();
    if report.collisions.collisions.is_empty() {
        writeln!(md, "No payload-domain collisions.\n").unwrap();
    } else {
        writeln!(
            md,
            "| Domain | Files | Conflicts | Complementary | Scope |\n|---|---|---|---|---|"
        )
        .unwrap();
        let mut cols: Vec<_> = report.collisions.collisions.iter().collect();
        cols.sort_by_key(|c| std::cmp::Reverse(c.files.len()));
        for c in cols {
            let cf = c
                .keys
                .iter()
                .filter(|k| k.verdict == KeyVerdict::Conflict)
                .count();
            let cp = c
                .keys
                .iter()
                .filter(|k| k.verdict == KeyVerdict::Complementary)
                .count();
            writeln!(
                md,
                "| `{}` | {} | {cf} | {cp} | {} |",
                c.domain,
                c.files.len(),
                c.scope
            )
            .unwrap();
        }
        writeln!(md, "\n_Run `contour profile collisions <repo> -r --flat --md-report` for the full per-key matrix._\n").unwrap();
    }

    // 3. Deprecations
    let deprecated: Vec<&FileHealth> = report
        .files
        .iter()
        .filter(|f| f.deprecations_critical > 0 || f.deprecations_warning > 0)
        .collect();
    writeln!(md, "## Deprecations\n").unwrap();
    if deprecated.is_empty() {
        writeln!(md, "No deprecated payloads or keys.\n").unwrap();
    } else {
        writeln!(md, "| Profile | Critical | Warning |\n|---|---|---|").unwrap();
        for f in deprecated {
            writeln!(
                md,
                "| `{}` | {} | {} |",
                short(&f.file),
                f.deprecations_critical,
                f.deprecations_warning
            )
            .unwrap();
        }
        writeln!(
            md,
            "\n_Run `contour profile scan <repo> -r --with-deprecations --md-report` for detail._\n"
        )
        .unwrap();
    }

    // 4. Validation
    let failed: Vec<&FileHealth> = report.files.iter().filter(|f| !f.valid).collect();
    writeln!(md, "## Validation\n").unwrap();
    if failed.is_empty() {
        writeln!(md, "All profiles are schema-valid.\n").unwrap();
    } else {
        writeln!(md, "| Profile | Errors |\n|---|---|").unwrap();
        for f in failed {
            writeln!(md, "| `{}` | {} |", short(&f.file), f.validation_errors).unwrap();
        }
        writeln!(
            md,
            "\n_Run `contour profile validate <repo> -r --report` for detail._\n"
        )
        .unwrap();
    }

    let clean = report.files.iter().filter(|f| f.is_clean()).count();
    writeln!(
        md,
        "---\n\n{clean}/{} profiles clean (no secrets, deprecations, or validation errors).",
        report.files.len()
    )
    .unwrap();
    md
}

/// Last two path components, for compact report output.
fn short(path: &str) -> String {
    let parts: Vec<&str> = path.rsplit('/').take(2).collect();
    parts.into_iter().rev().collect::<Vec<_>>().join("/")
}
