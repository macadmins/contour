//! Audit command CLI handler — content/security classification + triage routing.
//!
//! Reports which payloads carry binary content, which are certificates (and of
//! what kind), and which contain secrets, then optionally moves matching
//! profiles into category subfolders.

use anyhow::{Context, Result};
use colored::Colorize;
use rayon::prelude::*;
use std::path::{Path, PathBuf};

use crate::audit::route::{self, Bucket};
use crate::audit::{ProfileAudit, SecretKind, audit_profile};
use crate::cli::glob_utils::{collect_profile_files_multi_with_depth, should_batch_process_multi};
use crate::migrate::mapping::MigrationRegistry;
use crate::output::OutputMode;
use crate::profile::deprecation::{self, DeprecationReport};
use crate::profile::parser::parse_profile_auto_unsign;
use crate::schema::SchemaRegistry;

/// One scanned profile plus its optional deprecation report.
struct AuditEntry {
    audit: ProfileAudit,
    deprecations: Option<DeprecationReport>,
}

/// Handle `profile audit`.
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_audit(
    paths: &[String],
    recursive: bool,
    max_depth: Option<usize>,
    parallel: bool,
    certs_only: bool,
    secrets_only: bool,
    with_deprecations: bool,
    no_links: bool,
    fail_on_secrets: bool,
    route_into: Option<&str>,
    dry_run: bool,
    md_report: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    if certs_only && secrets_only {
        anyhow::bail!("--certs-only and --secrets-only are mutually exclusive");
    }

    // Resolve the file set.
    let files: Vec<PathBuf> = if should_batch_process_multi(paths) {
        collect_profile_files_multi_with_depth(paths, recursive, max_depth)?
    } else {
        let p = Path::new(&paths[0]);
        if !p.exists() {
            anyhow::bail!("Path not found: {}", paths[0]);
        }
        vec![p.to_path_buf()]
    };

    if files.is_empty() {
        if output_mode == OutputMode::Json {
            println!(
                "{}",
                serde_json::json!({ "total": 0, "profiles": [], "message": "No .mobileconfig files found" })
            );
        } else {
            println!("{}", "No .mobileconfig files found".yellow());
        }
        return Ok(());
    }

    let entries = audit_files(&files, with_deprecations, parallel);

    // Cross-reference graph across the scanned set — both directions, so a
    // certificate shows who depends on it, not just what it is.
    let link_analysis = (!no_links).then(|| {
        let parsed: Vec<(PathBuf, crate::profile::ConfigurationProfile)> = files
            .iter()
            .filter_map(|f| {
                crate::profile::parser::parse_profile_auto_unsign(&f.to_string_lossy())
                    .ok()
                    .map(|p| (f.clone(), p))
            })
            .collect();
        crate::link::analyze::analyze_links(&parsed)
    });

    // Output.
    if let Some(md_path) = md_report {
        std::fs::write(md_path, render_markdown(&entries))
            .with_context(|| format!("Failed to write Markdown report to {md_path}"))?;
    }
    match output_mode {
        OutputMode::Json => {
            print_json_with_links(&entries, with_deprecations, link_analysis.as_ref())
        }
        OutputMode::Human => {
            print_human(&entries, with_deprecations);
            if let Some(analysis) = &link_analysis {
                print_link_analysis(analysis);
            }
        }
    }

    // Triage routing.
    if let Some(dest) = route_into {
        route_entries(
            &entries,
            Path::new(dest),
            certs_only,
            secrets_only,
            dry_run,
            output_mode,
        )?;
    }

    // CI gate.
    if fail_on_secrets {
        let total: usize = entries
            .iter()
            .map(|e| {
                e.audit
                    .payloads
                    .iter()
                    .map(|p| p.secrets.len())
                    .sum::<usize>()
            })
            .sum();
        if total > 0 {
            anyhow::bail!("audit failed: {total} secret(s) found (--fail-on-secrets)");
        }
    }

    Ok(())
}

/// Audit every file, optionally in parallel, collecting deprecations on request.
fn audit_files(files: &[PathBuf], with_deprecations: bool, parallel: bool) -> Vec<AuditEntry> {
    let run = |path: &PathBuf| -> Result<AuditEntry, (String, String)> {
        let audit = audit_profile(path).map_err(|e| (path.display().to_string(), e.to_string()))?;
        let deprecations = if with_deprecations {
            scan_file_deprecations(path)
        } else {
            None
        };
        Ok(AuditEntry {
            audit,
            deprecations,
        })
    };

    let outcomes: Vec<Result<AuditEntry, (String, String)>> = if parallel {
        files.par_iter().map(run).collect()
    } else {
        files.iter().map(run).collect()
    };

    let mut entries = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(entry) => entries.push(entry),
            Err((path, err)) => eprintln!("{} {}: {}", "Warning:".yellow(), path, err),
        }
    }
    entries
}

/// Run a deprecation scan for one profile, returning `None` on any load error.
fn scan_file_deprecations(path: &Path) -> Option<DeprecationReport> {
    let profile = parse_profile_auto_unsign(&path.to_string_lossy()).ok()?;
    let migration = MigrationRegistry::new();
    let schema = SchemaRegistry::embedded().ok()?;
    Some(deprecation::scan_deprecations(
        &profile.to_plist_value(),
        path,
        &migration,
        &schema,
    ))
}

/// Move matching profiles into category subfolders under `dest`.
fn route_entries(
    entries: &[AuditEntry],
    dest: &Path,
    certs_only: bool,
    secrets_only: bool,
    dry_run: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let items: Vec<(PathBuf, Vec<Bucket>)> = entries
        .iter()
        .map(|e| {
            (
                PathBuf::from(&e.audit.path),
                route::buckets_for(&e.audit, certs_only, secrets_only),
            )
        })
        .filter(|(_, buckets)| !buckets.is_empty())
        .collect();

    let plans = route::plan_moves(&items, dest);

    if dry_run {
        if output_mode == OutputMode::Human {
            println!(
                "\n{}",
                "Routing plan (dry-run — nothing moved)".yellow().bold()
            );
            for plan in &plans {
                let dests: Vec<String> = plan
                    .destinations
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect();
                println!("  {} → {}", plan.source.display(), dests.join(", ").green());
            }
            println!("  {} {} profile(s) would move", "→".green(), plans.len());
        }
        return Ok(());
    }

    let mut moved = 0usize;
    for plan in &plans {
        route::execute_move(plan)
            .with_context(|| format!("Failed to route {}", plan.source.display()))?;
        moved += 1;
    }
    if output_mode == OutputMode::Human {
        println!(
            "\n  {} routed {} profile(s) → {}",
            "→".green(),
            moved,
            dest.display()
        );
    }
    Ok(())
}

/// Render the JSON document for `--json`.
fn print_json(entries: &[AuditEntry], with_deprecations: bool) {
    println!(
        "{}",
        serde_json::to_string_pretty(&json_value(entries, with_deprecations)).unwrap_or_default()
    );
}

/// The audit JSON envelope as a value, so callers can merge extra sections
/// (e.g. the cross-reference graph) before printing.
fn json_value(entries: &[AuditEntry], with_deprecations: bool) -> serde_json::Value {
    let (mut bin, mut certs, mut secrets) = (0usize, 0usize, 0usize);
    let (mut root, mut intermediate, mut leaf, mut identity) = (0usize, 0usize, 0usize, 0usize);
    let mut dep_total = 0usize;
    for e in entries {
        for p in &e.audit.payloads {
            if p.binary.present {
                bin += 1;
            }
            if !p.secrets.is_empty() {
                secrets += 1;
            }
            if let Some(c) = &p.cert {
                certs += 1;
                match c.kind {
                    crate::audit::cert::CertKind::Root => root += 1,
                    crate::audit::cert::CertKind::Intermediate => intermediate += 1,
                    crate::audit::cert::CertKind::Leaf => leaf += 1,
                    crate::audit::cert::CertKind::Identity => identity += 1,
                }
            }
        }
        dep_total += e.deprecations.as_ref().map_or(0, |d| d.findings.len());
    }

    let mut summary = serde_json::json!({
        "binary_payloads": bin,
        "cert_payloads": certs,
        "cert_breakdown": {
            "root": root, "intermediate": intermediate, "leaf": leaf, "identity": identity
        },
        "payloads_with_secrets": secrets,
    });
    if with_deprecations {
        summary["deprecations"] = serde_json::json!(dep_total);
    }

    let profiles: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let mut v = serde_json::to_value(&e.audit).unwrap_or_default();
            v["buckets"] = serde_json::json!(
                route::buckets_for(&e.audit, false, false)
                    .iter()
                    .map(|b| b.dir_name())
                    .collect::<Vec<_>>()
            );
            if let Some(dep) = &e.deprecations {
                v["deprecations"] = serde_json::to_value(dep).unwrap_or_default();
            }
            v
        })
        .collect();

    serde_json::json!({
        "total": entries.len(),
        "summary": summary,
        "profiles": profiles,
    })
}

/// Render human-readable output.
fn print_human(entries: &[AuditEntry], with_deprecations: bool) {
    println!(
        "{}",
        format!("Audited {} profile(s)", entries.len())
            .cyan()
            .bold()
    );
    println!();

    let (mut bin, mut certs, mut secrets) = (0usize, 0usize, 0usize);
    for e in entries {
        let a = &e.audit;
        println!("{}", a.path.bold());
        println!(
            "  {} {} ({})",
            "Profile:".cyan(),
            a.display_name,
            a.identifier
        );
        for p in &a.payloads {
            let mut badges: Vec<String> = Vec::new();
            if let Some(c) = &p.cert {
                badges.push(
                    format!("cert:{}", format!("{:?}", c.kind).to_lowercase())
                        .green()
                        .to_string(),
                );
            }
            if p.binary.present {
                badges.push(format!("binary:{}B", p.binary.bytes).blue().to_string());
                bin += 1;
            }
            if !p.secrets.is_empty() {
                let kinds: Vec<String> = p
                    .secrets
                    .iter()
                    .map(|s| secret_kind_label(s.kind).to_string())
                    .collect();
                badges.push(format!("secrets:[{}]", kinds.join(",")).red().to_string());
                secrets += 1;
            }
            if p.cert.is_some() {
                certs += 1;
            }
            let badge_str = if badges.is_empty() {
                "—".dimmed().to_string()
            } else {
                badges.join(" ")
            };
            println!("    {}. {} {}", p.index + 1, p.r#type.green(), badge_str);
        }
        if with_deprecations
            && let Some(dep) = &e.deprecations
            && !dep.is_empty()
        {
            println!(
                "    {} {} critical, {} warning",
                "Deprecations:".yellow(),
                dep.critical_count(),
                dep.warning_count()
            );
        }
        println!("{}", "─".repeat(60).dimmed());
    }

    println!();
    println!("{}", "Summary".white().bold());
    println!("  {} {} profiles", "Total:".cyan(), entries.len());
    println!(
        "  {} {} payloads with binary content",
        "Binary:".cyan(),
        bin
    );
    println!("  {} {} cert payloads", "Certs:".cyan(), certs);
    println!("  {} {} payloads with secrets", "Secrets:".cyan(), secrets);
}

/// Render a Markdown audit report.
fn render_markdown(entries: &[AuditEntry]) -> String {
    use std::fmt::Write as _;
    let mut md = String::from("# Audit Report\n\n");
    let _ = writeln!(md, "{} profile(s) audited.\n", entries.len());
    md.push_str("| Profile | Cert | Binary | Secrets |\n|---|---|---|---|\n");
    for e in entries {
        let a = &e.audit;
        let cert = a
            .payloads
            .iter()
            .filter_map(|p| p.cert.as_ref())
            .map(|c| format!("{:?}", c.kind).to_lowercase())
            .collect::<Vec<_>>()
            .join(", ");
        let bin: usize = a.payloads.iter().filter(|p| p.binary.present).count();
        let sec: usize = a.payloads.iter().map(|p| p.secrets.len()).sum();
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} |",
            a.path,
            if cert.is_empty() { "—".into() } else { cert },
            bin,
            sec
        );
    }
    md
}

/// Short label for a secret kind in human output.
fn secret_kind_label(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::SchemaSensitive => "schema",
        SecretKind::KnownSensitive => "known",
        SecretKind::PrivateKey => "privkey",
        SecretKind::DeployVar => "deployvar",
        SecretKind::HighEntropyLiteral => "entropy",
    }
}

/// Print the bidirectional cross-reference graph.
///
/// The incoming direction is the point: a certificate payload's own content
/// says nothing about who depends on it, so removing or re-identifying it
/// silently breaks the referrer.
fn print_link_analysis(analysis: &crate::link::analyze::LinkAnalysis) {
    if analysis.is_empty() && analysis.incoming.is_empty() {
        return;
    }

    println!();
    println!("{}", "Cross-references".bold());

    if analysis.links.is_empty() {
        println!("  {}", "no payload references anything".dimmed());
    }
    for link in &analysis.links {
        let target = match (&link.to_payload_type, &link.to_file) {
            (Some(t), Some(f)) => format!("{t}  [{f}]"),
            _ => format!("{} (no payload in scope owns this UUID)", "DANGLING".red()),
        };
        println!(
            "  {} {} → {}",
            "→".cyan(),
            format!("{}.{}", short_uuid(&link.from_payload_uuid), link.field).dimmed(),
            target
        );
    }

    for inc in &analysis.incoming {
        if inc.referenced_by.is_empty() {
            // Surfaced deliberately: a certificate nothing points at is often
            // a leftover, or a sign the referrer is outside the scanned set.
            println!(
                "  {} {} {} — {}",
                "←".yellow(),
                short_uuid(&inc.payload_uuid),
                inc.payload_type,
                "referenced by nothing in scope".yellow()
            );
        } else {
            println!(
                "  {} {} {} ← referenced by {}",
                "←".green(),
                short_uuid(&inc.payload_uuid),
                inc.payload_type,
                inc.referenced_by
                    .iter()
                    .map(|(uuid, field)| format!("{}.{field}", short_uuid(uuid)))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    let unreferenced = analysis.unreferenced().len();
    if unreferenced > 0 {
        println!(
            "  {} {unreferenced} referenceable payload(s) nothing points at",
            "·".dimmed()
        );
    }

    let dangling = analysis.dangling().len();
    if dangling > 0 {
        println!(
            "  {} {dangling} dangling reference(s) — these install and then fail silently",
            "!".red()
        );
    }
}

/// First 8 chars of a UUID, enough to correlate in a report.
fn short_uuid(uuid: &str) -> String {
    uuid.chars().take(8).collect()
}

/// JSON output with the link graph attached (when computed).
fn print_json_with_links(
    entries: &[AuditEntry],
    with_deprecations: bool,
    analysis: Option<&crate::link::analyze::LinkAnalysis>,
) {
    let Some(analysis) = analysis else {
        print_json(entries, with_deprecations);
        return;
    };
    let mut value = json_value(entries, with_deprecations);
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "cross_references".to_string(),
            serde_json::to_value(analysis).unwrap_or(serde_json::Value::Null),
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&value).unwrap_or_default()
    );
}
